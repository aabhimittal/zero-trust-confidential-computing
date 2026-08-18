// Tests for the decision record. The adversary throughout is a host with
// root: it cannot forge a decision or read sealed state, but it owns the
// disk the log is stored on and can restart the enclave whenever it likes.
package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"

	"github.com/aabhimittal/zero-trust-confidential-computing/internal/pdp"
	"github.com/aabhimittal/zero-trust-confidential-computing/internal/tee"
)

const testPolicy = `{"version":"2026.1","rules":[
  {"id":"allow-mfa","effect":"allow","resources":["payroll-db"],"when":{"min_auth":"mfa"}}]}`

type world struct {
	platform *tee.Platform
	image    tee.Image
	enclave  *tee.Enclave
	engine   *pdp.Engine
	store    *MemStore
	log      *Log
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{
		platform: tee.NewPlatform(7),
		image: tee.Image{
			Signer:        "release",
			EngineVersion: "engine/test",
			PolicyJSON:    []byte(testPolicy),
		},
		store: &MemStore{},
	}
	w.enclave = w.platform.Launch(w.image)
	engine, err := pdp.NewEngineInEnclave(w.enclave)
	if err != nil {
		t.Fatal(err)
	}
	w.engine = engine

	log, err := Open(w.enclave, engine, w.store, engine.PolicyVersion())
	if err != nil {
		t.Fatal(err)
	}
	w.log = log
	return w
}

// restart tears the enclave down and launches the identical image again,
// exactly as a host would. Attestation would still pass for this enclave —
// it is genuinely the endorsed build — so any protection has to come from
// the sealed state and the counter, not from identity.
func (w *world) restart(t *testing.T) (*Log, error) {
	t.Helper()
	w.enclave = w.platform.Launch(w.image)
	engine, err := pdp.NewEngineInEnclave(w.enclave)
	if err != nil {
		t.Fatal(err)
	}
	w.engine = engine
	return Open(w.enclave, engine, w.store, engine.PolicyVersion())
}

func request(subject string, auth string) pdp.Request {
	return pdp.Request{
		Subject:  pdp.Subject{ID: subject, AuthMethod: auth},
		Device:   pdp.Device{Managed: true, OSPatched: true, DiskEncrypted: true},
		Resource: pdp.Resource{Name: "payroll-db", Sensitivity: 3},
		Context:  pdp.Context{Network: "corp"},
	}
}

// record drives n decisions through the engine and into the log.
func (w *world) record(n int) []Entry {
	entries := make([]Entry, 0, n)
	for i := range n {
		auth := "mfa"
		if i%3 == 0 {
			auth = "password" // produces a deny, so the log has both verdicts
		}
		var nonce [32]byte
		nonce[0] = byte(i)
		entries = append(entries, w.log.Append(w.engine.Decide(request("subject", auth), nonce)))
	}
	return entries
}

// ─── The happy path ─────────────────────────────────────────────────────

func TestVerifyAcceptsAnUntouchedLog(t *testing.T) {
	w := newWorld(t)
	entries := w.record(6)
	cp, err := w.log.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	if cp.Count != 6 || w.log.Count() != 6 {
		t.Fatalf("expected 6 entries, got %d", cp.Count)
	}
	if err := Verify(entries, cp, w.engine.PublicKey()); err != nil {
		t.Fatalf("an untouched log must verify: %v", err)
	}
}

func TestEmptyLogCheckpointsAndVerifies(t *testing.T) {
	w := newWorld(t)
	cp, err := w.log.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	if cp.Count != 0 || cp.Head != ([32]byte{}) {
		t.Fatalf("an empty log must checkpoint as empty: %+v", cp)
	}
	if err := Verify(nil, cp, w.engine.PublicKey()); err != nil {
		t.Fatalf("an empty log must verify against its checkpoint: %v", err)
	}
}

func TestEntriesAreSequentialAndChained(t *testing.T) {
	w := newWorld(t)
	entries := w.record(4)
	var prev [32]byte
	for i, e := range entries {
		if e.Seq != uint64(i+1) {
			t.Fatalf("entry %d has sequence %d", i, e.Seq)
		}
		if e.PrevHash != prev {
			t.Fatalf("entry %d does not chain to its predecessor", e.Seq)
		}
		prev = e.Hash
	}
}

// ─── Tampering with the entries ─────────────────────────────────────────

func TestVerifyDetectsEveryEditToTheEntryRun(t *testing.T) {
	w := newWorld(t)
	entries := w.record(5)
	cp, err := w.log.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}

	edits := map[string]func([]Entry) []Entry{
		"flip a verdict": func(es []Entry) []Entry {
			es[1].Allow = !es[1].Allow
			return es
		},
		"rewrite a rule id": func(es []Entry) []Entry {
			es[2].RuleID = "allow-everything"
			return es
		},
		"repoint a request hash": func(es []Entry) []Entry {
			es[0].RequestHash[0] ^= 1
			return es
		},
		"repoint a decision hash": func(es []Entry) []Entry {
			es[3].DecisionHash[0] ^= 1
			return es
		},
		"change a policy version": func(es []Entry) []Entry {
			es[1].PolicyVersion = "2020.1"
			return es
		},
		"delete from the middle": func(es []Entry) []Entry {
			return append(es[:2:2], es[3:]...)
		},
		"reorder two entries": func(es []Entry) []Entry {
			es[1], es[2] = es[2], es[1]
			return es
		},
		"drop the tail": func(es []Entry) []Entry {
			return es[:3]
		},
		"drop the head": func(es []Entry) []Entry {
			return es[1:]
		},
		"duplicate an entry": func(es []Entry) []Entry {
			return append(es[:2:2], es[1:]...)
		},
		"renumber an entry": func(es []Entry) []Entry {
			es[2].Seq = 99
			return es
		},
		"splice in a fabricated entry": func(es []Entry) []Entry {
			forged := Entry{Seq: 6, Allow: true, RuleID: "allow-everything", PrevHash: es[4].Hash}
			forged.Hash = forged.ComputeHash() // internally consistent, still not ours
			return append(es[:5:5], forged)
		},
	}

	for name, edit := range edits {
		doctored := edit(append([]Entry(nil), entries...))
		if err := Verify(doctored, cp, w.engine.PublicKey()); err == nil {
			t.Errorf("%q must be detected", name)
		}
	}
}

// Recomputing the chain after an edit is the attacker's obvious next move.
// It defeats hash chaining alone, which is exactly why the checkpoint is
// signed by the enclave.
func TestRecomputingTheChainDoesNotSurviveTheCheckpoint(t *testing.T) {
	w := newWorld(t)
	entries := w.record(4)
	cp, err := w.log.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}

	// Rewrite the log wholesale: flip a verdict and rebuild every hash
	// after it so the chain is internally flawless.
	doctored := append([]Entry(nil), entries...)
	doctored[1].Allow = !doctored[1].Allow
	var prev [32]byte
	for i := range doctored {
		doctored[i].PrevHash = prev
		doctored[i].Hash = doctored[i].ComputeHash()
		prev = doctored[i].Hash
	}
	if _, err := replay(doctored); err != nil {
		t.Fatalf("test setup: the rebuilt chain should be internally valid: %v", err)
	}

	if err := Verify(doctored, cp, w.engine.PublicKey()); !errors.Is(err, ErrCheckpointMismatch) {
		t.Fatalf("a rebuilt chain must fail against the signed checkpoint, got %v", err)
	}
}

// ─── Tampering with the checkpoint ──────────────────────────────────────

func TestForgedCheckpointsAreRejected(t *testing.T) {
	w := newWorld(t)
	entries := w.record(3)
	cp, err := w.log.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}

	_, attackerKey, _ := ed25519.GenerateKey(rand.Reader)
	forged := Checkpoint{PolicyVersion: cp.PolicyVersion, Count: 3, Head: cp.Head, Counter: cp.Counter}
	forged.Signature = ed25519.Sign(attackerKey, forged.SignedBytes())
	if err := Verify(entries, forged, w.engine.PublicKey()); !errors.Is(err, ErrCheckpointSignature) {
		t.Fatalf("a checkpoint signed by another key must be rejected, got %v", err)
	}

	for name, mutate := range map[string]func(*Checkpoint){
		"count":          func(c *Checkpoint) { c.Count = 2 },
		"head":           func(c *Checkpoint) { c.Head[0] ^= 1 },
		"counter":        func(c *Checkpoint) { c.Counter = 99 },
		"policy version": func(c *Checkpoint) { c.PolicyVersion = "2020.1" },
		"nil signature":  func(c *Checkpoint) { c.Signature = nil },
		"short signature": func(c *Checkpoint) {
			c.Signature = c.Signature[:10]
		},
	} {
		tampered := cp
		mutate(&tampered)
		if err := Verify(entries, tampered, w.engine.PublicKey()); !errors.Is(err, ErrCheckpointSignature) {
			t.Errorf("altering the %s must break the checkpoint signature, got %v", name, err)
		}
	}
}

func TestVerifyRejectsMalformedVerificationKeys(t *testing.T) {
	w := newWorld(t)
	entries := w.record(2)
	cp, err := w.log.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []ed25519.PublicKey{nil, {}, {1, 2, 3}, make([]byte, 64)} {
		if err := Verify(entries, cp, key); !errors.Is(err, ErrCheckpointSignature) {
			t.Errorf("a malformed key must fail cleanly, got %v", err)
		}
	}
}

// A checkpoint only covers the entries that existed when it was taken.
func TestEntriesAddedAfterACheckpointNeedANewOne(t *testing.T) {
	w := newWorld(t)
	entries := w.record(3)
	early, err := w.log.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	entries = append(entries, w.record(2)...)

	if err := Verify(entries, early, w.engine.PublicKey()); !errors.Is(err, ErrCheckpointMismatch) {
		t.Fatalf("the old checkpoint must not cover new entries, got %v", err)
	}
	late, err := w.log.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(entries, late, w.engine.PublicKey()); err != nil {
		t.Fatalf("a fresh checkpoint must cover them: %v", err)
	}
}

// ─── Append-only consistency ────────────────────────────────────────────

func TestVerifyAppendOnlyAcceptsGrowthAndRejectsForks(t *testing.T) {
	w := newWorld(t)
	entries := w.record(3)
	older, err := w.log.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	entries = append(entries, w.record(3)...)
	newer, err := w.log.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyAppendOnly(entries, older, newer, w.engine.PublicKey()); err != nil {
		t.Fatalf("a log that only grew must verify: %v", err)
	}

	// A fork: an earlier checkpoint committing to a history the later one
	// does not contain. Only a compromised or duplicated signing identity
	// can produce this, and no amount of per-entry hashing would show it.
	forked := older
	forked.Head[0] ^= 1
	forked.Signature = w.engine.Sign(forked.SignedBytes())
	if err := VerifyAppendOnly(entries, forked, newer, w.engine.PublicKey()); !errors.Is(err, ErrCheckpointMismatch) {
		t.Fatalf("a forked history must be detected, got %v", err)
	}

	// Checkpoints presented out of order.
	if err := VerifyAppendOnly(entries, newer, older, w.engine.PublicKey()); err == nil {
		t.Fatal("a shrinking log must be rejected")
	}
}

func TestVerifyAppendOnlyHandlesAnEmptyStartingPoint(t *testing.T) {
	w := newWorld(t)
	older, err := w.log.Checkpoint() // zero entries
	if err != nil {
		t.Fatal(err)
	}
	entries := w.record(3)
	newer, err := w.log.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAppendOnly(entries, older, newer, w.engine.PublicKey()); err != nil {
		t.Fatalf("growth from an empty log must verify: %v", err)
	}
}

// ─── Restart, rollback, and the crash window ────────────────────────────

func TestRestartResumesTheSameChain(t *testing.T) {
	w := newWorld(t)
	entries := w.record(3)
	if _, err := w.log.Checkpoint(); err != nil {
		t.Fatal(err)
	}

	log, err := w.restart(t)
	if err != nil {
		t.Fatalf("a clean restart must reopen the log: %v", err)
	}
	if log.Count() != 3 {
		t.Fatalf("expected to resume at 3 entries, got %d", log.Count())
	}

	// The chain must continue, not restart: the next entry's predecessor is
	// the last entry from before the restart.
	var nonce [32]byte
	next := log.Append(w.engine.Decide(request("subject", "mfa"), nonce))
	if next.Seq != 4 || next.PrevHash != entries[2].Hash {
		t.Fatalf("the chain must continue across a restart, got seq %d", next.Seq)
	}
}

// The central rollback case: the host keeps a copy of the sealed state,
// lets the log advance, then serves the old copy back. The blob is
// genuinely sealed by this measurement and decrypts perfectly — it is
// simply not the current one.
func TestRollbackToAnEarlierCheckpointIsDetected(t *testing.T) {
	w := newWorld(t)
	w.record(3)
	if _, err := w.log.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	stale := append([]byte(nil), w.store.Blob...) // the host's snapshot

	w.record(3) // the decisions the host wants to erase
	if _, err := w.log.Checkpoint(); err != nil {
		t.Fatal(err)
	}

	w.store.Blob = stale
	if _, err := w.restart(t); !errors.Is(err, ErrRollback) {
		t.Fatalf("expected ErrRollback, got %v", err)
	}
}

// Rolling back by exactly one checkpoint is the case a naive crash
// tolerance would wave through. Because Checkpoint seals before it
// increments, a rollback always leaves the state *behind* the counter while
// a crash always leaves it *ahead* — so this needs no tolerance at all.
func TestSingleStepRollbackIsNotMistakenForACrash(t *testing.T) {
	w := newWorld(t)
	w.record(2)
	if _, err := w.log.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	stale := append([]byte(nil), w.store.Blob...)

	w.record(2)
	if _, err := w.log.Checkpoint(); err != nil { // exactly one checkpoint later
		t.Fatal(err)
	}

	w.store.Blob = stale
	_, err := w.restart(t)
	if !errors.Is(err, ErrRollback) {
		t.Fatalf("a one-checkpoint rollback must be a rollback, got %v", err)
	}
}

// Deleting the state entirely is the crudest version of the same attack.
// The platform counter remembers that checkpoints happened, so "no state"
// stops being consistent with "never started".
func TestDeletingTheSealedStateIsDetected(t *testing.T) {
	w := newWorld(t)
	w.record(2)
	if _, err := w.log.Checkpoint(); err != nil {
		t.Fatal(err)
	}

	w.store.Blob = nil
	if _, err := w.restart(t); !errors.Is(err, ErrRollback) {
		t.Fatalf("expected ErrRollback for deleted state, got %v", err)
	}
}

func TestCorruptOrForeignSealedStateIsRejected(t *testing.T) {
	w := newWorld(t)
	w.record(2)
	if _, err := w.log.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	good := append([]byte(nil), w.store.Blob...)

	// State sealed by a different workload on the same platform: a tampered
	// build cannot plant state for the genuine one.
	foreign := w.platform.Launch(tee.Image{
		Signer: "release", EngineVersion: "engine/test",
		PolicyJSON: []byte(`{"version":"evil","rules":[{"id":"r","effect":"allow","resources":["*"],"when":{}}]}`)})
	plantedBlob, err := foreign.Seal(encodeState(0, [32]byte{}, 1), tee.SealToMeasurement)
	if err != nil {
		t.Fatal(err)
	}

	for name, blob := range map[string][]byte{
		"garbage":                    []byte("not a sealed blob at all"),
		"truncated":                  good[:len(good)-2],
		"bit flipped":                flip(good),
		"sealed by another workload": plantedBlob,
	} {
		w.store.Blob = blob
		if _, err := w.restart(t); !errors.Is(err, ErrStateCorrupt) {
			t.Errorf("%s: expected ErrStateCorrupt, got %v", name, err)
		}
	}
}

// The benign half of the pair: a crash between sealing new state and
// advancing the counter. Nothing was lost, so Open repairs the lag and
// returns a working log rather than treating an unclean shutdown as an
// attack.
func TestCounterLagFromAnInterruptedCheckpointIsRepaired(t *testing.T) {
	w := newWorld(t)
	entries := w.record(2)

	// Hand-build the state an interrupted Checkpoint leaves behind: sealed
	// at counter 1, platform counter still 0.
	blob, err := w.enclave.Seal(encodeState(2, entries[1].Hash, 1), tee.SealToMeasurement)
	if err != nil {
		t.Fatal(err)
	}
	w.store.Blob = blob

	log, err := w.restart(t)
	if !errors.Is(err, ErrCounterLagged) {
		t.Fatalf("expected ErrCounterLagged, got %v", err)
	}
	if log == nil {
		t.Fatal("a lagged counter must still yield a usable log")
	}
	if log.Count() != 2 {
		t.Fatalf("no entries should be lost, got count %d", log.Count())
	}
	if got := w.enclave.CounterRead(counterName); got != 1 {
		t.Fatalf("Open must repair the counter, it is at %d", got)
	}
	// And the repaired log must reopen cleanly next time.
	if _, err := log.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.restart(t); err != nil {
		t.Fatalf("the repaired log must reopen cleanly: %v", err)
	}
}

// More than one ahead cannot come from a single interrupted checkpoint, so
// it means the platform's own counter state is suspect — which is not
// something to shrug off as a crash.
func TestStateFarAheadOfTheCounterIsRefused(t *testing.T) {
	w := newWorld(t)
	blob, err := w.enclave.Seal(encodeState(0, [32]byte{}, 5), tee.SealToMeasurement)
	if err != nil {
		t.Fatal(err)
	}
	w.store.Blob = blob
	if _, err := w.restart(t); !errors.Is(err, ErrStateCorrupt) {
		t.Fatalf("expected ErrStateCorrupt, got %v", err)
	}
}

// A tampered rebuild of the engine gets its own counter namespace, so it
// cannot read, advance, or interfere with the genuine log's counter — and
// it starts from a clean slate rather than inheriting a history.
func TestTamperedBuildCannotTouchTheGenuineLog(t *testing.T) {
	w := newWorld(t)
	w.record(3)
	if _, err := w.log.Checkpoint(); err != nil {
		t.Fatal(err)
	}

	tampered := w.platform.Launch(tee.Image{
		Signer: "release", EngineVersion: "engine/test",
		PolicyJSON: []byte(`{"version":"evil","rules":[{"id":"r","effect":"allow","resources":["*"],"when":{"min_auth":"password"}}]}`)})
	tamperedEngine, err := pdp.NewEngineInEnclave(tampered)
	if err != nil {
		t.Fatal(err)
	}

	// It cannot open the genuine store...
	if _, err := Open(tampered, tamperedEngine, w.store, "evil"); !errors.Is(err, ErrStateCorrupt) {
		t.Fatalf("a tampered build must not read the genuine sealed state, got %v", err)
	}
	// ...and whatever it does to its own counter leaves ours alone.
	tampered.CounterIncrement(counterName)
	tampered.CounterIncrement(counterName)
	if _, err := w.restart(t); err != nil {
		t.Fatalf("the genuine log must be unaffected: %v", err)
	}
}

// ─── Entry and decision digests ─────────────────────────────────────────

func TestDecisionHashSeparatesDistinctDecisions(t *testing.T) {
	w := newWorld(t)
	var nonce [32]byte
	allow := w.engine.Decide(request("alice", "mfa"), nonce)
	deny := w.engine.Decide(request("alice", "password"), nonce)

	if DecisionHash(allow) == DecisionHash(deny) {
		t.Fatal("different decisions must hash differently")
	}
	if DecisionHash(allow) != DecisionHash(allow) {
		t.Fatal("hashing must be deterministic")
	}

	// The signature is part of the digest, so an entry cannot be re-pointed
	// at a differently signed decision over identical content.
	resigned := allow
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	resigned.Signature = ed25519.Sign(other, allow.SignedBytes())
	if DecisionHash(resigned) == DecisionHash(allow) {
		t.Fatal("the decision signature must be inside the entry digest")
	}
}

func TestEntryHashCoversEveryField(t *testing.T) {
	base := Entry{
		Seq: 4, Allow: true, RuleID: "allow-mfa", PolicyVersion: "2026.1",
		RequestHash: [32]byte{1}, DecisionHash: [32]byte{2}, PrevHash: [32]byte{3},
	}
	base.Hash = base.ComputeHash()

	for name, mutate := range map[string]func(*Entry){
		"seq":            func(e *Entry) { e.Seq = 5 },
		"allow":          func(e *Entry) { e.Allow = false },
		"rule id":        func(e *Entry) { e.RuleID = "other" },
		"policy version": func(e *Entry) { e.PolicyVersion = "2020.1" },
		"request hash":   func(e *Entry) { e.RequestHash[0] ^= 1 },
		"decision hash":  func(e *Entry) { e.DecisionHash[0] ^= 1 },
		"prev hash":      func(e *Entry) { e.PrevHash[0] ^= 1 },
	} {
		other := base
		mutate(&other)
		if other.ComputeHash() == base.Hash {
			t.Errorf("the %s must be covered by the entry hash", name)
		}
	}
}

// ─── Concurrency ────────────────────────────────────────────────────────

// Decisions arrive from every enforcement point at once. Sequence numbers
// must not collide, and the chain must remain a chain.
func TestConcurrentAppendsProduceAValidChain(t *testing.T) {
	w := newWorld(t)
	const n = 100

	var wg sync.WaitGroup
	got := make([]Entry, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var nonce [32]byte
			nonce[0] = byte(i)
			got[i] = w.log.Append(w.engine.Decide(request("subject", "mfa"), nonce))
		}()
	}
	wg.Wait()

	// Reassemble by sequence number: concurrent callers get their entries
	// back in whatever order the scheduler chose, but the chain they form
	// must be complete and gap-free.
	ordered := make([]Entry, n)
	for _, e := range got {
		if e.Seq < 1 || e.Seq > n {
			t.Fatalf("sequence %d out of range", e.Seq)
		}
		if ordered[e.Seq-1].Seq != 0 {
			t.Fatalf("sequence %d was handed out twice", e.Seq)
		}
		ordered[e.Seq-1] = e
	}

	cp, err := w.log.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(ordered, cp, w.engine.PublicKey()); err != nil {
		t.Fatalf("concurrently appended entries must form a valid chain: %v", err)
	}
}

func TestConcurrentAppendsAndCheckpointsAreSafe(t *testing.T) {
	w := newWorld(t)
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var nonce [32]byte
			nonce[0] = byte(i)
			w.log.Append(w.engine.Decide(request("subject", "mfa"), nonce))
		}()
	}
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := w.log.Checkpoint(); err != nil {
				t.Error(err)
			}
			w.log.Count()
			w.log.Head()
		}()
	}
	wg.Wait()

	if _, err := w.restart(t); err != nil {
		t.Fatalf("the log must reopen cleanly after concurrent use: %v", err)
	}
}

func flip(b []byte) []byte {
	out := append([]byte(nil), b...)
	out[len(out)/2] ^= 1
	return out
}

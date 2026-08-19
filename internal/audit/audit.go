// Package audit gives VERITY a decision record that is worth as much as
// its decisions.
//
// A signed decision proves what the PDP said about one request. It says
// nothing about the set of decisions as a whole, and that is what auditors,
// incident responders, and regulators actually ask about: did anyone get
// into payroll last Tuesday? A host-level attacker who cannot forge a
// decision can still simply delete the ones that embarrass them, and a log
// that can be silently edited is not evidence.
//
// The log closes that gap in three layers, each defeating an attack the
// previous one leaves open:
//
//  1. Hash chaining. Every entry commits to its predecessor, so entries
//     cannot be altered, reordered, or removed from the middle without
//     breaking every hash after them.
//  2. Signed checkpoints. The enclave periodically signs (count, head) with
//     the same attested key that signs decisions. A chain alone can be
//     rewritten wholesale by anyone willing to recompute it; a signature
//     from an attested enclave cannot. This also makes *truncation*
//     detectable — dropping the last hour still leaves a chain that hashes
//     correctly, but no longer matches a checkpoint anyone holds.
//  3. Monotonic-counter binding. Checkpoints must persist across restarts,
//     so they are sealed and handed to the untrusted host, which is free to
//     serve back an older copy — a rollback that restores a genuinely
//     signed, genuinely consistent, but stale log. Each checkpoint advances
//     a platform counter the host cannot rewind, so a restored old state is
//     recognised on sight.
//
// Entries themselves live outside the enclave. The enclave keeps only the
// count and the chain head — constant memory for an unbounded log — which
// is both practical and the right trust model: the host may hold the
// records, it simply cannot change them undetected.
package audit

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/aabhimittal/zero-trust-confidential-computing/internal/canon"
	"github.com/aabhimittal/zero-trust-confidential-computing/internal/pdp"
	"github.com/aabhimittal/zero-trust-confidential-computing/internal/tee"
)

// counterName is the platform counter this log advances. Counters are
// namespaced per measurement, so a tampered rebuild of the engine cannot
// touch — or even observe — the genuine log's counter.
const counterName = "verity/audit/v1"

var (
	// ErrChainBroken: an entry does not hash to what the next entry
	// records as its predecessor. Something was altered, removed, or
	// reordered inside the run of entries presented.
	ErrChainBroken = errors.New("audit: entry chain is broken")

	// ErrCheckpointSignature: the checkpoint is not signed by the attested
	// key, so it proves nothing about who produced this history.
	ErrCheckpointSignature = errors.New("audit: checkpoint signature does not verify under the attested key")

	// ErrCheckpointMismatch: the entries are internally consistent but are
	// not the history the checkpoint commits to — the signature of
	// truncation, or of entries quietly appended by someone else.
	ErrCheckpointMismatch = errors.New("audit: entries do not match the signed checkpoint")

	// ErrRollback: the sealed state the host served back is older than the
	// platform counter says it should be. The host tried to rewind the log.
	ErrRollback = errors.New("audit: sealed log state is older than the platform counter permits")

	// ErrStateCorrupt: the sealed state exists but cannot be read as state
	// by this workload.
	ErrStateCorrupt = errors.New("audit: sealed log state is unreadable")

	// ErrCounterLagged: the sealed state is exactly one checkpoint ahead of
	// the platform counter — the fingerprint of a crash between saving new
	// state and advancing the counter.
	//
	// This is benign and unambiguous, and the ordering inside Checkpoint is
	// what makes it so. Because state is sealed before the counter moves,
	// an interrupted checkpoint can only ever leave the state *ahead*; a
	// rollback, which replays a blob the enclave sealed earlier, can only
	// ever leave it *behind*. The two conditions therefore never overlap,
	// and no tolerance has to be extended to the attacker's side. Open
	// repairs the lag, returns a fully usable log, and surfaces this so
	// that unexplained crash recovery in an audit system is still visible.
	ErrCounterLagged = errors.New("audit: platform counter lagged the sealed state; repaired")
)

// Signer is the enclave-resident signing capability the log borrows. It is
// satisfied by *pdp.Engine: the log deliberately speaks with the same key
// the PDP's decisions do, so a party that has attested the PDP needs no
// second trust decision to believe its audit trail.
type Signer interface {
	Sign(digest []byte) []byte
	PublicKey() ed25519.PublicKey
}

// Store is durable storage for the sealed checkpoint. It models the
// untrusted host filesystem, and the interface is small on purpose: the
// host can serve back anything it likes, including stale bytes, garbage, or
// nothing at all. Every one of those is a case the log must survive.
type Store interface {
	Load() ([]byte, error)
	Save([]byte) error
}

// MemStore is an in-memory Store for tests and the demo. Its exported field
// makes host tampering easy to express: snapshot Blob, let the log run, put
// the old bytes back.
type MemStore struct {
	Blob []byte
}

func (m *MemStore) Load() ([]byte, error) { return m.Blob, nil }

func (m *MemStore) Save(b []byte) error {
	m.Blob = append([]byte(nil), b...)
	return nil
}

// Entry is one decision's place in the chain. It carries enough of the
// decision to be read by a human, plus the digests that make it verifiable.
type Entry struct {
	Seq           uint64
	Allow         bool
	RuleID        string
	PolicyVersion string
	RequestHash   [32]byte
	// DecisionHash commits to the decision's signed content *and* its
	// signature, so the entry cannot be re-pointed at a different decision
	// that happens to concern the same request.
	DecisionHash [32]byte
	PrevHash     [32]byte
	Hash         [32]byte
}

// ComputeHash derives the entry's chain hash from its contents and its
// predecessor. Recomputing it is how verification detects any edit.
func (e Entry) ComputeHash() [32]byte {
	return canon.New("verity/audit/entry/v1").
		Uint64(e.Seq).
		Raw32(e.PrevHash).
		Bool(e.Allow).
		String(e.RuleID).
		String(e.PolicyVersion).
		Raw32(e.RequestHash).
		Raw32(e.DecisionHash).
		Sum()
}

// DecisionHash digests a decision together with its signature.
func DecisionHash(d pdp.Decision) [32]byte {
	return canon.New("verity/audit/decision/v1").
		Bytes(d.SignedBytes()).
		Bytes(d.Signature).
		Sum()
}

// Checkpoint is the enclave's signed statement about the whole log so far:
// "I have issued exactly Count entries, the last of which hashes to Head,
// and this is my Counter-th checkpoint."
type Checkpoint struct {
	PolicyVersion string
	Count         uint64
	Head          [32]byte
	Counter       uint64
	Signature     []byte
}

// SignedBytes is the canonical digest covered by the checkpoint signature.
func (c Checkpoint) SignedBytes() []byte {
	return canon.New("verity/audit/checkpoint/v1").
		String(c.PolicyVersion).
		Uint64(c.Count).
		Raw32(c.Head).
		Uint64(c.Counter).
		SumBytes()
}

// Log is the enclave-resident head of the audit chain. It is safe for
// concurrent use: decisions arrive from every enforcement point at once,
// and sequence numbers must not race.
type Log struct {
	mu      sync.Mutex
	enclave *tee.Enclave
	signer  Signer
	store   Store
	policy  string

	count   uint64
	head    [32]byte
	counter uint64
}

// Open recovers a log from sealed state, or starts a fresh one.
//
// It returns a usable *Log together with ErrCounterLagged when it detects
// the benign crash window; for every other inconsistency it returns a nil
// log and refuses to continue, because appending to a history you cannot
// vouch for produces a record that is worse than none.
func Open(enclave *tee.Enclave, signer Signer, store Store, policyVersion string) (*Log, error) {
	l := &Log{enclave: enclave, signer: signer, store: store, policy: policyVersion}

	platformCounter := enclave.CounterRead(counterName)
	blob, err := store.Load()
	if err != nil {
		return nil, fmt.Errorf("audit: loading sealed state: %w", err)
	}

	if len(blob) == 0 {
		// No state. That is only consistent with a log that has never
		// checkpointed: if the platform remembers checkpoints, the host
		// deleted the evidence of them.
		if platformCounter != 0 {
			return nil, fmt.Errorf("%w: no sealed state but platform counter is %d",
				ErrRollback, platformCounter)
		}
		return l, nil
	}

	plain, err := enclave.Unseal(blob)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStateCorrupt, err)
	}
	count, head, sealedCounter, err := decodeState(plain)
	if err != nil {
		return nil, err
	}

	l.count, l.head, l.counter = count, head, sealedCounter

	switch {
	case sealedCounter == platformCounter:
		return l, nil

	case sealedCounter == platformCounter+1:
		// Crash between sealing and incrementing. Nothing was lost — the
		// stored state is the newest one — so catch the counter up and
		// carry on, keeping the invariant that they agree after Open.
		enclave.CounterIncrement(counterName)
		return l, ErrCounterLagged

	case sealedCounter > platformCounter:
		// More than one ahead cannot arise from a single interrupted
		// checkpoint, so the platform's counter state itself is suspect.
		return nil, fmt.Errorf("%w: sealed state at counter %d, platform only at %d",
			ErrStateCorrupt, sealedCounter, platformCounter)

	default:
		// sealedCounter < platformCounter: the enclave sealed this blob at
		// some earlier point and the host served it back instead of the
		// current one.
		return nil, fmt.Errorf("%w: sealed state at counter %d, platform at %d",
			ErrRollback, sealedCounter, platformCounter)
	}
}

// Append records a decision and returns the entry, which the caller is
// expected to ship somewhere outside the enclave. Only the chain head stays
// in enclave memory.
func (l *Log) Append(d pdp.Decision) Entry {
	l.mu.Lock()
	defer l.mu.Unlock()

	e := Entry{
		Seq:           l.count + 1,
		Allow:         d.Allow,
		RuleID:        d.RuleID,
		PolicyVersion: d.PolicyVersion,
		RequestHash:   d.RequestHash,
		DecisionHash:  DecisionHash(d),
		PrevHash:      l.head,
	}
	e.Hash = e.ComputeHash()

	l.count, l.head = e.Seq, e.Hash
	return e
}

// Count reports how many entries the log has recorded.
func (l *Log) Count() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.count
}

// Head reports the current chain head.
func (l *Log) Head() [32]byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.head
}

// Checkpoint signs the current state, seals it to the host store, and only
// then advances the platform counter.
//
// That order is the load-bearing detail. It guarantees that an interrupted
// checkpoint leaves the sealed state one *ahead* of the counter, while a
// rollback — the host replaying a blob this enclave sealed at some earlier
// point — always leaves it *behind*. Because the two failure signatures
// point in opposite directions, Open can forgive crashes without forgiving
// anything an attacker can produce.
//
// Incrementing first would invert this: an attacker who restored the
// immediately preceding checkpoint would present exactly the state a crash
// produces, and any tolerance for unclean shutdown would become a
// one-checkpoint rollback that no one could detect.
func (l *Log) Checkpoint() (Checkpoint, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	next := l.counter + 1
	cp := Checkpoint{
		PolicyVersion: l.policy,
		Count:         l.count,
		Head:          l.head,
		Counter:       next,
	}
	cp.Signature = l.signer.Sign(cp.SignedBytes())

	blob, err := l.enclave.Seal(encodeState(l.count, l.head, next), tee.SealToMeasurement)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("audit: sealing state: %w", err)
	}
	if err := l.store.Save(blob); err != nil {
		return Checkpoint{}, fmt.Errorf("audit: saving sealed state: %w", err)
	}

	l.enclave.CounterIncrement(counterName)
	l.counter = next
	return cp, nil
}

// Verify is the auditor's function: it takes a run of entries and a signed
// checkpoint and decides whether the entries are exactly the history the
// attested enclave committed to.
//
// It requires the complete chain from sequence 1. A hash chain cannot prove
// membership of a fragment the way a Merkle tree can; the honest cost of
// this design's simplicity is that an auditor needs the whole log.
func Verify(entries []Entry, cp Checkpoint, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, cp.SignedBytes(), cp.Signature) {
		return ErrCheckpointSignature
	}
	head, err := replay(entries)
	if err != nil {
		return err
	}
	if uint64(len(entries)) != cp.Count {
		return fmt.Errorf("%w: %d entries presented, checkpoint commits to %d",
			ErrCheckpointMismatch, len(entries), cp.Count)
	}
	if head != cp.Head {
		return fmt.Errorf("%w: chain head %x… does not match checkpoint head %x…",
			ErrCheckpointMismatch, head[:8], cp.Head[:8])
	}
	return nil
}

// VerifyAppendOnly checks that a later checkpoint extends an earlier one
// over the same entries — that the log only ever grew.
//
// An enclave that signed two histories diverging at some sequence number
// would be evidence of key compromise or of two instances sharing an
// identity, neither of which any amount of per-entry hashing would reveal.
func VerifyAppendOnly(entries []Entry, older, newer Checkpoint, pub ed25519.PublicKey) error {
	if err := Verify(entries, newer, pub); err != nil {
		return err
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, older.SignedBytes(), older.Signature) {
		return ErrCheckpointSignature
	}
	if older.Count > newer.Count {
		return fmt.Errorf("%w: earlier checkpoint commits to %d entries, later one to %d",
			ErrCheckpointMismatch, older.Count, newer.Count)
	}
	if older.Counter > newer.Counter {
		return fmt.Errorf("%w: earlier checkpoint has counter %d, later one %d",
			ErrCheckpointMismatch, older.Counter, newer.Counter)
	}
	var wantHead [32]byte
	if older.Count > 0 {
		wantHead = entries[older.Count-1].Hash
	}
	if older.Head != wantHead {
		return fmt.Errorf("%w: history forked at entry %d", ErrCheckpointMismatch, older.Count)
	}
	return nil
}

// replay walks the chain from the beginning and returns the resulting head.
func replay(entries []Entry) ([32]byte, error) {
	var prev [32]byte
	for i, e := range entries {
		if e.Seq != uint64(i)+1 {
			return prev, fmt.Errorf("%w: entry %d carries sequence %d", ErrChainBroken, i+1, e.Seq)
		}
		if e.PrevHash != prev {
			return prev, fmt.Errorf("%w: entry %d does not follow its predecessor", ErrChainBroken, e.Seq)
		}
		if e.ComputeHash() != e.Hash {
			return prev, fmt.Errorf("%w: entry %d has been altered", ErrChainBroken, e.Seq)
		}
		prev = e.Hash
	}
	return prev, nil
}

// State is encoded as fixed-width fields rather than a self-describing
// format: it round-trips only inside the sealing envelope, and a fixed
// layout gives a decoder with no parsing surface at all.
const stateLen = 8 + 32 + 8

func encodeState(count uint64, head [32]byte, counter uint64) []byte {
	b := make([]byte, stateLen)
	binary.BigEndian.PutUint64(b[0:8], count)
	copy(b[8:40], head[:])
	binary.BigEndian.PutUint64(b[40:48], counter)
	return b
}

func decodeState(b []byte) (count uint64, head [32]byte, counter uint64, err error) {
	if len(b) != stateLen {
		return 0, head, 0, fmt.Errorf("%w: state is %d bytes, want %d", ErrStateCorrupt, len(b), stateLen)
	}
	count = binary.BigEndian.Uint64(b[0:8])
	copy(head[:], b[8:40])
	counter = binary.BigEndian.Uint64(b[40:48])
	return count, head, counter, nil
}

// Edge cases for enforcement: concurrency, attestation freshness, hostile
// decision channels, and quorum.
package pep

import (
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aabhimittal/zero-trust-confidential-computing/internal/attest"
	"github.com/aabhimittal/zero-trust-confidential-computing/internal/pdp"
	"github.com/aabhimittal/zero-trust-confidential-computing/internal/tee"
)

// ─── Concurrency ────────────────────────────────────────────────────────

// A gateway serves many requests at once while re-enrollment happens
// underneath it. A torn read of the pinned key mid-rotation would not just
// be a race: it would be a request judged against a key that never attested
// the engine that answered it.
func TestConcurrentAuthorizeAndReEnrollment(t *testing.T) {
	w := newWorld(t)
	if err := w.gateway.TrustPDP(w.engine); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, err := w.gateway.Authorize(goodRequest())
			// A concurrent re-enrollment may briefly leave no PDP pinned,
			// which is a legitimate fail-closed answer. Anything else is a
			// verified allow. There is no third possibility.
			switch {
			case err == nil && !d.Allow:
				t.Error("a verified decision for a valid request must allow")
			case err != nil && !errors.Is(err, ErrNoAttestedPDP) && !errors.Is(err, ErrBadDecision):
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = w.gateway.TrustPDP(w.engine)
			w.gateway.PDPBuild()
			w.gateway.Enrollments()
		}()
	}
	wg.Wait()
}

// A failed enrollment racing live traffic must drop the gateway to
// fail-closed rather than leaving a half-updated pin behind.
func TestConcurrentFailedEnrollmentNeverLeavesAPartialPin(t *testing.T) {
	w := newWorld(t)
	if err := w.gateway.TrustPDP(w.engine); err != nil {
		t.Fatal(err)
	}
	tampered, err := pdp.NewEngineInEnclave(w.platform.Launch(
		tee.Image{EngineVersion: "engine/test", PolicyJSON: []byte(backdooredPolicy)}))
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Whatever the interleaving, an unattested engine's verdict
			// must never be returned as a verified allow.
			if d, err := w.gateway.Authorize(badRequest()); err == nil && d.Allow {
				t.Error("a backdoored PDP's allow must never be honoured")
			}
		}()
	}
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = w.gateway.TrustPDP(tampered)
			_ = w.gateway.TrustPDP(w.engine)
		}()
	}
	wg.Wait()
}

// ─── Attestation freshness ──────────────────────────────────────────────

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestAttestationExpires(t *testing.T) {
	w := newWorld(t)
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	g := NewGateway(w.verifier, WithMaxAttestationAge(10*time.Minute), WithClock(clock.Now))
	if err := g.TrustPDP(w.engine); err != nil {
		t.Fatal(err)
	}

	clock.Advance(9 * time.Minute)
	if _, err := g.Authorize(goodRequest()); err != nil {
		t.Fatalf("inside the window the enrollment must hold: %v", err)
	}

	clock.Advance(2 * time.Minute) // now 11 minutes old
	if _, err := g.Authorize(goodRequest()); !errors.Is(err, ErrAttestationExpired) {
		t.Fatalf("expected ErrAttestationExpired, got %v", err)
	}

	// Re-attesting restores service without any other change.
	if err := g.TrustPDP(w.engine); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Authorize(goodRequest()); err != nil {
		t.Fatalf("a fresh handshake must restore service: %v", err)
	}
}

func TestExpiryBoundaryIsInclusive(t *testing.T) {
	w := newWorld(t)
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	g := NewGateway(w.verifier, WithMaxAttestationAge(time.Minute), WithClock(clock.Now))
	if err := g.TrustPDP(w.engine); err != nil {
		t.Fatal(err)
	}

	clock.Advance(time.Minute) // exactly at the limit
	if _, err := g.Authorize(goodRequest()); err != nil {
		t.Fatalf("an age exactly at the limit must still be accepted: %v", err)
	}
	clock.Advance(time.Nanosecond)
	if _, err := g.Authorize(goodRequest()); !errors.Is(err, ErrAttestationExpired) {
		t.Fatalf("one tick past the limit must expire, got %v", err)
	}
}

// If a clock running backwards read as "freshness", the cheapest way to
// keep a revoked PDP alive forever would be to wind the host's clock back.
func TestClockRunningBackwardsIsTreatedAsExpiry(t *testing.T) {
	w := newWorld(t)
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	g := NewGateway(w.verifier, WithMaxAttestationAge(10*time.Minute), WithClock(clock.Now))
	if err := g.TrustPDP(w.engine); err != nil {
		t.Fatal(err)
	}

	clock.Advance(-time.Hour)
	if _, err := g.Authorize(goodRequest()); !errors.Is(err, ErrAttestationExpired) {
		t.Fatalf("a backwards clock must not extend an enrollment, got %v", err)
	}
}

func TestZeroMaxAgeMeansNoExpiry(t *testing.T) {
	w := newWorld(t)
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	g := NewGateway(w.verifier, WithClock(clock.Now)) // no max age configured
	if err := g.TrustPDP(w.engine); err != nil {
		t.Fatal(err)
	}
	clock.Advance(100 * 365 * 24 * time.Hour)
	if _, err := g.Authorize(goodRequest()); err != nil {
		t.Fatalf("without a configured max age the enrollment must not expire: %v", err)
	}
}

// Expiry must not be confusable with having no PDP at all: the operator
// responses are different (re-attest vs investigate), so the errors are.
func TestExpiryAndAbsenceAreDistinctFailures(t *testing.T) {
	w := newWorld(t)
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	g := NewGateway(w.verifier, WithMaxAttestationAge(time.Minute), WithClock(clock.Now))

	if _, err := g.Authorize(goodRequest()); !errors.Is(err, ErrNoAttestedPDP) {
		t.Fatalf("before enrollment: expected ErrNoAttestedPDP, got %v", err)
	}
	if err := g.TrustPDP(w.engine); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Hour)
	if _, err := g.Authorize(goodRequest()); errors.Is(err, ErrNoAttestedPDP) {
		t.Fatal("an expired enrollment must not masquerade as never having had one")
	}
}

// ─── Key rotation ───────────────────────────────────────────────────────

// Each enclave generates a fresh decision key, so re-enrolling against a
// new instance must invalidate decisions from the old one — otherwise a
// decommissioned engine's signatures would outlive it.
func TestReEnrollmentRetiresTheOldDecisionKey(t *testing.T) {
	w := newWorld(t)
	if err := w.gateway.TrustPDP(w.engine); err != nil {
		t.Fatal(err)
	}

	replacement, err := pdp.NewEngineInEnclave(w.platform.Launch(
		tee.Image{EngineVersion: "engine/test", PolicyJSON: []byte(endorsedPolicy)}))
	if err != nil {
		t.Fatal(err)
	}
	if replacement.PublicKey().Equal(w.engine.PublicKey()) {
		t.Fatal("a relaunched enclave must generate a new decision key")
	}
	if err := w.gateway.TrustPDP(replacement); err != nil {
		t.Fatal(err)
	}

	// The retired engine now answers on the channel. Same measurement, same
	// endorsement — but not the key this gateway attested.
	if err := w.gateway.TrustPDP(&staleKeyService{attestor: replacement, decider: w.engine}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.gateway.Authorize(goodRequest()); !errors.Is(err, ErrBadDecision) {
		t.Fatalf("decisions from the retired key must be refused, got %v", err)
	}
}

// staleKeyService attests as one engine but answers with another's
// decisions — the shape of a botched rotation or a stale replica.
type staleKeyService struct {
	attestor *pdp.Engine
	decider  *pdp.Engine
}

func (s *staleKeyService) Attest(nonce [32]byte) (tee.Quote, ed25519.PublicKey) {
	return s.attestor.Attest(nonce)
}
func (s *staleKeyService) Decide(req pdp.Request, nonce [32]byte) pdp.Decision {
	return s.decider.Decide(req, nonce)
}

// ─── Hostile decision channels ──────────────────────────────────────────

// mutatingService relays genuine attestation and applies one mutation to
// every decision. The channel is the attacker's, so the PEP must survive
// arbitrary bytes on it without panicking and without granting anything.
type mutatingService struct {
	genuine *pdp.Engine
	mutate  func(*pdp.Decision)
}

func (m *mutatingService) Attest(nonce [32]byte) (tee.Quote, ed25519.PublicKey) {
	return m.genuine.Attest(nonce)
}
func (m *mutatingService) Decide(req pdp.Request, nonce [32]byte) pdp.Decision {
	d := m.genuine.Decide(req, nonce)
	m.mutate(&d)
	return d
}

func TestHostileDecisionsAreRefusedWithoutPanicking(t *testing.T) {
	mutations := map[string]func(*pdp.Decision){
		"zeroed entirely":  func(d *pdp.Decision) { *d = pdp.Decision{} },
		"nil signature":    func(d *pdp.Decision) { d.Signature = nil },
		"empty signature":  func(d *pdp.Decision) { d.Signature = []byte{} },
		"short signature":  func(d *pdp.Decision) { d.Signature = d.Signature[:8] },
		"long signature":   func(d *pdp.Decision) { d.Signature = make([]byte, 4096) },
		"flipped verdict":  func(d *pdp.Decision) { d.Allow = !d.Allow },
		"altered rule":     func(d *pdp.Decision) { d.RuleID = "maintenance-backdoor" },
		"altered reason":   func(d *pdp.Decision) { d.Reason = "approved by ops" },
		"altered version":  func(d *pdp.Decision) { d.PolicyVersion = "0.0.0" },
		"altered nonce":    func(d *pdp.Decision) { d.Nonce[0] ^= 1 },
		"zeroed nonce":     func(d *pdp.Decision) { d.Nonce = [32]byte{} },
		"altered req hash": func(d *pdp.Decision) { d.RequestHash[0] ^= 1 },
		"added obligation": func(d *pdp.Decision) { d.Obligations.ReadOnly = true },
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			svc := &mutatingService{genuine: w.engine, mutate: mutate}
			if err := w.gateway.TrustPDP(svc); err != nil {
				t.Fatalf("attestation is relayed genuinely, enrollment should pass: %v", err)
			}
			d, err := w.gateway.Authorize(goodRequest())
			if !errors.Is(err, ErrBadDecision) {
				t.Fatalf("expected ErrBadDecision, got %+v, %v", d, err)
			}
		})
	}
}

// A decision the PDP genuinely issued, for a genuinely different request,
// relayed for this one. Both the hash check and the signature must object.
func TestDecisionForAnotherRequestIsRefused(t *testing.T) {
	w := newWorld(t)
	svc := &crossBindService{genuine: w.engine}
	if err := w.gateway.TrustPDP(svc); err != nil {
		t.Fatal(err)
	}
	if _, err := w.gateway.Authorize(badRequest()); !errors.Is(err, ErrBadDecision) {
		t.Fatalf("expected ErrBadDecision, got %v", err)
	}
}

type crossBindService struct{ genuine *pdp.Engine }

func (s *crossBindService) Attest(nonce [32]byte) (tee.Quote, ed25519.PublicKey) {
	return s.genuine.Attest(nonce)
}

func (s *crossBindService) Decide(req pdp.Request, nonce [32]byte) pdp.Decision {
	// Genuinely signed, correct nonce — but answering alice's request while
	// mallory's is the one on the wire.
	return s.genuine.Decide(goodRequest(), nonce)
}

// A PDP that returns a wrong-length key cannot pass appraisal, but the
// gateway must refuse it explicitly rather than relying on that argument:
// pinning a malformed key would make ed25519.Verify panic on the request
// path.
func TestMalformedAttestedKeyIsNeverPinned(t *testing.T) {
	w := newWorld(t)
	for _, key := range []ed25519.PublicKey{nil, {}, {1, 2, 3}, make([]byte, 64)} {
		err := w.gateway.TrustPDP(&badKeyService{genuine: w.engine, key: key})
		if err == nil {
			t.Fatalf("a %d-byte key must not be pinned", len(key))
		}
		if _, err := w.gateway.Authorize(goodRequest()); !errors.Is(err, ErrNoAttestedPDP) {
			t.Fatalf("the gateway must stay fail-closed, got %v", err)
		}
	}
}

type badKeyService struct {
	genuine *pdp.Engine
	key     ed25519.PublicKey
}

func (s *badKeyService) Attest(nonce [32]byte) (tee.Quote, ed25519.PublicKey) {
	q, _ := s.genuine.Attest(nonce)
	return q, s.key
}
func (s *badKeyService) Decide(req pdp.Request, nonce [32]byte) pdp.Decision {
	return s.genuine.Decide(req, nonce)
}

// Every enrollment must challenge with a fresh nonce; a gateway that reused
// one would make captured quotes replayable indefinitely.
func TestEachEnrollmentUsesAFreshNonce(t *testing.T) {
	w := newWorld(t)
	rec := &nonceRecorder{genuine: w.engine}
	for range 20 {
		if err := w.gateway.TrustPDP(rec); err != nil {
			t.Fatal(err)
		}
	}
	seen := make(map[[32]byte]bool, len(rec.nonces))
	for _, n := range rec.nonces {
		if seen[n] {
			t.Fatal("an attestation nonce was reused")
		}
		seen[n] = true
	}
}

type nonceRecorder struct {
	genuine *pdp.Engine
	nonces  [][32]byte
}

func (r *nonceRecorder) Attest(nonce [32]byte) (tee.Quote, ed25519.PublicKey) {
	r.nonces = append(r.nonces, nonce)
	return r.genuine.Attest(nonce)
}
func (r *nonceRecorder) Decide(req pdp.Request, nonce [32]byte) pdp.Decision {
	return r.genuine.Decide(req, nonce)
}

func TestEnrollmentsAreCounted(t *testing.T) {
	w := newWorld(t)
	if w.gateway.Enrollments() != 0 {
		t.Fatal("a new gateway has no enrollments")
	}
	if err := w.gateway.TrustPDP(w.engine); err != nil {
		t.Fatal(err)
	}
	_ = w.gateway.TrustPDP(&quoteReplayer{genuine: w.engine}) // fails
	if got := w.gateway.Enrollments(); got != 1 {
		t.Fatalf("only successful enrollments count, got %d", got)
	}
}

// ─── Quorum ─────────────────────────────────────────────────────────────

// quorumWorld stands up n independently attested gateways over the given
// policies, all anchored to one platform and verifier.
func quorumWorld(t *testing.T, policies ...string) (*tee.Platform, []*Gateway, []*pdp.Engine) {
	t.Helper()
	platform := tee.NewPlatform(7)
	verifier := attest.NewVerifier(5, platform.AttestationRoot())

	gateways := make([]*Gateway, 0, len(policies))
	engines := make([]*pdp.Engine, 0, len(policies))
	for i, p := range policies {
		img := tee.Image{
			EngineVersion: "engine/test-" + string(rune('a'+i)),
			PolicyJSON:    []byte(p),
		}
		verifier.Endorse(tee.Measure(img), "build-"+string(rune('a'+i)))
		engine, err := pdp.NewEngineInEnclave(platform.Launch(img))
		if err != nil {
			t.Fatal(err)
		}
		g := NewGateway(verifier)
		if err := g.TrustPDP(engine); err != nil {
			t.Fatal(err)
		}
		gateways = append(gateways, g)
		engines = append(engines, engine)
	}
	return platform, gateways, engines
}

const laxPolicy = `{
  "version": "lax",
  "rules": [
    {"id": "allow-anyone-authenticated", "effect": "allow", "resources": ["payroll-db"],
     "when": {"min_auth": "password"}}
  ]
}`

func TestQuorumAgreesOnAllowAndDeny(t *testing.T) {
	_, gateways, _ := quorumWorld(t, endorsedPolicy, endorsedPolicy, endorsedPolicy)
	q, err := NewQuorum(3, gateways...)
	if err != nil {
		t.Fatal(err)
	}

	res, err := q.Authorize(goodRequest())
	if err != nil || !res.Decision.Allow {
		t.Fatalf("unanimous allow expected: %+v, %v", res, err)
	}
	if len(res.Concurring) != 3 || len(res.Builds) != 3 {
		t.Fatalf("every member's signed decision must be retained as evidence: %+v", res)
	}
	// Each concurring decision must be independently verifiable — the point
	// of a quorum is N signatures, not one signature repeated.
	for i := range res.Concurring {
		for j := range res.Concurring {
			if i != j && string(res.Concurring[i].Signature) == string(res.Concurring[j].Signature) {
				t.Fatal("concurring decisions must come from distinct signing keys")
			}
		}
	}

	res, err = q.Authorize(badRequest())
	if err != nil || res.Decision.Allow {
		t.Fatalf("unanimous deny expected: %+v, %v", res, err)
	}
}

// Dissent is the signal a single-PDP architecture structurally cannot
// produce: every member is attested and running endorsed code, so exactly
// one endorsement is wrong.
func TestQuorumRefusesToGuessWhenAttestedJudgesDisagree(t *testing.T) {
	_, gateways, _ := quorumWorld(t, endorsedPolicy, laxPolicy)
	q, err := NewQuorum(2, gateways...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.Authorize(badRequest()); !errors.Is(err, ErrQuorumDissent) {
		t.Fatalf("expected ErrQuorumDissent, got %v", err)
	}
}

// Agreement on the verdict but not on its conditions is not agreement on
// anything an enforcement point could act on.
func TestQuorumTreatsDifferingObligationsAsDissent(t *testing.T) {
	const readOnly = `{"version":"ro","rules":[
	  {"id":"allow","effect":"allow","resources":["payroll-db"],
	   "when":{"min_auth":"mfa","managed_device":true},
	   "obligations":{"read_only":true}}]}`
	const readWrite = `{"version":"rw","rules":[
	  {"id":"allow","effect":"allow","resources":["payroll-db"],
	   "when":{"min_auth":"mfa","managed_device":true}}]}`

	_, gateways, _ := quorumWorld(t, readOnly, readWrite)
	q, err := NewQuorum(2, gateways...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.Authorize(goodRequest()); !errors.Is(err, ErrQuorumDissent) {
		t.Fatalf("expected ErrQuorumDissent over obligations, got %v", err)
	}
}

func TestQuorumFailsClosedWhenMembersAreUnavailable(t *testing.T) {
	_, gateways, _ := quorumWorld(t, endorsedPolicy, endorsedPolicy, endorsedPolicy)
	q, err := NewQuorum(3, gateways...)
	if err != nil {
		t.Fatal(err)
	}

	// Knock one member out by giving it an unattestable PDP.
	other := tee.NewPlatform(7)
	rogue, err := pdp.NewEngineInEnclave(other.Launch(
		tee.Image{EngineVersion: "engine/test-a", PolicyJSON: []byte(endorsedPolicy)}))
	if err != nil {
		t.Fatal(err)
	}
	if err := gateways[2].TrustPDP(rogue); err == nil {
		t.Fatal("setup: a foreign platform must not enroll")
	}

	if _, err := q.Authorize(goodRequest()); !errors.Is(err, ErrQuorumUnavailable) {
		t.Fatalf("expected ErrQuorumUnavailable, got %v", err)
	}

	// A lower threshold accepts the survivors — the operator's call, made
	// explicitly rather than by silent degradation.
	tolerant, err := NewQuorum(2, gateways...)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := tolerant.Authorize(goodRequest()); err != nil || !res.Decision.Allow {
		t.Fatalf("two of three should satisfy a threshold of two: %v", err)
	}
}

// The attacker who cannot compromise several PDPs but can point several
// gateways at one they control. Their agreement is one opinion counted
// twice, and counting it twice is the whole exploit.
func TestQuorumRejectsMembersBackedByTheSamePDP(t *testing.T) {
	platform, gateways, engines := quorumWorld(t, endorsedPolicy, endorsedPolicy)
	_ = platform

	// Redirect the second gateway at the first gateway's engine.
	if err := gateways[1].TrustPDP(engines[0]); err != nil {
		t.Fatal(err)
	}
	q, err := NewQuorum(2, gateways...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.Authorize(goodRequest()); !errors.Is(err, ErrQuorumNotDiverse) {
		t.Fatalf("expected ErrQuorumNotDiverse, got %v", err)
	}
}

func TestQuorumConstructionRejectsImpossibleThresholds(t *testing.T) {
	_, gateways, _ := quorumWorld(t, endorsedPolicy, endorsedPolicy)
	for _, threshold := range []int{0, -1, 3, 100} {
		if _, err := NewQuorum(threshold, gateways...); err == nil {
			t.Errorf("threshold %d must be rejected", threshold)
		}
	}
	if _, err := NewQuorum(1); err == nil {
		t.Error("a quorum with no members must be rejected")
	}
}

func TestQuorumHonoursObligationsFromAgreeingMembers(t *testing.T) {
	const p = `{"version":"ro","rules":[
	  {"id":"allow","effect":"allow","resources":["payroll-db"],
	   "when":{"min_auth":"mfa","managed_device":true},
	   "obligations":{"read_only":true,"mask_fields":["ssn"]}}]}`

	_, gateways, _ := quorumWorld(t, p, p)
	q, err := NewQuorum(2, gateways...)
	if err != nil {
		t.Fatal(err)
	}
	res, err := q.Authorize(goodRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Decision.Allow || !res.Decision.Obligations.ReadOnly {
		t.Fatalf("the agreed obligations must survive into the result: %+v", res.Decision)
	}
}

// A quorum must not become a way to launder an expired enrollment: a
// member whose attestation has gone stale stops voting, and if that drops
// the count below the threshold the quorum fails closed.
func TestQuorumRespectsMemberExpiry(t *testing.T) {
	platform := tee.NewPlatform(7)
	verifier := attest.NewVerifier(5, platform.AttestationRoot())
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}

	newMember := func(version string, opts ...Option) *Gateway {
		t.Helper()
		img := tee.Image{EngineVersion: version, PolicyJSON: []byte(endorsedPolicy)}
		verifier.Endorse(tee.Measure(img), version)
		engine, err := pdp.NewEngineInEnclave(platform.Launch(img))
		if err != nil {
			t.Fatal(err)
		}
		g := NewGateway(verifier, opts...)
		if err := g.TrustPDP(engine); err != nil {
			t.Fatal(err)
		}
		return g
	}

	stable := newMember("engine/stable")
	expiring := newMember("engine/expiring",
		WithMaxAttestationAge(time.Minute), WithClock(clock.Now))

	q, err := NewQuorum(2, stable, expiring)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.Authorize(goodRequest()); err != nil {
		t.Fatalf("with both members fresh the quorum must form: %v", err)
	}

	clock.Advance(time.Hour)
	if _, err := q.Authorize(goodRequest()); !errors.Is(err, ErrQuorumUnavailable) {
		t.Fatalf("an expired member must stop counting toward the quorum, got %v", err)
	}
}

// Package pep is the Policy Enforcement Point: the gateway that sits in
// front of a protected resource and enforces the PDP's decisions.
//
// A conventional PEP trusts its PDP by network position or a TLS
// certificate — which says who the PDP claims to be, not what code it is
// running. VERITY's PEP holds a stronger line, in three phases:
//
// Enrollment (TrustPDP): the PEP challenges the PDP with a fresh nonce and
// appraises the returned quote. Only if the hardware signature, revocation
// status, TCB level, endorsed measurement, and key/nonce binding all check
// out does the PEP pin the PDP's decision-signing key. The pinned key is
// now transitively trustworthy: it is vouched for by attested code, which
// is vouched for by hardware, which is vouched for by the silicon vendor.
//
// Expiry: attestation is a statement about a moment, not a standing fact.
// A gateway configured with a maximum attestation age stops honouring an
// enrollment once it goes stale, forcing the PDP to prove itself again.
//
// Enforcement (Authorize): every request gets its own nonce; the returned
// decision must be signed by the pinned key over this exact request hash
// and this exact nonce. An altered verdict, a decision stripped of its
// obligations, a decision for a different request, a replayed old decision,
// or a decision from an unattested engine all fail the same signature
// check.
//
// The failure mode is fail-closed: no attested PDP, no access — a missing
// judge is a deny, never a pass-through.
//
// A Gateway is safe for concurrent use. That is not incidental: a gateway
// serves many requests at once while re-enrollment happens underneath it,
// and a torn read of the pinned key during a re-enrollment would be a
// security bug, not just a race.
package pep

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aabhimittal/zero-trust-confidential-computing/internal/attest"
	"github.com/aabhimittal/zero-trust-confidential-computing/internal/pdp"
	"github.com/aabhimittal/zero-trust-confidential-computing/internal/tee"
)

var (
	// ErrNoAttestedPDP: enforcement was attempted before any PDP passed
	// attestation. Fail closed.
	ErrNoAttestedPDP = errors.New("pep: no attested PDP enrolled; denying by default")

	// ErrAttestationExpired: a PDP was attested, but too long ago to still
	// count. The enrollment must be repeated before decisions are honoured
	// again.
	ErrAttestationExpired = errors.New("pep: attestation is older than this gateway accepts")

	// ErrBadDecision: a decision arrived that the pinned attested key did
	// not produce for this request and nonce — forged, altered, replayed,
	// or from a different (untrusted) engine.
	ErrBadDecision = errors.New("pep: decision signature invalid under the attested PDP key")
)

// PolicyService is the PEP's channel to a PDP. In production this is a
// network connection (and therefore attacker-reachable); modeling it as an
// interface lets the tests and demo interpose exactly the attacks a
// network adversary could mount.
type PolicyService interface {
	// Attest answers an attestation challenge with a quote and the
	// decision-verification key the quote binds.
	Attest(nonce [32]byte) (tee.Quote, ed25519.PublicKey)
	// Decide evaluates a request and returns a decision echoing the nonce.
	Decide(req pdp.Request, nonce [32]byte) pdp.Decision
}

// Option configures a Gateway at construction.
type Option func(*Gateway)

// WithMaxAttestationAge makes enrollments expire. Zero (the default) means
// an enrollment never ages out on its own.
func WithMaxAttestationAge(d time.Duration) Option {
	return func(g *Gateway) { g.maxAge = d }
}

// WithClock replaces the time source, so expiry is testable without
// sleeping and so a deployment can supply a monotonic clock.
func WithClock(now func() time.Time) Option {
	return func(g *Gateway) { g.now = now }
}

// Gateway is the enforcement point for one protected resource set.
type Gateway struct {
	mu       sync.RWMutex
	verifier *attest.Verifier
	pdp      PolicyService
	// pinnedKey is only ever set by a successful TrustPDP appraisal —
	// that invariant is the entire security argument of this package.
	pinnedKey   ed25519.PublicKey
	pdpBuild    string
	enrolledAt  time.Time
	enrollments int

	maxAge time.Duration
	now    func() time.Time
}

// NewGateway creates a gateway that will appraise PDPs with the given
// verifier.
func NewGateway(v *attest.Verifier, opts ...Option) *Gateway {
	g := &Gateway{verifier: v, now: time.Now}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// TrustPDP runs the enrollment handshake. On any appraisal failure the
// gateway keeps (or reverts to) its no-PDP state and returns the precise
// broken link in the trust chain.
func (g *Gateway) TrustPDP(svc PolicyService) error {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}

	// The handshake itself runs outside the lock: it talks to a remote
	// party over an attacker-controlled channel, and holding a gateway-wide
	// lock across that would let a slow or hostile PDP stall every request
	// in flight.
	quote, pub := svc.Attest(nonce)

	// Recompute the report data the genuine handshake would have produced
	// for this key and this nonce; the quote must match it exactly.
	build, err := g.verifier.Appraise(quote, tee.KeyBinding(pub, nonce))
	if err == nil && len(pub) != ed25519.PublicKeySize {
		// Unreachable through a successful appraisal — matching report data
		// already implies a 32-byte key — but pinning a key of the wrong
		// length would make ed25519.Verify panic on the request path, so
		// the invariant is enforced here rather than argued about.
		err = fmt.Errorf("%w: attested key is %d bytes", attest.ErrReportDataMismatch, len(pub))
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if err != nil {
		g.pdp, g.pinnedKey, g.pdpBuild = nil, nil, ""
		return fmt.Errorf("pep: refusing PDP: %w", err)
	}

	g.pdp, g.pinnedKey, g.pdpBuild = svc, pub, build
	g.enrolledAt = g.now()
	g.enrollments++
	return nil
}

// PDPBuild reports the endorsement name of the currently trusted PDP
// build, or "" if none is enrolled.
func (g *Gateway) PDPBuild() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.pdpBuild
}

// Enrollments counts successful attestation handshakes, which is how a
// deployment can alert on a PDP that keeps needing to re-attest.
func (g *Gateway) Enrollments() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.enrollments
}

// Authorize asks the attested PDP to decide the request, verifies the
// decision actually came from it, and enforces the verdict. The returned
// decision is safe to log and audit: its signature proves which code
// produced it.
func (g *Gateway) Authorize(req pdp.Request) (pdp.Decision, error) {
	// Snapshot the enrollment under the read lock, then release it before
	// calling out to the PDP. Everything the verification needs is in the
	// snapshot, so a concurrent re-enrollment can neither tear this check
	// nor be blocked by it: this request is judged against the enrollment
	// that was current when it started.
	g.mu.RLock()
	svc, key, enrolledAt, maxAge := g.pdp, g.pinnedKey, g.enrolledAt, g.maxAge
	g.mu.RUnlock()

	if svc == nil {
		return pdp.Decision{}, ErrNoAttestedPDP
	}
	if maxAge > 0 {
		// A clock that has gone backwards is treated as expiry rather than
		// freshness. Otherwise the cheapest way to keep a revoked PDP alive
		// forever would be to move the host's clock backwards.
		if age := g.now().Sub(enrolledAt); age < 0 || age > maxAge {
			return pdp.Decision{}, fmt.Errorf("%w: attested %s ago, limit %s",
				ErrAttestationExpired, age.Round(time.Millisecond), maxAge)
		}
	}

	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return pdp.Decision{}, err
	}

	d := svc.Decide(req, nonce)

	// Bind-check before believing anything in d: the signature must
	// verify under the attested key, over our request hash and our nonce.
	if d.Nonce != nonce || d.RequestHash != pdp.HashRequest(req) ||
		!ed25519.Verify(key, d.SignedBytes(), d.Signature) {
		return pdp.Decision{}, ErrBadDecision
	}
	return d, nil
}

// ─── Quorum enforcement ─────────────────────────────────────────────────
//
// Attestation proves a PDP is running the build you endorsed. It cannot
// prove the build you endorsed is correct. A logic bug in the policy
// engine, or a policy that says something its authors did not intend, is
// faithfully attested and faithfully wrong — and every gateway in the fleet
// agrees with it, because they are all running the same code.
//
// A quorum answers a different question: do several independently attested
// judges, ideally built and run independently, reach the same verdict?
// Disagreement then becomes a signal in its own right — the one signal a
// single-PDP architecture structurally cannot produce.

var (
	// ErrQuorumUnavailable: too few members returned a verifiable decision.
	// Fail closed — a quorum that degrades to "whoever answered" is not a
	// quorum.
	ErrQuorumUnavailable = errors.New("pep: too few attested PDPs responded to form a quorum")

	// ErrQuorumDissent: attested PDPs returned conflicting verdicts. Every
	// member is running endorsed code, so exactly one of the endorsements
	// is wrong. Denying is the only safe response, and the event deserves
	// an incident rather than a retry.
	ErrQuorumDissent = errors.New("pep: attested PDPs disagreed; refusing to guess")

	// ErrQuorumNotDiverse: two members are backed by the same PDP instance,
	// so their agreement is one opinion counted twice. This is what an
	// attacker does when they cannot compromise several PDPs but can
	// redirect several gateways at one they control.
	ErrQuorumNotDiverse = errors.New("pep: quorum members share a PDP identity; agreement would be double-counted")
)

// Quorum requires several independently attested gateways to agree.
type Quorum struct {
	members   []*Gateway
	threshold int
}

// QuorumResult carries the agreed verdict along with the evidence behind
// it: every concurring decision, each independently signed by a different
// attested engine, and the build names those engines attested to.
type QuorumResult struct {
	Decision   pdp.Decision
	Concurring []pdp.Decision
	Builds     []string
}

// NewQuorum builds a quorum requiring threshold agreeing members.
func NewQuorum(threshold int, members ...*Gateway) (*Quorum, error) {
	if threshold < 1 {
		return nil, errors.New("pep: quorum threshold must be at least 1")
	}
	if threshold > len(members) {
		return nil, fmt.Errorf("pep: quorum threshold %d exceeds %d members", threshold, len(members))
	}
	return &Quorum{members: members, threshold: threshold}, nil
}

// Authorize collects verified decisions from every member and returns one
// only if enough distinct, attested engines agree completely.
//
// "Completely" includes obligations: two engines that both say allow but
// disagree on whether the grant is read-only have not agreed on anything an
// enforcement point could safely act on.
func (q *Quorum) Authorize(req pdp.Request) (QuorumResult, error) {
	var (
		result   QuorumResult
		seenKeys [][]byte
	)

	for _, m := range q.members {
		d, err := m.Authorize(req)
		if err != nil {
			continue // an unavailable or unattested member simply does not vote
		}

		m.mu.RLock()
		key, build := m.pinnedKey, m.pdpBuild
		m.mu.RUnlock()

		for _, seen := range seenKeys {
			if bytes.Equal(seen, key) {
				return QuorumResult{}, fmt.Errorf("%w: build %q counted twice", ErrQuorumNotDiverse, build)
			}
		}
		seenKeys = append(seenKeys, key)

		if len(result.Concurring) > 0 {
			first := result.Concurring[0]
			if d.Allow != first.Allow || !d.Obligations.Equal(first.Obligations) {
				return QuorumResult{}, fmt.Errorf("%w: %q returned allow=%v/%s, %q returned allow=%v/%s",
					ErrQuorumDissent,
					result.Builds[0], first.Allow, first.Obligations,
					build, d.Allow, d.Obligations)
			}
		}
		result.Concurring = append(result.Concurring, d)
		result.Builds = append(result.Builds, build)
	}

	if len(result.Concurring) < q.threshold {
		return QuorumResult{}, fmt.Errorf("%w: %d of %d members responded, need %d",
			ErrQuorumUnavailable, len(result.Concurring), len(q.members), q.threshold)
	}
	result.Decision = result.Concurring[0]
	return result, nil
}

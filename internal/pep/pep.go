// Package pep is the Policy Enforcement Point: the gateway that sits in
// front of a protected resource and enforces the PDP's decisions.
//
// A conventional PEP trusts its PDP by network position or a TLS
// certificate — which says who the PDP claims to be, not what code it is
// running. VERITY's PEP holds a stronger line, in two phases:
//
// Enrollment (TrustPDP): the PEP challenges the PDP with a fresh nonce and
// appraises the returned quote. Only if the hardware signature, TCB level,
// endorsed measurement, and key/nonce binding all check out does the PEP
// pin the PDP's decision-signing key. The pinned key is now transitively
// trustworthy: it is vouched for by attested code, which is vouched for by
// hardware, which is vouched for by the silicon vendor.
//
// Enforcement (Authorize): every request gets its own nonce; the returned
// decision must be signed by the pinned key over this exact request hash
// and this exact nonce. An altered verdict, a decision for a different
// request, a replayed old decision, or a decision from an unattested
// engine all fail the same signature check.
//
// The failure mode is fail-closed: no attested PDP, no access — a missing
// judge is a deny, never a pass-through.
package pep

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/aabhimittal/zero-trust-confidential-computing/internal/attest"
	"github.com/aabhimittal/zero-trust-confidential-computing/internal/pdp"
	"github.com/aabhimittal/zero-trust-confidential-computing/internal/tee"
)

var (
	// ErrNoAttestedPDP: enforcement was attempted before any PDP passed
	// attestation. Fail closed.
	ErrNoAttestedPDP = errors.New("pep: no attested PDP enrolled; denying by default")

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

// Gateway is the enforcement point for one protected resource set.
type Gateway struct {
	verifier *attest.Verifier
	pdp      PolicyService
	// pinnedKey is only ever set by a successful TrustPDP appraisal —
	// that invariant is the entire security argument of this package.
	pinnedKey   ed25519.PublicKey
	pdpBuild    string
	enrollments int
}

// NewGateway creates a gateway that will appraise PDPs with the given
// verifier.
func NewGateway(v *attest.Verifier) *Gateway {
	return &Gateway{verifier: v}
}

// TrustPDP runs the enrollment handshake. On any appraisal failure the
// gateway keeps (or reverts to) its no-PDP state and returns the precise
// broken link in the trust chain.
func (g *Gateway) TrustPDP(svc PolicyService) error {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}

	quote, pub := svc.Attest(nonce)

	// Recompute the report data the genuine handshake would have produced
	// for this key and this nonce; the quote must match it exactly.
	build, err := g.verifier.Appraise(quote, tee.KeyBinding(pub, nonce))
	if err != nil {
		g.pdp, g.pinnedKey, g.pdpBuild = nil, nil, ""
		return fmt.Errorf("pep: refusing PDP: %w", err)
	}

	g.pdp, g.pinnedKey, g.pdpBuild = svc, pub, build
	g.enrollments++
	return nil
}

// PDPBuild reports the endorsement name of the currently trusted PDP
// build, or "" if none is enrolled.
func (g *Gateway) PDPBuild() string { return g.pdpBuild }

// Authorize asks the attested PDP to decide the request, verifies the
// decision actually came from it, and enforces the verdict. The returned
// decision is safe to log and audit: its signature proves which code
// produced it.
func (g *Gateway) Authorize(req pdp.Request) (pdp.Decision, error) {
	if g.pdp == nil {
		return pdp.Decision{}, ErrNoAttestedPDP
	}

	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return pdp.Decision{}, err
	}

	d := g.pdp.Decide(req, nonce)

	// Bind-check before believing anything in d: the signature must
	// verify under the attested key, over our request hash and our nonce.
	if d.Nonce != nonce || d.RequestHash != pdp.HashRequest(req) ||
		!ed25519.Verify(g.pinnedKey, d.SignedBytes(), d.Signature) {
		return pdp.Decision{}, ErrBadDecision
	}
	return d, nil
}

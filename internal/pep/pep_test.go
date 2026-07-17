// End-to-end tests: the full trust chain from platform to enforced
// decision, and the three attack classes the architecture must defeat.
package pep

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/aabhimittal/zero-trust-confidential-computing/internal/attest"
	"github.com/aabhimittal/zero-trust-confidential-computing/internal/pdp"
	"github.com/aabhimittal/zero-trust-confidential-computing/internal/tee"
)

const endorsedPolicy = `{
  "version": "test",
  "rules": [
    {"id": "allow-mfa-managed", "effect": "allow", "resources": ["payroll-db"],
     "when": {"min_auth": "mfa", "managed_device": true}}
  ]
}`

const backdooredPolicy = `{
  "version": "test",
  "rules": [
    {"id": "maintenance-backdoor", "effect": "allow", "resources": ["*"], "when": {}}
  ]
}`

type world struct {
	platform *tee.Platform
	verifier *attest.Verifier
	gateway  *Gateway
	engine   *pdp.Engine
}

func newWorld(t *testing.T) *world {
	t.Helper()
	platform := tee.NewPlatform(7)
	endorsed := tee.Image{EngineVersion: "engine/test", PolicyJSON: []byte(endorsedPolicy)}

	verifier := attest.NewVerifier(5, platform.AttestationRoot())
	verifier.Endorse(tee.Measure(endorsed), "endorsed-build")

	engine, err := pdp.NewEngineInEnclave(platform.Launch(endorsed))
	if err != nil {
		t.Fatal(err)
	}
	return &world{
		platform: platform,
		verifier: verifier,
		gateway:  NewGateway(verifier),
		engine:   engine,
	}
}

func goodRequest() pdp.Request {
	return pdp.Request{
		Subject:  pdp.Subject{ID: "alice", Roles: []string{"admin"}, AuthMethod: "mfa"},
		Device:   pdp.Device{Managed: true, OSPatched: true, DiskEncrypted: true},
		Resource: pdp.Resource{Name: "payroll-db", Sensitivity: 3},
		Context:  pdp.Context{Network: "corp"},
	}
}

func badRequest() pdp.Request {
	r := goodRequest()
	r.Subject = pdp.Subject{ID: "mallory", AuthMethod: "password"}
	r.Device = pdp.Device{}
	return r
}

func TestEndToEndAllowAndDeny(t *testing.T) {
	w := newWorld(t)
	if err := w.gateway.TrustPDP(w.engine); err != nil {
		t.Fatalf("genuine PDP must enroll: %v", err)
	}
	if w.gateway.PDPBuild() != "endorsed-build" {
		t.Fatalf("gateway should report the endorsed build, got %q", w.gateway.PDPBuild())
	}

	d, err := w.gateway.Authorize(goodRequest())
	if err != nil || !d.Allow {
		t.Fatalf("expected verified allow, got %+v, %v", d, err)
	}
	d, err = w.gateway.Authorize(badRequest())
	if err != nil || d.Allow {
		t.Fatalf("expected verified deny, got %+v, %v", d, err)
	}
}

func TestFailClosedBeforeEnrollment(t *testing.T) {
	w := newWorld(t)
	if _, err := w.gateway.Authorize(goodRequest()); !errors.Is(err, ErrNoAttestedPDP) {
		t.Fatalf("gateway without an attested PDP must deny, got %v", err)
	}
}

// Attack 1: host attacker relaunches the PDP with a backdoored policy. The
// measurement honestly reports the new bytes and enrollment must fail —
// and a previously trusted gateway must drop back to fail-closed.
func TestTamperedPDPRejected(t *testing.T) {
	w := newWorld(t)
	if err := w.gateway.TrustPDP(w.engine); err != nil {
		t.Fatal(err)
	}

	tampered, err := pdp.NewEngineInEnclave(w.platform.Launch(
		tee.Image{EngineVersion: "engine/test", PolicyJSON: []byte(backdooredPolicy)}))
	if err != nil {
		t.Fatal(err)
	}
	// Sanity: the tampered PDP itself would allow anything.
	var n [32]byte
	if d := tampered.Decide(badRequest(), n); !d.Allow {
		t.Fatal("test setup: backdoored policy should allow mallory")
	}

	if err := w.gateway.TrustPDP(tampered); !errors.Is(err, attest.ErrUnknownMeasurement) {
		t.Fatalf("expected ErrUnknownMeasurement, got %v", err)
	}
	if _, err := w.gateway.Authorize(badRequest()); !errors.Is(err, ErrNoAttestedPDP) {
		t.Fatalf("gateway must fail closed after rejecting a PDP, got %v", err)
	}
}

// quoteReplayer implements Attack 2: replays a genuine quote captured
// under an old nonce.
type quoteReplayer struct{ genuine *pdp.Engine }

func (a *quoteReplayer) Attest(nonce [32]byte) (tee.Quote, ed25519.PublicKey) {
	oldNonce := [32]byte{1, 2, 3}
	return a.genuine.Attest(oldNonce)
}
func (a *quoteReplayer) Decide(req pdp.Request, nonce [32]byte) pdp.Decision {
	panic("unreachable")
}

func TestReplayedQuoteRejected(t *testing.T) {
	w := newWorld(t)
	err := w.gateway.TrustPDP(&quoteReplayer{genuine: w.engine})
	if !errors.Is(err, attest.ErrReportDataMismatch) {
		t.Fatalf("expected ErrReportDataMismatch, got %v", err)
	}
}

// decisionForger implements Attack 3: genuine attestation passes through,
// but decisions are forged with an attacker key.
type decisionForger struct{ genuine *pdp.Engine }

func (a *decisionForger) Attest(nonce [32]byte) (tee.Quote, ed25519.PublicKey) {
	return a.genuine.Attest(nonce)
}
func (a *decisionForger) Decide(req pdp.Request, nonce [32]byte) pdp.Decision {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	d := pdp.Decision{
		Allow:       true,
		RuleID:      "forged",
		Reason:      "forged",
		RequestHash: pdp.HashRequest(req),
		Nonce:       nonce,
	}
	d.Signature = ed25519.Sign(key, d.SignedBytes())
	return d
}

func TestForgedDecisionRejected(t *testing.T) {
	w := newWorld(t)
	if err := w.gateway.TrustPDP(&decisionForger{genuine: w.engine}); err != nil {
		t.Fatalf("forger relays genuine attestation, enrollment should pass: %v", err)
	}
	if _, err := w.gateway.Authorize(badRequest()); !errors.Is(err, ErrBadDecision) {
		t.Fatalf("expected ErrBadDecision, got %v", err)
	}
}

// decisionReplayer answers every request with a previously captured ALLOW
// decision — testing that per-request nonces make old decisions single-use.
type decisionReplayer struct {
	genuine  *pdp.Engine
	captured *pdp.Decision
}

func (a *decisionReplayer) Attest(nonce [32]byte) (tee.Quote, ed25519.PublicKey) {
	return a.genuine.Attest(nonce)
}
func (a *decisionReplayer) Decide(req pdp.Request, nonce [32]byte) pdp.Decision {
	if a.captured == nil {
		d := a.genuine.Decide(req, nonce)
		if d.Allow {
			a.captured = &d
		}
		return d
	}
	return *a.captured
}

func TestReplayedDecisionRejected(t *testing.T) {
	w := newWorld(t)
	replayer := &decisionReplayer{genuine: w.engine}
	if err := w.gateway.TrustPDP(replayer); err != nil {
		t.Fatal(err)
	}

	// First request flows through and gets captured.
	if d, err := w.gateway.Authorize(goodRequest()); err != nil || !d.Allow {
		t.Fatalf("first authorize should succeed: %+v, %v", d, err)
	}
	// Replay of alice's ALLOW for mallory's request: the captured decision
	// carries the old nonce and old request hash, so it must die.
	if _, err := w.gateway.Authorize(badRequest()); !errors.Is(err, ErrBadDecision) {
		t.Fatalf("expected ErrBadDecision for replayed decision, got %v", err)
	}
}

// Attack on the platform itself: a whole fake "TEE" built in software.
func TestFakePlatformRejected(t *testing.T) {
	w := newWorld(t)

	fakePlatform := tee.NewPlatform(7) // attacker's own root, not the trusted one
	endorsedBytes := tee.Image{EngineVersion: "engine/test", PolicyJSON: []byte(endorsedPolicy)}
	engine, err := pdp.NewEngineInEnclave(fakePlatform.Launch(endorsedBytes))
	if err != nil {
		t.Fatal(err)
	}
	// Same endorsed code, same measurement — but the quote signature
	// chains to nobody the verifier trusts.
	if err := w.gateway.TrustPDP(engine); !errors.Is(err, attest.ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

// Stale platform: genuine hardware below the TCB floor is refused even
// when running endorsed code.
func TestStaleTCBRejected(t *testing.T) {
	stale := tee.NewPlatform(2)
	endorsed := tee.Image{EngineVersion: "engine/test", PolicyJSON: []byte(endorsedPolicy)}

	verifier := attest.NewVerifier(5, stale.AttestationRoot())
	verifier.Endorse(tee.Measure(endorsed), "endorsed-build")

	engine, err := pdp.NewEngineInEnclave(stale.Launch(endorsed))
	if err != nil {
		t.Fatal(err)
	}
	if err := NewGateway(verifier).TrustPDP(engine); !errors.Is(err, attest.ErrTCBOutOfDate) {
		t.Fatalf("expected ErrTCBOutOfDate, got %v", err)
	}
}

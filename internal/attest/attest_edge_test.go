// Edge cases for appraisal: revocation ordering, signer endorsement,
// misconfiguration, hostile evidence, and concurrency.
package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"

	"github.com/aabhimittal/zero-trust-confidential-computing/internal/tee"
)

// ─── Revocation ─────────────────────────────────────────────────────────

// Revocation has to beat endorsement, not merely coexist with it. If the
// endorsement lookup ran first, forgetting to delete a reference value
// would silently reinstate a build that was withdrawn for a CVE.
func TestRevocationOverridesAStandingEndorsement(t *testing.T) {
	h := newHarness(t, 7, 5)
	if _, err := h.verifier.Appraise(h.enclave.Quote(h.rd), h.rd); err != nil {
		t.Fatalf("setup: build should start out acceptable: %v", err)
	}

	h.verifier.Revoke(h.enclave.Measurement(), "CVE-2026-1")
	_, err := h.verifier.Appraise(h.enclave.Quote(h.rd), h.rd)
	if !errors.Is(err, ErrRevokedMeasurement) {
		t.Fatalf("expected ErrRevokedMeasurement, got %v", err)
	}
	// The endorsement is deliberately still in place; revocation must win
	// without anyone having to remember to remove it.
	if h.verifier.refs[h.enclave.Measurement()] == "" {
		t.Fatal("test is not exercising the intended ordering: endorsement was removed")
	}
}

func TestRevocationIsScopedToOneMeasurement(t *testing.T) {
	h := newHarness(t, 7, 5)
	other := h.platform.Launch(tee.Image{EngineVersion: "engine/2", PolicyJSON: []byte(`{"rules":[]}`)})
	h.verifier.Endorse(other.Measurement(), "second-build")

	h.verifier.Revoke(h.enclave.Measurement(), "CVE-2026-1")
	if _, err := h.verifier.Appraise(other.Quote(h.rd), h.rd); err != nil {
		t.Fatalf("revoking one build must not affect another: %v", err)
	}
}

// A revoked build must stay revoked even below the TCB floor and even if
// re-endorsed: revocation is checked before both.
func TestRevocationBeatsEveryLaterCheck(t *testing.T) {
	h := newHarness(t, 7, 5)
	h.verifier.Revoke(h.enclave.Measurement(), "")
	h.verifier.Endorse(h.enclave.Measurement(), "re-endorsed-by-mistake")

	if _, err := h.verifier.Appraise(h.enclave.Quote(h.rd), h.rd); !errors.Is(err, ErrRevokedMeasurement) {
		t.Fatalf("re-endorsing a revoked build must not resurrect it, got %v", err)
	}
}

// Revocation must not be reachable without a valid hardware signature —
// otherwise the error message becomes an oracle telling an attacker which
// measurements a verifier knows about.
func TestRevocationIsNotAnOracleForForgedQuotes(t *testing.T) {
	h := newHarness(t, 7, 5)
	h.verifier.Revoke(h.enclave.Measurement(), "CVE-2026-1")

	q := h.enclave.Quote(h.rd)
	q.Signature = make([]byte, ed25519.SignatureSize) // unsigned garbage
	if _, err := h.verifier.Appraise(q, h.rd); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("signature must be checked before anything is revealed, got %v", err)
	}
}

// ─── Signer endorsement ─────────────────────────────────────────────────

func TestSignerEndorsementAcceptsAnyBuildFromThatPublisher(t *testing.T) {
	p := tee.NewPlatform(7)
	v := NewVerifier(5, p.AttestationRoot())
	v.EndorseSigner("release-key", "any-release-build")

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	var nonce [32]byte
	rd := tee.KeyBinding(pub, nonce)

	for _, version := range []string{"v1", "v2", "v3-hotfix"} {
		e := p.Launch(tee.Image{Signer: "release-key", EngineVersion: version, PolicyJSON: []byte(`{}`)})
		name, err := v.Appraise(e.Quote(rd), rd)
		if err != nil || name != "any-release-build" {
			t.Fatalf("%s: expected signer endorsement to apply, got %q, %v", version, name, err)
		}
	}

	foreign := p.Launch(tee.Image{Signer: "attacker-key", EngineVersion: "v1", PolicyJSON: []byte(`{}`)})
	if _, err := v.Appraise(foreign.Quote(rd), rd); !errors.Is(err, ErrUnknownMeasurement) {
		t.Fatalf("another signer must not be covered, got %v", err)
	}
}

// An unsigned image reports the empty signer. It must not match a stray
// empty-string entry in the signer table, or "forgot to sign the build"
// silently becomes "endorsed".
func TestEmptySignerNeverMatches(t *testing.T) {
	p := tee.NewPlatform(7)
	v := NewVerifier(5, p.AttestationRoot())
	v.EndorseSigner("", "should-never-apply")

	unsigned := p.Launch(tee.Image{EngineVersion: "v1", PolicyJSON: []byte(`{}`)})
	var rd [64]byte
	if _, err := v.Appraise(unsigned.Quote(rd), rd); !errors.Is(err, ErrUnknownMeasurement) {
		t.Fatalf("an unsigned image must not match an empty signer endorsement, got %v", err)
	}
}

// Measurement endorsement must still take priority, so revocation of a
// specific bad build is not undone by a broad signer endorsement.
func TestRevocationBeatsSignerEndorsement(t *testing.T) {
	p := tee.NewPlatform(7)
	v := NewVerifier(5, p.AttestationRoot())
	v.EndorseSigner("release-key", "any-release-build")

	bad := p.Launch(tee.Image{Signer: "release-key", EngineVersion: "v0", PolicyJSON: []byte(`{}`)})
	v.Revoke(bad.Measurement(), "known bad")

	var rd [64]byte
	if _, err := v.Appraise(bad.Quote(rd), rd); !errors.Is(err, ErrRevokedMeasurement) {
		t.Fatalf("a revoked build must not be readmitted by its signer, got %v", err)
	}
}

// ─── Misconfiguration ───────────────────────────────────────────────────

func TestVerifierWithNoAnchorsFailsClosed(t *testing.T) {
	v := NewVerifier(5)
	p := tee.NewPlatform(7)
	e := p.Launch(tee.Image{EngineVersion: "v1", PolicyJSON: []byte(`{}`)})
	var rd [64]byte
	if _, err := v.Appraise(e.Quote(rd), rd); !errors.Is(err, ErrNoTrustAnchors) {
		t.Fatalf("expected ErrNoTrustAnchors, got %v", err)
	}
}

// ed25519.Verify panics on a public key of the wrong length. A typo'd trust
// anchor would therefore crash the enforcement point on the request path —
// and an attacker who could provoke that crash would have a denial of
// service against every gateway sharing the config.
func TestMalformedTrustAnchorsAreDroppedRatherThanPanicking(t *testing.T) {
	p := tee.NewPlatform(7)
	bad := []ed25519.PublicKey{nil, {}, {1, 2, 3}, make([]byte, 64)}

	v := NewVerifier(5, bad...)
	if v.TrustAnchorCount() != 0 {
		t.Fatalf("malformed anchors must not be stored, count is %d", v.TrustAnchorCount())
	}
	e := p.Launch(tee.Image{EngineVersion: "v1", PolicyJSON: []byte(`{}`)})
	var rd [64]byte
	if _, err := v.Appraise(e.Quote(rd), rd); !errors.Is(err, ErrNoTrustAnchors) {
		t.Fatalf("expected ErrNoTrustAnchors, got %v", err)
	}

	// A good anchor alongside bad ones must still work.
	mixed := NewVerifier(5, append(bad, p.AttestationRoot())...)
	if mixed.TrustAnchorCount() != 1 {
		t.Fatalf("expected exactly one usable anchor, got %d", mixed.TrustAnchorCount())
	}
	mixed.Endorse(e.Measurement(), "build")
	if _, err := mixed.Appraise(e.Quote(rd), rd); err != nil {
		t.Fatalf("a usable anchor among malformed ones must still appraise: %v", err)
	}
}

func TestMultipleAnchorsAreAllTried(t *testing.T) {
	p1, p2 := tee.NewPlatform(7), tee.NewPlatform(7)
	v := NewVerifier(5, p1.AttestationRoot(), p2.AttestationRoot())

	var rd [64]byte
	for _, p := range []*tee.Platform{p1, p2} {
		e := p.Launch(tee.Image{EngineVersion: "v1", PolicyJSON: []byte(`{}`)})
		v.Endorse(e.Measurement(), "build")
		if _, err := v.Appraise(e.Quote(rd), rd); err != nil {
			t.Fatalf("quotes from either anchored platform must appraise: %v", err)
		}
	}
}

// ─── Hostile evidence ───────────────────────────────────────────────────

func TestMalformedSignaturesAreRejectedWithoutPanicking(t *testing.T) {
	h := newHarness(t, 7, 5)
	base := h.enclave.Quote(h.rd)

	for name, sig := range map[string][]byte{
		"nil":       nil,
		"empty":     {},
		"short":     {1, 2, 3},
		"long":      make([]byte, 1000),
		"all zeros": make([]byte, ed25519.SignatureSize),
	} {
		q := base
		q.Signature = sig
		if _, err := h.verifier.Appraise(q, h.rd); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s signature: expected ErrBadSignature, got %v", name, err)
		}
	}
}

// ─── Boundaries ─────────────────────────────────────────────────────────

func TestTCBBoundaryIsInclusive(t *testing.T) {
	exact := newHarness(t, 5, 5)
	if _, err := exact.verifier.Appraise(exact.enclave.Quote(exact.rd), exact.rd); err != nil {
		t.Fatalf("TCB exactly at the minimum must be accepted: %v", err)
	}
	below := newHarness(t, 4, 5)
	if _, err := below.verifier.Appraise(below.enclave.Quote(below.rd), below.rd); !errors.Is(err, ErrTCBOutOfDate) {
		t.Fatal("one below the minimum must be refused")
	}
}

func TestTCBExtremesBehave(t *testing.T) {
	max := newHarness(t, ^uint32(0), 5)
	if _, err := max.verifier.Appraise(max.enclave.Quote(max.rd), max.rd); err != nil {
		t.Fatalf("maximum TCB must be accepted: %v", err)
	}
	// A verifier demanding the maximum accepts only the maximum.
	strict := newHarness(t, 0, ^uint32(0))
	if _, err := strict.verifier.Appraise(strict.enclave.Quote(strict.rd), strict.rd); !errors.Is(err, ErrTCBOutOfDate) {
		t.Fatal("TCB 0 must not satisfy a maximum-valued floor")
	}
}

// Report data is compared in full; a single flipped bit anywhere in the 64
// bytes must be fatal, including in the last byte where a length-based
// comparison bug would hide.
func TestSingleBitReportDataDifferenceIsRejected(t *testing.T) {
	h := newHarness(t, 7, 5)
	q := h.enclave.Quote(h.rd)
	for _, pos := range []int{0, 31, 32, 63} {
		expected := h.rd
		expected[pos] ^= 1
		if _, err := h.verifier.Appraise(q, expected); !errors.Is(err, ErrReportDataMismatch) {
			t.Errorf("bit flip at byte %d must be rejected, got %v", pos, err)
		}
	}
}

// ─── Concurrency ────────────────────────────────────────────────────────

// Appraisal runs on the request path of every enforcement point while
// endorsement and revocation happen on an operator's schedule. Those are
// genuinely concurrent, and a revocation racing an appraisal must be a
// synchronisation event, not a data race.
func TestConcurrentAppraisalEndorsementAndRevocation(t *testing.T) {
	h := newHarness(t, 7, 5)
	q := h.enclave.Quote(h.rd)

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Either verdict is legitimate depending on interleaving; what
			// must not happen is a race or a panic.
			_, err := h.verifier.Appraise(q, h.rd)
			if err != nil && !errors.Is(err, ErrRevokedMeasurement) {
				t.Errorf("unexpected appraisal error: %v", err)
			}
		}()
	}
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var m tee.Measurement
			m[0] = byte(i)
			h.verifier.Endorse(m, "churn")
			h.verifier.EndorseSigner("signer", "churn")
			h.verifier.Revoke(m, "churn")
			h.verifier.TrustAnchorCount()
		}()
	}
	wg.Wait()
}

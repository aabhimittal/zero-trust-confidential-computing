package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/aabhimittal/zero-trust-confidential-computing/internal/tee"
)

// harness wires one platform, one endorsed enclave, and a verifier that
// trusts the platform's root.
type harness struct {
	platform *tee.Platform
	enclave  *tee.Enclave
	verifier *Verifier
	pub      ed25519.PublicKey
	nonce    [32]byte
	rd       [64]byte
}

func newHarness(t *testing.T, platformTCB, minTCB uint32) *harness {
	t.Helper()
	p := tee.NewPlatform(platformTCB)
	img := tee.Image{EngineVersion: "engine/1", PolicyJSON: []byte(`{"rules":[]}`)}
	e := p.Launch(img)
	v := NewVerifier(minTCB, p.AttestationRoot())
	v.Endorse(e.Measurement(), "endorsed-build")

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{platform: p, enclave: e, verifier: v, pub: pub}
	if _, err := rand.Read(h.nonce[:]); err != nil {
		t.Fatal(err)
	}
	h.rd = tee.KeyBinding(pub, h.nonce)
	return h
}

func TestAppraiseHappyPath(t *testing.T) {
	h := newHarness(t, 7, 5)
	name, err := h.verifier.Appraise(h.enclave.Quote(h.rd), h.rd)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if name != "endorsed-build" {
		t.Fatalf("expected endorsement name, got %q", name)
	}
}

func TestAppraiseRejectsForgedSignature(t *testing.T) {
	h := newHarness(t, 7, 5)
	q := h.enclave.Quote(h.rd)

	// A software forger who knows every field of the quote still cannot
	// sign it: they don't hold the hardware key.
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	q.Signature = ed25519.Sign(attacker, q.SignedBytes())

	if _, err := h.verifier.Appraise(q, h.rd); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

func TestAppraiseRejectsAlteredMeasurement(t *testing.T) {
	h := newHarness(t, 7, 5)
	q := h.enclave.Quote(h.rd)

	// Attacker rewrites the measurement field to the endorsed value —
	// but the signature covered the original bytes.
	q.Measurement[0] ^= 0xFF
	if _, err := h.verifier.Appraise(q, h.rd); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature on altered quote, got %v", err)
	}
}

func TestAppraiseRejectsUnknownMeasurement(t *testing.T) {
	h := newHarness(t, 7, 5)
	tampered := h.platform.Launch(tee.Image{EngineVersion: "engine/1", PolicyJSON: []byte(`{"backdoor":true}`)})
	if _, err := h.verifier.Appraise(tampered.Quote(h.rd), h.rd); !errors.Is(err, ErrUnknownMeasurement) {
		t.Fatalf("expected ErrUnknownMeasurement, got %v", err)
	}
}

func TestAppraiseRejectsStaleTCB(t *testing.T) {
	h := newHarness(t, 4, 5) // platform patched below the verifier's floor
	if _, err := h.verifier.Appraise(h.enclave.Quote(h.rd), h.rd); !errors.Is(err, ErrTCBOutOfDate) {
		t.Fatalf("expected ErrTCBOutOfDate, got %v", err)
	}
}

func TestAppraiseRejectsReplayedNonce(t *testing.T) {
	h := newHarness(t, 7, 5)
	captured := h.enclave.Quote(h.rd) // quote from an earlier session

	var freshNonce [32]byte
	if _, err := rand.Read(freshNonce[:]); err != nil {
		t.Fatal(err)
	}
	expected := tee.KeyBinding(h.pub, freshNonce)
	if _, err := h.verifier.Appraise(captured, expected); !errors.Is(err, ErrReportDataMismatch) {
		t.Fatalf("expected ErrReportDataMismatch for replayed quote, got %v", err)
	}
}

func TestAppraiseRejectsWrongKeyBinding(t *testing.T) {
	h := newHarness(t, 7, 5)
	captured := h.enclave.Quote(h.rd)

	// Impostor presents their own key with the genuine quote.
	impostorPub, _, _ := ed25519.GenerateKey(rand.Reader)
	expected := tee.KeyBinding(impostorPub, h.nonce)
	if _, err := h.verifier.Appraise(captured, expected); !errors.Is(err, ErrReportDataMismatch) {
		t.Fatalf("expected ErrReportDataMismatch for substituted key, got %v", err)
	}
}

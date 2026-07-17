package tee

import (
	"crypto/ed25519"
	"testing"
)

func img(policy string) Image {
	return Image{EngineVersion: "engine/1", PolicyJSON: []byte(policy)}
}

func TestMeasurementDeterministic(t *testing.T) {
	if Measure(img(`{"a":1}`)) != Measure(img(`{"a":1}`)) {
		t.Fatal("identical images must produce identical measurements")
	}
}

func TestMeasurementSensitivity(t *testing.T) {
	base := Measure(img(`{"a":1}`))
	if Measure(img(`{"a":2}`)) == base {
		t.Fatal("changed policy bytes must change the measurement")
	}
	if Measure(Image{EngineVersion: "engine/2", PolicyJSON: []byte(`{"a":1}`)}) == base {
		t.Fatal("changed engine version must change the measurement")
	}
}

func TestLaunchStampsMeasurement(t *testing.T) {
	p := NewPlatform(1)
	e := p.Launch(img(`{}`))
	if e.Measurement() != Measure(img(`{}`)) {
		t.Fatal("launch must record the measurement of exactly the launched image")
	}
}

func TestQuoteVerifiesUnderPlatformRoot(t *testing.T) {
	p := NewPlatform(3)
	e := p.Launch(img(`{}`))
	var rd [64]byte
	rd[0] = 0xAB
	q := e.Quote(rd)

	if !ed25519.Verify(p.AttestationRoot(), q.SignedBytes(), q.Signature) {
		t.Fatal("quote must verify under the issuing platform's root")
	}
	if q.Measurement != e.Measurement() || q.ReportData != rd || q.TCBVersion != 3 {
		t.Fatal("quote must carry the enclave measurement, caller report data, and platform TCB")
	}
}

func TestQuoteFromDifferentPlatformDoesNotVerify(t *testing.T) {
	q := NewPlatform(1).Launch(img(`{}`)).Quote([64]byte{})
	other := NewPlatform(1)
	if ed25519.Verify(other.AttestationRoot(), q.SignedBytes(), q.Signature) {
		t.Fatal("a quote must not verify under an unrelated platform's root")
	}
}

func TestKeyBindingCommitsToKeyAndNonce(t *testing.T) {
	pubA, _, _ := ed25519.GenerateKey(nil)
	pubB, _, _ := ed25519.GenerateKey(nil)
	var n1, n2 [32]byte
	n2[0] = 1

	if KeyBinding(pubA, n1) == KeyBinding(pubB, n1) {
		t.Fatal("binding must differ for different keys")
	}
	if KeyBinding(pubA, n1) == KeyBinding(pubA, n2) {
		t.Fatal("binding must differ for different nonces")
	}
	if KeyBinding(pubA, n1) != KeyBinding(pubA, n1) {
		t.Fatal("binding must be deterministic")
	}
}

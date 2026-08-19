// Edge cases for the simulated platform: the boundaries where sealing,
// counters, and measurement identity either hold the line or quietly stop
// meaning anything.
package tee

import (
	"bytes"
	"crypto/ed25519"
	"sync"
	"testing"
)

func signedImg(signer, version, policy string) Image {
	return Image{Signer: signer, EngineVersion: version, PolicyJSON: []byte(policy)}
}

// ─── Measurement identity ───────────────────────────────────────────────

// Without length-prefixed framing, a NUL inside the version string lets an
// attacker shift the field boundary and present a different policy under
// the same measurement — defeating the one thing measurement exists to do.
func TestMeasurementResistsFieldBoundaryShifting(t *testing.T) {
	a := Measure(Image{EngineVersion: "engine\x00extra", PolicyJSON: []byte(`{}`)})
	b := Measure(Image{EngineVersion: "engine", PolicyJSON: []byte("extra\x00{}")})
	if a == b {
		t.Fatal("images differing only in where a field boundary falls must not collide")
	}

	c := Measure(Image{Signer: "ab", EngineVersion: "c", PolicyJSON: []byte(`{}`)})
	d := Measure(Image{Signer: "a", EngineVersion: "bc", PolicyJSON: []byte(`{}`)})
	if c == d {
		t.Fatal("signer and version must not be confusable with each other")
	}
}

func TestMeasurementCoversSigner(t *testing.T) {
	if Measure(signedImg("release", "v1", "{}")) == Measure(signedImg("attacker", "v1", "{}")) {
		t.Fatal("a different signer must produce a different measurement")
	}
}

func TestEmptyImageIsStillMeasured(t *testing.T) {
	// A zero image is a legitimate thing to measure; it simply is not the
	// same as any populated one.
	if Measure(Image{}) == Measure(signedImg("", "", "")) {
		return // identical by construction; both are the zero image
	}
	t.Fatal("the zero image must measure consistently")
}

func TestLargePolicyMeasuresWithoutTruncation(t *testing.T) {
	big := bytes.Repeat([]byte("x"), 1<<20)
	a := Measure(Image{PolicyJSON: big})
	flipped := append([]byte(nil), big...)
	flipped[len(flipped)-1] = 'y' // last byte only
	if a == Measure(Image{PolicyJSON: flipped}) {
		t.Fatal("a flipped byte anywhere in a large policy must change the measurement")
	}
}

// ─── Quote integrity ────────────────────────────────────────────────────

func TestQuoteSignatureCoversEveryField(t *testing.T) {
	p := NewPlatform(3)
	q := p.Launch(signedImg("release", "v1", "{}")).Quote([64]byte{0xAB})

	mutations := map[string]func(*Quote){
		"measurement": func(q *Quote) { q.Measurement[0] ^= 1 },
		"signer":      func(q *Quote) { q.Signer = "attacker" },
		"report data": func(q *Quote) { q.ReportData[63] ^= 1 },
		"tcb version": func(q *Quote) { q.TCBVersion = 99 },
	}
	for name, mutate := range mutations {
		tampered := q
		tampered.Measurement = q.Measurement // copy the array, not alias it
		mutate(&tampered)
		if ed25519.Verify(p.AttestationRoot(), tampered.SignedBytes(), tampered.Signature) {
			t.Errorf("altering the %s must invalidate the quote signature", name)
		}
	}
}

func TestQuoteWithMalformedSignatureDoesNotPanic(t *testing.T) {
	p := NewPlatform(1)
	q := p.Launch(signedImg("s", "v", "{}")).Quote([64]byte{})
	for _, sig := range [][]byte{nil, {}, {1, 2, 3}, bytes.Repeat([]byte{0}, 1000)} {
		tampered := q
		tampered.Signature = sig
		if ed25519.Verify(p.AttestationRoot(), tampered.SignedBytes(), tampered.Signature) {
			t.Fatal("a malformed signature must not verify")
		}
	}
}

// ─── Sealing ────────────────────────────────────────────────────────────

func TestSealRoundTrip(t *testing.T) {
	e := NewPlatform(1).Launch(signedImg("release", "v1", "{}"))
	for _, pol := range []SealPolicy{SealToMeasurement, SealToSigner} {
		blob, err := e.Seal([]byte("audit head"), pol)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(blob, []byte("audit head")) {
			t.Fatal("sealed blob must not contain the plaintext")
		}
		got, err := e.Unseal(blob)
		if err != nil || string(got) != "audit head" {
			t.Fatalf("round trip failed for policy %d: %q, %v", pol, got, err)
		}
	}
}

func TestSealToMeasurementExcludesEveryOtherWorkload(t *testing.T) {
	p := NewPlatform(1)
	genuine := p.Launch(signedImg("release", "v1", `{"rules":[]}`))
	blob, err := genuine.Seal([]byte("secret"), SealToMeasurement)
	if err != nil {
		t.Fatal(err)
	}

	others := map[string]*Enclave{
		"tampered policy": p.Launch(signedImg("release", "v1", `{"rules":[{"backdoor":true}]}`)),
		"newer version":   p.Launch(signedImg("release", "v2", `{"rules":[]}`)),
		"other signer":    p.Launch(signedImg("attacker", "v1", `{"rules":[]}`)),
	}
	for name, e := range others {
		if _, err := e.Unseal(blob); err == nil {
			t.Errorf("%s must not be able to unseal state sealed to another measurement", name)
		}
	}
}

// Seal-to-signer is the upgrade-friendly option, and this test states both
// halves of that bargain: a new build by the same signer gets in, and that
// is precisely why a downgraded build by the same signer does too.
func TestSealToSignerFollowsThePublisherNotTheBuild(t *testing.T) {
	p := NewPlatform(1)
	v1 := p.Launch(signedImg("release", "v1", "{}"))
	blob, err := v1.Seal([]byte("secret"), SealToSigner)
	if err != nil {
		t.Fatal(err)
	}

	v2 := p.Launch(signedImg("release", "v2", "{}"))
	if got, err := v2.Unseal(blob); err != nil || string(got) != "secret" {
		t.Fatalf("a later build from the same signer must read the state: %v", err)
	}
	old := p.Launch(signedImg("release", "v0-vulnerable", "{}"))
	if _, err := old.Unseal(blob); err != nil {
		t.Fatal("an older build from the same signer also reads it — that is the documented cost")
	}
	foreign := p.Launch(signedImg("attacker", "v1", "{}"))
	if _, err := foreign.Unseal(blob); err == nil {
		t.Fatal("a different signer must not read it")
	}
}

func TestSealedStateIsNotPortableBetweenPlatforms(t *testing.T) {
	img := signedImg("release", "v1", "{}")
	blob, err := NewPlatform(1).Launch(img).Seal([]byte("secret"), SealToMeasurement)
	if err != nil {
		t.Fatal(err)
	}
	// Identical image, identical measurement, different silicon.
	if _, err := NewPlatform(1).Launch(img).Unseal(blob); err == nil {
		t.Fatal("sealed state must not move between platforms")
	}
}

func TestUnsealRejectsMalformedInputWithoutPanicking(t *testing.T) {
	e := NewPlatform(1).Launch(signedImg("release", "v1", "{}"))
	good, err := e.Seal([]byte("secret"), SealToMeasurement)
	if err != nil {
		t.Fatal(err)
	}

	corrupt := map[string][]byte{
		"nil":              nil,
		"empty":            {},
		"policy byte only": {byte(SealToMeasurement)},
		"unknown policy":   append([]byte{99}, good[1:]...),
		"truncated":        good[:len(good)-1],
		"header only":      good[:8],
		"flipped ciphertext": func() []byte {
			b := append([]byte(nil), good...)
			b[len(b)-1] ^= 1
			return b
		}(),
		"flipped nonce": func() []byte {
			b := append([]byte(nil), good...)
			b[2] ^= 1
			return b
		}(),
		"policy byte swapped": func() []byte {
			b := append([]byte(nil), good...)
			b[0] = byte(SealToSigner)
			return b
		}(),
		"extra trailing byte": append(append([]byte(nil), good...), 0),
	}
	for name, blob := range corrupt {
		got, err := e.Unseal(blob)
		if err == nil {
			t.Errorf("%s: expected failure, got %q", name, got)
		}
	}
}

func TestSealRejectsUnknownPolicy(t *testing.T) {
	e := NewPlatform(1).Launch(signedImg("release", "v1", "{}"))
	if _, err := e.Seal([]byte("x"), SealPolicy(0)); err == nil {
		t.Fatal("sealing under an unknown policy must fail rather than pick a default")
	}
}

func TestSealOfEmptyPlaintextRoundTrips(t *testing.T) {
	e := NewPlatform(1).Launch(signedImg("release", "v1", "{}"))
	blob, err := e.Seal(nil, SealToMeasurement)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.Unseal(blob)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty plaintext must round trip: %q, %v", got, err)
	}
}

func TestSealUsesFreshNoncePerCall(t *testing.T) {
	e := NewPlatform(1).Launch(signedImg("release", "v1", "{}"))
	a, _ := e.Seal([]byte("same"), SealToMeasurement)
	b, _ := e.Seal([]byte("same"), SealToMeasurement)
	if bytes.Equal(a, b) {
		t.Fatal("sealing the same plaintext twice must not produce identical blobs")
	}
}

// ─── Monotonic counters ─────────────────────────────────────────────────

func TestCounterSurvivesEnclaveRestart(t *testing.T) {
	p := NewPlatform(1)
	img := signedImg("release", "v1", "{}")

	first := p.Launch(img)
	first.CounterIncrement("log")
	first.CounterIncrement("log")

	// The enclave is destroyed; a fresh one launches from identical bytes.
	restarted := p.Launch(img)
	if got := restarted.CounterRead("log"); got != 2 {
		t.Fatalf("counter must survive restart, got %d", got)
	}
	if got := restarted.CounterIncrement("log"); got != 3 {
		t.Fatalf("counter must continue from where it was, got %d", got)
	}
}

func TestCountersAreNamespacedByMeasurement(t *testing.T) {
	p := NewPlatform(1)
	genuine := p.Launch(signedImg("release", "v1", `{"rules":[]}`))
	genuine.CounterIncrement("log")
	genuine.CounterIncrement("log")

	tampered := p.Launch(signedImg("release", "v1", `{"rules":["backdoor"]}`))
	if got := tampered.CounterRead("log"); got != 0 {
		t.Fatalf("a different measurement must see its own counter, got %d", got)
	}
	tampered.CounterIncrement("log")
	if got := genuine.CounterRead("log"); got != 2 {
		t.Fatalf("another workload must not be able to advance our counter, got %d", got)
	}
}

func TestCountersAreNamespacedByName(t *testing.T) {
	e := NewPlatform(1).Launch(signedImg("release", "v1", "{}"))
	e.CounterIncrement("a")
	if e.CounterRead("b") != 0 {
		t.Fatal("counters must not alias across names")
	}
	if e.CounterRead("") != 0 {
		t.Fatal("the empty name must be its own counter, not a wildcard")
	}
}

func TestCountersAreNotPortableBetweenPlatforms(t *testing.T) {
	img := signedImg("release", "v1", "{}")
	a := NewPlatform(1).Launch(img)
	a.CounterIncrement("log")
	if NewPlatform(1).Launch(img).CounterRead("log") != 0 {
		t.Fatal("counter state must not leak between platforms")
	}
}

func TestConcurrentCounterIncrementsDoNotLoseUpdates(t *testing.T) {
	e := NewPlatform(1).Launch(signedImg("release", "v1", "{}"))
	const n = 200
	seen := make([]uint64, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			seen[i] = e.CounterIncrement("log")
		}()
	}
	wg.Wait()

	if got := e.CounterRead("log"); got != n {
		t.Fatalf("expected %d increments, counter is at %d", n, got)
	}
	// Every caller must have received a distinct value; a counter that
	// hands the same number to two callers is not monotonic in any useful
	// sense.
	distinct := make(map[uint64]bool, n)
	for _, v := range seen {
		if distinct[v] {
			t.Fatalf("value %d was returned to more than one caller", v)
		}
		distinct[v] = true
	}
}

func TestConcurrentSealUnsealIsSafe(t *testing.T) {
	e := NewPlatform(1).Launch(signedImg("release", "v1", "{}"))
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			blob, err := e.Seal([]byte{byte(i)}, SealToMeasurement)
			if err != nil {
				t.Error(err)
				return
			}
			got, err := e.Unseal(blob)
			if err != nil || len(got) != 1 || got[0] != byte(i) {
				t.Errorf("round trip mismatch: %v, %v", got, err)
			}
		}()
	}
	wg.Wait()
}

// The platform stamps identity at launch; the workload can read what it was
// launched with but has no way to alter it. These accessors are the enclave
// side of that one-way relationship.
func TestEnclaveReportsWhatThePlatformStamped(t *testing.T) {
	img := signedImg("release", "v1", `{"rules":[]}`)
	e := NewPlatform(1).Launch(img)

	if e.Signer() != "release" {
		t.Fatalf("expected the launched signer, got %q", e.Signer())
	}
	if string(e.PolicyJSON()) != `{"rules":[]}` {
		t.Fatalf("the workload must see exactly the measured policy bytes, got %q", e.PolicyJSON())
	}
	if e.Measurement() != Measure(img) {
		t.Fatal("the reported measurement must be the measurement of the launched image")
	}
}

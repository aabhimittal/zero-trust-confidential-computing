// Package tee simulates a confidential-computing platform: a CPU that can
// launch a workload into an isolated enclave, measure exactly what it
// launched, sign statements ("quotes") about that measurement with a key
// that never leaves the hardware, seal secrets so only that same workload
// can read them back, and provide monotonic counters that survive restarts.
//
// The simulation preserves the trust-relevant properties of real TEEs
// (Intel SGX/TDX, AMD SEV-SNP, AWS Nitro Enclaves):
//
//   - The platform, not the workload, computes the measurement. An enclave
//     cannot lie about its own identity: the Enclave type has no way to set
//     its measurement field, only Launch does.
//   - Quotes are signed by a platform root key standing in for the
//     CPU-fused attestation key and its vendor certificate chain.
//   - ReportData lets code inside the enclave bind 64 bytes of its choosing
//     (here: a decision-signing public key plus a verifier nonce) into the
//     signed quote, so attestation and application keys are cryptographically
//     linked.
//   - Sealing keys are derived from platform secrets and workload identity,
//     so state written by one workload is unreadable by any other — the
//     property that makes persistent enclave state possible at all.
//   - Monotonic counters are platform state that an enclave can advance but
//     never rewind, which is what makes rollback of sealed state detectable.
//
// What it deliberately does NOT provide — because it runs inside one
// ordinary process — is actual memory isolation or encryption. See
// docs/CONCEPTS.md for the exact mapping between this simulation and real
// hardware.
package tee

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"

	"github.com/aabhimittal/zero-trust-confidential-computing/internal/canon"
)

// Measurement is the cryptographic identity of a launched workload,
// analogous to SGX MRENCLAVE, TDX MRTD, or the SEV-SNP launch digest.
type Measurement [32]byte

// Image is what the platform loads into an enclave. Everything that
// determines the workload's behavior must be inside it, because only what
// is measured can be verified. For VERITY that is the policy-engine build
// identifier and the policy bundle the engine will interpret.
//
// Signer names the key that signed this build, standing in for SGX's
// MRSIGNER. It is reported separately in every quote so a relying party can
// choose between pinning one exact build ("this measurement") and trusting
// a publisher ("anything signed by our release key") — a trade-off with
// real consequences, discussed in docs/CONCEPTS.md.
type Image struct {
	Signer        string
	EngineVersion string
	PolicyJSON    []byte
}

// Measure computes the launch measurement of an image. It is a pure
// function of the image contents: relaunching identical bytes yields an
// identical measurement, and any tampering — a single flipped bit in the
// policy — yields a completely different one.
//
// Fields are framed by package canon rather than concatenated, because
// concatenation makes distinct images collide: with a plain separator byte,
// {EngineVersion: "a\x00b", PolicyJSON: "c"} and {EngineVersion: "a",
// PolicyJSON: "b\x00c"} measure identically, letting anyone who influences
// the version string swap in a different policy at the same measurement.
func Measure(img Image) Measurement {
	return canon.New("verity/measurement/v2").
		String(img.Signer).
		String(img.EngineVersion).
		Bytes(img.PolicyJSON).
		Sum()
}

// Platform models the CPU and its attestation infrastructure. rootKey
// stands in for the hardware-fused attestation key whose public half is
// published by the silicon vendor (Intel PCS, AMD KDS); relying parties
// trust quotes precisely because this key is unreachable from software.
//
// sealSecret stands in for the per-CPU key material behind SGX's EGETKEY:
// never extractable, never leaving the package, and mixed with workload
// identity so that each workload gets a different sealing key.
type Platform struct {
	rootKey    ed25519.PrivateKey
	rootPub    ed25519.PublicKey
	sealSecret [32]byte

	// TCBVersion models the platform's security patch level. Verifiers
	// reject quotes from platforms below their minimum (TCB recovery).
	TCBVersion uint32

	// counters is platform-resident monotonic counter state. It lives on
	// the Platform, not the Enclave, precisely so it survives an enclave
	// being torn down and relaunched — that persistence is what lets a
	// workload notice that its saved state was rewound.
	mu       sync.Mutex
	counters map[counterKey]uint64
}

// counterKey scopes a counter to the workload that owns it. A relaunched
// enclave with the same measurement sees the same counters; any other
// workload — including a tampered rebuild — addresses a different, and
// therefore fresh, counter namespace.
type counterKey struct {
	owner Measurement
	name  string
}

// NewPlatform "manufactures" a platform with a fresh attestation root and a
// fresh, unextractable sealing secret.
func NewPlatform(tcbVersion uint32) *Platform {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	p := &Platform{
		rootKey:    priv,
		rootPub:    pub,
		TCBVersion: tcbVersion,
		counters:   make(map[counterKey]uint64),
	}
	if _, err := rand.Read(p.sealSecret[:]); err != nil {
		panic(err)
	}
	return p
}

// AttestationRoot returns the public key relying parties use as their
// trust anchor, as they would use the silicon vendor's root certificate.
func (p *Platform) AttestationRoot() ed25519.PublicKey {
	return p.rootPub
}

// Enclave is a launched workload. Its measurement was fixed by the
// platform at launch time and is unexported so nothing can rewrite it.
type Enclave struct {
	platform    *Platform
	measurement Measurement
	image       Image
}

// Launch measures an image and instantiates it as an enclave. The platform
// records whatever it was given — hardware does not judge code, it reports
// it. Detecting tampering is the verifier's job, done by comparing the
// reported measurement against endorsed reference values.
func (p *Platform) Launch(img Image) *Enclave {
	return &Enclave{platform: p, measurement: Measure(img), image: img}
}

// Measurement returns the launch-time measurement.
func (e *Enclave) Measurement() Measurement {
	return e.measurement
}

// Signer returns the build signer the platform recorded at launch.
func (e *Enclave) Signer() string {
	return e.image.Signer
}

// PolicyJSON exposes the measured policy bytes to the workload running
// inside the enclave. The policy engine is constructed from exactly these
// bytes, which is what makes its behavior a function of the measurement.
func (e *Enclave) PolicyJSON() []byte {
	return e.image.PolicyJSON
}

// Quote is a signed attestation statement: "an enclave with this
// measurement, from this signer, on a platform at this TCB level, asked me
// to convey this report data." It corresponds to an SGX/TDX quote or
// SEV-SNP attestation report.
type Quote struct {
	Measurement Measurement
	Signer      string
	ReportData  [64]byte
	TCBVersion  uint32
	Signature   []byte
}

// Quote produces a quote over caller-chosen report data. Only code running
// inside the enclave can invoke this (in real SGX, the EREPORT instruction
// only executes in enclave mode), which is why report data can safely
// carry the enclave's public key: nothing outside the enclave can get the
// platform to bind a key to this measurement.
func (e *Enclave) Quote(reportData [64]byte) Quote {
	q := Quote{
		Measurement: e.measurement,
		Signer:      e.image.Signer,
		ReportData:  reportData,
		TCBVersion:  e.platform.TCBVersion,
	}
	q.Signature = ed25519.Sign(e.platform.rootKey, q.SignedBytes())
	return q
}

// SignedBytes is the canonical byte string covered by the quote signature.
// The one variable-length field is length-prefixed so that no two distinct
// quotes can serialize identically.
func (q Quote) SignedBytes() []byte {
	return canon.New("verity/quote/v2").
		Raw32(q.Measurement).
		String(q.Signer).
		Bytes(q.ReportData[:]).
		Uint64(uint64(q.TCBVersion)).
		SumBytes()
}

// KeyBinding is the report-data convention shared by VERITY's enclave
// workload and its verifier: the first 32 bytes commit to the workload's
// public key, the last 32 echo the verifier's nonce. The commitment ties
// the key to the measurement; the nonce ties the quote to this exchange,
// so a captured quote cannot be replayed later.
func KeyBinding(pub ed25519.PublicKey, nonce [32]byte) [64]byte {
	var rd [64]byte
	kh := sha256.Sum256(pub)
	copy(rd[:32], kh[:])
	copy(rd[32:], nonce[:])
	return rd
}

// ─── Sealing ────────────────────────────────────────────────────────────
//
// Enclave memory does not survive a restart, so any workload that needs
// durable state must hand it to the untrusted host — encrypted under a key
// the host cannot derive. That is sealing: the platform mixes its internal
// secret with the workload's identity, so the ciphertext is readable only
// by a workload the hardware agrees is the same one.

// SealPolicy selects which identity the sealing key is derived from.
type SealPolicy uint8

const (
	// SealToMeasurement binds state to one exact build. An upgraded engine
	// — even a legitimate, signed one — gets a different key and cannot
	// read the old state. Strongest, and the reason production TEE systems
	// need an explicit state-migration step at upgrade time.
	SealToMeasurement SealPolicy = 1

	// SealToSigner binds state to the publisher instead, so a newer build
	// from the same signer can read state written by an older one. This
	// buys painless upgrades at a real cost: it also lets a *downgraded*
	// build from that signer read the state, so a signer who ever published
	// a vulnerable build has effectively published access to sealed data.
	SealToSigner SealPolicy = 2
)

// ErrUnseal is returned whenever sealed data cannot be recovered: wrong
// workload, wrong platform, corrupted blob, or a truncated one. The causes
// are deliberately indistinguishable to the caller — a decryption oracle
// that explains *why* it failed is a decryption oracle.
var ErrUnseal = errors.New("tee: sealed blob does not decrypt under this workload's sealing key")

// sealingKey derives the AES key for an identity under the given policy.
// Because the platform secret is an input and never leaves the platform,
// the same workload on a *different* machine derives a different key —
// matching real hardware, where sealed state is not portable between CPUs.
func (p *Platform) sealingKey(m Measurement, signer string, pol SealPolicy) []byte {
	var identity [32]byte
	switch pol {
	case SealToSigner:
		identity = canon.New("verity/seal/signer/v1").String(signer).Sum()
	default:
		identity = canon.New("verity/seal/measurement/v1").Raw32(m).Sum()
	}
	mac := hmac.New(sha256.New, p.sealSecret[:])
	mac.Write(identity[:])
	return mac.Sum(nil)
}

// sealAAD is authenticated but not encrypted, so a blob cannot be silently
// re-labelled with a different policy byte and fed back in.
func sealAAD(pol SealPolicy) []byte {
	return []byte{byte(pol)}
}

// Seal encrypts plaintext under a key only this workload can derive. The
// returned blob is safe to hand to the untrusted host: it is confidential
// and tamper-evident, though (like all sealed state) the host remains free
// to delete it or serve back an older copy — see Enclave.CounterIncrement
// for how that residual rollback power is contained.
func (e *Enclave) Seal(plaintext []byte, pol SealPolicy) ([]byte, error) {
	if pol != SealToMeasurement && pol != SealToSigner {
		return nil, errors.New("tee: unknown seal policy")
	}
	key := e.platform.sealingKey(e.measurement, e.image.Signer, pol)
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	blob := make([]byte, 1+gcm.NonceSize(), 1+gcm.NonceSize()+len(plaintext)+gcm.Overhead())
	blob[0] = byte(pol)
	nonce := blob[1 : 1+gcm.NonceSize()]
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(blob, nonce, plaintext, sealAAD(pol)), nil
}

// Unseal reverses Seal. It returns ErrUnseal for every failure mode,
// including malformed input, and never panics on attacker-supplied bytes —
// the host controls this input entirely.
func (e *Enclave) Unseal(blob []byte) ([]byte, error) {
	if len(blob) < 1 {
		return nil, ErrUnseal
	}
	pol := SealPolicy(blob[0])
	if pol != SealToMeasurement && pol != SealToSigner {
		return nil, ErrUnseal
	}
	key := e.platform.sealingKey(e.measurement, e.image.Signer, pol)
	gcm, err := newGCM(key)
	if err != nil {
		return nil, ErrUnseal
	}
	if len(blob) < 1+gcm.NonceSize()+gcm.Overhead() {
		return nil, ErrUnseal
	}
	nonce := blob[1 : 1+gcm.NonceSize()]
	out, err := gcm.Open(nil, nonce, blob[1+gcm.NonceSize():], sealAAD(pol))
	if err != nil {
		return nil, ErrUnseal
	}
	return out, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// ─── Monotonic counters ─────────────────────────────────────────────────
//
// Sealing keeps the host from reading or forging enclave state, but not
// from *replacing* it with an older sealed copy it recorded earlier. That
// rollback is invisible to the enclave unless it has some piece of state
// the host cannot rewind. Monotonic counters are that piece: platform
// storage that only ever increases.

// CounterRead returns the current value of a named counter belonging to
// this workload. Counters are namespaced by measurement, so a tampered
// rebuild cannot read — or advance — the genuine engine's counter; it gets
// its own, starting at zero.
func (e *Enclave) CounterRead(name string) uint64 {
	e.platform.mu.Lock()
	defer e.platform.mu.Unlock()
	return e.platform.counters[counterKey{owner: e.measurement, name: name}]
}

// CounterIncrement advances a counter and returns the new value. There is
// deliberately no way to decrease one: that asymmetry is the whole point,
// and it survives the enclave being destroyed and relaunched.
func (e *Enclave) CounterIncrement(name string) uint64 {
	e.platform.mu.Lock()
	defer e.platform.mu.Unlock()
	k := counterKey{owner: e.measurement, name: name}
	e.platform.counters[k]++
	return e.platform.counters[k]
}

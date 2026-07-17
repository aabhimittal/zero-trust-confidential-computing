// Package tee simulates a confidential-computing platform: a CPU that can
// launch a workload into an isolated enclave, measure exactly what it
// launched, and sign statements ("quotes") about that measurement with a
// key that never leaves the hardware.
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
//
// What it deliberately does NOT provide — because it runs inside one
// ordinary process — is actual memory isolation or encryption. See
// docs/CONCEPTS.md for the exact mapping between this simulation and real
// hardware.
package tee

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
)

// Measurement is the cryptographic identity of a launched workload,
// analogous to SGX MRENCLAVE, TDX MRTD, or the SEV-SNP launch digest.
type Measurement [32]byte

// Image is what the platform loads into an enclave. Everything that
// determines the workload's behavior must be inside it, because only what
// is measured can be verified. For VERITY that is the policy-engine build
// identifier and the policy bundle the engine will interpret.
type Image struct {
	EngineVersion string
	PolicyJSON    []byte
}

// Measure computes the launch measurement of an image. It is a pure
// function of the image contents: relaunching identical bytes yields an
// identical measurement, and any tampering — a single flipped bit in the
// policy — yields a completely different one.
func Measure(img Image) Measurement {
	h := sha256.New()
	h.Write([]byte("verity/measurement/v1\x00"))
	h.Write([]byte(img.EngineVersion))
	h.Write([]byte{0})
	h.Write(img.PolicyJSON)
	var m Measurement
	h.Sum(m[:0])
	return m
}

// Platform models the CPU and its attestation infrastructure. rootKey
// stands in for the hardware-fused attestation key whose public half is
// published by the silicon vendor (Intel PCS, AMD KDS); relying parties
// trust quotes precisely because this key is unreachable from software.
type Platform struct {
	rootKey ed25519.PrivateKey
	rootPub ed25519.PublicKey
	// TCBVersion models the platform's security patch level. Verifiers
	// reject quotes from platforms below their minimum (TCB recovery).
	TCBVersion uint32
}

// NewPlatform "manufactures" a platform with a fresh attestation root.
func NewPlatform(tcbVersion uint32) *Platform {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return &Platform{rootKey: priv, rootPub: pub, TCBVersion: tcbVersion}
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

// PolicyJSON exposes the measured policy bytes to the workload running
// inside the enclave. The policy engine is constructed from exactly these
// bytes, which is what makes its behavior a function of the measurement.
func (e *Enclave) PolicyJSON() []byte {
	return e.image.PolicyJSON
}

// Quote is a signed attestation statement: "an enclave with this
// measurement, on a platform at this TCB level, asked me to convey this
// report data." It corresponds to an SGX/TDX quote or SEV-SNP attestation
// report.
type Quote struct {
	Measurement Measurement
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
		ReportData:  reportData,
		TCBVersion:  e.platform.TCBVersion,
	}
	q.Signature = ed25519.Sign(e.platform.rootKey, q.SignedBytes())
	return q
}

// SignedBytes is the canonical byte string covered by the quote signature.
func (q Quote) SignedBytes() []byte {
	b := make([]byte, 0, len("verity/quote/v1")+32+64+4)
	b = append(b, "verity/quote/v1"...)
	b = append(b, q.Measurement[:]...)
	b = append(b, q.ReportData[:]...)
	b = binary.BigEndian.AppendUint32(b, q.TCBVersion)
	return b
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

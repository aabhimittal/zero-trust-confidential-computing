// Package attest implements the Verifier role from the RATS architecture
// (RFC 9334): it appraises attestation evidence (a tee.Quote) against
// trust anchors and endorsed reference values, and hands relying parties a
// simple verdict.
//
// The appraisal answers five independent questions, and a quote must pass
// all of them:
//
//  1. Provenance — was this quote signed by hardware we trust?
//     (signature chains to a known attestation root)
//  2. Standing — has this build been withdrawn since we endorsed it?
//     (measurement is not on the revocation list)
//  3. Platform health — is that hardware sufficiently patched?
//     (TCB version meets the verifier's minimum)
//  4. Workload identity — is the measured code a build we endorsed?
//     (measurement appears in the reference-value set, or the build's
//     signer is one we accept)
//  5. Session binding — was this quote produced for us, now, over the key
//     we are about to trust? (report data matches the expected key
//     commitment and fresh nonce)
//
// Failing any single check makes the quote worthless, which is why each
// failure is a distinct sentinel error: the caller — and the demo — can
// show exactly which link of the chain broke.
//
// A Verifier is safe for concurrent use. Appraisal happens on the request
// path of every enforcement point, while endorsement and revocation happen
// on an operator's schedule; those are genuinely concurrent, and a
// revocation that raced with an appraisal used to be a data race.
package attest

import (
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"

	"github.com/aabhimittal/zero-trust-confidential-computing/internal/tee"
)

var (
	// ErrNoTrustAnchors: the verifier holds no usable attestation root, so
	// it cannot appraise anything. Distinguished from ErrBadSignature
	// because the fault is in our configuration, not in the evidence —
	// operationally these demand very different responses.
	ErrNoTrustAnchors = errors.New("attest: verifier has no usable attestation roots configured")

	// ErrBadSignature: the quote does not chain to a trusted hardware
	// root. Either it was forged in software or it comes from a platform
	// this verifier does not trust.
	ErrBadSignature = errors.New("attest: quote signature does not verify under any trusted attestation root")

	// ErrRevokedMeasurement: a build we previously endorsed has since been
	// withdrawn — typically because a vulnerability was found in it. This
	// check deliberately runs before the endorsement lookup so that
	// revocation always wins over a stale endorsement.
	ErrRevokedMeasurement = errors.New("attest: measurement has been revoked")

	// ErrTCBOutOfDate: genuine hardware, but running below the minimum
	// accepted patch level (TCB recovery has raised the bar).
	ErrTCBOutOfDate = errors.New("attest: platform TCB version below verifier minimum")

	// ErrUnknownMeasurement: genuine, patched hardware honestly reporting
	// code we never endorsed — the signature a tampered workload cannot
	// avoid producing.
	ErrUnknownMeasurement = errors.New("attest: measurement does not match any endorsed reference value")

	// ErrReportDataMismatch: valid quote, wrong session — the report data
	// does not bind the expected key and nonce. This is what defeats
	// replaying a captured quote from a genuine enclave.
	ErrReportDataMismatch = errors.New("attest: report data does not bind the expected key and nonce")
)

// Verifier holds a relying party's appraisal policy: which hardware roots
// it trusts, which workload builds it endorses, which it has revoked, and
// the minimum platform patch level it accepts.
type Verifier struct {
	mu      sync.RWMutex
	roots   []ed25519.PublicKey
	refs    map[tee.Measurement]string
	signers map[string]string
	revoked map[tee.Measurement]string
	minTCB  uint32
}

// NewVerifier creates a verifier anchored to one or more hardware
// attestation roots.
//
// Roots of the wrong length are dropped rather than stored: ed25519.Verify
// panics on a malformed public key, so a single typo'd trust anchor would
// otherwise turn every appraisal — including hostile ones — into a crash of
// the enforcement point. Dropping them means a misconfigured verifier fails
// closed with ErrNoTrustAnchors, which is the safe direction.
func NewVerifier(minTCB uint32, roots ...ed25519.PublicKey) *Verifier {
	usable := make([]ed25519.PublicKey, 0, len(roots))
	for _, r := range roots {
		if len(r) == ed25519.PublicKeySize {
			usable = append(usable, r)
		}
	}
	return &Verifier{
		roots:   usable,
		refs:    make(map[tee.Measurement]string),
		signers: make(map[string]string),
		revoked: make(map[tee.Measurement]string),
		minTCB:  minTCB,
	}
}

// TrustAnchorCount reports how many usable attestation roots the verifier
// holds, so a deployment can assert its configuration actually loaded.
func (v *Verifier) TrustAnchorCount() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.roots)
}

// Endorse registers a known-good measurement under a human-readable name.
// In production these reference values come out-of-band from a reproducible
// build pipeline or a transparency log — never from the party being
// attested, or the check would be circular.
func (v *Verifier) Endorse(m tee.Measurement, name string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.refs[m] = name
}

// EndorseSigner accepts any build published by the named signer, rather
// than one specific measurement.
//
// This is how large fleets stay operable — a new engine build rolls out
// without re-endorsing a measurement everywhere first — and it is a real
// weakening of the guarantee: the relying party no longer knows *which*
// policy is being enforced, only who published it. VERITY's own demo pins
// measurements; signer endorsement exists here because the trade-off is one
// every production deployment actually faces, and because revocation is the
// mechanism that makes it survivable.
func (v *Verifier) EndorseSigner(signer, name string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.signers[signer] = name
}

// Revoke withdraws a measurement. A revoked build is refused even if it is
// still endorsed and still passes every other check — the ordering inside
// Appraise guarantees revocation cannot be shadowed by an endorsement that
// nobody remembered to remove.
func (v *Verifier) Revoke(m tee.Measurement, reason string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if reason == "" {
		reason = "unspecified"
	}
	v.revoked[m] = reason
}

// Appraise checks a quote against the verifier's policy and the expected
// report data. On success it returns the endorsement name of the workload
// build the quote proves is running.
func (v *Verifier) Appraise(q tee.Quote, expectedReportData [64]byte) (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if len(v.roots) == 0 {
		return "", ErrNoTrustAnchors
	}

	signed := q.SignedBytes()
	trusted := false
	for _, root := range v.roots {
		if ed25519.Verify(root, signed, q.Signature) {
			trusted = true
			break
		}
	}
	if !trusted {
		return "", ErrBadSignature
	}

	if reason, bad := v.revoked[q.Measurement]; bad {
		return "", fmt.Errorf("%w: %x… (%s)", ErrRevokedMeasurement, q.Measurement[:8], reason)
	}

	if q.TCBVersion < v.minTCB {
		return "", fmt.Errorf("%w: platform at %d, minimum %d", ErrTCBOutOfDate, q.TCBVersion, v.minTCB)
	}

	name, ok := v.refs[q.Measurement]
	if !ok {
		// Fall back to signer endorsement. An empty signer never matches,
		// so an unsigned image cannot slip through a stray empty-string
		// entry in the signer table.
		if q.Signer != "" {
			name, ok = v.signers[q.Signer]
		}
		if !ok {
			return "", fmt.Errorf("%w: got %x…", ErrUnknownMeasurement, q.Measurement[:8])
		}
	}

	if subtle.ConstantTimeCompare(q.ReportData[:], expectedReportData[:]) != 1 {
		return "", ErrReportDataMismatch
	}

	return name, nil
}

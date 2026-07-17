// Package attest implements the Verifier role from the RATS architecture
// (RFC 9334): it appraises attestation evidence (a tee.Quote) against
// trust anchors and endorsed reference values, and hands relying parties a
// simple verdict.
//
// The appraisal answers four independent questions, and a quote must pass
// all of them:
//
//  1. Provenance — was this quote signed by hardware we trust?
//     (signature chains to a known attestation root)
//  2. Platform health — is that hardware sufficiently patched?
//     (TCB version meets the verifier's minimum)
//  3. Workload identity — is the measured code a build we endorsed?
//     (measurement appears in the reference-value set)
//  4. Session binding — was this quote produced for us, now, over the key
//     we are about to trust? (report data matches the expected key
//     commitment and fresh nonce)
//
// Failing any single check makes the quote worthless, which is why each
// failure is a distinct sentinel error: the caller — and the demo — can
// show exactly which link of the chain broke.
package attest

import (
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/aabhimittal/zero-trust-confidential-computing/internal/tee"
)

var (
	// ErrBadSignature: the quote does not chain to a trusted hardware
	// root. Either it was forged in software or it comes from a platform
	// this verifier does not trust.
	ErrBadSignature = errors.New("attest: quote signature does not verify under any trusted attestation root")

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
// it trusts, which workload builds it endorses, and the minimum platform
// patch level it accepts.
type Verifier struct {
	roots  []ed25519.PublicKey
	refs   map[tee.Measurement]string
	minTCB uint32
}

// NewVerifier creates a verifier anchored to one or more hardware
// attestation roots.
func NewVerifier(minTCB uint32, roots ...ed25519.PublicKey) *Verifier {
	return &Verifier{
		roots:  roots,
		refs:   make(map[tee.Measurement]string),
		minTCB: minTCB,
	}
}

// Endorse registers a known-good measurement under a human-readable name.
// In production these reference values come out-of-band from a reproducible
// build pipeline or a transparency log — never from the party being
// attested, or the check would be circular.
func (v *Verifier) Endorse(m tee.Measurement, name string) {
	v.refs[m] = name
}

// Appraise checks a quote against the verifier's policy and the expected
// report data. On success it returns the endorsement name of the workload
// build the quote proves is running.
func (v *Verifier) Appraise(q tee.Quote, expectedReportData [64]byte) (string, error) {
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

	if q.TCBVersion < v.minTCB {
		return "", fmt.Errorf("%w: platform at %d, minimum %d", ErrTCBOutOfDate, q.TCBVersion, v.minTCB)
	}

	name, ok := v.refs[q.Measurement]
	if !ok {
		return "", fmt.Errorf("%w: got %x", ErrUnknownMeasurement, q.Measurement[:8])
	}

	if subtle.ConstantTimeCompare(q.ReportData[:], expectedReportData[:]) != 1 {
		return "", ErrReportDataMismatch
	}

	return name, nil
}

// Package policy carries the endorsed Zero Trust policy bundle. The bytes
// of policy.json are part of the measured enclave image: this file IS the
// artifact whose hash the verifier endorses, which is why editing it (as
// the demo's attacker does) changes the launch measurement and breaks
// attestation.
package policy

import _ "embed"

// Endorsed is the policy bundle shipped with this build. In a production
// pipeline this file would be reviewed, built reproducibly, and its
// resulting measurement published as a reference value.
//
//go:embed policy.json
var Endorsed []byte

// EngineVersion identifies the policy-engine build measured alongside the
// policy. In a real deployment the measurement covers the entire enclave
// binary; this constant stands in for the engine-code portion of it.
const EngineVersion = "verity-pdp/1.1.0"

// Signer names the key that published this build, standing in for SGX's
// MRSIGNER. It lets a relying party endorse a publisher rather than one
// exact measurement — an option VERITY's own demo deliberately declines,
// since pinning the measurement is what makes "which policy is enforced" a
// question attestation can answer.
const Signer = "verity-release-2026"

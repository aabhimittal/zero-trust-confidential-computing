# VERITY — Zero Trust + Confidential Computing

*Zero Trust decisions you can cryptographically trust.*

A minimalist, end-to-end demonstration — pure Go, **zero dependencies**, ~1000
lines — of how confidential computing closes Zero Trust's deepest hole:
**who trusts the policy engine?**

```
go run ./cmd/verity demo
```

## The core thesis

Zero Trust's foundational promise is *never trust, always verify*. But it has
a hidden contradiction. Every ZT deployment has a **Policy Decision Point
(PDP)** — the component that says allow or deny. That PDP runs on an OS, in a
hypervisor, on a cloud host. An attacker who compromises that layer can
manipulate every policy decision silently. You built a rigorous castle, but
**the judge is corruptible**.

Confidential computing resolves this by making the policy engine itself
*attestable*. The CPU measures the PDP's code before execution; any tampering
changes its cryptographic fingerprint; downstream services refuse decisions
from a PDP with an unknown fingerprint. The judge now carries an unforgeable
identity card issued by the silicon itself.

VERITY demonstrates that binding end to end: Zero Trust policies enforced by
a TEE-attested engine, where the enforcement code's integrity is
cryptographically provable **before** its decisions are accepted.

## The trust chain

```mermaid
flowchart LR
    subgraph Host["Untrusted host (attacker may have root)"]
        subgraph Enclave["TEE enclave"]
            PDP["PDP: policy engine<br/>+ measured policy bundle<br/>+ ephemeral decision key"]
        end
    end
    Vendor["Silicon vendor<br/>(root of trust)"] -->|"fused key"| CPU["CPU attestation key"]
    CPU -->|"signs quote:<br/>measurement + key binding"| Verifier["Verifier<br/>(endorsed reference values)"]
    Verifier -->|"appraisal verdict"| PEP["PEP: resource gateway"]
    PDP -->|"signed decisions"| PEP
    PEP -->|"enforce"| Resource[("protected<br/>resource")]
    Client["client request"] --> PEP
```

Every link is verified, none assumed:

1. **Silicon vendor → platform.** Quotes are signed by a hardware-fused
   attestation key (`tee.Platform`). Software — including a hypervisor —
   cannot forge them.
2. **Platform → workload identity.** At launch the platform measures the
   exact bytes of the PDP: engine build + policy bundle (`tee.Measure`). The
   workload cannot influence its own measurement.
3. **Workload → decision key.** The engine generates an ed25519 keypair
   *inside* the enclave and binds its public key + the verifier's fresh nonce
   into the quote's report data (`tee.KeyBinding`).
4. **Verifier → enforcement.** The PEP appraises the quote — signature, TCB
   level, endorsed measurement, key/nonce binding — and only then pins the
   decision key (`pep.Gateway.TrustPDP`).
5. **Decision → request.** Every verdict is signed over the request hash and
   a per-request nonce, so decisions can't be altered, rebound, or replayed.

The linchpin is in `pdp.NewEngineInEnclave`: the engine is constructed **only
from bytes the platform measured**, so *"which policy is being enforced"* and
*"which measurement was attested"* are the same question.

## What the demo shows

`go run ./cmd/verity demo` walks the whole story:

- **Happy path** — five Zero Trust scenarios (MFA + device posture + network
  context) decided by the attested PDP, each decision's signature verified.
- **Attack 1: backdoored relaunch.** A host-root attacker splices an
  allow-all rule into the policy and restarts the PDP. The tampered PDP
  cheerfully approves everything — but its launch measurement no longer
  matches the endorsed reference value, enrollment fails with
  `ErrUnknownMeasurement`, and the PEP fails closed.
- **Attack 2: quote replay.** An impostor replays a captured genuine quote.
  The report data binds the old nonce, not this handshake's — caught by
  `ErrReportDataMismatch`.
- **Attack 3: decision forgery.** A man-in-the-middle passes attestation
  through untouched, then injects a forged ALLOW signed with their own key.
  The signature doesn't verify under the pinned attested key —
  `ErrBadDecision`.

The test suite (`go test ./...`) covers the same three attacks plus two more:
a fully software-emulated fake TEE (`ErrBadSignature`) and genuine-but-stale
hardware (`ErrTCBOutOfDate`).

## Repository map

| Path | Role | Real-world counterpart |
|---|---|---|
| `internal/tee` | Simulated CC platform: launch, measure, quote | Intel SGX/TDX, AMD SEV-SNP, AWS Nitro |
| `internal/attest` | Verifier: appraises quotes against reference values | RATS Verifier (RFC 9334), Intel Trust Authority, Azure MAA |
| `internal/pdp` | Zero Trust policy engine, runs *inside* the enclave | OPA / Cedar / custom PDP — but attestable |
| `internal/pep` | Enforcement gateway: attest-then-pin, verify every decision | API gateway, service mesh sidecar, ZTNA proxy |
| `policy/` | The endorsed policy bundle — part of the measured image | Reviewed, reproducibly-built policy artifact |
| `cmd/verity` | End-to-end narrative demo + attackers | — |
| `docs/CONCEPTS.md` | Deep conceptual walkthrough | — |

## What's simulated vs. real

Everything cryptographic is real: ed25519 signatures, SHA-256 measurements,
nonce freshness, key binding — the protocol is the genuine article. What one
process *cannot* simulate is hardware isolation:

| Property | VERITY | Real TEE |
|---|---|---|
| Measurement of launched code | ✅ real hash, platform-stamped | ✅ MRENCLAVE / MRTD / launch digest |
| Hardware-rooted quote signature | ✅ real signature, simulated key custody | ✅ key fused in silicon, vendor cert chain |
| Key binding via report data | ✅ identical pattern | ✅ SGX `REPORTDATA`, SNP `REPORT_DATA` |
| Freshness, TCB checks, reference values | ✅ | ✅ |
| Memory encryption / isolation from host | ❌ same address space | ✅ enforced by CPU |

So: VERITY proves the *protocol* and teaches the *architecture*; it does not
protect the demo process from its own host. Porting to a real TEE means
swapping `internal/tee` for a hardware SDK ([EGo](https://github.com/edgelesssys/ego),
[go-sev-guest](https://github.com/google/go-sev-guest),
[Nitro Enclaves](https://docs.aws.amazon.com/enclaves/)) — the attest, pdp,
and pep packages are designed to survive that swap unchanged. See
[docs/CONCEPTS.md](docs/CONCEPTS.md).

## Try it

```sh
go run ./cmd/verity demo      # the full story, happy path + 3 attacks
go run ./cmd/verity measure   # print the endorsed reference measurement
go test ./...                 # 30 tests incl. all attack classes
```

Then break it yourself: edit one byte of `policy/policy.json` and run
`measure` again — the reference measurement changes completely. That's the
whole idea, felt in one keystroke.

## Further reading

- [RFC 9334 — Remote ATtestation procedureS (RATS) architecture](https://www.rfc-editor.org/rfc/rfc9334)
- [NIST SP 800-207 — Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final)
- [Confidential Computing Consortium — A Technical Analysis of Confidential Computing](https://confidentialcomputing.io/resources/white-papers-reports/)
- [AMD SEV-SNP: Strengthening VM Isolation](https://www.amd.com/content/dam/amd/en/documents/epyc-business-docs/white-papers/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf)
- [Intel SGX Explained (Costan & Devadas)](https://eprint.iacr.org/2016/086)

## License

MIT — see [LICENSE](LICENSE).

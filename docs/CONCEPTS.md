# VERITY: Complete Conceptual Walkthrough

This document is the "why" behind every design decision in the codebase.
Read it alongside the source; each section names the code it explains.

## 1. The problem, precisely stated

NIST SP 800-207 decomposes Zero Trust into three roles:

- **PDP (Policy Decision Point)** — evaluates every access request against
  policy and signals allow/deny.
- **PEP (Policy Enforcement Point)** — sits in the data path and enforces
  the PDP's verdicts.
- **Policy** — the rules, fed by signals: identity, device posture, context.

The architecture verifies *users*, *devices*, and *requests* — but the PDP
itself is verified by nothing. It is trusted because of where it runs, which
is exactly the perimeter thinking Zero Trust set out to kill. Concretely, an
attacker with hypervisor or host-root access can:

1. patch the PDP process in memory (flip `deny` to `allow` on the way out),
2. swap the policy file it loads,
3. impersonate the PDP on the network and answer with forged decisions, or
4. replay old favorable decisions.

TLS and service identity certificates don't help: they authenticate *a key*,
not *the code holding it*. A compromised PDP presents the same certificate as
a healthy one.

## 2. What a TEE actually gives you

A Trusted Execution Environment (Intel SGX/TDX, AMD SEV-SNP, AWS Nitro
Enclaves, Arm CCA) provides two distinct things that are easy to conflate:

- **Isolation** (runtime property): enclave memory is encrypted and
  inaccessible to the OS/hypervisor. This defeats attack #1 above.
- **Attestation** (verifiable property): the CPU *measures* the code it
  loads — a cryptographic hash accumulated at launch — and will sign
  statements about that measurement with a key fused into the silicon and
  certified by the vendor (Intel PCS, AMD KDS). This defeats attacks #2–#4,
  and it is the property VERITY is about.

The measurement has different names per technology — SGX `MRENCLAVE`, TDX
`MRTD`, SEV-SNP launch digest, Nitro PCRs — but the same semantics: **the
identity of a workload is the hash of its bytes, computed by hardware the
workload cannot influence.** `internal/tee` models exactly this:
`Measure()` is a pure function of the image; `Enclave.measurement` is
unexported and set only by `Platform.Launch`.

### The quote

A quote (SGX/TDX term; SEV-SNP says "attestation report") is a signed
structure: *"An enclave measuring `M`, on a platform at TCB level `T`, asked
me to convey these 64 bytes of `REPORTDATA`."* Only code inside the enclave
can request one (SGX gates `EREPORT` on enclave mode) — modeled by
`Enclave.Quote` being a method on the enclave. The signature chains to the
vendor root, modeled by `Platform.rootKey`.

## 3. The key-binding pattern (`tee.KeyBinding`)

Attestation proves *what code* is running. But the PEP doesn't talk to
"code" — it consumes *signed decisions*. The bridge is the single most
important pattern in confidential computing:

1. The workload generates a keypair **inside** the enclave
   (`pdp.NewEngineInEnclave`). The private key never exists outside.
2. It puts `H(pubkey) ‖ nonce` into the quote's report data
   (`pdp.Engine.Attest`).
3. The verifier checks the quote, then knows: *this public key is
   controlled by that measured code, and this quote was made for me, now.*
4. From then on, a signature by that key **is** a statement by that code.

The hash commits to the key (32 bytes of a 64-byte field), and the nonce
supplies freshness. Without the nonce, a captured quote could be replayed
forever (demo Attack 2 / `TestReplayedQuoteRejected`). Without the key
commitment, any attacker could pair a genuine quote with their own key
(`TestAppraiseRejectsWrongKeyBinding`).

Real-world equivalents: SGX RA-TLS embeds the quote in an X.509 extension of
a self-signed TLS cert whose key hash sits in `REPORTDATA`; SEV-SNP guests
do the same with `REPORT_DATA`. VERITY strips away TLS to expose the bare
mechanism.

## 4. The verifier and appraisal (`internal/attest`)

RFC 9334 (RATS) names the roles VERITY implements:

| RATS role | VERITY |
|---|---|
| Attester | the PDP enclave (`pdp.Engine` + `tee.Enclave`) |
| Evidence | `tee.Quote` |
| Endorser | the reproducible-build pipeline that publishes reference measurements (`Verifier.Endorse`) |
| Verifier | `attest.Verifier.Appraise` |
| Relying Party | `pep.Gateway` |

Appraisal is four *independent* checks, each with its own sentinel error so
failures teach:

1. **Provenance** — signature chains to a trusted root (`ErrBadSignature`).
   Defeats fully software-emulated "TEEs" (`TestFakePlatformRejected`).
2. **Platform health** — TCB version ≥ floor (`ErrTCBOutOfDate`). Real
   platforms get microcode fixes; verifiers raise the bar ("TCB recovery")
   and old firmware stops attesting.
3. **Workload identity** — measurement ∈ endorsed set
   (`ErrUnknownMeasurement`). Note the epistemics: the hardware *honestly*
   reports tampered code; it's the comparison against endorsed values that
   converts honesty into rejection.
4. **Session binding** — report data matches expected key + fresh nonce
   (`ErrReportDataMismatch`).

Order matters: an unverified signature makes every other field attacker-
chosen, so it's checked first.

**Where reference values come from** is the part most demos hand-wave: they
must arrive *out-of-band* — a reproducible build plus a signed statement (or
transparency log) that "commit X builds to measurement M". They can never
come from the attester, or the check is circular. In the demo the verifier
computes the reference from its own copy of the endorsed image
(`cmd/verity` section 2), standing in for that pipeline.

## 5. Policy as measured data (`internal/pdp`, `policy/`)

VERITY measures `EngineVersion ‖ PolicyJSON` — the policy is *inside* the
attested identity. This is a deliberate architectural stance:

> Any input that determines the PDP's behavior must be measured, because an
> unmeasured input is an unattested one.

If the policy were loaded from a file outside the measurement (as most
real-world OPA deployments do!), a host attacker could leave the endorsed
binary untouched and swap the rules — attestation would still pass. VERITY's
constructor makes this structurally impossible: `NewEngineInEnclave` reads
policy bytes *only* from the measured image (`Enclave.PolicyJSON`), so
engine behavior is a deterministic function of the measurement.

The trade-off is operational: every policy change is a new measurement that
must be endorsed and rolled out like a code deploy. Real systems choose
between (a) measuring policy like VERITY, (b) measuring a *policy signing
key* and shipping signed policies at runtime, or (c) sealed policy storage.
(a) is the simplest to reason about, which is why a teaching codebase uses it.

The policy model itself is orthodox Zero Trust in miniature:

- **default deny** — access is a granted exception, never a baseline;
- **explicit deny overrides** any allow (`Engine.Decide` returns on the
  first fired deny);
- conditions over the canonical signal classes: identity strength
  (`min_auth` over password < mfa < hardware-key), device posture
  (managed/patched/encrypted), and context (network zone), plus roles and
  resource sensitivity bands.

## 6. Decision integrity (`pdp.Decision`, `pep.Gateway`)

An attested PDP is worthless if its verdicts can be tampered in transit.
Each `Decision` is signed over:

- the **verdict** (allow/deny + rule + reason) — can't flip deny→allow;
- the **request hash** (`HashRequest`, canonical encoding) — can't take
  alice's ALLOW and serve it for mallory's request;
- the **PEP's per-request nonce** — can't replay yesterday's ALLOW today
  (`TestReplayedDecisionRejected`).

Variable-length fields in `SignedBytes` are length-prefixed so no two
distinct decisions serialize identically, and both quote and decision
signatures use domain-separation tags (`verity/quote/v1`,
`verity/decision/v1`) so a signature can never be confused across contexts.

The PEP's security argument is one invariant: **`pinnedKey` is only ever
written by a successful appraisal.** Everything else follows — decisions are
accepted iff signed by a key vouched for by attested code, vouched for by
hardware, vouched for by the vendor. And the failure mode is fail-closed
(`ErrNoAttestedPDP`): a missing judge is a deny, never a pass-through.

## 7. The threat model, honestly

Defeated (by the architecture, and demonstrated in code):

| Attack | Caught by | Demo/test |
|---|---|---|
| Tampered policy/engine relaunch | reference-value mismatch | Attack 1, `TestTamperedPDPRejected` |
| Software-emulated fake TEE | quote signature | `TestFakePlatformRejected` |
| Quote replay / impostor key | nonce + key binding | Attack 2, `TestReplayedQuoteRejected` |
| Forged decision (MITM) | decision signature | Attack 3, `TestForgedDecisionRejected` |
| Decision replay | per-request nonce | `TestReplayedDecisionRejected` |
| Unpatched platform | TCB floor | `TestStaleTCBRejected` |

Out of scope — and out of scope for real TEEs too, which is worth teaching:

- **Endorsed-but-buggy code.** Attestation proves you're running exactly the
  code you endorsed, including its bugs. It is integrity, not correctness.
- **Bad policy.** An over-permissive rule attests perfectly.
- **Malicious signal sources.** If the device-posture feed lies, the PDP
  correctly evaluates false inputs (garbage in, attested garbage out).
- **Denial of service.** A host can always kill the enclave; the guarantee
  is that it fails *closed*, not that it stays up.
- **Side channels / TCB compromise.** Real attacks on real TEEs exist; TCB
  recovery (the version floor) is the deployed mitigation loop.

## 8. Porting to real hardware

The package boundaries are drawn so only `internal/tee` is a simulation:

1. **Intel TDX / AMD SEV-SNP** — run the PDP in a confidential VM; replace
   `Enclave.Quote` with `configfs-tsm` / `go-sev-guest` report generation
   (put `KeyBinding` output in `REPORT_DATA`); replace `attest.Verifier`'s
   root-key check with the vendor certificate chain and fetch reference
   values from your build pipeline.
2. **SGX via EGo** — compile the engine into an enclave; `Quote` maps to
   EGo's `GetRemoteReport`, appraisal to `VerifyRemoteReport` + MRENCLAVE
   comparison.
3. **AWS Nitro** — the PDP becomes an enclave image (EIF); measurements are
   PCRs; the attestation document is signed by the Nitro hypervisor and
   verified against the AWS root.

`attest`'s four-check structure, `pdp`'s measured-policy constructor, and
`pep`'s pin-after-appraisal invariant carry over unchanged — they *are* the
architecture.

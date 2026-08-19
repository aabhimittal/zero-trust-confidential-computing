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

Appraisal is five *independent* checks, each with its own sentinel error so
failures teach:

1. **Provenance** — signature chains to a trusted root (`ErrBadSignature`).
   Defeats fully software-emulated "TEEs" (`TestFakePlatformRejected`).
2. **Standing** — the measurement has not been withdrawn since it was
   endorsed (`ErrRevokedMeasurement`). A build found vulnerable must stop
   attesting even though nothing about it changed.
3. **Platform health** — TCB version ≥ floor (`ErrTCBOutOfDate`). Real
   platforms get microcode fixes; verifiers raise the bar ("TCB recovery")
   and old firmware stops attesting.
4. **Workload identity** — measurement ∈ endorsed set, or the build's signer
   is one we accept (`ErrUnknownMeasurement`). Note the epistemics: the
   hardware *honestly* reports tampered code; it's the comparison against
   endorsed values that converts honesty into rejection.
5. **Session binding** — report data matches expected key + fresh nonce
   (`ErrReportDataMismatch`).

Order matters, twice over. An unverified signature makes every other field
attacker-chosen, so it is checked first — and it also means a revocation
message cannot become an oracle telling an attacker which measurements a
verifier knows about (`TestRevocationIsNotAnOracleForForgedQuotes`).
Revocation is then checked *before* the endorsement lookup, so forgetting to
delete a reference value cannot silently reinstate a withdrawn build.

**Endorsing a signer instead of a measurement** (`EndorseSigner`) is how
large fleets stay operable: a new build rolls out without re-endorsing a
measurement everywhere first. It is also a real weakening — the relying party
no longer knows *which* policy is enforced, only who published it. VERITY's
own demo pins measurements; the option exists because the trade-off is one
every production deployment faces, and revocation is what makes it
survivable.

**Where reference values come from** is the part most demos hand-wave: they
must arrive *out-of-band* — a reproducible build plus a signed statement (or
transparency log) that "commit X builds to measurement M". They can never
come from the attester, or the check is circular. In the demo the verifier
computes the reference from its own copy of the endorsed image
(`cmd/verity` section 2), standing in for that pipeline.

## 5. Policy as measured data (`internal/pdp`, `policy/`)

VERITY measures `Signer ‖ EngineVersion ‖ PolicyJSON` — the policy is
*inside* the attested identity. This is a deliberate architectural stance:

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

All signed structures are framed by `internal/canon`, which enforces two
rules that are easy to state and easy to get wrong:

- **Domain separation.** Every encoding opens with a unique label
  (`verity/quote/v2`, `verity/decision/v2`, `verity/audit/entry/v1`), so
  bytes produced for one purpose can never be reinterpreted as valid bytes
  for another.
- **Length prefixing and type tagging.** Every variable-length field carries
  its length, and every field carries a byte naming its type. Without the
  first, `{version: "a\x00b", policy: "c"}` and `{version: "a", policy:
  "b\x00c"}` measure identically. Without the second, the integer `0` and the
  empty string are the same eight bytes — harmless within a fixed schema, but
  that makes injectivity depend on an invariant held by callers rather than
  by the encoder.

The PEP's security argument is one invariant: **`pinnedKey` is only ever
written by a successful appraisal.** Everything else follows — decisions are
accepted iff signed by a key vouched for by attested code, vouched for by
hardware, vouched for by the vendor. And the failure mode is fail-closed
(`ErrNoAttestedPDP`): a missing judge is a deny, never a pass-through.

## 7. Obligations: when "allow" is not a plain yes

Real authorization answers are rarely binary. "Yes, read-only." "Yes, for the
next ten minutes." "Yes, with these columns masked." A model that can only say
allow or deny forces every such case into an unqualified allow, and the
qualification then lives in a wiki page nobody enforces.

`pdp.Obligations` rides along with an allow, and — this is the part that
matters — is **covered by the decision signature**. An on-path attacker who
forwards a genuine ALLOW but deletes `read_only` has not weakened a grant;
they have produced an invalid signature. Downgrading is arithmetically
identical to forging, and fails identically (Attack 4).

Two consequences worth stating:

- Obligations are meaningless on a deny, so policy validation rejects them
  there rather than silently ignoring them.
- Comparing obligations needs `Obligations.Equal`, not `==`: the struct
  contains a slice. A caller reaching for `==` fails to compile; a caller who
  compares only the scalar fields silently succeeds, which is worse.

## 8. Fail-open is the direction that matters

Access-control bugs are not symmetric. Denying too much is reported within
the hour; allowing too much may never be reported. Several checks in `pdp`
exist purely because the natural implementation fails the wrong way:

| Signal | Naive behaviour | Why it fails open |
|---|---|---|
| `Resource.Sensitivity` unset (0) | scores below every `min_sensitivity` | evades the "no sensitive data from public networks" deny rule |
| `Context.Network` unrecognised | matches no rule's network list | evades every network-scoped deny |
| `Subject.AuthMethod` unrecognised | scores 0 | passes any rule that omits `min_auth` |
| Misspelled condition key in policy | ignored by lenient JSON decoding | becomes a rule with *no* such requirement |
| Unknown network in a policy rule | matches nothing | a deny rule that reads as protection and provides none |

The general shape: **a predicate over an uninterpretable value is a predicate
that does not fire**, and a deny rule that does not fire is an allow. So
`Request.Validate` refuses to judge requests carrying signals the engine
cannot interpret, and policy validation refuses to load rules whose
conditions can never fire. The refusal is still a *signed* decision
(`InvalidRequestRuleID`), so the enforcement point gets a verifiable answer
rather than a bare error that an attacker could spoof on the wire.

## 9. The record: making history as trustworthy as the verdict

A signed decision proves what the PDP said about one request. It says nothing
about the set of decisions, which is what auditors and incident responders
actually ask about. A host that cannot forge a decision can still delete the
ones that embarrass it.

`internal/audit` closes this in three layers, each defeating an attack the
previous one leaves open:

1. **Hash chaining.** Entries commit to their predecessor, so nothing can be
   altered, reordered, or removed from the middle. Defeats casual editing —
   but not an attacker willing to recompute the chain.
2. **Signed checkpoints.** The enclave signs `(count, head)` with the same
   attested key that signs decisions. A rebuilt chain no longer matches, and
   *truncation* becomes detectable: dropping the last hour leaves a chain
   that hashes correctly but matches no checkpoint anyone holds.
3. **Monotonic-counter binding.** Checkpoints must survive restarts, so they
   are sealed and handed to the untrusted host — which is free to serve back
   an older copy. That rollback restores a genuinely sealed, genuinely
   signed, genuinely consistent, but *stale* log. Each checkpoint advances a
   platform counter the host cannot rewind.

Entries live outside the enclave; only the count and head stay inside.
Constant memory for an unbounded log, and the right trust model: the host may
hold the records, it simply cannot change them undetected.

### The ordering that makes rollback distinguishable from a crash

This is the subtlest correctness argument in the codebase, and the first
version of it was wrong.

Persisting state and advancing a counter cannot be atomic, so a crash between
them leaves them disagreeing. Tolerating that disagreement is necessary —
otherwise every unclean shutdown is an incident — but a tolerance the
attacker can also produce is not a tolerance, it is a hole.

*Increment first, then seal:* a crash leaves the counter one **ahead** of the
stored state. So does an attacker who restores the immediately preceding
checkpoint. The two are indistinguishable, and any crash tolerance becomes an
undetectable one-checkpoint rollback.

*Seal first, then increment:* a crash leaves the stored state one **ahead** of
the counter. A rollback replays a blob the enclave sealed earlier, so it
always leaves the state **behind**. The two failure signatures point in
opposite directions, and no tolerance has to be extended to the attacker's
side at all.

`Log.Checkpoint` therefore seals before it increments, `Open` treats
"state ahead" as `ErrCounterLagged` (benign, repaired, still surfaced) and
"state behind" as `ErrRollback` (always an attack), and
`TestSingleStepRollbackIsNotMistakenForACrash` pins the distinction.

## 10. Quorum: the one signal a single PDP cannot produce

Attestation proves the PDP is running the build you endorsed. It cannot prove
that build is *correct*. A logic bug, or a policy that says something its
authors did not intend, is faithfully attested and faithfully wrong — and
every gateway in the fleet agrees, because they run the same code.

`pep.Quorum` asks a different question: do several independently attested
judges reach the same verdict? Disagreement becomes evidence in itself
(`ErrQuorumDissent`), and the only safe response is to deny and escalate.

Three details make it a real quorum rather than theatre:

- **Agreement includes obligations.** Two engines that both say allow but
  disagree on whether the grant is read-only have not agreed on anything an
  enforcement point could act on.
- **Diversity is enforced.** Members backed by the same PDP identity are one
  opinion counted twice — precisely what an attacker arranges when they can
  redirect several gateways at one PDP but cannot compromise several
  (`ErrQuorumNotDiverse`).
- **Unavailability fails closed.** A quorum that degrades to "whoever
  answered" is not a quorum (`ErrQuorumUnavailable`).

## 11. Attestation is a moment, not a standing fact

An enrollment records that a PDP proved itself *once*. Treating that as
permanent means a build revoked this morning keeps serving until someone
restarts a gateway. `pep.WithMaxAttestationAge` expires enrollments and forces
a fresh handshake.

One edge worth calling out: a clock running **backwards** is treated as
expiry, not freshness. Otherwise the cheapest way to keep a revoked PDP alive
indefinitely would be to wind the host's clock back — and the host is the
adversary.

## 12. The threat model, honestly

Defeated (by the architecture, and demonstrated in code):

| Attack | Caught by | Demo/test |
|---|---|---|
| Tampered policy/engine relaunch | reference-value mismatch | Attack 1, `TestTamperedPDPRejected` |
| Software-emulated fake TEE | quote signature | `TestFakePlatformRejected` |
| Quote replay / impostor key | nonce + key binding | Attack 2, `TestReplayedQuoteRejected` |
| Forged decision (MITM) | decision signature | Attack 3, `TestForgedDecisionRejected` |
| Obligation stripping / downgrade | obligations inside the signature | Attack 4, `TestStrippingOrWeakeningObligationsBreaksTheSignature` |
| Decision replay | per-request nonce | `TestReplayedDecisionRejected` |
| Retired decision key still answering | re-enrollment rotates the pin | `TestReEnrollmentRetiresTheOldDecisionKey` |
| Unpatched platform | TCB floor | `TestStaleTCBRejected` |
| Vulnerable endorsed build | revocation, checked before endorsement | Attack 6, `TestRevocationOverridesAStandingEndorsement` |
| Audit-log editing / truncation | hash chain + signed checkpoint | `TestVerifyDetectsEveryEditToTheEntryRun` |
| Audit-log rollback across restart | sealed state + monotonic counter | Attack 5, `TestRollbackToAnEarlierCheckpointIsDetected` |
| Audit-log deletion | counter remembers checkpoints happened | `TestDeletingTheSealedStateIsDetected` |
| Tampered build reading enclave state | measurement-bound sealing keys | `TestTamperedBuildCannotTouchTheGenuineLog` |
| Divergent attested judges | quorum dissent | Attack 7, `TestQuorumRefusesToGuessWhenAttestedJudgesDisagree` |
| Stale attestation | enrollment expiry | `TestAttestationExpires` |

Out of scope — and out of scope for real TEEs too, which is worth teaching:

- **Endorsed-but-buggy code.** Attestation proves you're running exactly the
  code you endorsed, including its bugs. It is integrity, not correctness.
  A quorum of *diverse* builds narrows this; it does not close it.
- **Bad policy.** An over-permissive rule attests perfectly. Validation
  catches rules that can never fire, not rules that fire too readily.
- **Malicious signal sources.** If the device-posture feed lies, the PDP
  correctly evaluates false inputs (garbage in, attested garbage out).
  Request validation rejects *uninterpretable* signals, not dishonest ones.
- **Denial of service.** A host can always kill the enclave; the guarantee
  is that it fails *closed*, not that it stays up. Deleting the sealed audit
  state is detectable but not preventable.
- **Side channels / TCB compromise.** Real attacks on real TEEs exist; TCB
  recovery (the version floor) plus revocation is the deployed mitigation
  loop.
- **Sealing's residual asymmetry.** `SealToSigner` lets a *downgraded* build
  from the same signer read state written by a newer one. That is the price
  of painless upgrades, stated in
  `TestSealToSignerFollowsThePublisherNotTheBuild` rather than hidden.

## 13. Porting to real hardware

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

`attest`'s five-check structure, `pdp`'s measured-policy constructor,
`pep`'s pin-after-appraisal invariant, and `audit`'s seal-then-increment
ordering carry over unchanged — they *are* the architecture. Only the
mechanics beneath them change: `Enclave.Seal` becomes `EGETKEY`-derived
sealing or an SNP derived key, and `CounterIncrement` becomes an SGX
monotonic counter, a vTPM NV counter, or an external counter service. Each
real counter has its own durability and rate limits, and those are the
constraint that shapes how often you can afford to checkpoint.

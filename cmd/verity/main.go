// Command verity runs the end-to-end demonstration of a TEE-attested Zero
// Trust policy engine: the full trust chain being built, exercised, and
// then attacked seven different ways.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"time"

	"github.com/aabhimittal/zero-trust-confidential-computing/internal/attest"
	"github.com/aabhimittal/zero-trust-confidential-computing/internal/audit"
	"github.com/aabhimittal/zero-trust-confidential-computing/internal/pdp"
	"github.com/aabhimittal/zero-trust-confidential-computing/internal/pep"
	"github.com/aabhimittal/zero-trust-confidential-computing/internal/tee"
	"github.com/aabhimittal/zero-trust-confidential-computing/policy"
)

func main() {
	cmd := "demo"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "demo":
		demo()
	case "measure":
		// Prints the reference measurement of the endorsed build — what a
		// reproducible-build pipeline would publish for verifiers.
		m := tee.Measure(endorsedImage())
		fmt.Printf("endorsed build:      %s\n", policy.EngineVersion)
		fmt.Printf("build signer:        %s\n", policy.Signer)
		fmt.Printf("launch measurement:  %x\n", m)
	default:
		fmt.Fprintf(os.Stderr, "usage: verity [demo|measure]\n")
		os.Exit(2)
	}
}

func endorsedImage() tee.Image {
	return tee.Image{
		Signer:        policy.Signer,
		EngineVersion: policy.EngineVersion,
		PolicyJSON:    policy.Endorsed,
	}
}

func section(n int, title string) {
	fmt.Printf("\n─── [%d] %s %s\n", n, title, dashes(70-len(title)))
}

func dashes(n int) string {
	if n < 3 {
		n = 3
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = '-'
	}
	return string(b)
}

func short(b []byte) string { return fmt.Sprintf("%x…", b[:8]) }

func shortM(m tee.Measurement) string { return short(m[:]) }

func ok(label string) { fmt.Printf("        ✓ %s\n", label) }

func blocked(err error) { fmt.Printf("        ✗ %v\n", err) }

// requests exercised against every PDP in the demo.
var scenarios = []struct {
	who string
	req pdp.Request
}{
	{
		who: "alice: payroll admin, MFA, healthy managed laptop, corp network → payroll-db",
		req: pdp.Request{
			Subject:  pdp.Subject{ID: "alice", Roles: []string{"payroll-admin"}, AuthMethod: "mfa"},
			Device:   pdp.Device{Managed: true, OSPatched: true, DiskEncrypted: true},
			Resource: pdp.Resource{Name: "payroll-db", Sensitivity: 3},
			Context:  pdp.Context{Network: "corp"},
		},
	},
	{
		who: "bob: password only, unmanaged personal machine, public wifi → payroll-db",
		req: pdp.Request{
			Subject:  pdp.Subject{ID: "bob", Roles: []string{"engineer"}, AuthMethod: "password"},
			Device:   pdp.Device{Managed: false, OSPatched: false, DiskEncrypted: false},
			Resource: pdp.Resource{Name: "payroll-db", Sensitivity: 3},
			Context:  pdp.Context{Network: "public"},
		},
	},
	{
		who: "carol: MFA but unpatched device, vpn → customer-pii",
		req: pdp.Request{
			Subject:  pdp.Subject{ID: "carol", Roles: []string{"support"}, AuthMethod: "mfa"},
			Device:   pdp.Device{Managed: true, OSPatched: false, DiskEncrypted: true},
			Resource: pdp.Resource{Name: "customer-pii", Sensitivity: 3},
			Context:  pdp.Context{Network: "vpn"},
		},
	},
	{
		who: "dave: password, personal machine, public wifi → wiki",
		req: pdp.Request{
			Subject:  pdp.Subject{ID: "dave", Roles: []string{"engineer"}, AuthMethod: "password"},
			Device:   pdp.Device{Managed: false, OSPatched: true, DiskEncrypted: false},
			Resource: pdp.Resource{Name: "wiki", Sensitivity: 1},
			Context:  pdp.Context{Network: "public"},
		},
	},
	{
		who: "mallory: stolen password, unmanaged box, vpn → customer-pii",
		req: pdp.Request{
			Subject:  pdp.Subject{ID: "mallory", Roles: []string{"engineer"}, AuthMethod: "password"},
			Device:   pdp.Device{Managed: false, OSPatched: true, DiskEncrypted: false},
			Resource: pdp.Resource{Name: "customer-pii", Sensitivity: 3},
			Context:  pdp.Context{Network: "vpn"},
		},
	},
}

// mallory is the request every attack in the demo is trying to get approved.
var mallory = scenarios[4].req

// auditedPDP is the PDP as it actually ships: the engine and its audit log
// live together inside the enclave, so every decision the engine issues is
// chained before it leaves. The log is not a downstream consumer that can
// be bypassed by talking to the engine directly.
type auditedPDP struct {
	*pdp.Engine
	log     *audit.Log
	entries []audit.Entry
}

func (a *auditedPDP) Decide(req pdp.Request, nonce [32]byte) pdp.Decision {
	d := a.Engine.Decide(req, nonce)
	a.entries = append(a.entries, a.log.Append(d))
	return d
}

func demo() {
	fmt.Println("VERITY — Zero Trust decisions you can cryptographically trust")
	fmt.Println("=============================================================")
	fmt.Println()
	fmt.Println("Thesis: every Zero Trust system has a judge (the Policy Decision Point).")
	fmt.Println("If the host running the judge is compromised, every 'verified' decision")
	fmt.Println("is attacker-controlled. Confidential computing makes the judge itself")
	fmt.Println("verifiable: hardware measures the PDP's code, enforcement points refuse")
	fmt.Println("decisions from any PDP whose measurement they did not endorse, and the")
	fmt.Println("record of what was decided is as tamper-evident as the decisions.")

	// ── 1. Platform ──────────────────────────────────────────────────────
	section(1, "Confidential-computing platform boots")
	platform := tee.NewPlatform(7)
	fmt.Printf("    hardware attestation root: %s  (public half of the CPU-fused key)\n",
		short(platform.AttestationRoot()))
	fmt.Printf("    platform TCB version:      %d\n", platform.TCBVersion)

	// ── 2. Endorsement ───────────────────────────────────────────────────
	section(2, "Verifier endorses the known-good PDP build")
	image := endorsedImage()
	reference := tee.Measure(image)
	verifier := attest.NewVerifier(5, platform.AttestationRoot())
	verifier.Endorse(reference, policy.EngineVersion+"+policy-2026.08.1")
	fmt.Printf("    reference measurement:     %s  (from the reviewed, reproducible build)\n", short(reference[:]))
	fmt.Println("    the verifier computed this from ITS OWN copy of the endorsed image —")
	fmt.Println("    reference values never come from the party being attested.")

	// ── 3. Launch ────────────────────────────────────────────────────────
	section(3, "Genuine PDP launches inside an enclave, with a sealed audit log")
	enclave := platform.Launch(image)
	engine, err := pdp.NewEngineInEnclave(enclave)
	if err != nil {
		panic(err)
	}
	store := &audit.MemStore{} // the untrusted host's disk
	log, err := audit.Open(enclave, engine, store, engine.PolicyVersion())
	if err != nil {
		panic(err)
	}
	judge := &auditedPDP{Engine: engine, log: log}
	fmt.Printf("    launch measurement:        %s  (stamped by the platform, not the code)\n",
		shortM(enclave.Measurement()))
	fmt.Printf("    decision signing key:      %s  (generated inside the enclave)\n", short(engine.PublicKey()))
	fmt.Printf("    policy loaded:             version %s, %d rules — from measured bytes only\n",
		engine.PolicyVersion(), engine.RuleCount())

	// ── 4. Enrollment ────────────────────────────────────────────────────
	section(4, "PEP challenges the PDP and appraises the quote")
	gateway := pep.NewGateway(verifier)
	if err := gateway.TrustPDP(judge); err != nil {
		panic(err)
	}
	ok("quote signature   — chains to the trusted hardware root")
	ok("revocation status — this build has not been withdrawn")
	ok("TCB level         — 7 ≥ verifier minimum 5")
	ok("measurement       — matches endorsed reference value")
	ok("key binding       — report data commits to the PDP key + fresh nonce")
	fmt.Printf("    → PEP pins the decision key of attested build %q\n", gateway.PDPBuild())

	// ── 5. Enforcement ───────────────────────────────────────────────────
	section(5, "Zero Trust in action — every decision verified against the attested key")
	runScenarios(gateway)

	// ── 6. Audit ─────────────────────────────────────────────────────────
	section(6, "The record: hash-chained, enclave-signed, rollback-resistant")
	checkpoint, err := log.Checkpoint()
	if err != nil {
		panic(err)
	}
	fmt.Printf("    %d decisions chained; head %s\n", checkpoint.Count, short(checkpoint.Head[:]))
	fmt.Printf("    checkpoint signed by the same attested key that signs decisions,\n")
	fmt.Printf("    sealed to measurement %s, and bound to platform counter %d.\n",
		shortM(enclave.Measurement()), checkpoint.Counter)
	if err := audit.Verify(judge.entries, checkpoint, engine.PublicKey()); err == nil {
		ok("auditor replays the chain and it matches the signed checkpoint")
	}

	fmt.Println("\n    an auditor is handed a doctored copy of the log:")
	doctored := append([]audit.Entry(nil), judge.entries...)
	doctored[1].Allow = true // flip bob's DENY to an ALLOW
	blocked(audit.Verify(doctored, checkpoint, engine.PublicKey()))

	fmt.Println("\n    ...and a copy with the last two entries quietly dropped:")
	blocked(audit.Verify(judge.entries[:len(judge.entries)-2], checkpoint, engine.PublicKey()))

	// ── 7. Attack 1 ──────────────────────────────────────────────────────
	section(7, "ATTACK 1: host-level attacker relaunches the PDP with a backdoored policy")
	tamperedEnclave := platform.Launch(tamperedImage())
	tamperedEngine, err := pdp.NewEngineInEnclave(tamperedEnclave)
	if err != nil {
		panic(err)
	}
	fmt.Println("    attacker has root on the host: injects rule {\"id\":\"maintenance-backdoor\",")
	fmt.Println("    \"effect\":\"allow\",\"resources\":[\"*\"]} and restarts the PDP.")
	fmt.Printf("    tampered measurement:      %s\n", shortM(tamperedEnclave.Measurement()))
	fmt.Printf("    endorsed reference:        %s\n", short(reference[:]))
	fmt.Println()
	fmt.Println("    the tampered PDP itself now happily approves mallory:")
	var zero [32]byte
	fmt.Printf("        tampered PDP says: ALLOW (%s)\n", tamperedEngine.Decide(mallory, zero).Reason)
	fmt.Println()
	fmt.Println("    but the hardware measured what actually launched, and enrollment fails:")
	blocked(gateway.TrustPDP(tamperedEngine))
	fmt.Println("    the PEP is now fail-closed — no attested judge, no access:")
	if _, err := gateway.Authorize(mallory); err != nil {
		fmt.Printf("        mallory → customer-pii: REFUSED (%v)\n", err)
	}
	fmt.Println("    the backdoored engine also cannot reach the real log: counters and")
	fmt.Println("    sealing keys are namespaced by measurement, so it gets an empty one.")

	// ── 8. Attack 2 ──────────────────────────────────────────────────────
	section(8, "ATTACK 2: impostor replays a captured quote from the genuine PDP")
	fmt.Println("    a network attacker recorded the genuine enclave's quote and presents it")
	fmt.Println("    as their own attestation, hoping to get their key pinned.")
	blocked(gateway.TrustPDP(&impostor{genuine: engine}))
	fmt.Println("    the replayed quote binds the OLD nonce and the GENUINE key — it cannot")
	fmt.Println("    match this handshake's fresh nonce, and it could never bind the")
	fmt.Println("    impostor's key, because quoting happens only inside the enclave.")

	// ── 9. Attack 3 ──────────────────────────────────────────────────────
	section(9, "ATTACK 3: man-in-the-middle injects a forged ALLOW decision")
	if err := gateway.TrustPDP(&decisionForger{genuine: judge}); err != nil {
		panic(err) // forwards genuine attestation, so enrollment succeeds
	}
	fmt.Println("    an on-path attacker intercepts the PEP↔PDP channel and answers")
	fmt.Println("    mallory's request with a forged ALLOW, signed with their own key.")
	if _, err := gateway.Authorize(mallory); err != nil {
		fmt.Printf("        mallory → customer-pii: REFUSED (%v)\n", err)
	}
	fmt.Println("    the forged decision is not signed by the key the quote attested, so")
	fmt.Println("    it dies at the PEP. Controlling the network buys the attacker nothing.")

	// ── 10. Attack 4 ─────────────────────────────────────────────────────
	section(10, "ATTACK 4: downgrade — strip the obligations off a genuine ALLOW")
	if err := gateway.TrustPDP(&obligationStripper{genuine: judge}); err != nil {
		panic(err)
	}
	fmt.Println("    carol's access to customer-pii is granted read-only, with ssn and")
	fmt.Println("    bank_account masked. The attacker forwards the genuine ALLOW but")
	fmt.Println("    deletes the obligations, hoping the PEP grants unrestricted access.")
	support := scenarios[2].req
	support.Device.OSPatched = true // let carol's request actually succeed
	if _, err := gateway.Authorize(support); err != nil {
		fmt.Printf("        carol → customer-pii: REFUSED (%v)\n", err)
	}
	fmt.Println("    obligations are inside the signature, so weakening a grant is")
	fmt.Println("    arithmetically identical to inventing one. Both are forgeries.")

	// ── 11. Attack 5 ─────────────────────────────────────────────────────
	section(11, "ATTACK 5: host rolls the audit log back to hide what it recorded")
	stale := append([]byte(nil), store.Blob...) // attacker snapshots the sealed state
	if err := gateway.TrustPDP(judge); err != nil {
		panic(err)
	}
	if _, err := gateway.Authorize(scenarios[0].req); err != nil {
		panic(err)
	}
	later, err := log.Checkpoint()
	if err != nil {
		panic(err)
	}
	fmt.Printf("    log advances to %d entries at counter %d, then the host kills the\n",
		later.Count, later.Counter)
	fmt.Println("    enclave and restores the sealed state it snapshotted earlier.")
	store.Blob = stale

	restarted := platform.Launch(image) // identical bytes: attestation would pass
	restartedEngine, err := pdp.NewEngineInEnclave(restarted)
	if err != nil {
		panic(err)
	}
	_, err = audit.Open(restarted, restartedEngine, store, restartedEngine.PolicyVersion())
	blocked(err)
	fmt.Println("    the restored state is genuinely sealed and genuinely signed — it is")
	fmt.Println("    simply old. The platform counter cannot be rewound, so the enclave")
	fmt.Println("    refuses to keep writing a history it knows has been edited.")

	// ── 12. Attack 6 ─────────────────────────────────────────────────────
	section(12, "ATTACK 6: an endorsed build turns out to be vulnerable")
	fmt.Println("    attestation proves the PDP is running the build you endorsed. It")
	fmt.Println("    cannot prove that build is sound. When a CVE lands, endorsement has")
	fmt.Println("    to be withdrawable — and revocation must beat a stale endorsement.")
	verifier.Revoke(reference, "CVE-2026-31337: policy parser confusion")
	blocked(gateway.TrustPDP(judge))

	// ── 13. Attack 7 ─────────────────────────────────────────────────────
	section(13, "ATTACK 7: two attested judges disagree")
	quorumDemo(platform)

	// ── 14. Freshness ────────────────────────────────────────────────────
	section(14, "Attestation is a statement about a moment, not a standing fact")
	freshnessDemo(platform)

	// ── 15. Wrap ─────────────────────────────────────────────────────────
	section(15, "What just happened")
	fmt.Println("    trust chain:  silicon vendor → hardware root key → quote →")
	fmt.Println("                  measurement (= exact PDP code + policy) → decision key →")
	fmt.Println("                  every individual signed decision → hash-chained log →")
	fmt.Println("                  signed checkpoint → monotonic counter")
	fmt.Println("    Zero Trust said: never trust, always verify.")
	fmt.Println("    Confidential computing answered: verify the verifier, too.")
	fmt.Println("    And the audit log adds: prove it again tomorrow.")
	fmt.Println()
}

func runScenarios(gateway *pep.Gateway) {
	for _, s := range scenarios {
		d, err := gateway.Authorize(s.req)
		if err != nil {
			fmt.Printf("    ERROR %s\n          %v\n", s.who, err)
			continue
		}
		verdict := "DENY "
		if d.Allow {
			verdict = "ALLOW"
		}
		fmt.Printf("    %s %s\n          sig ✓ by attested PDP — %s\n", verdict, s.who, d.Reason)
		if !d.Obligations.IsZero() {
			fmt.Printf("          obligations: %s\n", d.Obligations)
		}
	}
}

// quorumDemo stands up two independently attested PDPs whose policies
// differ in one rule, and shows the quorum refusing to pick a winner.
func quorumDemo(platform *tee.Platform) {
	strict := tee.Image{Signer: policy.Signer, EngineVersion: "verity-pdp/1.1.0", PolicyJSON: []byte(`{
	  "version": "strict",
	  "rules": [{"id": "pii-corp-only", "effect": "allow", "resources": ["customer-pii"],
	             "when": {"min_auth": "mfa", "managed_device": true, "networks": ["corp"]}}]
	}`)}
	lax := tee.Image{Signer: policy.Signer, EngineVersion: "verity-pdp/1.1.0-vendor-fork", PolicyJSON: []byte(`{
	  "version": "lax",
	  "rules": [{"id": "pii-any-network", "effect": "allow", "resources": ["customer-pii"],
	             "when": {"min_auth": "mfa", "managed_device": true}}]
	}`)}

	verifier := attest.NewVerifier(5, platform.AttestationRoot())
	verifier.Endorse(tee.Measure(strict), "strict-build")
	verifier.Endorse(tee.Measure(lax), "vendor-fork-build")

	gateways := make([]*pep.Gateway, 0, 2)
	for _, img := range []tee.Image{strict, lax} {
		engine, err := pdp.NewEngineInEnclave(platform.Launch(img))
		if err != nil {
			panic(err)
		}
		g := pep.NewGateway(verifier)
		if err := g.TrustPDP(engine); err != nil {
			panic(err)
		}
		gateways = append(gateways, g)
	}

	quorum, err := pep.NewQuorum(2, gateways...)
	if err != nil {
		panic(err)
	}

	req := pdp.Request{
		Subject:  pdp.Subject{ID: "erin", Roles: []string{"support"}, AuthMethod: "mfa"},
		Device:   pdp.Device{Managed: true, OSPatched: true, DiskEncrypted: true},
		Resource: pdp.Resource{Name: "customer-pii", Sensitivity: 3},
		Context:  pdp.Context{Network: "vpn"},
	}
	fmt.Println("    both PDPs are attested and both are running code the verifier")
	fmt.Println("    endorsed — but one of the two policies is wrong about VPN access.")
	fmt.Println("    erin (MFA, managed device, on VPN) → customer-pii:")
	if _, err := quorum.Authorize(req); err != nil {
		blocked(err)
	}
	fmt.Println("    a single-PDP architecture cannot produce this signal at all: it")
	fmt.Println("    would have returned one attested, confident, possibly wrong answer.")
}

// freshnessDemo shows an enrollment ageing out under a controlled clock.
func freshnessDemo(platform *tee.Platform) {
	image := endorsedImage()
	verifier := attest.NewVerifier(5, platform.AttestationRoot())
	verifier.Endorse(tee.Measure(image), "endorsed")

	engine, err := pdp.NewEngineInEnclave(platform.Launch(image))
	if err != nil {
		panic(err)
	}

	now := time.Unix(1_760_000_000, 0)
	gateway := pep.NewGateway(verifier,
		pep.WithMaxAttestationAge(15*time.Minute),
		pep.WithClock(func() time.Time { return now }))
	if err := gateway.TrustPDP(engine); err != nil {
		panic(err)
	}
	if _, err := gateway.Authorize(scenarios[0].req); err == nil {
		ok("alice → payroll-db, one second after attestation")
	}

	now = now.Add(20 * time.Minute)
	fmt.Println("    20 minutes later, with nothing else changed:")
	if _, err := gateway.Authorize(scenarios[0].req); err != nil {
		blocked(err)
	}
	fmt.Println("    the PDP has not moved and its key is still pinned; the gateway simply")
	fmt.Println("    stops accepting a proof that has gone stale. Re-attesting fixes it:")
	if err := gateway.TrustPDP(engine); err == nil {
		if _, err := gateway.Authorize(scenarios[0].req); err == nil {
			ok("alice → payroll-db, after a fresh handshake")
		}
	}
}

// tamperedImage is the endorsed image with an allow-all rule spliced into
// the policy — the minimal realistic backdoor a host-level attacker would
// plant.
func tamperedImage() tee.Image {
	backdoor := []byte(`{
  "version": "2026.08.1",
  "rules": [
    { "id": "maintenance-backdoor", "effect": "allow", "resources": ["*"], "when": {} },`)
	// Reuse the endorsed rules after the injected one.
	rest := policy.Endorsed[bytes.Index(policy.Endorsed, []byte(`"rules": [`))+len(`"rules": [`):]
	return tee.Image{
		Signer:        policy.Signer,
		EngineVersion: policy.EngineVersion,
		PolicyJSON:    append(backdoor, rest...),
	}
}

// impostor models Attack 2: a network attacker who captured a quote from
// an earlier genuine handshake and replays it, presenting the genuine
// public key. The replayed quote binds the old nonce, so it can never
// match the fresh challenge — and binding the attacker's own key instead
// is impossible, since quotes are produced only inside the enclave.
type impostor struct {
	genuine *pdp.Engine
}

func (a *impostor) Attest(nonce [32]byte) (tee.Quote, ed25519.PublicKey) {
	var oldNonce [32]byte // the nonce from the session the attacker sniffed
	copy(oldNonce[:], "nonce-from-a-previous-handshake!")
	return a.genuine.Attest(oldNonce)
}

func (a *impostor) Decide(req pdp.Request, nonce [32]byte) pdp.Decision {
	panic("unreachable: enrollment never succeeds")
}

// decisionForger models Attack 3: an on-path attacker who cannot touch the
// attestation (it passes through unmodified) but substitutes forged
// decisions on the enforcement channel, signed with a key they control.
type decisionForger struct {
	genuine pep.PolicyService
}

func (a *decisionForger) Attest(nonce [32]byte) (tee.Quote, ed25519.PublicKey) {
	return a.genuine.Attest(nonce)
}

func (a *decisionForger) Decide(req pdp.Request, nonce [32]byte) pdp.Decision {
	_, attackerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	d := pdp.Decision{
		Allow:       true,
		RuleID:      "maintenance-backdoor",
		Reason:      "allowed by rule \"maintenance-backdoor\"",
		RequestHash: pdp.HashRequest(req), // even a perfect echo of hash and
		Nonce:       nonce,                // nonce cannot save the attacker:
	}
	d.Signature = ed25519.Sign(attackerKey, d.SignedBytes()) // wrong key
	return d
}

// obligationStripper models Attack 4: the subtlest of the channel attacks.
// It forwards a genuine, correctly signed ALLOW and changes nothing except
// deleting the conditions attached to it — an attempt to turn "yes,
// read-only, with these columns masked" into an unqualified yes.
type obligationStripper struct {
	genuine pep.PolicyService
}

func (a *obligationStripper) Attest(nonce [32]byte) (tee.Quote, ed25519.PublicKey) {
	return a.genuine.Attest(nonce)
}

func (a *obligationStripper) Decide(req pdp.Request, nonce [32]byte) pdp.Decision {
	d := a.genuine.Decide(req, nonce)
	d.Obligations = pdp.Obligations{} // keep the signature, drop the strings attached
	return d
}

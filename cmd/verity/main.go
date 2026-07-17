// Command verity runs the end-to-end demonstration of a TEE-attested Zero
// Trust policy engine: the full trust chain being built, exercised, and
// then attacked three different ways.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"

	"github.com/aabhimittal/zero-trust-confidential-computing/internal/attest"
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
		m := tee.Measure(tee.Image{EngineVersion: policy.EngineVersion, PolicyJSON: policy.Endorsed})
		fmt.Printf("endorsed build:      %s\n", policy.EngineVersion)
		fmt.Printf("launch measurement:  %x\n", m)
	default:
		fmt.Fprintf(os.Stderr, "usage: verity [demo|measure]\n")
		os.Exit(2)
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

// requests exercised against every PDP in the demo, with the outcome the
// endorsed policy should produce.
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

func demo() {
	fmt.Println("VERITY — Zero Trust decisions you can cryptographically trust")
	fmt.Println("=============================================================")
	fmt.Println()
	fmt.Println("Thesis: every Zero Trust system has a judge (the Policy Decision Point).")
	fmt.Println("If the host running the judge is compromised, every 'verified' decision")
	fmt.Println("is attacker-controlled. Confidential computing makes the judge itself")
	fmt.Println("verifiable: hardware measures the PDP's code, and enforcement points")
	fmt.Println("refuse decisions from any PDP whose measurement they did not endorse.")

	// ── 1. Platform ──────────────────────────────────────────────────────
	section(1, "Confidential-computing platform boots")
	platform := tee.NewPlatform(7)
	fmt.Printf("    hardware attestation root: %s  (public half of the CPU-fused key)\n",
		short(platform.AttestationRoot()))
	fmt.Printf("    platform TCB version:      %d\n", platform.TCBVersion)

	// ── 2. Endorsement ───────────────────────────────────────────────────
	section(2, "Verifier endorses the known-good PDP build")
	endorsedImage := tee.Image{EngineVersion: policy.EngineVersion, PolicyJSON: policy.Endorsed}
	reference := tee.Measure(endorsedImage)
	verifier := attest.NewVerifier(5, platform.AttestationRoot())
	verifier.Endorse(reference, policy.EngineVersion+"+policy-2026.07.1")
	fmt.Printf("    reference measurement:     %s  (from the reviewed, reproducible build)\n", short(reference[:]))
	fmt.Println("    the verifier computed this from ITS OWN copy of the endorsed image —")
	fmt.Println("    reference values never come from the party being attested.")

	// ── 3. Launch ────────────────────────────────────────────────────────
	section(3, "Genuine PDP launches inside an enclave")
	enclave := platform.Launch(endorsedImage)
	engine, err := pdp.NewEngineInEnclave(enclave)
	if err != nil {
		panic(err)
	}
	fmt.Printf("    launch measurement:        %s  (stamped by the platform, not the code)\n",
		shortM(enclave.Measurement()))
	fmt.Printf("    decision signing key:      %s  (generated inside the enclave)\n", short(engine.PublicKey()))

	// ── 4. Enrollment ────────────────────────────────────────────────────
	section(4, "PEP challenges the PDP and appraises the quote")
	gateway := pep.NewGateway(verifier)
	if err := gateway.TrustPDP(engine); err != nil {
		panic(err)
	}
	fmt.Println("    quote signature   ✓  chains to the trusted hardware root")
	fmt.Println("    TCB level         ✓  7 ≥ verifier minimum 5")
	fmt.Println("    measurement       ✓  matches endorsed reference value")
	fmt.Println("    key binding       ✓  report data commits to the PDP key + fresh nonce")
	fmt.Printf("    → PEP pins the decision key of attested build %q\n", gateway.PDPBuild())

	// ── 5. Enforcement ───────────────────────────────────────────────────
	section(5, "Zero Trust in action — every decision verified against the attested key")
	runScenarios(gateway)

	// ── 6. Attack 1 ──────────────────────────────────────────────────────
	section(6, "ATTACK 1: host-level attacker relaunches the PDP with a backdoored policy")
	tampered := tamperedImage()
	tamperedEnclave := platform.Launch(tampered)
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
	mallory := scenarios[4].req
	var attackerNonce [32]byte
	td := tamperedEngine.Decide(mallory, attackerNonce)
	fmt.Printf("        tampered PDP says: ALLOW (%s)\n", td.Reason)
	fmt.Println()
	fmt.Println("    but the hardware measured what actually launched, and enrollment fails:")
	if err := gateway.TrustPDP(tamperedEngine); err != nil {
		fmt.Printf("        ✗ %v\n", err)
	}
	fmt.Println("    the PEP is now fail-closed — no attested judge, no access:")
	if _, err := gateway.Authorize(mallory); err != nil {
		fmt.Printf("        mallory → customer-pii: REFUSED (%v)\n", err)
	}

	// ── 7. Attack 2 ──────────────────────────────────────────────────────
	section(7, "ATTACK 2: impostor replays a captured quote from the genuine PDP")
	fmt.Println("    a network attacker recorded the genuine enclave's quote and presents it")
	fmt.Println("    as their own attestation, hoping to get their key pinned.")
	imp := &impostor{genuine: engine}
	if err := gateway.TrustPDP(imp); err != nil {
		fmt.Printf("        ✗ %v\n", err)
	}
	fmt.Println("    the replayed quote binds the OLD nonce and the GENUINE key — it cannot")
	fmt.Println("    match this handshake's fresh nonce, and it could never bind the")
	fmt.Println("    impostor's key, because quoting happens only inside the enclave.")

	// ── 8. Recovery + Attack 3 ───────────────────────────────────────────
	section(8, "ATTACK 3: man-in-the-middle injects a forged ALLOW decision")
	if err := gateway.TrustPDP(engine); err != nil {
		panic(err)
	}
	fmt.Println("    genuine PDP re-enrolled ✓ — now an on-path attacker intercepts the")
	fmt.Println("    PEP↔PDP channel and answers mallory's request with a forged ALLOW,")
	fmt.Println("    signed with the attacker's own key.")
	mitm := &decisionForger{genuine: engine}
	if err := gateway.TrustPDP(mitm); err != nil {
		panic(err) // forwards genuine attestation, so enrollment succeeds
	}
	if _, err := gateway.Authorize(mallory); err != nil {
		fmt.Printf("        mallory → customer-pii: REFUSED (%v)\n", err)
	}
	fmt.Println("    the forged decision is not signed by the key the quote attested, so")
	fmt.Println("    it dies at the PEP. Controlling the network buys the attacker nothing.")

	// ── 9. Wrap ──────────────────────────────────────────────────────────
	section(9, "What just happened")
	fmt.Println("    trust chain:  silicon vendor → hardware root key → quote →")
	fmt.Println("                  measurement (= exact PDP code + policy) → decision key →")
	fmt.Println("                  every individual signed decision")
	fmt.Println("    Zero Trust said: never trust, always verify.")
	fmt.Println("    Confidential computing answered: verify the verifier, too.")
	fmt.Println()
}

func runScenarios(gateway *pep.Gateway) {
	for _, s := range scenarios {
		d, err := gateway.Authorize(s.req)
		verdict := "DENY "
		if err != nil {
			fmt.Printf("    ERROR %s\n          %v\n", s.who, err)
			continue
		}
		if d.Allow {
			verdict = "ALLOW"
		}
		fmt.Printf("    %s %s\n          sig ✓ by attested PDP — %s\n", verdict, s.who, d.Reason)
	}
}

// tamperedImage is the endorsed image with an allow-all rule spliced into
// the policy — the minimal realistic backdoor a host-level attacker would
// plant.
func tamperedImage() tee.Image {
	backdoor := []byte(`{
  "version": "2026.07.1",
  "rules": [
    { "id": "maintenance-backdoor", "effect": "allow", "resources": ["*"], "when": {} },`)
	// Reuse the endorsed rules after the injected one.
	rest := policy.Endorsed[bytes.Index(policy.Endorsed, []byte(`"rules": [`))+len(`"rules": [`):]
	return tee.Image{EngineVersion: policy.EngineVersion, PolicyJSON: append(backdoor, rest...)}
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
	captured, genuinePub := a.genuine.Attest(oldNonce)
	return captured, genuinePub
}

func (a *impostor) Decide(req pdp.Request, nonce [32]byte) pdp.Decision {
	panic("unreachable: enrollment never succeeds")
}

// decisionForger models Attack 3: an on-path attacker who cannot touch the
// attestation (it passes through unmodified) but substitutes forged
// decisions on the enforcement channel, signed with a key they control.
type decisionForger struct {
	genuine *pdp.Engine
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

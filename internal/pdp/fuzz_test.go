package pdp

import (
	"crypto/ed25519"
	"testing"
	"unicode/utf8"

	"github.com/aabhimittal/zero-trust-confidential-computing/internal/tee"
)

// Policy bytes reach the parser before attestation has had a chance to
// reject them: a host-level attacker relaunches the enclave with whatever
// image they like, and NewEngineInEnclave runs on it. So the parser's
// contract against arbitrary input is "return an error", never "panic" —
// a crash here is a denial of service on the PDP, reachable by anyone who
// can restart it.
func FuzzPolicyParsing(f *testing.F) {
	f.Add([]byte(`{"version":"t","rules":[{"id":"r","effect":"allow","resources":["*"],"when":{}}]}`))
	f.Add([]byte(testPolicy))
	f.Add([]byte(`{`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"version":"t","rules":null}`))
	f.Add([]byte(`{"version":"t","rules":[{"id":"r","effect":"allow","resources":["*"],
	  "min_sensitivity":-9223372036854775808,"when":{}}]}`))
	f.Add([]byte(`{"version":"t","rules":[{"id":"r","effect":"allow","resources":["*"],
	  "when":{},"obligations":{"session_ttl_seconds":9223372036854775807}}]}`))

	p := tee.NewPlatform(1)
	f.Fuzz(func(t *testing.T, policyJSON []byte) {
		e := p.Launch(tee.Image{EngineVersion: "engine/fuzz", PolicyJSON: policyJSON})

		eng, err := NewEngineInEnclave(e)
		if err != nil {
			return // rejection is the expected outcome for almost all input
		}

		// Anything that survives validation must also be safe to *use*: a
		// policy that parses but makes Decide panic would be just as
		// exploitable as one that crashes the parser.
		var nonce [32]byte
		d := eng.Decide(baseRequest(), nonce)
		if !ed25519.Verify(eng.PublicKey(), d.SignedBytes(), d.Signature) {
			t.Fatal("every decision from an accepted policy must be validly signed")
		}

		// Accepted policies must satisfy the invariants validation claims.
		if eng.PolicyVersion() == "" {
			t.Fatal("an accepted policy must have a version")
		}
		seen := map[string]bool{}
		for _, r := range eng.policy.Rules {
			if r.Effect != "allow" && r.Effect != "deny" {
				t.Fatalf("accepted rule has effect %q", r.Effect)
			}
			if r.ID == "" || seen[r.ID] {
				t.Fatalf("accepted rule has an empty or duplicate id %q", r.ID)
			}
			seen[r.ID] = true
			if r.Effect == "deny" && !r.Obligations.IsZero() {
				t.Fatalf("accepted deny rule %q carries obligations", r.ID)
			}
		}
	})
}

// Request fields cross the network from clients and identity providers, so
// they are attacker-influenced too. Hashing must never panic, and it must
// stay a function of the request's meaning rather than its representation.
func FuzzRequestHashing(f *testing.F) {
	f.Add("alice", "payroll-admin", "mfa", "payroll-db", "corp", 3)
	f.Add("", "", "", "", "", 0)
	f.Add("\x00", "\x00", "mfa", "\x00", "corp", -1)
	f.Add("subject\x00id", "role", "mfa", "resource", "corp", 1<<30)
	f.Add("👤", "🔑", "hardware-key", "🗄", "vpn", 4)

	f.Fuzz(func(t *testing.T, id, role, auth, resource, network string, sensitivity int) {
		req := Request{
			Subject:  Subject{ID: id, Roles: []string{role}, AuthMethod: auth},
			Resource: Resource{Name: resource, Sensitivity: sensitivity},
			Context:  Context{Network: network},
		}

		h := HashRequest(req)
		if h != HashRequest(req) {
			t.Fatal("hashing must be deterministic")
		}

		// Role-set normalisation must hold for arbitrary content, not just
		// for the tidy ASCII the unit tests use.
		dup := req
		dup.Subject.Roles = []string{role, role}
		if role != "" && HashRequest(dup) != h {
			t.Fatal("duplicate roles must not change the hash")
		}
		nilled, emptied := req, req
		nilled.Subject.Roles, emptied.Subject.Roles = nil, []string{}
		if HashRequest(nilled) != HashRequest(emptied) {
			t.Fatal("nil and empty role lists must hash identically")
		}
		if role == "" && HashRequest(req) != HashRequest(nilled) {
			t.Fatal("a list of only empty roles must normalise to no roles")
		}
	})
}

// Whatever a hostile client sends, the engine must produce a signed,
// verifiable answer rather than crashing or silently allowing.
func FuzzDecideNeverPanicsOrFailsOpen(f *testing.F) {
	f.Add("alice", "mfa", "payroll-db", "corp", 3)
	f.Add("", "", "", "", 0)
	f.Add("x", "mfa", "payroll-db", "PUBLIC", 3)
	f.Add("x", "mfa", "payroll-db", "public", 0)

	eng := func() *Engine {
		p := tee.NewPlatform(1)
		e, err := NewEngineInEnclave(p.Launch(tee.Image{
			EngineVersion: "engine/fuzz", PolicyJSON: []byte(testPolicy)}))
		if err != nil {
			panic(err)
		}
		return e
	}()

	f.Fuzz(func(t *testing.T, id, auth, resource, network string, sensitivity int) {
		req := Request{
			Subject:  Subject{ID: id, AuthMethod: auth},
			Resource: Resource{Name: resource, Sensitivity: sensitivity},
			Context:  Context{Network: network},
		}
		var nonce [32]byte
		d := eng.Decide(req, nonce)

		if !ed25519.Verify(eng.PublicKey(), d.SignedBytes(), d.Signature) {
			t.Fatal("every decision must be validly signed, including refusals")
		}
		if d.RequestHash != HashRequest(req) {
			t.Fatal("a decision must commit to the request it answered")
		}

		// The central fail-closed claim: an allow is only reachable through
		// a request the engine was willing to judge in the first place.
		if d.Allow {
			if err := req.Validate(); err != nil {
				t.Fatalf("allowed an invalid request (%v): %+v", err, req)
			}
			if d.RuleID == "" || d.RuleID == InvalidRequestRuleID {
				t.Fatalf("an allow must name a real rule, got %q", d.RuleID)
			}
		}
		// Reasons are surfaced in audit logs and operator tooling, so they
		// must stay valid text even when echoing hostile input.
		if !utf8.ValidString(d.Reason) && utf8.ValidString(id+auth+resource+network) {
			t.Fatalf("reason became invalid UTF-8: %q", d.Reason)
		}
	})
}

package pdp

import (
	"crypto/ed25519"
	"testing"

	"github.com/aabhimittal/zero-trust-confidential-computing/internal/tee"
)

const testPolicy = `{
  "version": "test",
  "rules": [
    {"id": "deny-public-sensitive", "effect": "deny", "resources": ["*"],
     "min_sensitivity": 3, "when": {"networks": ["public"]}},
    {"id": "allow-mfa-managed", "effect": "allow", "resources": ["payroll-db"],
     "when": {"min_auth": "mfa", "managed_device": true, "networks": ["corp", "vpn"]}},
    {"id": "allow-wiki", "effect": "allow", "resources": ["wiki"],
     "when": {"min_auth": "password"}},
    {"id": "allow-release-eng", "effect": "allow", "resources": ["signing-service"],
     "when": {"min_auth": "hardware-key", "roles": ["release-eng"]}}
  ]
}`

func newEngine(t *testing.T, policyJSON string) *Engine {
	t.Helper()
	p := tee.NewPlatform(1)
	e := p.Launch(tee.Image{EngineVersion: "engine/test", PolicyJSON: []byte(policyJSON)})
	eng, err := NewEngineInEnclave(e)
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func baseRequest() Request {
	return Request{
		Subject:  Subject{ID: "alice", Roles: []string{"payroll-admin"}, AuthMethod: "mfa"},
		Device:   Device{Managed: true, OSPatched: true, DiskEncrypted: true},
		Resource: Resource{Name: "payroll-db", Sensitivity: 3},
		Context:  Context{Network: "corp"},
	}
}

func decide(t *testing.T, e *Engine, req Request) Decision {
	t.Helper()
	var nonce [32]byte
	d := e.Decide(req, nonce)
	if !ed25519.Verify(e.PublicKey(), d.SignedBytes(), d.Signature) {
		t.Fatal("every decision must carry a valid signature")
	}
	if d.RequestHash != HashRequest(req) {
		t.Fatal("decision must commit to the evaluated request")
	}
	return d
}

func TestAllowWhenAllConditionsHold(t *testing.T) {
	d := decide(t, newEngine(t, testPolicy), baseRequest())
	if !d.Allow || d.RuleID != "allow-mfa-managed" {
		t.Fatalf("expected allow by allow-mfa-managed, got %+v", d)
	}
}

func TestDefaultDeny(t *testing.T) {
	req := baseRequest()
	req.Resource = Resource{Name: "uncovered-resource", Sensitivity: 2}
	d := decide(t, newEngine(t, testPolicy), req)
	if d.Allow || d.RuleID != "" {
		t.Fatalf("unmatched resource must default-deny, got %+v", d)
	}
}

func TestExplicitDenyOverridesAllow(t *testing.T) {
	// Policy order puts the deny rule first, but even a matching allow
	// rule must not survive a fired deny.
	req := baseRequest()
	req.Context.Network = "public"
	// Also satisfy allow-mfa-managed except for network... make it match:
	// deny-public-sensitive fires (public + sensitivity 3), so result is deny
	// regardless of other rules.
	d := decide(t, newEngine(t, testPolicy), req)
	if d.Allow || d.RuleID != "deny-public-sensitive" {
		t.Fatalf("expected explicit deny, got %+v", d)
	}
}

func TestAuthStrengthOrdering(t *testing.T) {
	e := newEngine(t, testPolicy)

	req := baseRequest()
	req.Subject.AuthMethod = "password" // below the mfa floor
	if d := decide(t, e, req); d.Allow {
		t.Fatal("password must not satisfy min_auth mfa")
	}

	req.Subject.AuthMethod = "hardware-key" // above the floor
	if d := decide(t, e, req); !d.Allow {
		t.Fatal("hardware-key must satisfy min_auth mfa")
	}
}

func TestDevicePostureRequired(t *testing.T) {
	req := baseRequest()
	req.Device.Managed = false
	if d := decide(t, newEngine(t, testPolicy), req); d.Allow {
		t.Fatal("unmanaged device must not satisfy managed_device requirement")
	}
}

func TestRoleRequirement(t *testing.T) {
	e := newEngine(t, testPolicy)
	req := Request{
		Subject:  Subject{ID: "eve", Roles: []string{"engineer"}, AuthMethod: "hardware-key"},
		Device:   Device{Managed: true, OSPatched: true, DiskEncrypted: true},
		Resource: Resource{Name: "signing-service", Sensitivity: 4},
		Context:  Context{Network: "corp"},
	}
	if d := decide(t, e, req); d.Allow {
		t.Fatal("missing role must deny")
	}
	req.Subject.Roles = []string{"release-eng"}
	if d := decide(t, e, req); !d.Allow {
		t.Fatal("matching role must allow")
	}
}

func TestPolicyValidation(t *testing.T) {
	cases := map[string]string{
		"bad effect":    `{"rules":[{"id":"r","effect":"maybe","resources":["*"],"when":{}}]}`,
		"duplicate id":  `{"rules":[{"id":"r","effect":"allow","resources":["*"],"when":{}},{"id":"r","effect":"deny","resources":["*"],"when":{}}]}`,
		"no resources":  `{"rules":[{"id":"r","effect":"allow","resources":[],"when":{}}]}`,
		"unknown auth":  `{"rules":[{"id":"r","effect":"allow","resources":["*"],"when":{"min_auth":"vibes"}}]}`,
		"not even json": `{`,
	}
	for name, policyJSON := range cases {
		p := tee.NewPlatform(1)
		e := p.Launch(tee.Image{EngineVersion: "engine/test", PolicyJSON: []byte(policyJSON)})
		if _, err := NewEngineInEnclave(e); err == nil {
			t.Errorf("%s: expected constructor to reject policy", name)
		}
	}
}

func TestRequestHashIsCanonical(t *testing.T) {
	a, b := baseRequest(), baseRequest()
	if HashRequest(a) != HashRequest(b) {
		t.Fatal("equal requests must hash equally")
	}
	b.Context.Network = "vpn"
	if HashRequest(a) == HashRequest(b) {
		t.Fatal("different requests must hash differently")
	}
}

func TestAttestBindsEngineKey(t *testing.T) {
	e := newEngine(t, testPolicy)
	var nonce [32]byte
	nonce[0] = 42
	q, pub := e.Attest(nonce)
	if q.ReportData != tee.KeyBinding(pub, nonce) {
		t.Fatal("quote report data must bind the engine key and caller nonce")
	}
}

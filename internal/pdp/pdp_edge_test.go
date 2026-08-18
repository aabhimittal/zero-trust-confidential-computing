// Edge cases for the policy engine. Most of these are cases where a
// plausible implementation fails *open* — the direction that matters, since
// an access-control bug that denies too much gets reported within the hour
// and one that allows too much may never be reported at all.
package pdp

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/aabhimittal/zero-trust-confidential-computing/internal/tee"
)

func mustReject(t *testing.T, policyJSON, wantSubstring string) {
	t.Helper()
	p := tee.NewPlatform(1)
	e := p.Launch(tee.Image{EngineVersion: "engine/test", PolicyJSON: []byte(policyJSON)})
	_, err := NewEngineInEnclave(e)
	if err == nil {
		t.Fatalf("expected rejection, policy was accepted: %s", policyJSON)
	}
	if !strings.Contains(err.Error(), wantSubstring) {
		t.Fatalf("expected error mentioning %q, got: %v", wantSubstring, err)
	}
}

// ─── Fail-open paths in request signals ─────────────────────────────────

// The deny rule that protects sensitive resources on public networks is
// scoped with min_sensitivity. A resource whose sensitivity failed to
// populate scores 0, matches no sensitivity floor, and therefore slips past
// the deny — while a broad allow rule happily fires. The engine must refuse
// to judge such a request rather than judge it leniently.
func TestUnsetSensitivityCannotEvadeASensitivityScopedDeny(t *testing.T) {
	const p = `{"version":"t","rules":[
	  {"id":"deny-sensitive-public","effect":"deny","resources":["*"],
	   "min_sensitivity":3,"when":{"networks":["public"]}},
	  {"id":"allow-authenticated","effect":"allow","resources":["*"],
	   "when":{"min_auth":"password"}}]}`

	req := Request{
		Subject:  Subject{ID: "mallory", AuthMethod: "password"},
		Resource: Resource{Name: "payroll-db"}, // sensitivity never set
		Context:  Context{Network: "public"},
	}
	d := decide(t, newEngine(t, p), req)
	if d.Allow {
		t.Fatal("a request with no sensitivity must not be granted by a broad allow rule")
	}
	if d.RuleID != InvalidRequestRuleID {
		t.Fatalf("expected refusal as malformed, got rule %q (%s)", d.RuleID, d.Reason)
	}
}

// The mirror image: an unrecognised network zone matches no deny rule's
// network list, so the deny never fires.
func TestUnknownNetworkCannotEvadeANetworkScopedDeny(t *testing.T) {
	const p = `{"version":"t","rules":[
	  {"id":"deny-sensitive-public","effect":"deny","resources":["*"],
	   "min_sensitivity":3,"when":{"networks":["public"]}},
	  {"id":"allow-authenticated","effect":"allow","resources":["*"],
	   "when":{"min_auth":"password"}}]}`

	e := newEngine(t, p)
	for _, zone := range []string{"Public", "PUBLIC", "guest", "", "public "} {
		req := Request{
			Subject:  Subject{ID: "mallory", AuthMethod: "password"},
			Resource: Resource{Name: "payroll-db", Sensitivity: 3},
			Context:  Context{Network: zone},
		}
		d := decide(t, e, req)
		if d.Allow {
			t.Errorf("network %q must not be treated as a zone outside the deny rule", zone)
		}
		if d.RuleID != InvalidRequestRuleID {
			t.Errorf("network %q: expected refusal as malformed, got %q", zone, d.RuleID)
		}
	}
}

// An unrecognised auth method scores zero, which is below every floor, so
// it already fails allow rules. It must nonetheless be refused outright: a
// rule with no min_auth would otherwise grant access to a subject whose
// authentication the engine could not interpret.
func TestUnknownAuthMethodIsRefusedNotScoredZero(t *testing.T) {
	const p = `{"version":"t","rules":[
	  {"id":"open-wiki","effect":"allow","resources":["wiki"],"when":{}}]}`

	e := newEngine(t, p)
	for _, method := range []string{"", "MFA", "sms", "none", "hardware_key"} {
		d := decide(t, e, Request{
			Subject:  Subject{ID: "x", AuthMethod: method},
			Resource: Resource{Name: "wiki", Sensitivity: 1},
			Context:  Context{Network: "corp"},
		})
		if d.Allow {
			t.Errorf("auth method %q must not satisfy an unconditional allow rule", method)
		}
	}
}

func TestMalformedRequestsAreRefusedAndStillSigned(t *testing.T) {
	e := newEngine(t, testPolicy)
	valid := baseRequest()

	broken := map[string]func(*Request){
		"empty subject id":  func(r *Request) { r.Subject.ID = "" },
		"oversized subject": func(r *Request) { r.Subject.ID = strings.Repeat("a", 300) },
		"unknown auth":      func(r *Request) { r.Subject.AuthMethod = "telepathy" },
		"empty resource":    func(r *Request) { r.Resource.Name = "" },
		"sensitivity zero":  func(r *Request) { r.Resource.Sensitivity = 0 },
		"sensitivity high":  func(r *Request) { r.Resource.Sensitivity = 5 },
		"sensitivity neg":   func(r *Request) { r.Resource.Sensitivity = -1 },
		"unknown network":   func(r *Request) { r.Context.Network = "starlink" },
		"empty role":        func(r *Request) { r.Subject.Roles = []string{"ok", ""} },
		"too many roles":    func(r *Request) { r.Subject.Roles = make([]string, maxListLen+1) },
	}
	for name, breakIt := range broken {
		req := valid
		breakIt(&req)

		if err := req.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s: Validate should report ErrInvalidRequest, got %v", name, err)
		}
		// decide() asserts the signature verifies, which is the point: a
		// refusal must still be a decision the enforcement point can check,
		// not a bare error that could be spoofed on the wire.
		d := decide(t, e, req)
		if d.Allow || d.RuleID != InvalidRequestRuleID {
			t.Errorf("%s: expected a signed refusal, got %+v", name, d)
		}
	}
}

// The reserved namespace exists so an audit trail can distinguish "denied
// by a rule someone wrote" from "denied because the request made no sense".
func TestReservedRuleIDPrefixIsRejectedInPolicy(t *testing.T) {
	mustReject(t, `{"version":"t","rules":[
	  {"id":"!invalid-request","effect":"allow","resources":["*"],"when":{}}]}`, "reserved")
}

// ─── Policy authoring hazards ───────────────────────────────────────────

// A misspelled condition key is the highest-consequence typo in the file:
// with lenient decoding it parses as a rule with no such requirement, so
// the author reads a restriction that the engine does not enforce.
func TestMisspelledConditionKeyIsRejectedNotIgnored(t *testing.T) {
	for _, typo := range []string{
		`{"id":"r","effect":"allow","resources":["*"],"when":{"managed_devise":true}}`,
		`{"id":"r","effect":"allow","resources":["*"],"when":{"minauth":"mfa"}}`,
		`{"id":"r","effect":"allow","resources":["*"],"when":{},"obligation":{"read_only":true}}`,
		`{"id":"r","effect":"allow","resource":["*"],"when":{}}`,
	} {
		mustReject(t, `{"version":"t","rules":[`+typo+`]}`, "unknown field")
	}
}

func TestPolicyValidationRejectsEachDefect(t *testing.T) {
	cases := map[string]struct{ policy, want string }{
		"no version": {
			`{"rules":[{"id":"r","effect":"allow","resources":["*"],"when":{}}]}`, "version"},
		"no rules": {
			`{"version":"t","rules":[]}`, "no rules"},
		"empty rule id": {
			`{"version":"t","rules":[{"id":"","effect":"allow","resources":["*"],"when":{}}]}`, "empty id"},
		"duplicate id": {
			`{"version":"t","rules":[{"id":"r","effect":"allow","resources":["*"],"when":{}},
			  {"id":"r","effect":"deny","resources":["*"],"when":{}}]}`, "duplicate"},
		"bad effect": {
			`{"version":"t","rules":[{"id":"r","effect":"maybe","resources":["*"],"when":{}}]}`, "unknown effect"},
		"capitalised effect": {
			`{"version":"t","rules":[{"id":"r","effect":"Allow","resources":["*"],"when":{}}]}`, "unknown effect"},
		"no resources": {
			`{"version":"t","rules":[{"id":"r","effect":"allow","resources":[],"when":{}}]}`, "no resources"},
		"empty resource name": {
			`{"version":"t","rules":[{"id":"r","effect":"allow","resources":[""],"when":{}}]}`, "empty or over-long"},
		"unknown auth": {
			`{"version":"t","rules":[{"id":"r","effect":"allow","resources":["*"],"when":{"min_auth":"vibes"}}]}`, "unknown auth"},
		"unknown network": {
			`{"version":"t","rules":[{"id":"r","effect":"deny","resources":["*"],"when":{"networks":["pubic"]}}]}`, "unknown network"},
		"empty role name": {
			`{"version":"t","rules":[{"id":"r","effect":"allow","resources":["*"],"when":{"roles":[""]}}]}`, "empty or over-long role"},
		"sensitivity out of range": {
			`{"version":"t","rules":[{"id":"r","effect":"allow","resources":["*"],"min_sensitivity":9,"when":{}}]}`, "outside"},
		"negative sensitivity": {
			`{"version":"t","rules":[{"id":"r","effect":"allow","resources":["*"],"max_sensitivity":-1,"when":{}}]}`, "outside"},
		"inverted sensitivity band": {
			`{"version":"t","rules":[{"id":"r","effect":"allow","resources":["*"],
			  "min_sensitivity":4,"max_sensitivity":2,"when":{}}]}`, "never fire"},
		"obligations on a deny": {
			`{"version":"t","rules":[{"id":"r","effect":"deny","resources":["*"],"when":{},
			  "obligations":{"read_only":true}}]}`, "only qualify an allow"},
		"negative obligation": {
			`{"version":"t","rules":[{"id":"r","effect":"allow","resources":["*"],"when":{},
			  "obligations":{"session_ttl_seconds":-5}}]}`, "negative"},
		"not json":      {`{`, "does not parse"},
		"trailing junk": {`{"version":"t","rules":[{"id":"r","effect":"allow","resources":["*"],"when":{}}]} {}`, "trailing"},
		"json array":    {`[]`, "does not parse"},
		"json null":     {`null`, "version"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) { mustReject(t, c.policy, c.want) })
	}
}

func TestOversizedPolicyIsRejected(t *testing.T) {
	// A tampered image is parsed before attestation gets a chance to reject
	// it, so the parser's appetite is attacker-controlled.
	huge := `{"version":"t","rules":[` + strings.Repeat(
		`{"id":"x","effect":"allow","resources":["*"],"when":{}},`, 40000) + `]}`
	mustReject(t, huge, "over the")
}

func TestTooManyRulesIsRejected(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"version":"t","rules":[`)
	for i := range maxRules + 1 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"id":"r%d","effect":"allow","resources":["a"],"when":{}}`, i)
	}
	b.WriteString(`]}`)
	mustReject(t, b.String(), "over the 4096 limit")
}

// ─── Request canonicalisation ───────────────────────────────────────────

// The PDP and PEP hash their own copies of a request. Those copies arrive
// by different routes — one decoded from JSON, where an absent list is nil
// and an empty one is [] — and roles are a set, so ordering is not
// meaningful. If these hashed differently, a legitimate request would be
// refused with a signature error indistinguishable from an attack.
func TestRequestHashIgnoresNonMeaningfulRoleDifferences(t *testing.T) {
	base := baseRequest()
	base.Subject.Roles = []string{"a", "b"}

	same := []struct {
		name  string
		roles []string
	}{
		{"reordered", []string{"b", "a"}},
		{"duplicated", []string{"a", "b", "a"}},
		{"padded with empties", []string{"a", "", "b"}},
	}
	for _, c := range same {
		other := base
		other.Subject.Roles = c.roles
		if HashRequest(base) != HashRequest(other) {
			t.Errorf("%s roles must hash identically", c.name)
		}
	}

	nilRoles, emptyRoles := base, base
	nilRoles.Subject.Roles = nil
	emptyRoles.Subject.Roles = []string{}
	if HashRequest(nilRoles) != HashRequest(emptyRoles) {
		t.Fatal("nil and empty role lists must hash identically")
	}
}

func TestRequestHashSeparatesMeaningfulDifferences(t *testing.T) {
	base := baseRequest()
	mutations := map[string]func(*Request){
		"subject id":     func(r *Request) { r.Subject.ID = "eve" },
		"role added":     func(r *Request) { r.Subject.Roles = append(r.Subject.Roles, "root") },
		"auth method":    func(r *Request) { r.Subject.AuthMethod = "password" },
		"managed":        func(r *Request) { r.Device.Managed = false },
		"patched":        func(r *Request) { r.Device.OSPatched = false },
		"disk encrypted": func(r *Request) { r.Device.DiskEncrypted = false },
		"resource":       func(r *Request) { r.Resource.Name = "wiki" },
		"sensitivity":    func(r *Request) { r.Resource.Sensitivity = 4 },
		"network":        func(r *Request) { r.Context.Network = "vpn" },
	}
	for name, mutate := range mutations {
		other := baseRequest()
		mutate(&other)
		if HashRequest(base) == HashRequest(other) {
			t.Errorf("a change to %s must change the request hash", name)
		}
	}
}

// Field boundaries must not be shiftable: a subject id and a resource name
// that concatenate the same way must still hash differently.
func TestRequestHashResistsFieldBoundaryShifting(t *testing.T) {
	a, b := baseRequest(), baseRequest()
	a.Subject.ID, a.Resource.Name = "ab", "c"
	b.Subject.ID, b.Resource.Name = "a", "bc"
	if HashRequest(a) == HashRequest(b) {
		t.Fatal("shifting a field boundary must not preserve the request hash")
	}
}

// ─── Obligations ────────────────────────────────────────────────────────

const obligationPolicy = `{"version":"t","rules":[
  {"id":"pii-masked-readonly","effect":"allow","resources":["customer-pii"],
   "when":{"min_auth":"mfa"},
   "obligations":{"read_only":true,"session_ttl_seconds":1800,
                  "mask_fields":["ssn","dob"]}},
  {"id":"wiki","effect":"allow","resources":["wiki"],"when":{"min_auth":"password"}}]}`

func obligationRequest() Request {
	return Request{
		Subject:  Subject{ID: "carol", Roles: []string{"support"}, AuthMethod: "mfa"},
		Device:   Device{Managed: true, OSPatched: true, DiskEncrypted: true},
		Resource: Resource{Name: "customer-pii", Sensitivity: 3},
		Context:  Context{Network: "corp"},
	}
}

func TestObligationsRideWithTheAllow(t *testing.T) {
	d := decide(t, newEngine(t, obligationPolicy), obligationRequest())
	if !d.Allow {
		t.Fatalf("expected allow, got %+v", d)
	}
	if !d.Obligations.ReadOnly || d.Obligations.SessionTTLSeconds != 1800 ||
		len(d.Obligations.MaskFields) != 2 {
		t.Fatalf("obligations were not carried: %+v", d.Obligations)
	}
}

func TestRulesWithoutObligationsProduceNone(t *testing.T) {
	req := obligationRequest()
	req.Resource = Resource{Name: "wiki", Sensitivity: 1}
	d := decide(t, newEngine(t, obligationPolicy), req)
	if !d.Allow || !d.Obligations.IsZero() {
		t.Fatalf("expected an unqualified allow, got %+v", d)
	}
}

// Downgrading a grant must be exactly as hard as inventing one. This is the
// property that makes obligations worth having at all: an enforcement point
// that could be handed a de-restricted copy of a genuine allow would be
// enforcing the attacker's terms, not the policy's.
func TestStrippingOrWeakeningObligationsBreaksTheSignature(t *testing.T) {
	e := newEngine(t, obligationPolicy)
	d := decide(t, e, obligationRequest())

	downgrades := map[string]func(*Decision){
		"strip everything":  func(d *Decision) { d.Obligations = Obligations{} },
		"drop read-only":    func(d *Decision) { d.Obligations.ReadOnly = false },
		"extend the ttl":    func(d *Decision) { d.Obligations.SessionTTLSeconds = 86400 },
		"unmask a field":    func(d *Decision) { d.Obligations.MaskFields = []string{"ssn"} },
		"unmask all":        func(d *Decision) { d.Obligations.MaskFields = nil },
		"swap a mask field": func(d *Decision) { d.Obligations.MaskFields = []string{"ssn", "nickname"} },
	}
	for name, downgrade := range downgrades {
		tampered := d
		tampered.Obligations.MaskFields = append([]string(nil), d.Obligations.MaskFields...)
		downgrade(&tampered)
		if ed25519.Verify(e.PublicKey(), tampered.SignedBytes(), tampered.Signature) {
			t.Errorf("%q must invalidate the decision signature", name)
		}
	}
}

// Reordering mask fields changes nothing about what is imposed, so it must
// not read as tampering — the same normalisation argument as roles.
func TestReorderingMaskFieldsIsNotTampering(t *testing.T) {
	e := newEngine(t, obligationPolicy)
	d := decide(t, e, obligationRequest())

	reordered := d
	reordered.Obligations.MaskFields = []string{"dob", "ssn"}
	if !ed25519.Verify(e.PublicKey(), reordered.SignedBytes(), reordered.Signature) {
		t.Fatal("mask field order must not affect the signature")
	}
	if !d.Obligations.Equal(reordered.Obligations) {
		t.Fatal("obligations differing only in order must compare equal")
	}
}

func TestObligationsEqualDistinguishesRealDifferences(t *testing.T) {
	base := Obligations{ReadOnly: true, SessionTTLSeconds: 60, MaskFields: []string{"a"}}
	for name, other := range map[string]Obligations{
		"read-only cleared": {SessionTTLSeconds: 60, MaskFields: []string{"a"}},
		"different ttl":     {ReadOnly: true, SessionTTLSeconds: 61, MaskFields: []string{"a"}},
		"extra mask":        {ReadOnly: true, SessionTTLSeconds: 60, MaskFields: []string{"a", "b"}},
		"reauth added":      {ReadOnly: true, SessionTTLSeconds: 60, ReauthWithinSeconds: 5, MaskFields: []string{"a"}},
	} {
		if base.Equal(other) {
			t.Errorf("%s must not compare equal", name)
		}
	}
}

// Obligations are rendered into audit trails and operator tooling, so the
// rendering is read by humans deciding whether an access was appropriate.
// A grant that prints as unrestricted when it is not would mislead exactly
// the person the log exists for.
func TestObligationsRenderLegibly(t *testing.T) {
	cases := map[string]struct {
		o    Obligations
		want string
	}{
		"none":       {Obligations{}, "none"},
		"read only":  {Obligations{ReadOnly: true}, "read-only"},
		"reauth":     {Obligations{ReauthWithinSeconds: 300}, "re-auth within 300s"},
		"ttl":        {Obligations{SessionTTLSeconds: 60}, "session TTL 60s"},
		"masking":    {Obligations{MaskFields: []string{"ssn", "dob"}}, "mask ssn,dob"},
		"everything": {Obligations{ReadOnly: true, SessionTTLSeconds: 60}, "read-only; session TTL 60s"},
	}
	for name, c := range cases {
		if got := c.o.String(); got != c.want {
			t.Errorf("%s: rendered %q, want %q", name, got, c.want)
		}
	}
	// An imposed obligation must never render as "none".
	for _, o := range []Obligations{
		{ReadOnly: true}, {ReauthWithinSeconds: 1}, {SessionTTLSeconds: 1}, {MaskFields: []string{"x"}},
	} {
		if o.IsZero() || o.String() == "none" {
			t.Errorf("%+v imposes something and must not render as none", o)
		}
	}
}

func TestEngineExposesItsAttestedContext(t *testing.T) {
	e := newEngine(t, testPolicy)
	if e.RuleCount() != 4 {
		t.Fatalf("expected the measured policy's 4 rules, got %d", e.RuleCount())
	}
	if e.Enclave() == nil || e.Enclave().Measurement() == (tee.Measurement{}) {
		t.Fatal("the engine must expose the enclave it was measured into")
	}
	// Sign lets enclave-resident components (the audit log) speak with the
	// same attested authority, without the private key ever leaving.
	digest := []byte("checkpoint digest")
	if !ed25519.Verify(e.PublicKey(), digest, e.Sign(digest)) {
		t.Fatal("Sign must produce signatures verifiable under the attested key")
	}
}

// ─── Decision signing ───────────────────────────────────────────────────

func TestDecisionSignatureCoversEveryField(t *testing.T) {
	e := newEngine(t, testPolicy)
	d := decide(t, e, baseRequest())

	mutations := map[string]func(*Decision){
		"verdict":        func(d *Decision) { d.Allow = !d.Allow },
		"rule id":        func(d *Decision) { d.RuleID = "maintenance-backdoor" },
		"reason":         func(d *Decision) { d.Reason = "because" },
		"policy version": func(d *Decision) { d.PolicyVersion = "other" },
		"request hash":   func(d *Decision) { d.RequestHash[0] ^= 1 },
		"nonce":          func(d *Decision) { d.Nonce[31] ^= 1 },
	}
	for name, mutate := range mutations {
		tampered := d
		mutate(&tampered)
		if ed25519.Verify(e.PublicKey(), tampered.SignedBytes(), tampered.Signature) {
			t.Errorf("altering the %s must invalidate the signature", name)
		}
	}
}

// Two decisions that differ only in where the boundary between rule id and
// reason falls must not share a signed encoding.
func TestDecisionEncodingResistsFieldBoundaryShifting(t *testing.T) {
	a := Decision{RuleID: "ab", Reason: "c"}
	b := Decision{RuleID: "a", Reason: "bc"}
	if string(a.SignedBytes()) == string(b.SignedBytes()) {
		t.Fatal("rule id and reason must not be confusable")
	}
}

// A decision must be legible as coming from a specific policy version, so
// an auditor reviewing a year-old allow knows which rules were in force.
func TestDecisionsCarryThePolicyVersion(t *testing.T) {
	d := decide(t, newEngine(t, testPolicy), baseRequest())
	if d.PolicyVersion != "test" {
		t.Fatalf("expected the policy version on the decision, got %q", d.PolicyVersion)
	}
}

// ─── Evaluation semantics at the edges ──────────────────────────────────

func TestSensitivityBandBoundariesAreInclusive(t *testing.T) {
	const p = `{"version":"t","rules":[
	  {"id":"band","effect":"allow","resources":["*"],
	   "min_sensitivity":2,"max_sensitivity":3,"when":{"min_auth":"password"}}]}`
	e := newEngine(t, p)

	for sensitivity, want := range map[int]bool{1: false, 2: true, 3: true, 4: false} {
		d := decide(t, e, Request{
			Subject:  Subject{ID: "x", AuthMethod: "password"},
			Resource: Resource{Name: "thing", Sensitivity: sensitivity},
			Context:  Context{Network: "corp"},
		})
		if d.Allow != want {
			t.Errorf("sensitivity %d: expected allow=%v, got %v (%s)", sensitivity, want, d.Allow, d.Reason)
		}
	}
}

// Deny-overrides must hold regardless of where the deny sits in the file;
// a policy author must not be able to disable a prohibition by ordering.
func TestDenyOverridesRegardlessOfRuleOrder(t *testing.T) {
	const denyLast = `{"version":"t","rules":[
	  {"id":"allow-all","effect":"allow","resources":["*"],"when":{"min_auth":"password"}},
	  {"id":"deny-public","effect":"deny","resources":["*"],"when":{"networks":["public"]}}]}`

	d := decide(t, newEngine(t, denyLast), Request{
		Subject:  Subject{ID: "x", AuthMethod: "password"},
		Resource: Resource{Name: "thing", Sensitivity: 2},
		Context:  Context{Network: "public"},
	})
	if d.Allow || d.RuleID != "deny-public" {
		t.Fatalf("a deny later in the file must still win, got %+v", d)
	}
}

func TestWildcardAndExplicitResourcesCoexist(t *testing.T) {
	const p = `{"version":"t","rules":[
	  {"id":"specific","effect":"allow","resources":["wiki"],"when":{"min_auth":"password"}},
	  {"id":"wildcard","effect":"allow","resources":["*"],"when":{"min_auth":"hardware-key"}}]}`
	e := newEngine(t, p)

	weak := Request{
		Subject:  Subject{ID: "x", AuthMethod: "password"},
		Resource: Resource{Name: "wiki", Sensitivity: 1},
		Context:  Context{Network: "corp"},
	}
	if d := decide(t, e, weak); !d.Allow || d.RuleID != "specific" {
		t.Fatalf("first matching allow should win: %+v", d)
	}
	weak.Resource.Name = "other"
	if d := decide(t, e, weak); d.Allow {
		t.Fatal("the wildcard rule requires stronger auth and must not fire")
	}
}

// Role matching is any-of, and must not be satisfied by a near miss.
func TestRoleMatchingIsExactAndAnyOf(t *testing.T) {
	const p = `{"version":"t","rules":[
	  {"id":"r","effect":"allow","resources":["*"],
	   "when":{"min_auth":"password","roles":["release-eng","sre"]}}]}`
	e := newEngine(t, p)

	check := func(roles []string, want bool) {
		t.Helper()
		d := decide(t, e, Request{
			Subject:  Subject{ID: "x", Roles: roles, AuthMethod: "password"},
			Resource: Resource{Name: "thing", Sensitivity: 1},
			Context:  Context{Network: "corp"},
		})
		if d.Allow != want {
			t.Errorf("roles %v: expected allow=%v, got %v", roles, want, d.Allow)
		}
	}
	check([]string{"sre"}, true)
	check([]string{"release-eng"}, true)
	check([]string{"other", "sre"}, true)
	check([]string{"release-engineer"}, false) // prefix, not a match
	check([]string{"Release-Eng"}, false)      // case differs
	check(nil, false)
}

func TestDecisionsAreDeterministic(t *testing.T) {
	e := newEngine(t, testPolicy)
	var nonce [32]byte
	first := e.Decide(baseRequest(), nonce)
	for range 20 {
		again := e.Decide(baseRequest(), nonce)
		if again.Allow != first.Allow || again.RuleID != first.RuleID ||
			string(again.Signature) != string(first.Signature) {
			t.Fatal("the same request and nonce must produce the same signed decision")
		}
	}
}

// ─── Concurrency ────────────────────────────────────────────────────────

// One attested PDP serves many enforcement points. Evaluation reads shared
// policy state and signs with a shared key; both must be safe.
func TestConcurrentDecisionsAreSafeAndCorrect(t *testing.T) {
	e := newEngine(t, testPolicy)
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := baseRequest()
			var nonce [32]byte
			nonce[0] = byte(i)
			if i%2 == 0 {
				req.Device.Managed = false // should deny
			}
			d := e.Decide(req, nonce)
			if !ed25519.Verify(e.PublicKey(), d.SignedBytes(), d.Signature) {
				t.Error("every concurrent decision must be validly signed")
			}
			if d.Nonce != nonce {
				t.Error("decisions must echo the caller's own nonce, not another goroutine's")
			}
			if want := i%2 != 0; d.Allow != want {
				t.Errorf("goroutine %d: expected allow=%v, got %v", i, want, d.Allow)
			}
		}()
	}
	wg.Wait()
}

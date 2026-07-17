// Package pdp is the Zero Trust Policy Decision Point: the engine that
// evaluates access requests against policy and answers allow or deny.
//
// In classic Zero Trust this component is the single most attractive
// target — compromise the PDP and every "verified" decision in the system
// is silently attacker-controlled. VERITY closes that gap two ways:
//
//   - The engine is constructed only from bytes the TEE platform measured
//     (NewEngineInEnclave reads the policy out of the enclave image), so
//     the engine's behavior is a deterministic function of the launch
//     measurement. Different policy ⇒ different measurement ⇒ attestation
//     failure downstream.
//   - Every decision is signed with an ephemeral key generated inside the
//     enclave, and that key is bound into the attestation quote. A
//     decision is only as trustworthy as the attested code that signed it,
//     and enforcement points can verify exactly that.
//
// The policy model itself is deliberately small but genuinely Zero Trust:
// deny by default, explicit-deny overrides, and conditions over the three
// signal classes every ZT architecture evaluates — identity (who, how
// strongly authenticated), device posture (managed, patched, encrypted),
// and context (network zone).
package pdp

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/aabhimittal/zero-trust-confidential-computing/internal/tee"
)

// authStrength orders authentication methods so policies can require a
// minimum ("mfa or better") instead of enumerating methods.
var authStrength = map[string]int{
	"password":     1,
	"mfa":          2,
	"hardware-key": 3,
}

// Policy is the declarative rule bundle the engine interprets. It is the
// exact byte content measured into the enclave image; there is no other
// configuration channel, because an unmeasured channel would be an
// unattested one.
type Policy struct {
	Version string `json:"version"`
	Rules   []Rule `json:"rules"`
}

// Rule matches a set of resources and, when its conditions hold for a
// request, fires with an allow or deny effect. Evaluation is
// deny-overrides: any fired deny beats every allow, and if nothing fires
// the default is deny.
type Rule struct {
	ID     string `json:"id"`
	Effect string `json:"effect"` // "allow" or "deny"
	// Resources lists resource names this rule covers; "*" covers all.
	Resources []string `json:"resources"`
	// MinSensitivity/MaxSensitivity optionally narrow the rule to a
	// sensitivity band (0 = unbounded on that side).
	MinSensitivity int `json:"min_sensitivity,omitempty"`
	MaxSensitivity int `json:"max_sensitivity,omitempty"`
	// When are the conditions under which the rule fires.
	When Conditions `json:"when"`
}

// Conditions are request predicates. Empty fields do not constrain. For an
// allow rule they read as requirements; for a deny rule they describe the
// situation being forbidden (e.g. Networks: ["public"] on a deny rule
// fires exactly when the request comes from a public network).
type Conditions struct {
	MinAuth        string   `json:"min_auth,omitempty"`
	ManagedDevice  bool     `json:"managed_device,omitempty"`
	PatchedDevice  bool     `json:"patched_device,omitempty"`
	DiskEncryption bool     `json:"disk_encryption,omitempty"`
	Networks       []string `json:"networks,omitempty"`
	Roles          []string `json:"roles,omitempty"`
}

// Request carries the full signal set for one access attempt. Field order
// is fixed; HashRequest depends on it for a stable canonical encoding.
type Request struct {
	Subject  Subject  `json:"subject"`
	Device   Device   `json:"device"`
	Resource Resource `json:"resource"`
	Context  Context  `json:"context"`
}

type Subject struct {
	ID         string   `json:"id"`
	Roles      []string `json:"roles"`
	AuthMethod string   `json:"auth_method"`
}

type Device struct {
	Managed       bool `json:"managed"`
	OSPatched     bool `json:"os_patched"`
	DiskEncrypted bool `json:"disk_encrypted"`
}

type Resource struct {
	Name        string `json:"name"`
	Sensitivity int    `json:"sensitivity"` // 1 (public) … 4 (crown jewels)
}

type Context struct {
	Network string `json:"network"` // "corp", "vpn", "public"
}

// HashRequest canonically encodes a request and hashes it, so a signed
// decision commits to precisely the request it answered. Both PDP and PEP
// compute this from their own copy of the request; a mismatch means the
// decision was issued for something else.
func HashRequest(r Request) [32]byte {
	b, err := json.Marshal(r) // deterministic: fixed struct field order
	if err != nil {
		panic(err) // plain structs cannot fail to marshal
	}
	h := sha256.New()
	h.Write([]byte("verity/request/v1\x00"))
	h.Write(b)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// Decision is the PDP's signed verdict. The signature covers the verdict,
// the request hash, and the enforcement point's nonce — so a decision can
// be neither altered, nor rebound to a different request, nor replayed
// for a later one.
type Decision struct {
	Allow       bool
	RuleID      string
	Reason      string
	RequestHash [32]byte
	Nonce       [32]byte
	Signature   []byte
}

// SignedBytes is the canonical byte string covered by the decision
// signature. Variable-length fields are length-prefixed so no two distinct
// decisions can serialize identically.
func (d Decision) SignedBytes() []byte {
	b := []byte("verity/decision/v1")
	if d.Allow {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	for _, s := range []string{d.RuleID, d.Reason} {
		b = append(b, byte(len(s)>>8), byte(len(s)))
		b = append(b, s...)
	}
	b = append(b, d.RequestHash[:]...)
	b = append(b, d.Nonce[:]...)
	return b
}

// Engine is the policy engine, holding the parsed policy, the enclave it
// runs in, and its ephemeral decision-signing key. The private key exists
// only here — in real hardware, only inside encrypted enclave memory —
// which is why a valid decision signature proves the decision came from
// this attested code.
type Engine struct {
	policy  Policy
	enclave *tee.Enclave
	signKey ed25519.PrivateKey
	pubKey  ed25519.PublicKey
}

// NewEngineInEnclave constructs the engine from the enclave's measured
// policy bytes and generates its decision key inside. This constructor is
// the linchpin of the whole design: because the policy comes from the
// measured image and nowhere else, "which policy is being enforced" and
// "which measurement was attested" are the same question.
func NewEngineInEnclave(e *tee.Enclave) (*Engine, error) {
	var p Policy
	if err := json.Unmarshal(e.PolicyJSON(), &p); err != nil {
		return nil, fmt.Errorf("pdp: policy does not parse: %w", err)
	}
	if err := validate(p); err != nil {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Engine{policy: p, enclave: e, signKey: priv, pubKey: pub}, nil
}

func validate(p Policy) error {
	seen := map[string]bool{}
	for _, r := range p.Rules {
		if r.Effect != "allow" && r.Effect != "deny" {
			return fmt.Errorf("pdp: rule %q has unknown effect %q", r.ID, r.Effect)
		}
		if seen[r.ID] {
			return fmt.Errorf("pdp: duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		if len(r.Resources) == 0 {
			return fmt.Errorf("pdp: rule %q matches no resources", r.ID)
		}
		if r.When.MinAuth != "" && authStrength[r.When.MinAuth] == 0 {
			return fmt.Errorf("pdp: rule %q requires unknown auth method %q", r.ID, r.When.MinAuth)
		}
	}
	return nil
}

// PolicyVersion reports the loaded policy's version string.
func (e *Engine) PolicyVersion() string { return e.policy.Version }

// PublicKey returns the decision-verification key that Attest binds into
// the quote.
func (e *Engine) PublicKey() ed25519.PublicKey { return e.pubKey }

// Attest answers a verifier's challenge: it commits to the engine's public
// key and the caller's nonce in the report data and asks the platform for
// a quote. This is the enclave-internal half of the key-binding handshake.
func (e *Engine) Attest(nonce [32]byte) (tee.Quote, ed25519.PublicKey) {
	return e.enclave.Quote(tee.KeyBinding(e.pubKey, nonce)), e.pubKey
}

// Decide evaluates one request and returns a signed decision echoing the
// caller's nonce.
//
// Semantics, in order:
//  1. Consider only rules whose resource/sensitivity match covers the
//     request's resource.
//  2. A rule fires if all of its conditions hold for the request.
//  3. Any fired deny rule wins (explicit deny overrides allow).
//  4. Otherwise the first fired allow rule, in policy order, wins.
//  5. Otherwise: default deny — the Zero Trust posture is that access is
//     a granted exception, never an assumed baseline.
func (e *Engine) Decide(req Request, nonce [32]byte) Decision {
	d := Decision{
		Allow:       false,
		RuleID:      "",
		Reason:      "no allow rule matched (default deny)",
		RequestHash: HashRequest(req),
		Nonce:       nonce,
	}

	var allowed *Rule
	for i := range e.policy.Rules {
		r := &e.policy.Rules[i]
		if !matches(r, req.Resource) || !holds(r.When, req) {
			continue
		}
		if r.Effect == "deny" {
			d.Reason = fmt.Sprintf("denied by rule %q", r.ID)
			d.RuleID = r.ID
			d.Signature = ed25519.Sign(e.signKey, d.SignedBytes())
			return d
		}
		if allowed == nil {
			allowed = r
		}
	}
	if allowed != nil {
		d.Allow = true
		d.RuleID = allowed.ID
		d.Reason = fmt.Sprintf("allowed by rule %q", allowed.ID)
	}
	d.Signature = ed25519.Sign(e.signKey, d.SignedBytes())
	return d
}

func matches(r *Rule, res Resource) bool {
	if r.MinSensitivity != 0 && res.Sensitivity < r.MinSensitivity {
		return false
	}
	if r.MaxSensitivity != 0 && res.Sensitivity > r.MaxSensitivity {
		return false
	}
	return slices.Contains(r.Resources, "*") || slices.Contains(r.Resources, res.Name)
}

func holds(c Conditions, req Request) bool {
	if c.MinAuth != "" && authStrength[req.Subject.AuthMethod] < authStrength[c.MinAuth] {
		return false
	}
	if c.ManagedDevice && !req.Device.Managed {
		return false
	}
	if c.PatchedDevice && !req.Device.OSPatched {
		return false
	}
	if c.DiskEncryption && !req.Device.DiskEncrypted {
		return false
	}
	if len(c.Networks) > 0 && !slices.Contains(c.Networks, req.Context.Network) {
		return false
	}
	if len(c.Roles) > 0 {
		ok := false
		for _, role := range c.Roles {
			if slices.Contains(req.Subject.Roles, role) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

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
// deny by default, explicit-deny overrides, conditions over the three
// signal classes every ZT architecture evaluates — identity (who, how
// strongly authenticated), device posture (managed, patched, encrypted),
// and context (network zone) — and obligations, so an allow can be
// conditional rather than absolute.
//
// An Engine is immutable after construction and safe for concurrent use;
// a single attested PDP is expected to serve many enforcement points.
package pdp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aabhimittal/zero-trust-confidential-computing/internal/canon"
	"github.com/aabhimittal/zero-trust-confidential-computing/internal/tee"
)

// authStrength orders authentication methods so policies can require a
// minimum ("mfa or better") instead of enumerating methods. It doubles as
// the set of auth methods a request is allowed to claim: anything outside
// it is rejected rather than silently scored zero, so a typo in an identity
// provider's assertion cannot quietly become "weakest possible auth".
var authStrength = map[string]int{
	"password":     1,
	"mfa":          2,
	"hardware-key": 3,
}

// KnownNetworks is the closed set of network zones a request may claim.
//
// Closing this set is a security decision, not tidiness. Network conditions
// appear in *deny* rules ("no sensitive data from public networks"), and a
// deny rule only fires when the request's zone is in its list. An
// unrecognised zone — "Public", "guest", "" — would therefore match no deny
// rule and sail past it. Rejecting unknown zones outright turns that
// fail-open into a fail-closed.
var KnownNetworks = []string{"corp", "vpn", "public"}

// Sensitivity bounds. Zero is not a valid sensitivity: a resource whose
// sensitivity failed to populate must not be treated as harmless, for the
// same reason an unknown network must not be. See Request.Validate.
const (
	MinSensitivity = 1 // public
	MaxSensitivity = 4 // crown jewels
)

// Guardrails on policy size and field lengths. A tampered image is parsed
// before attestation rejects it, so these bound what an attacker can make
// the enclave do with a policy it will never be allowed to use.
const (
	maxPolicyBytes = 1 << 20
	maxRules       = 4096
	maxFieldLen    = 256
	maxListLen     = 64
)

// InvalidRequestRuleID is reported when a request is refused for being
// malformed rather than by a policy rule. It lives in a reserved namespace
// ("!" prefix) that policy rule IDs may not use, so an audit trail can
// never confuse "denied by a rule someone wrote" with "denied because the
// request made no sense".
const InvalidRequestRuleID = "!invalid-request"

// ErrInvalidRequest is the class of every request-validation failure.
var ErrInvalidRequest = errors.New("pdp: invalid request")

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
	// Obligations ride along with an allow, constraining how the granted
	// access may be exercised. They are meaningless on a deny and rejected
	// there by validation.
	Obligations Obligations `json:"obligations,omitempty"`
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

// Obligations are the strings attached to an allow: things the enforcement
// point must impose for the grant to remain valid. Mature Zero Trust
// architectures need this because real answers are rarely a clean yes —
// "yes, read-only", "yes, for the next ten minutes", "yes, with these
// columns masked".
//
// Obligations are covered by the decision signature, which is the point
// that matters: an on-path attacker cannot strip ReadOnly from a decision
// and hand the enforcement point a bare allow. Downgrading a grant is a
// forgery, and fails exactly like inventing one.
type Obligations struct {
	ReadOnly            bool     `json:"read_only,omitempty"`
	ReauthWithinSeconds int      `json:"reauth_within_seconds,omitempty"`
	SessionTTLSeconds   int      `json:"session_ttl_seconds,omitempty"`
	MaskFields          []string `json:"mask_fields,omitempty"`
}

// IsZero reports whether the obligations impose nothing.
func (o Obligations) IsZero() bool {
	return !o.ReadOnly && o.ReauthWithinSeconds == 0 &&
		o.SessionTTLSeconds == 0 && len(o.MaskFields) == 0
}

// Equal compares two obligation sets the way the signature does: through
// the same normalisation, so that a difference in MaskFields ordering is
// not mistaken for a difference in what is being imposed. Obligations
// contain a slice and so cannot be compared with ==; a caller reaching for
// == would silently fail to compile, but a caller comparing only the scalar
// fields would silently succeed, which is worse.
func (o Obligations) Equal(other Obligations) bool {
	return o.ReadOnly == other.ReadOnly &&
		o.ReauthWithinSeconds == other.ReauthWithinSeconds &&
		o.SessionTTLSeconds == other.SessionTTLSeconds &&
		slices.Equal(normalizeSet(o.MaskFields), normalizeSet(other.MaskFields))
}

func (o Obligations) hash(w *canon.Hasher) *canon.Hasher {
	return w.Bool(o.ReadOnly).
		Uint64(uint64(o.ReauthWithinSeconds)).
		Uint64(uint64(o.SessionTTLSeconds)).
		Strings(normalizeSet(o.MaskFields))
}

// String renders obligations for logs and the demo.
func (o Obligations) String() string {
	if o.IsZero() {
		return "none"
	}
	var parts []string
	if o.ReadOnly {
		parts = append(parts, "read-only")
	}
	if o.ReauthWithinSeconds > 0 {
		parts = append(parts, fmt.Sprintf("re-auth within %ds", o.ReauthWithinSeconds))
	}
	if o.SessionTTLSeconds > 0 {
		parts = append(parts, fmt.Sprintf("session TTL %ds", o.SessionTTLSeconds))
	}
	if len(o.MaskFields) > 0 {
		parts = append(parts, "mask "+strings.Join(o.MaskFields, ","))
	}
	return strings.Join(parts, "; ")
}

// Request carries the full signal set for one access attempt.
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

// Validate checks that a request is well-formed enough to be judged.
//
// Every check here closes a fail-open path. Policy conditions are
// predicates over claimed values, and an unrecognised value satisfies no
// predicate — which for a *deny* rule means the rule does not fire. Missing
// sensitivity would evade the "no sensitive data from public networks"
// rule; an unrecognised zone would evade every network-scoped deny. So the
// engine refuses to judge such requests at all rather than judging them
// leniently.
func (r Request) Validate() error {
	switch {
	case r.Subject.ID == "":
		return fmt.Errorf("%w: subject id is empty", ErrInvalidRequest)
	case len(r.Subject.ID) > maxFieldLen:
		return fmt.Errorf("%w: subject id exceeds %d bytes", ErrInvalidRequest, maxFieldLen)
	case authStrength[r.Subject.AuthMethod] == 0:
		return fmt.Errorf("%w: unknown auth method %q", ErrInvalidRequest, r.Subject.AuthMethod)
	case len(r.Subject.Roles) > maxListLen:
		return fmt.Errorf("%w: more than %d roles", ErrInvalidRequest, maxListLen)
	case r.Resource.Name == "":
		return fmt.Errorf("%w: resource name is empty", ErrInvalidRequest)
	case len(r.Resource.Name) > maxFieldLen:
		return fmt.Errorf("%w: resource name exceeds %d bytes", ErrInvalidRequest, maxFieldLen)
	case r.Resource.Sensitivity < MinSensitivity || r.Resource.Sensitivity > MaxSensitivity:
		return fmt.Errorf("%w: sensitivity %d outside %d..%d",
			ErrInvalidRequest, r.Resource.Sensitivity, MinSensitivity, MaxSensitivity)
	case !slices.Contains(KnownNetworks, r.Context.Network):
		return fmt.Errorf("%w: unknown network zone %q", ErrInvalidRequest, r.Context.Network)
	}
	for _, role := range r.Subject.Roles {
		if role == "" || len(role) > maxFieldLen {
			return fmt.Errorf("%w: role name empty or over %d bytes", ErrInvalidRequest, maxFieldLen)
		}
	}
	return nil
}

// normalizeSet makes a string slice canonical: nil and empty become the
// same thing, order stops mattering, and duplicates collapse.
//
// This matters because the PDP and PEP each hash their *own* copy of the
// request and compare. Those copies routinely take different routes — one
// decoded from JSON where an absent list arrives as nil and an empty one as
// [], the other built in code — and roles are a set, so ["a","b"] and
// ["b","a"] describe the same subject. Without normalisation those hash
// differently and a legitimate request is refused with a signature error
// that looks exactly like an attack.
func normalizeSet(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

// HashRequest canonically encodes a request and hashes it, so a signed
// decision commits to precisely the request it answered. Both PDP and PEP
// compute this from their own copy of the request; a mismatch means the
// decision was issued for something else.
func HashRequest(r Request) [32]byte {
	return canon.New("verity/request/v2").
		String(r.Subject.ID).
		Strings(normalizeSet(r.Subject.Roles)).
		String(r.Subject.AuthMethod).
		Bool(r.Device.Managed).
		Bool(r.Device.OSPatched).
		Bool(r.Device.DiskEncrypted).
		String(r.Resource.Name).
		Uint64(uint64(r.Resource.Sensitivity)).
		String(r.Context.Network).
		Sum()
}

// Decision is the PDP's signed verdict. The signature covers the verdict,
// its obligations, the policy version that produced it, the request hash,
// and the enforcement point's nonce — so a decision can be neither altered,
// nor stripped of its conditions, nor rebound to a different request, nor
// replayed for a later one.
type Decision struct {
	Allow         bool
	RuleID        string
	Reason        string
	Obligations   Obligations
	PolicyVersion string
	RequestHash   [32]byte
	Nonce         [32]byte
	Signature     []byte
}

// SignedBytes is the canonical byte string covered by the decision
// signature.
func (d Decision) SignedBytes() []byte {
	w := canon.New("verity/decision/v2").
		Bool(d.Allow).
		String(d.RuleID).
		String(d.Reason).
		String(d.PolicyVersion)
	w = d.Obligations.hash(w)
	return w.Raw32(d.RequestHash).Raw32(d.Nonce).SumBytes()
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
	raw := e.PolicyJSON()
	if len(raw) > maxPolicyBytes {
		return nil, fmt.Errorf("pdp: policy is %d bytes, over the %d limit", len(raw), maxPolicyBytes)
	}

	// DisallowUnknownFields is load-bearing. Ignoring unknown keys means a
	// policy that says "managed_devise": true — one transposed letter —
	// parses cleanly as a rule with *no* device requirement, silently
	// granting everything the author meant to restrict. A policy this
	// system attests to must not have a fail-open typo mode.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("pdp: policy does not parse: %w", err)
	}
	if dec.More() {
		return nil, errors.New("pdp: policy has trailing content after the bundle")
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
	if p.Version == "" {
		return errors.New("pdp: policy has no version; an unversioned bundle cannot be audited")
	}
	if len(p.Version) > maxFieldLen {
		return fmt.Errorf("pdp: policy version exceeds %d bytes", maxFieldLen)
	}
	if len(p.Rules) == 0 {
		return errors.New("pdp: policy has no rules; use an explicit deny-all rule if that is the intent")
	}
	if len(p.Rules) > maxRules {
		return fmt.Errorf("pdp: policy has %d rules, over the %d limit", len(p.Rules), maxRules)
	}

	seen := make(map[string]bool, len(p.Rules))
	for _, r := range p.Rules {
		switch {
		case r.ID == "":
			return errors.New("pdp: rule has an empty id; decisions would be unattributable")
		case len(r.ID) > maxFieldLen:
			return fmt.Errorf("pdp: rule id %q exceeds %d bytes", r.ID[:32], maxFieldLen)
		case strings.HasPrefix(r.ID, "!"):
			return fmt.Errorf("pdp: rule id %q uses the reserved %q prefix", r.ID, "!")
		case seen[r.ID]:
			return fmt.Errorf("pdp: duplicate rule id %q", r.ID)
		case r.Effect != "allow" && r.Effect != "deny":
			return fmt.Errorf("pdp: rule %q has unknown effect %q", r.ID, r.Effect)
		case len(r.Resources) == 0:
			return fmt.Errorf("pdp: rule %q matches no resources", r.ID)
		case len(r.Resources) > maxListLen:
			return fmt.Errorf("pdp: rule %q lists more than %d resources", r.ID, maxListLen)
		}
		seen[r.ID] = true

		for _, res := range r.Resources {
			if res == "" || len(res) > maxFieldLen {
				return fmt.Errorf("pdp: rule %q has an empty or over-long resource name", r.ID)
			}
		}
		if err := validateSensitivityBand(r); err != nil {
			return err
		}
		if err := validateConditions(r); err != nil {
			return err
		}
		if r.Effect == "deny" && !r.Obligations.IsZero() {
			return fmt.Errorf("pdp: rule %q is a deny but carries obligations, which only qualify an allow", r.ID)
		}
		if r.Obligations.ReauthWithinSeconds < 0 || r.Obligations.SessionTTLSeconds < 0 {
			return fmt.Errorf("pdp: rule %q has a negative obligation duration", r.ID)
		}
	}
	return nil
}

func validateSensitivityBand(r Rule) error {
	for _, s := range []int{r.MinSensitivity, r.MaxSensitivity} {
		if s != 0 && (s < MinSensitivity || s > MaxSensitivity) {
			return fmt.Errorf("pdp: rule %q bounds sensitivity at %d, outside %d..%d",
				r.ID, s, MinSensitivity, MaxSensitivity)
		}
	}
	// A band with min above max can never fire. That is always an authoring
	// mistake, and a silently dead rule in a security policy is worse than
	// a loud one: the author believes a restriction is in force.
	if r.MinSensitivity != 0 && r.MaxSensitivity != 0 && r.MinSensitivity > r.MaxSensitivity {
		return fmt.Errorf("pdp: rule %q has min_sensitivity %d above max_sensitivity %d and can never fire",
			r.ID, r.MinSensitivity, r.MaxSensitivity)
	}
	return nil
}

func validateConditions(r Rule) error {
	c := r.When
	if c.MinAuth != "" && authStrength[c.MinAuth] == 0 {
		return fmt.Errorf("pdp: rule %q requires unknown auth method %q", r.ID, c.MinAuth)
	}
	if len(c.Networks) > maxListLen || len(c.Roles) > maxListLen {
		return fmt.Errorf("pdp: rule %q has an over-long condition list", r.ID)
	}
	// An unknown zone in a condition list is the mirror image of an unknown
	// zone in a request: on a deny rule it produces a restriction that can
	// never fire, which reads as protection while providing none.
	for _, n := range c.Networks {
		if !slices.Contains(KnownNetworks, n) {
			return fmt.Errorf("pdp: rule %q names unknown network zone %q (known: %s)",
				r.ID, n, strings.Join(KnownNetworks, ", "))
		}
	}
	for _, role := range c.Roles {
		if role == "" || len(role) > maxFieldLen {
			return fmt.Errorf("pdp: rule %q has an empty or over-long role name", r.ID)
		}
	}
	return nil
}

// PolicyVersion reports the loaded policy's version string.
func (e *Engine) PolicyVersion() string { return e.policy.Version }

// RuleCount reports how many rules the attested policy contains.
func (e *Engine) RuleCount() int { return len(e.policy.Rules) }

// PublicKey returns the decision-verification key that Attest binds into
// the quote.
func (e *Engine) PublicKey() ed25519.PublicKey { return e.pubKey }

// Enclave exposes the enclave the engine runs in, so enclave-resident
// services built on top of it (such as the sealed audit log) can use the
// same sealing keys and counters.
func (e *Engine) Enclave() *tee.Enclave { return e.enclave }

// Sign signs a digest with the enclave-resident decision key. It lets
// enclave-internal components — the audit log's checkpoints, for instance —
// speak with the same attested authority as decisions, without ever
// exposing the private key.
func (e *Engine) Sign(digest []byte) []byte {
	return ed25519.Sign(e.signKey, digest)
}

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
//  0. A malformed request is refused outright — signed, so the enforcement
//     point still gets a verifiable answer rather than a bare error.
//  1. Consider only rules whose resource/sensitivity match covers the
//     request's resource.
//  2. A rule fires if all of its conditions hold for the request.
//  3. Any fired deny rule wins (explicit deny overrides allow).
//  4. Otherwise the first fired allow rule, in policy order, wins, and
//     carries its obligations with it.
//  5. Otherwise: default deny — the Zero Trust posture is that access is
//     a granted exception, never an assumed baseline.
func (e *Engine) Decide(req Request, nonce [32]byte) Decision {
	d := Decision{
		Allow:         false,
		RuleID:        "",
		Reason:        "no allow rule matched (default deny)",
		PolicyVersion: e.policy.Version,
		RequestHash:   HashRequest(req),
		Nonce:         nonce,
	}

	if err := req.Validate(); err != nil {
		d.RuleID = InvalidRequestRuleID
		d.Reason = err.Error()
		return e.sign(d)
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
			return e.sign(d)
		}
		if allowed == nil {
			allowed = r
		}
	}
	if allowed != nil {
		d.Allow = true
		d.RuleID = allowed.ID
		d.Obligations = allowed.Obligations
		d.Reason = fmt.Sprintf("allowed by rule %q", allowed.ID)
	}
	return e.sign(d)
}

func (e *Engine) sign(d Decision) Decision {
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
		matched := false
		for _, role := range c.Roles {
			if slices.Contains(req.Subject.Roles, role) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

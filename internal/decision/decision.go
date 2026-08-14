// Package decision evaluates a compiled policy bundle against a single tool
// call. It is the whole of what the enforcer decides.
//
// The deliberate omission is reversibility discovery. A bundle carries the
// static classification — this tool declares a reversible inverse, that one
// declares none — and this package looks the answer up. Whether the inverse can
// actually execute right now, which is what catches a *phantom rollback*, needs
// to read the world and belongs to the control plane. The enforcer is told; it
// does not find out.
//
// Stating that plainly matters more than it looks. A sidecar that appears to
// verify recoverability but only reads a lookup table would be believed exactly
// once, and the moment it mattered would be the moment it was wrong.
package decision

import (
	"encoding/json"
	"fmt"
	"io"
)

// Effect is what a matching rule does.
type Effect string

const (
	Allow           Effect = "allow"
	Deny            Effect = "deny"
	RequireApproval Effect = "require_approval"
	Redact          Effect = "redact"
)

// Reversibility mirrors revoco's four postures.
type Reversibility string

const (
	Reversible   Reversibility = "reversible"
	Compensable  Reversibility = "compensable"
	Irreversible Reversibility = "irreversible"
	Unknown      Reversibility = "unknown"
)

// Rule is one policy rule. Every field is required in the wire format: the
// compiler writes them all out explicitly so that neither runtime has to invent
// a default, which is the class of bug most likely to make the two disagree.
type Rule struct {
	ID             string   `json:"id"`
	Effect         Effect   `json:"effect"`
	Tools          []string `json:"tools"`
	Actions        []string `json:"actions"`
	Agents         []string `json:"agents"`
	RequireRoles   []string `json:"require_roles"`
	Reversibility  []string `json:"reversibility"`
	MinRisk        *int     `json:"min_risk"`
	MaxRisk        *int     `json:"max_risk"`
	MinThreatScore *int     `json:"min_threat_score"`
	RedactFields   []string `json:"redact_fields"`
	Reason         string   `json:"reason"`
}

// GlobKind pairs a tool-name pattern with the reversibility it implies.
type GlobKind struct {
	Tool string `json:"tool"`
	Kind string `json:"kind"`
}

// Bundle is a compiled policy plus the static reversibility registry.
type Bundle struct {
	Schema                   int               `json:"schema"`
	PolicyID                 string            `json:"policy_id"`
	DefaultEffect            Effect            `json:"default_effect"`
	Reversibility            map[string]string `json:"reversibility"`
	ReversibilityGlobs       []GlobKind        `json:"reversibility_globs"`
	UnknownToolReversibility string            `json:"unknown_tool_reversibility"`
	Rules                    []Rule            `json:"rules"`
}

// Call is one tool invocation to be judged.
type Call struct {
	Tool          string   `json:"tool"`
	Action        string   `json:"action"`
	AgentID       string   `json:"agent_id"`
	Roles         []string `json:"roles"`
	Risk          int      `json:"risk"`
	ThreatScore   int      `json:"threat_score"`
	Reversibility string   `json:"reversibility,omitempty"` // empty -> classify from bundle
}

// Verdict is the decision, in the shape the ledger records.
type Verdict struct {
	Effect        Effect `json:"effect"`
	RuleID        string `json:"rule_id"`
	Reason        string `json:"reason"`
	Reversibility string `json:"reversibility"`
	Allowed       bool   `json:"allowed"`
}

// SupportedSchema is the only bundle version this build understands.
const SupportedSchema = 1

// Load reads and validates a bundle.
//
// Validation refuses rather than repairs. A bundle from a future schema, or one
// with a rule missing a field, is rejected outright — an enforcer that guessed
// at the missing half would be enforcing a policy nobody wrote.
func Load(r io.Reader) (*Bundle, error) {
	var b Bundle
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("bundle is not valid: %w", err)
	}
	if b.Schema != SupportedSchema {
		return nil, fmt.Errorf(
			"bundle declares schema %d, this enforcer speaks %d. Refusing rather "+
				"than guessing which rules changed meaning", b.Schema, SupportedSchema)
	}
	if b.DefaultEffect == "" {
		return nil, fmt.Errorf("bundle has no default_effect; refusing to assume one")
	}
	for i, rule := range b.Rules {
		if rule.ID == "" || rule.Effect == "" {
			return nil, fmt.Errorf("rule %d has no id or no effect", i)
		}
		if rule.Tools == nil || rule.Actions == nil || rule.Agents == nil {
			return nil, fmt.Errorf(
				"rule %q omits tools, actions or agents. The compiler writes these "+
					"explicitly; a bundle without them was not produced by it", rule.ID)
		}
	}
	return &b, nil
}

// Classify returns the static reversibility of a tool: exact name first, then
// glob patterns in registration order, then the bundle's unknown fallback.
//
// The ordering is not cosmetic. revoco resolves the same way, and flattening
// exact names and globs into one map would silently change which spec wins for
// a tool matched by both.
func (b *Bundle) Classify(tool string) string {
	if kind, ok := b.Reversibility[tool]; ok {
		return kind
	}
	for _, g := range b.ReversibilityGlobs {
		if FnMatch(tool, g.Tool) {
			return g.Kind
		}
	}
	return b.UnknownToolReversibility
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// matches reports whether a rule applies to a call. Kept in the same order as
// revoco's `_rule_matches` so the two read as translations of each other.
func (r *Rule) matches(c *Call, rev string) bool {
	if !matchAny(c.Tool, r.Tools) {
		return false
	}
	if !matchAny(c.Action, r.Actions) {
		return false
	}
	if !matchAny(c.AgentID, r.Agents) {
		return false
	}
	for _, want := range r.RequireRoles {
		if !hasRole(c.Roles, want) {
			return false
		}
	}
	if len(r.Reversibility) > 0 && !contains(r.Reversibility, rev) {
		return false
	}
	if r.MinThreatScore != nil && c.ThreatScore < *r.MinThreatScore {
		return false
	}
	if r.MinRisk != nil && c.Risk < *r.MinRisk {
		return false
	}
	if r.MaxRisk != nil && c.Risk > *r.MaxRisk {
		return false
	}
	return true
}

// Evaluate walks the rules in order and returns the first match, or the
// bundle's default effect if nothing matches.
func (b *Bundle) Evaluate(c *Call) Verdict {
	rev := c.Reversibility
	if rev == "" {
		rev = b.Classify(c.Tool)
	}

	for i := range b.Rules {
		rule := &b.Rules[i]
		if rule.matches(c, rev) {
			return Verdict{
				Effect:        rule.Effect,
				RuleID:        rule.ID,
				Reason:        rule.Reason,
				Reversibility: rev,
				Allowed:       rule.Effect == Allow,
			}
		}
	}

	return Verdict{
		Effect:        b.DefaultEffect,
		RuleID:        "__default__",
		Reason:        fmt.Sprintf("no rule matched; default %s", b.DefaultEffect),
		Reversibility: rev,
		Allowed:       b.DefaultEffect == Allow,
	}
}

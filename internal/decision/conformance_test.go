package decision

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The fixtures are verdicts revoco actually produced, not verdicts anyone wrote
// down. If this test fails, the two runtimes disagree about what a policy means,
// and shipping in that state would produce a ledger that cannot be trusted in
// either direction. There is no "close enough" here.

type expectation struct {
	Effect        string `json:"effect"`
	RuleID        string `json:"rule_id"`
	Reversibility string `json:"reversibility"`
	Allowed       bool   `json:"allowed"`
}

type fixtureCase struct {
	Tool        string      `json:"tool"`
	Action      string      `json:"action"`
	AgentID     string      `json:"agent_id"`
	Roles       []string    `json:"roles"`
	Risk        int         `json:"risk"`
	ThreatScore int         `json:"threat_score"`
	Expect      expectation `json:"expect"`
}

type suite struct {
	Name   string          `json:"name"`
	Bundle json.RawMessage `json:"bundle"`
	Cases  []fixtureCase   `json:"cases"`
}

func loadSuites(t *testing.T) []suite {
	t.Helper()
	dir := filepath.Join("..", "..", "conformance", "fixtures")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read fixtures: %v", err)
	}

	var out []suite
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("cannot read %s: %v", e.Name(), err)
		}
		var s suite
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatalf("cannot parse %s: %v", e.Name(), err)
		}
		out = append(out, s)
	}
	// An empty fixture directory would make this test pass while checking
	// nothing, which is the failure mode a conformance suite must not have.
	if len(out) == 0 {
		t.Fatal("no fixtures found; the conformance suite would pass vacuously")
	}
	return out
}

func TestConformsToPythonGate(t *testing.T) {
	total := 0
	for _, s := range loadSuites(t) {
		bundle, err := Load(bytes.NewReader(s.Bundle))
		if err != nil {
			t.Fatalf("%s: bundle rejected: %v", s.Name, err)
		}
		if len(s.Cases) == 0 {
			t.Fatalf("%s: suite has no cases", s.Name)
		}

		failed := 0
		for _, c := range s.Cases {
			got := bundle.Evaluate(&Call{
				Tool: c.Tool, Action: c.Action, AgentID: c.AgentID,
				Roles: c.Roles, Risk: c.Risk, ThreatScore: c.ThreatScore,
			})
			if string(got.Effect) != c.Expect.Effect ||
				got.RuleID != c.Expect.RuleID ||
				got.Reversibility != c.Expect.Reversibility ||
				got.Allowed != c.Expect.Allowed {
				failed++
				if failed <= 5 { // enough to see the shape, not enough to drown in
					t.Errorf("%s: %s/%s agent=%s roles=%v risk=%d threat=%d\n"+
						"  python: %s via %s (rev %s, allowed %v)\n"+
						"  go    : %s via %s (rev %s, allowed %v)",
						s.Name, c.Tool, c.Action, c.AgentID, c.Roles, c.Risk, c.ThreatScore,
						c.Expect.Effect, c.Expect.RuleID, c.Expect.Reversibility, c.Expect.Allowed,
						got.Effect, got.RuleID, got.Reversibility, got.Allowed)
				}
			}
			total++
		}
		if failed > 5 {
			t.Errorf("%s: %d more divergences not shown", s.Name, failed-5)
		}
		t.Logf("%-22s %5d cases", s.Name, len(s.Cases))
	}
	t.Logf("%d cases checked against verdicts revoco actually produced", total)
}

// A bundle the compiler did not produce must be refused rather than
// interpreted. Each of these is a way a policy could silently come to mean
// something its author did not write.
func TestLoadRefusesMalformedBundles(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"future schema", `{"schema":99,"policy_id":"p","default_effect":"deny",
			"reversibility":{},"reversibility_globs":[],
			"unknown_tool_reversibility":"unknown","rules":[]}`},
		{"no default effect", `{"schema":1,"policy_id":"p","default_effect":"",
			"reversibility":{},"reversibility_globs":[],
			"unknown_tool_reversibility":"unknown","rules":[]}`},
		{"rule missing tools", `{"schema":1,"policy_id":"p","default_effect":"deny",
			"reversibility":{},"reversibility_globs":[],
			"unknown_tool_reversibility":"unknown",
			"rules":[{"id":"r","effect":"allow","actions":["*"],"agents":["*"],
			"require_roles":[],"reversibility":[],"min_risk":null,"max_risk":null,
			"min_threat_score":null,"redact_fields":[],"reason":"x"}]}`},
		{"unknown field", `{"schema":1,"policy_id":"p","default_effect":"deny",
			"reversibility":{},"reversibility_globs":[],
			"unknown_tool_reversibility":"unknown","rules":[],"surprise":true}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load(bytes.NewReader([]byte(tc.body))); err == nil {
				t.Fatal("bundle was accepted; it should have been refused")
			}
		})
	}
}

// The specific reason path.Match is not used. If someone swaps the
// implementation for the standard library's, this is what fails.
func TestGlobUsesPythonSemantics(t *testing.T) {
	cases := []struct {
		name, pattern string
		want          bool
	}{
		{"a/b", "a*", true},          // Go's path.Match says false
		{"a/b/c", "a*c", true},       // Go's path.Match says false
		{"a.b", "a?b", true},         //
		{"file1", "file[0-9]", true}, //
		{"fileX", "file[0-9]", false},
		{"file1", "file[!0-9]", false},
		{"fileX", "file[!0-9]", true},
		{"UPPER", "upper", false}, // case-sensitive
		{"a[b", "a[b", true},      // unterminated class is a literal in Python
	}
	for _, tc := range cases {
		if got := FnMatch(tc.name, tc.pattern); got != tc.want {
			t.Errorf("FnMatch(%q, %q) = %v, want %v", tc.name, tc.pattern, got, tc.want)
		}
	}
}

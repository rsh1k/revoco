// Command recoup-enforcer is the request-path half of recoup.
//
// It loads a compiled policy bundle and answers one question per tool call:
// what should happen to this? It holds no state beyond counters, talks to
// nothing, and is designed to be dropped in as a sidecar next to an agent or as
// a shared gateway in front of MCP servers.
//
// # Shadow mode
//
// The default is --mode=shadow, and that default is a deliberate product
// decision rather than caution. Nobody installs a thing that blocks their
// agents on the strength of a vendor's claim. In shadow mode every call is
// allowed and the verdict that *would* have applied is recorded, which turns the
// first deployment into a measurement rather than a bet: run it for a month,
// read off how much of the agent estate is doing irreversible work, and only
// then decide what to enforce.
//
// It also changes what the thing is during a security review. Observe-only
// software that cannot break production is a different conversation from a new
// control in the payment path.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rsh1k/recoup/internal/decision"
)

type mode string

const (
	modeShadow  mode = "shadow"  // decide, record, allow anyway
	modeEnforce mode = "enforce" // decide, record, apply
)

type counters struct {
	mu       sync.Mutex
	total    int64
	byEffect map[string]int64
	// Calls that shadow mode let through but enforce mode would have stopped.
	// This is the number the first month of a deployment exists to produce.
	wouldHaveBlocked int64
}

func newCounters() *counters {
	return &counters{byEffect: map[string]int64{}}
}

func (c *counters) record(v decision.Verdict, shadowed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total++
	c.byEffect[string(v.Effect)]++
	if shadowed && !v.Allowed {
		c.wouldHaveBlocked++
	}
}

func (c *counters) snapshot() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	byEffect := make(map[string]int64, len(c.byEffect))
	for k, v := range c.byEffect {
		byEffect[k] = v
	}
	return map[string]any{
		"decisions":          c.total,
		"by_effect":          byEffect,
		"would_have_blocked": c.wouldHaveBlocked,
	}
}

type server struct {
	bundle *decision.Bundle
	mode   mode
	counts *counters
}

// response is what a caller acts on. `enforced` is reported separately from
// `allowed` so a client can never confuse "this was fine" with "this was let
// through because we are only watching".
type response struct {
	Allowed       bool   `json:"allowed"`
	Enforced      bool   `json:"enforced"`
	Effect        string `json:"effect"`
	RuleID        string `json:"rule_id"`
	Reason        string `json:"reason"`
	Reversibility string `json:"reversibility"`
	PolicyID      string `json:"policy_id"`
	ShadowedBlock bool   `json:"shadowed_block,omitempty"`
}

func (s *server) decide(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var call decision.Call
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&call); err != nil {
		http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
		return
	}
	if call.Tool == "" {
		http.Error(w, "tool is required", http.StatusBadRequest)
		return
	}
	if call.Action == "" {
		// revoco's own default. Assuming `read` would be the dangerous guess.
		call.Action = "write"
	}

	verdict := s.bundle.Evaluate(&call)
	shadowed := s.mode == modeShadow
	s.counts.record(verdict, shadowed)

	resp := response{
		Allowed:       verdict.Allowed || shadowed,
		Enforced:      !shadowed,
		Effect:        string(verdict.Effect),
		RuleID:        verdict.RuleID,
		Reason:        verdict.Reason,
		Reversibility: verdict.Reversibility,
		PolicyID:      s.bundle.PolicyID,
		ShadowedBlock: shadowed && !verdict.Allowed,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *server) stats(w http.ResponseWriter, _ *http.Request) {
	out := s.counts.snapshot()
	out["mode"] = string(s.mode)
	out["policy_id"] = s.bundle.PolicyID
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": true, "policy_id": s.bundle.PolicyID, "mode": string(s.mode),
	})
}

func main() {
	var (
		bundlePath = flag.String("bundle", "", "path to a compiled policy bundle (required)")
		addr       = flag.String("addr", ":842", "listen address")
		modeFlag   = flag.String("mode", string(modeShadow), "shadow | enforce")
		identity   = flag.String("agent-identity", "unverified",
			"how the caller's agent id is established: unverified | trusted-network")
	)
	flag.Parse()

	if *bundlePath == "" {
		fmt.Fprintln(os.Stderr, "a --bundle is required; the enforcer has no built-in policy")
		os.Exit(2)
	}
	m := mode(*modeFlag)
	if m != modeShadow && m != modeEnforce {
		fmt.Fprintf(os.Stderr, "unknown mode %q; use shadow or enforce\n", *modeFlag)
		os.Exit(2)
	}

	f, err := os.Open(*bundlePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read bundle: %v\n", err)
		os.Exit(1)
	}
	bundle, err := decision.Load(f)
	_ = f.Close()
	if err != nil {
		// Refusing to start is correct. An enforcer that came up with a bundle
		// it did not fully understand would be enforcing something nobody wrote.
		fmt.Fprintf(os.Stderr, "bundle rejected: %v\n", err)
		os.Exit(1)
	}

	// The agent id arrives in the request body, so by default it is a claim
	// rather than a fact. That is harmless while every rule matches any agent,
	// and unacceptable the moment a rule narrows by one: an unauthenticated
	// caller would get to choose which rule applies to it by choosing what to
	// send. Rather than serve a policy whose agent conditions merely look
	// enforced, refuse to start and say exactly which rules are affected.
	//
	// `trusted-network` is the escape hatch for a deployment where something
	// upstream — a service mesh with mTLS, an mesh-injected sidecar — has
	// already established the identity. It is opt-in and named so that choosing
	// it is a decision someone made rather than a default they inherited.
	if affected := bundle.DependsOnAgentIdentity(); len(affected) > 0 && *identity == "unverified" {
		fmt.Fprintf(os.Stderr,
			"refusing to start: %d rule(s) decide on which agent is calling (%s),\n"+
				"but --agent-identity=unverified means that id is taken from the request\n"+
				"body and never checked. Any caller could select its own rule.\n\n"+
				"Either remove the agent conditions, or run behind something that\n"+
				"authenticates the caller and pass --agent-identity=trusted-network.\n",
			len(affected), strings.Join(affected, ", "))
		os.Exit(2)
	}

	s := &server{bundle: bundle, mode: m, counts: newCounters()}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/decide", s.decide)
	mux.HandleFunc("/v1/stats", s.stats)
	mux.HandleFunc("/healthz", s.healthz)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("recoup-enforcer on %s | policy %s | mode %s | %d rules",
		*addr, bundle.PolicyID, m, len(bundle.Rules))
	if *identity == "unverified" {
		log.Printf("agent identity is unverified: the agent_id field is informational " +
			"only. No rule in this bundle depends on it.")
	}
	if m == modeShadow {
		log.Printf("shadow mode: every call is allowed and the verdict recorded. " +
			"GET /v1/stats for what would have been blocked.")
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

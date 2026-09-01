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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rsh1k/revoco/recoup/internal/decision"
	"github.com/rsh1k/revoco/recoup/internal/journal"
	"github.com/rsh1k/revoco/recoup/internal/translog"
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
	bundle  *decision.Bundle
	mode    mode
	counts  *counters
	journal *journal.Writer
	log     *translog.Log
}

// leafFor is the exact bytes committed to the log for one decision. Canonical
// and self-contained: an auditor holding a receipt must be able to rebuild this
// byte for byte without asking the operator what it meant. Field order is fixed
// by the struct, which is why this is a struct and not a map.
type leaf struct {
	Tool          string `json:"tool"`
	Action        string `json:"action"`
	AgentID       string `json:"agent_id"`
	Risk          int    `json:"risk"`
	Reversibility string `json:"reversibility"`
	Effect        string `json:"effect"`
	RuleID        string `json:"rule_id"`
	Allowed       bool   `json:"allowed"`
	PolicyID      string `json:"policy_id"`
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
	// The receipt. With the leaf bytes and a later proof, a holder can show this
	// decision is in the log without the operator's cooperation.
	LeafIndex *int   `json:"leaf_index,omitempty"`
	Leaf      string `json:"leaf,omitempty"`
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
	s.journal.Append(journal.Entry{
		Tool: call.Tool, Action: call.Action, AgentID: call.AgentID,
		Roles: call.Roles, Risk: call.Risk, ThreatScore: call.ThreatScore,
		Reversibility: verdict.Reversibility, Effect: string(verdict.Effect),
		RuleID: verdict.RuleID, Allowed: verdict.Allowed, Shadowed: shadowed,
		PolicyID: s.bundle.PolicyID,
	})

	if s.log != nil {
		body, err := json.Marshal(leaf{
			Tool: call.Tool, Action: call.Action, AgentID: call.AgentID,
			Risk: call.Risk, Reversibility: verdict.Reversibility,
			Effect: string(verdict.Effect), RuleID: verdict.RuleID,
			Allowed: verdict.Allowed, PolicyID: s.bundle.PolicyID,
		})
		if err == nil {
			idx := s.log.Append(body)
			resp.LeafIndex, resp.Leaf = &idx, string(body)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// logHead publishes the current commitment. This is the value a witness
// co-signs, and the value an auditor pins now to detect a rewrite later.
func (s *server) logHead(w http.ResponseWriter, _ *http.Request) {
	if s.log == nil {
		http.Error(w, "log is not enabled", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.log.Head())
}

// logProof answers both proof kinds. Inclusion needs index and size;
// consistency needs from and size.
func (s *server) logProof(w http.ResponseWriter, r *http.Request) {
	if s.log == nil {
		http.Error(w, "log is not enabled", http.StatusNotFound)
		return
	}
	q := r.URL.Query()
	size, err := strconv.Atoi(q.Get("size"))
	if err != nil || size < 0 {
		size = s.log.Size()
	}
	head, err := s.log.HeadAt(size)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if from := q.Get("from"); from != "" {
		m, err := strconv.Atoi(from)
		if err != nil {
			http.Error(w, "from must be an integer", http.StatusBadRequest)
			return
		}
		proof, err := s.log.ConsistencyProof(m, size)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		old, _ := s.log.HeadAt(m)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"kind": "consistency", "from": m, "size": size,
			"old_root": old.Root, "root": head.Root, "proof": proof,
		})
		return
	}

	index, err := strconv.Atoi(q.Get("index"))
	if err != nil {
		http.Error(w, "index must be an integer, or pass from= for consistency",
			http.StatusBadRequest)
		return
	}
	proof, err := s.log.InclusionProof(index, size)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"kind": "inclusion", "index": index, "size": size,
		"root": head.Root, "proof": proof,
	})
}

func (s *server) stats(w http.ResponseWriter, _ *http.Request) {
	out := s.counts.snapshot()
	out["mode"] = string(s.mode)
	out["policy_id"] = s.bundle.PolicyID
	out["journal"] = s.journal.Stats()
	if s.log != nil {
		out["log"] = s.log.Head()
	}
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
		journalPath = flag.String("journal", "",
			"append one JSON line per decision here; feeds inventory, suggest and simulate")
		journalMax = flag.Int64("journal-max-bytes", journal.DefaultMaxSize,
			"rotate the journal past this size")
		withLog = flag.Bool("log", false,
			"commit every decision to an RFC 6962 Merkle log and serve proofs")
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

	jw, err := journal.Open(*journalPath, *journalMax)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	defer func() { _ = jw.Close() }()

	var tlog *translog.Log
	if *withLog {
		tlog = translog.New()
	}

	s := &server{bundle: bundle, mode: m, counts: newCounters(), journal: jw, log: tlog}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/decide", s.decide)
	mux.HandleFunc("/v1/stats", s.stats)
	mux.HandleFunc("/v1/log/head", s.logHead)
	mux.HandleFunc("/v1/log/proof", s.logProof)
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
	if *journalPath != "" {
		log.Printf("journalling decisions to %s (tool, action, agent and verdict; "+
			"never arguments)", *journalPath)
	}
	if *withLog {
		log.Printf("Merkle log on: every decision gets a receipt; " +
			"GET /v1/log/head to pin a root, /v1/log/proof to check one")
	}
	if m == modeShadow {
		log.Printf("shadow mode: every call is allowed and the verdict recorded. " +
			"GET /v1/stats for what would have been blocked.")
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

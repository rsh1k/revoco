// Package journal records what actually happened, one line per decision.
//
// The enforcer sees every tool call every agent makes. Until now that stream
// produced a single counter, which throws away the most useful thing the
// deployment knows: what the agent estate actually does, as opposed to what
// somebody assumed it does when they wrote the policy.
//
// The journal is what turns shadow mode from a compliance exercise into a
// working tool. From it the control plane can inventory the estate, propose a
// least-privilege policy that would have allowed everything real, and simulate a
// candidate policy against real traffic before anyone turns it on.
//
// # Deliberately boring
//
// JSON Lines, appended, fsync left to the OS, rotated by size. No database, no
// index, no query language. The file is the interface: `wc -l` it, `jq` it, ship
// it to a SIEM with anything that tails a file. A sidecar in the request path is
// the wrong place to put a storage engine.
//
// # What is not written
//
// Tool arguments. They are where the payment amounts, the customer records and
// the credentials live, and the entire deployment argument for this product is
// that regulated data stays in the customer's VPC. A journal that captured
// arguments would be a second copy of exactly the data nobody wants copied.
// Tool name, action, agent, verdict and timing are enough to inventory an
// estate and simulate a policy, and they are not enough to leak one.
package journal

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Entry is one decision, in the shape the analysis tools read back.
type Entry struct {
	At            string   `json:"at"`
	Tool          string   `json:"tool"`
	Action        string   `json:"action"`
	AgentID       string   `json:"agent_id"`
	Roles         []string `json:"roles,omitempty"`
	Risk          int      `json:"risk"`
	ThreatScore   int      `json:"threat_score,omitempty"`
	Reversibility string   `json:"reversibility"`
	Effect        string   `json:"effect"`
	RuleID        string   `json:"rule_id"`
	Allowed       bool     `json:"allowed"`
	Shadowed      bool     `json:"shadowed"`
	PolicyID      string   `json:"policy_id"`
}

// Writer appends entries to a size-bounded file.
type Writer struct {
	mu      sync.Mutex
	f       *os.File
	enc     *json.Encoder
	path    string
	written int64
	maxSize int64
	dropped int64
}

// DefaultMaxSize caps a journal at 256 MiB before it rotates. A sidecar that
// filled a node's disk would take down the workload it exists to protect, which
// is a worse outcome than losing old observations.
const DefaultMaxSize int64 = 256 << 20

// Open starts or resumes a journal. An empty path disables journalling and
// returns a nil Writer, which every method tolerates.
func Open(path string, maxSize int64) (*Writer, error) {
	if path == "" {
		return nil, nil
	}
	if maxSize <= 0 {
		maxSize = DefaultMaxSize
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("cannot open journal %s: %w", path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("cannot stat journal %s: %w", path, err)
	}
	return &Writer{f: f, enc: json.NewEncoder(f), path: path,
		written: info.Size(), maxSize: maxSize}, nil
}

// Append writes one entry.
//
// A failure here is counted and swallowed rather than returned. The journal
// feeds analysis, not enforcement, and a full disk must not become a reason the
// gate stops answering. The drop count is reported so the loss is visible
// instead of silent — an analysis run over a journal that quietly lost entries
// would produce a confident least-privilege policy with holes in it.
func (w *Writer) Append(e Entry) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.written >= w.maxSize {
		if err := w.rotate(); err != nil {
			w.dropped++
			return
		}
	}
	if e.At == "" {
		e.At = time.Now().UTC().Format(time.RFC3339Nano)
	}
	before, _ := w.f.Seek(0, 1)
	if err := w.enc.Encode(e); err != nil {
		w.dropped++
		return
	}
	after, _ := w.f.Seek(0, 1)
	if after > before {
		w.written += after - before
	}
}

// rotate keeps exactly one previous generation. Deeper retention belongs to
// whatever ships these off the node, not to a process in the request path.
func (w *Writer) rotate() error {
	if err := w.f.Close(); err != nil {
		return err
	}
	if err := os.Rename(w.path, w.path+".1"); err != nil {
		return err
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	w.f, w.enc, w.written = f, json.NewEncoder(f), 0
	return nil
}

// Stats reports what the analysis side needs to know about its own input.
func (w *Writer) Stats() map[string]any {
	if w == nil {
		return map[string]any{"enabled": false}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return map[string]any{
		"enabled": true, "path": w.path,
		"bytes": w.written, "dropped": w.dropped,
	}
}

// Close flushes and releases the file.
func (w *Writer) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.f.Close()
}

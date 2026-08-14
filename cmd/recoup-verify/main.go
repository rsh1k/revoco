// Command recoup-verify checks a receipt against a log root, offline.
//
// This is the piece that makes the log evidence rather than a dashboard. It
// links against nothing but the standard library and the proof code, talks to
// no server, and needs no credentials. An auditor, an insurer or a regulator
// runs it against a receipt and a root they pinned earlier, and gets an answer
// that does not depend on the operator being cooperative or even present.
//
// Two questions, which are different:
//
//	inclusion    is this decision in the log that had this root?
//	consistency  is the log that had this old root the same log, unmodified,
//	             as the one that has this new root now?
//
// The second is the one that catches a rewrite. Pin a root today, ask for a
// consistency proof next quarter, and an operator who deleted an inconvenient
// entry in between cannot produce one.
//
//	recoup-verify inclusion --receipt r.json --root <hex>
//	recoup-verify consistency --from 1200 --size 4800 --old-root <hex> --root <hex> --proof p.json
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/rsh1k/recoup/internal/translog"
)

// receipt is what the enforcer hands back on a decision, plus the proof fetched
// later. Keeping the leaf as raw bytes matters: the verifier must hash exactly
// what was committed, not a re-serialisation of a parsed copy, because a
// different field order would produce a different hash and a false alarm.
type receipt struct {
	Leaf  string   `json:"leaf"`
	Index int      `json:"index"`
	Size  int      `json:"size"`
	Proof []string `json:"proof"`
	Root  string   `json:"root,omitempty"`
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func readJSON(path string, into any) {
	raw, err := os.ReadFile(path)
	if err != nil {
		fail("cannot read %s: %v", path, err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		fail("cannot parse %s: %v", path, err)
	}
}

func decodeRoot(s, label string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		fail("%s must be 64 hex characters", label)
	}
	return b
}

func inclusion(args []string) {
	fs := flag.NewFlagSet("inclusion", flag.ExitOnError)
	path := fs.String("receipt", "", "receipt JSON from the enforcer, with its proof")
	rootHex := fs.String("root", "", "the log root to check against (hex)")
	_ = fs.Parse(args)

	if *path == "" {
		fail("--receipt is required")
	}
	var r receipt
	readJSON(*path, &r)
	if *rootHex == "" {
		*rootHex = r.Root
	}
	if *rootHex == "" {
		fail("no --root given and the receipt carries none")
	}

	proof, err := translog.DecodeHashes(r.Proof)
	if err != nil {
		fail("bad proof: %v", err)
	}
	// Hash the leaf bytes exactly as recorded.
	leafHash := translog.HashLeaf([]byte(r.Leaf))

	if err := translog.VerifyInclusion(leafHash, r.Index, r.Size, proof,
		decodeRoot(*rootHex, "--root")); err != nil {
		fmt.Printf("NOT VERIFIED\n  %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("verified\n")
	fmt.Printf("  entry %d of %d is in the log with root %s\n", r.Index, r.Size, *rootHex)
	fmt.Printf("  %s\n", r.Leaf)
	fmt.Printf("\n  This says the entry is in that log. It does not say the log is\n")
	fmt.Printf("  complete — for that, check consistency against a root pinned earlier.\n")
}

func consistency(args []string) {
	fs := flag.NewFlagSet("consistency", flag.ExitOnError)
	path := fs.String("proof", "", "consistency proof JSON from /v1/log/proof")
	from := fs.Int("from", -1, "the earlier tree size")
	size := fs.Int("size", -1, "the later tree size")
	oldHex := fs.String("old-root", "", "the root you pinned earlier (hex)")
	newHex := fs.String("root", "", "the root now (hex)")
	_ = fs.Parse(args)

	var doc struct {
		From    int      `json:"from"`
		Size    int      `json:"size"`
		OldRoot string   `json:"old_root"`
		Root    string   `json:"root"`
		Proof   []string `json:"proof"`
	}
	if *path != "" {
		readJSON(*path, &doc)
	}
	if *from >= 0 {
		doc.From = *from
	}
	if *size >= 0 {
		doc.Size = *size
	}
	if *newHex != "" {
		doc.Root = *newHex
	}
	// The old root deliberately defaults to the *pinned* value rather than
	// whatever the server just said it was. Taking the operator's word for what
	// the log used to contain would defeat the entire check.
	if *oldHex != "" {
		doc.OldRoot = *oldHex
	}
	if doc.OldRoot == "" || doc.Root == "" {
		fail("both --old-root and --root are required")
	}

	proof, err := translog.DecodeHashes(doc.Proof)
	if err != nil {
		fail("bad proof: %v", err)
	}
	if err := translog.VerifyConsistency(doc.From, doc.Size, proof,
		decodeRoot(doc.OldRoot, "--old-root"),
		decodeRoot(doc.Root, "--root")); err != nil {
		fmt.Printf("NOT VERIFIED\n  %v\n", err)
		fmt.Printf("\n  The log at size %d is not an append-only extension of the log\n", doc.Size)
		fmt.Printf("  you recorded at size %d. Something was changed or removed.\n", doc.From)
		os.Exit(1)
	}

	fmt.Printf("verified\n")
	fmt.Printf("  the log grew from %d to %d entries by appending only\n", doc.From, doc.Size)
	fmt.Printf("  nothing recorded before entry %d was altered or removed\n", doc.From)
}

func usage() {
	fmt.Fprintf(os.Stderr, `recoup-verify — check a log receipt offline

  recoup-verify inclusion   --receipt r.json [--root <hex>]
  recoup-verify consistency --proof p.json --old-root <hex> [--root <hex>]

Needs no server and no credentials. If it says verified, it is verified.
`)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "inclusion":
		inclusion(os.Args[2:])
	case "consistency":
		consistency(os.Args[2:])
	default:
		usage()
	}
}

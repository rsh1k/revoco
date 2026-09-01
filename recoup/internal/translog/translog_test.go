package translog

import (
	"encoding/hex"
	"fmt"
	"testing"
)

// Merkle code is easy to write and hard to write correctly, and the failure mode
// is silent: a tree that splits down the middle instead of at a power of two
// produces perfectly consistent-looking roots and has no prefix property at all.
// Nothing catches that until someone tries to prove something, by which point
// the log is the evidence and the evidence is wrong.
//
// So this checks against RFC 6962's published vectors first, then exhaustively
// over every leaf and every pair of tree sizes, then negatively — a proof that
// verifies when it should not is the only outcome that actually matters.

// The reference data from RFC 6962 section 2.1.3.
var rfcInputs = []string{
	"", "00", "10", "2021", "3031", "40414243", "5051525354555657",
	"606162636465666768696a6b6c6d6e6f",
}

// Roots of the first n of those inputs, from the same section.
var rfcRoots = []string{
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // 0, the empty tree
	"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", // 1, one empty-string leaf
	"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125", // 2
	"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77", // 3
	"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7", // 4
	"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4", // 5
	"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef", // 6
	"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c", // 7
	"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328", // 8
}

func buildRFC(t *testing.T, n int) *Log {
	t.Helper()
	l := New()
	for i := 0; i < n; i++ {
		b, err := hex.DecodeString(rfcInputs[i])
		if err != nil {
			t.Fatalf("bad test input %d: %v", i, err)
		}
		l.Append(b)
	}
	return l
}

func TestMatchesRFC6962Roots(t *testing.T) {
	// The first entry of rfcRoots is the empty tree; index 1 onward are trees
	// built from the leading inputs.
	l := New()
	if got := l.Head().Root; got != rfcRoots[0] {
		t.Errorf("empty tree root = %s, want %s", got, rfcRoots[0])
	}
	for n := 1; n <= len(rfcInputs); n++ {
		lg := buildRFC(t, n)
		if got := lg.Head().Root; got != rfcRoots[n] {
			t.Errorf("tree of %d: root = %s, want %s", n, got, rfcRoots[n])
		}
	}
}

func TestEveryLeafProvesInclusion(t *testing.T) {
	// Exhaustive rather than sampled. The sizes where this breaks are the ones
	// straddling a power of two, and picking sizes by hand is how you miss them.
	for n := 1; n <= 64; n++ {
		l := New()
		for i := 0; i < n; i++ {
			l.Append([]byte(fmt.Sprintf("entry-%d", i)))
		}
		head := l.Head()
		root, _ := hex.DecodeString(head.Root)

		for i := 0; i < n; i++ {
			hexProof, err := l.InclusionProof(i, n)
			if err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			proof, err := DecodeHashes(hexProof)
			if err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			leaf := HashLeaf([]byte(fmt.Sprintf("entry-%d", i)))
			if err := VerifyInclusion(leaf, i, n, proof, root); err != nil {
				t.Fatalf("n=%d i=%d: proof did not verify: %v", n, i, err)
			}
		}
	}
}

func TestEveryPrefixProvesConsistency(t *testing.T) {
	const N = 48
	l := New()
	roots := make([][]byte, N+1)
	for n := 0; n <= N; n++ {
		h, err := l.HeadAt(n)
		if err != nil {
			t.Fatalf("head at %d: %v", n, err)
		}
		roots[n], _ = hex.DecodeString(h.Root)
		if n < N {
			l.Append([]byte(fmt.Sprintf("entry-%d", n)))
		}
	}

	for m := 0; m <= N; m++ {
		for n := m; n <= N; n++ {
			hexProof, err := l.ConsistencyProof(m, n)
			if err != nil {
				t.Fatalf("consistency %d->%d: %v", m, n, err)
			}
			proof, err := DecodeHashes(hexProof)
			if err != nil {
				t.Fatalf("consistency %d->%d: %v", m, n, err)
			}
			if err := VerifyConsistency(m, n, proof, roots[m], roots[n]); err != nil {
				t.Fatalf("consistency %d->%d did not verify: %v", m, n, err)
			}
		}
	}
}

// The tests that matter. A verifier that never says no is not a verifier.
func TestVerifierRejectsBadProofs(t *testing.T) {
	l := New()
	for i := 0; i < 17; i++ {
		l.Append([]byte(fmt.Sprintf("entry-%d", i)))
	}
	head := l.Head()
	root, _ := hex.DecodeString(head.Root)
	hexProof, _ := l.InclusionProof(5, 17)
	proof, _ := DecodeHashes(hexProof)
	leaf := HashLeaf([]byte("entry-5"))

	t.Run("tampered leaf", func(t *testing.T) {
		if err := VerifyInclusion(HashLeaf([]byte("entry-5-forged")), 5, 17, proof, root); err == nil {
			t.Fatal("a forged leaf verified against the real root")
		}
	})
	t.Run("wrong index", func(t *testing.T) {
		if err := VerifyInclusion(leaf, 6, 17, proof, root); err == nil {
			t.Fatal("a proof verified at the wrong position")
		}
	})
	t.Run("flipped byte in the path", func(t *testing.T) {
		bad := make([][]byte, len(proof))
		copy(bad, proof)
		alt := make([]byte, len(bad[0]))
		copy(alt, bad[0])
		alt[0] ^= 0xff
		bad[0] = alt
		if err := VerifyInclusion(leaf, 5, 17, bad, root); err == nil {
			t.Fatal("a corrupted path verified")
		}
	})
	t.Run("padded proof", func(t *testing.T) {
		if err := VerifyInclusion(leaf, 5, 17, append(proof, proof[0]), root); err == nil {
			t.Fatal("a proof with extra hashes verified")
		}
	})
	t.Run("truncated proof", func(t *testing.T) {
		if err := VerifyInclusion(leaf, 5, 17, proof[:len(proof)-1], root); err == nil {
			t.Fatal("a short proof verified")
		}
	})
	t.Run("wrong root", func(t *testing.T) {
		other := HashLeaf([]byte("not the root"))
		if err := VerifyInclusion(leaf, 5, 17, proof, other); err == nil {
			t.Fatal("a proof verified against an unrelated root")
		}
	})
}

// A log that rewrote its own history is the thing consistency proofs exist to
// catch, so it gets its own test rather than being assumed.
func TestConsistencyCatchesARewrittenLog(t *testing.T) {
	honest := New()
	for i := 0; i < 8; i++ {
		honest.Append([]byte(fmt.Sprintf("entry-%d", i)))
	}
	oldHead, _ := honest.HeadAt(5)
	oldRoot, _ := hex.DecodeString(oldHead.Root)

	// A second log that agrees for four entries and then changes the fifth.
	forged := New()
	for i := 0; i < 4; i++ {
		forged.Append([]byte(fmt.Sprintf("entry-%d", i)))
	}
	forged.Append([]byte("entry-4-rewritten"))
	for i := 5; i < 8; i++ {
		forged.Append([]byte(fmt.Sprintf("entry-%d", i)))
	}
	forgedHead := forged.Head()
	forgedRoot, _ := hex.DecodeString(forgedHead.Root)

	hexProof, _ := forged.ConsistencyProof(5, 8)
	proof, _ := DecodeHashes(hexProof)

	// The forged log's own proof is internally consistent; what it cannot do is
	// reconcile with the root anyone recorded before the rewrite.
	if err := VerifyConsistency(5, 8, proof, oldRoot, forgedRoot); err == nil {
		t.Fatal("a rewritten log passed consistency against the original root")
	}
}

func TestHeadAtRejectsOutOfRange(t *testing.T) {
	l := New()
	l.Append([]byte("only"))
	if _, err := l.HeadAt(2); err == nil {
		t.Fatal("a head beyond the log was returned")
	}
	if _, err := l.InclusionProof(0, 5); err == nil {
		t.Fatal("a proof in a tree larger than the log was returned")
	}
}

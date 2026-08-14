// Package translog is an RFC 6962 Merkle tree log.
//
// It replaces the hash chain that came before it, and the reason is not
// tidiness. Both structures detect tampering; they differ in what can be proved
// about a *single* entry.
//
// With a hash chain, proving that one wire transfer was authorised means handing
// over the log and letting the other party walk it. That is exactly the wrong
// shape for this product, whose entire deployment argument is that the
// confidential half stays inside the customer's VPC. With a Merkle log the same
// proof is a handful of hashes: an auditor, an insurer or a regulator can verify
// that a specific decision is in the log, and that the log has never been
// rewritten, without ever seeing the rest of it.
//
//	inclusion proof    this entry is in a tree with this root      O(log n)
//	consistency proof  this tree is a prefix of that later tree    O(log n)
//
// Consistency is the property a chain cannot offer cheaply. It proves the log
// only ever appended — that nothing was retroactively inserted or removed
// between two points in time — which is the claim an audit actually turns on.
//
// # Hashing
//
// RFC 6962 domain-separates leaves from internal nodes:
//
//	leaf(d)     = SHA-256(0x00 || d)
//	node(l, r)  = SHA-256(0x01 || l || r)
//
// The prefixes are not decoration. Without them an attacker can present an
// internal node as though it were a leaf, and a second-preimage attack on the
// tree becomes possible. This is a well-known way to get Merkle trees wrong, so
// the constants are named rather than inlined.
//
// # Deliberately not a blockchain
//
// A Merkle log leaves one gap: a malicious operator can maintain two divergent
// logs and show a different one to each party. Blockchain closes it through
// consensus, at a cost the literature is blunt about. The cheap answer is
// witness co-signing — independent parties counter-sign tree heads, and any
// operator equivocating has to get every witness to lie in the same direction.
// `Head` is shaped to be signed for exactly that, and the signing itself belongs
// to the control plane rather than the request path.
package translog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

const (
	leafPrefix = 0x00
	nodePrefix = 0x01
)

// HashLeaf hashes one entry into a leaf.
func HashLeaf(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(data)
	return h.Sum(nil)
}

// HashNode hashes two children into their parent.
func HashNode(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{nodePrefix})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// Head is a signed-shaped commitment to the whole log at a point in time.
type Head struct {
	Size int    `json:"size"`
	Root string `json:"root"`
}

// Log is an append-only Merkle tree.
//
// Leaves are kept and interior nodes recomputed on demand. That is O(n) per
// root rather than O(log n), and it is the right trade at the sizes this runs
// at: an incrementally-maintained tree is materially harder to get right, and a
// subtly wrong log is worse than a slow one. The structure is behind an
// interface so it can be swapped for a tiled implementation when a deployment
// makes that the bottleneck rather than a guess.
type Log struct {
	mu     sync.RWMutex
	leaves [][]byte
}

// New returns an empty log.
func New() *Log { return &Log{} }

// Append adds an entry and returns its index.
func (l *Log) Append(data []byte) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.leaves = append(l.leaves, HashLeaf(data))
	return len(l.leaves) - 1
}

// Size is the number of entries.
func (l *Log) Size() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.leaves)
}

// root computes the Merkle tree hash of the first n leaves.
//
// RFC 6962 splits at the largest power of two strictly below n, which is what
// makes a tree of size n a genuine prefix of every larger tree. Splitting down
// the middle instead would produce a valid-looking tree with no consistency
// property at all — the bug worth guarding, because it only shows up when
// someone tries to prove something.
func (l *Log) root(hashes [][]byte) []byte {
	n := len(hashes)
	if n == 0 {
		// The empty tree is SHA-256 of nothing, per RFC 6962.
		h := sha256.Sum256(nil)
		return h[:]
	}
	if n == 1 {
		return hashes[0]
	}
	k := largestPowerOfTwoBelow(n)
	return HashNode(l.root(hashes[:k]), l.root(hashes[k:]))
}

// largestPowerOfTwoBelow returns the largest power of two strictly less than n,
// for n > 1.
func largestPowerOfTwoBelow(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// Head returns the current size and root.
func (l *Log) Head() Head {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return Head{Size: len(l.leaves), Root: hex.EncodeToString(l.root(l.leaves))}
}

// HeadAt returns the head the log had at size n, which is what makes an old
// receipt still checkable after the log has grown.
func (l *Log) HeadAt(n int) (Head, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if n < 0 || n > len(l.leaves) {
		return Head{}, fmt.Errorf("size %d is outside a log of %d", n, len(l.leaves))
	}
	return Head{Size: n, Root: hex.EncodeToString(l.root(l.leaves[:n]))}, nil
}

// InclusionProof returns the audit path for leaf index in a tree of size n.
func (l *Log) InclusionProof(index, n int) ([]string, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if n < 0 || n > len(l.leaves) {
		return nil, fmt.Errorf("size %d is outside a log of %d", n, len(l.leaves))
	}
	if index < 0 || index >= n {
		return nil, fmt.Errorf("index %d is outside a tree of %d", index, n)
	}
	return toHex(l.inclusion(l.leaves[:n], index)), nil
}

func (l *Log) inclusion(hashes [][]byte, index int) [][]byte {
	n := len(hashes)
	if n <= 1 {
		return nil
	}
	k := largestPowerOfTwoBelow(n)
	if index < k {
		return append(l.inclusion(hashes[:k], index), l.root(hashes[k:]))
	}
	return append(l.inclusion(hashes[k:], index-k), l.root(hashes[:k]))
}

// VerifyInclusion checks a proof without any access to the log.
//
// This is the whole point of the package: it takes only the leaf, its position,
// the tree size and the root, so an auditor can run it against a receipt without
// the operator's cooperation and without seeing anything else in the log.
func VerifyInclusion(leafHash []byte, index, size int, proof [][]byte, root []byte) error {
	if index < 0 || size < 0 || index >= size {
		return fmt.Errorf("index %d outside a tree of %d", index, size)
	}
	// RFC 6962 section 2.1.1, and it has to be this algorithm rather than a
	// mirror of the generator. The audit path is ordered leaf-to-root, so a
	// verifier that walks the tree top-down consumes it backwards: it happens to
	// agree for balanced trees and diverges the moment a subtree is ragged,
	// which is every tree whose size is not a power of two. That produced a
	// verifier passing at n=2 and failing at n=3.
	computed := leafHash
	fn, sn := index, size-1
	used := 0
	for _, p := range proof {
		if sn == 0 {
			return errors.New("proof is longer than the tree is deep")
		}
		if fn%2 == 1 || fn == sn {
			computed = HashNode(p, computed)
			if fn%2 == 0 {
				for fn != 0 && fn%2 == 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			computed = HashNode(computed, p)
		}
		fn >>= 1
		sn >>= 1
		used++
	}
	if sn != 0 {
		return errors.New("proof is too short for a tree of this size")
	}
	if used != len(proof) {
		// A proof with unused hashes is malformed. Accepting it would let an
		// attacker pad a valid proof, and a verifier that tolerates junk is one
		// that has stopped checking the shape of what it is given.
		return fmt.Errorf("proof has %d unused hash(es)", len(proof)-used)
	}
	if !bytes.Equal(computed, root) {
		return fmt.Errorf("root mismatch: computed %s, expected %s",
			hex.EncodeToString(computed), hex.EncodeToString(root))
	}
	return nil
}

// ConsistencyProof proves a tree of size m is a prefix of one of size n.
func (l *Log) ConsistencyProof(m, n int) ([]string, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if m < 0 || n > len(l.leaves) || m > n {
		return nil, fmt.Errorf("cannot prove %d is a prefix of %d in a log of %d",
			m, n, len(l.leaves))
	}
	if m == 0 || m == n {
		return []string{}, nil
	}
	return toHex(l.consistency(l.leaves[:n], m, true)), nil
}

func (l *Log) consistency(hashes [][]byte, m int, isRoot bool) [][]byte {
	n := len(hashes)
	if m == n {
		if isRoot {
			return nil
		}
		return [][]byte{l.root(hashes)}
	}
	k := largestPowerOfTwoBelow(n)
	if m <= k {
		// `b` carries through here. Forcing it false was the bug: it made the
		// generator emit the old root as a proof hash even when the old tree was
		// an exact subtree, so the verifier — which seeds from the old root in
		// that case — was handed one hash too many.
		return append(l.consistency(hashes[:k], m, isRoot), l.root(hashes[k:]))
	}
	return append(l.consistency(hashes[k:], m-k, false), l.root(hashes[:k]))
}

// VerifyConsistency checks that oldRoot at size m is a prefix of newRoot at n.
//
// This mirrors the generator's SUBPROOF decomposition rather than RFC 6962's
// index-arithmetic formulation. The bit-twiddling version was written first and
// was wrong on ragged trees — it verified every balanced case and failed at
// m=2, n=3 — which is the worst shape of bug to have here, because the sizes
// where it breaks are the ordinary ones and the sizes where it passes are the
// ones a hand-picked test would use.
//
// Walking the same recursion the proof was built from makes the correspondence
// checkable by reading, and the exhaustive test over every (m, n) pair covers
// the arithmetic the recursion replaces.
func VerifyConsistency(m, n int, proof [][]byte, oldRoot, newRoot []byte) error {
	if m < 0 || n < m {
		return fmt.Errorf("cannot verify %d as a prefix of %d", m, n)
	}
	if m == n {
		if len(proof) != 0 {
			return errors.New("a tree is a prefix of itself with an empty proof")
		}
		if !bytes.Equal(oldRoot, newRoot) {
			return errors.New("same size but different roots")
		}
		return nil
	}
	if m == 0 {
		// Every tree extends the empty one, and there is nothing to prove.
		return nil
	}

	gotOld, gotNew, rest, err := consumeConsistency(m, n, true, proof, oldRoot)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("proof has %d unused hash(es)", len(rest))
	}
	if !bytes.Equal(gotOld, oldRoot) {
		return errors.New("the old root does not follow from the proof; " +
			"the log may have rewritten history")
	}
	if !bytes.Equal(gotNew, newRoot) {
		return errors.New("the new root does not follow from the proof")
	}
	return nil
}

// consumeConsistency walks SUBPROOF(m, D[n], isRoot), returning the old and new
// subtree roots it implies and whatever proof hashes are left over.
func consumeConsistency(m, n int, isRoot bool, proof [][]byte, oldRoot []byte) (
	old, updated []byte, rest [][]byte, err error) {

	if m == n {
		if isRoot {
			// The old tree is the whole of this subtree and its root was not
			// carried in the proof, because the verifier already has it.
			return oldRoot, oldRoot, proof, nil
		}
		if len(proof) == 0 {
			return nil, nil, nil, errors.New("proof is too short")
		}
		return proof[0], proof[0], proof[1:], nil
	}

	k := largestPowerOfTwoBelow(n)
	if m <= k {
		// The old tree lives entirely in the left subtree; the right subtree is
		// new, and its root is the next hash.
		o, u, rest, err := consumeConsistency(m, k, isRoot, proof, oldRoot)
		if err != nil {
			return nil, nil, nil, err
		}
		if len(rest) == 0 {
			return nil, nil, nil, errors.New("proof is too short")
		}
		return o, HashNode(u, rest[0]), rest[1:], nil
	}

	// The left subtree is common to both trees, so it appears once and is
	// combined on the left of each.
	o, u, rest, err := consumeConsistency(m-k, n-k, false, proof, oldRoot)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(rest) == 0 {
		return nil, nil, nil, errors.New("proof is too short")
	}
	left := rest[0]
	return HashNode(left, o), HashNode(left, u), rest[1:], nil
}

func isPowerOfTwo(n int) bool { return n > 0 && n&(n-1) == 0 }

func toHex(hs [][]byte) []string {
	out := make([]string, len(hs))
	for i, h := range hs {
		out[i] = hex.EncodeToString(h)
	}
	return out
}

// DecodeHashes turns hex proof hashes back into bytes.
func DecodeHashes(in []string) ([][]byte, error) {
	out := make([][]byte, len(in))
	for i, s := range in {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("proof hash %d is not hex: %w", i, err)
		}
		if len(b) != sha256.Size {
			return nil, fmt.Errorf("proof hash %d is %d bytes, want %d",
				i, len(b), sha256.Size)
		}
		out[i] = b
	}
	return out, nil
}

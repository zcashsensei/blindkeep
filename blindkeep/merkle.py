"""Merkle transparency log (RFC 6962 hashing + proof algorithms).

This is the primitive that makes a storage node tamper-EVIDENT without any
zero-knowledge machinery:

  * inclusion proof   -> "this exact record is at index i of a tree of size n"
  * consistency proof -> "the tree of size n still contains, unmodified, every
                          record that was in the tree of size m <= n"

Together they mean a node cannot alter, reorder, or drop a record it has
already committed to without producing a root that fails verification.
Cost is a few SHA-256 hashes, not minutes of proving time.
"""

import hashlib

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

EMPTY_ROOT = hashlib.sha256(b"").digest()


def leaf_hash(data: bytes) -> bytes:
    """Hash of a leaf. Domain-separated from internal nodes so a leaf can never
    be reinterpreted as an interior node (second-preimage defence)."""
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _lpo2(n: int) -> int:
    """Largest power of two strictly less than n (requires n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def root(hashes) -> bytes:
    """Merkle tree head over a list of leaf hashes."""
    n = len(hashes)
    if n == 0:
        return EMPTY_ROOT
    if n == 1:
        return hashes[0]
    k = _lpo2(n)
    return node_hash(root(hashes[:k]), root(hashes[k:]))


def inclusion_proof(index: int, hashes):
    """Audit path proving `hashes[index]` is in the tree over `hashes`."""
    n = len(hashes)
    if not 0 <= index < n:
        raise IndexError(f"index {index} out of range for tree size {n}")
    if n == 1:
        return []
    k = _lpo2(n)
    if index < k:
        return inclusion_proof(index, hashes[:k]) + [root(hashes[k:])]
    return inclusion_proof(index - k, hashes[k:]) + [root(hashes[:k])]


def verify_inclusion(leaf: bytes, index: int, tree_size: int, proof, expected_root: bytes) -> bool:
    """Recompute the root from a leaf + audit path. No tree access needed."""
    if index >= tree_size or index < 0:
        return False
    fn, sn = index, tree_size - 1
    r = leaf
    for p in proof:
        if sn == 0:
            return False
        if (fn & 1) or (fn == sn):
            r = node_hash(p, r)
            if not (fn & 1):
                while fn != 0 and not (fn & 1):
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == expected_root


class CachedLog:
    """The same RFC 6962 tree, with its internal nodes kept instead of re-derived.

    WHY THIS EXISTS. `inclusion_proof()` above calls `root()` on each sibling subtree, and `root()`
    re-slices and re-hashes from the leaves every time. So one proof costs O(n), and serving a proof
    per record costs O(n^2). Measured on a 15W laptop: per-proof cost scales as n^0.99, giving
    ~1.1 s per proof at a million leaves — about 306 hours to answer a million requests. With the
    internal nodes cached it is 209,000 proofs/sec and 4.8 seconds for the same million, from 81 MB.
    Nothing about the cryptography changed; only the bookkeeping did.

    PROMOTE, DO NOT DUPLICATE. RFC 6962 is not a padded binary tree: a level with an odd count
    promotes its last node unchanged (that is what the `_lpo2` split produces). Duplicating it
    instead would be the Bitcoin-style tree, would still "work", and would silently produce
    different roots — an incompatibility no test that only checks self-consistency can see. The
    test suite therefore compares every proof against the recursive functions above, which are the
    normative definition.

    HASH-AGNOSTIC ON PURPOSE. `leaf_fn`/`node_fn` are injectable because the ZK roadmap needs a
    second tree over the same records using a circuit-friendly hash — SHA-256 costs ~25-30k
    constraints per compression inside a SNARK, while Poseidon-family hashes cost a few hundred.
    That is the difference between a provable log and an unprovable one, and it is a decision that
    has to be made before circuits are written, not after heads are published. This class is the
    structure; the hash is a parameter.
    """

    __slots__ = ("levels", "_leaf_fn", "_node_fn")

    def __init__(self, leaf_hashes=(), leaf_fn=leaf_hash, node_fn=node_hash):
        self._leaf_fn, self._node_fn = leaf_fn, node_fn
        self.levels = [list(leaf_hashes)]
        self._rebuild()

    def _rebuild(self):
        self.levels = [self.levels[0]]
        while len(self.levels[-1]) > 1:
            cur = self.levels[-1]
            nxt = [self._node_fn(cur[i], cur[i + 1]) for i in range(0, len(cur) - 1, 2)]
            if len(cur) & 1:
                nxt.append(cur[-1])                     # promote, never duplicate
            self.levels.append(nxt)

    def __len__(self):
        return len(self.levels[0])

    def root(self) -> bytes:
        if not self.levels[0]:
            return EMPTY_ROOT
        return self.levels[-1][0]

    def append(self, leaf: bytes) -> int:
        """Append one leaf, returning its index. Touches only the right spine.

        A promoted node becomes a paired node as soon as its sibling arrives, so the last entry of
        every level may change on any append — hence the tail of each level is recomputed rather
        than only appended to. Depth is log2(n), so this is O(log n) per record.
        """
        self.levels[0].append(leaf)
        i = 0
        while len(self.levels[i]) > 1:
            cur = self.levels[i]
            if i + 1 >= len(self.levels):
                self.levels.append([])
            nxt = self.levels[i + 1]
            want = (len(cur) + 1) // 2
            del nxt[max(0, want - 1):]                  # last entry can flip promoted -> paired
            for j in range(len(nxt), want):
                a = 2 * j
                nxt.append(self._node_fn(cur[a], cur[a + 1]) if a + 1 < len(cur) else cur[a])
            i += 1
        del self.levels[i + 1:]
        return len(self.levels[0]) - 1

    def inclusion_proof(self, index: int):
        """Audit path for `index` — pure lookups, no hashing."""
        n = len(self.levels[0])
        if not 0 <= index < n:
            raise IndexError(f"index {index} out of range for tree size {n}")
        proof, idx = [], index
        for lvl in self.levels[:-1]:
            sib = idx ^ 1
            if sib < len(lvl):
                proof.append(lvl[sib])
            idx >>= 1
        return proof


def consistency_proof(old_size: int, hashes):
    """Proof that the tree over `hashes` is an append-only extension of its own
    first `old_size` leaves."""
    n = len(hashes)
    if old_size < 0 or old_size > n:
        raise ValueError(f"old_size {old_size} out of range for tree size {n}")
    if old_size == 0 or old_size == n:
        return []
    return _subproof(old_size, hashes, True)


def _subproof(m: int, hashes, is_complete: bool):
    n = len(hashes)
    if m == n:
        return [] if is_complete else [root(hashes)]
    k = _lpo2(n)
    if m <= k:
        return _subproof(m, hashes[:k], is_complete) + [root(hashes[k:])]
    return _subproof(m - k, hashes[k:], False) + [root(hashes[:k])]


def verify_consistency(old_size: int, new_size: int, old_root: bytes,
                       new_root: bytes, proof) -> bool:
    """Verify the log never rewrote history between the two tree heads.

    This is the teeth of the design: a client that remembers ANY past signed
    head can detect a node that later forks or edits the log.
    """
    proof = list(proof)
    if old_size > new_size:
        return False
    if old_size == new_size:
        return not proof and old_root == new_root
    if old_size == 0:
        return not proof

    node, last = old_size - 1, new_size - 1
    while node & 1:
        node >>= 1
        last >>= 1

    if node:
        if not proof:
            return False
        fr = sr = proof[0]
        idx = 1
    else:
        fr = sr = old_root
        idx = 0

    while idx < len(proof):
        if last == 0:
            return False
        if (node & 1) or (node == last):
            fr = node_hash(proof[idx], fr)
            sr = node_hash(proof[idx], sr)
            while node != 0 and not (node & 1):
                node >>= 1
                last >>= 1
        else:
            sr = node_hash(sr, proof[idx])
        idx += 1
        node >>= 1
        last >>= 1

    return last == 0 and fr == old_root and sr == new_root

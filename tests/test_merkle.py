"""Exhaustive proof-algorithm tests.

Every (index, size) inclusion pair and every (old, new) consistency pair up to
MAX_N is checked against a directly-constructed tree, plus negative cases.
If these pass, the log's tamper-evidence claim is not a guess.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oblivio import merkle

MAX_N = 33


def leaves(n):
    return [merkle.leaf_hash(b"record-%d" % i) for i in range(n)]


def test_empty_and_single():
    assert merkle.root([]) == merkle.EMPTY_ROOT
    h = merkle.leaf_hash(b"only")
    assert merkle.root([h]) == h


def test_leaf_and_node_domain_separation():
    # A leaf hash must never collide with an interior node hash over the
    # same bytes -- otherwise a leaf could be passed off as a subtree.
    assert merkle.leaf_hash(b"") != merkle.node_hash(b"", b"")


def test_inclusion_all_pairs():
    for n in range(1, MAX_N):
        hs = leaves(n)
        r = merkle.root(hs)
        for i in range(n):
            proof = merkle.inclusion_proof(i, hs)
            assert merkle.verify_inclusion(hs[i], i, n, proof, r), f"inclusion failed n={n} i={i}"


def test_inclusion_rejects_wrong_leaf():
    n = 17
    hs = leaves(n)
    r = merkle.root(hs)
    forged = merkle.leaf_hash(b"forged")
    for i in range(n):
        proof = merkle.inclusion_proof(i, hs)
        assert not merkle.verify_inclusion(forged, i, n, proof, r)


def test_inclusion_rejects_wrong_index():
    n = 17
    hs = leaves(n)
    r = merkle.root(hs)
    for i in range(n):
        proof = merkle.inclusion_proof(i, hs)
        for j in range(n):
            if j == i:
                continue
            assert not merkle.verify_inclusion(hs[i], j, n, proof, r)


def test_inclusion_rejects_mutated_path():
    n = 20
    hs = leaves(n)
    r = merkle.root(hs)
    for i in range(n):
        proof = merkle.inclusion_proof(i, hs)
        for k in range(len(proof)):
            bad = list(proof)
            bad[k] = merkle.leaf_hash(b"tamper")
            assert not merkle.verify_inclusion(hs[i], i, n, bad, r)


def test_consistency_all_pairs():
    for n in range(0, MAX_N):
        hs = leaves(n)
        rn = merkle.root(hs)
        for m in range(0, n + 1):
            rm = merkle.root(hs[:m])
            proof = merkle.consistency_proof(m, hs)
            assert merkle.verify_consistency(m, n, rm, rn, proof), \
                f"consistency failed m={m} n={n}"


def test_consistency_detects_rewritten_history():
    """The attack the log exists to stop: node edits an old record and
    re-publishes a new head. Consistency against the OLD head must fail."""
    n = 24
    hs = leaves(n)
    for m in range(1, n):
        old_root = merkle.root(hs[:m])
        for victim in range(m):
            rewritten = list(hs)
            rewritten[victim] = merkle.leaf_hash(b"rewritten")
            new_root = merkle.root(rewritten)
            proof = merkle.consistency_proof(m, rewritten)
            assert not merkle.verify_consistency(m, n, old_root, new_root, proof), \
                f"rewrite of leaf {victim} went undetected at m={m}"


def test_consistency_detects_truncation():
    """Node drops the tail and pretends the log is shorter."""
    n = 20
    hs = leaves(n)
    old_root = merkle.root(hs)
    for shorter in range(1, n):
        short_root = merkle.root(hs[:shorter])
        # claiming a smaller tree is consistent with a larger one is invalid
        assert not merkle.verify_consistency(n, shorter, old_root, short_root, [])


def test_consistency_rejects_mutated_proof():
    n = 21
    hs = leaves(n)
    rn = merkle.root(hs)
    for m in range(1, n):
        rm = merkle.root(hs[:m])
        proof = merkle.consistency_proof(m, hs)
        for k in range(len(proof)):
            bad = list(proof)
            bad[k] = merkle.leaf_hash(b"tamper")
            assert not merkle.verify_consistency(m, n, rm, rn, bad)


def test_cached_log_matches_recursive_definition():
    """CachedLog is an optimisation, so it must be INDISTINGUISHABLE from the recursive
    functions above — which are the normative RFC 6962 definition.

    Checked incrementally: the tree is grown one append at a time and compared at EVERY size,
    because the failure mode that matters is a promoted node not being re-paired when its sibling
    arrives. A batch-only test would never see it. The other silent failure is duplicating an odd
    node instead of promoting it — that yields a self-consistent tree with different roots, i.e.
    an incompatible log that still passes its own verifier.
    """
    log = merkle.CachedLog()
    hs = []
    for n in range(1, 129):
        lf = merkle.leaf_hash(b"record-%d" % (n - 1))
        hs.append(lf)
        assert log.append(lf) == n - 1
        assert log.root() == merkle.root(hs), f"incremental root differs at n={n}"
        assert merkle.CachedLog(hs).root() == merkle.root(hs), f"batch root differs at n={n}"
        assert len(log) == n
        for i in range(n):
            proof = log.inclusion_proof(i)
            assert proof == merkle.inclusion_proof(i, hs), f"proof differs n={n} i={i}"
            assert merkle.verify_inclusion(hs[i], i, n, proof, log.root())


def test_cached_log_edges_and_tamper():
    assert merkle.CachedLog().root() == merkle.EMPTY_ROOT
    assert len(merkle.CachedLog()) == 0
    try:
        merkle.CachedLog(leaves(1)).inclusion_proof(3)
        raise AssertionError("out-of-range index must raise IndexError")
    except IndexError:
        pass
    n = 50
    hs = leaves(n)
    log = merkle.CachedLog(hs)
    forged = merkle.leaf_hash(b"TAMPERED")
    assert not merkle.verify_inclusion(forged, 7, n, log.inclusion_proof(7), log.root())


def test_cached_log_hash_is_injectable():
    """The ZK roadmap needs the same structure over a circuit-friendly hash, so the hash must be
    a parameter rather than a hard-coded call. Same shape, different root."""
    hs = leaves(9)
    std = merkle.CachedLog(hs)
    alt = merkle.CachedLog(
        hs, node_fn=lambda l, r: merkle.hashlib.sha256(b"\x02" + l + r).digest())
    assert alt.root() != std.root()
    assert [len(x) for x in alt.levels] == [len(x) for x in std.levels]


def run():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)} merkle tests passed (sizes 0..{MAX_N - 1}, all pairs)")


if __name__ == "__main__":
    run()

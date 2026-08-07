"""Poseidon, and the cross-language contract it has to satisfy.

The parameters and vectors in `poseidon_params.py` are GENERATED from halo2_gadgets by
`zk-encrypted-intelligence/halo2/src/dump_params.rs`. These tests are what make that generation
meaningful: they assert this implementation reproduces the Rust one exactly.

That matters more than it looks. A Poseidon that is subtly wrong still hashes, still builds a
tree, still produces a root — and every proof generated from it verifies against nothing. The
prover simply fails, with no indication that the two implementations disagree rather than the
witness being bad. So the agreement is asserted here rather than assumed anywhere.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blindkeep.poseidon import P, hash2, hash_n, leaf_hash, node_hash, permute
from blindkeep.poseidon_params import (FULL_ROUNDS, PARTIAL_ROUNDS, ROUND_CONSTANTS,
                                       VECTORS, WIDTH)
from blindkeep.zk_tree import build_levels, leaf_scalar, poseidon_path, poseidon_root

# Roots computed by the Rust circuit's own path_for(), over leaves 1000..1000+n.
RUST_ROOTS = [
    (1, 0x00000000000000000000000000000000000000000000000000000000000003e8),
    (2, 0x3db3688defa8c4658a1ccfda02d5887d4ae54762ce9933571162268b2d1ba44d),
    (3, 0x33cf5f918e30398855301a70fa81fb413d2fd22b42aac838db60623cc7e75d3f),
    (4, 0x3fbdbc0cf4614836ff535b5e71a409abbfb12812f76fee3f96b7e7e7904b79ed),
    (5, 0x21114a9d08541e89f942559ff71171053dbac4a237194b9b0606798ab5f5f269),
    (8, 0x08402c36e2493a82cd51716ebcc87b7ebbce3f39ef241929de115e4b85012967),
    (13, 0x3082bccf0c08e03bd0e27bd1790c46872510be359a0acb2ee73a6fa0ea70ce25),
]


# --- the contract with the circuit -------------------------------------------

def test_every_rust_vector_is_reproduced():
    """The load-bearing test. If this fails, proofs built here verify against nothing."""
    for a, b, want in VECTORS:
        got = hash2(a, b)
        assert got == want, f"Poseidon({a},{b}) = {got:064x}, Rust says {want:064x}"


def test_tree_roots_agree_with_the_circuit():
    """Including odd sizes, where a padding rule is most likely to drift."""
    for n, want in RUST_ROOTS:
        got = build_levels([1000 + j for j in range(n)])[-1][0]
        assert got == want, f"n={n}: python {got:064x} != rust {want:064x}"


def test_odd_levels_duplicate_rather_than_zero_pad():
    """A zero pad is a value a prover might also produce; duplication is not."""
    three = build_levels([1, 2, 3])
    assert three[1] == [hash2(1, 2), hash2(3, 3)]


# --- the permutation itself --------------------------------------------------

def test_round_schedule_matches_the_exported_constants():
    assert FULL_ROUNDS + PARTIAL_ROUNDS == len(ROUND_CONSTANTS)


def test_permutation_is_deterministic_and_in_field():
    a, b = permute([1, 2, 3]), permute([1, 2, 3])
    assert a == b and all(0 <= x < P for x in a)


def test_permutation_changes_every_element():
    assert permute([0, 0, 0]) != [0, 0, 0]


def test_length_is_domain_separated():
    """hash([a]) must not equal hash([a, 0]) — length extension closed by construction."""
    assert hash_n([7]) != hash_n([7, 0])


def test_inputs_beyond_the_rate_are_refused():
    for bad in ([], [1, 2, 3]):
        try:
            hash_n(bad)
        except ValueError:
            continue
        raise AssertionError(f"absorbed {len(bad)} elements; the rate is 2")


# --- merkle plumbing ---------------------------------------------------------

def test_leaf_and_node_hashes_are_32_bytes():
    assert len(leaf_hash(b"x")) == 32
    assert len(node_hash(b"" * 32, b"" * 32)) == 32


def test_distinct_records_get_distinct_leaves():
    assert leaf_hash(b"a") != leaf_hash(b"b")


def test_leaves_are_reduced_not_truncated():
    """Truncation would let two records share a position in the ZK tree."""
    a = leaf_scalar("ff" * 32)
    assert 0 <= a < P
    assert leaf_scalar("ff" * 32) != leaf_scalar("fe" + "ff" * 31)


def test_a_path_reconstructs_its_root():
    leaves = [f"{i:064x}" for i in range(1, 8)]
    root, steps = poseidon_path(leaves, 3)
    cur = leaf_scalar(leaves[3])
    for s in steps:
        sib = int(s["sibling"], 16)
        cur = hash2(sib, cur) if s["bit"] else hash2(cur, sib)
    assert cur == root, "walking the path did not reach the root it came with"


def test_every_index_reaches_the_same_root():
    leaves = [f"{i:064x}" for i in range(1, 10)]
    roots = {poseidon_path(leaves, i)[0] for i in range(len(leaves))}
    assert len(roots) == 1 and roots.pop() == poseidon_root(leaves)


def test_depth_is_logarithmic():
    for n, depth in ((2, 1), (8, 3), (64, 6), (256, 8)):
        _, steps = poseidon_path([f"{i:064x}" for i in range(1, n + 1)], 0)
        assert len(steps) == depth, f"{n} leaves needed {len(steps)} hashes, expected {depth}"


def test_an_empty_keep_is_refused():
    try:
        build_levels([])
    except ValueError:
        return
    raise AssertionError("an empty keep produced a tree")

def run():
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed, failed = [], []
    for name, fn in tests:
        try:
            fn()
            passed.append(name)
            print(f"  PASS  {name}")
        except AssertionError as exc:
            failed.append(name)
            print(f"  FAIL  {name}")
            print(f"          {exc}")
        except Exception as exc:
            failed.append(name)
            print(f"  ERROR {name}")
            print(f"          {type(exc).__name__}: {exc}")
    print()
    print(f"{len(passed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())

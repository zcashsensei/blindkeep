"""Poseidon over the Pallas base field — the hash a ZK circuit can afford.

SHA-256 is the right hash for a public transparency log and close to the worst case inside a
proof: a Merkle path costs on the order of 826,000 constraints with SHA-256 and a few thousand
with Poseidon. That is not an optimisation. It is the difference between a membership proof that
can be generated and one that cannot, which is why `merkle.CachedLog` takes `leaf_fn`/`node_fn`
and why the choice had to be made before any head was published.

**This must agree with the circuit exactly.** A root computed with different constants, a
different padding rule, or a different domain tag produces proofs that never verify, and nothing
announces the mismatch — the prover simply fails, or worse, a verifier accepts a proof about a
tree nobody built. So the parameters are *generated* from `halo2_gadgets` rather than transcribed
(`poseidon_params.py`), and `tests/test_poseidon.py` checks this implementation against
known-answer vectors produced by the Rust code. Those vectors are the contract between the two
languages; if they ever disagree, this file is wrong and not the circuit.

Domain separation follows halo2's `ConstantLength<L>`: the sponge starts with capacity element
`L · 2^64`, so a two-input hash cannot be confused with a three-input one that happens to end in
a zero.
"""

from __future__ import annotations

from typing import Sequence

from .poseidon_params import (ALPHA, FULL_ROUNDS, MDS, P, PARTIAL_ROUNDS, RATE,
                              ROUND_CONSTANTS, WIDTH)


def _sbox(x: int) -> int:
    return pow(x, ALPHA, P)


def _mds(state: Sequence[int]) -> list[int]:
    return [sum(MDS[i][j] * state[j] for j in range(WIDTH)) % P for i in range(WIDTH)]


def permute(state: Sequence[int]) -> list[int]:
    """The Poseidon permutation: half the full rounds, all the partial, then the rest.

    Partial rounds apply the S-box to one element only. That is what makes Poseidon affordable —
    the S-box is the expensive part in a circuit — and it is also the detail most easily got
    wrong, because a partial round still adds round constants to *every* element.
    """
    st = [x % P for x in state]
    half = FULL_ROUNDS // 2
    r = 0

    for _ in range(half):
        st = [_sbox((st[i] + ROUND_CONSTANTS[r][i]) % P) for i in range(WIDTH)]
        st = _mds(st)
        r += 1

    for _ in range(PARTIAL_ROUNDS):
        st = [(st[i] + ROUND_CONSTANTS[r][i]) % P for i in range(WIDTH)]
        st[0] = _sbox(st[0])
        st = _mds(st)
        r += 1

    for _ in range(half):
        st = [_sbox((st[i] + ROUND_CONSTANTS[r][i]) % P) for i in range(WIDTH)]
        st = _mds(st)
        r += 1

    assert r == len(ROUND_CONSTANTS), (
        f"used {r} round-constant rows of {len(ROUND_CONSTANTS)}; the round schedule and the "
        f"exported constants disagree")
    return st


def hash_n(inputs: Sequence[int]) -> int:
    """Hash a fixed-length input, halo2 `ConstantLength` style.

    The capacity element encodes the input length, so `hash([a, b])` and `hash([a, b, 0])` are
    different — length extension is closed by construction rather than by convention.
    """
    if not 0 < len(inputs) <= RATE:
        raise ValueError(f"this sponge absorbs 1..{RATE} elements, got {len(inputs)}")
    state = [0] * WIDTH
    state[RATE] = (len(inputs) << 64) % P
    for i, x in enumerate(inputs):
        state[i] = (state[i] + (x % P)) % P
    return permute(state)[0]


def hash2(a: int, b: int) -> int:
    """The two-to-one compression the Merkle tree is built from."""
    return hash_n([a, b])


# ---- Merkle plumbing, matching the circuit's tree exactly --------------------


def leaf_hash(data: bytes) -> bytes:
    """Poseidon leaf. Returns 32 big-endian bytes so it drops into `merkle.CachedLog`.

    The record is reduced into the field rather than truncated: truncation would let two distinct
    records share a leaf, which is a collision the log's whole purpose is to prevent.
    """
    return (hash_n([int.from_bytes(data, "big") % P]) % P).to_bytes(32, "big")


def node_hash(left: bytes, right: bytes) -> bytes:
    """Poseidon interior node, in the same encoding."""
    return hash2(int.from_bytes(left, "big"), int.from_bytes(right, "big")).to_bytes(32, "big")

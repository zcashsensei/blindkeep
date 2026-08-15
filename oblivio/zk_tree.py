"""A second, Poseidon-hashed tree over the same records — the one a circuit can prove.

The keep's log is RFC 6962 over SHA-256, which is correct for a public transparency log and
close to unusable inside a proof. This builds a parallel tree over exactly the same committed
leaves using Poseidon, so a membership proof costs `log2(n)` cheap hashes instead of an OR-proof
across every record.

**No node change, and no second thing to trust.** The Poseidon root is a deterministic function
of the leaf set the node already publishes and already signs over via the SHA-256 head. A
verifier fetches the leaves, checks the signed head as they always would, rebuilds this tree
themselves, and verifies the proof against the root they computed. Nothing here asks the node to
publish or sign anything new, which is why it needed no format change and no migration.

    signed SHA-256 head   anchors WHICH leaves exist
    this tree             makes a statement about them provable in a circuit

**Both trees, or neither is worth anything.** The Poseidon root alone proves membership in a set
the prover could have chosen. It is only meaningful composed with the signed head, and
`export_for_circuit` therefore carries the head alongside the path so the two cannot be separated
by accident.

The padding rule — duplicate the final leaf on an odd level rather than padding with zero —
matches `halo2/src/merkle.rs::path_for` exactly. A zero pad is a value a prover might also be
able to produce, and then two different trees share a root.
"""

from __future__ import annotations

import json
from typing import Any, Optional, Sequence

from .poseidon import P, hash2


def leaf_scalar(leaf_hex: str) -> int:
    """A committed SHA-256 leaf, reduced into the field the circuit works over.

    Reduced, never truncated: cutting bits would let two distinct records share a position in the
    ZK tree while remaining distinct in the log, which is precisely the collision the log exists
    to make impossible.
    """
    return int(leaf_hex, 16) % P


def build_levels(leaves: Sequence[int]) -> list[list[int]]:
    """Every level, leaves upward. Returned whole because a path needs the siblings at each."""
    if not leaves:
        raise ValueError("an empty keep has no tree and nothing to prove about")
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        cur = list(levels[-1])
        if len(cur) % 2 == 1:
            cur.append(cur[-1])          # duplicate, matching the circuit's rule
        levels.append([hash2(cur[i], cur[i + 1]) for i in range(0, len(cur), 2)])
    return levels


def poseidon_root(leaf_hexes: Sequence[str]) -> int:
    return build_levels([leaf_scalar(h) for h in leaf_hexes])[-1][0]


def poseidon_path(leaf_hexes: Sequence[str], index: int) -> tuple[int, list[dict[str, Any]]]:
    """The sibling and direction at each level, leaf upward.

    `bit` is 0 when the current node is the LEFT child. The circuit constrains it boolean and
    derives the ordering from it, so a wrong bit produces a different root rather than a silently
    reordered one.
    """
    leaves = [leaf_scalar(h) for h in leaf_hexes]
    if not 0 <= index < len(leaves):
        raise ValueError(f"index {index} is outside a keep of {len(leaves)} records")

    levels = build_levels(leaves)
    steps: list[dict[str, Any]] = []
    idx = index
    for level in levels[:-1]:
        cur = list(level)
        if len(cur) % 2 == 1:
            cur.append(cur[-1])
        sib = cur[idx + 1] if idx % 2 == 0 else cur[idx - 1]
        steps.append({"sibling": f"{sib:064x}", "bit": idx % 2})
        idx //= 2
    return levels[-1][0], steps


def export_for_circuit(client, index: int, head: Optional[dict] = None) -> dict[str, Any]:
    """Everything the halo2 prover needs, and the head that makes it mean something.

    The leaf is private input, the path is private input, the root is the circuit's public input.
    The signed head travels with them so a verifier can confirm the root was derived from a leaf
    set the node actually committed to — without it the proof is about an arbitrary tree.
    """
    head = head or client.head()
    leaf_hexes = [r["leaf_hex"] for r in client.list()]
    if not 0 <= index < len(leaf_hexes):
        raise ValueError(f"index {index} is outside a keep of {len(leaf_hexes)} records")

    root, steps = poseidon_path(leaf_hexes, index)
    return {
        "circuit": "merkle-poseidon-p128pow5t3",
        "leaf": f"{leaf_scalar(leaf_hexes[index]):064x}",
        "path": steps,
        "public": {"root": f"{root:064x}"},
        "anchor": {
            "sha256_root_hex": head["root_hex"],
            "tree_size": int(head["tree_size"]),
            "public_key_hex": head.get("public_key_hex", ""),
        },
        "depth": len(steps),
    }


def verify_anchor(bundle: dict[str, Any], leaf_hexes: Sequence[str],
                  head: dict[str, Any]) -> bool:
    """Recompute the root from the verifier's own leaves and check the bundle agrees.

    Run before handing anything to a proof verifier. A ZK proof establishes that a leaf sits under
    the claimed root; it says nothing about whether that root belongs to this keep, and a prover
    who supplies both is proving membership in a tree they built.
    """
    try:
        if bundle["anchor"]["sha256_root_hex"] != head["root_hex"]:
            return False
        if int(bundle["anchor"]["tree_size"]) != int(head["tree_size"]):
            return False
        if int(bundle["depth"]) != len(bundle["path"]):
            return False
        return int(bundle["public"]["root"], 16) == poseidon_root(leaf_hexes)
    except (KeyError, TypeError, ValueError):
        return False


def write_witness(bundle: dict[str, Any], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)

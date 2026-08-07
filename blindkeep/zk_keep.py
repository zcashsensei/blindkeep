"""Prove things about records in the keep without saying which record.

This is where the proof system meets the log, and it is the reason Blindkeep is a
zero-knowledge project rather than a project that happens to contain some
zero-knowledge code.

The log already proves the *node* honest: every record is committed to a signed
Merkle head the node cannot rewrite. What it cannot do is let a **holder** say
anything without disclosing which record they mean — `get(index)` names the
index, and even an inclusion proof reveals the leaf and its whole sibling path.
So the two guarantees stop at different places:

    the log        "this keep contains exactly these records, unaltered"
    this module    "I hold one of them, and it satisfies P" — without saying which

**Bound to a signed head, deliberately.** Every proof here carries the tree root
and size in its Fiat-Shamir transcript. A proof about a keep of 40 records does
not verify against the same keep at 41, and a proof about one keep never
verifies against another. Without that binding a proof would assert membership
in *some* set, which is a claim nobody asked about — this project's oldest
lesson, now in its fourth register.

**The honest cost, stated because it decides the roadmap.** Membership here is
an OR-proof across every leaf, so a proof is O(n) in the size of the keep: about
1 KB per record. At 40 records that is fine; at 40,000 it is not. Making it
O(log n) requires proving a Merkle path *inside a circuit*, which needs a SNARK
and a ZK-friendly hash — which is exactly why `merkle.CachedLog` takes
`leaf_fn`/`node_fn`, and why the second tree is a constructor argument rather
than a rewrite. The sigma version is not a placeholder for that work; it is the
reference implementation the circuit will be checked against.
"""

from __future__ import annotations

from typing import Any, Optional, Sequence

from .zk import (Commitment, Proof, ProofError, commit, prove_membership,
                 verify_membership)

# A leaf hash is 256 bits; the group's scalar field is smaller, so leaves are
# reduced before use. This is a *labelling* of the set being proven over, not a
# security boundary — the log's own integrity still rests on the full SHA-256
# leaf. Truncation here would only let two leaves share a label, which weakens
# what membership means, so the full value is reduced rather than cut.
def leaf_to_scalar(leaf_hex: str) -> int:
    from .zk import Q
    return int(leaf_hex, 16) % Q


def keep_context(head: dict[str, Any]) -> bytes:
    """The statement every proof in this module is about.

    Naming the root AND the size matters: a root alone identifies a state, but
    including the size makes a proof self-describing about *which* state, and
    makes an accidental cross-keep verification impossible rather than unlikely.
    """
    return ("blindkeep-keep-v1|root=" + str(head["root_hex"])
            + "|size=" + str(int(head["tree_size"]))).encode("utf-8")


def keep_leaves(client, limit: int = 400) -> list[str]:
    """Every committed leaf, in log order. Public by construction.

    These are the node's own commitments — publishing them reveals nothing the
    node did not already publish, and they are what a verifier checks against.
    """
    records = client.list()
    if len(records) > limit:
        raise ValueError(
            f"keep has more than {limit} records; an OR-proof over all of them "
            f"would be impractically large. This is the size at which the SNARK "
            f"path stops being optional — see the module docstring.")
    return [r["leaf_hex"] for r in records]


def prove_in_keep(client, index: int, head: Optional[dict] = None
                  ) -> dict[str, Any]:
    """Prove you hold the record at `index`, without revealing the index.

    The verifier learns: this keep, at this signed head, contains a record whose
    leaf the prover can open. It does not learn which one, and the commitment is
    unlinkable to any other proof about the same record.
    """
    head = head or client.head()
    leaves = keep_leaves(client)
    if not 0 <= index < len(leaves):
        raise ValueError(f"index {index} is outside a keep of {len(leaves)} records")

    scalars = [leaf_to_scalar(h) for h in leaves]
    mine = scalars[index]
    commitment, blinding = commit(mine)
    proof = prove_membership(commitment, mine, blinding, scalars,
                             context=keep_context(head))
    return {
        "commitment_hex": commitment.value_hex,
        "proof": proof.as_dict(),
        "head": {"root_hex": head["root_hex"], "tree_size": head["tree_size"]},
        "keep_size": len(leaves),
    }


def verify_in_keep(bundle: dict[str, Any], leaves: Sequence[str],
                   head: dict[str, Any]) -> bool:
    """Check a proof against a keep the verifier looked up themselves.

    `leaves` and `head` are the verifier's, never the bundle's. A proof that
    supplies the set it is proving membership in proves nothing: the prover
    would simply choose a set containing their value. The same reasoning as the
    storage client's first check — bind to the question that was asked.
    """
    if bundle.get("head", {}).get("root_hex") != head["root_hex"]:
        return False
    if int(bundle.get("head", {}).get("tree_size", -1)) != int(head["tree_size"]):
        return False
    if int(bundle.get("keep_size", -1)) != len(leaves):
        return False
    try:
        commitment = Commitment(bundle["commitment_hex"])
        proof = Proof.from_dict(bundle["proof"])
    except (KeyError, TypeError, ValueError, ProofError):
        # A malformed bundle is a refusal, never an exception: verification is
        # called on input a stranger supplied, so it must not be a crash surface.
        return False
    return verify_membership(commitment, proof, [leaf_to_scalar(h) for h in leaves],
                             context=keep_context(head))

"""Catch a node showing different histories to different clients — and prove it did.

A signed tree head says "this is my log, at this size, with this root". Nothing in one head
prevents a node signing a *second* head for the same size with a different root, and handing each
to a different client. Both verify. Both are internally consistent. Each client's history is
sound; they simply are not the same history.

That is equivocation, and it is the one attack the five checks cannot see, because it is not
visible from inside a single conversation. Certificate Transparency has the same problem and the
same answer: **clients gossip the heads they have seen.** Two signed heads of equal size with
different roots is not a suspicion — it is a signature by the node on two contradictory claims,
publishable by anyone who holds both.

    the five checks   "is what this node told ME consistent?"
    this module       "is what it told me the same as what it told you?"

**The client already refuses a fork it sees itself.** `client._update_pin` raises on a same-size
head with a different root, which is the local half of the problem. What it does not do is keep
the evidence, or ever compare against a head someone else was given. This does both: it preserves
the two heads as a portable artefact, and makes them exchangeable.

**Detection, not prevention.** Gossip cannot stop a node equivocating. It makes doing so
detectable by anyone who compares notes, and — because the proof is two of the node's own
signatures — undeniable once detected. That is the whole of what is achievable without
consensus, and claiming more would be the same overreach this project keeps refusing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from .crypto import NodeIdentity, signed_head_message


class EquivocationError(Exception):
    """A node signed two contradictory heads. The proof is attached."""

    def __init__(self, message: str, proof: "EquivocationProof"):
        super().__init__(message)
        self.proof = proof


@dataclass(frozen=True)
class SignedHead:
    """One head, exactly as a node published it."""
    tree_size: int
    root_hex: str
    signature_hex: str
    public_key_hex: str
    seen_at: float = 0.0

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SignedHead":
        return cls(tree_size=int(d["tree_size"]), root_hex=str(d["root_hex"]).lower(),
                   signature_hex=str(d["signature_hex"]),
                   public_key_hex=str(d["public_key_hex"]).lower(),
                   seen_at=float(d.get("signed_at", 0.0)))

    def as_dict(self) -> dict[str, Any]:
        return {"tree_size": self.tree_size, "root_hex": self.root_hex,
                "signature_hex": self.signature_hex,
                "public_key_hex": self.public_key_hex, "seen_at": self.seen_at}

    def verify(self) -> bool:
        """Is this genuinely signed by the key it names?

        Checked before a head is ever stored or gossiped. An unsigned head proves nothing about
        anybody, and a collection of them would turn this into a way to slander honest nodes.
        """
        try:
            pub = bytes.fromhex(self.public_key_hex)
            sig = bytes.fromhex(self.signature_hex)
            root = bytes.fromhex(self.root_hex)
        except ValueError:
            return False
        return NodeIdentity.verify(pub, signed_head_message(self.tree_size, root), sig)


@dataclass(frozen=True)
class EquivocationProof:
    """Two of a node's own signatures, on two different roots at one size.

    Self-contained on purpose. Anyone can check it without contacting the node, without trusting
    whoever passed it along, and after the node has stopped serving either head.
    """
    a: SignedHead
    b: SignedHead

    def as_dict(self) -> dict[str, Any]:
        return {"kind": "equivocation", "public_key_hex": self.a.public_key_hex,
                "tree_size": self.a.tree_size, "head_a": self.a.as_dict(),
                "head_b": self.b.as_dict()}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "EquivocationProof":
        return cls(a=SignedHead.from_dict(d["head_a"]), b=SignedHead.from_dict(d["head_b"]))

    def holds(self) -> bool:
        """Verify the accusation from the artefact alone."""
        return (self.a.public_key_hex == self.b.public_key_hex
                and self.a.tree_size == self.b.tree_size
                and self.a.root_hex != self.b.root_hex
                and self.a.verify() and self.b.verify())

    def summary(self) -> str:
        return (f"node {self.a.public_key_hex[:16]}… signed two different roots at tree_size "
                f"{self.a.tree_size}: {self.a.root_hex[:16]}… and {self.b.root_hex[:16]}…")


@dataclass
class HeadLog:
    """Heads seen from one node, and the check that runs on every addition.

    Keyed by size because that is where equivocation shows: a node may legitimately publish many
    heads as its log grows, and may never publish two for the same size.
    """
    public_key_hex: str
    heads: dict[int, SignedHead] = field(default_factory=dict)

    def observe(self, head: SignedHead) -> None:
        """Record a head, or raise with proof if it contradicts one already held."""
        if head.public_key_hex != self.public_key_hex:
            raise EquivocationError(
                "head is signed by a different key than this log tracks",
                EquivocationProof(head, head))
        if not head.verify():
            # Not equivocation — just a head nobody signed. Refused so that unsigned junk can
            # never enter the record and later be produced as "evidence".
            raise ValueError("head signature does not verify; refusing to record it")

        seen = self.heads.get(head.tree_size)
        if seen is not None and seen.root_hex != head.root_hex:
            proof = EquivocationProof(seen, head)
            raise EquivocationError(proof.summary(), proof)
        self.heads[head.tree_size] = head

    def merge(self, other: Iterable[SignedHead]) -> int:
        """Take in heads another client was given. This is the gossip.

        Returns how many were new. Raises `EquivocationError` the moment a contradiction appears,
        because there is nothing useful to do with the rest once the node is known to be lying.
        """
        added = 0
        for h in other:
            before = len(self.heads)
            self.observe(h)
            added += len(self.heads) - before
        return added

    def export(self) -> list[dict[str, Any]]:
        """What to hand another client. Public data — every one of these was published."""
        return [h.as_dict() for h in sorted(self.heads.values(), key=lambda h: h.tree_size)]

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"public_key_hex": self.public_key_hex, "heads": self.export()},
                      f, indent=2)

    @classmethod
    def load(cls, path: str) -> "HeadLog":
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
        log = cls(public_key_hex=d["public_key_hex"])
        for h in d["heads"]:
            log.observe(SignedHead.from_dict(h))
        return log


def gossip(mine: HeadLog, theirs: Iterable[dict[str, Any]]) -> int:
    """Compare notes with another client. The whole protocol.

    Deliberately trivial: the security does not come from an elaborate exchange, it comes from
    two people ever comparing at all. A node can lie to each of them separately for as long as
    they never speak.
    """
    return mine.merge(SignedHead.from_dict(h) for h in theirs)

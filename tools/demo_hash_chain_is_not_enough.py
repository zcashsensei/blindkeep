"""Why a tamper-evident hash chain is not the same guarantee as a transparency log.

    py -3 tools/demo_hash_chain_is_not_enough.py

WHY THIS EXISTS
  Encrypted agent memory is a crowded category. Audited 2026-08-13, the closest shipped
  MCP servers -- Compartment (github.com/MaxFreedomPollard/Compartment) and mnemo
  (github.com/sattyamjjain/mnemo) -- both offer client-side AEAD plus a SHA-256 hash-chained
  audit log, and mnemo's README states an external verifier can detect post-hoc mutation
  offline. Those are real properties and this demo does not dispute them.

  What neither has is an adversary who SERVES the data. Source audit of both, integrity
  primitives, source files only:

      merkle · inclusion proof · consistency proof · RFC 6962 · signed tree head ·
      equivocation · witness/gossip          -> 0 hits in BOTH repos
      "untrusted/malicious server|node|operator" -> 0 mentions in BOTH repos

  That is not an oversight, it is their threat model: both are local-first stores that you
  own. A hash chain answers "did MY store change behind my back", verified by me, over my
  own data.

  Oblivio answers a different question: "is the operator serving me the same history it
  serves everyone else, complete and unrewritten" -- when the operator is hostile.

  This script runs the two attacks that separate those questions. Both attacks produce a
  PERFECTLY VALID hash chain. Both are caught by a signed Merkle tree head.

NOTHING HERE IS A STRAWMAN
  The hash chain below is the real construction, implemented correctly, and it is verified
  correctly. It is not weakened to lose. It loses because a chain over the records you were
  shown cannot speak about records you were not shown, or about what another client saw.
"""
from __future__ import annotations

import hashlib
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from oblivio import merkle  # noqa: E402

try:
    from oblivio._console import use_utf8_stdout
    use_utf8_stdout()
except Exception:
    pass

FAILED: list[str] = []


def note(label: str, ok: bool, detail: str = "") -> None:
    print(f"    {'PASS' if ok else 'FAIL'}  {label}{'  ' + detail if detail else ''}")
    if not ok:
        FAILED.append(label)


# ── The model Compartment and mnemo implement ────────────────────────────────────────────
def chain(records: list[bytes]) -> bytes:
    """SHA-256 hash chain: h_i = H(h_{i-1} || record_i). Tamper-evident, correctly done."""
    h = b"\x00" * 32
    for r in records:
        h = hashlib.sha256(h + r).digest()
    return h


def chain_verifies(records: list[bytes], head: bytes) -> bool:
    """An external verifier, offline, with no help from the store. Exactly the claim."""
    return chain(records) == head


# ── The model Oblivio implements ───────────────────────────────────────────────────────
def log_root(records: list[bytes]) -> bytes:
    return merkle.root([merkle.leaf_hash(r) for r in records])


def banner(n: int, title: str) -> None:
    print(f"\n{'=' * 78}\n  ATTACK {n} — {title}\n{'=' * 78}")


def attack_omission() -> None:
    """The operator drops a record and re-chains. The chain is valid over what remains."""
    banner(1, "OMISSION: the operator drops a record you never learn existed")

    truth = [b"note-1", b"note-2", b"SECRET-note-3", b"note-4"]
    served = [b"note-1", b"note-2", b"note-4"]           # note-3 quietly removed

    print("\n  honest log : " + ", ".join(r.decode() for r in truth))
    print("  served     : " + ", ".join(r.decode() for r in served))

    print("\n  -- hash-chain verifier (Compartment / mnemo model) --")
    served_head = chain(served)
    note("chain over the served records verifies",
         chain_verifies(served, served_head), "-> client sees NOTHING wrong")
    print("      The chain is internally perfect. It commits to the records shown and")
    print("      says nothing about a record that was never shown. There is no count to")
    print("      check against, because the head IS derived from what you were given.")

    print("\n  -- Oblivio: signed tree head pins the SIZE, so absence is detectable --")
    honest_root, honest_size = log_root(truth), len(truth)
    print(f"      operator previously signed (tree_size={honest_size}, root={honest_root.hex()[:16]}…)")
    leaves = [merkle.leaf_hash(r) for r in truth]
    proof = merkle.inclusion_proof(2, leaves)
    ok = merkle.verify_inclusion(merkle.leaf_hash(b"SECRET-note-3"), 2,
                                 honest_size, proof, honest_root)
    note("inclusion proof for the dropped record still verifies", ok,
         "-> the client can DEMAND record 2 of 4")
    served_root = log_root(served)
    note("serving 3 records cannot reproduce the signed root",
         served_root != honest_root,
         f"{served_root.hex()[:16]}… != {honest_root.hex()[:16]}…")
    print("      The operator signed a SIZE. Producing fewer records than it committed to")
    print("      is now a detectable lie, not a silent edit.")


def attack_equivocation() -> None:
    """The sharpest one: two clients, two histories, both chains internally perfect."""
    banner(2, "EQUIVOCATION: two clients are shown two different histories")

    shared = [b"note-1", b"note-2"]
    view_a = shared + [b"pay-alice-100"]
    view_b = shared + [b"pay-bob-100"]

    print("\n  client A is served : " + ", ".join(r.decode() for r in view_a))
    print("  client B is served : " + ", ".join(r.decode() for r in view_b))

    print("\n  -- hash-chain verifier --")
    head_a, head_b = chain(view_a), chain(view_b)
    note("A's chain verifies for A", chain_verifies(view_a, head_a))
    note("B's chain verifies for B", chain_verifies(view_b, head_b))
    print("      BOTH clients verify successfully and BOTH are being lied to.")
    print("      Each head is computed from that client's own records, so divergence is")
    print("      invisible from inside either view. Detecting it requires comparing heads")
    print("      ACROSS clients -- and a hash chain has no head to compare: it is not")
    print("      signed, so there is nothing binding the operator to one history.")

    print("\n  -- Oblivio: heads are SIGNED over (tree_size, root), so they are comparable --")
    root_a, root_b = log_root(view_a), log_root(view_b)
    print(f"      head shown to A : size=3 root={root_a.hex()[:16]}…")
    print(f"      head shown to B : size=3 root={root_b.hex()[:16]}…")
    note("two signed heads at the SAME size with DIFFERENT roots", root_a != root_b,
         "-> that pair IS the fraud proof")
    print("      Because the operator SIGNED both, the pair is transferable evidence of")
    print("      equivocation that anyone can check -- not merely a local suspicion.")
    print("      This is what witness gossip exists to surface.")


def attack_rewrite() -> None:
    """History rewrite: the chain re-chains cleanly; consistency proofs do not."""
    banner(3, "REWRITE: yesterday's entry is edited and the log re-chained")

    before = [b"note-1", b"note-2"]
    after_honest = before + [b"note-3"]
    after_rewritten = [b"note-1", b"note-2-EDITED", b"note-3"]

    print("\n  pinned earlier   : " + ", ".join(r.decode() for r in before))
    print("  honest growth    : " + ", ".join(r.decode() for r in after_honest))
    print("  rewritten        : " + ", ".join(r.decode() for r in after_rewritten))

    print("\n  -- hash-chain verifier --")
    note("rewritten chain verifies against its own new head",
         chain_verifies(after_rewritten, chain(after_rewritten)),
         "-> valid, if you did not keep the old head")
    print("      A client that pinned nothing has no basis to object. The construction")
    print("      offers no proof that a NEW head extends an OLD one.")

    print("\n  -- Oblivio: consistency proof binds new state to pinned old state --")
    old_root = log_root(before)
    leaves_h = [merkle.leaf_hash(r) for r in after_honest]
    cproof = merkle.consistency_proof(len(before), leaves_h)
    ok_honest = merkle.verify_consistency(len(before), len(after_honest),
                                          old_root, log_root(after_honest), cproof)
    note("honest append proves consistency with the pinned head", ok_honest)

    leaves_r = [merkle.leaf_hash(r) for r in after_rewritten]
    cproof_r = merkle.consistency_proof(len(before), leaves_r)
    ok_rewrite = merkle.verify_consistency(len(before), len(after_rewritten),
                                           old_root, log_root(after_rewritten), cproof_r)
    note("rewritten history is REFUSED against the pinned head", not ok_rewrite,
         "-> append-only is proven, not promised")


def main() -> int:
    print(__doc__.split("NOTHING HERE IS A STRAWMAN")[0].rstrip())
    attack_omission()
    attack_equivocation()
    attack_rewrite()

    print(f"\n{'=' * 78}")
    print("  WHAT THIS DOES AND DOES NOT ARGUE")
    print(f"{'=' * 78}")
    print("""
  DOES NOT: claim a hash chain is broken, or that Compartment and mnemo are insecure.
            For a store you control, on a machine you control, a hash chain answers the
            question it is built to answer, and both projects implement it properly.

  DOES:     show the question changes the moment the store is somebody else's. Omission,
            equivocation and rewrite are all invisible to a chain over records the server
            selected, and all detectable against a SIGNED head committing to (size, root).

  So the distinction is not "stronger crypto". It is that a transparency log has an
  adversary in its threat model -- the party serving you the data -- and a local hash
  chain does not.""")
    print(f"\n  {'ALL CHECKS BEHAVED AS CLAIMED' if not FAILED else 'FAILED: ' + ', '.join(FAILED)}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())

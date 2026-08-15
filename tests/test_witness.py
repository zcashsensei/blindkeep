"""Equivocation: catching a node that tells two clients two different histories.

The five client checks answer "is what this node told ME consistent?". They cannot answer "is it
the same as what it told you?", because that question is not visible from inside one conversation.

So the load-bearing test is `test_two_clients_comparing_notes_catch_the_split`: neither client can
detect the attack alone, and the moment they exchange heads the node's own signatures convict it.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oblivio.crypto import NodeIdentity, signed_head_message
from oblivio.witness import (
    EquivocationError,
    EquivocationProof,
    HeadLog,
    SignedHead,
    gossip,
)

NODE = NodeIdentity.generate()
OTHER = NodeIdentity.generate()


def head(size, root_byte, identity=NODE):
    """A genuinely signed head, as a node would publish it."""
    root = bytes([root_byte]) * 32
    sig = identity.sign(signed_head_message(size, root))
    return SignedHead(tree_size=size, root_hex=root.hex(), signature_hex=sig.hex(),
                      public_key_hex=identity.public_hex(), seen_at=time.time())


def log():
    return HeadLog(public_key_hex=NODE.public_hex())


# --- the attack ---------------------------------------------------------------

def test_two_clients_comparing_notes_catch_the_split():
    """Neither sees it alone. Together it is undeniable.

    The node serves size 5 with root A to one client and root B to another. Both views verify;
    both are internally consistent; they are different histories.
    """
    alice, bob = log(), log()
    alice.observe(head(5, 0xAA))
    bob.observe(head(5, 0xBB))

    # Alone, each is perfectly happy.
    assert len(alice.heads) == 1 and len(bob.heads) == 1

    try:
        gossip(alice, bob.export())
    except EquivocationError as exc:
        assert exc.proof.holds(), "the proof does not verify"
        assert "tree_size 5" in exc.proof.summary()
        return
    raise AssertionError("the split view went undetected")


def test_the_proof_stands_on_its_own():
    """Checkable without the node, without trusting the messenger, after the fact."""
    a, b = head(9, 0x11), head(9, 0x22)
    proof = EquivocationProof(a, b)
    assert proof.holds()
    # Survives a round trip, because it has to travel to be worth anything.
    assert EquivocationProof.from_dict(proof.as_dict()).holds()


def test_a_third_party_can_verify_without_having_been_there():
    a, b = head(3, 0x01), head(3, 0x02)
    exported = EquivocationProof(a, b).as_dict()
    stranger = EquivocationProof.from_dict(exported)
    assert stranger.holds()
    assert stranger.a.verify() and stranger.b.verify()


# --- what must NOT count as equivocation --------------------------------------

def test_a_growing_log_is_not_equivocation():
    """A node publishes many heads legitimately. Only two at the SAME size contradict."""
    l = log()
    for size, root in ((1, 0x01), (2, 0x02), (3, 0x03), (10, 0x0A)):
        l.observe(head(size, root))
    assert len(l.heads) == 4


def test_the_same_head_seen_twice_is_fine():
    l = log()
    h = head(7, 0x77)
    l.observe(h)
    l.observe(h)
    assert len(l.heads) == 1


def test_gossiping_identical_views_changes_nothing():
    alice, bob = log(), log()
    for size, root in ((1, 0x01), (2, 0x02)):
        alice.observe(head(size, root))
        bob.observe(head(size, root))
    assert gossip(alice, bob.export()) == 0


def test_gossip_fills_in_heads_you_never_saw():
    """The useful half: consistency checking over a longer history than you witnessed."""
    alice, bob = log(), log()
    alice.observe(head(1, 0x01))
    bob.observe(head(1, 0x01))
    bob.observe(head(2, 0x02))
    assert gossip(alice, bob.export()) == 1
    assert 2 in alice.heads


# --- evidence hygiene ---------------------------------------------------------

def test_an_unsigned_head_cannot_enter_the_record():
    """Otherwise this becomes a way to manufacture accusations against honest nodes."""
    l = log()
    forged = SignedHead(tree_size=4, root_hex="ff" * 32, signature_hex="00" * 64,
                        public_key_hex=NODE.public_hex())
    try:
        l.observe(forged)
    except ValueError as exc:
        assert "does not verify" in str(exc)
        return
    raise AssertionError("an unsigned head was recorded as evidence")


def test_a_proof_needs_both_signatures_to_hold():
    real = head(6, 0x66)
    fake = SignedHead(tree_size=6, root_hex="ee" * 32, signature_hex="00" * 64,
                      public_key_hex=NODE.public_hex())
    assert EquivocationProof(real, fake).holds() is False


def test_two_different_nodes_disagreeing_is_not_equivocation():
    """Separate operators run separate logs. That is replication, not misbehaviour."""
    a = head(5, 0xAA, NODE)
    b = head(5, 0xBB, OTHER)
    assert EquivocationProof(a, b).holds() is False


def test_a_head_from_the_wrong_node_is_rejected_by_the_log():
    l = log()
    try:
        l.observe(head(1, 0x01, OTHER))
    except EquivocationError as exc:
        assert "different key" in str(exc)
        return
    raise AssertionError("a foreign node's head entered this log")


def test_the_same_root_at_the_same_size_is_not_a_contradiction():
    proof = EquivocationProof(head(8, 0x88), head(8, 0x88))
    assert proof.holds() is False, "identical roots were called a contradiction"


# --- persistence ---------------------------------------------------------------

def test_a_head_log_survives_a_round_trip(tmp="_witness_tmp.json"):
    l = log()
    l.observe(head(1, 0x01))
    l.observe(head(2, 0x02))
    try:
        l.save(tmp)
        back = HeadLog.load(tmp)
        assert back.public_key_hex == l.public_key_hex
        assert set(back.heads) == {1, 2}
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


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

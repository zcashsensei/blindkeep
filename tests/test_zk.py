"""Zero-knowledge proof tests. The adversarial ones are the point.

An honest proof verifying tells you almost nothing — a function that returns
True always passes that test. What matters is that a proof **cannot be moved**:
not to a different statement, not to a different commitment, not to a candidate
set the prover picked afterwards.

`test_a_proof_does_not_transfer_to_another_statement` is the one this module
exists for. It is the same failure the storage client had — a valid proof of
something other than what was asked — in its third register.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blindkeep.zk import (
    G,
    H,
    P,
    Q,
    Commitment,
    Proof,
    ProofError,
    commit,
    prove_equality,
    prove_membership,
    prove_opening,
    prove_range,
    verify_equality,
    verify_membership,
    verify_opening,
    verify_range,
)


def expect_error(fn, contains=None):
    try:
        fn()
    except ProofError as e:
        if contains:
            assert contains in str(e).lower(), f"wrong reason: {e}"
        return
    raise AssertionError("expected a refusal, got none")


# --- group parameters --------------------------------------------------------

def test_generators_are_in_the_prime_order_subgroup():
    """Order q, so there is no small subgroup to be confused into."""
    assert pow(G, Q, P) == 1 and pow(H, Q, P) == 1
    assert G != 1 and H != 1


def test_h_is_derived_not_chosen():
    """If anyone knew log_G(H), commitments would not be binding."""
    from blindkeep.zk import _derive_h
    assert _derive_h() == H, "H is not reproducible from its seed"
    assert H != G


# --- commitments -------------------------------------------------------------

def test_commitments_hide_the_value():
    a, _ = commit(42)
    b, _ = commit(42)
    assert a.value_hex != b.value_hex, "same value committed twice looks identical"


def test_commitment_is_reproducible_with_its_blinding():
    c1, r = commit(42)
    c2, _ = commit(42, blinding=r)
    assert c1.value_hex == c2.value_hex


def test_negative_values_are_refused():
    expect_error(lambda: commit(-1), "non-negative")


# --- opening -----------------------------------------------------------------

def test_honest_opening_verifies():
    c, r = commit(1234)
    assert verify_opening(c, prove_opening(c, 1234, r)) is True


def test_wrong_value_does_not_verify():
    c, r = commit(1234)
    assert verify_opening(c, prove_opening(c, 9999, r)) is False


def test_wrong_blinding_does_not_verify():
    c, r = commit(1234)
    assert verify_opening(c, prove_opening(c, 1234, r + 1)) is False


def test_proof_shape_does_not_depend_on_the_value():
    """Structural indistinguishability, not a substring search.

    Grepping a proof for the decimal value is not a leakage test: a few
    thousand characters of random hex contain any given three-digit string by
    coincidence, so the check fails on correct code and would pass on leaky
    code with a different value. What can be asserted is that the proof's
    structure carries no information — same fields, same sizes, whatever was
    committed.
    """
    a = prove_opening(*(lambda c, r: (c, 5, r))(*commit(5)))
    b = prove_opening(*(lambda c, r: (c, 4294967295, r))(*commit(4294967295)))
    assert a.data.keys() == b.data.keys()
    assert a.kind == b.kind
    for field in a.data:
        assert abs(len(a.data[field]) - len(b.data[field])) <= 2, (
            f"{field} length tracks the committed value")


# --- THE test: statements cannot be swapped ----------------------------------

def test_a_proof_does_not_transfer_to_another_statement():
    """A proof built for one context must not verify under another.

    This is what Fiat-Shamir binding buys. Without the statement inside the
    challenge hash, a proof of "within limit for account A" would verify as a
    proof about account B — genuinely valid, and an answer to a question nobody
    asked.
    """
    c, r = commit(500)
    proof = prove_opening(c, 500, r, context=b"account-A")
    assert verify_opening(c, proof, context=b"account-A") is True
    assert verify_opening(c, proof, context=b"account-B") is False


def test_a_proof_does_not_transfer_to_another_commitment():
    c1, r1 = commit(500)
    c2, _ = commit(500)
    proof = prove_opening(c1, 500, r1)
    assert verify_opening(c2, proof) is False


def test_context_binding_is_unambiguous():
    """Length-prefixed transcript: ('ab','c') must not hash like ('a','bc')."""
    c, r = commit(7)
    p1 = prove_opening(c, 7, r, context=b"ab")
    assert verify_opening(c, p1, context=b"ab") is True
    # A concatenation-based transcript would let this pass.
    assert verify_opening(c, p1, context=b"a") is False


def test_tampered_proof_fields_do_not_verify():
    c, r = commit(500)
    proof = prove_opening(c, 500, r)
    for field in ("t_hex", "s1_hex", "s2_hex"):
        broken = dict(proof.data)
        broken[field] = f"{int(broken[field], 16) + 1:x}"
        assert verify_opening(c, Proof("opening", broken)) is False, field


def test_malformed_proofs_return_false_not_crash():
    c, _ = commit(1)
    for bad in ({}, {"t_hex": "zz"}, {"t_hex": "01"}, {"kind": "x"}):
        assert verify_opening(c, Proof("opening", bad)) is False
    assert verify_opening(c, Proof("wrong-kind", {})) is False


# --- equality ----------------------------------------------------------------

def test_equal_values_prove_equal():
    c1, r1 = commit(77)
    c2, r2 = commit(77)
    assert verify_equality(c1, c2, prove_equality(c1, c2, r1, r2)) is True


def test_different_values_do_not_prove_equal():
    c1, r1 = commit(77)
    c2, r2 = commit(78)
    assert verify_equality(c1, c2, prove_equality(c1, c2, r1, r2)) is False


def test_prover_supplied_y_is_ignored():
    """The verifier recomputes y. A prover who could choose it could prove
    equality between commitments that are not equal."""
    c1, r1 = commit(77)
    c2, r2 = commit(77)
    proof = prove_equality(c1, c2, r1, r2)
    forged = dict(proof.data)
    forged["y_hex"] = "01"
    assert verify_equality(c1, c2, Proof("equality", forged)) is True, (
        "changing y changed the outcome, so the verifier is trusting it")


# --- set membership ----------------------------------------------------------

def test_membership_verifies_without_revealing_which():
    cands = [10, 20, 30, 40]
    c, r = commit(30)
    proof = prove_membership(c, 30, r, cands)
    assert verify_membership(c, proof, cands) is True
    blob = json.dumps(proof.as_dict())
    # The value appears only because it is a public candidate; what must not
    # leak is the index, and every branch is structurally identical.
    assert len(proof.data["t_hex"]) == len(cands)
    assert len(set(proof.data["c_hex"])) == len(cands), "branches distinguishable"


def test_value_outside_the_set_cannot_be_proven():
    c, r = commit(99)
    expect_error(lambda: prove_membership(c, 99, r, [10, 20]), "not among")


def test_prover_cannot_choose_the_candidate_set():
    """The verifier's set is authoritative.

    Otherwise a prover proves membership in a set they picked after seeing the
    question, which proves nothing at all.
    """
    real = [10, 20, 30]
    c, r = commit(30)
    proof = prove_membership(c, 30, r, real)
    assert verify_membership(c, proof, [30, 40, 50]) is False
    assert verify_membership(c, proof, [10, 20]) is False


def test_membership_proof_does_not_transfer_between_contexts():
    cands = [1, 2, 3]
    c, r = commit(2)
    proof = prove_membership(c, 2, r, cands, context=b"desk-1")
    assert verify_membership(c, proof, cands, context=b"desk-1") is True
    assert verify_membership(c, proof, cands, context=b"desk-2") is False


def test_tampered_membership_challenges_do_not_verify():
    cands = [1, 2, 3]
    c, r = commit(2)
    proof = prove_membership(c, 2, r, cands)
    broken = dict(proof.data)
    broken["c_hex"] = list(broken["c_hex"])
    broken["c_hex"][0] = f"{int(broken['c_hex'][0], 16) ^ 1:x}"
    assert verify_membership(c, Proof("membership", broken), cands) is False


# --- range: the predicate a risk limit needs ---------------------------------

def test_range_proof_verifies():
    r = 12345 % Q
    c, proof = prove_range(200, r, bits=8)
    assert verify_range(c, proof, bits=8) is True


def test_value_too_large_is_refused_at_proving_time():
    expect_error(lambda: prove_range(256, 1, bits=8), "does not fit")
    expect_error(lambda: prove_range(-1, 1, bits=8), "does not fit")


def test_range_proofs_are_structurally_identical_whatever_the_value():
    """Two different values in the same range produce proofs of the same shape."""
    _, low = prove_range(3, 111, bits=8)
    _, high = prove_range(200, 222, bits=8)
    assert low.data.keys() == high.data.keys()
    assert len(low.data["bit_commitments_hex"]) == len(high.data["bit_commitments_hex"])
    assert len(low.data["bit_proofs"]) == len(high.data["bit_proofs"])
    for a, b in zip(low.data["bit_proofs"], high.data["bit_proofs"]):
        assert a.keys() == b.keys()
        assert len(a["t_hex"]) == len(b["t_hex"]) == 2, (
            "a bit proof exposes how many branches were simulated")


def test_range_proof_is_bound_to_its_bit_width():
    c, proof = prove_range(200, 999, bits=8)
    assert verify_range(c, proof, bits=16) is False, (
        "a proof of 'fits in 8 bits' verified as 'fits in 16 bits'")


def test_range_proof_does_not_transfer_to_another_commitment():
    c1, proof = prove_range(200, 999, bits=8)
    c2, _ = commit(200)
    assert verify_range(c2, proof, bits=8) is False


def test_tampered_bit_commitment_breaks_the_proof():
    c, proof = prove_range(200, 999, bits=8)
    broken = dict(proof.data)
    broken["bit_commitments_hex"] = list(broken["bit_commitments_hex"])
    broken["bit_commitments_hex"][0] = f"{int(broken['bit_commitments_hex'][0], 16) * 2 % P:x}"
    assert verify_range(c, Proof("range", broken), bits=8) is False


def test_range_proof_context_binds():
    c, proof = prove_range(50, 777, bits=8, context=b"risk-limit-A")
    assert verify_range(c, proof, bits=8, context=b"risk-limit-A") is True
    assert verify_range(c, proof, bits=8, context=b"risk-limit-B") is False


def test_a_wider_range_still_works():
    c, proof = prove_range(60000, 4242, bits=16)
    assert verify_range(c, proof, bits=16) is True


# --- the worked example ------------------------------------------------------

def test_prove_a_position_was_within_a_limit():
    """The use case, end to end: prove a trade was inside a cap, reveal nothing.

    The verifier learns the position was under 2^10 and learns nothing else —
    not the size, not the direction, not the instrument.
    """
    position = 731
    c, proof = prove_range(position, 555, bits=10, context=b"desk:kage|limit:1024")
    assert verify_range(c, proof, bits=10, context=b"desk:kage|limit:1024") is True
    # The verifier holds only the commitment and the proof; nothing it has
    # determines the position, and a second commitment to the same number is
    # unlinkable to the first.
    other, _ = commit(position)
    assert other.value_hex != c.value_hex
    # And the same proof says nothing about a different desk's limit.
    assert verify_range(c, proof, bits=10, context=b"desk:other|limit:1024") is False


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
            print(f"  FAIL  {name}\n          {exc}")
        except Exception as exc:
            failed.append(name)
            print(f"  ERROR {name}\n          {type(exc).__name__}: {exc}")
    print(f"\n{len(passed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())

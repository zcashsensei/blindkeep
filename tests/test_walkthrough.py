"""The walkthrough is a claim surface, so it gets tested like one.

A demo that drifts is worse than no demo: it is a confident wrong answer shown
to exactly the people deciding whether to trust the project. These tests fix
the two ways it could rot —

  * a step stops running real code and becomes prose (every step must carry
    measured facts, and the adversarial steps must actually fail closed), and
  * it starts claiming something the repo cannot back (the not-claimed list
    must survive, and the proof step must stay labelled a sigma protocol
    rather than the halo2 circuit that lives in another repo).
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oblivio.walkthrough import CANARY, run


def collect():
    """Run once; return (steps by number, done event)."""
    steps, done = {}, None
    for ev in run():
        assert ev["stage"] != "error", ev.get("msg")
        if ev["stage"] == "step":
            steps[ev["n"]] = ev
        elif ev["stage"] == "done":
            done = ev
    return steps, done


RUN = collect()


def test_all_ten_steps_run_and_finish():
    steps, done = RUN
    assert sorted(steps) == list(range(1, 11)), sorted(steps)
    assert done is not None and done["steps"] == 10


def test_every_step_reports_measured_facts():
    """No step may be narration. Each one has to return something it measured."""
    steps, _ = RUN
    for n, ev in steps.items():
        assert ev["facts"], f"step {n} carries no facts"
        assert ev["title"] and ev["detail"], f"step {n} is missing its text"


def test_node_disk_holds_no_plaintext():
    steps, _ = RUN
    facts = steps[4]["facts"]
    assert facts["plaintext_hits"] == 0
    assert facts["files_scanned"] > 0, "a scan of zero files proves nothing"
    assert facts["bytes_scanned"] > 0
    assert facts["canary"] == CANARY.decode()


def test_reads_verify_before_they_decrypt():
    steps, _ = RUN
    f = steps[5]["facts"]
    assert f["records_read"] == f["inclusion_proofs_verified"] == f["plaintext_matches"] > 0


def test_adversarial_steps_fail_closed():
    steps, _ = RUN
    assert steps[6]["facts"]["accepted"] is False
    assert steps[6]["facts"]["bytes_flipped"] == 1
    assert steps[7]["facts"]["fetched"] is True
    assert steps[7]["facts"]["decrypted"] is False


def test_gate_actually_withholds():
    """A release with nothing withheld would demo a gate that never says no."""
    steps, _ = RUN
    f = steps[8]["facts"]
    assert f["withheld"] > 0, "the walkthrough must show the gate refusing"
    assert "secret" in f["withheld_classes"]
    assert f["unreachable"] == 0


def test_budget_is_bounded_and_the_length_bound_is_stated():
    steps, _ = RUN
    f = steps[9]["facts"]
    assert 0 < f["epsilon_spent"] <= f["epsilon_budget"]
    assert f["padding_bytes"] >= 0 and f["bucket_bytes"] >= f["payload_bytes"]
    assert f["length_bits_bound"] > 0


def test_proof_verifies_and_a_tampered_proof_does_not():
    steps, _ = RUN
    f = steps[10]["facts"]
    assert f["verified"] is True
    assert f["tampered_proof_accepted"] is False
    assert f["value_revealed"] == "none"


def test_proof_step_does_not_claim_halo2():
    """The constant-size circuit is a separate Rust repo. Saying otherwise here
    would be the single most damaging overclaim the project could make."""
    steps, _ = RUN
    f = steps[10]["facts"]
    assert "sigma" in f["system"].lower()
    assert "halo2" not in f["system"].lower()


def test_receipt_keeps_the_non_claims():
    _, done = RUN
    receipt = done["receipt"]
    assert receipt["steps"] and len(receipt["steps"]) == 10
    assert receipt["node_pubkey"]
    text = " ".join(receipt["not_claimed"]).lower()
    for owed in ("halo2", "provider", "detected"):
        assert owed in text, f"the receipt stopped disclaiming {owed}"


def test_nothing_is_left_on_disk():
    """Temp trees from a demo anyone can press are a slow disk leak."""
    before = {n for n in os.listdir(tempfile.gettempdir())
              if n.startswith("oblivio-walkthrough-")}
    collect()
    after = {n for n in os.listdir(tempfile.gettempdir())
             if n.startswith("oblivio-walkthrough-")}
    assert after <= before, f"left behind: {after - before}"

"""Calibrated randomness: the mechanism is exact, the ledger refuses, the pad is deterministic.

The claims discipline test matters most here: every scoped statement the dp
module emits must survive being read by a hostile referee. A selection epsilon
reported as end-to-end DP would be the `claimed privacy vs the socket` defect
in new clothes, so `test_the_claim_is_scoped` pins the exact wording.
"""

import json
import math
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oblivio.delegate import LeakError
from oblivio.dp import (
    DEFAULT_BUCKETS,
    BudgetError,
    PrivacyLedger,
    dp_delegate,
    exponential_mechanism,
    pad_to_bucket,
    select_abstraction,
)
from oblivio.frontier_private import FrontierPrivateError, frontier_chat

PRIVATE = ("Sarah Whitfield, my landlord in Truro who breeds Basenjis, "
           "owes me £4,000 — what should I do?")


# --- exponential mechanism ---------------------------------------------------

def test_epsilon_zero_is_uniform_and_large_epsilon_prefers_utility():
    rng = random.Random(7)
    utils = [0.0, -10.0]
    n = 4000
    flat = sum(1 for _ in range(n)
               if exponential_mechanism(utils, 0.0, sensitivity=10.0, rng=rng) == 0)
    sharp = sum(1 for _ in range(n)
                if exponential_mechanism(utils, 20.0, sensitivity=10.0, rng=rng) == 0)
    # epsilon=0: both options equally likely. epsilon=20, gap=10, sens=10:
    # preference ratio e^10 — the better option should essentially always win.
    assert abs(flat / n - 0.5) < 0.05, f"eps=0 was not uniform: {flat}/{n}"
    assert sharp / n > 0.99, f"eps=20 did not prefer the better option: {sharp}/{n}"


def test_mechanism_rejects_bad_parameters():
    for bad in (lambda: exponential_mechanism([], 1.0),
                lambda: exponential_mechanism([0.0], -1.0),
                lambda: exponential_mechanism([0.0], 1.0, sensitivity=0.0)):
        try:
            bad()
            raise AssertionError("should have raised")
        except ValueError:
            pass


def test_the_claim_is_scoped():
    """The report must say what the epsilon bounds — and what it does not."""
    _, report = select_abstraction(["a generic question"], 2.0, rng=random.Random(1))
    assert "NOT end-to-end" in report["claim"]
    assert report["selection_epsilon"] == 2.0
    assert report["mechanism"] == "exponential_mechanism"


# --- ledger ------------------------------------------------------------------

def test_ledger_accumulates_and_refuses_before_spending():
    led = PrivacyLedger(epsilon_budget=5.0, specificity_budget=100)
    led.charge(epsilon=2.0, spec=10)
    led.charge(epsilon=2.0, spec=10)
    try:
        led.charge(epsilon=2.0, spec=10)     # 6.0 > 5.0
        raise AssertionError("budget should have refused")
    except BudgetError:
        pass
    # The refused charge must not have been recorded — refuse-then-spend,
    # never spend-then-notice.
    assert led.epsilon_spent == 4.0
    assert led.specificity_spent == 20
    assert led.sends == 2


def test_ledger_persists_spends_but_not_budgets(tmp_path=None):
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "ledger.json")
        led = PrivacyLedger(epsilon_budget=10.0, path=path)
        led.charge(epsilon=3.0, spec=7)
        again = PrivacyLedger.load(path, epsilon_budget=4.0)
        assert again.epsilon_spent == 3.0
        assert again.specificity_spent == 7
        # Budget comes from the CALLER, not the file: editing JSON must not
        # raise your own limit.
        assert again.epsilon_budget == 4.0
        try:
            again.charge(epsilon=2.0, spec=1)   # 5.0 > 4.0
            raise AssertionError("loaded ledger should enforce caller budget")
        except BudgetError:
            pass


# --- length bucketing --------------------------------------------------------

def test_padding_lands_exactly_on_a_bucket():
    for size in (1, 700, 1024, 1025, 5000):
        pad, rep = pad_to_bucket(size, DEFAULT_BUCKETS)
        assert rep["bucketed"] is True
        assert size + pad == rep["bucket_bytes"]
        assert rep["bucket_bytes"] in DEFAULT_BUCKETS
        assert rep["length_bits_bound"] == round(math.log2(len(DEFAULT_BUCKETS)), 3)


def test_oversize_is_reported_not_hidden():
    pad, rep = pad_to_bucket(max(DEFAULT_BUCKETS) + 1, DEFAULT_BUCKETS)
    assert pad == 0
    assert rep["bucketed"] is False
    assert "exceeds" in rep["reason"]


def test_default_buckets_fit_in_a_header():
    """The widest gap is what travels as padding; it must clear ~8 KiB limits."""
    bs = sorted(DEFAULT_BUCKETS)
    widest = max(b - a for a, b in zip(bs, bs[1:]))
    assert widest <= 8192 - 4096, f"widest pad {widest} risks header limits"


# --- dp_delegate -------------------------------------------------------------

def make_local(candidates, classifier="PRIVATE"):
    """Local model stub: classifier verdict, then one candidate per attempt."""
    state = {"i": 0}
    calls = []

    def fn(prompt, system=None):
        calls.append((prompt, system))
        sys_l = (system or "")
        if "GENERAL or PRIVATE" in sys_l:
            return classifier
        if "Rewrite" in sys_l:
            i = min(state["i"], len(candidates) - 1)
            state["i"] += 1
            return candidates[i]
        return "final answer applied to the private situation"

    fn.calls = calls
    return fn


def remote_stub(reply="generic guidance"):
    calls = []

    def fn(prompt, system=None):
        calls.append(prompt)
        return reply

    fn.calls = calls
    return fn


def test_leaky_candidates_never_enter_the_pool():
    """The gate is unchanged: a candidate naming Sarah cannot be selected."""
    local = make_local([
        "How can Sarah recover an unpaid debt?",                   # leaks
        "How does one recover an unpaid personal debt?",           # clear
        "What are options when a private individual owes money?",  # clear
        "What are options when a private individual owes money?",  # duplicate
    ])
    remote = remote_stub()
    result, report = dp_delegate(PRIVATE, local, remote,
                                 epsilon=2.0, candidates=4,
                                 rng=random.Random(3))
    assert "sarah" not in result.sent.lower()
    assert report["pool_cleared"] == 2
    assert remote.calls == [result.sent]


def test_nothing_sent_when_every_candidate_leaks():
    local = make_local(["Sarah owes £4,000 in Truro"] * 4)
    remote = remote_stub()
    try:
        dp_delegate(PRIVATE, local, remote, epsilon=2.0, candidates=4)
        raise AssertionError("should have refused")
    except LeakError:
        pass
    assert remote.calls == []


def test_budget_refusal_happens_before_the_remote_call():
    local = make_local(["How does one recover an unpaid personal debt?"])
    remote = remote_stub()
    led = PrivacyLedger(epsilon_budget=1.0)     # smaller than one send
    try:
        dp_delegate(PRIVATE, local, remote, epsilon=2.0, candidates=1, ledger=led)
        raise AssertionError("should have refused")
    except BudgetError:
        pass
    assert remote.calls == [], "budget refusal must precede transmission"


# --- frontier_chat integration ----------------------------------------------

def run_chat(local, remote, **kw):
    return frontier_chat(PRIVATE, local=local, remote=remote,
                         enable_frontier=True, accept_residual_risks=True, **kw)


def test_receipt_carries_the_dp_report():
    local = make_local(["How does one recover an unpaid personal debt?",
                        "What are options when someone owes you money?"])
    receipt = run_chat(local, remote_stub(), dp_epsilon=2.0, dp_candidates=2)
    assert receipt.dp is not None
    assert receipt.dp["selection_epsilon"] == 2.0
    assert receipt.mode == "abstracted"
    assert any("exponential" in c for c in receipt.claims)
    assert receipt.as_dict()["dp"]["claim"].startswith("the CHOICE")


def test_dp_epsilon_zero_restores_first_past_the_gate():
    local = make_local(["How does one recover an unpaid personal debt?"])
    receipt = run_chat(local, remote_stub(), dp_epsilon=0.0)
    assert receipt.dp is None
    assert receipt.mode == "abstracted"


def test_fast_path_discloses_style_in_the_residual():
    local = make_local([], classifier="GENERAL")
    receipt = frontier_chat("How do I write a decorator?", local=local,
                            remote=remote_stub(), enable_frontier=True,
                            accept_residual_risks=True)
    assert receipt.mode == "general_direct"
    assert any("EXACT phrasing" in r for r in receipt.residual)


def test_budget_exhaustion_surfaces_as_refusal():
    local = make_local(["How does one recover an unpaid personal debt?"])
    led = PrivacyLedger(epsilon_budget=1.0)
    try:
        run_chat(local, remote_stub(), dp_epsilon=2.0, ledger=led)
        raise AssertionError("should have refused")
    except FrontierPrivateError as exc:
        assert "budget" in str(exc)


def test_wire_facts_come_from_the_completer_not_the_caller():
    """A remote that reports bucketing/non-streaming upgrades the claims;
    one that reports nothing leaves them unassessed."""
    local = make_local(["How does one recover an unpaid personal debt?"])

    remote = remote_stub()
    remote.last_wire_length = {"bucketed": True, "bucket_bytes": 2048,
                               "buckets": 4, "length_bits_bound": 2.0}
    remote.response_streaming = False
    receipt = run_chat(local, remote, dp_epsilon=2.0)
    assert receipt.length_channel["bucket_bytes"] == 2048
    assert receipt.response_streaming is False
    assert any("2048-byte" in c for c in receipt.claims)
    assert not any("Whisper Leak" in r for r in receipt.residual), \
        "a non-streamed leg retires the streaming residual"

    local2 = make_local(["How does one recover an unpaid personal debt?"])
    bare = remote_stub()
    receipt2 = run_chat(local2, bare, dp_epsilon=2.0)
    assert receipt2.length_channel is None
    assert receipt2.response_streaming is None
    assert any("Whisper Leak" in r for r in receipt2.residual), \
        "an unassessed leg keeps the streaming residual"


def test_attestation_absence_is_stated():
    local = make_local(["How does one recover an unpaid personal debt?"])
    receipt = run_chat(local, remote_stub(), dp_epsilon=2.0)
    assert receipt.attestation == "none offered"
    assert receipt.as_dict()["attestation"] == "none offered"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok {fn.__name__}")
    print(f"{len(fns)} passed")

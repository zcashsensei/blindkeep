"""Delegated inference: the provider must receive nothing about you.

The abstraction is a model's judgement and will sometimes be wrong. The gate is not, and these
tests are almost entirely about the gate — because a design where privacy depends on a model
behaving well is a design that discloses on the day it does not.

The load-bearing assertion is `test_nothing_is_sent_when_the_gate_refuses`: a leaky abstraction
must reach no remote call at all, not merely be reported afterwards.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blindkeep.delegate import (
    LeakError,
    LeakGate,
    delegate,
    identifying_terms,
)

PRIVATE = ("Sarah Whitfield, my landlord in Truro who breeds Basenjis, "
           "owes me £4,000 since March")


def local_stub(reply):
    """A local model that says whatever the test tells it to."""
    calls = []

    def fn(prompt, system=None):
        calls.append({"prompt": prompt, "system": system})
        return reply(prompt) if callable(reply) else reply

    fn.calls = calls
    return fn


def remote_stub(reply="pay attention to the limitation period and put it in writing"):
    calls = []

    def fn(prompt, system=None):
        calls.append({"prompt": prompt, "system": system})
        return reply

    fn.calls = calls
    return fn


# --- what counts as identifying ---------------------------------------------

def test_names_places_and_amounts_are_identifying():
    terms = identifying_terms(PRIVATE)
    for expected in ("sarah", "whitfield", "truro", "basenjis", "£4,000", "march"):
        assert expected in terms, f"{expected!r} was not treated as identifying: {sorted(terms)}"


def test_ordinary_words_are_not():
    terms = identifying_terms("what are the options for recovering an unpaid debt")
    for ordinary in ("what", "the", "for", "an"):
        assert ordinary not in terms


def test_a_sentence_initial_capital_is_not_a_name():
    """Otherwise every first word would force a rewrite and the gate would be switched off."""
    assert "what" not in identifying_terms("What should I do next?")


def test_numbers_are_always_identifying():
    assert "1987" in identifying_terms("born in 1987")
    assert "42kg" in identifying_terms("weighs 42kg")


# --- the gate ----------------------------------------------------------------

def test_a_clean_abstraction_passes():
    gate = LeakGate().add(PRIVATE)
    gate.check("What are the options for recovering an unpaid debt from a private individual?")


def test_a_surviving_name_is_caught():
    gate = LeakGate().add(PRIVATE)
    try:
        gate.check("How do I get Sarah to pay what she owes?")
    except LeakError as exc:
        assert "sarah" in str(exc).lower()
        return
    raise AssertionError("a name reached the wire")


def test_a_surviving_amount_is_caught():
    gate = LeakGate().add(PRIVATE)
    try:
        gate.check("How do I recover £4,000 from someone?")
    except LeakError as exc:
        assert "4,000" in str(exc) or "£4,000" in str(exc)
        return
    raise AssertionError("an amount reached the wire")


def test_a_copied_phrase_is_caught_even_with_names_removed():
    """The quasi-identifier case pseudonymisation cannot reach.

    Every name is gone and the sentence still identifies one person.
    """
    gate = LeakGate().add(PRIVATE)
    try:
        gate.check("My landlord in a small town who breeds unusual dogs owes me money")
    except LeakError:
        return
    raise AssertionError("a distinguishing phrase survived the gate")


def test_context_is_checked_not_only_the_message():
    """Memory assembled into the prompt leaks exactly like the message does."""
    gate = LeakGate().add("what is my address?", "the user lives at Ridgeway Cottage")
    try:
        gate.check("What should I do about Ridgeway Cottage?")
    except LeakError:
        return
    raise AssertionError("context was not checked")


def test_the_gate_reports_every_reason_not_just_the_first():
    gate = LeakGate().add(PRIVATE)
    problems = gate.leaks("Sarah in Truro owes £4,000")
    assert problems, "no problems reported"
    assert any("identifying terms" in p for p in problems)


# --- the loop ----------------------------------------------------------------

def test_only_the_abstraction_reaches_the_provider():
    local = local_stub("What are the options for recovering an unpaid debt?")
    remote = remote_stub()
    out = delegate(PRIVATE, local, remote)

    sent = remote.calls[0]["prompt"]
    for secret in ("Sarah", "Whitfield", "Truro", "Basenjis", "4,000", "March"):
        assert secret not in sent, f"{secret!r} reached the provider"
    assert out.sent == sent


def test_the_private_context_is_reapplied_locally():
    """The value of the frontier model survives: the answer comes back specific."""
    def local(prompt, system=None):
        if "Rewrite" in (system or ""):
            return "What are the options for recovering an unpaid debt?"
        return "Write to Sarah Whitfield giving 14 days to repay the £4,000."

    out = delegate(PRIVATE, local, remote_stub())
    assert "Sarah Whitfield" in out.reply and "£4,000" in out.reply
    assert "Sarah" not in out.sent


def test_nothing_is_sent_when_the_gate_refuses():
    """The assertion this module exists for: a leak must never reach the network."""
    local = local_stub("How do I get Sarah Whitfield in Truro to pay?")
    remote = remote_stub()
    try:
        delegate(PRIVATE, local, remote, attempts=2)
    except LeakError:
        assert remote.calls == [], "the provider was called despite the refusal"
        return
    raise AssertionError("a leaky abstraction was sent")


def test_a_leaky_attempt_is_retried_before_giving_up():
    """A model that leaks once is told why and asked again — but never lowered to."""
    state = {"n": 0}

    def local(prompt, system=None):
        if "Rewrite" in (system or ""):
            state["n"] += 1
            return ("Get Sarah to pay" if state["n"] == 1
                    else "What are the options for recovering an unpaid debt?")
        return "applied answer"

    remote = remote_stub()
    out = delegate(PRIVATE, local, remote, attempts=3)
    assert out.attempts == 2, f"expected a retry, took {out.attempts}"
    assert len(remote.calls) == 1, "the leaky attempt was also sent"


def test_the_retry_tells_the_model_what_leaked():
    """Otherwise the second attempt is a coin flip rather than a correction."""
    seen = []

    def local(prompt, system=None):
        if "Rewrite" in (system or ""):
            seen.append(prompt)
            return "Sarah owes money" if len(seen) == 1 else "How are debts recovered?"
        return "applied"

    delegate(PRIVATE, local, remote_stub(), attempts=3)
    assert len(seen) == 2 and "still contained private detail" in seen[1], seen


def test_giving_up_is_an_answer_not_a_failure():
    local = local_stub("Sarah Whitfield owes me money")
    try:
        delegate(PRIVATE, local, remote_stub(), attempts=2)
    except LeakError as exc:
        assert "Nothing was sent" in str(exc)
        assert "local model" in str(exc), "the refusal should name the alternative"
        return
    raise AssertionError("no refusal")


def test_the_result_states_what_the_provider_still_learned():
    """Confidentiality of content is not unlinkability of interest, and the object says so."""
    local = local_stub("How are unpaid debts recovered?")
    out = delegate(PRIVATE, local, remote_stub())
    assert out.as_dict()["private"] is True
    assert "roughly what about" in out.as_dict()["notice"]


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

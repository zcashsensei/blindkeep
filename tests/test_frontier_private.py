"""Maximum-effort frontier path: content gate + honest non-claims."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blindkeep.delegate import LeakError
from blindkeep.frontier_private import (
    FrontierPrivateError,
    frontier_chat,
)


PRIVATE = ("Sarah Whitfield, my landlord in Truro who breeds Basenjis, "
           "owes me £4,000 — what should I do?")


def local_stub(mapper):
    calls = []

    def fn(prompt, system=None):
        calls.append((prompt, system))
        if callable(mapper):
            return mapper(prompt, system)
        return mapper

    fn.calls = calls
    return fn


def remote_stub(reply="generic legal guidance about unpaid debts"):
    calls = []

    def fn(prompt, system=None):
        calls.append(prompt)
        return reply

    fn.calls = calls
    return fn


def test_opt_in_is_mandatory():
    try:
        frontier_chat("hi", local=local_stub("x"), remote=remote_stub(),
                      enable_frontier=False, accept_residual_risks=True)
        raise AssertionError("should refuse")
    except FrontierPrivateError as exc:
        assert "enable_frontier" in str(exc)


def test_residual_ack_is_mandatory():
    try:
        frontier_chat("hi", local=local_stub("x"), remote=remote_stub(),
                      enable_frontier=True, accept_residual_risks=False)
        raise AssertionError("should refuse")
    except FrontierPrivateError as exc:
        assert "accept_residual" in str(exc)


def test_private_facts_do_not_reach_remote():
    """The load-bearing property: remote sees only the abstraction."""

    def local(prompt, system=None):
        sys_l = (system or "").lower()
        if "rewrite" in sys_l or "general question" in sys_l:
            return "What are options for recovering unpaid debt from a private individual?"
        if "general guidance" in prompt.lower() or "apply the guidance" in sys_l:
            return "Sarah in Truro is owed £4,000 — put the claim in writing."
        # classifier
        return "PRIVATE"

    remote = remote_stub()
    receipt = frontier_chat(
        PRIVATE,
        local=local,
        remote=remote,
        enable_frontier=True,
        accept_residual_risks=True,
    )
    assert remote.calls, "remote should have been called once"
    sent = remote.calls[0]
    for banned in ("Sarah", "Whitfield", "Truro", "Basenjis", "4000", "£4,000"):
        assert banned not in sent, f"{banned!r} leaked to remote: {sent!r}"
    d = receipt.as_dict()
    assert d["identity_private"] is False
    assert d["metadata_private"] is False
    assert d["content_private"] is True
    assert "Sarah" in receipt.reply  # re-specialised locally
    assert receipt.mode == "abstracted"


def test_leaky_abstraction_sends_nothing():
    def local(prompt, system=None):
        # Always "abstract" to something that still names Sarah
        if "guidance" in (prompt or "").lower():
            return "answer"
        return "What should Sarah Whitfield do about the debt in Truro?"

    remote = remote_stub()
    try:
        frontier_chat(
            PRIVATE,
            local=local,
            remote=remote,
            enable_frontier=True,
            accept_residual_risks=True,
            # force abstract path: classifier says private / no general
        )
        raise AssertionError("leaky path should refuse")
    except FrontierPrivateError:
        pass
    assert remote.calls == [], "remote must not be called when the gate refuses"


def test_receipt_lists_residual_risks():
    def local(prompt, system=None):
        if "rewrite" in (system or "").lower():
            return "How do I recover a private debt?"
        if "guidance" in (prompt or "").lower():
            return "put it in writing"
        return "PRIVATE"

    r = frontier_chat(
        PRIVATE,
        local=local,
        remote=remote_stub(),
        enable_frontier=True,
        accept_residual_risks=True,
    )
    joined = " ".join(r.residual).lower()
    assert "api key" in joined or "account" in joined
    assert any("claim" in c.lower() or "fact" in c.lower() for c in r.claims)


def test_empty_question_refused():
    try:
        frontier_chat("  ", local=local_stub("x"), remote=remote_stub(),
                      enable_frontier=True, accept_residual_risks=True)
        raise AssertionError("empty should refuse")
    except FrontierPrivateError:
        pass


def run():
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = []
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except Exception as exc:
            failed.append(name)
            print(f"  FAIL  {name}: {exc}")
    print(f"\n{len(tests) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())

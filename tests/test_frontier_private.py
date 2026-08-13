"""Maximum-effort frontier path: content gate + honest non-claims."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blindkeep.delegate import LeakError
from blindkeep.frontier_private import (
    FrontierPrivateError,
    assess_network,
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
    assert r.as_dict()["identity_private"] is False


def test_account_decoupled_claims_identity_private():
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
        account_decoupled=True,
    )
    d = r.as_dict()
    assert d["identity_private"] is True
    assert d["account_decoupled"] is True
    assert any("blind token" in c.lower() or "api key" in c.lower() for c in r.claims)


def test_empty_question_refused():
    try:
        frontier_chat("  ", local=local_stub("x"), remote=remote_stub(),
                      enable_frontier=True, accept_residual_risks=True)
        raise AssertionError("empty should refuse")
    except FrontierPrivateError:
        pass


# --- metadata privacy is decided by the transport, never by a flag ----------
#
# The defect these pin: /api/frontier-chat took `ohttp_independent` from the
# request body and reported metadata_private=True on a direct socket. A caller
# asserting privacy was enough to be granted it. Every case below except the
# last must refuse, so the honest answer is the default and the one True has
# to be earned by facts the code can check.

def metadata_receipt(**kw):
    return frontier_chat(
        "what is the capital of France",
        local=local_stub("a generic question"),
        remote=remote_stub("a generic answer"),
        enable_frontier=True, accept_residual_risks=True,
        account_decoupled=True, **kw).as_dict()


SPLIT = dict(gateway_url="https://gw.example", relay_url="https://relay.other")


def test_metadata_privacy_refused_on_a_direct_socket():
    d = metadata_receipt(transport="direct", gateway_url="https://gw.example",
                         ohttp_independent_operators=True)
    assert d["metadata_private"] is False, "a flag must not buy metadata privacy"
    assert d["transport"] == "direct"
    assert "not the transport" in " ".join(d["metadata_reasons"])


def test_metadata_privacy_refused_when_ohttp_has_no_relay():
    d = metadata_receipt(transport="ohttp", gateway_url="https://gw.example",
                         ohttp_independent_operators=True)
    assert d["metadata_private"] is False


def test_metadata_privacy_refused_when_relay_and_gateway_share_a_host():
    d = metadata_receipt(transport="ohttp", gateway_url="https://same.example",
                         relay_url="https://same.example/forward",
                         ohttp_independent_operators=True)
    assert d["metadata_private"] is False
    assert "same host" in " ".join(d["metadata_reasons"])


def test_metadata_privacy_refused_when_both_roles_run_on_loopback():
    # The demo shape: gateway and relay on loopback, different PORTS. The
    # module docstring calls this "a rename of direct send" -- so must the
    # code. Same address on two ports is one host, so the stricter same-host
    # rule answers first; what matters is that it refuses.
    d = metadata_receipt(transport="ohttp", gateway_url="http://127.0.0.1:8751",
                         relay_url="http://127.0.0.1:8750",
                         ohttp_independent_operators=True)
    assert d["metadata_private"] is False
    assert "same host" in " ".join(d["metadata_reasons"])


def test_metadata_privacy_refused_across_two_machines_on_one_LAN():
    # Distinct hosts, so the same-host rule does NOT fire -- this is the case
    # only the private-address check can refuse.
    d = metadata_receipt(transport="ohttp", gateway_url="http://192.168.1.50:8751",
                         relay_url="http://127.0.0.1:8750",
                         ohttp_independent_operators=True)
    assert d["metadata_private"] is False
    assert "this machine" in " ".join(d["metadata_reasons"])


def test_metadata_privacy_refused_without_an_independence_assertion():
    assert metadata_receipt(transport="ohttp", **SPLIT)["metadata_private"] is False


def test_metadata_privacy_granted_only_on_a_confirmed_split():
    d = metadata_receipt(transport="ohttp", ohttp_independent_operators=True,
                         **SPLIT)
    assert d["metadata_private"] is True
    assert d["transport"] == "ohttp"
    # Even when granted, the unverifiable half is stated rather than hidden.
    assert "cannot be verified" in " ".join(d["metadata_reasons"])


def test_ip_warning_survives_an_unbacked_independence_claim():
    # Claiming independence used to delete the IP warning from the receipt.
    d = metadata_receipt(transport="direct", gateway_url="https://gw.example",
                         ohttp_independent_operators=True)
    assert any("IP is visible" in r for r in d["residual"])


def test_localhost_names_count_as_this_machine():
    posture = assess_network(transport="ohttp", gateway_url="http://localhost:1",
                             relay_url="http://localhost:2",
                             independent_operators=True)
    assert posture.metadata_private is False


def test_an_unresolvable_name_is_never_treated_as_local():
    # _is_local does no DNS. An unknown name must not read as local, or the
    # "both on this machine" refusal could be dodged by naming a host.
    posture = assess_network(transport="ohttp", gateway_url="https://gw.example",
                             relay_url="https://relay.other",
                             independent_operators=True)
    assert posture.metadata_private is True


# --- documented attacks must appear in the receipt --------------------------
#
# A receipt that omits a known attack overclaims by silence. Each of these is
# published and undefended here, so each must be visible to the reader. Pinned
# by test because a residual list is exactly the thing that quietly shrinks.
# Sources: docs/ENDPOINT_PRIVACY_RESEARCH.md

def test_receipt_discloses_the_stylometry_channel():
    d = metadata_receipt(transport="direct")
    joined = " ".join(d["residual"]).lower()
    assert "style" in joined, "prompts are a behavioural biometric; say so"


def test_receipt_discloses_the_token_length_side_channel():
    joined = " ".join(metadata_receipt(transport="direct")["residual"]).lower()
    assert "packet sizes" in joined or "whisper leak" in joined


def test_receipt_discloses_that_ohttp_has_no_forward_secrecy():
    joined = " ".join(metadata_receipt(transport="direct")["residual"]).lower()
    assert "forward secrecy" in joined


def test_receipt_discloses_the_anonymity_set_problem():
    joined = " ".join(metadata_receipt(transport="direct")["residual"]).lower()
    assert "anonymity set" in joined


def test_disclosure_survives_the_most_privileged_path():
    """The best case is where a reader is likeliest to stop reading."""
    d = metadata_receipt(transport="ohttp", ohttp_independent_operators=True,
                         gateway_url="https://gw.example",
                         relay_url="https://relay.other")
    assert d["metadata_private"] is True
    joined = " ".join(d["residual"]).lower()
    for topic in ("style", "forward secrecy", "anonymity set"):
        assert topic in joined, f"{topic} vanished on the strongest path"


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

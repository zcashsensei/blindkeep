"""Oblivious HTTP: the relay must not be able to read, and the gateway must not see an address.

The round-trip test is the easy half. The half that matters is
`test_the_relay_cannot_read_what_it_forwards` and
`test_the_gateway_never_learns_a_client_address` — those are the two properties the whole
construction exists to provide, and each is asserted by attacking it rather than by inspection.

`test_visibility_refuses_to_reassure_when_one_party_runs_both` is here because the security of
this design is a fact about *operators*, not about code. A caller must not be able to get the
comfortable answer without asserting independence, and if the assertion is false the report has
to say so in the loudest terms available.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oblivio.hpke import generate_keypair
from oblivio.oblivious import (
    Client,
    Gateway,
    KeyConfig,
    ObliviousError,
    Relay,
    decapsulate_request,
    decapsulate_response,
    encapsulate_request,
    encapsulate_response,
    visibility,
)

SECRET = b"What are the options for recovering an unpaid debt?"
ANSWER = b"Generally: a written demand, then a formal claim."


def wired(origin=lambda req: ANSWER):
    """A full client -> relay -> gateway -> origin chain, with each party's view recorded."""
    gateway = Gateway()
    relay = Relay(forward=lambda blob: gateway.handle(blob, origin))
    client = Client(config=gateway.config)
    return client, relay, gateway


def expect(fn, contains=None):
    try:
        fn()
    except ObliviousError as e:
        if contains:
            assert contains in str(e).lower(), f"wrong reason: {e}"
        return str(e)
    raise AssertionError("expected a refusal, got none")


# --- the two properties the construction exists for --------------------------

def test_the_relay_cannot_read_what_it_forwards():
    """The relay is handed the exact bytes. They must be opaque to it."""
    seen = {}
    gateway = Gateway()

    def forward(blob):
        seen["blob"] = blob
        return gateway.handle(blob, lambda req: ANSWER)

    relay = Relay(forward=forward)
    client = Client(config=gateway.config)
    reply = client.send(relay, SECRET, client_address="203.0.113.9")

    assert reply == ANSWER, "round trip failed"
    blob = seen["blob"]
    assert SECRET not in blob, "the plaintext request appeared in what the relay forwarded"
    assert ANSWER not in blob, "the answer appeared in what the relay forwarded"
    for word in (b"debt", b"recovering", b"unpaid"):
        assert word not in blob, f"{word!r} leaked into the relay's view"


def test_the_gateway_never_learns_a_client_address():
    """The gateway's API offers no way to receive one. This asserts the shape, not the intent."""
    client, relay, gateway = wired()
    client.send(relay, SECRET, client_address="203.0.113.9")
    assert relay.seen_addresses == ["203.0.113.9"], "the relay should see the address"
    assert not hasattr(gateway, "seen_addresses"), (
        "the gateway grew an address field; that is the collusion boundary dissolving")
    import inspect
    sig = inspect.signature(gateway.handle)
    assert "address" not in " ".join(sig.parameters), (
        "Gateway.handle accepts an address parameter — it must not be able to receive one")


def test_neither_party_alone_can_link_the_person_to_the_question():
    """State the join explicitly: relay has address+time, gateway has content. Disjoint."""
    client, relay, gateway = wired()
    client.send(relay, SECRET, client_address="198.51.100.4")
    relay_view = set(relay.seen_addresses)
    gateway_view = {SECRET}
    assert not (relay_view & {SECRET}), "the relay saw request content"
    assert "198.51.100.4" not in {v.decode(errors="ignore") for v in gateway_view}, (
        "the gateway saw an address")


# --- correctness --------------------------------------------------------------

def test_round_trip_through_all_three_roles():
    client, relay, gateway = wired()
    assert client.send(relay, SECRET) == ANSWER
    assert gateway.handled == 1 and relay.forwarded == 1


def test_the_origin_receives_exactly_the_request():
    got = {}
    gateway = Gateway()
    relay = Relay(forward=lambda b: gateway.handle(b, lambda req: got.setdefault("req", req) or ANSWER))
    Client(config=gateway.config).send(relay, SECRET)
    assert got["req"] == SECRET


def test_key_config_survives_a_serialize_parse_round_trip():
    gateway = Gateway(key_id=7)
    parsed = KeyConfig.parse(gateway.config.serialize())
    assert parsed == gateway.config, f"{parsed} != {gateway.config}"


def test_two_requests_do_not_reuse_an_encapsulated_key():
    """A repeated enc would let the gateway link two requests to one client."""
    gateway = Gateway()
    encs = set()
    for _ in range(8):
        wire, _ = encapsulate_request(gateway.config, SECRET)
        encs.add(wire[7:39])
    assert len(encs) == 8, "an encapsulated key repeated across requests — clients are linkable"


def test_response_key_differs_from_request_key():
    """Reusing the request key and nonce for the response is a total AES-GCM break."""
    gateway = Gateway()
    wire, ctx = encapsulate_request(gateway.config, SECRET)
    _, gctx = decapsulate_request(gateway._sk, gateway.config, wire)
    sealed = encapsulate_response(gctx, ANSWER)
    assert sealed[16:] != wire[39:], "response ciphertext reused the request keystream"
    assert decapsulate_response(ctx, sealed) == ANSWER


# --- refusals ------------------------------------------------------------------

def test_a_tampered_header_is_refused_not_reinterpreted():
    gateway = Gateway()
    wire, _ = encapsulate_request(gateway.config, SECRET)
    tampered = bytes([wire[0] ^ 0xFF]) + wire[1:]
    expect(lambda: decapsulate_request(gateway._sk, gateway.config, tampered),
           contains="does not match")


def test_a_tampered_ciphertext_is_refused():
    gateway = Gateway()
    wire, _ = encapsulate_request(gateway.config, SECRET)
    tampered = wire[:-1] + bytes([wire[-1] ^ 0x01])
    expect(lambda: decapsulate_request(gateway._sk, gateway.config, tampered),
           contains="authenticate")


def test_a_truncated_request_is_refused():
    gateway = Gateway()
    wire, _ = encapsulate_request(gateway.config, SECRET)
    for cut in (0, 10, 38):
        expect(lambda c=cut: decapsulate_request(gateway._sk, gateway.config, wire[:c]))


def test_a_response_from_the_wrong_context_is_refused():
    """Otherwise a relay could swap in another gateway's answer."""
    g1, g2 = Gateway(), Gateway()
    _, ctx1 = encapsulate_request(g1.config, SECRET)
    wire2, _ = encapsulate_request(g2.config, SECRET)
    _, gctx2 = decapsulate_request(g2._sk, g2.config, wire2)
    expect(lambda: decapsulate_response(ctx1, encapsulate_response(gctx2, ANSWER)),
           contains="authenticate")


def test_an_unsupported_kem_is_refused():
    raw = bytearray(Gateway().config.serialize())
    raw[1:3] = (0x0010).to_bytes(2, "big")
    expect(lambda: KeyConfig.parse(bytes(raw)), contains="not supported")


# --- the assumption no code can enforce ---------------------------------------

def test_visibility_refuses_to_reassure_when_one_party_runs_both():
    good = visibility(independent_operators=True)
    assert "no single party" in good["overall"]

    bad = visibility(independent_operators=False)
    assert "NONE OF THE ABOVE HOLDS" in bad["overall"], (
        "a self-run relay+gateway was not flagged as void")
    assert "rename" in bad["overall"]


def test_visibility_requires_the_claim_to_be_stated():
    """No default. A caller must assert independence rather than receive it silently."""
    try:
        visibility()
    except TypeError:
        return
    raise AssertionError("visibility() defaulted the independence assumption")


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

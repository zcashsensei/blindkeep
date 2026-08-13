"""/api/frontier-chat end to end: client -> OHTTP relay -> gateway -> provider.

Why this suite exists
---------------------
The endpoint accepted `ohttp_independent` from the request body and reported
`metadata_private: true` on the strength of it, while calling the gateway over
a direct socket -- `make_gateway_remote` was never passed `use_ohttp`, so the
OHTTP transport the repo ships was unreachable from the product. The library
had the capability; the endpoint did not use it and claimed it anyway.

A unit test on the receipt cannot see that: the receipt was internally
consistent with the flag it was handed. Only driving the HTTP surface with real
relay and gateway processes shows which socket carried the request.

The strongest check here is `test_the_client_never_contacts_the_gateway`, which
points the client's `gateway_url` at a CLOSED port while the relay forwards to
the live gateway. If the call still succeeds, the client provably never opened
a connection to the gateway -- that is the whole point of an IP split, proven
by construction rather than asserted.

Everything runs on loopback, so `metadata_private` is expected to stay FALSE
throughout. Two roles on one machine is one operator, which the module docstring
calls "a rename of direct send". A suite that ran both halves locally and then
asserted metadata privacy would be reproducing the defect it is meant to catch.
"""

import json
import os
import pathlib
import shutil
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from blindkeep import frontier_private
from blindkeep.anon_token import issue
from blindkeep.frontier_gateway import FrontierGateway, serve_gateway
from blindkeep.frontier_relay import serve_relay

APP_PORT = 8803
GW_PORT = 8804
RELAY_PORT = 8805
DEAD_PORT = 8806          # deliberately nothing listening here

SERVERS = []
TMPDIRS = []

app = None
gw = None
GW_URL = f"http://127.0.0.1:{GW_PORT}"
RELAY_URL = f"http://127.0.0.1:{RELAY_PORT}"
OHTTP_CONFIG = ""
HITS = {"ohttp": 0, "json": 0}


def _boot():
    global app, gw, OHTTP_CONFIG
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="blindkeep-frontier-"))
    TMPDIRS.append(str(tmp))

    # --- gateway: holds the "provider credential", never calls a real one ---
    gw = FrontierGateway(api_base="http://provider.invalid", api_key="sk-TEST")
    gw.complete = lambda prompt, model=None, system=None: f"answer:{prompt}"

    # Count which surface served each request. The client is supposed to reach
    # /ohttp only; /v1/complete being hit would mean a direct send.
    raw_ohttp, raw_json = gw.handle_ohttp, gw.handle_json

    def counted_ohttp(data):
        HITS["ohttp"] += 1
        return raw_ohttp(data)

    def counted_json(body, token_header):
        HITS["json"] += 1
        return raw_json(body, token_header)

    gw.handle_ohttp, gw.handle_json = counted_ohttp, counted_json

    gw_httpd = serve_gateway(gw, host="127.0.0.1", port=GW_PORT)
    threading.Thread(target=gw_httpd.serve_forever, daemon=True).start()
    SERVERS.append(gw_httpd)

    OHTTP_CONFIG = gw.public_params()["ohttp_key_config_b64"]

    # --- relay: forwards opaque bytes, holds no keys ---
    relay_httpd = serve_relay(GW_URL + "/ohttp", host="127.0.0.1",
                              port=RELAY_PORT)
    threading.Thread(target=relay_httpd.serve_forever, daemon=True).start()
    SERVERS.append(relay_httpd)

    # --- local model: stubbed, so the suite needs no Ollama install ---
    # Two jobs, as the real path has: abstract the question on the way out,
    # then re-specialise the provider's answer on the way back. The marker on
    # the second lets a test prove the gateway's reply really came home.
    def local_stub(prompt, system=None):
        if "answer:" in prompt:
            return "specialised locally from the gateway reply"
        return "a generic question about a general topic"

    frontier_private.make_ollama_local = lambda base, model: local_stub

    # --- the app itself, pointed entirely at the temp dir ---
    import app as _app
    app = _app
    app.PORT = APP_PORT
    app.KEY_PATH = tmp / "master.key"
    app.KEY_SEALED_PATH = tmp / "master.key.sealed"
    app.PIN_PATH = tmp / "pin.json"
    app.CAT_PATH = tmp / "catalogue.json"
    app.POLICY_PATH = tmp / "policy.json"
    app.ensure_node = lambda: (True, "test")

    httpd = ThreadingHTTPServer(("127.0.0.1", APP_PORT), app.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    SERVERS.append(httpd)
    time.sleep(0.4)


def token_blob():
    """A fresh single-use blind token; the gateway redeems each one once."""
    tok = issue(gw.issuer)
    return {"token_hex": tok.value_hex, "signature_hex": tok.signature_hex}


def chat(**overrides):
    body = {
        "text": "what is a reasonable notice period",
        "model": "test-model",
        "enable_frontier": True,
        "accept_residual_risks": True,
        "gateway_url": GW_URL,
        "token": token_blob(),
    }
    body.update(overrides)
    data = json.dumps(body).encode()
    r = urllib.request.Request(f"http://127.0.0.1:{APP_PORT}/api/frontier-chat",
                               data=data, method="POST")
    r.add_header("X-Blindkeep-Token", app.TOKEN)
    r.add_header("Host", "127.0.0.1")
    r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, json.loads(resp.read() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or "{}")


# --- the defect itself ------------------------------------------------------


def test_a_direct_send_cannot_claim_metadata_privacy():
    """The original bug, at the endpoint that had it."""
    code, d = chat(ohttp_independent=True)          # no relay_url
    assert code == 200, d
    assert d["transport"] == "direct", d
    assert d["metadata_private"] is False, "a request-body flag bought privacy"
    assert "not the transport" in " ".join(d["metadata_reasons"]), d


def test_the_endpoint_can_actually_speak_ohttp():
    """Wiring, not just honesty: the transport must be REACHABLE from the app."""
    before = HITS["ohttp"]
    code, d = chat(relay_url=RELAY_URL, ohttp_config=OHTTP_CONFIG)
    assert code == 200, d
    assert d["transport"] == "ohttp", d
    assert HITS["ohttp"] == before + 1, "the gateway's OHTTP surface never ran"
    # The gateway's answer travelled back through the relay and was then
    # re-specialised on this machine -- the whole round trip, not just the send.
    assert d["reply"] == "specialised locally from the gateway reply", d


def test_the_client_never_contacts_the_gateway():
    """Point gateway_url at a closed port; the relay still reaches the gateway.

    Success here is only possible if the client's socket went to the relay and
    nowhere else -- an IP split proven by construction.
    """
    before = HITS["ohttp"]
    code, d = chat(gateway_url=f"http://127.0.0.1:{DEAD_PORT}",
                   relay_url=RELAY_URL, ohttp_config=OHTTP_CONFIG)
    assert code == 200, f"client tried to reach the gateway directly: {d}"
    assert HITS["ohttp"] == before + 1, d
    assert d["transport"] == "ohttp", d


def test_the_direct_gateway_surface_is_never_touched_over_ohttp():
    before = HITS["json"]
    chat(relay_url=RELAY_URL, ohttp_config=OHTTP_CONFIG)
    assert HITS["json"] == before, "request arrived on the plaintext surface"


# --- honesty on the loopback deployment this suite actually runs ------------


def test_two_local_roles_still_refuse_to_claim_metadata_privacy():
    code, d = chat(relay_url=RELAY_URL, ohttp_config=OHTTP_CONFIG,
                   ohttp_independent=True)
    assert code == 200, d
    assert d["transport"] == "ohttp", d
    assert d["metadata_private"] is False, "one operator on loopback is not a split"
    # Relay and gateway share the address 127.0.0.1 -- two ports on one host --
    # so the same-host rule answers before the private-address one.
    assert "same host" in " ".join(d["metadata_reasons"]), d


def test_the_ip_warning_survives_a_local_ohttp_run():
    _, d = chat(relay_url=RELAY_URL, ohttp_config=OHTTP_CONFIG,
                ohttp_independent=True)
    assert any("IP is visible" in r for r in d["residual"]), d


# --- incomplete OHTTP setup is refused, not silently downgraded -------------


def test_a_relay_without_a_key_config_is_refused():
    """Silently falling back to a direct send is how the claim drifted before."""
    code, d = chat(relay_url=RELAY_URL)
    assert code == 400, d
    assert "ohttp_config" in json.dumps(d)


def test_a_relay_without_a_gateway_is_refused():
    code, d = chat(relay_url=RELAY_URL, ohttp_config=OHTTP_CONFIG,
                   gateway_url="")
    assert code == 400, d


def test_the_account_stays_decoupled_on_every_path():
    """The client presents a blind token; it never holds the provider key."""
    _, d = chat(relay_url=RELAY_URL, ohttp_config=OHTTP_CONFIG)
    assert d["identity_private"] is True, d
    assert "sk-TEST" not in json.dumps(d), "the gateway's API key reached the client"


def _cleanup():
    for httpd in SERVERS:
        try:
            httpd.shutdown()
            httpd.server_close()
        except Exception:
            pass
    for d in TMPDIRS:
        shutil.rmtree(d, ignore_errors=True)


def run():
    _boot()
    try:
        tests = [(k, v) for k, v in sorted(globals().items())
                 if k.startswith("test_")]
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
    finally:
        _cleanup()


if __name__ == "__main__":
    raise SystemExit(run())

"""Account-decoupled gateway: client holds no API key; blind token redeems once."""

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blindkeep.anon_token import Client, Issuer, Token, issue
from blindkeep.frontier_gateway import (
    FrontierGateway,
    GatewayError,
    make_gateway_remote,
    serve_gateway,
)
from blindkeep.frontier_private import frontier_chat


def test_gateway_redeems_token_once():
    gw = FrontierGateway(api_base="http://example.invalid", api_key="sk-test")
    # Don't call cloud — override complete
    gw.complete = lambda prompt, model=None, system=None: f"echo:{prompt}"  # type: ignore
    tok = issue(gw.issuer)
    hdr = f"{tok.value_hex}.{tok.signature_hex}"
    out = gw.handle_json({"prompt": "generic question about debt"}, hdr)
    assert out["reply"].startswith("echo:")
    try:
        gw.handle_json({"prompt": "again"}, hdr)
        raise AssertionError("replay should fail")
    except GatewayError as exc:
        assert "spent" in str(exc).lower() or "already" in str(exc).lower()


def test_forged_token_refused():
    gw = FrontierGateway(api_base="http://example.invalid", api_key="sk-test")
    gw.complete = lambda *a, **k: "nope"  # type: ignore
    try:
        gw.handle_json({"prompt": "x"}, "00" * 32 + "." + "11" * 64)
        raise AssertionError("forgery accepted")
    except GatewayError:
        pass


def test_client_path_holds_no_api_key():
    """Historic property: remote completer never needs a provider key."""
    gw = FrontierGateway(api_base="http://example.invalid", api_key="sk-secret-never-on-client")
    seen = []

    def complete(prompt, model=None, system=None):
        seen.append(prompt)
        return "guidance"

    gw.complete = complete  # type: ignore
    httpd = serve_gateway(gw, host="127.0.0.1", port=0)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        tok = issue(gw.issuer)
        remote = make_gateway_remote(
            f"http://127.0.0.1:{port}", tok, model="m")
        # Local always abstracts to a clean generic string
        def local(prompt, system=None):
            s = (system or "").lower()
            if "rewrite" in s or "general question" in s:
                return "What are options for recovering unpaid private debt?"
            if "guidance" in (prompt or "").lower() or "apply" in s:
                return "Sarah should put the claim in writing."
            return "PRIVATE"

        receipt = frontier_chat(
            "Sarah Whitfield in Truro owes me £4000",
            local=local,
            remote=remote,
            enable_frontier=True,
            accept_residual_risks=True,
            account_decoupled=True,
        )
        assert receipt.account_decoupled is True
        assert receipt.as_dict()["identity_private"] is True
        assert "Sarah" not in seen[0]
        assert "Sarah" in receipt.reply
    finally:
        httpd.shutdown()


def test_public_params_expose_issuer_not_api_key():
    gw = FrontierGateway(api_base="https://api.x.ai", api_key="sk-secret")
    p = gw.public_params()
    assert "issuer_n_hex" in p
    assert "sk-secret" not in json.dumps(p)
    assert "api_key" not in p


def run():
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = []
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except Exception as exc:
            failed.append(name)
            print(f"  FAIL  {name}: {type(exc).__name__}: {exc}")
    print(f"\n{len(tests) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())

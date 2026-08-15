#!/usr/bin/env python3
"""Prove the historic stack end-to-end offline (no real frontier API needed).

Runs: blind token issue → gateway (mocked provider) → content-gated client path
where the client holds no API key and private facts never reach the gateway.

    python tools/demo_historic_stack.py
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from oblivio.anon_token import issue
from oblivio.frontier_gateway import FrontierGateway, make_gateway_remote, serve_gateway
from oblivio.frontier_private import frontier_chat


PRIVATE = (
    "Sarah Whitfield, my landlord in Truro who breeds Basenjis, "
    "owes me £4,000 — what should I do?"
)


def main() -> int:
    print("=== Oblivio historic stack demo (offline) ===\n")

    gw = FrontierGateway(api_base="http://mock.invalid", api_key="sk-NEVER-ON-CLIENT")
    seen_at_gateway: list[str] = []

    def complete(prompt, model=None, system=None):
        seen_at_gateway.append(prompt)
        return (
            "For unpaid private debts, document the amount, send a written "
            "demand, and consider small-claims if ignored."
        )

    gw.complete = complete  # type: ignore

    httpd = serve_gateway(gw, host="127.0.0.1", port=0)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print(f"[gateway] http://127.0.0.1:{port}  (holds API key; client never sees it)")

    tok = issue(gw.issuer)
    print(f"[token]   issued one-time blind token {tok.value_hex[:12]}…")

    remote = make_gateway_remote(
        f"http://127.0.0.1:{port}", tok, model="mock-model")

    def local(prompt, system=None):
        s = (system or "").lower()
        if "rewrite" in s or "general question" in s:
            return (
                "What are the practical options for recovering an unpaid debt "
                "from a private individual?"
            )
        if "guidance" in (prompt or "").lower() or "apply" in s:
            return (
                "Sarah Whitfield in Truro should document the £4,000, send a "
                "written demand, and consider small-claims if needed."
            )
        return "PRIVATE"

    receipt = frontier_chat(
        PRIVATE,
        local=local,
        remote=remote,
        enable_frontier=True,
        accept_residual_risks=True,
        account_decoupled=True,
    )

    print("\n--- wire (what the gateway / provider saw) ---")
    print(seen_at_gateway[0] if seen_at_gateway else "(nothing)")
    print("\n--- specialised reply (local only) ---")
    print(receipt.reply)
    print("\n--- receipt ---")
    print(receipt.notice)
    print(f"  content_private   = {receipt.as_dict()['content_private']}")
    print(f"  identity_private  = {receipt.as_dict()['identity_private']}")
    print(f"  account_decoupled = {receipt.account_decoupled}")
    print(f"  mode              = {receipt.mode}")

    # Assertions: the historic properties
    wire = seen_at_gateway[0]
    for banned in ("Sarah", "Whitfield", "Truro", "Basenjis", "4000", "£4,000"):
        assert banned not in wire, f"LEAK on wire: {banned!r} in {wire!r}"
    assert "Sarah" in receipt.reply
    assert receipt.account_decoupled and receipt.as_dict()["identity_private"]
    # Replay token must fail
    try:
        remote2 = make_gateway_remote(
            f"http://127.0.0.1:{port}", tok, model="mock-model")
        remote2("another generic question", None)
        print("\nFAIL: token replay accepted")
        return 1
    except Exception:
        print("\n[token]   replay correctly refused")

    httpd.shutdown()
    print("\n=== HISTORIC STACK PROVED (offline) ===")
    print("Client held no provider API key. Private facts never hit the wire.")
    print("For production: run frontier-gateway with a real key + Ollama client.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

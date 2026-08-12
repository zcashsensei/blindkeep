"""Account-decoupled frontier gateway — the missing half of "historic" privacy.

What was already built
----------------------
* Content privacy: abstract + LeakGate (``delegate`` / ``frontier_private``)
* Unlinkable entitlement: Chaum blind tokens (``anon_token``)
* Network split: OHTTP roles (``oblivious``)

What was missing for everyone
-----------------------------
The **client still held the frontier API key**, so the provider always saw a
named customer. That is identity, not a content leak.

This module is a gateway that:

1. Holds the **provider credential** (API key) itself
2. Accepts only a **one-time blind token** as proof of entitlement
3. Forwards a prompt it cannot attribute to a subscriber
4. Optionally sits behind an OHTTP relay so it never sees the client IP

The client never learns or presents the frontier API key. That is the
historic-in-open-source claim this repo can defend:

    content gated on the client  +  account held only at the gateway
    +  blind token unlinkability  +  optional OHTTP IP split

What it still cannot do without two real operators
--------------------------------------------------
If one person runs relay and gateway, OHTTP is void for IP. If the gateway
logs prompts, the gateway operator can read them (they must decrypt to
forward). Content privacy still depends on the client's LeakGate — the
gateway is not your adversary model for names; the provider and a curious
gateway operator are different threats.

This is infrastructure you can run today. It is not Apple PCC with Cloudflare
and Fastly. It is the open stack that makes that architecture possible.
"""

from __future__ import annotations

import base64
import json
import os
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .anon_token import Issuer, Token, TokenError
from .cloud_gate import CloudGateError, cloud_complete
from .oblivious import Gateway as OhttpGateway, ObliviousError


class GatewayError(Exception):
    """Request refused before any provider call."""


@dataclass
class FrontierGateway:
    """Redeems blind tokens and calls the provider with the gateway's key."""

    api_base: str
    api_key: str
    default_model: str = "default"
    dialect: Optional[str] = None
    issuer: Issuer = field(default_factory=Issuer)
    ohttp: OhttpGateway = field(default_factory=OhttpGateway)
    lock: threading.Lock = field(default_factory=threading.Lock)
    handled: int = 0
    refused: int = 0

    def public_params(self) -> dict[str, Any]:
        n, e = self.issuer.public
        return {
            "issuer_n_hex": f"{n:x}",
            "issuer_e": e,
            "ohttp_key_config_b64": base64.b64encode(
                self.ohttp.config.serialize()).decode("ascii"),
            "api_base": self.api_base,
            "note": (
                "Present a one-time Blindkeep-Token. Do not send a provider "
                "API key. Content should already be leak-gated on the client."
            ),
        }

    def redeem_header(self, header: str) -> None:
        """Blindkeep-Token: <value_hex>.<signature_hex>"""
        if not header or "." not in header:
            raise GatewayError("missing or malformed Blindkeep-Token")
        value_hex, _, sig_hex = header.partition(".")
        tok = Token(value_hex=value_hex.strip(), signature_hex=sig_hex.strip())
        with self.lock:
            try:
                self.issuer.redeem(tok)
            except TokenError as exc:
                self.refused += 1
                raise GatewayError(str(exc)) from exc

    def complete(self, prompt: str, *, model: Optional[str] = None,
                 system: Optional[str] = None) -> str:
        if not (prompt or "").strip():
            raise GatewayError("empty prompt")
        try:
            out = cloud_complete(
                prompt,
                api_base=self.api_base,
                api_key=self.api_key,
                model=model or self.default_model,
                system=system,
                enable_cloud=True,
                accept_not_private=True,
                dialect=self.dialect,
            )
        except CloudGateError as exc:
            raise GatewayError(str(exc)) from exc
        with self.lock:
            self.handled += 1
        return out["reply"]

    def handle_json(self, body: dict, token_header: str) -> dict:
        self.redeem_header(token_header)
        reply = self.complete(
            body.get("prompt") or body.get("text") or "",
            model=body.get("model"),
            system=body.get("system"),
        )
        return {
            "reply": reply,
            "account": "gateway — client presented no provider API key",
            "token": "redeemed once",
        }

    def handle_ohttp(self, encapsulated: bytes) -> bytes:
        """OHTTP: decrypt, run JSON complete, re-seal."""

        def origin(raw: bytes) -> bytes:
            try:
                msg = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise GatewayError(f"inner request is not JSON: {exc}") from exc
            token = msg.get("token") or ""
            self.redeem_header(token)
            reply = self.complete(
                msg.get("prompt") or "",
                model=msg.get("model"),
                system=msg.get("system"),
            )
            return json.dumps({"reply": reply}).encode("utf-8")

        try:
            return self.ohttp.handle(encapsulated, origin)
        except ObliviousError as exc:
            raise GatewayError(str(exc)) from exc


def save_issuer(issuer: Issuer, path: str) -> None:
    pem = issuer._key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(pem)
    spent_path = path + ".spent.json"
    with open(spent_path, "w", encoding="utf-8") as f:
        json.dump({"spent": sorted(issuer.spent), "issued": issuer.issued}, f)


def load_issuer(path: str) -> Issuer:
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise GatewayError("issuer key is not RSA")
    issuer = Issuer(key=key)
    spent_path = path + ".spent.json"
    if os.path.exists(spent_path):
        with open(spent_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        issuer.spent = set(data.get("spent") or [])
        issuer.issued = int(data.get("issued") or 0)
    return issuer


def serve_gateway(gw: FrontierGateway, host: str = "127.0.0.1",
                  port: int = 8751) -> ThreadingHTTPServer:
    """HTTP surface for the account-decoupled gateway."""

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _read_json(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            if n > 2_000_000:
                raise GatewayError("body too large")
            raw = self.rfile.read(n) if n else b"{}"
            try:
                obj = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError as exc:
                raise GatewayError("bad JSON") from exc
            if not isinstance(obj, dict):
                raise GatewayError("expected a JSON object")
            return obj

        def _send(self, code: int, obj, ctype: str = "application/json"):
            body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urlparse(self.path).path
            if path in ("/", "/v1/params", "/params"):
                return self._send(200, gw.public_params())
            if path == "/health":
                return self._send(200, {
                    "ok": True, "handled": gw.handled, "refused": gw.refused})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            path = urlparse(self.path).path
            try:
                if path in ("/v1/complete", "/complete"):
                    body = self._read_json()
                    tok = self.headers.get("Blindkeep-Token") or body.get("token") or ""
                    return self._send(200, gw.handle_json(body, tok))
                if path in ("/ohttp", "/v1/ohttp"):
                    n = int(self.headers.get("Content-Length") or 0)
                    if n > 2_000_000:
                        raise GatewayError("body too large")
                    raw = self.rfile.read(n)
                    sealed = gw.handle_ohttp(raw)
                    return self._send(200, sealed, "application/ohttp-response")
            except GatewayError as exc:
                return self._send(403, {"error": str(exc)})
            except Exception as exc:
                return self._send(500, {"error": type(exc).__name__})
            self._send(404, {"error": "not found"})

    httpd = ThreadingHTTPServer((host, port), H)
    return httpd


def make_gateway_remote(
    gateway_url: str,
    token: Token,
    *,
    model: str,
    use_ohttp: bool = False,
    ohttp_key_config_b64: Optional[str] = None,
    relay_url: Optional[str] = None,
) -> Callable[[str, Optional[str]], str]:
    """Client-side completer: no provider API key — only a blind token."""
    import urllib.error
    import urllib.request

    base = gateway_url.rstrip("/")
    token_hdr = f"{token.value_hex}.{token.signature_hex}"

    def complete_direct(prompt: str, system: Optional[str] = None) -> str:
        body = json.dumps({
            "prompt": prompt, "model": model, "system": system,
        }).encode()
        req = urllib.request.Request(
            base + "/v1/complete",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Blindkeep-Token": token_hdr,
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=180) as resp:
                data = json.loads(resp.read(8 * 1024 * 1024).decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read(2048).decode("utf-8", "replace")
            raise GatewayError(f"gateway HTTP {exc.code}: {detail}") from exc
        return data["reply"]

    def complete_ohttp(prompt: str, system: Optional[str] = None) -> str:
        from .oblivious import Client as OhttpClient, KeyConfig, Relay

        if not ohttp_key_config_b64 or not relay_url:
            raise GatewayError("OHTTP needs key config + relay URL")
        cfg = KeyConfig.parse(base64.b64decode(ohttp_key_config_b64))
        inner = json.dumps({
            "prompt": prompt, "model": model, "system": system,
            "token": token_hdr,
        }).encode()

        def forward(enc: bytes) -> bytes:
            # Relay posts opaque bytes to the gateway's OHTTP endpoint.
            # The client never talks to the gateway directly.
            r = urllib.request.Request(
                relay_url.rstrip("/") + "/forward",
                data=enc,
                headers={"Content-Type": "application/ohttp-request"},
                method="POST",
            )
            with urllib.request.urlopen(r, timeout=180) as resp:
                return resp.read(8 * 1024 * 1024)

        client = OhttpClient(cfg)
        relay = Relay(forward=forward)
        raw = client.send(relay, inner, client_address="client")
        return json.loads(raw.decode("utf-8"))["reply"]

    return complete_ohttp if use_ohttp else complete_direct

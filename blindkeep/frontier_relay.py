"""OHTTP relay HTTP surface — sees client addresses, never plaintext.

Forwards opaque encapsulated requests to a gateway. Holds no keys. If the same
operator runs this and the gateway, OHTTP anonymity is void (see oblivious.py).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import urlparse


def serve_relay(gateway_ohttp_url: str, host: str = "127.0.0.1",
                port: int = 8750) -> ThreadingHTTPServer:
    target = gateway_ohttp_url.rstrip("/")
    if not target.endswith("/ohttp") and not target.endswith("/v1/ohttp"):
        target = target + "/ohttp"

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = json.dumps({
                "role": "ohttp-relay",
                "forwards_to": target,
                "warning": (
                    "If you also operate the gateway, network anonymity is void. "
                    "Independence is contractual, not cryptographic."
                ),
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            path = urlparse(self.path).path
            if path not in ("/forward", "/"):
                self.send_response(404)
                self.end_headers()
                return
            n = int(self.headers.get("Content-Length") or 0)
            if n > 2_000_000:
                self.send_response(413)
                self.end_headers()
                return
            raw = self.rfile.read(n)
            # Client address is what the relay learns — logged only in memory
            # for ops; not forwarded to the gateway.
            _ = self.client_address
            try:
                req = urllib.request.Request(
                    target, data=raw,
                    headers={"Content-Type": "application/ohttp-request"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=180) as resp:
                    out = resp.read(8 * 1024 * 1024)
            except urllib.error.HTTPError as exc:
                err = exc.read(2048)
                self.send_response(exc.code)
                self.send_header("Content-Length", str(len(err)))
                self.end_headers()
                self.wfile.write(err)
                return
            except Exception as exc:
                err = json.dumps({"error": type(exc).__name__}).encode()
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(err)))
                self.end_headers()
                self.wfile.write(err)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/ohttp-response")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

    return ThreadingHTTPServer((host, port), H)

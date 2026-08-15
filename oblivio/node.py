"""Local HTTP memory node.

stdlib only (http.server). Serves ciphertext + Merkle proofs + signed heads.
Multi-node replication is a client concern (see replica.py); each process is
one independent node with its own identity and log.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlparse

from ._console import use_utf8_stdout
from .store import MemoryStore

# Resource limits. A node accepts writes from anyone, so every bound a client
# could otherwise choose has to be chosen here instead.
MAX_BODY_BYTES = 8 * 1024 * 1024       # largest request body accepted
MAX_RECORD_BYTES = 4 * 1024 * 1024     # largest single record stored
MAX_RECORD_ID_LEN = 128
LIST_DEFAULT_LIMIT = 1000
LIST_MAX_LIMIT = 10_000


class RequestTooLarge(Exception):
    """Body or record exceeds the configured limit."""


class _Handler(BaseHTTPRequestHandler):
    store: MemoryStore  # set on class before serve

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("[node] " + (fmt % args) + "\n")

    def _fail(self, exc: Exception) -> None:
        """Report an unexpected error without describing the server.

        Exception text from the filesystem layer contains absolute paths, which
        disclose the operating system, directory layout and account name of
        whoever runs the node. Log it locally; tell the client nothing.
        """
        self.log_message("unhandled error: %s: %s", type(exc).__name__, exc)
        self._send(500, {"error": "internal error"})

    def _send(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        """Read a bounded request body.

        Content-Length is attacker-controlled. Allocating or blocking on it
        lets one client claim gigabytes it never sends, occupying a handler
        thread until it times out; a handful of those stop the node serving.
        """
        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            raise ValueError("Content-Length required")
        try:
            length = int(raw_len)
        except ValueError:
            raise ValueError("Content-Length is not a number") from None
        if length < 0:
            raise ValueError("Content-Length is negative")
        if length > MAX_BODY_BYTES:
            raise RequestTooLarge(
                f"body of {length} bytes exceeds the {MAX_BODY_BYTES} byte limit")
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise ValueError("request body was shorter than Content-Length")
        return json.loads(raw.decode("utf-8") or "{}")

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if path == "/health":
                return self._send(200, {"ok": True, "service": "oblivio", "size": self.store.size})
            if path == "/v1/head":
                from dataclasses import asdict
                return self._send(200, asdict(self.store.head()))
            if path == "/v1/list":
                # Unpaginated listing grows without bound; cap it so one
                # request cannot ask the node to serialise its whole log.
                qs = parse_qs(parsed.query)
                limit = min(int(qs.get("limit", [LIST_DEFAULT_LIMIT])[0]), LIST_MAX_LIMIT)
                offset = max(int(qs.get("offset", ["0"])[0]), 0)
                if limit < 0:
                    raise ValueError("limit must not be negative")
                records = self.store.list_meta()[offset:offset + limit]
                return self._send(200, {
                    "records": records,
                    "offset": offset,
                    "limit": limit,
                    "total": self.store.size,
                })
            if path.startswith("/v1/get/"):
                index = int(path.rsplit("/", 1)[-1])
                return self._send(200, self.store.get(index))
            if path.startswith("/v1/get_id/"):
                rid = path.rsplit("/", 1)[-1]
                return self._send(200, self.store.get_by_record_id(rid))
            if path == "/v1/consistency":
                qs = parse_qs(parsed.query)
                old_size = int(qs.get("old_size", ["0"])[0])
                return self._send(200, self.store.consistency(old_size))
            self._send(404, {"error": "not found"})
        except (IndexError, KeyError):
            self._send(404, {"error": "not found"})
        except RequestTooLarge as e:
            self._send(413, {"error": str(e)})
        except ValueError as e:
            self._send(400, {"error": str(e)})
        except Exception as e:
            self._fail(e)

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        try:
            if path == "/v1/put":
                body = self._read_json()
                record_id = body["record_id"]
                if not isinstance(record_id, str) or not record_id:
                    raise ValueError("record_id must be a non-empty string")
                if len(record_id) > MAX_RECORD_ID_LEN:
                    raise ValueError(
                        f"record_id exceeds {MAX_RECORD_ID_LEN} characters")
                b64 = body.get("ciphertext_b64")
                if not isinstance(b64, str) or not b64:
                    raise ValueError("ciphertext_b64 must be a non-empty string")
                ct = base64.b64decode(b64, validate=True)
                if len(ct) > MAX_RECORD_BYTES:
                    raise RequestTooLarge(
                        f"record of {len(ct)} bytes exceeds the "
                        f"{MAX_RECORD_BYTES} byte limit")
                label = body.get("label") or ""
                if not isinstance(label, str):
                    raise ValueError("label must be a string")
                result = self.store.put_ciphertext(record_id, ct, label=label)
                return self._send(200, result)
            self._send(404, {"error": "not found"})
        except RequestTooLarge as e:
            self._send(413, {"error": str(e)})
        except (KeyError, ValueError, base64.binascii.Error) as e:
            self._send(400, {"error": str(e)})
        except Exception as e:
            self._fail(e)


class ExposureRefused(Exception):
    """Refused to bind a public interface without an explicit acknowledgement."""


def _is_loopback(host: str) -> bool:
    """True for addresses reachable only from this machine.

    The empty string is NOT loopback: passing "" to bind() means INADDR_ANY, which is
    every interface — the same exposure as 0.0.0.0 wearing a friendlier spelling. An
    earlier version of this function grouped it with "localhost" and would have waved
    through the exact case the gate exists to catch.

    Anything unrecognised is treated as public. A gate that fails open is not a gate.
    """
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False        # a hostname, or "": assume it reaches further than this box


def serve(data_dir: str, host: str = "127.0.0.1", port: int = 8741,
          accept_no_auth: bool = False) -> None:
    """Run a node. Binding beyond loopback requires saying so out loud.

    This node has no authentication and no transport security — by design at this stage,
    and documented in SECURITY.md. On loopback that is fine: the only reachable clients
    are already on the machine. On any other interface it means every peer who can route
    to the port may append records to the log and read the ciphertext it holds. Appends
    are what hurt: the log is append-only, so there is no supported way to remove what a
    stranger wrote into it, and nothing bounds how much they write.

    `--host 0.0.0.0` was one keystroke away from that, with nothing in between. So the
    gate is the same shape the cloud path already uses: the dangerous thing stays
    available, and choosing it has to be deliberate and legible in the command that did
    it. It is not a security control — anyone can pass the flag — it is a control against
    doing this by accident, which is how it would actually happen.
    """
    if not _is_loopback(host) and not accept_no_auth:
        raise ExposureRefused(
            f"refusing to bind {host}:{port} — this node has NO authentication and NO "
            f"TLS, so anyone who can reach that address can append records to your log "
            f"and read the ciphertext it stores. Appends cannot be removed: the log is "
            f"append-only.\n"
            f"  keep it private : --host 127.0.0.1  (the default)\n"
            f"  expose it anyway: --accept-no-auth, and put a reverse proxy in front of "
            f"it that provides TLS, authentication and rate limiting.")
    store = MemoryStore(data_dir)
    handler = type("Handler", (_Handler,), {"store": store})
    httpd = ThreadingHTTPServer((host, port), handler)
    pub = store.identity.public_hex()
    print(f"oblivio memory node listening on http://{host}:{port}")
    print(f"  data_dir = {data_dir}")
    print(f"  pubkey   = {pub}")
    print(f"  size     = {store.size}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
        httpd.server_close()


def main(argv: Optional[list[str]] = None) -> int:
    use_utf8_stdout()
    import argparse

    p = argparse.ArgumentParser(description="Oblivio local memory node")
    p.add_argument("--data-dir", default="data/node", help="persistent store directory")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8741)
    p.add_argument("--accept-no-auth", action="store_true",
                   help="bind a non-loopback address despite there being no "
                        "authentication or TLS on this node")
    args = p.parse_args(argv)
    try:
        serve(args.data_dir, host=args.host, port=args.port,
              accept_no_auth=args.accept_no_auth)
    except ExposureRefused as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

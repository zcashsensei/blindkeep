"""Resource and disclosure hardening.

A node accepts requests from anyone, so every bound a client could otherwise
choose has to be enforced by the node. Each test here corresponds to a defect
found by probing a running node as a hostile client would, and exists so the
defect cannot return.
"""

import base64
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blindkeep.client import MAX_RESPONSE_BYTES, BlindkeepClient, SecurityError
from blindkeep.crypto import generate_master_key
from blindkeep.node import (
    LIST_MAX_LIMIT,
    MAX_BODY_BYTES,
    MAX_RECORD_BYTES,
    MAX_RECORD_ID_LEN,
    _Handler,
)
from blindkeep.store import MemoryStore, client_encrypt

SERVERS = []
TMPDIRS = []


def node():
    d = tempfile.mkdtemp(prefix="blindkeep-hard-")
    TMPDIRS.append(d)
    store = MemoryStore(os.path.join(d, "node"))
    handler = type("H", (_Handler,), {"store": store,
                                      "log_message": lambda *a, **k: None})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    SERVERS.append(httpd)
    port = httpd.server_address[1]
    return f"http://127.0.0.1:{port}", port, store, d


def post(url, payload):
    req = urllib.request.Request(
        url + "/v1/put", data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def get(url, path):
    try:
        with urllib.request.urlopen(url + path, timeout=15) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


# --- information disclosure -------------------------------------------------

def test_errors_do_not_disclose_server_paths():
    """Filesystem error text names the OS, directory layout and account."""
    url, _, store, _ = node()
    key = generate_master_key()
    rid, blob = client_encrypt(key, b"x")
    res = store.put_ciphertext(rid, blob)
    os.remove(os.path.join(store.records_dir, res["leaf_hex"]))

    code, body = get(url, "/v1/get/0")
    assert code == 500, code
    lowered = body.lower()
    for marker in ("users", "appdata", "temp", "home", "/var", "c:\\", ".py"):
        assert marker not in lowered, f"response disclosed {marker!r}: {body}"
    assert "internal error" in lowered


def test_missing_record_is_a_plain_404():
    url, _, _, _ = node()
    code, body = get(url, "/v1/get_id/does-not-exist")
    assert code == 404, code
    assert "users" not in body.lower() and "traceback" not in body.lower()


# --- request bounds ---------------------------------------------------------

def test_oversized_content_length_is_refused_immediately():
    """Content-Length is attacker-controlled: never block or allocate on it."""
    url, port, _, _ = node()
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        claim = 8 * 1024 * 1024 * 1024
        s.sendall(
            f"POST /v1/put HTTP/1.1\r\nHost: x\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {claim}\r\n\r\n".encode() + b'{"record_id":"a"}')
        s.settimeout(8)
        resp = s.recv(200).decode(errors="replace")
        assert "413" in resp, f"expected 413, got: {resp[:120]!r}"
    except socket.timeout:
        raise AssertionError("node blocked waiting for a body that never came")
    finally:
        s.close()


def test_record_larger_than_the_limit_is_refused():
    url, _, store, _ = node()
    oversized = base64.b64encode(b"\x00" * (MAX_RECORD_BYTES + 1)).decode()
    code, _ = post(url, {"record_id": "big", "ciphertext_b64": oversized})
    assert code == 413, f"expected 413, got {code}"
    assert store.size == 0, "an oversized record was stored anyway"


def test_record_at_the_limit_is_accepted():
    """The bound must not be so eager that legitimate writes fail."""
    url, _, store, _ = node()
    ok = base64.b64encode(b"\x00" * (MAX_RECORD_BYTES - 1024)).decode()
    code, _ = post(url, {"record_id": "ok", "ciphertext_b64": ok})
    assert code == 200, code
    assert store.size == 1


def test_malformed_put_bodies_are_rejected():
    url, _, store, _ = node()
    for payload in (
        {},
        {"record_id": ""},
        {"record_id": 12345, "ciphertext_b64": "AAAA"},
        {"record_id": "a"},
        {"record_id": "a", "ciphertext_b64": ""},
        {"record_id": "a", "ciphertext_b64": "not valid base64!!"},
        {"record_id": "a" * (MAX_RECORD_ID_LEN + 1), "ciphertext_b64": "AAAA"},
        {"record_id": "a", "ciphertext_b64": "AAAA", "label": 99},
    ):
        code, _ = post(url, payload)
        assert code in (400, 413), f"{payload} produced {code}"
    assert store.size == 0, "a malformed request stored a record"


def test_body_limit_is_below_python_memory_pressure():
    assert MAX_BODY_BYTES <= 64 * 1024 * 1024
    assert MAX_RECORD_BYTES <= MAX_BODY_BYTES


# --- listing bounds ---------------------------------------------------------

def test_list_is_paginated():
    url, _, store, _ = node()
    key = generate_master_key()
    for i in range(25):
        rid, blob = client_encrypt(key, f"r{i}".encode())
        store.put_ciphertext(rid, blob)

    code, body = get(url, "/v1/list?limit=10")
    data = json.loads(body)
    assert code == 200
    assert len(data["records"]) == 10, len(data["records"])
    assert data["total"] == 25

    code, body = get(url, "/v1/list?limit=10&offset=20")
    assert len(json.loads(body)["records"]) == 5


def test_list_limit_is_capped():
    url, _, _, _ = node()
    _, body = get(url, f"/v1/list?limit={LIST_MAX_LIMIT * 100}")
    assert json.loads(body)["limit"] <= LIST_MAX_LIMIT


# --- client-side hardening --------------------------------------------------

def test_client_refuses_redirects():
    """A node must not be able to point the client at another host."""

    class Redirector(_Handler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.send_header("Content-Length", "0")
            self.end_headers()

    d = tempfile.mkdtemp(prefix="blindkeep-redir-")
    TMPDIRS.append(d)
    store = MemoryStore(os.path.join(d, "node"))
    handler = type("R", (Redirector,), {"store": store,
                                        "log_message": lambda *a, **k: None})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    SERVERS.append(httpd)
    url = f"http://127.0.0.1:{httpd.server_address[1]}"

    client = BlindkeepClient(url, generate_master_key(),
                             pin_path=os.path.join(d, "pin.json"))
    try:
        client.head()
    except Exception as exc:
        assert "redirect" in str(exc).lower(), f"wrong failure: {exc}"
        return
    raise AssertionError("client followed a redirect supplied by the node")


def test_client_response_limit_is_configured():
    assert 0 < MAX_RESPONSE_BYTES <= 64 * 1024 * 1024


# --- lookup cost ------------------------------------------------------------

def test_record_lookup_is_indexed_not_scanned():
    """A linear scan lets a client burn node CPU at no cost to itself."""
    _, _, store, _ = node()
    key = generate_master_key()
    ids = []
    for i in range(500):
        rid, blob = client_encrypt(key, f"r{i}".encode())
        store.put_ciphertext(rid, blob)
        ids.append(rid)

    assert hasattr(store, "_by_record_id"), "no record_id index present"
    assert len(store._by_record_id) == 500
    assert store.get_by_record_id(ids[-1])["index"] == 499
    assert store.get_by_record_id(ids[0])["index"] == 0
    try:
        store.get_by_record_id("nope")
    except KeyError:
        return
    raise AssertionError("unknown record_id did not raise")



# --- exposure gate ----------------------------------------------------------

def test_public_bind_is_refused_without_acknowledgement():
    """The node has no auth. Reaching a public interface must be deliberate.

    Every one of these is INADDR_ANY or a routable address by another spelling. The
    empty string is the interesting one: it means "all interfaces" to bind(), and a
    check that grouped it with "localhost" would wave through the exact case this
    gate exists to catch.
    """
    from blindkeep.node import ExposureRefused, serve

    for host in ("0.0.0.0", "", "::", "192.168.1.50", "example.com"):
        try:
            serve("data/does-not-matter", host=host, port=0)
        except ExposureRefused as exc:
            msg = str(exc)
            assert "NO authentication" in msg
            assert "--accept-no-auth" in msg, "the refusal must name the way through"
            continue
        raise AssertionError(f"binding {host!r} was allowed without acknowledgement")


def test_loopback_is_not_gated():
    """The default must stay frictionless, or the gate gets removed instead of used."""
    from blindkeep.node import _is_loopback

    for host in ("127.0.0.1", "localhost", "::1", "127.0.0.5"):
        assert _is_loopback(host), f"{host!r} should be treated as loopback"
    for host in ("0.0.0.0", "", "::", "10.0.0.1", "example.com"):
        assert not _is_loopback(host), f"{host!r} must NOT be treated as loopback"


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
            print(f"  FAIL  {name}\n          {exc}")
        except Exception as exc:
            failed.append(name)
            print(f"  ERROR {name}\n          {type(exc).__name__}: {exc}")
    for h in SERVERS:
        try:
            h.shutdown()
            h.server_close()
        except Exception:
            pass
    for d in TMPDIRS:
        shutil.rmtree(d, ignore_errors=True)
    print(f"\n{len(passed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())

"""Peer discovery tests, including a hostile bootstrap server."""

import json
import os
import shutil
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blindkeep.discover import (
    DiscoveryError,
    Peer,
    discover,
    fetch_bootstrap,
    filter_live,
    load_peers,
    normalise_url,
    urls,
)
from blindkeep.node import _Handler
from blindkeep.store import MemoryStore

SERVERS = []
TMPDIRS = []


def tmpdir():
    d = tempfile.mkdtemp(prefix="blindkeep-disc-")
    TMPDIRS.append(d)
    return d


def live_node():
    d = tmpdir()
    store = MemoryStore(os.path.join(d, "node"))
    h = type("H", (_Handler,), {"store": store, "log_message": lambda *a, **k: None})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), h)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    SERVERS.append(httpd)
    return f"http://127.0.0.1:{httpd.server_address[1]}", httpd


def json_server(payload, status=200):
    body = json.dumps(payload).encode() if not isinstance(payload, bytes) else payload

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a, **k):
            pass

        def do_GET(self):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    SERVERS.append(httpd)
    return f"http://127.0.0.1:{httpd.server_address[1]}"


def write_peers(entries, bootstrap=None):
    d = tmpdir()
    p = os.path.join(d, "peers.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump({"nodes": entries, "bootstrap_url": bootstrap}, f)
    return p


# --- url validation ---------------------------------------------------------

def test_normalise_accepts_and_canonicalises():
    assert normalise_url("http://127.0.0.1:8741/") == "http://127.0.0.1:8741"
    assert normalise_url("  https://a.example  ") == "https://a.example"


def test_dangerous_urls_are_refused():
    for bad in (
        "",
        "ftp://example.com",
        "file:///etc/passwd",
        "http://169.254.169.254/latest/meta-data/",   # AWS metadata
        "http://metadata.google.internal/",
        "http://user:pw@example.com",
        "http://",
    ):
        try:
            normalise_url(bad)
        except DiscoveryError:
            continue
        raise AssertionError(f"accepted dangerous url {bad!r}")


# --- loading ----------------------------------------------------------------

def test_loads_the_example_file():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    peers = load_peers(os.path.join(root, "data", "peers.example.json"))
    assert len(peers) == 3
    assert all(p.url.startswith("http://127.0.0.1") for p in peers)


def test_loads_plain_string_entries():
    peers = load_peers(write_peers(["http://127.0.0.1:1/", "http://127.0.0.1:2"]))
    assert urls(peers) == ["http://127.0.0.1:1", "http://127.0.0.1:2"]


def test_pinned_pubkey_is_preserved():
    peers = load_peers(write_peers([{"url": "http://127.0.0.1:1", "pubkey_hex": "ab" * 32}]))
    assert peers[0].pubkey_hex == "ab" * 32


def test_missing_file_raises_clearly():
    try:
        load_peers(os.path.join(tmpdir(), "nope.json"))
    except DiscoveryError as exc:
        assert "not found" in str(exc)
        return
    raise AssertionError("missing file did not raise")


def test_malformed_file_raises_clearly():
    d = tmpdir()
    p = os.path.join(d, "bad.json")
    with open(p, "w", encoding="utf-8") as f:
        f.write("{not json")
    try:
        load_peers(p)
    except DiscoveryError:
        return
    raise AssertionError("malformed JSON did not raise")


# --- liveness ---------------------------------------------------------------

def test_dead_peers_are_dropped_live_kept():
    up, _ = live_node()
    dead = "http://127.0.0.1:9"        # discard port, never answers
    live = filter_live([Peer(url=up), Peer(url=dead)], timeout=1.0)
    assert urls(live) == [up], urls(live)
    assert live[0].tree_size == 0


def test_discover_returns_only_live_nodes():
    up, _ = live_node()
    path = write_peers([up, "http://127.0.0.1:9"])
    assert urls(discover(path, timeout=1.0)) == [up]


def test_discover_can_skip_probing():
    path = write_peers(["http://127.0.0.1:9"])
    assert len(discover(path, require_live=False)) == 1


def test_discover_raises_when_nothing_is_live():
    path = write_peers(["http://127.0.0.1:9"])
    try:
        discover(path, timeout=1.0)
    except DiscoveryError as exc:
        assert "responded" in str(exc)
        return
    raise AssertionError("returned peers when none were live")


def test_discover_raises_with_no_sources():
    try:
        discover()
    except DiscoveryError:
        return
    raise AssertionError("discover() with no sources did not raise")


# --- bootstrap, treated as hostile ------------------------------------------

def test_bootstrap_supplies_candidates():
    up, _ = live_node()
    boot = json_server({"nodes": [{"url": up}]})
    assert urls(discover(bootstrap_url=boot, timeout=1.0)) == [up]


def test_bootstrap_cannot_inject_metadata_addresses():
    """The attack: a bootstrap points clients at cloud credentials endpoints."""
    up, _ = live_node()
    boot = json_server({"nodes": [
        {"url": "http://169.254.169.254/latest/meta-data/"},
        {"url": "file:///etc/passwd"},
        {"url": up},
    ]})
    got = urls(fetch_bootstrap(boot))
    assert got == [up], f"a dangerous url survived: {got}"


def test_bootstrap_cannot_override_a_local_pin():
    """A locally pinned key must win over whatever bootstrap claims."""
    up, _ = live_node()
    path = write_peers([{"url": up, "pubkey_hex": "aa" * 32}])
    boot = json_server({"nodes": [{"url": up, "pubkey_hex": "bb" * 32}]})
    peers = discover(path, bootstrap_url=boot, timeout=1.0)
    assert len(peers) == 1
    assert peers[0].pubkey_hex == "aa" * 32, "bootstrap replaced a local pin"


def test_bootstrap_garbage_raises_not_crashes():
    for payload in (b"not json", {"nodes": "a string"}, {"wrong": []}):
        boot = json_server(payload)
        try:
            fetch_bootstrap(boot)
        except DiscoveryError:
            continue
        raise AssertionError(f"accepted bootstrap payload {payload!r}")


def test_unreachable_bootstrap_raises():
    try:
        fetch_bootstrap("http://127.0.0.1:9", timeout=1.0)
    except DiscoveryError:
        return
    raise AssertionError("unreachable bootstrap did not raise")


def test_discovered_peers_drive_a_replicated_client():
    """Discovery must produce something ReplicatedClient actually accepts."""
    from blindkeep.crypto import generate_master_key
    from blindkeep.replica import ReplicatedClient

    a, _ = live_node()
    b, _ = live_node()
    path = write_peers([a, b])
    found = urls(discover(path, timeout=1.0))
    assert len(found) == 2

    d = tmpdir()
    client = ReplicatedClient(found, generate_master_key(),
                              pin_dir=os.path.join(d, "pins"))
    receipt = client.put(b"discovered and stored")
    assert receipt.written == 2
    assert client.get(receipt.record_id)["plaintext"] == b"discovered and stored"


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

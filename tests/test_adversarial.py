"""Adversarial protocol tests: run REAL malicious nodes against the real client.

test_merkle.py proves the proof algorithms are correct in isolation. That is not
the same as proving the client USES them correctly. These tests stand up an
actual HTTP node that lies in specific ways and assert the client refuses.

A node here is never assumed honest. Every test below is a capability a real
storage provider trivially has.
"""

import os
import shutil
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blindkeep.client import SecurityError, BlindkeepClient
from blindkeep.crypto import NodeIdentity, generate_master_key
from blindkeep.node import _Handler
from blindkeep.store import MemoryStore

SERVERS = []
TMPDIRS = []


def quiet(cls):
    return type("Quiet" + cls.__name__, (cls,), {"log_message": lambda *a, **k: None})


def start(store, handler_cls=_Handler):
    handler = type("Bound", (quiet(handler_cls),), {"store": store})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    SERVERS.append(httpd)
    return f"http://127.0.0.1:{httpd.server_address[1]}"


def tmpdir():
    d = tempfile.mkdtemp(prefix="blindkeep-test-")
    TMPDIRS.append(d)
    return d


def fresh(nrecords=0, identity=None, texts=None):
    """A store, a client key, and a client pointed at it."""
    d = tmpdir()
    store = MemoryStore(os.path.join(d, "node"), identity=identity)
    url = start(store)
    key = generate_master_key()
    client = BlindkeepClient(url, key, pin_path=os.path.join(d, "pin.json"))
    texts = texts or [b"memory-%d" % i for i in range(nrecords)]
    for t in texts:
        client.put(t)
    return store, client, d


# --- baseline: the honest path must actually work ----------------------------

def test_honest_roundtrip():
    _, client, _ = fresh()
    res = client.put(b"the agent remembered this", label="")
    got = client.get(res["index"])
    assert got["plaintext"] == b"the agent remembered this", got["plaintext"]


def test_node_never_sees_plaintext():
    """The privacy claim, checked against bytes actually written to disk."""
    store, client, d = fresh()
    secret = b"SUPERSECRET-CANARY-9137"
    client.put(secret)
    hits = []
    for root, _, files in os.walk(store.data_dir):
        for fn in files:
            with open(os.path.join(root, fn), "rb") as fh:
                if secret in fh.read():
                    hits.append(os.path.join(root, fn))
    assert not hits, f"plaintext canary found on node disk: {hits}"


# --- attacks the client is already expected to stop --------------------------

def test_ciphertext_tamper_detected():
    """Node edits a stored blob. Leaf no longer matches -> must refuse."""
    store, client, _ = fresh()
    res = client.put(b"original value")
    blob_path = os.path.join(store.records_dir, res["leaf_hex"])
    with open(blob_path, "rb") as fh:
        blob = bytearray(fh.read())
    blob[-1] ^= 0xFF
    with open(blob_path, "wb") as fh:
        fh.write(bytes(blob))
    try:
        client.get(res["index"])
    except Exception:
        return  # refused, as required
    raise AssertionError("client accepted a modified ciphertext")


def test_forged_head_signature_rejected():
    """A head not signed by the node's key must never be trusted."""
    _, client, _ = fresh(2)
    head = client.head()
    forged = dict(head)
    forged["root_hex"] = ("00" * 32)
    try:
        client._verify_head(forged)
    except SecurityError:
        return
    raise AssertionError("client accepted a head with a bad signature")


def test_history_rewrite_detected():
    """Node rewrites an old record and re-signs. Consistency vs the pin fails."""
    d = tmpdir()
    ident = NodeIdentity.generate()
    store_a = MemoryStore(os.path.join(d, "a"), identity=ident)
    url_a = start(store_a)
    key = generate_master_key()
    pin = os.path.join(d, "pin.json")
    client = BlindkeepClient(url_a, key, pin_path=pin)
    client.put(b"record-one")
    client.put(b"record-two")
    client.head()  # pin at size 2

    # Same node identity, different history, LONGER log.
    store_b = MemoryStore(os.path.join(d, "b"), identity=ident)
    rid, ct = __import__("blindkeep.store", fromlist=["x"]).client_encrypt(key, b"REWRITTEN")
    store_b.put_ciphertext(rid, ct)
    for extra in (b"record-two", b"record-three"):
        r, c = __import__("blindkeep.store", fromlist=["x"]).client_encrypt(key, extra)
        store_b.put_ciphertext(r, c)
    url_b = start(store_b)

    evil = BlindkeepClient(url_b, key, pin_path=pin)
    try:
        evil.head()
    except SecurityError:
        return
    raise AssertionError("client accepted a rewritten history")


# --- attacks I believe the client currently MISSES ---------------------------

def test_equal_size_fork_detected():
    """Same tree_size, different root, validly signed.

    The pin update only compares sizes, so a fork at equal length may slip
    through with no consistency check performed at all."""
    d = tmpdir()
    ident = NodeIdentity.generate()
    key = generate_master_key()
    pin = os.path.join(d, "pin.json")

    from blindkeep.store import client_encrypt
    store_a = MemoryStore(os.path.join(d, "a"), identity=ident)
    store_b = MemoryStore(os.path.join(d, "b"), identity=ident)
    for store, second in ((store_a, b"branch-A"), (store_b, b"branch-B")):
        for text in (b"shared-first", second):
            rid, ct = client_encrypt(key, text)
            store.put_ciphertext(rid, ct)

    client = BlindkeepClient(start(store_a), key, pin_path=pin)
    client.head()  # pin: size 2, root of branch A

    forked = BlindkeepClient(start(store_b), key, pin_path=pin)
    try:
        forked.head()  # size 2, DIFFERENT root
    except SecurityError:
        return
    raise AssertionError(
        "client accepted an equal-size fork: same length, different root, no check")


def test_index_substitution_detected():
    """Client asks for index 0; node serves index 1 with index 1's genuine,
    valid proof. Every internal check passes -- but it is the wrong record."""

    class Substituting(_Handler):
        def do_GET(self):
            if self.path == "/v1/get/0":
                return self._send(200, self.store.get(1))
            return super().do_GET()

    d = tmpdir()
    store = MemoryStore(os.path.join(d, "node"))
    key = generate_master_key()
    honest = BlindkeepClient(start(store), key, pin_path=os.path.join(d, "p1.json"))
    honest.put(b"record-ZERO")
    honest.put(b"record-ONE")

    client = BlindkeepClient(start(store, Substituting), key,
                            pin_path=os.path.join(d, "p2.json"))
    try:
        got = client.get(0)
    except SecurityError:
        return
    raise AssertionError(
        f"client asked for index 0 and accepted index {got['index']} "
        f"({got['plaintext']!r}) as verified")


def test_record_id_substitution_detected():
    """Same attack through get_by_id: the returned record_id is never compared
    to the one that was requested."""

    class Substituting(_Handler):
        def do_GET(self):
            if self.path.startswith("/v1/get_id/"):
                return self._send(200, self.store.get(1))
            return super().do_GET()

    d = tmpdir()
    store = MemoryStore(os.path.join(d, "node"))
    key = generate_master_key()
    honest = BlindkeepClient(start(store), key, pin_path=os.path.join(d, "p1.json"))
    first = honest.put(b"record-ZERO")
    honest.put(b"record-ONE")

    client = BlindkeepClient(start(store, Substituting), key,
                            pin_path=os.path.join(d, "p2.json"))
    try:
        got = client.get_by_id(first["record_id"])
    except SecurityError:
        return
    raise AssertionError(
        f"asked for record_id {first['record_id'][:12]}... and accepted "
        f"{got['record_id'][:12]}... ({got['plaintext']!r})")


def test_labelled_record_is_readable():
    """A record stored with a label must be retrievable. The label is the AAD,
    so a client that does not re-supply it cannot decrypt its own memory."""
    _, client, _ = fresh()
    res = client.put(b"labelled memory", label="notes")
    got = client.get(res["index"])
    assert got["plaintext"] == b"labelled memory", got["plaintext"]


def run():
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed, failed = [], []
    for name, fn in tests:
        try:
            fn()
            passed.append(name)
            print(f"  PASS  {name}")
        except AssertionError as exc:
            failed.append((name, str(exc)))
            print(f"  FAIL  {name}\n          {exc}")
        except Exception as exc:
            failed.append((name, f"{type(exc).__name__}: {exc}"))
            print(f"  ERROR {name}\n          {type(exc).__name__}: {exc}")
    for httpd in SERVERS:
        httpd.shutdown()
        httpd.server_close()
    for d in TMPDIRS:
        shutil.rmtree(d, ignore_errors=True)
    print(f"\n{len(passed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())

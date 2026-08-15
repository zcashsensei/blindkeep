"""Metadata minimisation tests.

Encryption hides record contents. These tests check the two metadata leaks that
could be closed without new cryptography -- plaintext labels and exact record
sizes -- and document, by assertion, the one that could not: access pattern.
"""

import os
import shutil
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oblivio.client import OblivioClient
from oblivio.crypto import generate_master_key
from oblivio.node import _Handler
from oblivio.store import (
    MemoryStore,
    PAD_BLOCK,
    client_encrypt,
    client_open,
)

SERVERS = []
TMPDIRS = []


def tmpdir():
    d = tempfile.mkdtemp(prefix="oblivio-meta-")
    TMPDIRS.append(d)
    return d


def node():
    d = tmpdir()
    store = MemoryStore(os.path.join(d, "node"))
    handler = type("B", (_Handler,), {"store": store,
                                      "log_message": lambda *a, **k: None})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    SERVERS.append(httpd)
    url = f"http://127.0.0.1:{httpd.server_address[1]}"
    client = OblivioClient(url, generate_master_key(),
                             pin_path=os.path.join(d, "pin.json"))
    return client, store, d


# --- labels -----------------------------------------------------------------

def test_label_round_trips():
    client, _, _ = node()
    res = client.put(b"contents", label="medical-records")
    got = client.get(res["index"])
    assert got["plaintext"] == b"contents"
    assert got["label"] == "medical-records", got["label"]


def test_label_never_reaches_the_node():
    """A descriptive label is exactly the metadata users leak most readily."""
    client, store, _ = node()
    client.put(b"contents", label="medical-records")

    meta = store.list_meta()
    assert meta[0]["label"] == "", f"node stored a plaintext label: {meta[0]['label']!r}"

    hits = []
    for root, _, files in os.walk(store.data_dir):
        for fn in files:
            with open(os.path.join(root, fn), "rb") as fh:
                if b"medical-records" in fh.read():
                    hits.append(os.path.join(root, fn))
    assert not hits, f"label found in plaintext on node disk: {hits}"


def test_label_is_authenticated_not_merely_hidden():
    """The label is inside the AEAD, so it cannot be altered without detection."""
    client, store, _ = node()
    res = client.put(b"contents", label="real-label")
    path = os.path.join(store.records_dir, res["leaf_hex"])
    with open(path, "rb") as fh:
        blob = bytearray(fh.read())
    blob[-1] ^= 0xFF
    with open(path, "wb") as fh:
        fh.write(bytes(blob))
    try:
        client.get(res["index"])
    except Exception:
        return
    raise AssertionError("altered record was accepted")


# --- size padding -----------------------------------------------------------

def test_sizes_are_padded_to_buckets():
    key = generate_master_key()
    sizes = set()
    for n in (1, 10, 100, 200):
        _, blob = client_encrypt(key, b"x" * n)
        sizes.add(len(blob))
    assert len(sizes) == 1, (
        f"payloads of 1..200 bytes produced distinguishable lengths: {sorted(sizes)}")


def test_padding_overhead_is_bounded():
    key = generate_master_key()
    _, blob = client_encrypt(key, b"x" * 10_000)
    overhead = len(blob) - 10_000
    assert overhead < PAD_BLOCK + 64, f"overhead {overhead} bytes is larger than expected"


def test_padding_survives_round_trip_at_boundaries():
    """Off-by-one framing errors hide exactly at block boundaries."""
    key = generate_master_key()
    for n in (0, 1, PAD_BLOCK - 7, PAD_BLOCK - 6, PAD_BLOCK - 5,
              PAD_BLOCK, PAD_BLOCK + 1, 2 * PAD_BLOCK):
        payload = b"y" * n
        rid, blob = client_encrypt(key, payload, label="L" * (n % 17))
        label, out = client_open(key, rid, blob)
        assert out == payload, f"payload corrupted at n={n}"
        assert label == "L" * (n % 17), f"label corrupted at n={n}"
        assert len(blob) % PAD_BLOCK == 0 or len(blob) > n, f"not padded at n={n}"


def test_trailing_zero_bytes_are_preserved():
    """Padding is zero bytes, so real trailing zeros must not be eaten."""
    key = generate_master_key()
    payload = b"data" + b"\x00" * 50
    rid, blob = client_encrypt(key, payload)
    assert client_open(key, rid, blob)[1] == payload


# --- what is still exposed --------------------------------------------------

def test_access_pattern_is_still_visible():
    """Documents the remaining gap: the node sees WHICH record is read.

    Closing this requires private information retrieval. This test asserts the
    current limitation so that it is recorded rather than assumed away."""
    client, store, _ = node()
    ids = [client.put(f"record {i}".encode())["record_id"] for i in range(3)]
    seen = []
    original = store.get_by_record_id

    def watched(record_id):
        seen.append(record_id)
        return original(record_id)

    store.get_by_record_id = watched
    client.get_by_id(ids[1])
    assert seen == [ids[1]], (
        "access pattern is no longer observable -- if this fails because PIR "
        "landed, update SECURITY.md and delete this test")


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

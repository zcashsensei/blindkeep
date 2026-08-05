"""End-to-end demo: node + client put/get/verify on localhost.

Run:  py -3 demo.py
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from blindkeep.client import SecurityError, BlindkeepClient
from blindkeep.node import _Handler
from blindkeep.store import MemoryStore


def main() -> int:
    td = tempfile.mkdtemp(prefix="blindkeep-demo-")
    node_dir = os.path.join(td, "node")
    client_dir = os.path.join(td, "client")
    os.makedirs(client_dir)

    store = MemoryStore(node_dir)
    handler = type("Handler", (_Handler,), {"store": store})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}"
    print(f"demo node up at {url}")
    print(f"node pubkey: {store.identity.public_hex()[:32]}...")

    key_path = os.path.join(client_dir, "master.key")
    pin_path = os.path.join(client_dir, "pin.json")
    key = BlindkeepClient.create_keys(key_path)
    client = BlindkeepClient(
        url, key, pin_path=pin_path,
        expected_pubkey_hex=store.identity.public_hex(),
    )

    memories = [
        ("prefs", "User prefers concise answers and risk-aware trading notes."),
        ("session", "Last session: reviewed Blindkeep memory layer, merkle proofs green."),
        ("todo", "Next: peer discovery and free community capacity pool."),
    ]

    indices = []
    for label, text in memories:
        r = client.put(text, label=label)
        indices.append(r["index"])
        print(f"  put  index={r['index']}  size={r['tree_size']}  root={r['root_hex'][:16]}…  [{label}]")

    print("\nfetch + verify + decrypt:")
    for idx, (label, text) in zip(indices, memories):
        got = client.get(idx, label=label)
        ok = got["plaintext"].decode() == text
        print(f"  get  index={idx}  ok={ok}  text={got['plaintext'].decode()[:60]}")
        assert ok

    # pin advanced; second client with pin should accept append-only growth
    client2 = BlindkeepClient(
        url, key, pin_path=pin_path,
        expected_pubkey_hex=store.identity.public_hex(),
    )
    r = client2.put("append-only check", label="check")
    print(f"\nappend after pin reload: index={r['index']} (consistency enforced)")

    # negative: wrong master key cannot read
    bad = BlindkeepClient(url, BlindkeepClient.create_keys(os.path.join(client_dir, "other.key")))
    try:
        bad.get(0, label="prefs")
        print("FAIL: wrong key should not decrypt")
        return 1
    except Exception as e:
        print(f"wrong key rejected as expected: {type(e).__name__}")

    httpd.shutdown()
    shutil.rmtree(td, ignore_errors=True)
    print("\nDEMO OK — encrypted memory in, proofs checked, plaintext only on client.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SecurityError as e:
        print(f"SECURITY FAILURE: {e}", file=sys.stderr)
        raise SystemExit(2)

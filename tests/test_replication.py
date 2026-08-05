"""Multi-node replication tests against real HTTP nodes.

Every scenario below runs genuine node processes over HTTP -- offline nodes,
tampered nodes and dishonest nodes are produced by actually breaking a node,
not by mocking a failure.
"""

import base64
import os
import shutil
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blindkeep.crypto import generate_master_key
from blindkeep.node import _Handler
from blindkeep.replica import (
    DivergenceError,
    ReplicatedClient,
    ReplicationError,
)
from blindkeep.store import MemoryStore

SERVERS = []
TMPDIRS = []


def quiet(cls):
    return type("Q" + cls.__name__, (cls,), {"log_message": lambda *a, **k: None})


def start_node(data_dir, handler_cls=_Handler):
    store = MemoryStore(data_dir)
    handler = type("B", (quiet(handler_cls),), {"store": store})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    SERVERS.append(httpd)
    return f"http://127.0.0.1:{httpd.server_address[1]}", store, httpd


def tmpdir():
    d = tempfile.mkdtemp(prefix="blindkeep-repl-")
    TMPDIRS.append(d)
    return d


def cluster(n=3, quorum=None):
    d = tmpdir()
    urls, stores, servers = [], [], []
    for i in range(n):
        u, s, h = start_node(os.path.join(d, f"node{i}"))
        urls.append(u)
        stores.append(s)
        servers.append(h)
    key = generate_master_key()
    client = ReplicatedClient(urls, key, pin_dir=os.path.join(d, "pins"),
                              quorum=quorum)
    return client, stores, servers, d


# --- baseline ---------------------------------------------------------------

def test_replicates_to_every_node():
    client, stores, _, _ = cluster(3)
    receipt = client.put(b"replicated memory", label="notes")
    assert receipt.written == 3, receipt.failures
    assert len(receipt.placements) == 3
    for s in stores:
        assert s.size == 1, f"node has {s.size} records, expected 1"


def test_identical_ciphertext_on_every_node():
    """All nodes must commit the same leaf, or divergence is undetectable."""
    client, stores, _, _ = cluster(3)
    receipt = client.put(b"same bytes everywhere")
    leaves = {s.get(0)["leaf_hex"] for s in stores}
    assert len(leaves) == 1, f"nodes hold different ciphertext: {leaves}"
    assert receipt.leaf_hex in leaves


def test_read_reaches_unanimous_agreement():
    client, _, _, _ = cluster(3)
    r = client.put(b"quorum read please")
    got = client.get(r.record_id)
    assert got["plaintext"] == b"quorum read please"
    assert got["agreement"] == 3
    assert got["dissenting"] == []


def test_record_id_is_stable_across_nodes():
    """Indices are per-node; the record id is the portable address."""
    client, stores, _, _ = cluster(3)
    stores[0].put_ciphertext("deadbeef" * 4, b"x" * 40, label="skew")
    r = client.put(b"after skew")
    indices = set(r.placements.values())
    assert len(indices) > 1, "expected node indices to diverge for this test"
    assert client.get(r.record_id)["plaintext"] == b"after skew"


# --- availability -----------------------------------------------------------

def test_survives_one_node_offline():
    client, _, servers, _ = cluster(3)
    r = client.put(b"written while all three were up")
    servers[0].shutdown()
    got = client.get(r.record_id)
    assert got["plaintext"] == b"written while all three were up"
    assert got["agreement"] == 2
    assert len(got["failures"]) == 1


def test_refuses_when_quorum_is_lost():
    client, _, servers, _ = cluster(3)
    r = client.put(b"about to lose the cluster")
    servers[0].shutdown()
    servers[1].shutdown()
    try:
        client.get(r.record_id)
    except ReplicationError:
        return
    raise AssertionError("returned a value with only one node responding")


def test_write_refuses_below_quorum():
    client, _, servers, _ = cluster(3)
    servers[0].shutdown()
    servers[1].shutdown()
    try:
        client.put(b"should not be accepted")
    except ReplicationError:
        return
    raise AssertionError("accepted a write that reached only one node")


def test_healthy_reports_quorum_loss():
    client, _, servers, _ = cluster(3)
    assert client.healthy()
    servers[0].shutdown()
    assert client.healthy(), "2 of 3 should still be healthy"
    servers[1].shutdown()
    assert not client.healthy(), "1 of 3 must not report healthy"


# --- dishonest nodes --------------------------------------------------------

def test_tampered_node_is_outvoted():
    """A node whose stored bytes were altered fails verification and is
    excluded from the vote; the honest majority still answers."""
    client, stores, _, _ = cluster(3)
    r = client.put(b"authentic content")

    victim = stores[0]
    rec = victim.get(0)
    path = os.path.join(victim.records_dir, rec["leaf_hex"])
    with open(path, "rb") as fh:
        blob = bytearray(fh.read())
    blob[-1] ^= 0xFF
    with open(path, "wb") as fh:
        fh.write(bytes(blob))

    got = client.get(r.record_id)
    assert got["plaintext"] == b"authentic content"
    assert got["agreement"] == 2, got
    assert len(got["failures"]) == 1, "tampered node should have been excluded"


def test_majority_tampered_refuses_rather_than_guessing():
    client, stores, _, _ = cluster(3, quorum=2)
    r = client.put(b"trust nobody")
    for victim in stores[:2]:
        rec = victim.get(0)
        path = os.path.join(victim.records_dir, rec["leaf_hex"])
        with open(path, "rb") as fh:
            blob = bytearray(fh.read())
        blob[0] ^= 0xFF
        with open(path, "wb") as fh:
            fh.write(bytes(blob))
    try:
        client.get(r.record_id)
    except (ReplicationError, DivergenceError):
        return
    raise AssertionError("returned data when only one node remained honest")


def test_divergent_write_is_detected():
    """A node that commits different bytes than it was sent must be caught."""

    class Mutating(_Handler):
        def do_POST(self):
            if self.path == "/v1/put":
                body = self._read_json()
                ct = bytearray(base64.b64decode(body["ciphertext_b64"]))
                ct[0] ^= 0xFF                      # silently alter the payload
                result = self.store.put_ciphertext(
                    body["record_id"], bytes(ct), label=body.get("label") or "")
                return self._send(200, result)
            return super().do_POST()

    d = tmpdir()
    urls = []
    u0, _, _ = start_node(os.path.join(d, "n0"))
    u1, _, _ = start_node(os.path.join(d, "n1"))
    u2, _, _ = start_node(os.path.join(d, "n2"), Mutating)
    urls = [u0, u1, u2]
    client = ReplicatedClient(urls, generate_master_key(),
                              pin_dir=os.path.join(d, "pins"))
    receipt = client.put(b"payload that one node will alter")

    # Correct behaviour is to tolerate the bad node, not to abort: two honest
    # nodes met quorum. What must not happen is the alteration going unnoticed.
    assert u2 not in receipt.placements, "the mutating node was counted as a good write"
    assert u2 in receipt.failures, "the alteration was not recorded as a failure"
    assert receipt.written == 2, receipt.placements
    assert u0 in receipt.placements and u1 in receipt.placements

    # And the record must still read back correctly from the honest majority.
    got = client.get(receipt.record_id)
    assert got["plaintext"] == b"payload that one node will alter"


def test_status_reports_every_node():
    client, _, servers, _ = cluster(3)
    client.put(b"seed")
    servers[2].shutdown()
    st = client.status()
    assert len(st) == 3
    assert sum(1 for s in st if s.reachable) == 2
    live = [s for s in st if s.reachable]
    assert all(s.tree_size == 1 for s in live), [s.tree_size for s in live]
    assert len({s.pubkey_hex for s in live}) == 2, "nodes must have distinct identities"


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

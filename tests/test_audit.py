"""Retrieval audit tests.

The audit's value is in the distinctions it draws: a node that is offline, a
node that lost data, and a node that lied are three different problems and must
not be scored as one.
"""

import os
import shutil
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blindkeep.audit import audit_node, audit_peers, rank
from blindkeep.client import BlindkeepClient
from blindkeep.crypto import generate_master_key
from blindkeep.node import _Handler
from blindkeep.store import MemoryStore

SERVERS = []
TMPDIRS = []


def tmpdir():
    d = tempfile.mkdtemp(prefix="blindkeep-audit-")
    TMPDIRS.append(d)
    return d


def node(handler_cls=_Handler, records=0, key=None):
    d = tmpdir()
    store = MemoryStore(os.path.join(d, "node"))
    h = type("H", (handler_cls,), {"store": store, "log_message": lambda *a, **k: None})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), h)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    SERVERS.append(httpd)
    url = f"http://127.0.0.1:{httpd.server_address[1]}"
    key = key or generate_master_key()
    client = BlindkeepClient(url, key, pin_path=os.path.join(d, "pin.json"))
    ids = [client.put(f"record {i}".encode())["record_id"] for i in range(records)]
    return client, store, httpd, ids, d, key


# --- the honest node --------------------------------------------------------

def test_healthy_node_scores_one():
    client, _, _, _, _, _ = node(records=10)
    r = audit_node(client, sample_size=5)
    assert r.challenges == 5, r.challenges
    assert r.passed == 5, r.summary()
    assert r.score == 1.0
    assert r.trustworthy
    assert r.security_failures == 0
    assert r.median_ms > 0


def test_sample_is_capped_by_available_records():
    client, _, _, _, _, _ = node(records=3)
    r = audit_node(client, sample_size=10)
    assert r.challenges == 3


def test_empty_node_is_reported_not_crashed():
    client, _, _, _, _, _ = node(records=0)
    r = audit_node(client, sample_size=5)
    assert r.challenges == 0
    assert "no records" in r.error
    assert r.score == 0.0


# --- the failing node -------------------------------------------------------

def test_missing_data_lowers_the_score():
    """A node that lost data answers, but cannot produce the record."""
    client, store, _, ids, _, _ = node(records=6)
    for i in range(3):                      # delete half the blobs from disk
        meta = store.get(i)
        os.remove(os.path.join(store.records_dir, meta["leaf_hex"]))

    r = audit_node(client, record_ids=ids, sample_size=6)
    assert r.challenges == 6
    assert r.failed == 3, r.summary()
    assert abs(r.score - 0.5) < 1e-9, r.score
    assert r.security_failures == 0, "data loss must not be reported as dishonesty"
    assert r.trustworthy, "a node that lost data is unreliable, not dishonest"


def test_offline_node_is_marked_offline_not_dishonest():
    client, _, httpd, ids, _, _ = node(records=3)
    httpd.shutdown()
    r = audit_node(client, sample_size=3)
    assert r.offline
    assert r.score == 0.0
    assert not r.trustworthy
    assert r.security_failures == 0


# --- the dishonest node -----------------------------------------------------

def test_substituting_node_is_flagged_as_a_security_failure():
    """A node that answers with the wrong record is not merely unreliable."""

    class Substituting(_Handler):
        def do_GET(self):
            if self.path.startswith("/v1/get_id/"):
                return self._send(200, self.store.get(0))
            return super().do_GET()

    d = tmpdir()
    store = MemoryStore(os.path.join(d, "node"))
    key = generate_master_key()

    honest = type("A", (_Handler,), {"store": store, "log_message": lambda *a, **k: None})
    h1 = ThreadingHTTPServer(("127.0.0.1", 0), honest)
    threading.Thread(target=h1.serve_forever, daemon=True).start()
    SERVERS.append(h1)
    setup = BlindkeepClient(f"http://127.0.0.1:{h1.server_address[1]}", key,
                            pin_path=os.path.join(d, "p1.json"))
    ids = [setup.put(f"rec {i}".encode())["record_id"] for i in range(5)]

    evil = type("B", (Substituting,), {"store": store, "log_message": lambda *a, **k: None})
    h2 = ThreadingHTTPServer(("127.0.0.1", 0), evil)
    threading.Thread(target=h2.serve_forever, daemon=True).start()
    SERVERS.append(h2)
    client = BlindkeepClient(f"http://127.0.0.1:{h2.server_address[1]}", key,
                             pin_path=os.path.join(d, "p2.json"))

    r = audit_node(client, record_ids=ids[1:], sample_size=4)
    assert r.security_failures > 0, r.summary()
    assert not r.trustworthy, "a lying node must never be judged trustworthy"
    assert any(c.security_failure for c in r.samples)


def test_one_security_failure_outweighs_many_passes():
    """Honesty is not scored proportionally."""
    from blindkeep.audit import AuditResult
    r = AuditResult(url="x", challenges=100, passed=99, failed=1,
                    security_failures=1)
    assert r.score == 0.99
    assert not r.trustworthy


# --- multiple nodes ---------------------------------------------------------

def test_audit_peers_judges_each_node_separately():
    key = generate_master_key()
    good, _, _, ids, _, _ = node(records=5, key=key)
    bad, _, bad_httpd, _, _, _ = node(records=5, key=key)
    bad_httpd.shutdown()

    d = tmpdir()
    results = audit_peers([good.base_url, bad.base_url], key,
                          pin_dir=os.path.join(d, "pins"), sample_size=3)
    assert len(results) == 2
    by_url = {r.url: r for r in results}
    assert by_url[good.base_url].score == 1.0
    assert by_url[bad.base_url].offline


def test_rank_puts_honest_and_fast_first():
    from blindkeep.audit import AuditResult
    a = AuditResult(url="slow", challenges=10, passed=10,
                    samples=[type("C", (), {"ms": 900.0})()])
    b = AuditResult(url="fast", challenges=10, passed=10,
                    samples=[type("C", (), {"ms": 5.0})()])
    c = AuditResult(url="liar", challenges=10, passed=10, security_failures=1,
                    samples=[type("C", (), {"ms": 1.0})()])
    order = [r.url for r in rank([a, c, b])]
    assert order[0] == "fast", order
    assert order[-1] == "liar", "a fast liar must never rank above an honest node"


def test_result_serialises_for_reporting():
    client, _, _, _, _, _ = node(records=4)
    d = audit_node(client, sample_size=2).as_dict()
    for field in ("url", "score", "challenges", "trustworthy", "samples"):
        assert field in d, field
    import json
    json.dumps(d)          # must be JSON-serialisable for a status page


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

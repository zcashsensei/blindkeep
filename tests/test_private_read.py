"""Access-pattern privacy, and an honest account of its price.

`read_private` is the trivial PIR construction: fetch everything, choose locally. That is not a
stand-in for something cleverer — against a single server it is provably optimal, since any
information-theoretically private retrieval must move at least the whole database.

So the tests that matter are the ones about the *cost being visible* and the *limits being
stated*. A privacy feature whose price is hidden gets switched off the first time someone notices
the bandwidth, and one whose residual leaks are unstated gets trusted for things it never did.
"""

import os
import sys
import threading
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blindkeep.client import BlindkeepClient
from blindkeep.crypto import generate_master_key
from blindkeep.node import _Handler
from blindkeep.private_read import (
    RetrievalError,
    pad_writes,
    read_private,
    read_private_by_label,
    visibility,
)
from blindkeep.store import MemoryStore

SERVERS = []
TMP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_pir_tmp")


def keep(n=5, tag="a", label="note"):
    d = os.path.join(TMP, tag)
    os.makedirs(d, exist_ok=True)
    store = MemoryStore(os.path.join(d, "node"))
    handler = type("B", (_Handler,), {"store": store, "log_message": lambda *a, **k: None})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    SERVERS.append(httpd)
    c = BlindkeepClient(f"http://127.0.0.1:{httpd.server_address[1]}", generate_master_key(),
                        pin_path=os.path.join(d, "pin.json"))
    for i in range(n):
        c.put(f"record {tag}{i}".encode(), label=label)
    return c


# --- it returns the right record ----------------------------------------------

def test_the_right_record_comes_back():
    c = keep(5, "right")
    r = read_private(c, 2)
    assert r.plaintext == b"record right2"
    assert r.index == 2


def test_every_index_is_readable():
    c = keep(4, "every")
    for i in range(4):
        assert read_private(c, i).plaintext == f"record every{i}".encode()


def test_labels_survive_because_they_are_inside_the_ciphertext():
    c = keep(3, "lab", label="health")
    assert read_private(c, 1).label == "health"


def test_selecting_by_label_happens_locally():
    """A label filter cannot be pushed to the node even in principle — it cannot read them."""
    c = keep(3, "bylabel", label="health")
    assert len(read_private_by_label(c, "health")) == 3
    assert read_private_by_label(c, "absent") == []


# --- the cost is reported, not hidden -----------------------------------------

def test_the_cost_is_reported():
    c = keep(6, "cost")
    r = read_private(c, 0)
    assert r.fetched == 6, "reading one record fetched fewer than all of them"
    assert r.bytes_transferred > 0
    assert "cannot tell which" in r.cost()


def test_reading_one_record_costs_the_whole_keep():
    """The defining property. If this ever stops being true, the privacy is gone."""
    c = keep(7, "whole")
    assert read_private(c, 3).fetched == 7


def test_an_oversized_keep_refuses_and_explains_the_trade():
    c = keep(4, "big")
    try:
        read_private(c, 0, max_records=2)
    except RetrievalError as exc:
        msg = str(exc)
        assert "bandwidth" in msg
        assert "no third option" in msg, "the refusal should state the real trade-off"
        return
    raise AssertionError("an oversized keep was fetched anyway")


def test_an_out_of_range_index_is_refused():
    c = keep(3, "range")
    for bad in (-1, 3, 99):
        try:
            read_private(c, bad)
        except RetrievalError:
            continue
        raise AssertionError(f"index {bad} was accepted")


# --- what remains visible ------------------------------------------------------

def test_visibility_names_what_is_still_leaked():
    """A privacy feature that leaves you unsure what remains has not finished its job."""
    c = keep(3, "vis")
    v = visibility(c)
    assert v["record_count"] == 3
    assert "hidden" in v["which_record_was_read"]
    assert "visible" in v["when_records_were_written"]
    assert "visible" in v["that_a_read_happened"]


def test_padding_raises_the_count():
    c = keep(3, "pad")
    pad_writes(c, 5, label="pad")
    assert int(c.head()["tree_size"]) == 8


def test_padding_is_indistinguishable_to_the_node_and_labelled_for_you():
    """The node cannot separate cover from real; you can, or the cover would be useless."""
    c = keep(2, "padlab", label="real")
    pad_writes(c, 3, label="pad")
    assert len(read_private_by_label(c, "real")) == 2
    assert len(read_private_by_label(c, "pad")) == 3


def test_negative_padding_is_refused():
    c = keep(1, "negpad")
    try:
        pad_writes(c, -1)
    except RetrievalError:
        return
    raise AssertionError("a negative padding count was accepted")


def run():
    os.makedirs(TMP, exist_ok=True)
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed, failed = [], []
    for name, fn in tests:
        try:
            fn()
            passed.append(name)
            print(f"  PASS  {name}")
        except AssertionError as exc:
            failed.append(name)
            print(f"  FAIL  {name}")
            print(f"          {exc}")
        except Exception as exc:
            failed.append(name)
            print(f"  ERROR {name}")
            print(f"          {type(exc).__name__}: {exc}")
    for h in SERVERS:
        try:
            h.shutdown(); h.server_close()
        except Exception:
            pass
    import shutil
    shutil.rmtree(TMP, ignore_errors=True)
    print()
    print(f"{len(passed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())

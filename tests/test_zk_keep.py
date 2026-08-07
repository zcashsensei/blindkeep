"""Proofs about records in a real keep, against a real node.

The assertions that matter are the ones about what a proof must NOT do: verify
against a different keep, a later head, or a set the prover supplied. A
membership proof whose set comes from the prover is not a proof of anything.
"""

import os
import sys
import threading
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blindkeep.client import BlindkeepClient
from blindkeep.crypto import generate_master_key
from blindkeep.node import _Handler
from blindkeep.store import MemoryStore
from blindkeep.zk_keep import (
    keep_context,
    keep_leaves,
    leaf_to_scalar,
    prove_in_keep,
    verify_in_keep,
)

SERVERS = []
TMP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_zkkeep_tmp")


def keep(n=4, tag="a"):
    """A live node with n records, and a client for it."""
    d = os.path.join(TMP, tag)
    os.makedirs(d, exist_ok=True)
    store = MemoryStore(os.path.join(d, "node"))
    handler = type("B", (_Handler,), {"store": store, "log_message": lambda *a, **k: None})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    SERVERS.append(httpd)
    client = BlindkeepClient(f"http://127.0.0.1:{httpd.server_address[1]}",
                             generate_master_key(),
                             pin_path=os.path.join(d, "pin.json"))
    for i in range(n):
        client.put(f"record {tag}{i}".encode(), label=f"r{i}")
    return client


# --- the honest path ---------------------------------------------------------

def test_a_holder_proves_membership_without_naming_the_record():
    client = keep(4, "honest")
    bundle = prove_in_keep(client, index=2)
    head = client.head()
    assert verify_in_keep(bundle, keep_leaves(client), head) is True
    # Nothing in the bundle says which record it was.
    assert "index" not in bundle
    assert len(bundle["proof"]["t_hex"]) == 4, "branch count must not depend on the index"


def test_every_index_produces_an_indistinguishable_proof():
    client = keep(4, "shape")
    shapes = set()
    for i in range(4):
        b = prove_in_keep(client, index=i)
        shapes.add((len(b["proof"]["t_hex"]), len(b["proof"]["c_hex"]),
                    len(b["proof"]["s_hex"])))
    assert len(shapes) == 1, "proof shape leaks which record was proven"


def test_two_proofs_of_the_same_record_are_unlinkable():
    client = keep(4, "unlink")
    a = prove_in_keep(client, index=1)
    b = prove_in_keep(client, index=1)
    assert a["commitment_hex"] != b["commitment_hex"]


# --- what a proof must NOT do ------------------------------------------------

def test_a_proof_does_not_verify_against_a_different_keep():
    a, b = keep(4, "k1"), keep(4, "k2")
    bundle = prove_in_keep(a, index=0)
    assert verify_in_keep(bundle, keep_leaves(b), b.head()) is False


def test_a_proof_does_not_survive_the_keep_growing():
    client = keep(4, "grow")
    bundle = prove_in_keep(client, index=0)
    client.put(b"one more", label="new")
    assert verify_in_keep(bundle, keep_leaves(client), client.head()) is False, (
        "a proof about a 4-record keep verified against a 5-record one")


def test_the_verifier_uses_its_own_leaf_set():
    """A prover who supplies the set proves membership in a set they chose."""
    client = keep(4, "ownset")
    bundle = prove_in_keep(client, index=0)
    head = client.head()
    real = keep_leaves(client)
    forged = ["ff" * 32] + real[1:]
    assert verify_in_keep(bundle, forged, head) is False


def test_a_tampered_commitment_does_not_verify():
    client = keep(4, "tamper")
    bundle = prove_in_keep(client, index=0)
    bundle["commitment_hex"] = f"{int(bundle['commitment_hex'], 16) + 1:x}"
    assert verify_in_keep(bundle, keep_leaves(client), client.head()) is False


def test_a_bundle_claiming_the_wrong_head_is_refused():
    client = keep(4, "wronghead")
    bundle = prove_in_keep(client, index=0)
    bundle["head"]["root_hex"] = "00" * 32
    assert verify_in_keep(bundle, keep_leaves(client), client.head()) is False


def test_malformed_bundles_return_false_not_crash():
    client = keep(2, "malformed")
    head = client.head()
    leaves = keep_leaves(client)
    for bad in ({}, {"head": {}}, {"commitment_hex": "zz", "proof": {},
                                   "head": {"root_hex": head["root_hex"],
                                            "tree_size": head["tree_size"]},
                                   "keep_size": 2}):
        assert verify_in_keep(bad, leaves, head) is False


# --- binding and scale -------------------------------------------------------

def test_the_context_names_both_root_and_size():
    client = keep(3, "ctx")
    head = client.head()
    ctx = keep_context(head)
    assert head["root_hex"].encode() in ctx and b"size=3" in ctx


def test_leaf_scalars_are_reduced_not_truncated():
    """Truncation would let two distinct leaves share a label."""
    from blindkeep.zk import Q
    a = leaf_to_scalar("ff" * 32)
    assert 0 <= a < Q
    assert leaf_to_scalar("ff" * 32) != leaf_to_scalar("fe" + "ff" * 31)


def test_an_oversized_keep_is_refused_with_the_reason():
    """O(n) proofs stop being practical, and the error says so rather than hanging."""
    client = keep(3, "big")
    try:
        keep_leaves(client, limit=2)
    except ValueError as exc:
        assert "SNARK" in str(exc), "the refusal should name what fixes it"
        return
    raise AssertionError("an oversized keep was accepted")


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
            print(f"  FAIL  {name}\n          {exc}")
        except Exception as exc:
            failed.append(name)
            print(f"  ERROR {name}\n          {type(exc).__name__}: {exc}")
    for h in SERVERS:
        try:
            h.shutdown(); h.server_close()
        except Exception:
            pass
    import shutil
    shutil.rmtree(TMP, ignore_errors=True)
    print(f"\n{len(passed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())

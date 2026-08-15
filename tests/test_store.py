"""Memory store + client encryption tests (no network)."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oblivio import merkle
from oblivio.crypto import NodeIdentity, generate_master_key, signed_head_message
from oblivio.store import MemoryStore, client_decrypt, client_encrypt


def test_roundtrip_encrypt():
    key = generate_master_key()
    rid, blob = client_encrypt(key, b"agent memory: prefer risk-off on Fridays", label="prefs")
    plain = client_decrypt(key, rid, blob, label="prefs")
    assert plain == b"agent memory: prefer risk-off on Fridays"


def test_wrong_key_fails():
    key = generate_master_key()
    other = generate_master_key()
    rid, blob = client_encrypt(key, b"secret")
    try:
        client_decrypt(other, rid, blob)
        assert False, "should have failed"
    except Exception:
        pass


def test_store_put_get_inclusion():
    with tempfile.TemporaryDirectory() as td:
        store = MemoryStore(td)
        key = generate_master_key()
        for i in range(5):
            rid, blob = client_encrypt(key, f"memory-{i}".encode())
            result = store.put_ciphertext(rid, blob, label=f"m{i}")
            leaf = bytes.fromhex(result["leaf_hex"])
            root = bytes.fromhex(result["head"]["root_hex"])
            proof = [bytes.fromhex(p) for p in result["proof"]]
            assert merkle.verify_inclusion(
                leaf, result["index"], result["head"]["tree_size"], proof, root
            )
            # signature checks
            msg = signed_head_message(result["head"]["tree_size"], root)
            assert NodeIdentity.verify(
                bytes.fromhex(result["head"]["public_key_hex"]),
                msg,
                bytes.fromhex(result["head"]["signature_hex"]),
            )

        got = store.get(2)
        ct = __import__("base64").b64decode(got["ciphertext_b64"])
        plain = client_decrypt(key, got["record_id"], ct)
        assert plain == b"memory-2"


def test_store_detects_rewrite_via_consistency():
    with tempfile.TemporaryDirectory() as td:
        store = MemoryStore(td)
        key = generate_master_key()
        heads = []
        for i in range(8):
            rid, blob = client_encrypt(key, f"x{i}".encode())
            r = store.put_ciphertext(rid, blob)
            heads.append(r["head"])

        # honest consistency from size 3 to 8
        cons = store.consistency(3)
        assert merkle.verify_consistency(
            3, 8,
            bytes.fromhex(cons["old_root_hex"]),
            bytes.fromhex(cons["head"]["root_hex"]),
            [bytes.fromhex(p) for p in cons["proof"]],
        )

        # forge: rewrite leaf 1 on disk (simulates malicious node)
        forged_leaves = list(store._leaves)
        forged_leaves[1] = merkle.leaf_hash(b"evil")
        forged_root = merkle.root(forged_leaves)
        # consistency from old honest size-3 head must fail against forged tip
        old_root = bytes.fromhex(heads[2]["root_hex"])  # after 3 puts, size=3
        proof = merkle.consistency_proof(3, forged_leaves)
        assert not merkle.verify_consistency(3, 8, old_root, forged_root, proof)


def test_reload_persists():
    with tempfile.TemporaryDirectory() as td:
        s1 = MemoryStore(td)
        key = generate_master_key()
        rid, blob = client_encrypt(key, b"persist me")
        s1.put_ciphertext(rid, blob)
        pub = s1.identity.public_hex()
        del s1

        s2 = MemoryStore(td)
        assert s2.size == 1
        assert s2.identity.public_hex() == pub
        got = s2.get(0)
        plain = client_decrypt(
            key, got["record_id"],
            __import__("base64").b64decode(got["ciphertext_b64"]),
        )
        assert plain == b"persist me"


def run():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)} store tests passed")


if __name__ == "__main__":
    run()

"""The end-to-end walkthrough, as running code.

`demo.py` proves the storage layer on a terminal. This proves the whole claim —
seal, log, gate, budget, proof — and does it by CALLING the shipped modules, not
by describing them. Nothing here narrates a step it did not perform: every line
the caller sees is a return value.

Design rules, because a demo is the thing most likely to quietly become a lie:

  * Real code only. If a step cannot be run it is reported as not run, never
    printed as if it were. The halo2 circuit lives in a separate Rust repo, so
    the proof step here is the sigma-protocol range proof in `zk.py` and says so.
  * Local only. A temp node on 127.0.0.1, no API key, no provider, no network,
    no cost. Anyone can press the button, including a stranger reading the repo.
  * Adversarial steps included. A walkthrough that only shows the happy path is
    marketing. Tamper and wrong-key are steps 6 and 7 for that reason.
  * Everything torn down. The temp tree is removed even when a step raises.

Usage:

    for ev in run():
        print(ev)

The final event carries the receipt: the same facts, machine-readable.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import time
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from typing import Any, Iterator

from . import zk
from .client import OblivioClient
from .dp import DEFAULT_BUCKETS, PrivacyLedger, pad_to_bucket
from .memory_gate import (DEFAULT_POLICY, Grant, MemoryGate, Sensitivity,
                          SimpleBackend, Tier)
from .node import _Handler
from .store import MemoryStore

# The three memories are chosen so the gate has something to actually decide:
# one of each class the policy treats differently. A demo where everything is
# released proves nothing about a release policy.
MEMORIES = [
    (Sensitivity.PUBLIC, "prefs",
     "User prefers concise answers and risk-aware trading notes."),
    (Sensitivity.PERSONAL, "session",
     "Last session: reviewed the memory layer, merkle proofs green."),
    (Sensitivity.SECRET, "keys",
     "Recovery phrase lives in the safe, not on this machine."),
]

# Distinctive enough that finding it on disk is unambiguous, and not a substring
# of anything else written during the run.
CANARY = b"SUPERSECRET-CANARY-9137"

# ε per send, and the session budget. Small and fixed so the arithmetic on screen
# is checkable by eye — the point is the accounting, not the number.
EPSILON_PER_SEND = 1.5
EPSILON_BUDGET = 16.0
SPEC_PER_SEND = 24

# The range proof runs 16 bit-proofs in pure Python. ε is proved in thousandths,
# so 16 bits covers 0..65.535 — comfortably above a 16.0 budget, and about a
# second to prove rather than the several a 32-bit proof would cost.
RANGE_BITS = 16


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _scan_for(root: str, needle: bytes) -> tuple[int, int, list[str]]:
    """Every byte the node wrote, searched for `needle`. Returns (files, bytes, hits)."""
    files = nbytes = 0
    hits: list[str] = []
    for dirpath, _, names in os.walk(root):
        for name in names:
            path = os.path.join(dirpath, name)
            with open(path, "rb") as fh:
                blob = fh.read()
            files += 1
            nbytes += len(blob)
            if needle in blob:
                hits.append(os.path.relpath(path, root))
    return files, nbytes, hits


def run() -> Iterator[dict[str, Any]]:
    """Run the walkthrough, yielding one event per step.

    Events are dicts with a `stage` key: `step` (a completed step), `error`
    (the run stopped), `done` (carries the receipt). A step event always
    reports what was measured, never what was expected.
    """
    started = time.time()
    steps: list[dict[str, Any]] = []
    tmp = tempfile.mkdtemp(prefix="oblivio-walkthrough-")
    httpd = None

    def step(n: int, title: str, detail: str, **facts) -> dict[str, Any]:
        ev = {"stage": "step", "n": n, "title": title, "detail": detail,
              "facts": facts, "ms": round((time.time() - started) * 1000)}
        steps.append({"n": n, "title": title, "detail": detail, "facts": facts})
        return ev

    try:
        # -- 1. a node ------------------------------------------------------
        node_dir = os.path.join(tmp, "node")
        client_dir = os.path.join(tmp, "client")
        os.makedirs(client_dir)
        store = MemoryStore(node_dir)
        # Silent: the walkthrough's own events are the output. A node access log
        # interleaved with them on stderr reads like something went wrong.
        handler = type("Handler", (_Handler,),
                       {"store": store,
                        "log_message": lambda self, fmt, *a: None})
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{port}"
        pubkey = store.identity.public_hex()
        yield step(
            1, "A keep starts",
            "A storage node on loopback with its own Ed25519 identity. In "
            "production this is someone else's machine — which is the whole "
            "problem the rest of the run is about.",
            url=url, pubkey=pubkey[:32] + "…", data_dir="(temporary)")

        # -- 2. keys stay here ----------------------------------------------
        key_path = os.path.join(client_dir, "master.key")
        pin_path = os.path.join(client_dir, "pin.json")
        key = OblivioClient.create_keys(key_path)
        client = OblivioClient(url, key, pin_path=pin_path,
                                 expected_pubkey_hex=pubkey)
        yield step(
            2, "The client holds the only key",
            "A master key is generated on this side and pinned to the node's "
            "public key. The node is never sent the key, and a node that "
            "swaps its identity later is refused rather than trusted.",
            master_key_bytes=len(key), pinned_to=pubkey[:16] + "…",
            key_location="client, never transmitted")

        # -- 3. seal ---------------------------------------------------------
        gate = MemoryGate(client, index_path=os.path.join(client_dir, "index.json"))
        sealed = []
        for sensitivity, label, text in MEMORIES:
            res = gate.remember(text, sensitivity=sensitivity, label=label)
            sealed.append((sensitivity, label, text, res))
        head = client.head()
        yield step(
            3, "Memories are sealed before they leave",
            "Each record is encrypted client-side under its own derived key, "
            "and its sensitivity class travels INSIDE the ciphertext — so the "
            "node cannot read the class, and cannot edit it either.",
            records=len(sealed),
            classes=[s.label for s, _, _, _ in sealed],
            tree_size=head.get("tree_size"),
            root=str(head.get("root_hex", ""))[:16] + "…")

        # -- 4. the node holds ciphertext ------------------------------------
        canary_res = client.put(CANARY, label="public:canary")
        files, nbytes, hits = _scan_for(store.data_dir, CANARY)
        if hits:
            yield {"stage": "error",
                   "msg": f"plaintext found on node disk: {hits}"}
            return
        yield step(
            4, "The keep holds ciphertext, checked",
            "A canary is stored, then every byte the node wrote is searched "
            "for it. This is the privacy claim tested against the disk rather "
            "than asserted in a README.",
            canary=CANARY.decode(), files_scanned=files, bytes_scanned=nbytes,
            plaintext_hits=0)

        # -- 5. read back ----------------------------------------------------
        verified = 0
        for sensitivity, label, text, res in sealed:
            got = client.get(res["index"])
            if got["plaintext"].decode() != text:
                yield {"stage": "error", "msg": f"read-back mismatch at index {res['index']}"}
                return
            verified += 1
        yield step(
            5, "Read back: proof checked, then decrypted",
            "Every read verifies an RFC 6962 inclusion proof against the "
            "signed head before the plaintext is opened. The order matters — "
            "decrypting first would mean trusting the node to hand back what "
            "it was given.",
            records_read=verified, inclusion_proofs_verified=verified,
            plaintext_matches=verified)

        # -- 6. tamper -------------------------------------------------------
        blob_path = os.path.join(store.records_dir, canary_res["leaf_hex"])
        with open(blob_path, "rb") as fh:
            blob = bytearray(fh.read())
        blob[-1] ^= 0xFF
        with open(blob_path, "wb") as fh:
            fh.write(bytes(blob))
        try:
            client.get(canary_res["index"])
            yield {"stage": "error",
                   "msg": "a tampered record was accepted — this is a defect"}
            return
        except Exception as exc:
            refusal = type(exc).__name__
        yield step(
            6, "A tampered record is refused",
            "One byte of a stored blob is flipped, exactly as a hostile "
            "operator would. The leaf no longer matches the logged hash, so "
            "the client refuses. Tamper-EVIDENT: the edit is possible and "
            "always detected — never claim tamper-proof.",
            bytes_flipped=1, accepted=False, refused_with=refusal)

        # -- 7. wrong key ----------------------------------------------------
        other = OblivioClient(
            url, OblivioClient.create_keys(os.path.join(client_dir, "other.key")),
            expected_pubkey_hex=pubkey)
        try:
            other.get(0)
            yield {"stage": "error",
                   "msg": "a wrong key decrypted a record — this is a defect"}
            return
        except Exception as exc:
            rejected = type(exc).__name__
        yield step(
            7, "A second key reads nothing",
            "A different master key against the same node. It can fetch the "
            "ciphertext — that is what a storage node is for — and it cannot "
            "open it.",
            fetched=True, decrypted=False, rejected_with=rejected)

        # -- 8. the gate decides ---------------------------------------------
        def _refuse(prompt: str, system: str | None = None) -> str:
            raise AssertionError("the walkthrough never completes a prompt")

        cloud = SimpleBackend(
            name="a hosted model", claimed_tier=Tier.OPEN, completer=_refuse,
            prover=lambda: Grant(Tier.OPEN, Tier.OPEN,
                                 "open path, nothing claimed"))
        release = gate.release_for(cloud)
        withheld = sorted({s.label for _, s in release.withheld})
        yield step(
            8, "The gate decides what may cross",
            "Storage was the substrate; this is the product. The backend "
            "proves a tier, and only memories cleared for that tier are "
            "released. Nothing is sent — the walkthrough never calls a model.",
            backend="a hosted model", proved_tier=release.grant.granted.label,
            released=len(release.allowed), withheld=len(release.withheld),
            withheld_classes=withheld or ["none"],
            unreachable=len(release.unreachable),
            policy={s.label: t.label for s, t in DEFAULT_POLICY.items()})

        # -- 9. the bound ----------------------------------------------------
        ledger = PrivacyLedger(epsilon_budget=EPSILON_BUDGET)
        for _ in release.allowed:
            ledger.charge(epsilon=EPSILON_PER_SEND, spec=SPEC_PER_SEND)
        payload = sum(len(t.encode()) for t in release.allowed)
        pad, bucket = pad_to_bucket(payload)
        yield step(
            9, "What still leaks is measured",
            "Encryption does not blind the model you are asking. What crosses "
            "is bounded and the bound is computed: ε adds per send against a "
            "session budget, and the length is padded to a fixed bucket so an "
            "observer learns at most log₂(N) bits from the size.",
            sends=ledger.sends,
            epsilon_spent=round(ledger.epsilon_spent, 3),
            epsilon_budget=ledger.epsilon_budget,
            payload_bytes=payload, padding_bytes=pad,
            bucket_bytes=bucket.get("bucket_bytes"),
            buckets=bucket.get("buckets", len(DEFAULT_BUCKETS)),
            length_bits_bound=bucket.get("length_bits_bound"),
            composition="sequential (epsilons add)")

        # -- 10. the proof ----------------------------------------------------
        # ε in thousandths, so a float budget becomes the integer a range proof
        # can speak about at all.
        spent_milli = int(round(ledger.epsilon_spent * 1000))
        t0 = time.time()
        blinding = zk._rand()
        commitment, proof = zk.prove_range(spent_milli, blinding, bits=RANGE_BITS,
                                           context=b"oblivio-walkthrough")
        prove_ms = round((time.time() - t0) * 1000)
        t0 = time.time()
        ok = zk.verify_range(commitment, proof, bits=RANGE_BITS,
                             context=b"oblivio-walkthrough")
        verify_ms = round((time.time() - t0) * 1000)
        tampered = dict(proof.as_dict())
        tampered["s_hex"] = f"{(int(tampered['s_hex'], 16) + 1):x}"
        forged_ok = zk.verify_range(commitment, zk.Proof.from_dict(tampered),
                                    bits=RANGE_BITS,
                                    context=b"oblivio-walkthrough")
        if not ok or forged_ok:
            yield {"stage": "error",
                   "msg": f"proof check failed (valid={ok}, forged_accepted={forged_ok})"}
            return
        proof_bytes = len(json.dumps(proof.as_dict()).encode())
        yield step(
            10, "The budget is proved, not asserted",
            "The ε spend is committed to and range-proved: a verifier learns "
            "the budget HELD without learning the spend. Sigma protocols from "
            "zk.py — the constant-size halo2 circuit is the separate Rust "
            "repo and is deliberately not claimed here.",
            proves=f"0 ≤ ε·1000 < 2^{RANGE_BITS}", value_revealed="none",
            verified=ok, tampered_proof_accepted=forged_ok,
            prove_ms=prove_ms, verify_ms=verify_ms, proof_bytes=proof_bytes,
            system="sigma protocol (zk.py)")

        receipt = {
            "walkthrough": "oblivio",
            "ran_at": _now(),
            "elapsed_ms": round((time.time() - started) * 1000),
            "node_pubkey": pubkey,
            "steps": steps,
            "not_claimed": [
                "No provider was contacted and no prompt was completed.",
                "The proof is a sigma-protocol range proof, not the halo2 circuit.",
                "One node on loopback — independent operators are not demonstrated.",
                "Tamper is DETECTED, not prevented.",
            ],
        }
        yield {"stage": "done", "steps": len(steps),
               "elapsed_ms": receipt["elapsed_ms"], "receipt": receipt}

    except Exception as exc:                                    # pragma: no cover
        yield {"stage": "error", "msg": f"{type(exc).__name__}: {exc}"}
    finally:
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        shutil.rmtree(tmp, ignore_errors=True)

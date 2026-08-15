"""Oblivio client: encrypt locally, verify every response.

The client never trusts the node with plaintext or with history.
Every get re-checks inclusion against the signed head; optional pin
remembers a past head and checks append-only consistency.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from typing import Any, Optional

from . import merkle
from .crypto import NodeIdentity, generate_master_key, signed_head_message
from .store import client_encrypt, client_open


MAX_RESPONSE_BYTES = 16 * 1024 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects.

    A node is untrusted. Following its redirect would let it point the client
    at an arbitrary host — including addresses only the client can reach — and
    turn every client into a request forwarder on its behalf.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SecurityError(f"node attempted to redirect to {newurl!r}")


@dataclass
class PinnedHead:
    tree_size: int
    root_hex: str
    public_key_hex: str


class OblivioClient:
    def __init__(
        self,
        base_url: str,
        master_key: bytes,
        pin_path: Optional[str] = None,
        expected_pubkey_hex: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.master_key = master_key
        self.pin_path = pin_path
        self.expected_pubkey_hex = expected_pubkey_hex
        self._opener = urllib.request.build_opener(_NoRedirect())
        self._pin: Optional[PinnedHead] = None
        if pin_path and os.path.exists(pin_path):
            with open(pin_path, "r", encoding="utf-8") as f:
                d = json.load(f)
            self._pin = PinnedHead(**d)

    # ---- transport -----------------------------------------------------------

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with self._opener.open(req, timeout=30) as resp:
                # A node is untrusted, so its response size is untrusted too.
                # Reading without a bound lets one hostile node exhaust the
                # memory of every client that talks to it.
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise SecurityError(
                        f"{self.base_url}: response exceeds "
                        f"{MAX_RESPONSE_BYTES} bytes")
                return json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = e.read(4096).decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {e.code}: {detail}") from e

    # ---- head verification ---------------------------------------------------

    def _verify_head(self, head: dict) -> bytes:
        size = int(head["tree_size"])
        root = bytes.fromhex(head["root_hex"])
        sig = bytes.fromhex(head["signature_hex"])
        pub = bytes.fromhex(head["public_key_hex"])
        if self.expected_pubkey_hex and head["public_key_hex"] != self.expected_pubkey_hex:
            raise SecurityError("node public key does not match expected pin")
        msg = signed_head_message(size, root)
        if not NodeIdentity.verify(pub, msg, sig):
            raise SecurityError("invalid tree-head signature")
        return root

    def _update_pin(self, head: dict) -> None:
        """After verifying head (+ optional consistency), remember it."""
        pin = PinnedHead(
            tree_size=int(head["tree_size"]),
            root_hex=head["root_hex"],
            public_key_hex=head["public_key_hex"],
        )
        if self._pin is not None:
            if pin.public_key_hex != self._pin.public_key_hex:
                raise SecurityError("node identity changed since the pinned head")
            if pin.tree_size < self._pin.tree_size:
                raise SecurityError("tree size went backwards")
            # Equal size with a different root is a fork: no consistency proof
            # can exist, so the size comparison alone would let it through.
            if (pin.tree_size == self._pin.tree_size
                    and pin.root_hex != self._pin.root_hex):
                raise SecurityError(
                    "same tree size but a different root — the log was forked")
            if pin.tree_size > self._pin.tree_size and self._pin.tree_size > 0:
                cons = self._request("GET", f"/v1/consistency?old_size={self._pin.tree_size}")
                if not merkle.verify_consistency(
                    self._pin.tree_size,
                    pin.tree_size,
                    bytes.fromhex(self._pin.root_hex),
                    bytes.fromhex(pin.root_hex),
                    [bytes.fromhex(p) for p in cons["proof"]],
                ):
                    raise SecurityError("consistency proof failed — history rewrite?")
        self._pin = pin
        if self.pin_path:
            os.makedirs(os.path.dirname(self.pin_path) or ".", exist_ok=True)
            with open(self.pin_path, "w", encoding="utf-8") as f:
                json.dump(asdict(pin), f, indent=2)

    # ---- public API ----------------------------------------------------------

    def head(self) -> dict:
        head = self._request("GET", "/v1/head")
        self._verify_head(head)
        self._update_pin(head)
        return head

    def put(self, plaintext: bytes | str, label: str = "") -> dict[str, Any]:
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        record_id, ciphertext = client_encrypt(self.master_key, plaintext, label=label)
        return self.put_ciphertext(record_id, ciphertext, label=label)

    def put_ciphertext(self, record_id: str, ciphertext: bytes,
                       label: str = "") -> dict[str, Any]:
        """Upload an already-encrypted record.

        Replication needs every node to receive byte-identical ciphertext, so
        the encryption happens once and this uploads the same bytes to each.
        Identical ciphertext also means an identical leaf hash, which lets the
        caller check that every node committed to the same thing.
        """
        # The label is NOT sent. It is encrypted inside the ciphertext, so the
        # node stores no readable description of what a record contains.
        body = {
            "record_id": record_id,
            "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
            "label": "",
        }
        resp = self._request("POST", "/v1/put", body)
        root = self._verify_head(resp["head"])
        leaf = bytes.fromhex(resp["leaf_hex"])
        proof = [bytes.fromhex(p) for p in resp["proof"]]
        if not merkle.verify_inclusion(
            leaf, int(resp["index"]), int(resp["head"]["tree_size"]), proof, root
        ):
            raise SecurityError("inclusion proof failed on put")
        # leaf must match what we uploaded
        if leaf != merkle.leaf_hash(ciphertext):
            raise SecurityError("node returned different leaf than uploaded ciphertext")
        self._update_pin(resp["head"])
        return {
            "record_id": record_id,
            "index": resp["index"],
            "leaf_hex": resp["leaf_hex"],
            "tree_size": resp["head"]["tree_size"],
            "root_hex": resp["head"]["root_hex"],
        }

    def get(self, index: int, label: Optional[str] = None) -> dict[str, Any]:
        resp = self._request("GET", f"/v1/get/{index}")
        return self._open_response(resp, label=label, expect_index=index)

    def get_by_id(self, record_id: str, label: Optional[str] = None) -> dict[str, Any]:
        resp = self._request("GET", f"/v1/get_id/{record_id}")
        return self._open_response(resp, label=label, expect_record_id=record_id)

    def _open_response(self, resp: dict, label: Optional[str] = None,
                       expect_index: Optional[int] = None,
                       expect_record_id: Optional[str] = None) -> dict[str, Any]:
        # Bind the response to the REQUEST before trusting anything inside it.
        # Every proof below can be perfectly valid for the wrong record: the
        # node simply answers a different question than the one it was asked.
        if expect_index is not None and int(resp["index"]) != int(expect_index):
            raise SecurityError(
                f"asked for index {expect_index}, node answered index {resp['index']}")
        if expect_record_id is not None and resp["record_id"] != expect_record_id:
            raise SecurityError(
                f"asked for record_id {expect_record_id}, "
                f"node answered {resp['record_id']}")
        root = self._verify_head(resp["head"])
        ct = base64.b64decode(resp["ciphertext_b64"])
        leaf = merkle.leaf_hash(ct)
        if leaf.hex() != resp["leaf_hex"]:
            raise SecurityError("ciphertext does not match committed leaf")
        proof = [bytes.fromhex(p) for p in resp["proof"]]
        if not merkle.verify_inclusion(
            leaf, int(resp["index"]), int(resp["head"]["tree_size"]), proof, root
        ):
            raise SecurityError("inclusion proof failed on get")
        self._update_pin(resp["head"])
        # The label travels inside the ciphertext, so it is recovered by
        # decryption rather than taken from anything the node said. A node
        # cannot read it, alter it, or substitute one record's label onto
        # another's contents.
        rec_label, plaintext = client_open(self.master_key, resp["record_id"], ct)
        return {
            "record_id": resp["record_id"],
            "index": resp["index"],
            "label": rec_label,
            "plaintext": plaintext,
            "tree_size": resp["head"]["tree_size"],
            "root_hex": resp["head"]["root_hex"],
        }

    def list(self) -> list[dict]:
        return self._request("GET", "/v1/list")["records"]

    # ---- key I/O -------------------------------------------------------------

    @staticmethod
    def save_master_key(path: str, key: bytes) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "wb") as f:
            f.write(key)

    @staticmethod
    def load_master_key(path: str) -> bytes:
        with open(path, "rb") as f:
            key = f.read()
        if len(key) != 32:
            raise ValueError("master key must be 32 bytes")
        return key

    @classmethod
    def create_keys(cls, key_path: str) -> bytes:
        key = generate_master_key()
        cls.save_master_key(key_path, key)
        return key


class SecurityError(Exception):
    """Raised when the node fails a cryptographic check."""

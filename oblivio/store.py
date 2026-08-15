"""Append-only encrypted memory store with Merkle commitments.

Layout under data_dir/:
  identity.pem     node signing key
  records/         ciphertext blobs (hex-named by leaf hash)
  log.jsonl        one JSON line per append: index, leaf_hex, meta
  head.json        latest signed tree head (size, root, signature)
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, asdict
from typing import Any, Optional

from . import merkle
from .crypto import (
    NodeIdentity,
    decrypt,
    encrypt,
    generate_master_key,
    signed_head_message,
)


@dataclass
class RecordMeta:
    record_id: str          # client-facing uuid hex
    leaf_hex: str           # merkle leaf = hash(envelope)
    index: int
    size: int               # ciphertext byte length
    created_at: float
    label: str = ""         # optional client tag (not secret)


@dataclass
class TreeHead:
    tree_size: int
    root_hex: str
    signature_hex: str
    public_key_hex: str
    signed_at: float


class MemoryStore:
    """Local node store: holds ciphertext, publishes signed Merkle heads."""

    def __init__(self, data_dir: str, identity: Optional[NodeIdentity] = None):
        self.data_dir = data_dir
        self.records_dir = os.path.join(data_dir, "records")
        self.log_path = os.path.join(data_dir, "log.jsonl")
        self.head_path = os.path.join(data_dir, "head.json")
        self.identity_path = os.path.join(data_dir, "identity.pem")
        os.makedirs(self.records_dir, exist_ok=True)

        if identity is not None:
            self.identity = identity
            self.identity.save(self.identity_path)
        elif os.path.exists(self.identity_path):
            self.identity = NodeIdentity.load(self.identity_path)
        else:
            self.identity = NodeIdentity.generate()
            self.identity.save(self.identity_path)

        self._lock = threading.RLock()
        # The tree keeps its internal nodes so a proof is a lookup, not a re-derivation.
        # `_leaves` stays the live level-0 list, so every existing reader still sees exactly what
        # it saw before; only append goes through the log. Serving one proof per record was O(n^2)
        # — ~306 hours for a million records on a laptop, now ~5 seconds.
        self._log = merkle.CachedLog()
        self._leaves: list[bytes] = self._log.levels[0]
        self._meta: list[RecordMeta] = []
        self._by_record_id: dict[str, int] = {}
        self._load()

    # ---- persistence ---------------------------------------------------------

    def _load(self) -> None:
        if not os.path.exists(self.log_path):
            self._publish_head()
            return
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                leaf = bytes.fromhex(row["leaf_hex"])
                self._log.append(leaf)
                self._meta.append(RecordMeta(
                    record_id=row["record_id"],
                    leaf_hex=row["leaf_hex"],
                    index=row["index"],
                    size=row["size"],
                    created_at=row["created_at"],
                    label=row.get("label", ""),
                ))
                # First write of an id wins, so a later duplicate cannot
                # displace the record a client already holds a proof for.
                self._by_record_id.setdefault(row["record_id"], row["index"])
        if not os.path.exists(self.head_path):
            self._publish_head()

    def _append_log(self, meta: RecordMeta) -> None:
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(meta)) + "\n")

    def _publish_head(self) -> TreeHead:
        root = self._log.root()
        size = len(self._leaves)
        msg = signed_head_message(size, root)
        sig = self.identity.sign(msg)
        head = TreeHead(
            tree_size=size,
            root_hex=root.hex(),
            signature_hex=sig.hex(),
            public_key_hex=self.identity.public_hex(),
            signed_at=time.time(),
        )
        with open(self.head_path, "w", encoding="utf-8") as f:
            json.dump(asdict(head), f, indent=2)
        return head

    # ---- public API ----------------------------------------------------------

    def head(self) -> TreeHead:
        with self._lock:
            if os.path.exists(self.head_path):
                with open(self.head_path, "r", encoding="utf-8") as f:
                    d = json.load(f)
                return TreeHead(**d)
            return self._publish_head()

    def put_ciphertext(self, record_id: str, ciphertext: bytes,
                       label: str = "") -> dict[str, Any]:
        """Append opaque ciphertext. Returns index + inclusion proof + head."""
        if not record_id or not ciphertext:
            raise ValueError("record_id and ciphertext required")
        leaf = merkle.leaf_hash(ciphertext)
        with self._lock:
            index = len(self._leaves)
            path = os.path.join(self.records_dir, leaf.hex())
            with open(path, "wb") as f:
                f.write(ciphertext)
            meta = RecordMeta(
                record_id=record_id,
                leaf_hex=leaf.hex(),
                index=index,
                size=len(ciphertext),
                created_at=time.time(),
                label=label or "",
            )
            self._log.append(leaf)
            self._meta.append(meta)
            self._by_record_id.setdefault(record_id, index)
            self._append_log(meta)
            head = self._publish_head()
            proof = self._log.inclusion_proof(index)
            return {
                "record_id": record_id,
                "index": index,
                "leaf_hex": leaf.hex(),
                "proof": [p.hex() for p in proof],
                "head": asdict(head),
            }

    def get(self, index: int) -> dict[str, Any]:
        with self._lock:
            if not 0 <= index < len(self._leaves):
                raise IndexError(f"index {index} out of range")
            meta = self._meta[index]
            path = os.path.join(self.records_dir, meta.leaf_hex)
            with open(path, "rb") as f:
                ct = f.read()
            proof = self._log.inclusion_proof(index)
            head = self.head()
            return {
                "record_id": meta.record_id,
                "index": index,
                "label": meta.label,
                "ciphertext_b64": base64.b64encode(ct).decode("ascii"),
                "leaf_hex": meta.leaf_hex,
                "proof": [p.hex() for p in proof],
                "head": asdict(head),
                "created_at": meta.created_at,
            }

    def get_by_record_id(self, record_id: str) -> dict[str, Any]:
        # Indexed rather than scanned: a linear search made every lookup O(n),
        # so a client issuing lookups against a large log could consume the
        # node's CPU at almost no cost to itself.
        with self._lock:
            index = self._by_record_id.get(record_id)
            if index is None:
                raise KeyError(record_id)
            return self.get(index)

    def consistency(self, old_size: int) -> dict[str, Any]:
        with self._lock:
            n = len(self._leaves)
            if old_size < 0 or old_size > n:
                raise ValueError(f"old_size {old_size} out of range")
            old_root = merkle.root(self._leaves[:old_size]) if old_size else merkle.EMPTY_ROOT
            proof = merkle.consistency_proof(old_size, self._leaves)
            head = self.head()
            return {
                "old_size": old_size,
                "old_root_hex": old_root.hex(),
                "proof": [p.hex() for p in proof],
                "head": asdict(head),
            }

    def list_meta(self) -> list[dict[str, Any]]:
        with self._lock:
            return [asdict(m) for m in self._meta]

    @property
    def size(self) -> int:
        return len(self._leaves)


# ---- client-side helpers used by client.py -----------------------------------


def new_record_id() -> str:
    return uuid.uuid4().hex


# ---- record framing: metadata minimisation -----------------------------------
#
# Everything a node could otherwise read is moved inside the ciphertext.
#
#   * The label is encrypted with the record. Nodes never receive it. It was
#     previously stored in plaintext, which leaked the one piece of metadata
#     users are most likely to make descriptive ("medical", "passwords").
#   * Records are padded to a fixed block boundary before encryption, so the
#     stored length reveals only a bucket rather than an exact size.
#
# This does not hide *which* record is read — that requires private information
# retrieval and remains an open limitation. It does close the two metadata
# leaks that need no new cryptography.

# Domain tag frozen from before the Oblivio rename: existing data/signatures verify against it. Never rename.
AAD_V1 = b"blindkeep-record-v1"
PAD_BLOCK = 256          # bounded overhead: at most 255 bytes per record
_HEADER = 6              # 2 bytes label length + 4 bytes payload length


def _frame(label: str, plaintext: bytes) -> bytes:
    """Pack label and payload into a padded, fixed-shape buffer."""
    lb = label.encode("utf-8")
    if len(lb) > 0xFFFF:
        raise ValueError("label too long")
    if len(plaintext) > 0xFFFFFFFF:
        raise ValueError("record too large")
    body = len(lb).to_bytes(2, "big") + len(plaintext).to_bytes(4, "big") + lb + plaintext
    pad = (-len(body)) % PAD_BLOCK
    return body + b"\x00" * pad


def _unframe(buf: bytes) -> tuple[str, bytes]:
    if len(buf) < _HEADER:
        raise ValueError("record too short to be valid")
    label_len = int.from_bytes(buf[:2], "big")
    payload_len = int.from_bytes(buf[2:6], "big")
    start = _HEADER + label_len
    end = start + payload_len
    if end > len(buf):
        raise ValueError("record framing is inconsistent")
    return buf[_HEADER:start].decode("utf-8"), buf[start:end]


def client_encrypt(master_key: bytes, plaintext: bytes,
                   label: str = "") -> tuple[str, bytes]:
    """Encrypt a record. The label travels inside the ciphertext, and the
    result is padded so its length reveals only a 256-byte bucket."""
    rid = new_record_id()
    blob = encrypt(master_key, bytes.fromhex(rid), _frame(label, plaintext),
                   aad=AAD_V1)
    return rid, blob


def client_open(master_key: bytes, record_id: str,
                ciphertext: bytes) -> tuple[str, bytes]:
    """Decrypt a record, returning (label, plaintext)."""
    buf = decrypt(master_key, bytes.fromhex(record_id), ciphertext, aad=AAD_V1)
    return _unframe(buf)


def client_decrypt(master_key: bytes, record_id: str, ciphertext: bytes,
                   label: str = "") -> bytes:
    """Decrypt and return the payload only.

    `label` is accepted for call compatibility and ignored: the label is now
    carried inside the ciphertext rather than supplied alongside it.
    """
    return client_open(master_key, record_id, ciphertext)[1]


__all__ = [
    "MemoryStore",
    "RecordMeta",
    "TreeHead",
    "new_record_id",
    "client_encrypt",
    "client_decrypt",
    "generate_master_key",
]

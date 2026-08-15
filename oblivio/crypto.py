"""Node identity and client-side encryption.

Privacy is not a ZK proof: the node never sees plaintext.
  * Client encrypts with AES-256-GCM before upload.
  * Node signs tree heads with Ed25519 so clients can pin a log tip.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ---- Node identity (Ed25519) -------------------------------------------------


@dataclass
class NodeIdentity:
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    @classmethod
    def generate(cls) -> "NodeIdentity":
        sk = Ed25519PrivateKey.generate()
        return cls(private_key=sk, public_key=sk.public_key())

    @classmethod
    def load(cls, path: str) -> "NodeIdentity":
        with open(path, "rb") as f:
            data = f.read()
        sk = serialization.load_pem_private_key(data, password=None)
        if not isinstance(sk, Ed25519PrivateKey):
            raise TypeError("expected Ed25519 private key")
        return cls(private_key=sk, public_key=sk.public_key())

    def save(self, path: str) -> None:
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "wb") as f:
            f.write(pem)

    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def public_hex(self) -> str:
        return self.public_bytes().hex()

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message)

    @staticmethod
    def verify(public_raw: bytes, message: bytes, signature: bytes) -> bool:
        try:
            pk = Ed25519PublicKey.from_public_bytes(public_raw)
            pk.verify(signature, message)
            return True
        except Exception:
            return False


def signed_head_message(tree_size: int, root: bytes) -> bytes:
    """Canonical bytes a node signs for a published tree head."""
    # Domain tag frozen from before the Oblivio rename: existing data/signatures verify against it. Never rename.
    return b"blindkeep-head-v1\0" + struct.pack(">Q", tree_size) + root


# ---- Client envelope encryption ----------------------------------------------


def generate_master_key() -> bytes:
    """32-byte master secret kept only on the client."""
    return AESGCM.generate_key(bit_length=256)


def _record_key(master_key: bytes, record_id: bytes) -> bytes:
    """Per-record key via HKDF so one key leak does not decrypt the whole store."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        # Domain tag frozen from before the Oblivio rename: existing data/signatures verify against it. Never rename.
        info=b"blindkeep-record-v1" + record_id,
    ).derive(master_key)


def encrypt(master_key: bytes, record_id: bytes, plaintext: bytes,
            aad: bytes = b"") -> bytes:
    """Return nonce || ciphertext||tag. Node stores this blob; never plaintext."""
    key = _record_key(master_key, record_id)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ct


def decrypt(master_key: bytes, record_id: bytes, blob: bytes,
            aad: bytes = b"") -> bytes:
    if len(blob) < 12 + 16:
        raise ValueError("ciphertext too short")
    key = _record_key(master_key, record_id)
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, aad)

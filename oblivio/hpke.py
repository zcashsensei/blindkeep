"""HPKE (RFC 9180), base mode, in the one ciphersuite Oblivious HTTP needs.

`oblivious.py` is the module that matters; this is the layer underneath it, written because
`cryptography` exposes X25519, HKDF and AES-GCM but not the HPKE construction that combines them.
Everything here is assembled from those three primitives — **no new cryptography is invented, and
none should be.** The whole value of HPKE is that it is specified, analysed and test-vectored;
a variant of it is worth nothing.

Suite: **DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM** — `0x0020 / 0x0001 / 0x0001`,
the mandatory-to-implement suite in RFC 9458 §4.

**Why the labels look so fussy.** Every Extract and Expand is domain-separated by a suite id and a
label (`LabeledExtract`, `LabeledExpand`). It reads like ceremony and is not: without it, key
material derived for one purpose in one suite can collide with another, and the security proof
depends on those strings being exactly right. They are byte-for-byte from the RFC, and
`test_hpke.py` checks them against the RFC's own published vectors rather than against my reading
of them. **A hand-rolled HPKE that has not reproduced the official vectors is not HPKE**, so the
vector test is the only thing that makes this file usable at all.

Base mode only. PSK and authenticated modes are not implemented and their mode bytes are refused
rather than silently treated as base — OHTTP does not use them, and a mode that quietly degrades
is worse than one that is absent.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.hmac import HMAC

# Suite identifiers, RFC 9180 §7.
KEM_X25519_HKDF_SHA256 = 0x0020
KDF_HKDF_SHA256 = 0x0001
AEAD_AES_128_GCM = 0x0001

MODE_BASE = 0x00

NSECRET = 32          # DHKEM(X25519, HKDF-SHA256) shared secret
NENC = 32             # serialized ephemeral public key
NH = 32               # HKDF-SHA256 output
NK = 16               # AES-128-GCM key
NN = 12               # AES-128-GCM nonce
NT = 16               # AES-128-GCM tag

HPKE_V1 = b"HPKE-v1"


class HpkeError(Exception):
    """A refusal. No key material was derived and nothing was encrypted."""


def _i2osp(n: int, length: int) -> bytes:
    return n.to_bytes(length, "big")


def _extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract. Written out because `cryptography`'s HKDF couples extract and expand."""
    h = HMAC(salt or bytes(NH), hashes.SHA256())
    h.update(ikm)
    return h.finalize()


def _expand(prk: bytes, info: bytes, length: int) -> bytes:
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(prk)


def _suite_id_kem(kem_id: int = KEM_X25519_HKDF_SHA256) -> bytes:
    return b"KEM" + _i2osp(kem_id, 2)


def _suite_id_hpke(kem_id: int = KEM_X25519_HKDF_SHA256,
                   kdf_id: int = KDF_HKDF_SHA256,
                   aead_id: int = AEAD_AES_128_GCM) -> bytes:
    return b"HPKE" + _i2osp(kem_id, 2) + _i2osp(kdf_id, 2) + _i2osp(aead_id, 2)


def labeled_extract(salt: bytes, label: bytes, ikm: bytes, suite_id: bytes) -> bytes:
    return _extract(salt, HPKE_V1 + suite_id + label + ikm)


def labeled_expand(prk: bytes, label: bytes, info: bytes, length: int,
                   suite_id: bytes) -> bytes:
    return _expand(prk, _i2osp(length, 2) + HPKE_V1 + suite_id + label + info, length)


# ---- DHKEM(X25519, HKDF-SHA256) ---------------------------------------------


def _extract_and_expand(dh: bytes, kem_context: bytes) -> bytes:
    suite = _suite_id_kem()
    eae_prk = labeled_extract(b"", b"eae_prk", dh, suite)
    return labeled_expand(eae_prk, b"shared_secret", kem_context, NSECRET, suite)


def encap(pk_r: X25519PublicKey, *, sk_e: X25519PrivateKey | None = None) -> tuple[bytes, bytes]:
    """Encapsulate to a recipient public key. Returns (shared_secret, enc).

    `sk_e` exists only so the RFC's test vectors can be reproduced with their fixed ephemeral key.
    **Production callers must never pass it** — a reused ephemeral key destroys the forward secrecy
    that is the entire reason this is an ephemeral-static scheme.
    """
    sk_e = sk_e or X25519PrivateKey.generate()
    dh = sk_e.exchange(pk_r)
    enc = sk_e.public_key().public_bytes_raw()
    return _extract_and_expand(dh, enc + pk_r.public_bytes_raw()), enc


def decap(enc: bytes, sk_r: X25519PrivateKey) -> bytes:
    if len(enc) != NENC:
        raise HpkeError(f"encapsulated key is {len(enc)} bytes, expected {NENC}")
    dh = sk_r.exchange(X25519PublicKey.from_public_bytes(enc))
    return _extract_and_expand(dh, enc + sk_r.public_key().public_bytes_raw())


# ---- key schedule ------------------------------------------------------------


@dataclass
class Context:
    """A sealed HPKE context. Holds the sequence number, because nonce reuse is fatal."""
    key: bytes
    base_nonce: bytes
    exporter_secret: bytes
    seq: int = 0

    def _nonce(self) -> bytes:
        # XOR the sequence into the base nonce, RFC 9180 §5.2. A counter rather than a random
        # nonce, so a caller cannot reuse one by accident.
        seq_bytes = _i2osp(self.seq, NN)
        return bytes(a ^ b for a, b in zip(self.base_nonce, seq_bytes))

    def seal(self, aad: bytes, plaintext: bytes) -> bytes:
        ct = AESGCM(self.key).encrypt(self._nonce(), plaintext, aad)
        self.seq += 1
        return ct

    def open(self, aad: bytes, ciphertext: bytes) -> bytes:
        pt = AESGCM(self.key).decrypt(self._nonce(), ciphertext, aad)
        self.seq += 1
        return pt

    def export(self, exporter_context: bytes, length: int) -> bytes:
        """Derive independent key material. OHTTP uses this for the response direction."""
        return labeled_expand(self.exporter_secret, b"sec", exporter_context, length,
                              _suite_id_hpke())


def key_schedule(shared_secret: bytes, info: bytes, mode: int = MODE_BASE) -> Context:
    if mode != MODE_BASE:
        raise HpkeError(
            f"mode {mode:#04x} is not implemented. Only base mode is, because that is what "
            f"OHTTP uses; treating an unimplemented mode as base would be a silent downgrade.")
    suite = _suite_id_hpke()
    psk_id_hash = labeled_extract(b"", b"psk_id_hash", b"", suite)
    info_hash = labeled_extract(b"", b"info_hash", info, suite)
    ks_context = _i2osp(mode, 1) + psk_id_hash + info_hash

    secret = labeled_extract(shared_secret, b"secret", b"", suite)
    return Context(
        key=labeled_expand(secret, b"key", ks_context, NK, suite),
        base_nonce=labeled_expand(secret, b"base_nonce", ks_context, NN, suite),
        exporter_secret=labeled_expand(secret, b"exp", ks_context, NH, suite),
    )


def setup_base_s(pk_r: X25519PublicKey, info: bytes, *,
                 sk_e: X25519PrivateKey | None = None) -> tuple[bytes, Context]:
    shared_secret, enc = encap(pk_r, sk_e=sk_e)
    return enc, key_schedule(shared_secret, info)


def setup_base_r(enc: bytes, sk_r: X25519PrivateKey, info: bytes) -> Context:
    return key_schedule(decap(enc, sk_r), info)


def generate_keypair() -> tuple[X25519PrivateKey, X25519PublicKey]:
    sk = X25519PrivateKey.generate()
    return sk, sk.public_key()

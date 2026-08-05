"""Master key recovery.

Losing `master.key` means losing every record permanently. That is a correct
cryptographic property and a fatal product defect: ordinary people lose files.
Every consumer encryption product that ignored this has failed on it.

Recovery here is entirely client-side. Nodes are not involved, learn nothing,
and cannot assist an attacker — a recovery scheme that asks a server for help
would give back the trust the rest of the design removes.

Three independent mechanisms, because people lose things in different ways:

* **Recovery code** — the key rendered as a checksummed, transcribable string.
  Write it down. Guards against disk failure.
* **Passphrase-wrapped backup** — the key sealed under a passphrase with scrypt.
  A file safe to email to yourself or keep in cloud storage. Guards against
  losing the paper.
* **Split shares** — Shamir's Secret Sharing: any *k* of *n* shares reconstruct
  the key, and *k-1* reveal nothing at all. Give shares to people or places.
  Guards against losing any single thing, including your memory of a passphrase.

None weakens confidentiality: each protects the same 32-byte secret, so the
weakest one you actually use sets your security. Choose accordingly.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

KEY_LEN = 32
_CHECKSUM_LEN = 4
_GROUP = 4                       # characters per group in a printed code

# scrypt cost. N=2**17 is roughly 128 MiB and a few hundred milliseconds, which
# is deliberately slow: this parameter is the only thing standing between a
# stolen backup file and an offline guessing attack on a human-chosen passphrase.
_SCRYPT_N = 2 ** 17
_SCRYPT_R = 8
_SCRYPT_P = 1
_BACKUP_MAGIC = b"BLINDKEEP-BACKUP-v1"


class RecoveryError(Exception):
    """A recovery input was malformed, corrupt, or insufficient."""


# --------------------------------------------------------------------------- #
# 1. Recovery code
# --------------------------------------------------------------------------- #

def _checksum(key: bytes) -> bytes:
    return hashlib.sha256(b"blindkeep-recovery-v1" + key).digest()[:_CHECKSUM_LEN]


def to_recovery_code(key: bytes) -> str:
    """Render a key as a grouped, checksummed string safe to write on paper."""
    if len(key) != KEY_LEN:
        raise RecoveryError(f"key must be {KEY_LEN} bytes, got {len(key)}")
    raw = base64.b32encode(key + _checksum(key)).decode("ascii").rstrip("=")
    return "-".join(raw[i:i + _GROUP] for i in range(0, len(raw), _GROUP))


def from_recovery_code(code: str) -> bytes:
    """Parse a recovery code, rejecting transcription errors via the checksum.

    Accepts any spacing or case, and repairs the two substitutions people make
    most often when copying by hand: O for 0 and I/L for 1. Base32's alphabet
    excludes 0/1/8/9 precisely so this is unambiguous.
    """
    cleaned = (code.strip().upper()
               .replace("-", "").replace(" ", "").replace("\n", "")
               .replace("0", "O").replace("1", "I").replace("8", "B"))
    if not cleaned:
        raise RecoveryError("recovery code is empty")
    padding = "=" * (-len(cleaned) % 8)
    try:
        blob = base64.b32decode(cleaned + padding)
    except Exception as exc:
        raise RecoveryError(f"recovery code is not valid: {exc}") from exc
    if len(blob) != KEY_LEN + _CHECKSUM_LEN:
        raise RecoveryError(
            f"recovery code decodes to {len(blob)} bytes, expected "
            f"{KEY_LEN + _CHECKSUM_LEN} — it looks truncated or has extra characters")
    key, check = blob[:KEY_LEN], blob[KEY_LEN:]
    if _checksum(key) != check:
        raise RecoveryError(
            "recovery code failed its checksum — it was mistyped. "
            "The key is NOT recovered; check the code and try again.")
    return key


# --------------------------------------------------------------------------- #
# 2. Passphrase-wrapped backup
# --------------------------------------------------------------------------- #

def wrap_key(key: bytes, passphrase: str) -> bytes:
    """Seal a key under a passphrase. Output is safe to store anywhere."""
    if len(key) != KEY_LEN:
        raise RecoveryError(f"key must be {KEY_LEN} bytes")
    if not passphrase:
        raise RecoveryError("passphrase must not be empty")
    salt = os.urandom(16)
    kek = Scrypt(salt=salt, length=32, n=_SCRYPT_N, r=_SCRYPT_R,
                 p=_SCRYPT_P).derive(passphrase.encode("utf-8"))
    nonce = os.urandom(12)
    sealed = AESGCM(kek).encrypt(nonce, key, _BACKUP_MAGIC)
    return _BACKUP_MAGIC + salt + nonce + sealed


def unwrap_key(blob: bytes, passphrase: str) -> bytes:
    """Recover a key from a passphrase-wrapped backup."""
    if not blob.startswith(_BACKUP_MAGIC):
        raise RecoveryError("not a Blindkeep backup file")
    body = blob[len(_BACKUP_MAGIC):]
    if len(body) < 16 + 12 + 16:
        raise RecoveryError("backup file is truncated")
    salt, nonce, sealed = body[:16], body[16:28], body[28:]
    kek = Scrypt(salt=salt, length=32, n=_SCRYPT_N, r=_SCRYPT_R,
                 p=_SCRYPT_P).derive(passphrase.encode("utf-8"))
    try:
        return AESGCM(kek).decrypt(nonce, sealed, _BACKUP_MAGIC)
    except Exception as exc:
        raise RecoveryError("wrong passphrase, or the backup file is damaged") from exc


# --------------------------------------------------------------------------- #
# 3. Split shares — Shamir's Secret Sharing over GF(256)
# --------------------------------------------------------------------------- #
#
# Each byte of the key is the constant term of an independent random polynomial
# of degree k-1 over GF(256). A share is that polynomial evaluated at x=i.
# Any k shares interpolate back to x=0; any k-1 are information-theoretically
# independent of the secret — not merely hard to invert, but carrying no
# information about it whatsoever.

_EXP = [0] * 512
_LOG = [0] * 256


def _init_tables() -> None:
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        x ^= (x << 1) ^ (0x11B if x & 0x80 else 0)   # AES field polynomial
        x &= 0xFF
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_init_tables()


def _mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("division by zero in GF(256)")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


@dataclass(frozen=True)
class Share:
    index: int
    data: bytes

    def encode(self) -> str:
        body = bytes([self.index]) + self.data
        raw = base64.b32encode(body + _checksum_share(body)).decode("ascii").rstrip("=")
        return f"{self.index}-" + "-".join(
            raw[i:i + _GROUP] for i in range(0, len(raw), _GROUP))

    @classmethod
    def decode(cls, text: str) -> "Share":
        cleaned = text.strip().upper().replace(" ", "").replace("\n", "")
        if "-" not in cleaned:
            raise RecoveryError(f"share is malformed: {text[:24]!r}")
        _, _, rest = cleaned.partition("-")
        rest = rest.replace("-", "").replace("0", "O").replace("1", "I").replace("8", "B")
        try:
            blob = base64.b32decode(rest + "=" * (-len(rest) % 8))
        except Exception as exc:
            raise RecoveryError(f"share is not valid: {exc}") from exc
        if len(blob) < 1 + _CHECKSUM_LEN:
            raise RecoveryError("share is truncated")
        body, check = blob[:-_CHECKSUM_LEN], blob[-_CHECKSUM_LEN:]
        if _checksum_share(body) != check:
            raise RecoveryError("share failed its checksum — it was mistyped")
        return cls(index=body[0], data=body[1:])


def _checksum_share(body: bytes) -> bytes:
    return hashlib.sha256(b"blindkeep-share-v1" + body).digest()[:_CHECKSUM_LEN]


def split_key(key: bytes, threshold: int, shares: int) -> list[Share]:
    """Split a key so any `threshold` of `shares` reconstruct it."""
    if len(key) != KEY_LEN:
        raise RecoveryError(f"key must be {KEY_LEN} bytes")
    if not 2 <= threshold <= shares <= 255:
        raise RecoveryError(
            f"need 2 <= threshold <= shares <= 255, got "
            f"threshold={threshold} shares={shares}")

    out: list[bytearray] = [bytearray() for _ in range(shares)]
    for byte in key:
        # coefficients[0] is the secret byte; the rest are uniformly random
        coefficients = [byte] + [secrets.randbelow(256) for _ in range(threshold - 1)]
        for s in range(shares):
            x = s + 1                      # x=0 is the secret, never handed out
            acc = 0
            for coeff in reversed(coefficients):   # Horner evaluation
                acc = _mul(acc, x) ^ coeff
            out[s].append(acc)
    return [Share(index=i + 1, data=bytes(d)) for i, d in enumerate(out)]


def combine_shares(shares: list[Share]) -> bytes:
    """Reconstruct a key from shares via Lagrange interpolation at x=0."""
    if len(shares) < 2:
        raise RecoveryError("at least 2 shares are required")
    seen = {s.index for s in shares}
    if len(seen) != len(shares):
        raise RecoveryError("duplicate share indices — shares must be distinct")
    if 0 in seen:
        raise RecoveryError("share index 0 is invalid")
    length = len(shares[0].data)
    if any(len(s.data) != length for s in shares):
        raise RecoveryError("shares have different lengths — they are not from one split")

    secret = bytearray()
    for pos in range(length):
        acc = 0
        for i, si in enumerate(shares):
            num, den = 1, 1
            for j, sj in enumerate(shares):
                if i == j:
                    continue
                num = _mul(num, sj.index)              # (0 - x_j) == x_j in GF(2^n)
                den = _mul(den, si.index ^ sj.index)
            acc ^= _mul(si.data[pos], _div(num, den))
        secret.append(acc)

    if len(secret) != KEY_LEN:
        raise RecoveryError(
            f"reconstructed {len(secret)} bytes, expected {KEY_LEN} — "
            f"shares may be from different splits")
    return bytes(secret)

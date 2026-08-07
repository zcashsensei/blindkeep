"""Prove you are entitled to ask, without revealing who is asking.

`delegate.py` removes your content from the question. It cannot remove *you* from the request:
the provider still sees an authenticated account, an IP, a time. A question about nobody, sent
from a named subscriber, still says "this person asked something about debt recovery at 14:20".

That gap is not a new problem and it does not need a new solution. Zcash hides who spent a note
while still proving the note was theirs to spend, and the property it preserves is exactly the
one wanted here — *unlinkability of authorisation*. `RFC 9578 (Privacy Pass)` standardises the
web-shaped version: a token signed at issuance is not feasibly linkable to the token redeemed
later.

This is Chaum's blind signature, the construction underneath Privacy Pass's publicly-verifiable
token type:

    client   picks a token, blinds it with a random factor, sends the blinded value
    issuer   signs what it cannot read, and learns nothing about the token
    client   removes the blinding — a valid signature on a token the issuer never saw
    redeem   present the token; the issuer verifies it signed *something*, not *this*

The issuer's two views — what it signed, and what came back — are **independent**. It can count
its subscribers and refuse strangers; it cannot say which subscriber asked which question.

**Full-domain hashing is not optional here.** Signing a raw blinded message would let anyone
multiply two signatures into a third, because RSA is multiplicatively homomorphic — the exact
property that makes blinding work also makes naive blind signing forgeable. Hashing the token
into the full range of the modulus first removes the attacker's control of the value being
signed, so the forgery has nothing to build from. `test_anon_token.py` attacks this directly.

**What this is not.** Not RFC 9474 RSABSSA, which uses PSS and has a security proof under
stronger assumptions; this is the simpler full-domain-hash construction. Unaudited. And it hides
*who*, never *that*: the provider still learns a request happened, and network-level identity
(IP, TLS fingerprint, timing) is a separate problem this does not touch.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import rsa

TOKEN_BYTES = 32


class TokenError(Exception):
    """A token was refused. It was not honoured and not spent."""


def _mgf1(seed: bytes, length: int) -> bytes:
    """Expand a seed to arbitrary length. The standard construction, not a novel one."""
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def full_domain_hash(token: bytes, n: int) -> int:
    """Map a token across the whole modulus range.

    The security-critical step. Without it the issuer signs a value the client fully controls,
    and RSA's multiplicative structure turns two honest signatures into a forged third. Hashing
    first means a forger would need preimages, not arithmetic.
    """
    size = (n.bit_length() + 7) // 8
    # One byte short of the modulus, so the result is always < n without needing rejection.
    raw = _mgf1(b"blindkeep-anon-token-v1\0" + token, size - 1)
    return int.from_bytes(raw, "big") % n


@dataclass(frozen=True)
class Token:
    """A redeemable, unlinkable proof of entitlement."""
    value_hex: str
    signature_hex: str

    @property
    def value(self) -> bytes:
        return bytes.fromhex(self.value_hex)

    def as_dict(self) -> dict:
        return {"token_hex": self.value_hex, "signature_hex": self.signature_hex}


class Issuer:
    """Signs blinded tokens, and refuses one that has already been spent.

    Holds a spent-token set because a blind signature is unlinkable, not un-copyable: nothing in
    the token itself stops it being redeemed twice, and an issuer that does not remember has
    issued an unlimited pass rather than one.
    """

    def __init__(self, key: Optional[rsa.RSAPrivateKey] = None, bits: int = 2048):
        self._key = key or rsa.generate_private_key(public_exponent=65537, key_size=bits)
        nums = self._key.private_numbers()
        pub = nums.public_numbers
        self.n = pub.n
        self.e = pub.e
        self._d = nums.d
        self.spent: set[str] = set()
        self.issued = 0

    @property
    def public(self) -> tuple[int, int]:
        return self.n, self.e

    def sign_blinded(self, blinded: int) -> int:
        """Sign a value the issuer cannot read. This is the whole point of the exchange."""
        if not 0 < blinded < self.n:
            raise TokenError("blinded value is outside the modulus")
        self.issued += 1
        return pow(blinded, self._d, self.n)

    def redeem(self, token: Token) -> None:
        """Accept a token once. Raises on a forgery or a replay; never returns False quietly."""
        if not self.verify(token):
            raise TokenError("token signature is not valid")
        if token.value_hex in self.spent:
            raise TokenError("token has already been spent")
        self.spent.add(token.value_hex)

    def verify(self, token: Token) -> bool:
        try:
            sig = int(token.signature_hex, 16)
            value = token.value
        except ValueError:
            return False
        if not 0 < sig < self.n:
            return False
        return pow(sig, self.e, self.n) == full_domain_hash(value, self.n)


@dataclass
class Client:
    """Holds the blinding factor, which is what makes the issuer's two views independent."""
    n: int
    e: int
    _token: bytes = field(default=b"", repr=False)
    _r: int = field(default=0, repr=False)

    def blind(self) -> int:
        """A fresh token and a fresh blinding factor. Reusing either destroys unlinkability."""
        self._token = secrets.token_bytes(TOKEN_BYTES)
        while True:
            r = secrets.randbelow(self.n - 2) + 2
            # r must be invertible mod n; with an RSA modulus anything else means you have
            # factored it, but checking costs nothing and skipping it is how the rare case bites.
            try:
                pow(r, -1, self.n)
            except ValueError:
                continue
            self._r = r
            break
        return (full_domain_hash(self._token, self.n) * pow(self._r, self.e, self.n)) % self.n

    def unblind(self, blinded_signature: int) -> Token:
        """Strip the blinding. The issuer never saw this token and cannot recognise it later."""
        if not self._token:
            raise TokenError("nothing was blinded; call blind() first")
        sig = (blinded_signature * pow(self._r, -1, self.n)) % self.n
        token = Token(value_hex=self._token.hex(), signature_hex=f"{sig:x}")
        # Forget the blinding: keeping it would let anyone with this object's memory link the
        # issuance to the redemption, which is precisely what the protocol exists to prevent.
        self._token, self._r = b"", 0
        return token


def issue(issuer: Issuer) -> Token:
    """One full exchange, for callers that hold both ends (tests, single-process use)."""
    client = Client(*issuer.public)
    return client.unblind(issuer.sign_blinded(client.blind()))

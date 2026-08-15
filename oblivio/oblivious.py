"""Oblivious HTTP (RFC 9458): split *who is asking* from *what is asked*, across two operators.

`dispatch.py` fixed the timing and admitted what it could not fix: sending direct means the
provider's API key is an account identity and the IP is a network fact, so scheduling hides *when*
and *which*, never *whose*. I called that structurally unfixable. **That was wrong**, and this
module is the correction.

The fix is not stronger cryptography. It is refusing to let one party hold both halves:

    client  --encrypted for the gateway-->  RELAY  --forwards-->  GATEWAY  -->  provider
            the relay sees your IP,                the gateway sees the request,
            and only ciphertext                    and only the relay's IP

Neither party can link a person to a question. That is the whole idea, and its security rests on
something no algorithm can supply: **the relay and the gateway must not collude.** A relay you
operate yourself sees both halves and is therefore not a privacy boundary — it is a rename. Apple
runs exactly this design for Private Cloud Compute and solves the trust problem the only way it
can be solved: two *different companies* (Cloudflare and Fastly) under contract.

**What each party learns, stated so it cannot quietly drift:**

    relay     your IP, the time, the size. Never the plaintext — it holds no key.
    gateway   the request and the response. Never your IP — it only ever sees the relay.
    provider  whatever the gateway forwards, from the gateway's address.

**Layering.** This is the transport underneath `dispatch.py`, not a replacement for it. OHTTP hides
identity; it does nothing about *when* requests are made, so a client that sends the moment its
user presses enter still leaks behaviour to the relay. The two compose: `dispatch` decides when,
`oblivious` decides who knows.

🔴 **Verification status, deliberately unflattering.** The HPKE layer beneath this reproduces
RFC 9180's published vectors byte-for-byte (`test_hpke.py`). This framing does **not** yet have
RFC 9458's own test vector checked against it, and it has never been run against a real relay, so
**interoperability with a production OHTTP deployment is unproven.** Round-trip tests prove the
two halves of *this* implementation agree with each other, which is a weaker claim and is the only
one made here. Until a vector or a live relay says otherwise, treat this as correct-by-construction
rather than correct-by-evidence.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .hpke import (
    AEAD_AES_128_GCM,
    KDF_HKDF_SHA256,
    KEM_X25519_HKDF_SHA256,
    NENC,
    NK,
    NN,
    NT,
    _expand,
    _extract,
    _i2osp,
    generate_keypair,
    setup_base_r,
    setup_base_s,
)

REQUEST_LABEL = b"message/bhttp request"
RESPONSE_LABEL = b"message/bhttp response"
HDR_LEN = 7                       # key_id(1) + kem(2) + kdf(2) + aead(2)
RESPONSE_NONCE_LEN = max(NN, NK)  # 16 for AES-128-GCM


class ObliviousError(Exception):
    """A refusal. Nothing was forwarded and nothing was decrypted."""


# ---- key configuration (RFC 9458 §3) ----------------------------------------


@dataclass(frozen=True)
class KeyConfig:
    """What a gateway publishes so clients can encrypt to it without ever contacting it.

    A client fetching this from the gateway directly would defeat the point — the fetch itself
    would reveal the client's IP to the gateway. It is meant to be distributed out of band or via
    the relay, and `Client` therefore takes it as a value rather than fetching it.
    """
    key_id: int
    public_key: bytes
    kem_id: int = KEM_X25519_HKDF_SHA256
    kdf_id: int = KDF_HKDF_SHA256
    aead_id: int = AEAD_AES_128_GCM

    def header(self) -> bytes:
        return (_i2osp(self.key_id, 1) + _i2osp(self.kem_id, 2)
                + _i2osp(self.kdf_id, 2) + _i2osp(self.aead_id, 2))

    def serialize(self) -> bytes:
        algorithms = _i2osp(self.kdf_id, 2) + _i2osp(self.aead_id, 2)
        return (_i2osp(self.key_id, 1) + _i2osp(self.kem_id, 2) + self.public_key
                + _i2osp(len(algorithms), 2) + algorithms)

    @classmethod
    def parse(cls, raw: bytes) -> "KeyConfig":
        if len(raw) < 1 + 2 + 32 + 2:
            raise ObliviousError(f"key config is {len(raw)} bytes, too short to be valid")
        key_id = raw[0]
        kem_id = int.from_bytes(raw[1:3], "big")
        if kem_id != KEM_X25519_HKDF_SHA256:
            raise ObliviousError(
                f"KEM {kem_id:#06x} is not supported. Only DHKEM(X25519, HKDF-SHA256) is, and "
                f"guessing at another would produce a key nobody can decrypt.")
        public_key = raw[3:35]
        alg_len = int.from_bytes(raw[35:37], "big")
        algs = raw[37:37 + alg_len]
        if alg_len < 4 or len(algs) < 4:
            raise ObliviousError("key config lists no usable symmetric algorithm")
        return cls(key_id=key_id, public_key=public_key, kem_id=kem_id,
                   kdf_id=int.from_bytes(algs[0:2], "big"),
                   aead_id=int.from_bytes(algs[2:4], "big"))


# ---- request encapsulation (RFC 9458 §4.1) ----------------------------------


def encapsulate_request(config: KeyConfig, request: bytes) -> tuple[bytes, Any]:
    """Encrypt a request to the gateway. Returns (wire bytes, context for the response).

    The header is bound into `info`, so a relay that edits the algorithm identifiers in transit
    produces something the gateway cannot open rather than something it opens differently.
    """
    hdr = config.header()
    info = REQUEST_LABEL + b"\x00" + hdr
    enc, ctx = setup_base_s(X25519PublicKey.from_public_bytes(config.public_key), info)
    ct = ctx.seal(b"", request)
    return hdr + enc + ct, (enc, ctx)


def decapsulate_request(sk_r: X25519PrivateKey, config: KeyConfig,
                        encapsulated: bytes) -> tuple[bytes, Any]:
    """Gateway side. Returns (request, context for sealing the response)."""
    if len(encapsulated) < HDR_LEN + NENC + NT:
        raise ObliviousError(
            f"encapsulated request is {len(encapsulated)} bytes; too short to contain a header, "
            f"an encapsulated key and a tag")
    hdr, rest = encapsulated[:HDR_LEN], encapsulated[HDR_LEN:]
    if hdr != config.header():
        raise ObliviousError(
            "request header does not match this gateway's key configuration — wrong key id or "
            "altered algorithms; refusing rather than attempting a different suite")
    enc, ct = rest[:NENC], rest[NENC:]
    info = REQUEST_LABEL + b"\x00" + hdr
    ctx = setup_base_r(enc, sk_r, info)
    try:
        return ctx.open(b"", ct), (enc, ctx)
    except Exception as exc:
        raise ObliviousError(f"request did not authenticate: {type(exc).__name__}") from exc


# ---- response encapsulation (RFC 9458 §4.2) ---------------------------------


def _response_keys(enc: bytes, ctx, response_nonce: bytes) -> tuple[bytes, bytes]:
    """Derive the response key from the *exporter*, not the request key.

    The response travels in the opposite direction and must not reuse the request's key and nonce —
    doing so would repeat a nonce under the same key, which for AES-GCM is a total break rather
    than a weakness.
    """
    secret = ctx.export(RESPONSE_LABEL, NK)
    prk = _extract(enc + response_nonce, secret)
    return _expand(prk, b"key", NK), _expand(prk, b"nonce", NN)


def encapsulate_response(context: Any, response: bytes) -> bytes:
    enc, ctx = context
    response_nonce = secrets.token_bytes(RESPONSE_NONCE_LEN)
    key, nonce = _response_keys(enc, ctx, response_nonce)
    return response_nonce + AESGCM(key).encrypt(nonce, response, b"")


def decapsulate_response(context: Any, encapsulated: bytes) -> bytes:
    enc, ctx = context
    if len(encapsulated) < RESPONSE_NONCE_LEN + NT:
        raise ObliviousError(f"encapsulated response is {len(encapsulated)} bytes; too short")
    response_nonce = encapsulated[:RESPONSE_NONCE_LEN]
    key, nonce = _response_keys(enc, ctx, response_nonce)
    try:
        return AESGCM(key).decrypt(nonce, encapsulated[RESPONSE_NONCE_LEN:], b"")
    except Exception as exc:
        raise ObliviousError(f"response did not authenticate: {type(exc).__name__}") from exc


# ---- the three roles ---------------------------------------------------------


@dataclass
class Gateway:
    """Holds the private key. Sees requests and responses; never sees a client address."""
    key_id: int = 1
    _sk: X25519PrivateKey = field(default_factory=lambda: generate_keypair()[0], repr=False)
    handled: int = 0

    @property
    def config(self) -> KeyConfig:
        return KeyConfig(key_id=self.key_id,
                         public_key=self._sk.public_key().public_bytes_raw())

    def handle(self, encapsulated: bytes, origin: Callable[[bytes], bytes]) -> bytes:
        """Decrypt, hand the plaintext to the origin, and seal the reply back."""
        request, ctx = decapsulate_request(self._sk, self.config, encapsulated)
        self.handled += 1
        return encapsulate_response(ctx, origin(request))


@dataclass
class Relay:
    """Sees the client address; forwards opaque bytes. Holds no key, by construction.

    There is deliberately no hook here for inspecting or transforming the payload. A relay that
    could read a request would not be a relay, and the cheapest way to guarantee it cannot is to
    give it nothing to read with.
    """
    forward: Callable[[bytes], bytes]
    seen_addresses: list[str] = field(default_factory=list)
    forwarded: int = 0

    def relay(self, encapsulated: bytes, client_address: str = "") -> bytes:
        if client_address:
            self.seen_addresses.append(client_address)
        self.forwarded += 1
        return self.forward(encapsulated)


@dataclass
class Client:
    """Encrypts to the gateway's config and speaks only to the relay."""
    config: KeyConfig

    def send(self, relay: Relay, request: bytes, client_address: str = "") -> bytes:
        encapsulated, ctx = encapsulate_request(self.config, request)
        return decapsulate_response(ctx, relay.relay(encapsulated, client_address))


def visibility(*, independent_operators: bool) -> dict[str, str]:
    """Who learns what. The one field that matters is the last one.

    `independent_operators` is not something this code can verify — it is a fact about contracts
    and corporate control, and it is the assumption the entire construction rests on. It is a
    required argument rather than a default so that no caller can obtain the reassuring answer
    without stating the claim.
    """
    base = {
        "your_ip_at_the_gateway": "hidden — the gateway only ever sees the relay's address",
        "your_ip_at_the_relay": "VISIBLE — unavoidable; the relay is who you connect to",
        "request_content_at_the_relay": "hidden — the relay holds no key and cannot be given one",
        "request_content_at_the_gateway": "VISIBLE — it decrypts in order to forward",
        "account_identity": "hidden from the provider; the gateway's credential is used, not yours",
        "when_you_asked": "VISIBLE to the relay unless dispatch.py schedules the send",
    }
    base["overall"] = (
        "no single party links you to your question"
        if independent_operators else
        "🔴 NONE OF THE ABOVE HOLDS. If one party runs both the relay and the gateway it sees "
        "the address and the plaintext, and this is a rename of sending direct, not a privacy "
        "boundary. Independence is a contractual property; no code in this file can enforce it.")
    return base

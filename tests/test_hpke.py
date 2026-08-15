"""HPKE against the RFC's own test vectors, not against my reading of the RFC.

Everything else in this suite is secondary to `test_rfc9180_a1_*`. A hand-assembled HPKE that
has not reproduced the official vectors is not HPKE — it is a plausible-looking key-derivation
pipeline that will interoperate with nothing and whose security proof does not apply. The labels,
the suite ids, the I2OSP widths and the XOR-counter nonce all have to be byte-exact, and the only
way to know they are is to check them against values someone else published.

Vectors: RFC 9180 Appendix A.1 — DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM, base mode.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from oblivio.hpke import (
    MODE_BASE,
    NENC,
    HpkeError,
    decap,
    encap,
    generate_keypair,
    key_schedule,
    setup_base_r,
    setup_base_s,
)

H = bytes.fromhex

# --- RFC 9180 A.1 ------------------------------------------------------------
INFO = H("4f6465206f6e2061204772656369616e2055726e")
SK_E = H("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736")
PK_E = H("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")
SK_R = H("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")
PK_R = H("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d")
SHARED_SECRET = H("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc")
KEY = H("4531685d41d65f03dc48f6b8302c05b0")
BASE_NONCE = H("56d890e5accaaf011cff4b7d")
EXPORTER_SECRET = H("45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8")

PT = H("4265617574792069732074727574682c20747275746820626561757479")
AAD0 = H("436f756e742d30")
CT0 = H("f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a")
AAD1 = H("436f756e742d31")
CT1 = H("af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84")

EXPORTS = [
    (b"", 32, H("3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee")),
    (H("00"), 32, H("2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5")),
    (H("54657374436f6e74657874"), 32,
     H("e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931")),
]


def _sender_context():
    sk_e = X25519PrivateKey.from_private_bytes(SK_E)
    pk_r = X25519PublicKey.from_public_bytes(PK_R)
    return setup_base_s(pk_r, INFO, sk_e=sk_e)


# --- the tests that make this file usable at all -----------------------------

def test_rfc9180_a1_encap_matches_the_published_shared_secret():
    sk_e = X25519PrivateKey.from_private_bytes(SK_E)
    pk_r = X25519PublicKey.from_public_bytes(PK_R)
    shared_secret, enc = encap(pk_r, sk_e=sk_e)
    assert enc == PK_E, f"enc mismatch: {enc.hex()}"
    assert shared_secret == SHARED_SECRET, f"shared secret mismatch: {shared_secret.hex()}"


def test_rfc9180_a1_key_schedule_matches_published_key_nonce_and_exporter():
    ctx = key_schedule(SHARED_SECRET, INFO, MODE_BASE)
    assert ctx.key == KEY, f"key mismatch: {ctx.key.hex()}"
    assert ctx.base_nonce == BASE_NONCE, f"base_nonce mismatch: {ctx.base_nonce.hex()}"
    assert ctx.exporter_secret == EXPORTER_SECRET, f"exporter mismatch: {ctx.exporter_secret.hex()}"


def test_rfc9180_a1_seal_matches_published_ciphertext_for_two_sequence_numbers():
    """Sequence 1 is the one that proves the XOR-counter nonce, not just the first nonce."""
    _, ctx = _sender_context()
    assert ctx.seal(AAD0, PT) == CT0, "sequence 0 ciphertext mismatch"
    assert ctx.seal(AAD1, PT) == CT1, "sequence 1 ciphertext mismatch — nonce counter is wrong"


def test_rfc9180_a1_exports_match():
    _, ctx = _sender_context()
    for context, length, expected in EXPORTS:
        got = ctx.export(context, length)
        assert got == expected, f"export({context.hex()!r}) mismatch: {got.hex()}"


def test_rfc9180_a1_decap_recovers_the_same_secret():
    sk_r = X25519PrivateKey.from_private_bytes(SK_R)
    assert decap(PK_E, sk_r) == SHARED_SECRET


# --- round trip and refusals -------------------------------------------------

def test_round_trip_with_fresh_keys():
    sk_r, pk_r = generate_keypair()
    enc, sender = setup_base_s(pk_r, b"info")
    receiver = setup_base_r(enc, sk_r, b"info")
    ct = sender.seal(b"aad", b"the message")
    assert receiver.open(b"aad", ct) == b"the message"


def test_sequence_numbers_must_stay_in_step():
    """A receiver that skips a message cannot silently decrypt the next one."""
    sk_r, pk_r = generate_keypair()
    enc, sender = setup_base_s(pk_r, b"info")
    receiver = setup_base_r(enc, sk_r, b"info")
    sender.seal(b"", b"first")
    second = sender.seal(b"", b"second")
    try:
        receiver.open(b"", second)
    except Exception:
        return
    raise AssertionError("out-of-order open succeeded; the nonce counter is not being enforced")


def test_a_different_info_derives_a_different_key():
    """info is bound into the key schedule; if it were not, context separation would be fake."""
    sk_r, pk_r = generate_keypair()
    enc, sender = setup_base_s(pk_r, b"info-a")
    receiver = setup_base_r(enc, sk_r, b"info-b")
    ct = sender.seal(b"", b"secret")
    try:
        receiver.open(b"", ct)
    except Exception:
        return
    raise AssertionError("mismatched info still decrypted — info is not bound into the schedule")


def test_non_base_modes_are_refused_not_downgraded():
    for mode in (0x01, 0x02, 0x03):
        try:
            key_schedule(SHARED_SECRET, INFO, mode)
        except HpkeError as e:
            assert "not implemented" in str(e).lower()
            continue
        raise AssertionError(f"mode {mode:#04x} was silently treated as base mode")


def test_a_wrong_length_encapsulated_key_is_refused():
    sk_r, _ = generate_keypair()
    for bad in (b"", b"\x00" * (NENC - 1), b"\x00" * (NENC + 1)):
        try:
            decap(bad, sk_r)
        except HpkeError:
            continue
        raise AssertionError(f"accepted a {len(bad)}-byte encapsulated key")


def run():
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed, failed = [], []
    for name, fn in tests:
        try:
            fn()
            passed.append(name)
            print(f"  PASS  {name}")
        except AssertionError as exc:
            failed.append(name)
            print(f"  FAIL  {name}")
            print(f"          {exc}")
        except Exception as exc:
            failed.append(name)
            print(f"  ERROR {name}")
            print(f"          {type(exc).__name__}: {exc}")
    print()
    print(f"{len(passed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())

"""Anonymous entitlement: the issuer must not be able to link issuance to redemption.

Correctness is the easy half — a token verifies, a forgery does not. The half that matters is
`test_the_issuer_cannot_link_issuance_to_redemption`: the blinded values the issuer signs must
share nothing with the tokens that come back, or the whole construction is ceremony.

The second load-bearing test is `test_multiplying_two_signatures_does_not_forge_a_third`. RSA is
multiplicatively homomorphic, which is exactly why blinding works — and exactly why signing
anything the client fully controls is forgeable. Full-domain hashing is what closes it, and this
asserts the closure rather than assuming it.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blindkeep.anon_token import (
    Client,
    Issuer,
    Token,
    TokenError,
    full_domain_hash,
    issue,
)

# One key for the whole module: 2048-bit RSA keygen is slow and the tests are about the
# protocol, not about key generation.
ISSUER = Issuer()


def fresh():
    """A separate issuer where a test needs its own spent-set."""
    i = Issuer.__new__(Issuer)
    i._key, i.n, i.e = ISSUER._key, ISSUER.n, ISSUER.e
    i._d, i.spent, i.issued = ISSUER._d, set(), 0
    return i


def expect(fn, contains=None):
    try:
        fn()
    except TokenError as e:
        if contains:
            assert contains in str(e).lower(), f"wrong reason: {e}"
        return str(e)
    raise AssertionError("expected a refusal, got none")


# --- the property the whole thing exists for ---------------------------------

def test_the_issuer_cannot_link_issuance_to_redemption():
    """What the issuer signs and what it later sees must be independent values."""
    seen_at_signing, redeemed = [], []
    for _ in range(8):
        client = Client(*ISSUER.public)
        blinded = client.blind()
        seen_at_signing.append(blinded)
        redeemed.append(client.unblind(ISSUER.sign_blinded(blinded)))

    signing_view = {f"{b:x}" for b in seen_at_signing}
    redemption_view = {t.value_hex for t in redeemed} | {t.signature_hex for t in redeemed}
    assert not (signing_view & redemption_view), (
        "a value the issuer saw at signing reappeared at redemption")


def test_the_same_token_blinded_twice_looks_different():
    """Otherwise an issuer could fingerprint a client by the values it presents."""
    a, b = Client(*ISSUER.public), Client(*ISSUER.public)
    assert a.blind() != b.blind()


def test_the_client_forgets_the_blinding_after_unblinding():
    """Keeping it would let anyone holding the object link the two halves."""
    client = Client(*ISSUER.public)
    client.unblind(ISSUER.sign_blinded(client.blind()))
    assert client._r == 0 and client._token == b""
    expect(lambda: client.unblind(1), contains="nothing was blinded")


# --- forgery ------------------------------------------------------------------

def test_multiplying_two_signatures_does_not_forge_a_third():
    """RSA's homomorphism is what makes blinding work. It must not also make forgery work."""
    i = fresh()
    t1, t2 = issue(i), issue(i)
    product = (int(t1.signature_hex, 16) * int(t2.signature_hex, 16)) % i.n
    # A signature on H(t1)*H(t2) — which is a valid signature on NO token, because no token
    # hashes to that product.
    forged = Token(value_hex=t1.value_hex, signature_hex=f"{product:x}")
    assert i.verify(forged) is False, "signatures multiplied into a working forgery"


def test_a_token_without_a_signature_is_refused():
    i = fresh()
    expect(lambda: i.redeem(Token(value_hex="ab" * 32, signature_hex="01")),
           contains="not valid")


def test_a_signature_from_another_issuer_is_refused():
    other = Issuer(bits=2048)
    stolen = issue(other)
    assert ISSUER.verify(stolen) is False


def test_tampering_with_the_token_invalidates_the_signature():
    i = fresh()
    t = issue(i)
    flipped = Token(value_hex=("00" if t.value_hex[:2] != "00" else "01") + t.value_hex[2:],
                    signature_hex=t.signature_hex)
    assert i.verify(flipped) is False


def test_malformed_tokens_return_false_rather_than_raising():
    for bad in (Token("zz", "01"), Token("ab", "zz"), Token("", "")):
        assert ISSUER.verify(bad) is False


# --- single use ---------------------------------------------------------------

def test_a_token_is_spent_once():
    """Unlinkable is not un-copyable: nothing in the token stops a replay, so the issuer must."""
    i = fresh()
    t = issue(i)
    i.redeem(t)
    expect(lambda: i.redeem(t), contains="already been spent")


def test_a_refused_token_is_not_marked_spent():
    """A forgery must not be able to burn a legitimate token's value."""
    i = fresh()
    t = issue(i)
    bad = Token(value_hex=t.value_hex, signature_hex="02")
    expect(lambda: i.redeem(bad))
    i.redeem(t)                       # the real one still works


def test_many_tokens_are_all_distinct():
    i = fresh()
    tokens = [issue(i) for _ in range(16)]
    assert len({t.value_hex for t in tokens}) == 16
    for t in tokens:
        i.redeem(t)
    assert len(i.spent) == 16


# --- the hashing that makes it sound -----------------------------------------

def test_the_hash_covers_the_modulus_range():
    """A hash confined to a small range would leave the signature trivially forgeable.

    This assertion used to be `max(of 32 samples) > n >> 8`, which failed roughly one run in
    150 — and the rate depended on the *key*, because the output is one byte short of the
    modulus (see below), so each sample clears n>>8 with probability 1 - n/2^2048. A modulus
    with high leading bits fails it often; most keys almost never do. A test that is a
    coin-flip against a value it does not control is not measuring the property it names.

    The bound is structural, so assert it structurally.
    """
    n = ISSUER.n
    size = (n.bit_length() + 7) // 8
    ceiling = 1 << (8 * (size - 1))          # what the construction can actually emit

    values = [full_domain_hash(os.urandom(32), n) for _ in range(64)]
    assert len(set(values)) == 64, "the hash repeated on distinct inputs"

    # Upper bound: exact, deterministic, and the reason no rejection sampling is needed.
    assert all(0 <= v < ceiling <= n for v in values)

    # Lower bound: the output must reach the top of that range, not hug the bottom. Missing
    # this needs all 64 samples in the bottom 1/64th, which is ~10^-115 — not a flake.
    assert max(v.bit_length() for v in values) >= 8 * (size - 1) - 6, (
        "hash output is not spread across the modulus")


def test_the_hash_is_one_byte_short_of_the_modulus_and_that_is_deliberate():
    """"Full domain" is approximate here, and the gap should be stated rather than discovered.

    The output spans [0, 2^2040) against a 2048-bit modulus, so it reaches about 1/256th of the
    way into the top byte's worth of range. That costs 8 bits of preimage space out of 2040 and
    buys away rejection sampling entirely. It is a fine trade — but it is a trade, and the test
    named "covers the modulus range" was quietly asserting the opposite of it.
    """
    n = ISSUER.n
    size = (n.bit_length() + 7) // 8
    ceiling = 1 << (8 * (size - 1))
    assert ceiling <= n, "the hash can exceed the modulus; rejection sampling would be required"
    assert ceiling * 256 > n, "the hash is more than one byte short; that is wasted range"


def test_the_hash_is_domain_separated_and_deterministic():
    n = ISSUER.n
    tok = os.urandom(32)
    assert full_domain_hash(tok, n) == full_domain_hash(tok, n)
    assert full_domain_hash(tok, n) != int.from_bytes(tok, "big") % n


def test_a_blinded_value_outside_the_modulus_is_refused():
    i = fresh()
    expect(lambda: i.sign_blinded(i.n), contains="outside the modulus")
    expect(lambda: i.sign_blinded(0), contains="outside the modulus")


# --- what it does not do ------------------------------------------------------

def test_the_issuer_still_learns_how_many_tokens_it_signed():
    """Stated as a test because it is a real limit, not a bug: this hides WHO, never THAT."""
    i = fresh()
    for _ in range(3):
        issue(i)
    assert i.issued == 3


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

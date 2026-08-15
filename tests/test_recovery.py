"""Key recovery tests.

Recovery is the mechanism that decides whether losing a file is an
inconvenience or a permanent loss, so these tests check the failure paths as
hard as the success paths: a mistyped code must be REJECTED rather than
silently returning a wrong key, and fewer than the threshold of shares must
reveal nothing.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oblivio.crypto import generate_master_key
from oblivio.recovery import (
    RecoveryError,
    Share,
    combine_shares,
    from_recovery_code,
    split_key,
    to_recovery_code,
    unwrap_key,
    wrap_key,
)


# --- recovery code ----------------------------------------------------------

def test_recovery_code_round_trips():
    for _ in range(25):
        key = generate_master_key()
        assert from_recovery_code(to_recovery_code(key)) == key


def test_recovery_code_is_transcribable():
    code = to_recovery_code(generate_master_key())
    assert "-" in code, "code should be grouped for copying by hand"
    body = code.replace("-", "")
    assert body.isalnum() and body.isupper()
    for confusing in "0189":
        assert confusing not in body, f"base32 should exclude {confusing}"


def test_recovery_code_tolerates_common_transcription_slips():
    key = generate_master_key()
    code = to_recovery_code(key)
    assert from_recovery_code(code.lower()) == key
    assert from_recovery_code(code.replace("-", " ")) == key
    assert from_recovery_code(code.replace("-", "")) == key
    assert from_recovery_code(f"  {code}\n") == key
    # O/0 and I/1 are the classic handwriting confusions
    assert from_recovery_code(code.replace("O", "0")) == key
    assert from_recovery_code(code.replace("I", "1")) == key


def test_mistyped_code_is_rejected_not_silently_wrong():
    """The dangerous failure is returning a plausible but wrong key."""
    key = generate_master_key()
    code = to_recovery_code(key)
    body = [c for c in code if c != "-"]
    rejected = 0
    for pos in range(len(body)):
        broken = list(body)
        broken[pos] = "Z" if broken[pos] != "Z" else "Y"
        try:
            got = from_recovery_code("".join(broken))
        except RecoveryError:
            rejected += 1
            continue
        assert got != key, "a corrupted code produced the correct key"
        raise AssertionError(f"corrupted code at position {pos} was accepted")
    assert rejected == len(body), f"only {rejected}/{len(body)} corruptions rejected"


def test_the_final_character_has_no_spare_bits():
    """The bug this file did not catch for its whole life, found because it flaked 1 run in 8.

    A 36-byte payload is 57 base32 characters plus 3 bits, so the final character carries 3
    real bits and 2 that decode to nothing — and `b32decode` ignores them rather than
    objecting. Four different final characters produced byte-identical output, so a mistype
    among them sailed past the checksum, which covers the key and not its spelling.

    The old test substituted "Z" at every position and so hit this only when the final
    character happened to be Y, Z, 2 or 3 — 4 cases in 32. An intermittent test was the only
    evidence that a real input was silently accepted.
    """
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    for _ in range(20):
        code = to_recovery_code(generate_master_key())
        body = [c for c in code if c != "-"]
        last = alphabet.index(body[-1])
        # Every character sharing the final one's top 3 bits used to decode identically.
        for i in range(32):
            if i >> 2 != last >> 2 or i == last:
                continue
            variant = body[:-1] + [alphabet[i]]
            try:
                from_recovery_code("".join(variant))
            except RecoveryError as exc:
                assert "canonical" in str(exc).lower()
                continue
            raise AssertionError(
                f"{alphabet[i]!r} in the final position decoded the same as {alphabet[last]!r}")


def test_one_spelling_per_key():
    """Canonicality, stated directly: a key has exactly one valid written form."""
    for _ in range(20):
        key = generate_master_key()
        code = to_recovery_code(key)
        assert to_recovery_code(from_recovery_code(code)) == code
        # The repairs are normalisations, not alternative spellings — they must land here too.
        for typo in (code.lower(), code.replace("-", ""), code.replace("O", "0"),
                     code.replace("I", "1"), code.replace("B", "8")):
            assert from_recovery_code(typo) == key
            assert to_recovery_code(from_recovery_code(typo)) == code


def test_truncated_code_is_rejected():
    code = to_recovery_code(generate_master_key())
    try:
        from_recovery_code(code[: len(code) // 2])
    except RecoveryError:
        return
    raise AssertionError("a truncated code was accepted")


# --- passphrase backup ------------------------------------------------------

def test_passphrase_backup_round_trips():
    key = generate_master_key()
    blob = wrap_key(key, "correct horse battery staple")
    assert unwrap_key(blob, "correct horse battery staple") == key


def test_backup_does_not_contain_the_key():
    key = generate_master_key()
    blob = wrap_key(key, "pass")
    assert key not in blob, "the key appears verbatim in its own backup"


def test_wrong_passphrase_is_rejected():
    blob = wrap_key(generate_master_key(), "right")
    try:
        unwrap_key(blob, "wrong")
    except RecoveryError:
        return
    raise AssertionError("a wrong passphrase was accepted")


def test_tampered_backup_is_rejected():
    blob = bytearray(wrap_key(generate_master_key(), "pass"))
    blob[-1] ^= 0xFF
    try:
        unwrap_key(bytes(blob), "pass")
    except RecoveryError:
        return
    raise AssertionError("a tampered backup was accepted")


def test_backups_of_one_key_differ():
    """Fresh salt and nonce per backup, so two files never match."""
    key = generate_master_key()
    assert wrap_key(key, "p") != wrap_key(key, "p")


# --- split shares -----------------------------------------------------------

def test_threshold_shares_reconstruct():
    key = generate_master_key()
    shares = split_key(key, threshold=3, shares=5)
    assert len(shares) == 5
    assert combine_shares(shares[:3]) == key
    assert combine_shares(shares[2:]) == key
    assert combine_shares([shares[0], shares[2], shares[4]]) == key
    assert combine_shares(shares) == key


def test_all_threshold_combinations_work():
    from itertools import combinations
    key = generate_master_key()
    shares = split_key(key, threshold=3, shares=5)
    for combo in combinations(shares, 3):
        assert combine_shares(list(combo)) == key


def test_fewer_than_threshold_reveals_nothing():
    key = generate_master_key()
    shares = split_key(key, threshold=3, shares=5)
    for combo in ([shares[0], shares[1]], [shares[3], shares[4]]):
        assert combine_shares(combo) != key, "2 of 3 shares reconstructed the key"
    for s in shares:
        assert key not in s.data, "a share contains the key verbatim"


def test_two_of_two_works():
    key = generate_master_key()
    shares = split_key(key, threshold=2, shares=2)
    assert combine_shares(shares) == key


def test_shares_encode_and_decode():
    key = generate_master_key()
    shares = split_key(key, threshold=2, shares=3)
    restored = [Share.decode(s.encode()) for s in shares]
    assert combine_shares(restored[:2]) == key


def test_mistyped_share_is_rejected():
    share = split_key(generate_master_key(), threshold=2, shares=3)[0]
    text = share.encode()
    pos = len(text) - 3
    broken = text[:pos] + ("Z" if text[pos] != "Z" else "Y") + text[pos + 1:]
    try:
        Share.decode(broken)
    except RecoveryError:
        return
    raise AssertionError("a corrupted share was accepted")


def test_every_single_character_corruption_of_a_share_is_rejected():
    """The test above corrupts position len-3, which is why it never found the hole.

    A share payload is 37 bytes and ends one bit into its final base32 character, so 16 of the
    32 characters used to decode to identical bytes. Corrupting a fixed interior position can
    never see that; the exhaustive sweep is the only version of this test worth having.
    """
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    share = split_key(generate_master_key(), threshold=2, shares=3)[0]
    prefix, _, rest = share.encode().partition("-")
    rest = rest.replace("-", "")
    for pos in range(len(rest)):
        for repl in alphabet:
            if repl == rest[pos]:
                continue
            broken = f"{prefix}-" + rest[:pos] + repl + rest[pos + 1:]
            try:
                Share.decode(broken)
            except RecoveryError:
                continue
            raise AssertionError(
                f"corrupting position {pos} to {repl!r} was accepted "
                f"({'final character' if pos == len(rest) - 1 else 'interior'})")


def test_a_share_labelled_wrongly_is_rejected():
    """The index is printed in front of the payload and is what a person files it under.

    It used to be read from the payload alone, so a share carrying one number and labelled
    another decoded happily as the payload's — the label a human trusts was decorative.
    """
    shares = split_key(generate_master_key(), threshold=2, shares=3)
    body = shares[0].encode().partition("-")[2]
    mislabelled = shares[1].encode().split("-")[0] + "-" + body
    try:
        Share.decode(mislabelled)
    except RecoveryError as exc:
        assert "labelled" in str(exc), f"rejected for the wrong reason: {exc}"
        return
    raise AssertionError("a share whose label contradicts its payload was accepted")


def test_duplicate_shares_are_rejected():
    shares = split_key(generate_master_key(), threshold=3, shares=5)
    try:
        combine_shares([shares[0], shares[0], shares[1]])
    except RecoveryError:
        return
    raise AssertionError("duplicate shares were accepted as distinct")


def test_shares_from_different_splits_do_not_silently_merge():
    a = split_key(generate_master_key(), threshold=2, shares=3)
    b = split_key(generate_master_key(), threshold=2, shares=3)
    mixed = combine_shares([a[0], b[1]])
    assert mixed != a  # cannot equal either original key
    assert isinstance(mixed, bytes)


def test_invalid_parameters_are_rejected():
    key = generate_master_key()
    for t, n in ((1, 3), (4, 3), (0, 0), (2, 300)):
        try:
            split_key(key, threshold=t, shares=n)
        except RecoveryError:
            continue
        raise AssertionError(f"accepted invalid threshold={t} shares={n}")


# --- the property that matters ---------------------------------------------

def test_every_path_recovers_a_working_key():
    """All three mechanisms must yield a byte-identical key."""
    key = generate_master_key()
    via_code = from_recovery_code(to_recovery_code(key))
    via_backup = unwrap_key(wrap_key(key, "a passphrase"), "a passphrase")
    via_shares = combine_shares(split_key(key, threshold=2, shares=3)[:2])
    assert via_code == key
    assert via_backup == key
    assert via_shares == key


def test_recovered_key_actually_decrypts_stored_records():
    """The end-to-end property: recovery must return DATA, not just bytes.

    Stores a record, destroys the key, reconstructs it from a subset of shares,
    and reads the original plaintext back.
    """
    import tempfile
    from oblivio.store import MemoryStore, client_encrypt, client_open

    key = generate_master_key()
    secret = b"the only copy of something that matters"

    with tempfile.TemporaryDirectory() as td:
        store = MemoryStore(td)
        rid, blob = client_encrypt(key, secret, label="irreplaceable")
        store.put_ciphertext(rid, blob)

        shares = split_key(key, threshold=3, shares=5)
        code = to_recovery_code(key)
        backup = wrap_key(key, "a passphrase I remember")

        del key   # the key no longer exists anywhere but in the recovery data

        import base64
        stored = base64.b64decode(store.get(0)["ciphertext_b64"])

        # a) three of five shares, deliberately non-adjacent
        via_shares = combine_shares([shares[0], shares[2], shares[4]])
        label, plain = client_open(via_shares, rid, stored)
        assert plain == secret and label == "irreplaceable"

        # b) the written code
        label, plain = client_open(from_recovery_code(code), rid, stored)
        assert plain == secret and label == "irreplaceable"

        # c) the passphrase backup
        label, plain = client_open(
            unwrap_key(backup, "a passphrase I remember"), rid, stored)
        assert plain == secret and label == "irreplaceable"


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
            print(f"  FAIL  {name}\n          {exc}")
        except Exception as exc:
            failed.append(name)
            print(f"  ERROR {name}\n          {type(exc).__name__}: {exc}")
    print(f"\n{len(passed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())

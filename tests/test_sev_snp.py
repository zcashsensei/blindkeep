"""SEV-SNP verifier tests, against SYNTHETIC reports.

What these prove: the parser reads the documented layout, the AMD little-endian
signature encoding is handled, the certificate chain is walked, and every
mismatch refuses.

What these CANNOT prove: that a real EPYC machine emits this layout. Every
report here is one this suite built itself, so the offsets are being checked
against the same reading of the spec that produced them. That is why
`test_sev_snp_is_not_in_the_default_registry` exists and is the most important
test in the file.
"""

import base64
import datetime
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from oblivio.attest import (
    Attestation,
    Policy,
    Unverified,
    default_registry,
    expected_report_data,
    new_nonce,
    verify_attestation,
)
from oblivio.sev_snp import (
    OFF_CHIP_ID,
    OFF_CURRENT_TCB,
    OFF_MEASUREMENT,
    OFF_POLICY,
    OFF_REPORT_DATA,
    OFF_REPORTED_TCB,
    OFF_SIGNATURE,
    OFF_SIGNATURE_ALGO,
    POLICY_DEBUG_BIT,
    REPORT_BYTES,
    SIGNED_BYTES,
    SIG_COMPONENT_BYTES,
    SevSnpVerifier,
    parse_report,
    registry_with_sev_snp,
    verify_chain,
)

MEASUREMENT = bytes(range(48))
TCB = 0x0303000000000008


def _cert(subject, issuer_cert, issuer_key, key, ca=True):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    issuer_name = issuer_cert.subject if issuer_cert else name
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder()
         .subject_name(name)
         .issuer_name(issuer_name)
         .public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(days=1))
         .not_valid_after(now + datetime.timedelta(days=3650))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None),
                        critical=True))
    return b.sign(issuer_key, hashes.SHA384())


def chain():
    """ARK -> ASK -> VCEK, the shape AMD publishes."""
    ark_k = ec.generate_private_key(ec.SECP384R1())
    ask_k = ec.generate_private_key(ec.SECP384R1())
    vcek_k = ec.generate_private_key(ec.SECP384R1())
    ark = _cert("ARK", None, ark_k, ark_k)
    ask = _cert("ASK", ark, ark_k, ask_k)
    vcek = _cert("VCEK", ask, ask_k, vcek_k, ca=False)
    pem = lambda c: c.public_bytes(Encoding.PEM)
    return pem(ark), pem(ask), pem(vcek), vcek_k


def build_report(vcek_key, nonce, *, measurement=MEASUREMENT, debug=False,
                 algo=1, tcb=TCB, big_endian_sig=False, tamper_after_sign=False):
    """Assemble a 1184-byte report at the documented offsets and sign it."""
    raw = bytearray(REPORT_BYTES)
    struct.pack_into("<I", raw, 0, 2)                       # VERSION
    policy = (1 << POLICY_DEBUG_BIT) if debug else 0
    struct.pack_into("<Q", raw, OFF_POLICY, policy)
    struct.pack_into("<I", raw, OFF_SIGNATURE_ALGO, algo)
    struct.pack_into("<Q", raw, OFF_CURRENT_TCB, tcb)
    struct.pack_into("<Q", raw, OFF_REPORTED_TCB, tcb)
    raw[OFF_REPORT_DATA:OFF_REPORT_DATA + 32] = bytes.fromhex(
        expected_report_data(nonce))
    raw[OFF_MEASUREMENT:OFF_MEASUREMENT + 48] = measurement
    raw[OFF_CHIP_ID:OFF_CHIP_ID + 64] = bytes(range(64))

    sig = vcek_key.sign(bytes(raw[:SIGNED_BYTES]), ec.ECDSA(hashes.SHA384()))
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(sig)
    order = "big" if big_endian_sig else "little"
    for i, v in enumerate((r, s)):
        off = OFF_SIGNATURE + i * SIG_COMPONENT_BYTES
        raw[off:off + 48] = v.to_bytes(48, order)

    if tamper_after_sign:
        raw[OFF_MEASUREMENT] ^= 0xFF
    return bytes(raw)


def envelope(blob, nonce, *, measurement=None, debug=False):
    rep = parse_report(blob)
    return Attestation(
        format="sev-snp",
        measurement_hex=(measurement or rep.measurement).hex()
        if isinstance(measurement or rep.measurement, bytes) else measurement,
        report_data_hex=expected_report_data(nonce),
        signed_at=__import__("time").time(),
        debug_enabled=debug,
        signature_hex="",
        signing_key_hex="",
        raw={"report_b64": base64.b64encode(blob).decode()},
    )


def expect_refusal(fn, *, contains=None):
    try:
        fn()
    except Unverified as e:
        if contains:
            assert contains in str(e).lower(), f"wrong reason: {e}"
        return str(e)
    raise AssertionError("expected a refusal, got none")


# --- THE test ---------------------------------------------------------------

def test_sev_snp_is_not_in_the_default_registry():
    """Unvalidated code must not be reachable by default.

    This verifier has never seen a report from real hardware. Until it has,
    asking for sev-snp on the default path must refuse.
    """
    reg = default_registry()
    v = reg["sev-snp"]
    assert not isinstance(v, SevSnpVerifier), (
        "the real SEV-SNP verifier was wired into the default registry before "
        "being validated against hardware")
    expect_refusal(lambda: v.verify_signature(None),
                   contains="no verifier is implemented")


def test_enabling_it_is_a_deliberate_act():
    ark, ask, vcek, _ = chain()
    reg = registry_with_sev_snp(ark, ask, vcek)
    assert isinstance(reg["sev-snp"], SevSnpVerifier)
    assert not isinstance(default_registry()["sev-snp"], SevSnpVerifier), (
        "opting in mutated the default registry for everyone")


# --- parsing ----------------------------------------------------------------

def test_parses_documented_offsets():
    _, _, _, k = chain()
    n = new_nonce()
    rep = parse_report(build_report(k, n))
    assert rep.version == 2
    assert rep.measurement == MEASUREMENT
    assert rep.report_data[:32].hex() == expected_report_data(n)
    assert rep.reported_tcb == TCB
    assert rep.chip_id == bytes(range(64))
    assert len(rep.signed_region) == SIGNED_BYTES


def test_debug_bit_is_bit_19():
    _, _, _, k = chain()
    n = new_nonce()
    assert parse_report(build_report(k, n, debug=True)).debug_enabled is True
    assert parse_report(build_report(k, n, debug=False)).debug_enabled is False
    assert parse_report(build_report(k, n, debug=True)).policy == 1 << 19


def test_wrong_report_size_is_refused():
    expect_refusal(lambda: parse_report(b"\x00" * 100), contains="1184")


def test_signature_component_beyond_p384_is_refused():
    _, _, _, k = chain()
    raw = bytearray(build_report(k, new_nonce()))
    raw[OFF_SIGNATURE + 60] = 0x01          # data past the 48-byte P-384 range
    expect_refusal(lambda: parse_report(bytes(raw)), contains="p-384")


# --- the chain --------------------------------------------------------------

def test_good_chain_verifies():
    ark, ask, vcek, _ = chain()
    assert verify_chain(ark, ask, vcek).subject.rfc4514_string() == "CN=VCEK"


def test_vcek_from_a_different_chain_is_refused():
    ark, ask, _, _ = chain()
    _, _, other_vcek, _ = chain()
    expect_refusal(lambda: verify_chain(ark, ask, other_vcek),
                   contains="vcek under ask")


def test_malformed_certificates_are_refused():
    expect_refusal(lambda: verify_chain(b"not a cert", b"nope", b"no"),
                   contains="could not load")


# --- full verification ------------------------------------------------------

def test_synthetic_report_verifies_end_to_end():
    ark, ask, vcek, k = chain()
    n = new_nonce()
    blob = build_report(k, n)
    v = SevSnpVerifier(ark, ask, vcek, expected_tcb=TCB)
    assert v.verify_signature(envelope(blob, n)) is True


def test_it_slots_into_the_five_checks():
    """The class supplies check 2; the pipeline still runs the other four."""
    ark, ask, vcek, k = chain()
    n = new_nonce()
    blob = build_report(k, n)
    att = envelope(blob, n)
    att = Attestation(
        format=att.format, measurement_hex=att.measurement_hex,
        report_data_hex=att.report_data_hex, signed_at=att.signed_at,
        debug_enabled=att.debug_enabled, signature_hex="",
        signing_key_hex="aa", raw=att.raw)
    policy = Policy.build([MEASUREMENT.hex()], ["aa"])
    res = verify_attestation(att, nonce=n, policy=policy,
                             registry=registry_with_sev_snp(ark, ask, vcek))
    assert len(res.checks) == 5


def test_tampering_after_signing_is_caught():
    ark, ask, vcek, k = chain()
    n = new_nonce()
    blob = build_report(k, n, tamper_after_sign=True)
    v = SevSnpVerifier(ark, ask, vcek)
    # The envelope is built from the tampered bytes, so the fields agree with
    # each other and only the signature disagrees.
    assert v.verify_signature(envelope(blob, n)) is False


def test_big_endian_signature_does_not_verify():
    """Guards the single most common error against this format."""
    ark, ask, vcek, k = chain()
    n = new_nonce()
    blob = build_report(k, n, big_endian_sig=True)
    v = SevSnpVerifier(ark, ask, vcek)
    assert v.verify_signature(envelope(blob, n)) is False, (
        "a big-endian signature verified, so the endianness handling is not "
        "doing what this module claims")


def test_envelope_measurement_must_match_the_signed_report():
    ark, ask, vcek, k = chain()
    n = new_nonce()
    blob = build_report(k, n)
    att = envelope(blob, n, measurement=("ff" * 48))
    expect_refusal(lambda: SevSnpVerifier(ark, ask, vcek).verify_signature(att),
                   contains="envelope measurement")


def test_envelope_debug_flag_must_match_the_signed_policy():
    ark, ask, vcek, k = chain()
    n = new_nonce()
    blob = build_report(k, n, debug=True)          # signed POLICY says debug
    att = envelope(blob, n, debug=False)           # envelope claims otherwise
    expect_refusal(lambda: SevSnpVerifier(ark, ask, vcek).verify_signature(att),
                   contains="debug flag")


def test_report_data_tail_must_be_empty():
    ark, ask, vcek, k = chain()
    n = new_nonce()
    raw = bytearray(build_report(k, n))
    raw[OFF_REPORT_DATA + 40] = 0x42                # data hidden past the nonce
    expect_refusal(
        lambda: SevSnpVerifier(ark, ask, vcek).verify_signature(
            envelope(bytes(raw), n)),
        contains="past the nonce binding")


def test_unsupported_signature_algorithm_is_refused():
    ark, ask, vcek, k = chain()
    n = new_nonce()
    blob = build_report(k, n, algo=7)
    expect_refusal(
        lambda: SevSnpVerifier(ark, ask, vcek).verify_signature(envelope(blob, n)),
        contains="unsupported signature algorithm")


def test_tcb_mismatch_is_refused():
    ark, ask, vcek, k = chain()
    n = new_nonce()
    blob = build_report(k, n, tcb=TCB)
    expect_refusal(
        lambda: SevSnpVerifier(ark, ask, vcek, expected_tcb=0x99).verify_signature(
            envelope(blob, n)),
        contains="tcb")


def test_missing_report_payload_is_refused():
    ark, ask, vcek, k = chain()
    n = new_nonce()
    att = Attestation(format="sev-snp", measurement_hex="00" * 48,
                      report_data_hex=expected_report_data(n),
                      signed_at=0.0, debug_enabled=False, signature_hex="",
                      signing_key_hex="", raw={})
    expect_refusal(
        lambda: SevSnpVerifier(ark, ask, vcek).verify_signature(att),
        contains="no report_b64")


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

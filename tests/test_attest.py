"""Attestation tests. Mostly adversarial, because the honest path is the easy one.

The report that matters here is not the forged one — a bad signature is caught by
any implementation. It is the report that is **genuine, correctly signed,
unexpired, on approved hardware, and describes a different machine than the one
about to see the data.** `test_replayed_genuine_report_is_refused` is the reason
this module exists.
"""

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blindkeep.attest import (
    Attestation,
    AttestationError,
    Ed25519Verifier,
    Policy,
    Result,
    Unverified,
    attest_host,
    default_registry,
    expected_report_data,
    fetch_attestation,
    new_nonce,
    verify_attestation,
)
from blindkeep.crypto import NodeIdentity

SERVERS = []
GOOD_MEASUREMENT = "a" * 64
OTHER_MEASUREMENT = "b" * 64


def mint(identity, nonce, *, measurement=GOOD_MEASUREMENT, fmt="ed25519-ref",
         debug=False, signed_at=None, sign=True):
    """Produce an attestation document the way an honest enclave would."""
    att = Attestation(
        format=fmt,
        measurement_hex=measurement,
        report_data_hex=expected_report_data(nonce),
        signed_at=time.time() if signed_at is None else signed_at,
        debug_enabled=debug,
        signature_hex="00" * 64,
        signing_key_hex=identity.public_hex(),
    )
    if not sign:
        return att
    sig = identity.sign(att.signed_bytes())
    return Attestation(
        format=att.format, measurement_hex=att.measurement_hex,
        report_data_hex=att.report_data_hex, signed_at=att.signed_at,
        debug_enabled=att.debug_enabled, signature_hex=sig.hex(),
        signing_key_hex=att.signing_key_hex)


def policy_for(identity, measurements=(GOOD_MEASUREMENT,), **kw):
    return Policy.build(list(measurements), [identity.public_hex()], **kw)


def enclave_server(identity, *, replay_nonce=None, measurement=GOOD_MEASUREMENT,
                   status=200, body_override=None, redirect_to=None):
    """A host that answers attestation challenges. Honest unless told otherwise."""
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a, **k):
            pass

        def do_POST(self):
            if redirect_to:
                self.send_response(302)
                self.send_header("Location", redirect_to)
                self.end_headers()
                return
            n = int(self.headers.get("Content-Length", 0))
            asked = json.loads(self.rfile.read(n) or b"{}")
            # A replaying host ignores the challenge and returns an old report.
            nonce = replay_nonce or bytes.fromhex(asked["nonce_hex"])
            att = mint(identity, nonce, measurement=measurement)
            payload = body_override if body_override is not None else {
                "format": att.format,
                "measurement_hex": att.measurement_hex,
                "report_data_hex": att.report_data_hex,
                "signed_at": att.signed_at,
                "debug_enabled": att.debug_enabled,
                "signature_hex": att.signature_hex,
                "signing_key_hex": att.signing_key_hex,
            }
            body = (payload if isinstance(payload, bytes)
                    else json.dumps(payload).encode())
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    SERVERS.append(httpd)
    return f"http://127.0.0.1:{httpd.server_address[1]}"


def expect_refusal(fn, *, contains=None, exc=Unverified):
    try:
        fn()
    except exc as e:
        if contains:
            assert contains in str(e).lower(), f"wrong reason: {e}"
        return str(e)
    raise AssertionError("expected a refusal, got none")


# --- the honest path ---------------------------------------------------------

def test_honest_attestation_verifies():
    ident = NodeIdentity.generate()
    nonce = new_nonce()
    res = verify_attestation(mint(ident, nonce), nonce=nonce,
                             policy=policy_for(ident))
    assert isinstance(res, Result)
    assert len(res.checks) == 5, f"expected 5 checks, ran {res.checks}"
    assert "measurement-approved" in res.checks


def test_summary_names_the_measurement():
    ident = NodeIdentity.generate()
    nonce = new_nonce()
    res = verify_attestation(mint(ident, nonce), nonce=nonce,
                             policy=policy_for(ident))
    assert GOOD_MEASUREMENT[:16] in res.summary()


# --- check 3: the one that matters -------------------------------------------

def test_replayed_genuine_report_is_refused():
    """A real report, correctly signed and unexpired — for another session.

    Everything about this document is authentic. Only the binding is wrong.
    """
    ident = NodeIdentity.generate()
    captured = new_nonce()
    stolen = mint(ident, captured)          # genuine, from an earlier exchange
    ours = new_nonce()                      # what we actually challenged with
    expect_refusal(
        lambda: verify_attestation(stolen, nonce=ours, policy=policy_for(ident)),
        contains="nonce")


def test_nonces_are_not_reused():
    assert new_nonce() != new_nonce(), "nonce reuse re-permits replay"


def test_report_data_is_domain_separated():
    """The nonce is hashed with a domain tag, not raw, so a signature over some
    other protocol's hash of the same nonce cannot be repurposed."""
    n = new_nonce()
    import hashlib
    assert expected_report_data(n) != hashlib.sha256(n).hexdigest()


# --- check 2: signature and roots --------------------------------------------

def test_forged_signature_is_refused():
    ident = NodeIdentity.generate()
    nonce = new_nonce()
    att = mint(ident, nonce, sign=False)     # signature left as zeroes
    expect_refusal(
        lambda: verify_attestation(att, nonce=nonce, policy=policy_for(ident)),
        contains="signature")


def test_untrusted_signing_key_is_refused():
    """Real hardware, real signature, key nobody agreed to trust."""
    host, stranger = NodeIdentity.generate(), NodeIdentity.generate()
    nonce = new_nonce()
    att = mint(stranger, nonce)
    expect_refusal(
        lambda: verify_attestation(att, nonce=nonce, policy=policy_for(host)),
        contains="trusted roots")


def test_field_tampered_after_signing_is_refused():
    ident = NodeIdentity.generate()
    nonce = new_nonce()
    good = mint(ident, nonce)
    tampered = Attestation(
        format=good.format, measurement_hex=OTHER_MEASUREMENT,
        report_data_hex=good.report_data_hex, signed_at=good.signed_at,
        debug_enabled=good.debug_enabled, signature_hex=good.signature_hex,
        signing_key_hex=good.signing_key_hex)
    expect_refusal(
        lambda: verify_attestation(
            tampered, nonce=nonce,
            policy=policy_for(ident, (GOOD_MEASUREMENT, OTHER_MEASUREMENT))),
        contains="signature")


# --- check 4: measurement ----------------------------------------------------

def test_unapproved_measurement_is_refused():
    """Genuine enclave, genuine signature, software nobody reviewed."""
    ident = NodeIdentity.generate()
    nonce = new_nonce()
    att = mint(ident, nonce, measurement=OTHER_MEASUREMENT)
    expect_refusal(
        lambda: verify_attestation(att, nonce=nonce, policy=policy_for(ident)),
        contains="not on the approved")


def test_empty_allowlist_is_refused_at_construction():
    ident = NodeIdentity.generate()
    expect_refusal(lambda: Policy.build([], [ident.public_hex()]),
                   contains="empty allowlist", exc=AttestationError)


def test_empty_roots_are_refused_at_construction():
    expect_refusal(lambda: Policy.build([GOOD_MEASUREMENT], []),
                   contains="trusted root", exc=AttestationError)


# --- check 5: posture and freshness ------------------------------------------

def test_debug_enabled_enclave_is_refused():
    ident = NodeIdentity.generate()
    nonce = new_nonce()
    att = mint(ident, nonce, debug=True)
    expect_refusal(
        lambda: verify_attestation(att, nonce=nonce, policy=policy_for(ident)),
        contains="debug")


def test_stale_attestation_is_refused():
    ident = NodeIdentity.generate()
    nonce = new_nonce()
    att = mint(ident, nonce, signed_at=time.time() - 3600)
    expect_refusal(
        lambda: verify_attestation(att, nonce=nonce, policy=policy_for(ident)),
        contains="older than")


def test_future_dated_attestation_is_refused():
    ident = NodeIdentity.generate()
    nonce = new_nonce()
    att = mint(ident, nonce, signed_at=time.time() + 600)
    expect_refusal(
        lambda: verify_attestation(att, nonce=nonce, policy=policy_for(ident)),
        contains="future")


def test_small_clock_skew_is_tolerated():
    ident = NodeIdentity.generate()
    nonce = new_nonce()
    att = mint(ident, nonce, signed_at=time.time() + 5)
    verify_attestation(att, nonce=nonce, policy=policy_for(ident))


# --- check 1: formats --------------------------------------------------------

def test_unknown_format_is_refused():
    ident = NodeIdentity.generate()
    nonce = new_nonce()
    att = mint(ident, nonce, fmt="something-invented")
    expect_refusal(
        lambda: verify_attestation(att, nonce=nonce, policy=policy_for(ident)),
        contains="unknown attestation format")


def test_real_formats_refuse_rather_than_pass_silently():
    """sev-snp/tdx/nvidia are registered as unimplemented ON PURPOSE.

    The dangerous behaviour would be returning no opinion for a format this
    build cannot parse, because a caller reads no error as success.
    """
    ident = NodeIdentity.generate()
    reg = default_registry()
    for fmt in ("sev-snp", "tdx", "nvidia-gpu"):
        assert fmt in reg, f"{fmt} is not registered; it would fail as 'unknown'"
        nonce = new_nonce()
        att = mint(ident, nonce, fmt=fmt)
        msg = expect_refusal(
            lambda: verify_attestation(att, nonce=nonce,
                                       policy=policy_for(ident)))
        assert "no verifier is implemented" in msg, (
            f"{fmt} refused for the wrong reason: {msg}")


def test_reference_verifier_rejects_malformed_hex():
    ident = NodeIdentity.generate()
    nonce = new_nonce()
    good = mint(ident, nonce)
    bad = Attestation(
        format=good.format, measurement_hex=good.measurement_hex,
        report_data_hex=good.report_data_hex, signed_at=good.signed_at,
        debug_enabled=good.debug_enabled, signature_hex="not-hex",
        signing_key_hex=good.signing_key_hex)
    assert Ed25519Verifier().verify_signature(bad) is False


def test_malformed_document_is_refused():
    expect_refusal(lambda: Attestation.from_dict({"format": "ed25519-ref"}),
                   contains="malformed")


# --- no partial trust --------------------------------------------------------

def test_failure_returns_nothing_at_all():
    """Every failure raises. There is no object that means 'partly attested'."""
    ident = NodeIdentity.generate()
    nonce = new_nonce()
    for att in (mint(ident, nonce, debug=True),
                mint(ident, nonce, measurement=OTHER_MEASUREMENT),
                mint(ident, nonce, sign=False)):
        try:
            verify_attestation(att, nonce=nonce, policy=policy_for(ident))
        except Unverified:
            continue
        raise AssertionError("a failing attestation returned a result")


# --- fetching ----------------------------------------------------------------

def test_end_to_end_against_an_honest_host():
    ident = NodeIdentity.generate()
    url = enclave_server(ident)
    res = attest_host(url, policy=policy_for(ident))
    assert len(res.checks) == 5


def test_end_to_end_against_a_replaying_host():
    """The host answers every challenge with one captured genuine report."""
    ident = NodeIdentity.generate()
    url = enclave_server(ident, replay_nonce=new_nonce())
    expect_refusal(lambda: attest_host(url, policy=policy_for(ident)),
                   contains="nonce")


def test_end_to_end_against_a_host_running_unapproved_code():
    ident = NodeIdentity.generate()
    url = enclave_server(ident, measurement=OTHER_MEASUREMENT)
    expect_refusal(lambda: attest_host(url, policy=policy_for(ident)),
                   contains="not on the approved")


def test_attestation_host_redirect_is_refused():
    ident = NodeIdentity.generate()
    url = enclave_server(ident, redirect_to="http://127.0.0.1:1/evil")
    expect_refusal(lambda: attest_host(url, policy=policy_for(ident)),
                   contains="redirect", exc=AttestationError)


def test_unreachable_host_is_an_error_not_a_pass():
    ident = NodeIdentity.generate()
    expect_refusal(
        lambda: attest_host("http://127.0.0.1:1/attest", policy=policy_for(ident)),
        contains="unreachable", exc=AttestationError)


def test_non_json_response_is_refused():
    ident = NodeIdentity.generate()
    url = enclave_server(ident, body_override=b"<html>not json</html>")
    expect_refusal(lambda: attest_host(url, policy=policy_for(ident)),
                   contains="not valid json")


def test_http_error_is_an_error_not_a_pass():
    ident = NodeIdentity.generate()
    url = enclave_server(ident, status=500)
    expect_refusal(lambda: attest_host(url, policy=policy_for(ident)),
                   contains="http 500", exc=AttestationError)


def test_attested_complete_cannot_be_called_without_a_verified_result():
    """The ordering is enforced by the signature, not by the caller's memory."""
    from blindkeep.attest import attested_complete
    for fake in (True, "verified", None, {"checks": 5}):
        expect_refusal(
            lambda f=fake: attested_complete(
                "hi", api_base="http://127.0.0.1:1", api_key="k", model="m",
                result=f),
            contains="requires a verified result", exc=AttestationError)


def test_attested_complete_accepts_a_real_result():
    from blindkeep.attest import attested_complete
    ident = NodeIdentity.generate()
    url = enclave_server(ident)
    res = attest_host(url, policy=policy_for(ident))
    # The host above answers attestation, not completions, so this fails at the
    # transport -- which proves the Result gate was passed, not bypassed.
    expect_refusal(
        lambda: attested_complete("hi", api_base="http://127.0.0.1:1",
                                  api_key="k", model="m", result=res),
        contains="unreachable", exc=AttestationError)


def test_fetch_returns_unverified_documents():
    """fetch_attestation must not be mistaken for verification."""
    ident = NodeIdentity.generate()
    url = enclave_server(ident, measurement=OTHER_MEASUREMENT)
    att = fetch_attestation(url, new_nonce())
    assert att.measurement_hex == OTHER_MEASUREMENT, (
        "fetch silently filtered something; it must return what was said")


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
    for h in SERVERS:
        try:
            h.shutdown()
            h.server_close()
        except Exception:
            pass
    print(f"\n{len(passed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())

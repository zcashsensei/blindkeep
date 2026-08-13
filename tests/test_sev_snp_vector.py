"""Known-answer test against a report from REAL AMD SEV-SNP hardware.

    py -3 tests/test_sev_snp_vector.py     # trust the EXIT CODE, not the text

Every other test in test_sev_snp.py checks the implementation against the same reading of
the spec that produced it. Only a real report can catch the failure that matters: a parser
that reads the wrong 48 bytes as the measurement and PASSES.

🔴 THIS FILE MUST NEVER BE SILENTLY GREEN. A test that quietly passes when its fixture is
missing is the exact defect that let an invariant stay green for its whole life
(`except: []`). So when no vector is present it does not just skip — it asserts that the
project is still SAYING SO, by checking `status.NOT_CLAIMED` still carries the disclaimer.

The invariant therefore holds in both states, and the only way to fail is to be dishonest:
    vector present  -> it must parse and verify
    vector absent   -> the docs must still admit it is unvalidated
Removing the disclaimer without adding a vector fails here, which is the point.
"""
from __future__ import annotations

import json
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from blindkeep import attest, status                              # noqa: E402
from blindkeep._console import use_utf8_stdout                     # noqa: E402
from blindkeep.sev_snp import parse_report, registry_with_sev_snp  # noqa: E402

# This file prints U+26A0 and an em dash. A Windows console defaults to cp1252
# and raises UnicodeEncodeError on both, which crashed the suite before any
# assertion ran -- so the honesty check this file exists to enforce could not
# report either way. Fourth occurrence of this bug class in the project.
use_utf8_stdout()

VECTORS = ROOT / "tests" / "vectors"
REPORT = VECTORS / "sev_snp_real.bin"
META = VECTORS / "sev_snp_real.json"
DISCLAIMER = "SEV-SNP validated against real hardware"

FAILED: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {name}{'  ' + detail if detail else ''}")
    if not ok:
        FAILED.append(name)


def test_no_vector_means_the_docs_still_say_so() -> None:
    """The honesty half. Only meaningful while the vector is absent."""
    if REPORT.exists():
        return
    print("\n  ⚠  NO REAL-HARDWARE VECTOR PRESENT — sev-snp is NOT validated.")
    print("     docs/SEV_SNP_VALIDATION.md · ~1 hour · a few dollars of VM time.")
    still_disclaimed = any(DISCLAIMER in str(x) for x in status.NOT_CLAIMED)
    check("absent vector: NOT_CLAIMED still carries the disclaimer", still_disclaimed,
          "" if still_disclaimed else "-- the docs claim more than the tests prove")


def test_real_report_parses_to_its_known_answers() -> None:
    if not REPORT.exists():
        return
    meta = json.loads(META.read_text(encoding="utf-8"))
    raw = REPORT.read_bytes()

    check("report is the recorded size", len(raw) == meta["report_bytes"],
          f"{len(raw)} vs {meta['report_bytes']}")

    rep = parse_report(raw)
    check("measurement matches the recorded answer",
          rep.measurement.hex() == meta["expected_measurement_hex"])
    check("report_data matches the recorded answer",
          rep.report_data[:32].hex() == meta["expected_report_data_hex"])
    check("debug is disabled", rep.debug_enabled is False)
    check("reported_tcb matches", rep.reported_tcb == meta["reported_tcb"])


def test_real_report_passes_all_five_checks() -> None:
    if not REPORT.exists():
        return
    import base64

    meta = json.loads(META.read_text(encoding="utf-8"))
    raw = REPORT.read_bytes()
    rep = parse_report(raw)
    certs = {n: (VECTORS / f"sev_snp_real_{n}.pem").read_bytes()
             for n in ("ark", "ask", "vcek")}
    nonce = bytes.fromhex(meta["nonce_hex"])

    att = attest.Attestation(
        format="sev-snp",
        measurement_hex=rep.measurement.hex(),
        report_data_hex=rep.report_data[:32].hex(),
        signed_at=time.time(),
        debug_enabled=rep.debug_enabled,
        signature_hex="",
        signing_key_hex="amd-vcek",
        raw={"report_b64": base64.b64encode(raw).decode()},
    )
    policy = attest.Policy.build([rep.measurement.hex()], ["amd-vcek"])
    reg = registry_with_sev_snp(certs["ark"], certs["ask"], certs["vcek"])
    try:
        res = attest.verify_attestation(att, nonce=nonce, policy=policy, registry=reg)
        check("real report passes all five checks", True, res.summary())
    except Exception as e:
        # Everything in the report is big-endian EXCEPT r and s. A failure here with the
        # parse checks clean is that, before it is anything else.
        check("real report passes all five checks", False,
              f"{type(e).__name__}: {e} -- suspect _le_component (little-endian r/s)")


def test_a_wrong_nonce_is_rejected() -> None:
    """A vector that verifies under ANY nonce would mean check 3 is not binding."""
    if not REPORT.exists():
        return
    import base64

    meta = json.loads(META.read_text(encoding="utf-8"))
    raw = REPORT.read_bytes()
    rep = parse_report(raw)
    certs = {n: (VECTORS / f"sev_snp_real_{n}.pem").read_bytes()
             for n in ("ark", "ask", "vcek")}

    att = attest.Attestation(
        format="sev-snp", measurement_hex=rep.measurement.hex(),
        report_data_hex=rep.report_data[:32].hex(), signed_at=time.time(),
        debug_enabled=rep.debug_enabled, signature_hex="", signing_key_hex="amd-vcek",
        raw={"report_b64": base64.b64encode(raw).decode()},
    )
    policy = attest.Policy.build([rep.measurement.hex()], ["amd-vcek"])
    reg = registry_with_sev_snp(certs["ark"], certs["ask"], certs["vcek"])
    rejected = False
    try:
        attest.verify_attestation(att, nonce=b"\x00" * attest.NONCE_BYTES,
                                  policy=policy, registry=reg)
    except Exception:
        rejected = True
    check("a wrong nonce is REJECTED (check 3 binds)", rejected)


def main() -> int:
    print("test_sev_snp_vector — real-hardware known-answer vector")
    test_no_vector_means_the_docs_still_say_so()
    test_real_report_parses_to_its_known_answers()
    test_real_report_passes_all_five_checks()
    test_a_wrong_nonce_is_rejected()
    print(f"\n{'FAILED: ' + ', '.join(FAILED) if FAILED else 'ALL PASS'}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Turn one captured SEV-SNP report into a permanent known-answer vector.

Two modes, matching docs/SEV_SNP_VALIDATION.md:

    py -3 tools/sev_snp_ingest.py --nonce
        Before you rent anything. Generates a nonce, prints the report_data hex to carry
        to the guest, and saves both so a closed terminal does not cost you the trip.

    py -3 tools/sev_snp_ingest.py --capture blindkeep-snp-capture --nonce <hex>
        After you come home. Runs the three assumption checks, then the full five-check
        pipeline, then writes tests/vectors/ so the parser can never silently regress.

🔴 IT REFUSES TO WRITE THE VECTOR IF ANY CHECK FAILS. The doc's rule is that a
disagreement means the parser is wrong and the fix belongs in sev_snp.py — never adjust
the expectation to match the parser. Writing a vector from a failed capture would bake
the bug in as the expected answer, which is the one outcome worse than having no vector.
"""
from __future__ import annotations

import argparse
import base64
import json
import pathlib
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from blindkeep import attest                                  # noqa: E402
from blindkeep.sev_snp import parse_report, registry_with_sev_snp  # noqa: E402

VECTORS = ROOT / "tests" / "vectors"
NONCE_STASH = ROOT / "data" / "sev_snp_nonce.json"
EXPECTED_BYTES = 1184


def cmd_nonce() -> int:
    nonce = attest.new_nonce()
    rd = attest.expected_report_data(nonce)
    NONCE_STASH.parent.mkdir(parents=True, exist_ok=True)
    NONCE_STASH.write_text(json.dumps(
        {"nonce_hex": nonce.hex(), "report_data_hex": rd,
         "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, indent=1),
        encoding="utf-8")
    print(f"nonce        : {nonce.hex()}")
    print(f"report_data  : {rd}")
    print(f"\nsaved to     : {NONCE_STASH}")
    print("\nOn the guest:  ./sev_snp_capture.sh " + rd)
    return 0


def _load(cap: pathlib.Path, name: str) -> bytes:
    p = cap / name
    if not p.exists():
        raise SystemExit(f"FAIL: {p} missing — capture is incomplete")
    return p.read_bytes()


def cmd_ingest(cap: pathlib.Path, nonce_hex: str) -> int:
    nonce = bytes.fromhex(nonce_hex)
    raw = _load(cap, "report.bin")
    ark, ask, vcek = (_load(cap, f"{n}.pem") for n in ("ark", "ask", "vcek"))

    failures: list[str] = []

    def check(label: str, ok: bool, detail: str = "") -> None:
        print(f"  {'ok  ' if ok else 'FAIL'} {label}{'  ' + detail if detail else ''}")
        if not ok:
            failures.append(label)

    print(f"\ncapture: {cap}")
    check("report is 1184 bytes", len(raw) == EXPECTED_BYTES, f"got {len(raw)}")

    rep = parse_report(raw)   # ← the three spec assumptions are exercised here

    # ── Assumption 1: OFF_REPORT_DATA is right and the padding matches. ───────────────────
    want_rd = attest.expected_report_data(nonce)
    got_rd = rep.report_data[:32].hex()
    check("report_data binds OUR nonce", got_rd == want_rd,
          f"\n         expected {want_rd}\n         got      {got_rd}")

    # ── Assumption 2: MEASUREMENT really starts at 0x090. ────────────────────────────────
    m = rep.measurement
    plausible = (len(m) == 48 and any(m) and len(set(m)) > 8
                 and not all(32 <= b < 127 for b in m))
    check("measurement is a plausible 48-byte digest", plausible, m.hex()[:32] + "…")
    check("measurement is not all zeros", any(m))

    # ── Assumption 3 is exercised by the signature verifying at all (little-endian r/s). ──
    check("debug disabled on a normal launch", rep.debug_enabled is False,
          f"policy=0x{rep.policy:x}")

    print(f"\n  version {rep.version} · reported_tcb 0x{rep.reported_tcb:x} "
          f"· chip_id {rep.chip_id.hex()[:16]}…")
    amd = cap / "amd_display.txt"
    print(f"  cross-check against AMD's own parse: "
          f"{'see ' + str(amd) if amd.exists() else 'ABSENT — weaker validation'}")

    # ── Full five-check pipeline ─────────────────────────────────────────────────────────
    print("\nfull pipeline:")
    att = attest.Attestation(
        format="sev-snp",
        measurement_hex=m.hex(),
        report_data_hex=got_rd,
        signed_at=time.time(),
        debug_enabled=rep.debug_enabled,
        signature_hex="",
        signing_key_hex="amd-vcek",
        raw={"report_b64": base64.b64encode(raw).decode()},
    )
    policy = attest.Policy.build([m.hex()], ["amd-vcek"])
    reg = registry_with_sev_snp(ark, ask, vcek)
    try:
        res = attest.verify_attestation(att, nonce=nonce, policy=policy, registry=reg)
        print(f"  {res.summary()}")
    except Exception as e:
        # A signature failure with checks 1-2 clean points at _le_component before anything
        # else — everything in the report is big-endian EXCEPT r and s.
        check("verify_attestation", False, f"{type(e).__name__}: {e}")
        print("\n  Signature failure with report_data + measurement clean is the classic "
              "little-endian r/s symptom — look at _le_component in sev_snp.py FIRST.")

    if failures:
        print(f"\n❌ {len(failures)} check(s) failed — NO VECTOR WRITTEN.")
        print("   The parser is wrong; the fix belongs in blindkeep/sev_snp.py.")
        print("   Do NOT edit the expectation to match the parser.")
        return 1

    # ── Step 6: make it permanent ────────────────────────────────────────────────────────
    VECTORS.mkdir(parents=True, exist_ok=True)
    (VECTORS / "sev_snp_real.bin").write_bytes(raw)
    for n, blob in (("ark", ark), ("ask", ask), ("vcek", vcek)):
        (VECTORS / f"sev_snp_real_{n}.pem").write_bytes(blob)
    (VECTORS / "sev_snp_real.json").write_text(json.dumps({
        "nonce_hex": nonce_hex,
        "expected_report_data_hex": want_rd,
        "expected_measurement_hex": m.hex(),
        "report_bytes": len(raw),
        "reported_tcb": rep.reported_tcb,
        "captured_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "note": "Known-answer vector from real AMD SEV-SNP hardware. The report contains "
                "CHIP_ID, which identifies a physical processor — this came from a "
                "throwaway VM. Never commit a report from a machine you keep.",
    }, indent=1), encoding="utf-8")

    print(f"\n✅ vector written to {VECTORS}")
    print("   next:  py -3 tests/test_sev_snp_vector.py")
    print("   then:  docs/SEV_SNP_VALIDATION.md step 7 (enable it on the default path)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--nonce", nargs="?", const="", default=None,
                    help="with no value: generate one. With a hex value: use it for --capture.")
    ap.add_argument("--capture", type=pathlib.Path, help="folder brought back from the guest")
    a = ap.parse_args()

    if a.capture is None:
        if a.nonce is None:
            ap.print_help()
            return 2
        return cmd_nonce()

    nonce_hex = a.nonce or ""
    if not nonce_hex and NONCE_STASH.exists():
        nonce_hex = json.loads(NONCE_STASH.read_text(encoding="utf-8"))["nonce_hex"]
        print(f"(using the nonce stashed at {NONCE_STASH})")
    if not nonce_hex:
        raise SystemExit("FAIL: --nonce <hex> required (or run --nonce first to stash one)")
    return cmd_ingest(a.capture, nonce_hex)


if __name__ == "__main__":
    raise SystemExit(main())

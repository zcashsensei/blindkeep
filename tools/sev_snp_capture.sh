#!/usr/bin/env bash
# Capture one SEV-SNP attestation report bound to a Oblivio nonce.
#
# Runs ON THE GUEST (a rented SEV-SNP confidential VM). Everything it needs is the
# 32-byte report_data hex printed by tools/sev_snp_ingest.py --nonce on your own machine.
#
#   ./sev_snp_capture.sh <report_data_hex>
#
# Produces ./oblivio-snp-capture/ containing report.bin, ark.pem, ask.pem, vcek.pem
# and capture.json. Bring that whole folder home and run:
#
#   py -3 tools/sev_snp_ingest.py --capture <folder> --nonce <nonce_hex>
#
# See docs/SEV_SNP_VALIDATION.md. Destroy the VM afterwards — this is one capture,
# not infrastructure.
set -euo pipefail

RD_HEX="${1:-}"
OUT="./oblivio-snp-capture"

die() { echo "FAIL: $*" >&2; exit 1; }

[ -n "$RD_HEX" ] || die "usage: $0 <report_data_hex>   (64 hex chars = 32 bytes)"
[ "${#RD_HEX}" -eq 64 ] || die "report_data must be 64 hex chars (32 bytes), got ${#RD_HEX}"

# ── Step 2 of the doc: confirm this really IS SEV-SNP before capturing anything. ──────────
# A plain-SEV or ordinary VM produces something report-shaped and worthless; capturing it
# and finding out at home wastes the entire trip.
[ -e /dev/sev-guest ] || die "/dev/sev-guest absent — this is NOT an SEV-SNP guest. Fix the instance."
echo "ok   /dev/sev-guest present"
if dmesg 2>/dev/null | grep -qiE 'sev-snp'; then
  echo "ok   dmesg reports SEV-SNP"
else
  echo "warn dmesg has no SEV-SNP line (may need sudo); /dev/sev-guest is the binding check"
fi

command -v snpguest >/dev/null 2>&1 || die "snpguest not found — cargo install snpguest"

mkdir -p "$OUT"
cd "$OUT"

# REPORT_DATA is 64 bytes: our 32-byte hash, zero-padded. The padding is part of what the
# parser is being tested on, so write it explicitly rather than letting a tool guess.
python3 -c "
import sys
rd = bytes.fromhex(sys.argv[1])
assert len(rd) == 32, len(rd)
open('rd.bin','wb').write(rd + b'\x00'*32)
" "$RD_HEX"
echo "ok   rd.bin written (32-byte hash + 32 zero bytes)"

snpguest report report.bin rd.bin
[ -s report.bin ] || die "snpguest produced no report"
SZ=$(wc -c < report.bin)
echo "ok   report.bin captured ($SZ bytes; 1184 expected)"

# Chip- and TCB-specific. A VCEK from another machine will not verify this report, and that
# is correct behaviour rather than a bug to route around.
snpguest certificates PEM ./certs
for f in vcek ask ark; do
  if   [ -f "./certs/$f.pem" ]; then cp "./certs/$f.pem" "./$f.pem"
  elif [ -f "./certs/${f^^}.pem" ]; then cp "./certs/${f^^}.pem" "./$f.pem"
  else die "certs/$f.pem missing — snpguest certificates did not return the full chain"
  fi
  echo "ok   $f.pem"
done

# AMD's own parse, kept beside ours so the two readings can be compared at home. This is the
# independent opinion that makes the capture worth more than our parser agreeing with itself.
snpguest display report report.bin > amd_display.txt 2>&1 || \
  echo "warn snpguest display failed — not fatal, but the cross-check is weaker without it"

cat > capture.json <<JSON
{
  "report_data_hex": "$RD_HEX",
  "report_bytes": $SZ,
  "captured_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "snpguest": "$(snpguest --version 2>/dev/null || echo unknown)",
  "kernel": "$(uname -r)",
  "note": "CHIP_ID inside report.bin identifies this physical processor. Throwaway VM only."
}
JSON

cd ..
echo
echo "DONE -> $OUT"
echo "Bring the whole folder home, then:"
echo "  py -3 tools/sev_snp_ingest.py --capture $OUT --nonce <nonce_hex>"
echo
echo "Now DESTROY this VM."

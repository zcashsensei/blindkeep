# Validating the SEV-SNP verifier against real hardware

`blindkeep/sev_snp.py` parses AMD SEV-SNP attestation reports, verifies ECDSA P-384 against a
VCEK, and walks the ARK → ASK → VCEK chain. **It has never seen a report from real hardware**, so
it is deliberately excluded from `attest.default_registry()` and `sev-snp` refuses on the default
path.

This is the procedure that changes that. It is not a coding task — the code is written and its
tests pass against synthetic reports. What is missing is one real report, and the confidence that
this implementation reads it the same way AMD's does.

**Time:** about an hour. **Cost:** a few dollars of VM time.

---

## Why this cannot be skipped

An unvalidated parser fails in one of two ways. It always errors — merely useless. Or it reads
the wrong 48 bytes as the measurement and **passes**, which is the worst thing this project could
ship, because the entire value of attestation is that passing means something.

Three specific things a spec reading is most likely to have got wrong, and each is silent:

| Assumption in `sev_snp.py` | Why it might be wrong |
|---|---|
| `MEASUREMENT` begins at `0x090` | Offsets shift between report versions |
| The signature covers exactly the first `0x2A0` bytes | The signed range is not the whole struct |
| `r` and `s` are 72-byte **little-endian** fields | Everything else in the report is big-endian |

The third is the classic. Getting endianness backwards produces a signature that never verifies —
the safe direction — but it is indistinguishable from "the report is invalid", so it would look
like a working refusal rather than a broken parser.

---

## Step 1 — get a SEV-SNP guest

Any of these produce genuine reports. Pick whichever account you already have.

| Provider | Instance type | Notes |
|---|---|---|
| Azure | `DCa_v5` / `DCad_v5` (AMD) | Confidential VM; enable *AMD SEV-SNP* at creation |
| AWS | any `.metal` or Nitro instance with AMD SEV-SNP enabled | Enable via `CpuOptions` |
| GCP | `n2d-standard-*` with **Confidential VM** = SEV-SNP | Choose SEV-SNP, not plain SEV |

Ubuntu 22.04+ or a recent Fedora both ship a kernel with `/dev/sev-guest`.

**Destroy the VM when finished.** It is needed for one capture, not as infrastructure.

## Step 2 — confirm it really is SEV-SNP

```bash
ls -l /dev/sev-guest              # must exist
dmesg | grep -i -E 'sev-snp|SEV-SNP'
```

If `/dev/sev-guest` is absent you have a plain SEV or ordinary VM, and every report from it will
be worthless for this purpose. Stop here and fix the instance, rather than capturing something
that looks like a report and is not.

## Step 3 — capture a report bound to a nonce we choose

The 64-byte `REPORT_DATA` field is caller-supplied. Blindkeep fills it with
`sha256("blindkeep-attest-v1\0" || nonce)`, so generate the nonce with Blindkeep and carry the
expected value with you — this is the check that makes the report *about our request*.

```bash
# on your own machine
python - <<'PY'
from blindkeep.attest import new_nonce, expected_report_data
n = new_nonce()
print("nonce        :", n.hex())
print("report_data  :", expected_report_data(n))
PY
```

On the guest, using [`snpguest`](https://github.com/virtee/snpguest) (`cargo install snpguest`):

```bash
# REPORT_DATA must be the 32-byte hash above, zero-padded to 64 bytes
python3 -c "open('rd.bin','wb').write(bytes.fromhex('<report_data>') + b'\x00'*32)"
snpguest report report.bin rd.bin
snpguest certificates PEM ./certs        # VCEK, ASK, ARK for THIS chip and TCB
```

Bring back `report.bin`, `certs/vcek.pem`, `certs/ask.pem`, `certs/ark.pem`, and the nonce.

**The certificates are chip- and TCB-specific.** A VCEK from a different machine, or the same
machine after a firmware update, will not verify this report — and that is correct behaviour, not
a bug to work around.

## Step 4 — run it

```bash
python - <<'PY'
from blindkeep.attest import Attestation, Policy, verify_attestation
from blindkeep.sev_snp import parse_report, registry_with_sev_snp
import base64, pathlib

raw = pathlib.Path("report.bin").read_bytes()
print("report bytes :", len(raw), "(expected 1184)")

rep = parse_report(raw)                       # ← the three assumptions get tested here
print("measurement  :", rep.measurement.hex())
print("report_data  :", rep.report_data[:32].hex())
print("debug        :", rep.debug_enabled)
print("reported TCB :", hex(rep.reported_tcb))
PY
```

**Check the three assumptions explicitly, not just that it did not crash:**

1. `report_data[:32]` equals the `report_data` you printed in step 3. If it does not,
   `OFF_REPORT_DATA` is wrong or the padding differs.
2. `measurement` is 48 bytes of plausible digest — not zeros, not ASCII, not obviously shifted.
   Compare against `snpguest display report report.bin`, which prints AMD's own parse.
3. `debug_enabled` is `False` on a normally-launched guest.

If any disagrees, **the parser is wrong and the fix belongs in `sev_snp.py`** — do not adjust the
test to match the parser.

## Step 5 — verify the whole pipeline

```bash
python - <<'PY'
from blindkeep.attest import Attestation, Policy, verify_attestation
from blindkeep.sev_snp import parse_report, registry_with_sev_snp
import base64, pathlib

raw   = pathlib.Path("report.bin").read_bytes()
rep   = parse_report(raw)
certs = {n: pathlib.Path(f"certs/{n}.pem").read_bytes() for n in ("ark", "ask", "vcek")}
nonce = bytes.fromhex("<the nonce from step 3>")

att = Attestation(
    format="sev-snp",
    measurement_hex=rep.measurement.hex(),
    report_data_hex=rep.report_data[:32].hex(),
    signed_at=__import__("time").time(),
    debug_enabled=rep.debug_enabled,
    signature_hex="", signing_key_hex="amd-vcek",
    raw={"report_b64": base64.b64encode(raw).decode()},
)
policy = Policy.build([rep.measurement.hex()], ["amd-vcek"])
reg = registry_with_sev_snp(certs["ark"], certs["ask"], certs["vcek"])
print(verify_attestation(att, nonce=nonce, policy=policy, registry=reg).summary())
PY
```

Expected: `attested [sev-snp] measurement … (5 checks passed)`.

A signature failure here, with steps 1–4 clean, points at the **little-endian `r`/`s`** handling
in `_le_component` before anything else.

## Step 6 — make it a permanent test

Add the captured report as a known-answer vector so the parser can never silently regress:

```
tests/vectors/sev_snp_real.bin        the report
tests/vectors/sev_snp_real.json       nonce, expected measurement, cert paths
```

Then extend `tests/test_sev_snp.py` with a case that loads them. Until this exists, every test in
that file checks the implementation against **the same reading of the spec that produced it** —
which is why the suite currently says so in its own docstring.

**Redact nothing and publish nothing without looking.** A report contains `CHIP_ID`, which
identifies the physical processor. For a throwaway VM that is harmless; do not commit a report
from a machine you keep.

## Step 7 — turn it on

Only after step 6 passes:

1. Move `SevSnpVerifier` into `attest.default_registry()`.
2. Delete `test_sev_snp_is_not_in_the_default_registry`, which exists to fail the moment someone
   enables this without validating it — that is its whole job.
3. `blindkeep status` will flip **`SEV-SNP enabled by default`** to `OK` on its own, and
   `SEV-SNP validated against real hardware` should be removed from `NOT_CLAIMED` in
   `blindkeep/status.py`.
4. Update the README and `SECURITY.md`, both of which currently state plainly that no vendor
   verifier is validated.

---

## What this still does not give you

Validation proves the parser reads AMD's format correctly. It does not prove:

- **that the enclave is trustworthy** — attestation shifts trust to AMD and the certificate
  chain, it does not remove trust;
- **that the measurement is of good code** — a valid attestation of a malicious image is still a
  valid attestation. The measurement allowlist is where that judgement lives, and it is yours;
- **anything about `tdx` or `nvidia-gpu`**, which remain unimplemented and refuse.

And the reason to run `--tier sealed` rather than `--tier attested` even afterwards: the
`ecc::chip::mul` soundness bug sat inside the most scrutinised circuit in this ecosystem for four
years. A validated verifier is a better assumption, not an absent one.

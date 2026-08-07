"""AMD SEV-SNP attestation report parsing and verification.

**NEVER RUN AGAINST REAL HARDWARE. NOT IN THE DEFAULT REGISTRY.**

That warning is the most important line in this file, so it is the first one.
Everything below implements the AMD SEV Secure Nested Paging Firmware ABI
Specification (rev 1.55) as documented — the 1184-byte report layout, ECDSA
P-384 over SHA-384, AMD's little-endian signature encoding, and the ARK → ASK →
VCEK certificate chain. None of it has been checked against a report produced by
an actual EPYC machine, because the author does not have one.

**Why it is written anyway, and why it is disabled anyway.** A verifier is only
useful if it is correct, and correctness here is a claim about byte offsets in
someone else's silicon. Two outcomes are possible from an unvalidated parser:
it always fails, which is merely useless, or it reads the wrong 48 bytes as the
measurement and *passes* — which is the worst failure this project could ship,
because the entire point of attestation is that passing means something. So the
code exists, is reviewable, and is reachable only by a caller who deliberately
constructs it:

    registry = default_registry()                       # sev-snp REFUSES
    registry = registry_with_sev_snp(ark, ask, vcek)    # deliberate opt-in

`attest.default_registry()` is unchanged and still refuses `sev-snp`. Enabling
this is an act, not a default — the same shape as the cloud gate.

**What validation requires**, so the remaining work is concrete rather than
vague: one report captured from a real SEV-SNP guest (Azure DCasv5/DCadsv5, AWS
SEV-SNP instances or GCP N2D confidential VMs all produce them), its matching
VCEK from AMD's KDS, and a run of `tests/test_sev_snp.py` extended with that
report as a known-answer vector. Three specific things it must confirm, because
they are the ones a spec reading is most likely to get wrong:

1. that `MEASUREMENT` really begins at offset 0x090,
2. that the signature covers exactly the first 0x2A0 bytes,
3. that `r` and `s` are 72-byte **little-endian** fields, not big-endian.

**Not implemented even once validated:** fetching VCEKs from AMD's KDS,
certificate revocation, and TCB-version policy beyond the equality check below.
Certificates are supplied by the caller.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .attest import Attestation, Unverified

# Layout, AMD SEV-SNP Firmware ABI rev 1.55, ATTESTATION_REPORT.
REPORT_BYTES = 0x4A0            # 1184 total
SIGNED_BYTES = 0x2A0            # 672 signed; the signature itself follows
OFF_VERSION = 0x000
OFF_POLICY = 0x008
OFF_SIGNATURE_ALGO = 0x034
OFF_CURRENT_TCB = 0x038
OFF_REPORT_DATA = 0x050         # 64 bytes
OFF_MEASUREMENT = 0x090         # 48 bytes
OFF_REPORTED_TCB = 0x180
OFF_CHIP_ID = 0x1A0             # 64 bytes
OFF_SIGNATURE = 0x2A0

SIG_COMPONENT_BYTES = 72        # r and s are each 72 bytes, little-endian
P384_BYTES = 48
SIG_ALGO_ECDSA_P384_SHA384 = 1
POLICY_DEBUG_BIT = 19           # confirmed against the IETF CoRIM profile draft


@dataclass(frozen=True)
class Report:
    """A parsed report. Parsing is not verification — nothing here is trusted."""
    version: int
    policy: int
    signature_algo: int
    current_tcb: int
    reported_tcb: int
    report_data: bytes
    measurement: bytes
    chip_id: bytes
    signed_region: bytes
    signature_r: int
    signature_s: int

    @property
    def debug_enabled(self) -> bool:
        return bool(self.policy & (1 << POLICY_DEBUG_BIT))


def _le_component(blob: bytes) -> int:
    """AMD stores r and s little-endian in 72-byte fields; everything else is big.

    Getting this backwards produces a signature that never verifies, which is
    the safe direction — but it is also the single most common implementation
    error against this format, so it is isolated here with a name.
    """
    if len(blob) != SIG_COMPONENT_BYTES:
        raise Unverified(
            f"signature component is {len(blob)} bytes, expected {SIG_COMPONENT_BYTES}")
    if any(blob[P384_BYTES:]):
        raise Unverified(
            "signature component has data beyond the P-384 range; not a "
            "P-384 signature in AMD's encoding")
    return int.from_bytes(blob[:P384_BYTES], "little")


def parse_report(raw: bytes) -> Report:
    """Parse the binary report. Raises rather than returning a partial object."""
    if len(raw) != REPORT_BYTES:
        raise Unverified(
            f"attestation report is {len(raw)} bytes, expected {REPORT_BYTES}")

    version, = struct.unpack_from("<I", raw, OFF_VERSION)
    policy, = struct.unpack_from("<Q", raw, OFF_POLICY)
    algo, = struct.unpack_from("<I", raw, OFF_SIGNATURE_ALGO)
    current_tcb, = struct.unpack_from("<Q", raw, OFF_CURRENT_TCB)
    reported_tcb, = struct.unpack_from("<Q", raw, OFF_REPORTED_TCB)

    sig = raw[OFF_SIGNATURE:OFF_SIGNATURE + 2 * SIG_COMPONENT_BYTES]
    return Report(
        version=version,
        policy=policy,
        signature_algo=algo,
        current_tcb=current_tcb,
        reported_tcb=reported_tcb,
        report_data=raw[OFF_REPORT_DATA:OFF_REPORT_DATA + 64],
        measurement=raw[OFF_MEASUREMENT:OFF_MEASUREMENT + 48],
        chip_id=raw[OFF_CHIP_ID:OFF_CHIP_ID + 64],
        signed_region=raw[:SIGNED_BYTES],
        signature_r=_le_component(sig[:SIG_COMPONENT_BYTES]),
        signature_s=_le_component(sig[SIG_COMPONENT_BYTES:]),
    )


def verify_chain(ark_pem: bytes, ask_pem: bytes, vcek_pem: bytes) -> x509.Certificate:
    """ARK self-signed, ARK signs ASK, ASK signs VCEK. Returns the VCEK.

    The root is checked for self-consistency but NOT against a pinned AMD root
    fingerprint — the caller supplies the ARK, so the caller is asserting it is
    AMD's. Pinning belongs where the policy lives, not here.
    """
    try:
        ark = x509.load_pem_x509_certificate(ark_pem)
        ask = x509.load_pem_x509_certificate(ask_pem)
        vcek = x509.load_pem_x509_certificate(vcek_pem)
    except Exception as exc:
        raise Unverified(f"could not load AMD certificate chain: {exc}") from exc

    for child, parent, name in ((ark, ark, "ARK self-signature"),
                                (ask, ark, "ASK under ARK"),
                                (vcek, ask, "VCEK under ASK")):
        try:
            parent.public_key().verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(child.signature_hash_algorithm),
            )
        except (InvalidSignature, TypeError, ValueError) as exc:
            raise Unverified(f"{name} did not verify: {exc}") from exc
    return vcek


class SevSnpVerifier:
    """Real SEV-SNP verification. Construct deliberately; never a default.

    Implements `attest.Verifier` so it drops into the existing five checks: this
    class supplies check 2, and the surrounding pipeline still enforces nonce
    binding, the measurement allowlist, debug posture and freshness.
    """

    format = "sev-snp"

    def __init__(self, ark_pem: bytes, ask_pem: bytes, vcek_pem: bytes,
                 expected_tcb: Optional[int] = None):
        self.vcek = verify_chain(ark_pem, ask_pem, vcek_pem)
        self.expected_tcb = expected_tcb

    def verify_signature(self, att: Attestation) -> bool:
        raw = att.raw.get("report_b64") or att.raw.get("report_hex")
        if not raw:
            raise Unverified(
                "sev-snp attestation carries no report_b64/report_hex field")
        try:
            blob = (bytes.fromhex(raw) if "report_hex" in att.raw
                    else __import__("base64").b64decode(raw, validate=True))
        except Exception as exc:
            raise Unverified(f"report is not decodable: {exc}") from exc

        report = parse_report(blob)

        if report.signature_algo != SIG_ALGO_ECDSA_P384_SHA384:
            raise Unverified(
                f"unsupported signature algorithm {report.signature_algo}; only "
                f"ECDSA P-384/SHA-384 ({SIG_ALGO_ECDSA_P384_SHA384}) is implemented")

        # The envelope the surrounding pipeline reads must match the signed
        # report, or the checks above it would verify one thing while the
        # signature covered another.
        if att.measurement_hex != report.measurement.hex():
            raise Unverified(
                "envelope measurement does not match the signed report")
        # SNP gives 64 caller-controlled bytes; the nonce binding is a 32-byte
        # SHA-256 placed at the front. Compare that prefix explicitly and require
        # the remainder to be zero, rather than pattern-matching hex strings —
        # a host that hid data in the tail would otherwise go unnoticed.
        if report.report_data[:32].hex() != att.report_data_hex:
            raise Unverified(
                "envelope report_data does not match the signed report")
        if any(report.report_data[32:]):
            raise Unverified(
                "report_data carries unexpected bytes past the nonce binding")
        if att.debug_enabled != report.debug_enabled:
            raise Unverified(
                "envelope debug flag does not match the signed POLICY")

        if self.expected_tcb is not None and report.reported_tcb != self.expected_tcb:
            raise Unverified(
                f"reported TCB {report.reported_tcb:#x} is not the expected "
                f"{self.expected_tcb:#x}")

        der = encode_dss_signature(report.signature_r, report.signature_s)
        try:
            self.vcek.public_key().verify(
                der, report.signed_region, ec.ECDSA(hashes.SHA384()))
        except InvalidSignature:
            return False
        except (TypeError, ValueError) as exc:
            raise Unverified(f"VCEK could not verify the report: {exc}") from exc
        return True


def registry_with_sev_snp(ark_pem: bytes, ask_pem: bytes, vcek_pem: bytes,
                          expected_tcb: Optional[int] = None) -> dict:
    """A registry where sev-snp is real. Reaching for this is the opt-in.

    Deliberately not exported from `attest`, and deliberately not the default:
    see this module's docstring for why an unvalidated verifier stays off.
    """
    from .attest import default_registry

    reg = default_registry()
    reg["sev-snp"] = SevSnpVerifier(ark_pem, ask_pem, vcek_pem,
                                    expected_tcb=expected_tcb)
    return reg

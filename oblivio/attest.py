"""Remote attestation: prove a model host cannot read what it is about to compute.

The storage client already refuses a node that fails a cryptographic check. This
applies the same discipline to the *compute* side. A host claiming to run inside
a trusted execution environment must prove it, and a proof that does not check
out means refuse — never "send anyway and hope".

**Five checks, mirroring the five the storage client runs.** They follow the
published SEV-SNP verification order, because that is the order in which a
failure is cheapest to detect:

===  ===================================  ==============================================
 #   Check                                Defeats
===  ===================================  ==============================================
 1   Format has a registered verifier     An unknown envelope being waved through
 2   Signature chains to a pinned root    A report signed by anyone at all
 3   ``report_data`` binds OUR nonce      A genuine report replayed from another session
 4   Measurement is on the allowlist      Real hardware running software you did not approve
 5   Policy: debug off, not expired       An enclave opened for inspection
===  ===================================  ==============================================

Check 3 is the one that is easy to leave out and fatal to omit. A perfectly
valid, correctly signed, unexpired attestation report proves something about
*some* machine at *some* time. Without binding it to the nonce this client just
generated, a host can replay a report captured from a genuinely confidential
machine and then process the request somewhere else entirely. The same lesson
the storage client learned: a valid proof of the wrong thing is not an answer.

**What this module does NOT do — stated plainly, because the gap matters.**

It ships **no hardware vendor root certificates** and **no parser for real
SEV-SNP, TDX or NVIDIA GPU attestation binaries**. Those formats are registered
here as *unimplemented*, which means requesting one **refuses**. It does not
mean the check is skipped:

    an unrecognised or unimplemented format must REFUSE, never pass silently.

That is the whole design decision. A verifier that returns "no opinion" for a
format it cannot parse is worse than absent, because callers read the absence of
an error as success. What is implemented and fully tested is the verification
*framework* and an Ed25519 reference format, which exercises every check with
real cryptography. Wiring a real vendor verifier means implementing `Verifier`
for that format and supplying its roots — the surrounding logic does not change.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

from . import dialects

from .crypto import NodeIdentity

NONCE_BYTES = 32
MAX_REPORT_BYTES = 1 * 1024 * 1024
DEFAULT_MAX_AGE = 300.0


class AttestationError(Exception):
    """Attestation could not be established. The caller must not transmit."""


class Unverified(AttestationError):
    """A specific check failed. The message names which one."""


# ---- the request binding ----------------------------------------------------


def new_nonce() -> bytes:
    """A fresh challenge. Never reuse one: reuse re-permits replay."""
    return secrets.token_bytes(NONCE_BYTES)


def expected_report_data(nonce: bytes) -> str:
    """What the host must place in `report_data` to prove freshness.

    SEV-SNP gives 64 bytes of caller-controlled space in the signed report for
    exactly this. The host cannot forge it without the hardware key, and cannot
    reuse an old report because it never contained this nonce.
    """
    return hashlib.sha256(b"oblivio-attest-v1\0" + nonce).hexdigest()


# ---- what a host presents ---------------------------------------------------


@dataclass(frozen=True)
class Attestation:
    """A parsed but *untrusted* report. Nothing here is believed until verified."""
    format: str
    measurement_hex: str
    report_data_hex: str
    signed_at: float
    debug_enabled: bool
    signature_hex: str
    signing_key_hex: str
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Attestation":
        try:
            return cls(
                format=str(d["format"]),
                measurement_hex=str(d["measurement_hex"]).lower(),
                report_data_hex=str(d["report_data_hex"]).lower(),
                signed_at=float(d["signed_at"]),
                debug_enabled=bool(d.get("debug_enabled", False)),
                signature_hex=str(d["signature_hex"]),
                signing_key_hex=str(d["signing_key_hex"]).lower(),
                raw=d,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise Unverified(f"malformed attestation document: {exc}") from exc

    def signed_bytes(self) -> bytes:
        """Canonical bytes covered by the signature.

        Explicit and ordered rather than a JSON dump of the whole document: a
        host that could add fields outside the signed range could vary anything
        the client later reads.
        """
        return (b"oblivio-attestation-v1\0"
                + self.format.encode("utf-8") + b"\0"
                + self.measurement_hex.encode("ascii") + b"\0"
                + self.report_data_hex.encode("ascii") + b"\0"
                + repr(self.signed_at).encode("ascii") + b"\0"
                + (b"debug" if self.debug_enabled else b"nodebug"))


@dataclass(frozen=True)
class Policy:
    """What the caller is willing to accept."""
    allowed_measurements: frozenset[str]
    trusted_roots: frozenset[str]
    max_age_seconds: float = DEFAULT_MAX_AGE
    require_debug_disabled: bool = True

    @classmethod
    def build(cls, measurements: list[str], roots: list[str],
              max_age_seconds: float = DEFAULT_MAX_AGE,
              require_debug_disabled: bool = True) -> "Policy":
        if not measurements:
            # An empty allowlist would accept any software on real hardware.
            # That is not a weaker policy, it is no policy.
            raise AttestationError(
                "at least one approved measurement is required; an empty "
                "allowlist accepts any code the host chooses to run")
        if not roots:
            raise AttestationError(
                "at least one trusted root key is required; without one, any "
                "self-signed report verifies")
        return cls(
            allowed_measurements=frozenset(m.lower() for m in measurements),
            trusted_roots=frozenset(r.lower() for r in roots),
            max_age_seconds=float(max_age_seconds),
            require_debug_disabled=require_debug_disabled)


# ---- format verifiers -------------------------------------------------------


class Verifier(Protocol):
    format: str

    def verify_signature(self, att: Attestation) -> bool:
        ...


class Ed25519Verifier:
    """Reference format. Real signatures, real refusals, no vendor hardware.

    Exists so every check in this module is exercised against genuine
    cryptography rather than a stub. It attests nothing about silicon — it
    proves the *framework* is correct, which is the part a vendor verifier
    would otherwise have to be trusted to get right.
    """

    format = "ed25519-ref"

    def verify_signature(self, att: Attestation) -> bool:
        try:
            pub = bytes.fromhex(att.signing_key_hex)
            sig = bytes.fromhex(att.signature_hex)
        except ValueError:
            return False
        return NodeIdentity.verify(pub, att.signed_bytes(), sig)


class UnimplementedVerifier:
    """A real format this project cannot yet check. Registered so it REFUSES.

    Leaving a format unregistered would make it fail check 1, which is also a
    refusal — but the message would say "unknown format" and invite someone to
    register it as a no-op. This says what is actually true: the format is real,
    the verifier is not written, and nothing may be sent to it.
    """

    def __init__(self, format: str, note: str = ""):
        self.format = format
        self.note = note

    def verify_signature(self, att: Attestation) -> bool:
        raise Unverified(
            f"{self.format}: no verifier is implemented in this build, so this "
            f"attestation cannot be checked. Refusing rather than assuming it "
            f"is valid. {self.note}".strip())


def default_registry() -> dict[str, Verifier]:
    """Formats this build knows about, and what it can actually do with each."""
    note = ("Implement Verifier for this format and supply the vendor root "
            "certificates to enable it.")
    reg: dict[str, Verifier] = {}
    for v in (
        Ed25519Verifier(),
        UnimplementedVerifier("sev-snp", note),
        UnimplementedVerifier("tdx", note),
        UnimplementedVerifier("nvidia-gpu", note),
    ):
        reg[v.format] = v
    return reg


# ---- the verification ------------------------------------------------------


@dataclass
class Result:
    """What passed. Returned only when every check passed."""
    format: str
    measurement_hex: str
    checks: list[str]
    age_seconds: float

    def summary(self) -> str:
        return (f"attested [{self.format}] measurement "
                f"{self.measurement_hex[:16]}… age {self.age_seconds:.1f}s "
                f"({len(self.checks)} checks passed)")


def verify_attestation(att: Attestation, *,
                       nonce: bytes,
                       policy: Policy,
                       registry: Optional[dict[str, Verifier]] = None,
                       now: Optional[float] = None) -> Result:
    """Run all five checks. Raise on the first failure; never return partial trust."""
    registry = registry if registry is not None else default_registry()
    now = time.time() if now is None else now
    checks: list[str] = []

    # 1 -- a format nobody can check is a format nobody may use.
    verifier = registry.get(att.format)
    if verifier is None:
        raise Unverified(
            f"unknown attestation format {att.format!r}; refusing rather than "
            f"accepting an envelope this build cannot read")
    checks.append("format-registered")

    # 2 -- signed by a key the caller decided to trust in advance. Checked
    # before the signature so an untrusted key never even gets verified.
    if att.signing_key_hex not in policy.trusted_roots:
        raise Unverified(
            "attestation signing key is not in the trusted roots; a report "
            "signed by an unknown key proves only that someone has a key")
    if not verifier.verify_signature(att):
        raise Unverified("attestation signature did not verify")
    checks.append("signature-chains-to-root")

    # 3 -- bound to THIS request. The check that stops a replayed-but-genuine
    # report from a machine that is not the one about to see the data.
    expected = expected_report_data(nonce)
    if not hmac.compare_digest(att.report_data_hex, expected):
        raise Unverified(
            "report_data does not bind this client's nonce — the report may be "
            "genuine and still describe a different machine or session")
    checks.append("bound-to-our-nonce")

    # 4 -- right hardware, approved software.
    if att.measurement_hex not in policy.allowed_measurements:
        raise Unverified(
            f"measurement {att.measurement_hex[:16]}… is not on the approved "
            f"list; the hardware may be genuine and the code still unreviewed")
    checks.append("measurement-approved")

    # 5 -- posture and freshness.
    if policy.require_debug_disabled and att.debug_enabled:
        raise Unverified(
            "enclave reports debug enabled; its memory is inspectable, which "
            "defeats the only property being bought here")
    age = now - att.signed_at
    if age > policy.max_age_seconds:
        raise Unverified(
            f"attestation is {age:.0f}s old, older than the "
            f"{policy.max_age_seconds:.0f}s limit")
    if age < -30.0:
        # Tolerate small clock skew; a report from the future by more than that
        # is either a broken clock or an attempt to buy unlimited freshness.
        raise Unverified(
            f"attestation is dated {-age:.0f}s in the future; refusing")
    checks.append("policy-and-freshness")

    return Result(format=att.format, measurement_hex=att.measurement_hex,
                  checks=checks, age_seconds=age)


# ---- fetching ---------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects, for the reason the storage client refuses them.

    A host being asked to prove it is trustworthy is by definition not yet
    trusted, and following its redirect lets it choose who answers.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AttestationError(f"attestation host redirected to {newurl!r}")


def fetch_attestation(url: str, nonce: bytes, timeout: float = 10.0) -> Attestation:
    """Ask a host for a report bound to `nonce`. Returns it UNVERIFIED."""
    body = json.dumps({"nonce_hex": nonce.hex()}).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"})
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(MAX_REPORT_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise AttestationError(f"attestation endpoint returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise AttestationError(f"attestation endpoint unreachable: {exc}") from exc
    if len(raw) > MAX_REPORT_BYTES:
        raise AttestationError("attestation document exceeds size limit")
    try:
        return Attestation.from_dict(json.loads(raw.decode("utf-8")))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise Unverified(f"attestation document is not valid JSON: {exc}") from exc


def attest_host(url: str, *, policy: Policy,
                registry: Optional[dict[str, Verifier]] = None,
                timeout: float = 10.0) -> Result:
    """Challenge a host and verify its answer. Raises unless every check passes.

    The nonce is generated here and never leaves this call, so a caller cannot
    accidentally verify against a nonce an attacker supplied.
    """
    nonce = new_nonce()
    att = fetch_attestation(url, nonce, timeout=timeout)
    return verify_attestation(att, nonce=nonce, policy=policy, registry=registry)


# ---- inference against a host that passed --------------------------------


def attested_complete(prompt: str, *,
                      api_base: str,
                      api_key: str,
                      model: str,
                      result: Result,
                      system: Optional[str] = None,
                      dialect: Optional[str] = None,
                      timeout: float = 120.0) -> dict:
    """Send a prompt to a host whose attestation already verified.

    Takes a `Result` rather than a boolean, so **the call is impossible to make
    without having verified first**. An ordering that matters cannot be left to
    a caller remembering it.

    Deliberately does not route through `cloud_gate`: that module's identity is
    the NOT PRIVATE labelling and the two acknowledgements that go with it, and
    stamping that notice on an attested response would be as wrong as omitting
    it from an unattested one. The duplicated POST is the price of keeping the
    gated path isolated and its guarantee legible.

    It shares a *dialect* with that path, though, and only a dialect. Wire
    format is not a guarantee: an enclave that speaks one vendor's JSON is no
    less attested than one speaking another's, and refusing to reach it would
    be an arbitrary limit dressed up as caution. What stays unshared is the
    labelling, which is the part that actually carries meaning.
    """
    if not isinstance(result, Result):
        raise AttestationError(
            "attested_complete requires a verified Result; attest the host first")

    spoken = dialects.get(dialect) if dialect else dialects.detect(api_base)[0]

    req = urllib.request.Request(
        spoken.url(api_base),
        data=spoken.body(model=model, prompt=prompt, system=system),
        headers=spoken.headers(api_key),
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read(MAX_REPORT_BYTES).decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # Never echo the request: it carries the bearer token.
        raise AttestationError(f"attested host returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise AttestationError(f"attested host unreachable: {exc}") from exc

    try:
        reply = spoken.reply(data)
    except dialects.DialectError as exc:
        raise AttestationError(str(exc)) from exc

    return {
        "reply": reply,
        "attested": True,
        "measurement_hex": result.measurement_hex,
        "checks": list(result.checks),
        "dialect": spoken.name,
    }

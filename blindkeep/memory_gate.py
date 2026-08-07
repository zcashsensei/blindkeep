"""One encrypted memory layer, any AI — with release decided by PROVEN trust.

The project already had three ways to talk to a model, each a separate module
with its own call shape and its own idea of what was safe to send. This is the
layer above them: memory lives encrypted in the keep, every backend is placed on
a **trust tier it must prove**, and a policy decides which memories may cross to
which tier. The model is swappable. The guarantee is not.

**The tiers, strongest first.**

===============  =========================================  ====================
Tier             What the operator can read                 How it is proven
===============  =========================================  ====================
``LOCAL``        nothing; there is no operator              endpoint is loopback
``SEALED``       a generic question, and it cannot read     BOTH of the below
                 even that
``ATTESTED``     nothing; hardware prevents it              `attest.py`, 5 checks
``DELEGATED``    a generic question containing no fact      a leak gate cleared it
                 about you
``PSEUDONYMOUS`` the question minus declared identities     a vault is attached
``OPEN``         everything sent                            nothing to prove
===============  =========================================  ====================

**Sensitivity is carried inside the ciphertext.** A record's class lives in its
encrypted label, which is authenticated as AAD — so the node holding the record
cannot read it, and cannot relabel `secret` as `public` to coax a client into
releasing it. The classification is as tamper-evident as the record.

**A claimed tier is worth nothing.** `prove()` is not optional and not
advisory: a backend that claims `ATTESTED` and fails verification is demoted to
`OPEN` and carries the reason with it. Nothing is silently downgraded — the
demotion is what the refusal message names, so a user who thought they were
talking to an enclave finds out at the moment it matters rather than never.

**What this does not do.** It decides what *leaves*. It cannot govern what a
model does with text after it arrives, it does not make `PSEUDONYMOUS` private
(see `vault_proxy.py` for that ceiling), and `LOCAL` is only as private as the
machine it runs on. Nothing here weakens the storage guarantee, which is
unchanged and unconditional: the node never holds plaintext on any tier.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Optional, Protocol

DEFAULT_RECALL = 6
INDEX_LIMIT = 500


class GateError(Exception):
    """The gate refused. Nothing was transmitted."""


class PolicyRefusal(GateError):
    """A memory was not cleared for the tier the backend actually proved."""


class Tier(IntEnum):
    """Ordered so a comparison means what it reads like: higher is stronger."""
    OPEN = 0
    PSEUDONYMOUS = 1
    DELEGATED = 2
    ATTESTED = 3
    SEALED = 4
    LOCAL = 5

    @property
    def label(self) -> str:
        return self.name.lower()


class Sensitivity(IntEnum):
    PUBLIC = 0
    PERSONAL = 1
    SENSITIVE = 2
    SECRET = 3

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, raw: str) -> "Sensitivity":
        try:
            return cls[raw.strip().upper()]
        except KeyError:
            # An unreadable class must be treated as the MOST sensitive, not
            # the least. A typo in a label should cost recall, never exposure.
            return cls.SECRET


# The default policy. Deliberately strict at the top: SECRET never leaves the
# machine, whatever a remote host can prove about itself, because "the operator
# cannot read it" is still a claim about someone else's hardware.
DEFAULT_POLICY: dict[Sensitivity, Tier] = {
    Sensitivity.PUBLIC: Tier.OPEN,
    Sensitivity.PERSONAL: Tier.PSEUDONYMOUS,
    Sensitivity.SENSITIVE: Tier.DELEGATED,
    Sensitivity.SECRET: Tier.LOCAL,
}


# ---- labels ----------------------------------------------------------------


def encode_label(sensitivity: Sensitivity, label: str = "") -> str:
    """`personal:chat`. Travels inside the AEAD, so the node cannot alter it."""
    return f"{sensitivity.label}:{label}"


def decode_label(raw: str) -> tuple[Sensitivity, str]:
    head, sep, rest = raw.partition(":")
    if not sep:
        # A record stored before classification existed, or by another tool.
        # Unclassified is not public.
        return Sensitivity.SECRET, raw
    return Sensitivity.parse(head), rest


# ---- backends --------------------------------------------------------------


@dataclass(frozen=True)
class Grant:
    """The outcome of asking a backend to prove its tier."""
    claimed: Tier
    granted: Tier
    reason: str
    detail: str = ""

    @property
    def demoted(self) -> bool:
        return self.granted < self.claimed

    def summary(self) -> str:
        if self.demoted:
            return (f"DEMOTED {self.claimed.label} -> {self.granted.label}: "
                    f"{self.reason}")
        return f"{self.granted.label}: {self.reason}"


class Backend(Protocol):
    """Any AI. Proves a tier, then completes a prompt."""
    name: str
    claimed_tier: Tier

    def prove(self) -> Grant:
        ...

    def complete(self, prompt: str, system: Optional[str] = None) -> str:
        ...


@dataclass
class SimpleBackend:
    """A backend built from callables, so this module imports no provider.

    Keeping the wiring out here is what lets the import guard stay strict: the
    gate never reaches a hosted provider, it is *handed* something that can.
    """
    name: str
    claimed_tier: Tier
    completer: Callable[[str, Optional[str]], str]
    prover: Optional[Callable[[], Grant]] = None
    vault: Any = None
    # Only used by the delegating tiers: the local model that writes the generic question and
    # re-applies the answer, and the gate that refuses to send a leaky abstraction.
    local: Optional[Callable[[str, Optional[str]], str]] = None
    gate: Any = None

    def prove(self) -> Grant:
        if self.prover is None:
            if self.claimed_tier is Tier.OPEN:
                return Grant(Tier.OPEN, Tier.OPEN, "open path, nothing claimed")
            return Grant(
                self.claimed_tier, Tier.OPEN,
                f"no prover supplied for a {self.claimed_tier.label} claim")
        try:
            return self.prover()
        except Exception as exc:
            return Grant(self.claimed_tier, Tier.OPEN,
                         f"proof failed: {type(exc).__name__}", str(exc))

    def complete(self, prompt: str, system: Optional[str] = None) -> str:
        return self.completer(prompt, system)


def loopback_prover(base_url: str) -> Callable[[], Grant]:
    """Prove LOCAL by showing the endpoint cannot leave the machine."""
    def prove() -> Grant:
        from .ollama_mem import NotLocalError, _assert_local
        try:
            _assert_local(base_url)
        except NotLocalError as exc:
            return Grant(Tier.LOCAL, Tier.OPEN, "endpoint is not loopback",
                         str(exc))
        return Grant(Tier.LOCAL, Tier.LOCAL, f"loopback endpoint {base_url}")
    return prove


def attestation_prover(url: str, policy) -> Callable[[], Grant]:
    """Prove ATTESTED by challenging the host and verifying all five checks."""
    def prove() -> Grant:
        from .attest import AttestationError, attest_host
        try:
            res = attest_host(url, policy=policy)
        except AttestationError as exc:
            return Grant(Tier.ATTESTED, Tier.OPEN, "attestation failed", str(exc))
        return Grant(Tier.ATTESTED, Tier.ATTESTED, res.summary())
    return prove


def sealed_prover(attest_url: str, policy: Any, gate: Any) -> Callable[[], Grant]:
    """Prove SEALED by proving BOTH — abstraction and attestation, independently.

    The two mechanisms fail differently, which is the entire reason to run them together. An
    abstraction fails when it carries something it should not; an enclave fails when its hardware
    or its attestation is broken — and the ecc::chip::mul soundness bug sat inside the most
    scrutinised circuit in the ecosystem for four years before anyone noticed. Composed, an
    attacker needs both to fail at once: a leaked identifier reaches a host that cannot read it,
    and a broken enclave receives a question about nobody.

    **Degrades to the strongest tier that still holds, never to OPEN by default.** Losing the
    enclave should not throw away a working abstraction, and losing the abstraction should not
    throw away a verified enclave. Silently keeping the SEALED label would be the real failure, so
    the demotion is named either way.
    """
    def prove() -> Grant:
        from .attest import AttestationError, attest_host

        has_gate = gate is not None and hasattr(gate, "check")
        try:
            res = attest_host(attest_url, policy=policy)
            attested, why = True, res.summary()
        except AttestationError as exc:
            attested, why = False, str(exc)
        except Exception as exc:                      # a broken prover is not a passing one
            attested, why = False, f"{type(exc).__name__}: {exc}"

        if attested and has_gate:
            return Grant(Tier.SEALED, Tier.SEALED,
                         f"abstraction gate + attestation ({why})")
        if attested:
            return Grant(Tier.SEALED, Tier.ATTESTED,
                         "attested, but no abstraction gate attached", why)
        if has_gate:
            return Grant(Tier.SEALED, Tier.DELEGATED,
                         "abstraction gate holds, but attestation failed", why)
        return Grant(Tier.SEALED, Tier.OPEN,
                     "neither attestation nor an abstraction gate", why)
    return prove


def delegation_prover(gate: Any) -> Callable[[], Grant]:
    """Prove DELEGATED by showing a leak gate is attached and will be consulted.

    Ranked below ATTESTED deliberately: attestation is enforced by hardware, whereas this rests
    on an abstraction having been complete. The gate makes that checkable, not certain.
    """
    def prove() -> Grant:
        if gate is None or not hasattr(gate, "check"):
            return Grant(Tier.DELEGATED, Tier.OPEN, "no leak gate attached")
        return Grant(Tier.DELEGATED, Tier.DELEGATED,
                     "leak gate attached; only a cleared abstraction is sent")
    return prove


def vault_prover(vault: Any) -> Callable[[], Grant]:
    """Prove PSEUDONYMOUS by showing a usable vault is actually attached."""
    def prove() -> Grant:
        if vault is None or not hasattr(vault, "anonymize"):
            return Grant(Tier.PSEUDONYMOUS, Tier.OPEN,
                         "no usable vault attached")
        return Grant(Tier.PSEUDONYMOUS, Tier.PSEUDONYMOUS,
                     "entity vault attached")
    return prove


# ---- release ---------------------------------------------------------------


@dataclass
class Release:
    """What may cross to this backend, and what was held back."""
    grant: Grant
    allowed: list[str] = field(default_factory=list)
    withheld: list[tuple[str, Sensitivity]] = field(default_factory=list)

    def context_block(self) -> str:
        if not self.allowed:
            return ""
        return ("\n\nPreviously stored memories about this user:\n"
                + "\n".join(f"- {t}" for t in self.allowed))

    def summary(self) -> str:
        held = ", ".join(sorted({s.label for _, s in self.withheld}))
        base = (f"{self.grant.granted.label}: released {len(self.allowed)}, "
                f"withheld {len(self.withheld)}")
        return f"{base} ({held})" if held else base


class MemoryGate:
    """Encrypted memory with a release policy, in front of any model."""

    def __init__(self, client, policy: Optional[dict[Sensitivity, Tier]] = None,
                 index_path: str = "data/client/gate_index.json"):
        self.client = client
        self.policy = dict(policy or DEFAULT_POLICY)
        self.index_path = index_path
        self._index: list[dict[str, Any]] = self._load_index()

    # ---- index ------------------------------------------------------------

    def _load_index(self) -> list[dict[str, Any]]:
        try:
            with open(self.index_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _save_index(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.index_path)) or ".",
                    exist_ok=True)
        tmp = self.index_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._index[-INDEX_LIMIT:], f, indent=2)
        os.replace(tmp, self.index_path)

    # ---- memory -----------------------------------------------------------

    def remember(self, text: str,
                 sensitivity: Sensitivity = Sensitivity.PERSONAL,
                 label: str = "chat") -> dict[str, Any]:
        """Encrypt and store, with the class sealed inside the ciphertext."""
        full = encode_label(sensitivity, label)
        result = self.client.put(text.encode("utf-8"), label=full)
        self._index.append({"record_id": result["record_id"],
                            "index": result["index"],
                            "sensitivity": sensitivity.label})
        self._save_index()
        return result

    def _recall(self, record_id: str) -> tuple[Sensitivity, str]:
        rec = self.client.get_by_id(record_id)
        # The class is taken from the DECRYPTED label, never from the index
        # file, which is plaintext on disk and therefore editable by anything
        # running as this user. The authenticated label is the authority.
        sensitivity, _ = decode_label(rec.get("label", "") or "")
        return sensitivity, rec["plaintext"].decode("utf-8")

    # ---- the decision -----------------------------------------------------

    def release_for(self, backend: Backend, n: int = DEFAULT_RECALL,
                    strict: bool = False) -> Release:
        """Prove the backend's tier, then release only what clears it.

        `strict=True` raises instead of returning a partial release, for callers
        that would rather fail than proceed with less context than they asked
        for.
        """
        grant = backend.prove()
        release = Release(grant=grant)

        for entry in self._index[-n:]:
            try:
                sensitivity, text = self._recall(entry["record_id"])
            except Exception:
                continue                 # a node may be down; degrade, not crash
            required = self.policy.get(sensitivity, Tier.LOCAL)
            if grant.granted < required:
                release.withheld.append((entry["record_id"], sensitivity))
                continue
            release.allowed.append(text)

        if grant.granted is Tier.PSEUDONYMOUS:
            vault = getattr(backend, "vault", None)
            if vault is None:
                raise PolicyRefusal(
                    "pseudonymous tier granted but no vault is reachable to "
                    "apply it")
            release.allowed = [vault.anonymize(t).text for t in release.allowed]

        if strict and release.withheld:
            raise PolicyRefusal(
                f"{len(release.withheld)} memories are not cleared for "
                f"{grant.granted.label}. {grant.summary()}")
        return release

    def chat(self, backend: Backend, message: str,
             system: Optional[str] = None,
             recall: int = DEFAULT_RECALL,
             remember: bool = True,
             sensitivity: Sensitivity = Sensitivity.PERSONAL) -> dict[str, Any]:
        """One exchange against any backend, with policy applied to context.

        The exchange itself is stored at `sensitivity`, so a conversation that
        was allowed out to an open model does not silently become recallable to
        a stricter policy later, nor the reverse.
        """
        release = self.release_for(backend, recall)
        base = system or (
            "You are a helpful assistant with persistent memory of this user.")
        prompt = message
        granted = release.grant.granted

        # ── the delegating tiers ────────────────────────────────────────────
        # The released context is private material too, so it is abstracted ALONGSIDE the message
        # rather than appended after it. Sending a generic question with the user's memories
        # stapled underneath would defeat the whole construction, and is the obvious way to get
        # this wrong.
        if granted in (Tier.DELEGATED, Tier.SEALED):
            from .delegate import delegate as _delegate

            local = getattr(backend, "local", None)
            if local is None:
                raise PolicyRefusal(
                    f"{granted.label} requires a local model to write the abstraction; "
                    f"none was attached")
            result = _delegate(message, local, backend.complete,
                               context=release.allowed)
            reply = result.reply
            if remember:
                self.remember(f"user: {message}", sensitivity=sensitivity)
                self.remember(f"assistant: {reply}", sensitivity=sensitivity)
            return {
                "reply": reply,
                "tier": granted.label,
                "grant": release.grant.summary(),
                "released": len(release.allowed),
                "withheld": len(release.withheld),
                "summary": release.summary(),
                "sent": result.sent,
                "attempts": result.attempts,
            }

        vault = getattr(backend, "vault", None)
        if granted is Tier.PSEUDONYMOUS and vault is not None:
            prompt = vault.anonymize(message).text
            base = vault.anonymize(base).text

        reply = backend.complete(prompt, base + release.context_block())

        if granted is Tier.PSEUDONYMOUS and vault is not None:
            reply = vault.restore(reply)

        if remember:
            self.remember(f"user: {message}", sensitivity=sensitivity)
            self.remember(f"assistant: {reply}", sensitivity=sensitivity)

        return {
            "reply": reply,
            "tier": release.grant.granted.label,
            "grant": release.grant.summary(),
            "released": len(release.allowed),
            "withheld": len(release.withheld),
            "summary": release.summary(),
        }

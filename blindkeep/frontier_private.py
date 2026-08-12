"""Maximum-effort privacy path from this machine to a frontier model.

This is the closest Blindkeep gets to "private frontier chat for everyone"
**without lying**.

What this path CAN do for a normal person today
-----------------------------------------------
* Keep **private facts off the wire**: a local model rewrites a generic
  question; ``LeakGate`` mechanically refuses to send if any identifying
  term or n-gram from your message/context survives.
* Re-specialise the answer **locally** against your real situation.
* Pull context from the encrypted keep without ever uploading raw memories.
* Emit a **receipt** of exactly what left, what is claimed, and what is not.
* Optionally attach a blind entitlement token (Privacy Pass shape).
* Optionally mark OHTTP independent-operator status when you supply one.

What this path CANNOT do (and will not claim)
---------------------------------------------
* Hide that a **paid API account** exists, if *your* API key is used.
  Commercial endpoints authenticate customers. That is identity.
* Give true **IP anonymity** if one party runs both OHTTP relay and gateway
  (including "I run both on localhost"). That is a rename of direct send.
* Stop the provider learning that *someone* asked *roughly this kind of*
  question — abstraction removes facts about you, not the fact of a request.
* Guarantee a local model abstracts perfectly; the **gate** is the guarantee,
  and when it cannot clear a question, **nothing is sent**.

So: this is historic in the sense of a **composed, gated, receipted stack
you can actually run**. It is not "anonymous ChatGPT for free with zero
metadata." The receipt is part of the product so those two sentences cannot
drift apart.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Sequence

from .delegate import LeakError, ask


class FrontierPrivateError(Exception):
    """The path refused. Nothing private left the machine, or setup was incomplete."""


# Residual risks that ALWAYS remain on a commercial frontier endpoint when
# the user supplies their own API key. Listed so a UI cannot paper over them.
DEFAULT_RESIDUAL = (
    "The provider learns that someone asked a question of roughly this shape.",
    "Your IP is visible to whoever terminates TLS unless independent OHTTP "
    "relay + gateway operators are used (not the same person).",
    "A compromised local machine can still read the question before abstraction.",
)

CONTENT_CLAIMS = (
    "Private facts from your message and keep context must not appear on the wire.",
    "LeakGate refuses the send if identifying terms or copied phrases survive.",
    "The specialised answer is produced only on this machine.",
)

ACCOUNT_DECOUPLED_CLAIMS = (
    "The client presents no provider API key — only a one-time blind token.",
    "Issuance and redemption of the token are unlinkable (Chaum / Privacy Pass shape).",
    "The frontier account credential lives only on the gateway.",
)


Completer = Callable[[str, Optional[str]], str]


@dataclass
class FrontierReceipt:
    """What happened — including what is NOT claimed."""

    reply: str
    sent: str                          # exact text that left toward the provider
    mode: str                          # "abstracted" | "general_direct"
    attempts: int
    claims: list[str] = field(default_factory=list)
    residual: list[str] = field(default_factory=list)
    route_reasons: list[str] = field(default_factory=list)
    ohttp_independent: Optional[bool] = None
    account_decoupled: bool = False
    notice: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "reply": self.reply,
            "sent": self.sent,
            "mode": self.mode,
            "attempts": self.attempts,
            "claims": list(self.claims),
            "residual": list(self.residual),
            "route_reasons": list(self.route_reasons),
            "ohttp_independent": self.ohttp_independent,
            "account_decoupled": self.account_decoupled,
            "notice": self.notice,
            "content_private": True,
            # True only when client used a gateway + blind token (no user API key).
            "identity_private": self.account_decoupled,
            # True only when caller asserts independent OHTTP operators.
            "metadata_private": self.ohttp_independent is True,
        }


def _require_frontier_opt_in(enable: bool, accept_residual: bool) -> None:
    missing = []
    if not enable:
        missing.append("enable_frontier")
    if not accept_residual:
        missing.append("accept_residual_risks")
    if missing:
        raise FrontierPrivateError(
            "Frontier-private path is disabled until you acknowledge it. Missing: "
            + ", ".join(missing)
            + ". This path protects CONTENT (private facts), not account identity "
            "or network metadata. See residual risks in the receipt.")


def frontier_chat(
    message: str,
    *,
    local: Completer,
    remote: Completer,
    context: Sequence[str] = (),
    enable_frontier: bool = False,
    accept_residual_risks: bool = False,
    max_specificity: Optional[int] = 24,
    ohttp_independent_operators: Optional[bool] = None,
    account_decoupled: bool = False,
    extra_residual: Sequence[str] = (),
) -> FrontierReceipt:
    """Run the maximum-effort path to a frontier model.

    ``local`` must be on this machine (Ollama or equivalent).
    ``remote`` may be a direct provider call **or** ``make_gateway_remote``
    (client holds no API key — historic account decoupling).
    """
    _require_frontier_opt_in(enable_frontier, accept_residual_risks)
    text = (message or "").strip()
    if not text:
        raise FrontierPrivateError("nothing to ask")

    try:
        result = ask(
            text,
            local=local,
            remote=remote,
            context=list(context),
            max_specificity=max_specificity,
        )
    except LeakError as exc:
        raise FrontierPrivateError(str(exc)) from exc

    mode = "general_direct" if result.attempts == 0 else "abstracted"
    residual = list(DEFAULT_RESIDUAL) + list(extra_residual)
    claims = list(CONTENT_CLAIMS)

    if account_decoupled:
        claims = claims + list(ACCOUNT_DECOUPLED_CLAIMS)
    else:
        residual = [
            "The client's API key is still an account identity for billing.",
            *residual,
        ]

    if ohttp_independent_operators is True:
        residual = [r for r in residual if "IP is visible" not in r]
        residual.append(
            "OHTTP independent operators claimed by the caller — this code "
            "cannot verify corporate separation.")
    elif ohttp_independent_operators is False:
        residual.append(
            "OHTTP operators are NOT independent — IP + content can recombine "
            "at one party. Network anonymity is void.")

    if account_decoupled and ohttp_independent_operators is True:
        notice = (
            "HISTORIC STACK (claimed): content gated + account decoupled via "
            "blind token + OHTTP IP split asserted independent. Verify operators."
        )
    elif account_decoupled:
        notice = (
            "CONTENT gated + ACCOUNT decoupled (no client API key; blind token). "
            "Metadata/IP not private without independent OHTTP operators."
        )
    else:
        notice = (
            "CONTENT gated: private facts should not be on the wire. "
            "Account identity still follows the client's API key."
        )
    if mode == "general_direct":
        notice += (
            " General path: exact text sent (no private overlap detected).")

    return FrontierReceipt(
        reply=result.reply,
        sent=result.sent,
        mode=mode,
        attempts=result.attempts,
        claims=claims,
        residual=residual,
        route_reasons=[],
        ohttp_independent=ohttp_independent_operators,
        account_decoupled=account_decoupled,
        notice=notice,
    )


def make_ollama_local(base: str = "http://127.0.0.1:11434",
                     model: str = "llama3.2") -> Completer:
    """Local completer via Ollama's chat API. Raises FrontierPrivateError if down."""
    from . import dialects
    import json
    import urllib.error
    import urllib.request

    d = dialects.OLLAMA

    def complete(prompt: str, system: Optional[str] = None) -> str:
        req = urllib.request.Request(
            d.url(base),
            data=d.body(model=model, prompt=prompt, system=system),
            headers=d.headers(""),
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=180) as resp:
                data = json.loads(resp.read(8 * 1024 * 1024).decode("utf-8"))
            return d.reply(data)
        except Exception as exc:
            raise FrontierPrivateError(
                f"local model unreachable at {base!r} ({type(exc).__name__}: {exc}). "
                f"Install Ollama and pull a model, e.g. `ollama pull {model}`. "
                f"Without a local model there is no abstraction and this path "
                f"refuses rather than sending private text.") from exc

    return complete


def make_cloud_remote(*,
                     api_base: str,
                     api_key: str,
                     model: str,
                     dialect: Optional[str] = None,
                     anon_token_header: Optional[dict] = None) -> Completer:
    """Hosted completer. Still uses the cloud gate's dual opt-in internally."""
    from .cloud_gate import cloud_complete

    def complete(prompt: str, system: Optional[str] = None) -> str:
        return cloud_complete(
            prompt,
            api_base=api_base,
            api_key=api_key,
            model=model,
            system=system,
            enable_cloud=True,
            accept_not_private=True,  # residual risks already accepted upstream
            dialect=dialect,
            headers=anon_token_header,
        )["reply"]

    return complete


def default_api_key() -> str:
    return (os.environ.get("BLINDKEEP_CLOUD_KEY")
            or os.environ.get("OPENAI_API_KEY")
            or os.environ.get("ANTHROPIC_API_KEY")
            or os.environ.get("XAI_API_KEY")
            or "")

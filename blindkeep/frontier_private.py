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
* Report an OHTTP IP split **only when the transport actually took one** —
  ``assess_network`` decides ``metadata_private`` from the socket that was
  used, the relay and gateway hosts, and only then your unverifiable claim of
  operator independence. Passing a flag cannot turn it on.

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

import ipaddress
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Sequence
from urllib.parse import urlparse

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


def _host_of(url: Optional[str]) -> str:
    """Lowercased hostname of a URL, or "" when there isn't one."""
    if not url:
        return ""
    parsed = urlparse(url if "//" in url else "//" + url)
    return (parsed.hostname or "").lower()


def _is_local(host: str) -> bool:
    """True only when the host is DEMONSTRABLY this machine or a private LAN.

    Literal addresses and the reserved local names only. No DNS resolution:
    a lookup here would be a network round trip inside the privacy path, and
    the answer could differ from the one the transport later gets. An
    unresolvable-by-inspection name reads as NOT local, so this can never be
    the reason a path is waved through -- it is only ever used to REFUSE.
    """
    if not host:
        return False
    if host == "localhost" or host.endswith((".localhost", ".local")):
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_private or addr.is_link_local


@dataclass
class NetworkPosture:
    """What the code KNOWS about the network path, apart from what is CLAIMED.

    ``metadata_private`` is never set from an assertion alone. Three facts have
    to hold first -- OHTTP was really the transport, the relay and the gateway
    are different hosts, and they are not both on this machine -- and only then
    does the caller's unverifiable independence claim count for anything.
    """

    transport: str
    metadata_private: bool
    reasons: list[str] = field(default_factory=list)


def assess_network(
    *,
    transport: str,
    gateway_url: Optional[str] = None,
    relay_url: Optional[str] = None,
    independent_operators: Optional[bool] = None,
) -> NetworkPosture:
    """Decide metadata privacy from transport facts, not from the caller's word.

    Ordered so the first FAILING fact is the reason given. Every branch except
    the last returns False: this function's job is to refuse.
    """
    gw_host, relay_host = _host_of(gateway_url), _host_of(relay_url)

    if transport != "ohttp":
        return NetworkPosture(transport, False, [
            "The client connected to the gateway directly, so the gateway "
            "sees the client IP. OHTTP was not the transport."])
    if not relay_host:
        return NetworkPosture(transport, False, [
            "OHTTP was requested but no relay URL was supplied, so there is "
            "no party to split IP from content."])
    if gw_host and relay_host == gw_host:
        return NetworkPosture(transport, False, [
            f"Relay and gateway are the same host ({relay_host}). One party "
            f"sees both the client IP and the decrypted request -- that is a "
            f"rename of a direct send, not an IP split."])
    if _is_local(relay_host) and _is_local(gw_host):
        return NetworkPosture(transport, False, [
            f"Relay ({relay_host}) and gateway ({gw_host}) are both on this "
            f"machine or LAN. Running both roles yourself voids the split."])
    if independent_operators is not True:
        return NetworkPosture(transport, False, [
            "OHTTP is in use and the hosts differ, but operator independence "
            "was not asserted. Two hosts can still be one operator."])

    return NetworkPosture(transport, True, [
        f"OHTTP transport confirmed: the client reached {relay_host}, which "
        f"forwarded opaque bytes to {gw_host or 'the gateway'}.",
        "Operator independence is ASSERTED BY YOU and cannot be verified from "
        "here. If one party runs both, this claim is void.",
    ])


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
    ohttp_independent: Optional[bool] = None   # what the caller CLAIMED
    account_decoupled: bool = False
    notice: str = ""
    transport: str = "direct"                  # what actually carried the request
    metadata_private: bool = False             # decided by assess_network, not by a flag
    metadata_reasons: list[str] = field(default_factory=list)

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
            "transport": self.transport,
            "metadata_reasons": list(self.metadata_reasons),
            "content_private": True,
            # True only when client used a gateway + blind token (no user API key).
            "identity_private": self.account_decoupled,
            # Decided by assess_network from the transport actually used. A
            # caller cannot turn this on by passing a flag -- that was the
            # defect this field exists to prevent.
            "metadata_private": self.metadata_private,
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
    transport: str = "direct",
    gateway_url: Optional[str] = None,
    relay_url: Optional[str] = None,
) -> FrontierReceipt:
    """Run the maximum-effort path to a frontier model.

    ``local`` must be on this machine (Ollama or equivalent).
    ``remote`` may be a direct provider call **or** ``make_gateway_remote``
    (client holds no API key — historic account decoupling).

    ``transport`` is the FACT of what carried the request — pass
    ``frontier_gateway.transport_of(remote)`` rather than restating it, so the
    receipt cannot disagree with the socket. ``ohttp_independent_operators``
    remains a caller assertion and, on its own, no longer buys anything.
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

    posture = assess_network(
        transport=transport,
        gateway_url=gateway_url,
        relay_url=relay_url,
        independent_operators=ohttp_independent_operators,
    )

    if posture.metadata_private:
        # Only a CONFIRMED OHTTP split may retire the IP warning. Retiring it
        # on the caller's say-so is what let a direct send read as private.
        residual = [r for r in residual if "IP is visible" not in r]
    residual.extend(posture.reasons)
    if ohttp_independent_operators is False:
        residual.append(
            "OHTTP operators are NOT independent — IP + content can recombine "
            "at one party. Network anonymity is void.")

    if account_decoupled and posture.metadata_private:
        notice = (
            "HISTORIC STACK: content gated + account decoupled via blind token "
            "+ OHTTP IP split confirmed in transport. Operator independence is "
            "your assertion — verify it."
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
        transport=posture.transport,
        metadata_private=posture.metadata_private,
        metadata_reasons=posture.reasons,
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

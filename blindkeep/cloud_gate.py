"""Opt-in path to a hosted model. NOT PRIVATE.

Every other route in this project is built so that data cannot leave the
machine. This one deliberately can, because sometimes a user genuinely wants a
frontier model and is entitled to make that trade knowingly.

The design principle is that the trade must be **explicit, per-call, and
impossible to enter by accident**:

* Two separate acknowledgements are required, and neither has a default that
  enables it. One says "use the cloud"; the other says "I understand this is
  not private". Requiring two is not bureaucracy — a single flag gets copied
  from a forum post without being read.
* Nothing in the default `put`, `get`, `chat` or replication paths imports this
  module. It is reachable only when a caller reaches for it.
* Stored memories are never attached to a cloud request by this module. It sends
  the prompt it is given and nothing else.

**On redaction.** `redact()` is provided because it is better than nothing, and
it is *not* a privacy control. Pattern matching cannot understand what is
sensitive in prose: it will catch an API key and miss "my daughter's school is
St Mary's". Treat anything sent through this path as disclosed.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Optional

from . import dialects

MAX_REPLY_BYTES = 8 * 1024 * 1024
NOT_PRIVATE_NOTICE = (
    "NOT PRIVATE: this request leaves your machine and is processed by a "
    "third party, which may retain it.")


class CloudGateError(Exception):
    """The cloud path was not explicitly and knowingly enabled."""


def require_opt_in(enable_cloud: bool, accept_not_private: bool) -> None:
    """Refuse unless both acknowledgements are present."""
    missing = []
    if not enable_cloud:
        missing.append("enable_cloud")
    if not accept_not_private:
        missing.append("accept_not_private")
    if missing:
        raise CloudGateError(
            "Cloud path is disabled. Missing: " + ", ".join(missing) + ". "
            + NOT_PRIVATE_NOTICE)


# Conservative, high-confidence patterns only. A loose pattern that mangles
# ordinary prose teaches people to switch redaction off, which is worse than
# not offering it.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("[REDACTED_KEY]", re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}")),
    ("[REDACTED_KEY]", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}")),
    ("[REDACTED_KEY]", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("[REDACTED_KEY]", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("[REDACTED_EMAIL]", re.compile(r"\b[\w.%+\-]+@[\w.\-]+\.[A-Za-z]{2,}\b")),
    ("[REDACTED_ADDRESS]", re.compile(r"\b0x[a-fA-F0-9]{40}\b")),
    ("[REDACTED_PATH]", re.compile(r"[A-Za-z]:\\Users\\[^\s\"']+")),
    ("[REDACTED_PATH]", re.compile(r"/(?:home|Users)/[^\s\"']+")),
    ("[REDACTED_PRIVATE_KEY]",
     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
]


def _scrub(text: str) -> str:
    """Strip anything credential-shaped from a provider's error text.

    Unlike `redact`, this is not a privacy control and makes no claim to
    completeness -- it guards one narrow case: a provider that quotes part of
    the request back in its error message. Best-effort is the right bar here,
    because the alternative being weighed is showing the message unexamined.
    """
    return re.sub(r"(sk-[A-Za-z0-9_-]{8,}|Bearer\s+\S+)", "***", text)


def redact(text: str) -> tuple[str, list[str]]:
    """Best-effort removal of obvious secrets. NOT a privacy guarantee.

    Returns the redacted text and a list of what was replaced, so a caller can
    show the user what was caught — and, more usefully, prompt them to consider
    what was not.
    """
    found: list[str] = []
    out = text
    for label, pattern in _PATTERNS:
        out, n = pattern.subn(label, out)
        if n:
            found.append(f"{label} x{n}")
    return out, found


def cloud_complete(prompt: str, *,
                   api_base: str,
                   api_key: str,
                   model: str,
                   enable_cloud: bool = False,
                   accept_not_private: bool = False,
                   system: Optional[str] = None,
                   apply_redaction: bool = False,
                   headers: Optional[dict] = None,
                   dialect: Optional[str] = None,
                   pad_to_buckets: Optional[tuple] = None,
                   timeout: float = 120.0) -> dict:
    """Send one prompt to a hosted model, in whatever API it speaks. NOT PRIVATE.

    Returns the reply together with what was actually transmitted, so a caller
    can show the user the exact text that left the machine rather than asking
    them to trust that redaction worked.

    `dialect` selects the wire format (see `dialects.py`); omitted, it is
    inferred from `api_base` and the guess is reported in the result. The
    dialect changes only how bytes are framed -- **every dialect is equally
    NOT PRIVATE**, because what makes this path disclosing is that an operator
    receives the prompt at all, not which JSON shape carried it.
    """
    require_opt_in(enable_cloud, accept_not_private)
    if not api_key:
        raise CloudGateError("an api_key is required for the cloud path")
    if not api_base:
        raise CloudGateError("an api_base is required for the cloud path")

    sent = prompt
    redacted: list[str] = []
    if apply_redaction:
        sent, redacted = redact(prompt)

    if dialect:
        spoken, why = dialects.get(dialect), f"dialect {dialect!r} was requested"
    else:
        spoken, why = dialects.detect(api_base)

    # Extra headers exist so an anonymous entitlement can actually be presented. A token that
    # cannot reach the provider protects nobody, and carrying it in the message body would put it
    # in the one place the model reads.
    hdrs = spoken.headers(api_key)
    hdrs.update(headers or {})

    body = spoken.body(model=model, prompt=sent, system=system)

    # Length bucketing lives in a HEADER, never in the prompt: padding the body
    # would put filler in the one place the model reads (and strict APIs reject
    # unknown JSON fields). The bound covers body + this header; the remaining
    # headers add a near-constant offset the bucket absorbs in practice.
    pad_report: Optional[dict] = None
    if pad_to_buckets:
        from .dp import pad_to_bucket
        frame = len("X-Blindkeep-Pad: \r\n")
        pad, pad_report = pad_to_bucket(len(body) + frame, pad_to_buckets)
        if pad_report.get("bucketed"):
            hdrs["X-Blindkeep-Pad"] = "x" * pad

    req = urllib.request.Request(
        spoken.url(api_base),
        data=body,
        headers=hdrs,
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read(MAX_REPLY_BYTES).decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # The REQUEST carries the key and must never be echoed. The RESPONSE
        # does not -- it carries the provider's explanation, which is the only
        # thing that can tell a user what to actually do. Suppressing it bought
        # no safety and cost the diagnosis: a real 400 here said "your credit
        # balance is too low", and the caller saw only "HTTP 400" and went
        # looking for a bug in the request.
        #
        # Scrubbed anyway, because "the response cannot contain a credential"
        # is an assumption about someone else's server, and a cheap belt is
        # worth more than a confident argument.
        detail = ""
        try:
            body = exc.read(MAX_REPLY_BYTES).decode("utf-8", "replace")
            msg = json.loads(body).get("error", {}).get("message", "")
            if msg:
                detail = f": {_scrub(msg)[:300]}"
        except Exception:
            pass

        # A 404 is nearly always the wrong dialect rather than a dead endpoint --
        # each provider routes completions at a different path, so the request
        # never reaches a handler. "HTTP 404" sends the user to check their URL,
        # which is fine and not the fault.
        hint = ""
        if exc.code == 404:
            hint = (f" (no route at {spoken.path} -- if this endpoint speaks a "
                    f"different API, pass another dialect: "
                    f"{', '.join(sorted(dialects.DIALECTS))})")
        raise CloudGateError(
            f"provider returned HTTP {exc.code} for the {spoken.name} "
            f"dialect{detail}{hint}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise CloudGateError(f"provider unreachable: {exc}") from exc

    try:
        reply = spoken.reply(data)
    except dialects.DialectError as exc:
        raise CloudGateError(str(exc)) from exc

    return {
        "reply": reply,
        "sent": sent,
        "redacted": redacted,
        "private": False,
        "notice": NOT_PRIVATE_NOTICE,
        "dialect": spoken.name,
        "dialect_reason": why,
        # Wire facts for a receipt: this path reads ONE HTTP body — there were
        # no per-token packets to observe — and reports what padding really ran.
        "response_streaming": False,
        "length_channel": pad_report,
    }

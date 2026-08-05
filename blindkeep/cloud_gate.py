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
                   timeout: float = 120.0) -> dict:
    """Send one prompt to an OpenAI-compatible endpoint. NOT PRIVATE.

    Returns the reply together with what was actually transmitted, so a caller
    can show the user the exact text that left the machine rather than asking
    them to trust that redaction worked.
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

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": sent})

    req = urllib.request.Request(
        api_base.rstrip("/") + "/v1/chat/completions",
        data=json.dumps({"model": model, "messages": messages}).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {api_key}"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read(MAX_REPLY_BYTES).decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # Never echo the request: it carries the bearer token.
        raise CloudGateError(
            f"provider returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise CloudGateError(f"provider unreachable: {exc}") from exc

    try:
        reply = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise CloudGateError(
            f"unexpected provider response shape: {sorted(data)}") from exc

    return {
        "reply": reply,
        "sent": sent,
        "redacted": redacted,
        "private": False,
        "notice": NOT_PRIVATE_NOTICE,
    }

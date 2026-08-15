"""How to *speak* to a model, kept separate from what is allowed to reach one.

`memory_gate` promises one encrypted memory layer and any AI. That promise was
false at the wire: every outbound call in this project hardcoded a single
vendor's HTTP shape -- `/v1/chat/completions`, a bearer token, and a reply dug
out of `choices[0].message.content`. Any model that did not imitate that one
company's API simply could not be reached, and the CLI's own help told users
their endpoint had to imitate it. A privacy layer that works with one vendor is
not a privacy layer; it is that vendor's client with extra steps.

A dialect is **transport and nothing else**: which URL, which auth header, which
JSON shape in, which field out. It is deliberately incapable of deciding what
may be sent. That separation is the point, and it is worth stating plainly
because the tempting version of this file is the wrong one:

    a dialect chooses BYTES ON THE WIRE
    a tier     chooses WHAT IS ALLOWED TO BECOME THOSE BYTES

If a dialect could influence a tier, then adding support for a new provider
could quietly weaken a guarantee, and "we support more models" would be a
privacy regression wearing a feature's clothes. So dialects take an
already-approved string and post it. They never see a record, a sensitivity
class, or a `Grant`, and no dialect can promote or demote anything.

**This does not make a hosted model private.** It makes hosted models
*interchangeable*, which matters for a different reason: privacy that only
works if you choose one specific company is a hostage, not a property. The
tiers in `memory_gate` are what decide disclosure, and they read the same on
every dialect here -- a frontier API is `OPEN` whether it is one vendor's or
another's, and open weights on loopback are `LOCAL` whether the server is
llama.cpp, vLLM, Ollama or LM Studio. **The guarantee must not depend on whose
model you picked**, which is exactly why this file is boring on purpose.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

# Anthropic's API rejects a request without it, and every other dialect ignores an
# upper bound it did not ask for. A default belongs here rather than in each caller,
# so that "which providers need this field" stays a fact about dialects.
DEFAULT_MAX_TOKENS = 4096

# Pinned rather than tracked: this is a wire-compatibility date, not a model version,
# and it changes only when the request format itself does.
ANTHROPIC_VERSION = "2023-06-01"


class DialectError(ValueError):
    """The dialect could not build a request, or could not read a reply."""


@dataclass(frozen=True)
class Dialect:
    """One provider wire format. Frozen: a transport must not carry state."""

    name: str
    path: str
    auth_header: Optional[str]          # None means the endpoint takes no key
    auth_prefix: str
    build_body: Callable[..., dict]
    extract: Callable[[Any], str]
    extra_headers: dict = field(default_factory=dict)
    # Stated so a caller can warn rather than leak: a local server needs no key,
    # and silently sending one to a loopback process is a small betrayal.
    wants_key: bool = True

    def url(self, api_base: str) -> str:
        return api_base.rstrip("/") + self.path

    def headers(self, api_key: str) -> dict:
        h = {"Content-Type": "application/json"}
        h.update(self.extra_headers)
        if self.auth_header and api_key:
            h[self.auth_header] = f"{self.auth_prefix}{api_key}"
        return h

    def body(self, *, model: str, prompt: str, system: Optional[str],
             max_tokens: int = DEFAULT_MAX_TOKENS) -> bytes:
        payload = self.build_body(model=model, prompt=prompt, system=system,
                                  max_tokens=max_tokens)
        return json.dumps(payload).encode("utf-8")

    def reply(self, data: Any) -> str:
        try:
            text = self.extract(data)
        except (KeyError, IndexError, TypeError) as exc:
            shape = sorted(data) if isinstance(data, dict) else type(data).__name__
            raise DialectError(
                f"reply did not match the {self.name} format (got {shape}); "
                f"if this endpoint speaks a different API, pass the right --dialect"
            ) from exc
        if not isinstance(text, str):
            raise DialectError(f"{self.name} reply was {type(text).__name__}, not text")
        return text


# ---- the shapes ----------------------------------------------------------


def _openai_body(*, model, prompt, system, max_tokens):
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    return {"model": model, "messages": messages}


def _anthropic_body(*, model, prompt, system, max_tokens):
    # `system` is a top-level field here, not a message with a role. Sending it as a
    # message is the single most common way this call is got wrong.
    payload = {"model": model,
               "max_tokens": max_tokens,
               "messages": [{"role": "user", "content": prompt}]}
    if system:
        payload["system"] = system
    return payload


def _ollama_body(*, model, prompt, system, max_tokens):
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    return {"model": model, "messages": messages, "stream": False}


def _anthropic_extract(data):
    # Content is a list of typed blocks; the first text block is the reply. Skipping
    # non-text blocks rather than indexing [0] keeps this working when a model returns
    # a thinking or tool block first.
    for block in data["content"]:
        if block.get("type") == "text":
            return block["text"]
    raise KeyError("no text block in content")


OPENAI = Dialect(
    name="openai",
    path="/v1/chat/completions",
    auth_header="Authorization",
    auth_prefix="Bearer ",
    build_body=_openai_body,
    extract=lambda d: d["choices"][0]["message"]["content"],
)

ANTHROPIC = Dialect(
    name="anthropic",
    path="/v1/messages",
    auth_header="x-api-key",
    auth_prefix="",
    build_body=_anthropic_body,
    extract=_anthropic_extract,
    extra_headers={"anthropic-version": ANTHROPIC_VERSION},
)

OLLAMA = Dialect(
    name="ollama",
    path="/api/chat",
    auth_header=None,
    auth_prefix="",
    build_body=_ollama_body,
    extract=lambda d: d["message"]["content"],
    wants_key=False,
)

DIALECTS = {d.name: d for d in (OPENAI, ANTHROPIC, OLLAMA)}

# Hosts whose API is not the OpenAI shape. Everything absent from this table is
# assumed OpenAI-compatible, which is a defensible default precisely because so
# many projects -- open-weight servers especially -- deliberately imitate it.
_BY_HOST = {
    "api.anthropic.com": ANTHROPIC,
}


def get(name: str) -> Dialect:
    try:
        return DIALECTS[name.strip().lower()]
    except KeyError:
        raise DialectError(
            f"unknown dialect {name!r}; known: {', '.join(sorted(DIALECTS))}") from None


def detect(api_base: str) -> tuple[Dialect, str]:
    """Guess a dialect from the endpoint, and say so out loud.

    Returns the reason alongside the dialect because a silent guess is how a
    caller ends up believing it reached a model it never reached. A wrong guess
    here is harmless -- the request fails and `reply()` names the fix -- but a
    guess the user never saw is not.
    """
    host = (urlsplit(api_base).hostname or "").lower()
    if host in _BY_HOST:
        d = _BY_HOST[host]
        return d, f"{host} speaks the {d.name} API"
    if host in ("localhost", "127.0.0.1", "::1") and api_base.rstrip("/").endswith("11434"):
        return OLLAMA, "port 11434 is Ollama's native API"
    return OPENAI, (
        f"assuming the OpenAI-compatible format for {host or api_base!r}; "
        f"pass an explicit dialect if that is wrong")

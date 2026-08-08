"""Any model, closed or open weights — and the same guarantee on each.

Two things are being tested, and the second matters more than the first:

  1. each dialect frames a request the way its provider actually expects
  2. NOTHING a dialect does can change what is allowed to be sent

The second is the reason this module exists. A privacy layer that only holds
when you pick one company is not a property, it is a dependency.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blindkeep import dialects
from blindkeep.dialects import ANTHROPIC, OLLAMA, OPENAI, DialectError

PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print(f"  FAIL: {name}")


def test_openai_shape():
    body = json.loads(OPENAI.body(model="m", prompt="hi", system="sys"))
    check("openai path", OPENAI.url("https://x/") == "https://x/v1/chat/completions")
    check("openai bearer", OPENAI.headers("k")["Authorization"] == "Bearer k")
    check("openai system is a message", body["messages"][0]["role"] == "system")
    check("openai user last", body["messages"][-1]["content"] == "hi")
    check("openai extract",
          OPENAI.reply({"choices": [{"message": {"content": "out"}}]}) == "out")


def test_anthropic_shape():
    body = json.loads(ANTHROPIC.body(model="m", prompt="hi", system="sys"))
    check("anthropic path", ANTHROPIC.url("https://x") == "https://x/v1/messages")
    h = ANTHROPIC.headers("k")
    check("anthropic uses x-api-key", h.get("x-api-key") == "k")
    check("anthropic sends no bearer", "Authorization" not in h)
    check("anthropic version header", "anthropic-version" in h)
    # The most common way this call is got wrong: system as a message.
    check("anthropic system is top-level", body.get("system") == "sys")
    check("anthropic no system message",
          all(m["role"] != "system" for m in body["messages"]))
    # Rejected outright without it, so the dialect must supply one.
    check("anthropic sends max_tokens", isinstance(body.get("max_tokens"), int))


def test_anthropic_skips_non_text_blocks():
    """A thinking or tool block arriving first must not be read as the reply."""
    data = {"content": [{"type": "thinking", "thinking": "..."},
                        {"type": "text", "text": "the answer"}]}
    check("anthropic finds the text block", ANTHROPIC.reply(data) == "the answer")


def test_ollama_needs_no_key():
    check("ollama path", OLLAMA.url("http://127.0.0.1:11434") ==
          "http://127.0.0.1:11434/api/chat")
    check("ollama sends no auth header", OLLAMA.headers("k") == {"Content-Type": "application/json"})
    check("ollama declares it wants no key", OLLAMA.wants_key is False)
    check("ollama extract", OLLAMA.reply({"message": {"content": "out"}}) == "out")


def test_detection_is_never_silent():
    for base in ("https://api.anthropic.com", "https://api.x.ai",
                 "http://127.0.0.1:8000", "http://127.0.0.1:11434"):
        d, why = dialects.detect(base)
        check(f"detect({base}) states a reason", isinstance(why, str) and why)
    check("anthropic host detected", dialects.detect("https://api.anthropic.com")[0] is ANTHROPIC)
    check("ollama port detected", dialects.detect("http://127.0.0.1:11434")[0] is OLLAMA)
    # An unknown host is assumed OpenAI-compatible, and says so rather than
    # pretending to know.
    d, why = dialects.detect("https://unknown.example")
    check("unknown host falls back to openai", d is OPENAI)
    check("fallback admits it is assuming", "assum" in why.lower())


def test_wrong_dialect_names_the_fix():
    """A mismatched reply must not read as an empty answer."""
    try:
        OPENAI.reply({"content": [{"type": "text", "text": "hi"}]})
        check("wrong dialect raises", False)
    except DialectError as exc:
        check("wrong dialect raises", True)
        check("error names the remedy", "dialect" in str(exc).lower())


def test_unknown_dialect_lists_known_ones():
    try:
        dialects.get("nope")
        check("unknown dialect raises", False)
    except DialectError as exc:
        check("unknown dialect raises", True)
        check("lists what is available", "openai" in str(exc))


def test_every_dialect_round_trips():
    """No dialect may be declared without being usable end to end."""
    for name, d in dialects.DIALECTS.items():
        body = json.loads(d.body(model="m", prompt="p", system=None))
        check(f"{name} builds a dict", isinstance(body, dict))
        check(f"{name} carries the model", body.get("model") == "m")
        check(f"{name} url is absolute", d.url("https://h").startswith("https://h/"))


def test_dialect_cannot_touch_a_guarantee():
    """The load-bearing test: transport is not policy.

    A dialect is handed an already-approved string. If it could see a
    sensitivity class or a tier, then adding a provider could weaken a promise
    — so the type must have no way to express one.
    """
    fields = set(OPENAI.__dataclass_fields__)
    forbidden = {"tier", "sensitivity", "grant", "policy", "private", "trust"}
    check("dialect has no policy fields", not (fields & forbidden))
    # Frozen: a transport that accumulates state can drift between calls.
    try:
        OPENAI.name = "mutated"
        check("dialect is immutable", False)
    except Exception:
        check("dialect is immutable", True)


def test_no_dialect_is_privileged():
    """Every dialect is equally untrusted; none is a shortcut to a better tier."""
    check("all dialects are the same type",
          all(isinstance(d, dialects.Dialect) for d in dialects.DIALECTS.values()))
    # If a dialect ever gained a bespoke method, it could be relied on
    # asymmetrically by a caller — which is how a general path quietly becomes
    # a special-cased one.
    base = set(dir(OPENAI))
    for name, d in dialects.DIALECTS.items():
        check(f"{name} exposes no bespoke surface", set(dir(d)) == base)


for fn in list(globals().values()):
    if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
        fn()

print(f"{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)

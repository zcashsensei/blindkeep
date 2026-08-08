"""Reversible pseudonymisation for the opt-in cloud path. RISK REDUCTION, NOT A GUARANTEE.

`cloud_gate.py` sends a prompt to a hosted model and tells the user plainly that
it is not private. This module narrows *what* is disclosed on that path: values
the user cares about are swapped for stable placeholders before the request
leaves, and restored in the reply once it comes back. The provider sees the
shape of the question and not the identities in it.

    "Sarah at Acme owes 4,000"
      -> "<PERSON_0_a1b2c3> at <ORG_0_a1b2c3> owes 4,000"
      -> model reasons about the relationship
      -> "<PERSON_0_a1b2c3> should be invoiced" -> "Sarah should be invoiced"

**Where this sits in the honest hierarchy.** Local model (`ollama_mem.py`) is
private because nothing leaves. Attested confidential inference is private
because the operator is cryptographically prevented from reading. This module is
neither: it is a *smaller disclosure* to a provider who is still trusted not to
correlate. It belongs between those two and must never be described as equal to
them.

**What defeats it, stated up front:**

* **Quasi-identifiers.** `<PERSON_0>` who is a paediatric cardiologist in Truro
  with a Basenji is one person, and no substitution changes that. Pattern
  matching removes names, not identifiability.
* **Undetected entities.** Detection here is deterministic — declared values and
  conservative patterns — because this project has one dependency and a regex
  cannot do named-entity recognition on prose. Anything neither declared nor
  matched is transmitted verbatim. `declare()` is the load-bearing part, not the
  patterns.
* **Reversibility.** The mapping exists, so this is pseudonymisation and not
  anonymisation: under GDPR the data stays personal data. Masking would be
  irreversible and out of scope; it would also make the reply useless.
* **Stable placeholders are a persistent pseudonym.** With `stable=True` the
  provider can link every session that mentions `<PERSON_0>` even without
  knowing who that is. `stable=False` breaks the linkage and costs the model its
  cross-session grounding. That trade is the caller's to make.

**What it does guarantee**, because these are enforced rather than intended:

1. A declared value that survives substitution raises instead of being sent
   (`LeakError`) — the same refuse-rather-than-return discipline the storage
   client uses.
2. Placeholders carry a per-vault random tag, so text arriving from outside
   cannot forge one and have it expand into a real value on the way back.
3. No stored memory is attached to a request by this module. It pseudonymises
   the prompt it is handed and nothing else — the caller assembles context
   deliberately, exactly as with `cloud_gate`.
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass
from typing import Any, Iterable, Optional

from .cloud_gate import cloud_complete

MIN_DECLARED_LENGTH = 3
TAG_BYTES = 3


class VaultError(Exception):
    """The vault was asked to do something unsafe or impossible."""


class LeakError(VaultError):
    """A value the vault knows about survived into text about to be sent."""


# Conservative, high-confidence patterns only, for the same reason
# `cloud_gate.redact` keeps its list short: a loose pattern that mangles ordinary
# prose teaches people to switch the protection off, which is worse than not
# offering it. Order matters only for readability — overlaps are resolved by
# span length, not by list position.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("KEY", re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}")),
    ("KEY", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}")),
    ("KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("KEY", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("PRIVATE_KEY", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    ("EMAIL", re.compile(r"\b[\w.%+\-]+@[\w.\-]+\.[A-Za-z]{2,}\b")),
    ("CRYPTO_ADDRESS", re.compile(r"\b0x[a-fA-F0-9]{40}\b")),
    ("PATH", re.compile(r"[A-Za-z]:\\Users\\[^\s\"']+")),
    ("PATH", re.compile(r"/(?:home|Users)/[^\s\"']+")),
    ("IP", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    # Deliberately narrow: a general phone-number regex eats version strings,
    # order totals and dates. This wants an explicit international prefix.
    ("PHONE", re.compile(r"\+\d[\d\s\-().]{7,17}\d")),
]


@dataclass(frozen=True)
class Mapping:
    placeholder: str
    value: str
    kind: str


@dataclass
class Anonymized:
    """The result of a substitution, including what was *not* protected."""
    text: str
    used: list[Mapping]
    unprotected_hint: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "used": [{"placeholder": m.placeholder, "kind": m.kind} for m in self.used],
            "unprotected_hint": self.unprotected_hint,
        }


class EntityVault:
    """A reversible value <-> placeholder map, storable as a Blindkeep record.

    Every other implementation of this pattern keeps the mapping in a session
    dict or a cache. Here it can be persisted through the client, which means the
    most sensitive artefact in the system — the table that re-identifies
    everything — inherits encryption, a Merkle commitment and key recovery
    instead of living in process memory.
    """

    def __init__(self, *, stable: bool = True, tag: Optional[str] = None):
        self.stable = stable
        # A per-vault tag makes placeholders unguessable from outside. Without it
        # a memory containing the literal text "<PERSON_0>" would expand into a
        # real name on the way back — text the user never wrote, attributed to a
        # person the model never saw.
        self.tag = tag or secrets.token_hex(TAG_BYTES)
        self._by_value: dict[str, Mapping] = {}
        self._by_placeholder: dict[str, Mapping] = {}
        self._counters: dict[str, int] = {}

    # ---- building the map ----------------------------------------------------

    def declare(self, value: str, kind: str = "PERSON") -> str:
        """Register a value as sensitive and return its placeholder.

        This is the part that actually works on prose. Patterns find structured
        secrets; only the user knows that "Marta" is their daughter and that
        "the Ridgeway file" is a live acquisition.
        """
        value = value.strip()
        if not value:
            raise VaultError("cannot declare an empty value")
        if len(value) < MIN_DECLARED_LENGTH:
            # "Jo" would rewrite the middle of "John" under a boundary-less
            # match and half the dictionary under a boundary-ed one. Neither
            # failure is worth the two characters.
            raise VaultError(
                f"{value!r} is shorter than {MIN_DECLARED_LENGTH} characters; "
                "too collision-prone to substitute safely")
        kind = _normalise_kind(kind)
        existing = self._by_value.get(value.casefold())
        if existing:
            return existing.placeholder
        n = self._counters.get(kind, 0)
        self._counters[kind] = n + 1
        placeholder = f"<{kind}_{n}_{self.tag}>"
        m = Mapping(placeholder=placeholder, value=value, kind=kind)
        self._by_value[value.casefold()] = m
        self._by_placeholder[placeholder] = m
        return placeholder

    def declare_many(self, values: Iterable[str], kind: str = "PERSON") -> list[str]:
        return [self.declare(v, kind=kind) for v in values]

    def learn_from(self, text: str) -> list[Mapping]:
        """Declare every pattern-detectable value found in `text`.

        Useful for priming a vault from memories already stored: the structured
        secrets in a user's own history are exactly the ones that should never
        reach a provider.
        """
        learned = []
        for kind, span in _pattern_spans(text):
            value = text[span[0]:span[1]]
            if value.casefold() in self._by_value:
                continue
            self.declare(value, kind=kind)
            learned.append(self._by_value[value.casefold()])
        return learned

    # ---- the sandwich --------------------------------------------------------

    def anonymize(self, text: str) -> Anonymized:
        """Replace declared and detected values with placeholders.

        Raises `LeakError` rather than returning text that still contains a known
        value. A partial substitution is more dangerous than none: it reads as
        protected and is not.
        """
        if self._foreign_placeholder(text):
            raise VaultError(
                "the input already contains text shaped like this vault's "
                "placeholders; refusing rather than round-tripping it into a "
                "real value")

        spans = _resolve_overlaps(list(self._declared_spans(text))
                                  + list(_pattern_spans(text)))

        used: list[Mapping] = []
        out = text
        # Right to left so earlier offsets stay valid as the string changes.
        for kind, (start, end) in sorted(spans, key=lambda s: s[1][0], reverse=True):
            value = text[start:end]
            known = self._by_value.get(value.casefold())
            placeholder = known.placeholder if known else self.declare(value, kind=kind)
            m = self._by_placeholder[placeholder]
            if m not in used:
                used.append(m)
            out = out[:start] + placeholder + out[end:]

        leaked = self._leaks(out)
        if leaked:
            raise LeakError(
                "these declared values survived substitution and would have "
                f"been transmitted: {sorted(leaked)}")

        return Anonymized(text=out, used=used,
                          unprotected_hint=_unprotected_hint(out))

    def restore(self, text: str) -> str:
        """Put the real values back into a reply.

        Tolerant by necessity: models reformat placeholders. `<PERSON_0_a1b2>`
        comes back as `PERSON_0_a1b2`, `[PERSON_0_a1b2]`, `**<PERSON_0_a1b2>**`
        or lower-cased, and a reply that half-restores is worse than useless.
        """
        out = text
        # Longest placeholder first so PERSON_1 never eats the prefix of
        # PERSON_10 — the classic off-by-one in this pattern.
        for placeholder in sorted(self._by_placeholder, key=len, reverse=True):
            m = self._by_placeholder[placeholder]
            body = placeholder[1:-1]                       # strip < >
            pattern = re.compile(
                r"[<\[\(]?\s*" + re.escape(body) + r"\s*[>\]\)]?(?![0-9A-Za-z_])",
                re.IGNORECASE)
            out = pattern.sub(lambda _m, v=m.value: v, out)
        return out

    # ---- checks --------------------------------------------------------------

    def _leaks(self, text: str) -> set[str]:
        """Declared values still present in text that is about to be sent.

        Uses `_literal_spans` — the *same* matcher substitution used. A guard
        that matches more loosely than the action it guards fires on correct
        behaviour: bare containment reports "Sarah" as leaked because the
        untouched, unrelated word "Sarahsson" contains it. Once a guard cries
        wolf on valid input it gets switched off, and then it protects nothing.
        """
        return {m.value for m in self._by_value.values()
                if _literal_spans(text, m.value)}

    def _foreign_placeholder(self, text: str) -> bool:
        return bool(re.search(r"<[A-Z_]+_\d+_" + re.escape(self.tag) + r">", text))

    def _declared_spans(self, text: str) -> Iterable[tuple[str, tuple[int, int]]]:
        for _, m in self._by_value.items():
            for span in _literal_spans(text, m.value):
                yield m.kind, span

    # ---- persistence ---------------------------------------------------------

    def to_json(self) -> str:
        return json.dumps({
            "version": 1,
            "stable": self.stable,
            "tag": self.tag,
            "counters": self._counters,
            "mappings": [
                {"placeholder": m.placeholder, "value": m.value, "kind": m.kind}
                for m in self._by_placeholder.values()
            ],
        }, indent=2)

    @classmethod
    def from_json(cls, raw: str | bytes) -> "EntityVault":
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        d = json.loads(raw)
        if int(d.get("version", 0)) != 1:
            raise VaultError(f"unsupported vault version {d.get('version')!r}")
        v = cls(stable=bool(d["stable"]), tag=d["tag"])
        v._counters = {str(k): int(n) for k, n in d["counters"].items()}
        for item in d["mappings"]:
            m = Mapping(placeholder=item["placeholder"], value=item["value"],
                        kind=item["kind"])
            v._by_value[m.value.casefold()] = m
            v._by_placeholder[m.placeholder] = m
        return v

    def save(self, client, label: str = "entity-vault") -> dict[str, Any]:
        """Persist through a BlindkeepClient: encrypted, committed, recoverable."""
        return client.put(self.to_json(), label=label)

    @classmethod
    def load(cls, client, record_id: str) -> "EntityVault":
        rec = client.get_by_id(record_id)
        return cls.from_json(rec["plaintext"])


# ---- span helpers -----------------------------------------------------------

def _normalise_kind(kind: str) -> str:
    k = re.sub(r"[^A-Za-z_]", "_", kind).strip("_").upper()
    if not k:
        raise VaultError("kind must contain at least one letter")
    return k


def _literal_spans(text: str, value: str) -> list[tuple[int, int]]:
    """Case-insensitive whole-token matches of a literal value.

    Word boundaries are applied only at ends that are word characters, so an
    email or a path — whose edges are not word characters — still matches.
    """
    left = r"\b" if value[:1].isalnum() or value[:1] == "_" else ""
    right = r"\b" if value[-1:].isalnum() or value[-1:] == "_" else ""
    pattern = re.compile(left + re.escape(value) + right, re.IGNORECASE)
    return [m.span() for m in pattern.finditer(text)]


def _pattern_spans(text: str) -> list[tuple[str, tuple[int, int]]]:
    out = []
    for kind, pattern in _PATTERNS:
        for m in pattern.finditer(text):
            out.append((kind, m.span()))
    return out


def _resolve_overlaps(
    spans: list[tuple[str, tuple[int, int]]],
) -> list[tuple[str, tuple[int, int]]]:
    """Keep the longest span when two detectors overlap.

    An email inside a path, a key inside a URL: replacing the shorter one first
    leaves half the longer one exposed. Longest-wins is deterministic, and ties
    break on kind name so the same input always produces the same output.
    """
    ordered = sorted(spans, key=lambda s: (s[1][0], -(s[1][1] - s[1][0]), s[0]))
    kept: list[tuple[str, tuple[int, int]]] = []
    for kind, (start, end) in ordered:
        if any(start < k_end and end > k_start for _, (k_start, k_end) in kept):
            continue
        kept.append((kind, (start, end)))
    return kept


def _unprotected_hint(text: str) -> str:
    """One line naming what substitution cannot cover.

    Shown to the user rather than kept as a comment, because the residual risk
    here is judgement — only they can look at the remaining prose and decide
    whether it identifies them.
    """
    words = len(re.findall(r"\b\w+\b", text))
    return (f"{words} words are being transmitted as written. Substitution "
            "removes identifiers, not identifiability — check the remaining "
            "prose for anything that describes you uniquely.")


# ---- the proxied call -------------------------------------------------------

def private_cloud_complete(prompt: str, *,
                           vault: EntityVault,
                           api_base: str,
                           api_key: str,
                           model: str,
                           enable_cloud: bool = False,
                           accept_not_private: bool = False,
                           system: Optional[str] = None,
                           dialect: Optional[str] = None,
                           timeout: float = 120.0) -> dict:
    """Anonymise, send, restore. Still not private — see the module docstring.

    The gate is deliberately not softened: both acknowledgements are still
    required, because a smaller disclosure is still a disclosure and the user
    should enter it on purpose. What changes is the size of it, and that the
    caller can see precisely which text left.
    """
    anon = vault.anonymize(prompt)
    sent_system = None
    if system is not None:
        sent_system = vault.anonymize(system).text

    result = cloud_complete(
        anon.text,
        api_base=api_base,
        api_key=api_key,
        model=model,
        enable_cloud=enable_cloud,
        accept_not_private=accept_not_private,
        system=sent_system,
        apply_redaction=False,          # substitution already ran; stacking the
                                        # regex pass would corrupt placeholders
        dialect=dialect,
        timeout=timeout)

    return {
        "reply": vault.restore(result["reply"]),
        "reply_raw": result["reply"],
        "sent": anon.text,
        "substitutions": [
            {"placeholder": m.placeholder, "kind": m.kind} for m in anon.used
        ],
        "private": False,
        "pseudonymized": True,
        "notice": result["notice"],
        "residual_risk": anon.unprotected_hint,
    }

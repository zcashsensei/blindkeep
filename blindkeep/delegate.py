"""Send a hosted model a question that contains none of your content.

Pseudonymisation is bounded by what a detector can find: it swaps the names it recognises and
transmits everything it does not, so "the only paediatric cardiologist in Truro" survives intact.
That is a smaller disclosure, and `vault_proxy.py` says so.

This is a different construction. A **local** model reads the private material and writes a
*generic* question — one that could have come from anyone. Only that leaves the machine. The
frontier model answers it in the abstract, and the local model re-specialises the answer against
the private context, which never left:

    private   "Sarah, my landlord in Truro who breeds Basenjis, owes me £4,000"
    sent      "What are the options for recovering an unpaid debt from a private individual?"
    returned  generic guidance
    shown     that guidance, re-applied to Sarah, Truro, and £4,000 — locally

The provider still does the reasoning you wanted. It just never receives a fact about you.

**Why this is not merely better substitution.** Substitution is subtractive: it starts from your
text and removes what it recognises, so anything unrecognised ships. Abstraction is generative:
it starts from nothing and writes a new question, so anything not deliberately included is
absent. The failure modes are opposite — substitution leaks what it missed, abstraction loses
what it failed to carry. Losing utility is recoverable. Leaking is not.

**The gate is the load-bearing part, not the abstraction.** A local model asked to be generic will
sometimes not be, and a model that "usually" strips identifiers is a model that discloses on the
day it matters. So nothing is sent on trust: `LeakGate` compares the outgoing text against every
private source mechanically and **raises rather than sends** on any hit. The rules are deliberately
blunt — rare words, proper nouns, numbers, and any shared 3-gram — because a subtle rule that
sometimes allows a leak is worse than a crude one that sometimes forces a rewrite.

**What this does NOT give you, and what now narrows it.** The provider still learns that *someone*
asked, and roughly what about. Two of those are addressed elsewhere and one is not:

* **Who asked** — `anon_token.py`. A blind-signed entitlement proves you may ask without saying
  which subscriber you are, so the request arrives unattributed rather than merely uncontentful.
* **How identifying the question itself is** — `specificity()` below counts uncommon terms and
  `LeakGate(max_specificity=...)` will refuse an abstraction that is too detailed. It is a proxy,
  not a solution: nothing syntactic can tell that an ordinary-sounding question names one person.
* **That a request happened at all** — untouched. Timing and volume are network properties, and
  no amount of rewriting hides them.

It also rests on a judgement — was the abstraction complete? — rather than on hardware, which is
why it ranks below `ATTESTED`, and why `SEALED` runs both.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Sequence

# Words that carry no identifying weight and appear in almost any question. Kept short on
# purpose: every entry is a hole in the gate, so the list earns its size rather than being
# comprehensive.
_COMMON = frozenset("""
a an the and or but if then than that this these those there here of in on at to for from with
without into onto over under about between during before after while is are was were be been
being am do does did doing have has had having can could should would may might must will shall
i me my mine we us our ours you your yours he him his she her hers it its they them their theirs
what which who whom whose when where why how all any both each few more most other some such no
nor not only own same so too very just now also as by up down out off again further once
""".split())

_TOKEN = re.compile(r"[A-Za-z0-9£$€][A-Za-z0-9'’£$€.,-]*")
NGRAM = 3


class LeakError(Exception):
    """Outgoing text carried something from the private side. Nothing was sent."""


def _tokens(text: str) -> list[str]:
    return _TOKEN.findall(text)


def _is_identifying(token: str) -> bool:
    """Rare enough to be worth refusing over.

    Deliberately generous. A false positive costs a rewrite; a false negative costs a disclosure,
    and those are not comparable — so anything not demonstrably ordinary is treated as private.

    **Position is not used, and that is the point.** An earlier version exempted capitals at the
    start of a sentence, reasoning that "What" should not read as a name. It also exempted
    "Sarah" in *"Sarah Whitfield owes me £4,000"*, because a name at the start of a message is
    still at the start of a message. Sentence-initial words that are genuinely ordinary are
    already covered by `_COMMON`; nothing else needs an exemption, and giving one opened a hole
    exactly where private text most often begins.
    """
    bare = token.strip(".,'’-")
    if not bare:
        return False
    if bare.lower() in _COMMON:
        return False
    if any(c.isdigit() for c in bare):
        return True                      # amounts, dates, account numbers, ages
    if any(c in bare for c in "£$€"):
        return True
    if bare[0].isupper():
        return True                      # a capital that is not a common word: a name
    if len(bare) >= 8:
        return True                      # long words are rare words
    return False


def identifying_terms(text: str) -> set[str]:
    """Everything in `text` that must not appear downstream."""
    return {tok.strip(".,'’-").lower() for tok in _tokens(text) if _is_identifying(tok)}


def _ngrams(text: str, n: int = NGRAM) -> set[tuple[str, ...]]:
    toks = [t.strip(".,'’-").lower() for t in _tokens(text)]
    toks = [t for t in toks if t]
    return {tuple(toks[i:i + n]) for i in range(len(toks) - n + 1)}


def specificity(text: str) -> int:
    """How many uncommon terms the text carries. A PROXY for how identifying it is.

    The gate above is syntactic: it can tell that "Sarah" survived, and cannot tell that "what
    are the options after a diagnosis of a rare autoimmune condition in a man under thirty" names
    almost nobody. Every word there is ordinary; the *combination* is not.

    Nothing syntactic solves that. What can be done is refuse to pretend otherwise — count the
    uncommon terms, hand the number to the caller, and let them set a policy. A measurement that
    is honestly a proxy beats a check that implies a guarantee it cannot give.
    """
    return len({t.strip(".,'’-").lower() for t in _tokens(text)
                if t.strip(".,'’-").lower() not in _COMMON})


@dataclass
class LeakGate:
    """Refuses to let private material reach the wire.

    Holds the private sources rather than a single string, because context assembled from several
    memories leaks the same way one message does — and checking only the message is exactly the
    gap that would make this theatre.

    `max_specificity` is off by default and advisory when set: it bounds how detailed an
    abstraction may be, which limits — never eliminates — the chance that a question is unusual
    enough to identify the person asking it.
    """
    sources: list[str] = field(default_factory=list)
    max_specificity: Optional[int] = None

    def add(self, *texts: str) -> "LeakGate":
        self.sources.extend(t for t in texts if t)
        return self

    def leaks(self, outgoing: str) -> list[str]:
        """Every reason this text must not be sent. Empty means clear."""
        found: list[str] = []
        private_terms: set[str] = set()
        for s in self.sources:
            private_terms |= identifying_terms(s)

        out_terms = {t.strip(".,'’-").lower() for t in _tokens(outgoing)}
        shared = sorted(private_terms & out_terms)
        if shared:
            found.append(f"identifying terms survived: {shared}")

        out_ngrams = _ngrams(outgoing)
        for s in self.sources:
            overlap = _ngrams(s) & out_ngrams
            if overlap:
                sample = " ".join(sorted(overlap)[0])
                found.append(f"phrase copied from the private side: {sample!r}")
                break

        if self.max_specificity is not None:
            score = specificity(outgoing)
            if score > self.max_specificity:
                found.append(
                    f"too specific to be safely generic: {score} uncommon terms, "
                    f"limit {self.max_specificity}")
        return found

    def check(self, outgoing: str) -> None:
        problems = self.leaks(outgoing)
        if problems:
            raise LeakError(
                "refusing to send — the abstraction did not remove everything:\n  "
                + "\n  ".join(problems))


DEFAULT_ABSTRACT_SYSTEM = (
    "Rewrite the user's message as a general question that any stranger could have asked.\n"
    "Remove every name, place, number, amount, date and distinguishing detail. Keep only the "
    "shape of the problem.\n"
    "Do not answer it. Do not explain. Reply with the question and nothing else."
)

DEFAULT_APPLY_SYSTEM = (
    "You are given general guidance and the user's real situation. Apply the guidance to their "
    "situation concretely, using their actual names, numbers and details. Do not mention that the "
    "guidance was general."
)


@dataclass
class Delegation:
    """What happened, including exactly what left the machine."""
    reply: str
    sent: str
    generic_reply: str
    attempts: int

    def as_dict(self) -> dict[str, Any]:
        return {"sent": self.sent, "attempts": self.attempts, "private": True,
                "notice": "the provider received no fact about you; it still learned "
                          "that you asked something, and roughly what about"}


@dataclass(frozen=True)
class Route:
    """Whether a question needs abstracting, and why.

    `reasons` is empty exactly when `abstract` is False, so a caller can always show the user
    what forced the slower path instead of reporting an unexplained quality drop.
    """
    abstract: bool
    reasons: list[str] = field(default_factory=list)
    specificity: int = 0

    @property
    def direct(self) -> bool:
        return not self.abstract

    def as_dict(self) -> dict[str, Any]:
        return {"abstract": self.abstract, "reasons": list(self.reasons),
                "specificity": self.specificity}


CLASSIFY_SYSTEM = (
    "Does the question depend on private facts about the person asking — their name, their "
    "situation, their documents, anyone they know — or does it presuppose circumstances not "
    "stated in the question itself?\n"
    "A question anyone in the world could have typed, whose answer does not change based on who "
    "asked, is GENERAL.\n"
    "Reply with exactly one word: GENERAL or PRIVATE."
)


def route(message: str, context: Sequence[str] = (), *,
          classifier: Optional[Callable[[str, Optional[str]], str]] = None,
          max_specificity: Optional[int] = None) -> Route:
    """Decide whether this question needs abstracting at all.

    Abstraction costs answer quality, and most questions have nothing to protect: "how do I write
    a decorator" carries no fact about anyone. Paying the cost on those is a tax with no payer —
    it makes the private path feel worse than it is, which is how people turn it off entirely.

    Two checks, in order, and they are deliberately different in kind.

    **First, mechanically: does the text overlap the private context?** This reuses `LeakGate`
    unchanged rather than introducing a second rulebook — it is the identical check `delegate()`
    applies before transmitting, so the two cannot drift apart and let stored memory take the fast
    path. No judgement is involved and none is needed.

    **Second, by judgement: is the question about the asker at all?** This one cannot be
    mechanical, and the tempting shortcut is wrong. `identifying_terms` exists to guard the wire,
    where a false positive costs a rewrite, so it flags anything not demonstrably ordinary —
    every capitalised word, every number, every word over eight letters. Point it at *"How do I
    write a Python decorator?"* and it objects to "Python" and "decorator". Reused here it would
    abstract essentially everything, which is not caution, it is the feature not existing.
    Distinguishing "Python" from "Sarah" is a question about meaning, so it goes to a model —
    a **local** one, so asking costs no privacy.

    **Without a classifier it abstracts.** Not as a placeholder: a router with no way to tell
    general from private has not earned the fast path, and defaulting to "send it" would trade a
    recoverable cost (a worse answer) for an unrecoverable one (a disclosure). Empty input
    abstracts for the same reason.

    What this is **not** is a sensitivity detector. Nothing — syntax or model — reliably tells
    that an ordinary-sounding question names one person (see `specificity`). The claim is narrow
    and one-directional: *a question that overlaps no stored memory and is judged to be about
    nobody is a question abstraction would only degrade.* Everything else takes the slow path.
    """
    text = (message or "").strip()
    if not text:
        return Route(abstract=True, reasons=["empty question — nothing to reason about"])

    score = specificity(text)

    # 1. Mechanical, no judgement: does it carry stored private material?
    reasons = list(LeakGate(max_specificity=max_specificity).add(*context).leaks(text))
    if reasons:
        return Route(abstract=True, reasons=reasons, specificity=score)

    # 2. Judgement, and only a local model may make it.
    if classifier is None:
        return Route(abstract=True, specificity=score, reasons=[
            "no local classifier supplied — cannot tell a general question from a private one, "
            "so taking the safe path"])

    try:
        verdict = (classifier(text, CLASSIFY_SYSTEM) or "").strip().upper()
    except Exception as exc:
        return Route(abstract=True, specificity=score,
                     reasons=[f"classifier failed ({type(exc).__name__}) — taking the safe path"])

    # Anything that is not an unambiguous GENERAL is treated as private, including a model that
    # answers with a paragraph instead of the one word it was asked for.
    if verdict.startswith("GENERAL"):
        return Route(abstract=False, specificity=score)
    return Route(abstract=True, specificity=score,
                 reasons=[f"the local model judged this question private (said {verdict[:40]!r})"])


def delegate(message: str,
             local: Callable[[str, Optional[str]], str],
             remote: Callable[[str, Optional[str]], str],
             context: Sequence[str] = (),
             attempts: int = 3,
             abstract_system: str = DEFAULT_ABSTRACT_SYSTEM,
             apply_system: str = DEFAULT_APPLY_SYSTEM) -> Delegation:
    """Abstract locally, verify, send only the abstraction, re-specialise locally.

    `local` must be a model on this machine; `remote` may be anything. Both are passed in rather
    than imported so this module reaches no provider itself — the same discipline that keeps the
    cloud path unreachable by default.

    Retries a failed abstraction rather than sending a leaky one, and gives up rather than
    lowering the bar. A refusal here means "use the local model for this question", which is a
    real answer and not a failure.
    """
    gate = LeakGate().add(message, *context)
    problems: list[str] = []

    for attempt in range(1, attempts + 1):
        prompt = message if attempt == 1 else (
            f"{message}\n\nYour previous attempt still contained private detail "
            f"({'; '.join(problems)}). Be more general.")
        generic = local(prompt, abstract_system).strip()

        problems = gate.leaks(generic)
        if not problems:
            generic_reply = remote(generic, None)
            # The answer comes back generic; the private context is applied HERE, on this machine.
            final = local(
                f"General guidance:\n{generic_reply}\n\n"
                f"My situation:\n{message}"
                + ("\n\nWhat you know about me:\n" + "\n".join(f"- {c}" for c in context)
                   if context else ""),
                apply_system)
            return Delegation(reply=final.strip(), sent=generic,
                              generic_reply=generic_reply, attempts=attempt)

    raise LeakError(
        f"could not abstract this question in {attempts} attempts without leaking:\n  "
        + "\n  ".join(problems)
        + "\n  Nothing was sent. Ask the local model directly instead.")


def ask(message: str,
        local: Callable[[str, Optional[str]], str],
        remote: Callable[[str, Optional[str]], str],
        context: Sequence[str] = (),
        *,
        max_specificity: Optional[int] = None,
        **kw) -> Delegation:
    """Route first: abstract only when there is something to protect.

    The privacy of this path does not come from abstracting everything. It comes from the gate,
    which is applied either way — a question only skips abstraction by *passing* that gate, not by
    being waved through. So the fast path is not a weaker mode with the check disabled; it is the
    case where the check found nothing to remove and abstraction would therefore delete detail for
    no gain.

    That distinction is what makes this safe to default on. A router that guessed "this looks
    harmless" would be a second, softer rule quietly overriding the first.
    """
    decision = route(message, context, classifier=local, max_specificity=max_specificity)

    if decision.direct:
        reply = remote(message, None)
        return Delegation(reply=reply.strip(), sent=message,
                          generic_reply=reply, attempts=0)

    return delegate(message, local, remote, context=context, **kw)

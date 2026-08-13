"""Calibrated randomness on the outbound path, with honest accounting.

Three mechanisms, each of which reduces a leak to a number the receipt can
print. Sources and the mapping from attack to mechanism: docs/ENDPOINT_MATH.md.

1. **Exponential-mechanism selection** (`select_abstraction`). The local model
   writes several candidate abstractions; every one is checked by ``LeakGate``;
   the transmitted candidate is then chosen by the exponential mechanism with
   utility = -specificity. Two exact properties follow. The choice is
   randomised, so the emitted text is no longer a deterministic function of the
   private input. And the mechanism's preference between any two gate-clearing
   candidates is bounded by e^epsilon, so "which phrasing was chosen" carries a
   bounded amount of signal.

   **What this is NOT.** It is not end-to-end differential privacy of the
   emitted text with respect to the private input. The candidates themselves
   are written by a model that read the private text, and a full token-level
   guarantee (InferDPT / RANTEXT, arXiv 2310.12214) needs an embedding-space
   metric this stdlib-only module does not have. The receipt therefore reports
   ``selection_epsilon``, scoped exactly, and never the unqualified claim.
   The gate remains the load-bearing part, exactly as in ``delegate``.

2. **A privacy ledger** (`PrivacyLedger`). Epsilons compose by addition
   (sequential composition), so a session budget is enforceable: every send
   spends its epsilon and its specificity, and when the budget is gone the
   path refuses rather than quietly continuing. The specificity budget is a
   PROXY (see ``delegate.specificity``) and the ledger says so in its own
   serialisation — no unit it cannot defend, no "bits" it did not measure.

3. **Length bucketing** (`pad_to_bucket`). A padded request lands on one of N
   fixed sizes, so a network observer's length channel carries at most
   log2(N) bits — an exact worst-case bound, unlike random padding, which
   leaves a distribution an observer can average away (Whisper Leak,
   arXiv 2511.03675, evaluates and breaks the random alternatives).
"""

from __future__ import annotations

import json
import math
import os
import random
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Sequence

from .delegate import (
    DEFAULT_ABSTRACT_SYSTEM,
    DEFAULT_APPLY_SYSTEM,
    Delegation,
    LeakError,
    LeakGate,
    specificity,
)


class BudgetError(Exception):
    """The session's privacy budget is spent. Nothing was sent."""


# --- 1. exponential mechanism ------------------------------------------------

def exponential_mechanism(
    utilities: Sequence[float],
    epsilon: float,
    sensitivity: float = 1.0,
    rng: Optional[random.Random] = None,
) -> int:
    """Sample an index with probability proportional to exp(eps * u / (2 * sens)).

    The textbook mechanism (McSherry-Talwar), numerically stabilised by
    subtracting the maximum utility before exponentiating. ``epsilon = 0``
    degenerates to a uniform draw; larger epsilon prefers higher utility more
    sharply, and the preference ratio between any two options is bounded by
    exp(epsilon * |u_i - u_j| / (2 * sensitivity)).

    ``rng`` defaults to ``random.SystemRandom`` — an adversary must not be able
    to predict the draw. A seeded ``random.Random`` is for tests only.
    """
    if not utilities:
        raise ValueError("no candidates to select among")
    if epsilon < 0:
        raise ValueError("epsilon must be >= 0")
    if sensitivity <= 0:
        raise ValueError("sensitivity must be > 0")
    r = rng if rng is not None else random.SystemRandom()
    top = max(utilities)
    weights = [math.exp(epsilon * (u - top) / (2.0 * sensitivity)) for u in utilities]
    total = sum(weights)
    pick = r.random() * total
    acc = 0.0
    for i, w in enumerate(weights):
        acc += w
        if pick <= acc:
            return i
    return len(weights) - 1     # floating-point tail


def select_abstraction(
    candidates: Sequence[str],
    epsilon: float,
    *,
    specificity_cap: int = 64,
    rng: Optional[random.Random] = None,
) -> tuple[int, dict[str, Any]]:
    """Pick one gate-cleared candidate by the exponential mechanism.

    Utility is ``-specificity`` clipped into [-cap, 0]: a function of the
    candidate text alone, so a candidate cannot buy selection weight with
    anything except being more generic. The clip bounds the mechanism's
    sensitivity, which is what makes the preference ratio a real number
    rather than an unbounded one.

    Returns the chosen index and a report the receipt embeds verbatim —
    including the scoped claim, so a UI cannot shorten it into a lie.
    """
    utils = [-float(min(specificity(c), specificity_cap)) for c in candidates]
    idx = exponential_mechanism(utils, epsilon, sensitivity=float(specificity_cap), rng=rng)
    return idx, {
        "mechanism": "exponential_mechanism",
        "selection_epsilon": epsilon,
        "candidates": len(candidates),
        "utility": "-min(specificity, cap)",
        "specificity_cap": specificity_cap,
        "claim": (
            "the CHOICE among gate-cleared candidates is randomised with "
            "preference ratio bounded by e^epsilon; this is NOT end-to-end "
            "differential privacy of the text itself"),
    }


# --- 2. the ledger -----------------------------------------------------------

@dataclass
class PrivacyLedger:
    """Session accounting: epsilons add, budgets refuse.

    ``spend`` is called once per transmitted request. When either budget would
    be exceeded the ledger raises ``BudgetError`` BEFORE the send — a budget
    that is checked after transmission is a diary, not a control.

    Persistence is optional and deliberately plain JSON: the ledger's job is
    honest arithmetic, not tamper evidence. (The keep's Merkle log is where
    tamper evidence lives; a signed/ZK-provable ledger is the roadmap item in
    docs/ENDPOINT_MATH.md, and its arithmetic is exactly what ships here.)
    """

    epsilon_budget: float = 16.0
    specificity_budget: int = 512
    epsilon_spent: float = 0.0
    specificity_spent: int = 0
    sends: int = 0
    path: Optional[str] = None

    def charge(self, *, epsilon: float, spec: int) -> None:
        """Check-then-spend. Raises without recording when over budget."""
        if epsilon < 0 or spec < 0:
            raise ValueError("charges must be >= 0")
        if self.epsilon_spent + epsilon > self.epsilon_budget:
            raise BudgetError(
                f"epsilon budget spent: {self.epsilon_spent:.2f} + {epsilon:.2f} "
                f"> {self.epsilon_budget:.2f}. Nothing was sent. Reset the "
                f"ledger only if you accept restarting the accounting.")
        if self.specificity_spent + spec > self.specificity_budget:
            raise BudgetError(
                f"specificity budget spent: {self.specificity_spent} + {spec} "
                f"> {self.specificity_budget}. Nothing was sent.")
        self.epsilon_spent += epsilon
        self.specificity_spent += spec
        self.sends += 1
        if self.path:
            self.save(self.path)

    def as_dict(self) -> dict[str, Any]:
        return {
            "epsilon_spent": round(self.epsilon_spent, 6),
            "epsilon_budget": self.epsilon_budget,
            "specificity_spent": self.specificity_spent,
            "specificity_budget": self.specificity_budget,
            "sends": self.sends,
            "composition": "sequential (epsilons add)",
            "note": (
                "specificity is a PROXY for how identifying a text is, not a "
                "measured bit-count; see delegate.specificity"),
        }

    def save(self, path: str) -> None:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.as_dict(), f, indent=1)
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: str, *,
             epsilon_budget: float = 16.0,
             specificity_budget: int = 512) -> "PrivacyLedger":
        """Load a ledger, or start one if the file does not exist.

        Stored SPENDS are trusted from disk; stored BUDGETS are not — the
        caller's budget is policy and policy comes from the caller, otherwise
        editing a JSON file would raise your own limit silently.
        """
        led = cls(epsilon_budget=epsilon_budget,
                  specificity_budget=specificity_budget, path=path)
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            led.epsilon_spent = float(raw.get("epsilon_spent", 0.0))
            led.specificity_spent = int(raw.get("specificity_spent", 0))
            led.sends = int(raw.get("sends", 0))
        except FileNotFoundError:
            pass
        return led


# --- 3. length bucketing -----------------------------------------------------

# Doubling ladder capped at 8 KiB: padding travels in an HTTP header, and the
# widest gap (4 KiB) must fit inside common server header limits (~8 KiB).
# An abstracted question is far below the cap; anything above it is reported
# unbucketed rather than padded to a lie.
DEFAULT_BUCKETS = (1 << 10, 1 << 11, 1 << 12, 1 << 13)


def pad_to_bucket(size: int, buckets: Sequence[int] = DEFAULT_BUCKETS) -> tuple[int, dict[str, Any]]:
    """Bytes of padding to land ``size`` on a fixed bucket, plus the exact bound.

    With N buckets an observer of the padded length learns at most log2(N)
    bits, worst case, full stop — that is the whole point of determinism.
    A payload larger than every bucket cannot be hidden among them; it is
    reported as unbucketed rather than padded to a lie.
    """
    bs = sorted(set(buckets))
    if not bs or any(b <= 0 for b in bs):
        raise ValueError("buckets must be positive")
    for b in bs:
        if size <= b:
            return b - size, {
                "bucketed": True,
                "bucket_bytes": b,
                "buckets": len(bs),
                "length_bits_bound": round(math.log2(len(bs)), 3),
            }
    return 0, {
        "bucketed": False,
        "buckets": len(bs),
        "reason": f"payload of {size} bytes exceeds the largest bucket ({bs[-1]})",
    }


# --- putting 1 and 2 in front of the wire ------------------------------------

Completer = Callable[[str, Optional[str]], str]


def dp_delegate(
    message: str,
    local: Completer,
    remote: Completer,
    context: Sequence[str] = (),
    *,
    epsilon: float = 2.0,
    candidates: int = 4,
    ledger: Optional[PrivacyLedger] = None,
    rng: Optional[random.Random] = None,
    abstract_system: str = DEFAULT_ABSTRACT_SYSTEM,
    apply_system: str = DEFAULT_APPLY_SYSTEM,
) -> tuple[Delegation, dict[str, Any]]:
    """``delegate.delegate`` with a randomised choice instead of first-past-the-gate.

    The plain path transmits the FIRST candidate that clears the gate, which
    makes the emitted text a deterministic function of the private input and
    the model. Here the local model writes up to ``candidates`` attempts, every
    one is gated, and one CLEARED candidate is chosen by the exponential
    mechanism. The gate is unchanged and still absolute: a candidate that
    leaks is never in the pool, whatever its utility, and if no candidate
    clears, nothing is sent — same refusal, same message discipline.

    The ledger, when given, is charged BEFORE the remote call: epsilon for the
    selection, specificity of the text actually chosen.
    """
    if candidates < 1:
        raise ValueError("need at least one candidate")
    gate = LeakGate().add(message, *context)

    pool: list[str] = []
    problems: list[str] = []
    for attempt in range(1, candidates + 1):
        prompt = message if attempt == 1 else (
            f"{message}\n\nYour previous attempt still contained private detail "
            f"({'; '.join(problems) or 'be broader'}). Write a DIFFERENT, more "
            f"general phrasing.")
        generic = local(prompt, abstract_system).strip()
        found = gate.leaks(generic)
        if found:
            problems = found
        elif generic and generic not in pool:
            pool.append(generic)

    if not pool:
        raise LeakError(
            f"could not abstract this question in {candidates} attempts without leaking:\n  "
            + "\n  ".join(problems or ["no usable candidate produced"])
            + "\n  Nothing was sent. Ask the local model directly instead.")

    idx, report = select_abstraction(pool, epsilon, rng=rng)
    chosen = pool[idx]
    report["pool_cleared"] = len(pool)

    if ledger is not None:
        ledger.charge(epsilon=epsilon, spec=specificity(chosen))
        report["ledger"] = ledger.as_dict()

    generic_reply = remote(chosen, None)
    final = local(
        f"General guidance:\n{generic_reply}\n\n"
        f"My situation:\n{message}"
        + ("\n\nWhat you know about me:\n" + "\n".join(f"- {c}" for c in context)
           if context else ""),
        apply_system)
    return (Delegation(reply=final.strip(), sent=chosen,
                       generic_reply=generic_reply, attempts=len(pool)),
            report)

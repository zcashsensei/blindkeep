"""Decouple *when you ask* from *when a request leaves*, and make every request look alike.

`delegate.py` removes your content from the question. `anon_token.py` removes your name from the
authorisation. Both leave the same residue, and both say so in their own docstrings: the provider
still learns that a request happened, how big it was, and — across many requests — the shape of a
person's day. A question about nobody, unattributed, still arrives at 09:12, 09:14 and 23:40, in
bursts on weekdays, sized 2,847 and 3,102 bytes. That is a behavioural fingerprint, and no amount
of rewriting the question touches it.

The fix is not cryptographic. It is scheduling:

    without  request leaves when you press enter      timing == your behaviour
    with     request leaves on the next fixed slot    timing == a clock

**Constant rate, not jitter.** A randomised delay feels private and is not: an observer averages
over enough samples and the underlying activity reappears, because the mean of a jittered signal is
the signal. A *constant* rate has no underlying signal to recover — the channel emits one request
per interval whether you are working, asleep, or on holiday. `jitter` is therefore not offered as
an option here. Offering it would be selling the feeling.

**Poisson is the exception, and it is not jitter.** `interval_mode="poisson"` draws each gap from
an exponential distribution instead of using a fixed one. That sounds like the thing just refused
and is its opposite: a Poisson process is *memoryless*, so the time since the last send tells an
observer nothing about the time until the next, and independent Poisson streams merge into another
Poisson stream — which is what lets many clients' traffic combine without the mixture revealing
its parts. This is the timing model mix networks use, for that reason. Constant rate remains the
default because it is the easier claim to check; Poisson is the better one when this channel feeds
into a mix or shares a relay with other users.

**Responses are padded too, and the reason is specific.** See `pad_payload`: an unpadded streamed
response leaks token lengths, which is enough to classify a conversation's topic and recover a
fraction of its text from ciphertext alone. Padding the request and not the response protects the
half nobody was reading.

**Cover traffic is real traffic.** A slot with nothing queued still sends: a generic question, from
the same code path, padded to the same bucket, costing the same money. That is the price and it is
not hidden — `Channel.cost()` reports it. A channel that skipped empty slots would announce, every
time it skipped, that nothing was queued.

**Two adversaries, two different results.** Saying "private" without naming who is watching is how
this kind of module ends up lying:

    network observer (ISP, wire)   learns: a Blindkeep node exists, and its constant rate.
                                   Nothing about when you worked, or how much.
    the provider itself            learns: an account asked N generic questions per hour, forever.
                                   Which of them were real, and when you were at your desk, are
                                   hidden. The *prompt length* is not — the provider reads the
                                   prompt, so bucketing helps against the wire, never against them.

Sending direct means the provider's own API key identifies the account no matter what happens here.
That is structural: they require their key. `relay=` exists for that reason — a relay holds the key
and redeems an `anon_token`, so the provider sees the relay and the relay sees an unnamed token.
Neither alone links a question to a person; a relay you run yourself sees both halves and is
therefore not one. That limit is stated in `visibility()` rather than papered over.
"""

from __future__ import annotations

import math
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# One request per minute is slow enough to be affordable and fast enough to be usable. It is the
# knob that trades money and latency against how coarse the timing signal becomes; a caller who
# raises it is buying cheapness with resolution, and should know that is the trade.
DEFAULT_INTERVAL = 60.0

# Padded byte lengths. Coarse on purpose: fine-grained buckets leak the thing they pad, because a
# bucket that fits one message closely is a measurement of that message.
SIZE_BUCKETS = (512, 1024, 2048, 4096, 8192, 16384)

# Sent when a slot comes up with nothing queued. Deliberately dull and self-contained: cover that
# reads as a real question is cover that a provider can answer, bill, and log without noticing.
COVER_QUESTIONS = (
    "What are the general steps involved in reviewing a contract?",
    "How does someone usually go about comparing two suppliers?",
    "What should a person consider before changing bank accounts?",
    "What is the usual process for appealing a decision?",
    "How do people typically organise a long research project?",
)

NGRAM = 3


class DispatchError(Exception):
    """The request was not sent. Nothing left the machine."""


class LinkageError(DispatchError):
    """Sending this would tie two requests to one person. Nothing was sent."""


def bucket_for(length: int) -> int:
    """The smallest bucket that fits. Raises rather than inventing one that fits exactly."""
    for size in SIZE_BUCKETS:
        if length <= size:
            return size
    raise DispatchError(
        f"{length} bytes exceeds the largest bucket ({SIZE_BUCKETS[-1]}). Padding it would create "
        f"a bucket of one, which is a measurement rather than a disguise. Shorten the question.")


def pad_payload(data: bytes) -> bytes:
    """Pad a payload to its bucket, reversibly. **This is the response-side fix.**

    Requests were padded from the start; responses were not, and that was a real hole rather than
    an omission of polish. LLMs stream token by token, so the sequence of encrypted packet sizes
    tracks the *lengths of the tokens being generated* — enough to reconstruct a meaningful share
    of the output and to classify the topic of a conversation with high confidence, from ciphertext
    alone. Padding the question and leaving the answer bare protects the half nobody was reading.

    **Buffering is the larger half of the fix, and it is architectural rather than arithmetic.**
    The attack needs a *sequence* of sizes; one padded blob is a single size. A gateway that waits
    for the whole response and returns it once removes the sequence entirely, which is why this
    pads a complete payload and offers no streaming variant. The cost is that the user waits for
    the full answer instead of watching it type, and that cost is the defence.
    """
    body = _i2osp_len(len(data)) + data
    target = bucket_for(len(body))
    return body + b"\x00" * (target - len(body))


def unpad_payload(padded: bytes) -> bytes:
    """Recover the payload. Refuses a declared length that does not fit what arrived."""
    if len(padded) < 4:
        raise DispatchError("padded payload is too short to carry a length prefix")
    n = int.from_bytes(padded[:4], "big")
    if n > len(padded) - 4:
        raise DispatchError(
            f"declared length {n} exceeds the {len(padded) - 4} bytes present; refusing to return "
            f"a truncated payload rather than guessing at the remainder")
    return padded[4:4 + n]


def _i2osp_len(n: int) -> bytes:
    return n.to_bytes(4, "big")


def padding_headers(payload_len: int) -> dict[str, str]:
    """Filler that brings the request up to its bucket.

    Carried in a header rather than in the prompt for one reason: **padding inside the prompt
    changes the answer.** A model given 4KB of filler reads the filler. A header is covered by TLS,
    counted by anyone measuring the connection, and ignored by every server that does not know the
    name — which is the exact set of properties padding needs.

    This hides length from the *wire*. The provider parses the prompt and sees its true length; no
    header can change that, and this docstring will not imply otherwise.
    """
    target = bucket_for(payload_len)
    fill = target - payload_len
    return {"X-Blindkeep-Pad": "A" * fill} if fill else {}


def _ngrams(text: str, n: int = NGRAM) -> set[tuple[str, ...]]:
    toks = [t.lower() for t in text.split() if t]
    return {tuple(toks[i:i + n]) for i in range(len(toks) - n + 1)}


@dataclass
class Sent:
    """One slot, resolved. Records what left the machine, including whether it was real."""
    slot: int
    at: float
    real: bool
    bucket: int
    prompt: str
    reply: Optional[str] = None
    ticket: Optional[str] = None
    error: Optional[str] = None

    def as_dict(self) -> dict[str, Any]:
        return {"slot": self.slot, "real": self.real, "bucket": self.bucket,
                "delivered": self.error is None}


@dataclass
class Channel:
    """A constant-rate, fixed-size, session-free path to a provider.

    `send(prompt, headers)` is injected rather than imported, so this module reaches no provider
    itself — the same discipline that keeps `cloud_gate` unreachable by default, and what makes the
    timing behaviour testable without a network.

    The queue is FIFO and unbounded. A burst of ten questions on a one-minute channel takes ten
    minutes to drain, and that is the feature working: the alternative is emitting ten requests in
    four seconds and telling the provider exactly when you sat down.
    """
    send: Callable[[str, dict[str, str]], str]
    interval: float = DEFAULT_INTERVAL
    clock: Callable[[], float] = time.monotonic
    strict_linkage: bool = True
    interval_mode: str = "constant"          # "constant" | "poisson"
    cover_questions: tuple[str, ...] = COVER_QUESTIONS

    _queue: list[tuple[str, str]] = field(default_factory=list, repr=False)
    _results: dict[str, Sent] = field(default_factory=dict, repr=False)
    _seen_ngrams: set[tuple[str, ...]] = field(default_factory=set, repr=False)
    _spent_tokens: set[str] = field(default_factory=set, repr=False)
    _slot: int = 0
    _real: int = 0
    _cover: int = 0
    _next_at: Optional[float] = None

    # ---- submitting -------------------------------------------------------------

    def submit(self, prompt: str, *, token: Optional[str] = None,
               history: Optional[list] = None) -> str:
        """Queue one question. Returns a ticket; the request leaves at the next slot, not now.

        `history` exists only to be refused. Conversation history is the single most effective way
        to link requests — it carries the previous turns verbatim — so a parameter that quietly
        accepted it would undo the rest of this module. There is no flag to allow it.
        """
        if history:
            raise LinkageError(
                "conversation history ties this request to the previous one and defeats the "
                "channel. Send a self-contained question, or use the local model, which keeps "
                "history on this machine where it is free.")
        if not prompt or not prompt.strip():
            raise DispatchError("refusing to queue an empty question")

        if token is not None:
            if token in self._spent_tokens:
                raise LinkageError(
                    "this entitlement token has already been spent. A reused token is a shared "
                    "identifier across two requests — exactly what blind signing exists to avoid. "
                    "Redeem a fresh one.")
            self._spent_tokens.add(token)

        problems = self.linkage(prompt)
        if problems and self.strict_linkage:
            raise LinkageError(
                "refusing to send — this question shares material with an earlier one:\n  "
                + "\n  ".join(problems))

        self._seen_ngrams |= _ngrams(prompt)
        ticket = secrets.token_hex(8)
        self._queue.append((ticket, prompt))
        return ticket

    def linkage(self, prompt: str) -> list[str]:
        """Every way this question could be tied to an earlier one. Empty means clear.

        Blunt on purpose, for the reason `delegate.LeakGate` is blunt: a subtle rule that sometimes
        permits a linkage is worse than a crude one that sometimes forces a rewrite. A shared rare
        phrase across two supposedly unrelated requests is a join key.
        """
        overlap = _ngrams(prompt) & self._seen_ngrams
        if overlap:
            sample = " ".join(sorted(overlap)[0])
            return [f"phrase repeated from an earlier question: {sample!r}"]
        return []

    # ---- the clock --------------------------------------------------------------

    def _next_gap(self) -> float:
        """How long until the next slot.

        Constant returns the interval. Poisson draws from Exp(1/interval), giving a memoryless
        gap: knowing when the last request went out tells an observer nothing about the next.
        Sampled from `secrets` rather than `random`, because a predictable schedule is a schedule
        an adversary can subtract.
        """
        if self.interval_mode == "constant":
            return self.interval
        if self.interval_mode != "poisson":
            raise DispatchError(
                f"unknown interval_mode {self.interval_mode!r}. Use 'constant' or 'poisson' — "
                f"an unrecognised mode must not fall back to a weaker schedule silently.")
        # Uniform in (0, 1], then inverse-transform to an exponential.
        u = (secrets.randbits(53) + 1) / (1 << 53)
        return -self.interval * math.log(u)

    def due(self) -> bool:
        """True when the next slot has arrived. A slot is never skipped for being empty."""
        return self._next_at is None or self.clock() >= self._next_at

    def wait(self) -> float:
        """Seconds until the next slot. The worst-case added latency is one full interval."""
        if self._next_at is None:
            return 0.0
        return max(0.0, self._next_at - self.clock())

    def tick(self) -> Sent:
        """Send exactly one request: the queued one if there is one, otherwise cover.

        Both branches take the same path, the same padding, and the same call. The only difference
        is which string is sent, and the provider cannot see that difference — which is the whole
        mechanism. Everything else in this module exists to keep those two branches identical.
        """
        if not self.due():
            raise DispatchError(
                f"slot {self._slot} is not due for another {self.wait():.1f}s. Sending early "
                f"would make emission time depend on caller behaviour, which is the leak.")

        now = self.clock()
        self._next_at = now + self._next_gap()
        slot = self._slot
        self._slot += 1

        if self._queue:
            ticket, prompt = self._queue.pop(0)
            real = True
            self._real += 1
        else:
            ticket, prompt = None, secrets.choice(self.cover_questions)
            real = False
            self._cover += 1

        payload = prompt.encode("utf-8")
        bucket = bucket_for(len(payload))
        record = Sent(slot=slot, at=now, real=real, bucket=bucket, prompt=prompt, ticket=ticket)

        try:
            reply = self.send(prompt, padding_headers(len(payload)))
            record.reply = reply
        except Exception as exc:
            # A failure must not change the channel's shape. The slot is spent either way, the
            # next one is already scheduled, and a caller who retries goes to the back of the
            # queue — otherwise a flaky provider turns into a timing side channel.
            record.error = f"{type(exc).__name__}: {exc}"

        if ticket:
            self._results[ticket] = record
        return record

    def result(self, ticket: str) -> Optional[Sent]:
        """The answer, once its slot has come up. `None` means still queued."""
        return self._results.get(ticket)

    def pending(self) -> int:
        return len(self._queue)

    # ---- honesty ----------------------------------------------------------------

    def cost(self) -> dict[str, Any]:
        """What the constant rate is charging you, in requests and in waiting."""
        total = self._real + self._cover
        return {
            "slots": total,
            "real": self._real,
            "cover": self._cover,
            "cover_fraction": round(self._cover / total, 3) if total else 0.0,
            "mean_latency_seconds": self.interval,
            # Constant rate bounds the wait; Poisson does not, and reporting a bound it cannot
            # keep would be the same class of lie this module exists to avoid.
            "worst_case_latency_seconds": (
                self.interval if self.interval_mode == "constant" else None),
            "latency_note": (
                "a queued question waits at most one interval"
                if self.interval_mode == "constant" else
                "exponential gaps are unbounded — the mean is the interval, but any single wait "
                "can be much longer. That unpredictability is the property being bought."),
            "note": ("cover requests are billed by the provider at the same rate as real ones; "
                     "that is the price of the timing signal being a clock instead of you"),
        }

    def visibility(self, *, relay: bool = False) -> dict[str, str]:
        """What each adversary still learns. A report, because the residue is real.

        Written in the shape of `private_read.visibility()` for the same reason: a privacy feature
        that leaves the user unsure what remains has not finished doing its job.
        """
        return {
            "when_you_were_active": "hidden — emission is on a fixed clock, not on your input",
            "how_much_you_used_it": "hidden — the rate is constant whether you work or sleep",
            "which_requests_were_real": "hidden — cover takes the identical code path",
            "request_size_on_the_wire": f"bucketed to {SIZE_BUCKETS}, so exact lengths are hidden",
            "prompt_length_at_the_provider": "VISIBLE — they parse the prompt; no header changes it",
            "that_the_channel_exists": "visible, and not addressable by any scheduling scheme",
            "who_holds_the_account": (
                "hidden from the provider — see oblivious.py, where the gateway's credential is "
                "used instead of yours; holds only if relay and gateway are independent"
                if relay else
                "VISIBLE — you are sending direct, and the provider's API key is an account "
                "identity. Scheduling hides when and which; it cannot hide whose key. "
                "oblivious.py (RFC 9458) is the path that does."),
            "your_ip_address": (
                "seen by the relay, not the provider" if relay else
                "VISIBLE to the provider — a network-layer property this module does not touch"),
            "relay_correlation": (
                "a relay you operate yourself sees both the IP and the timing, so it is a single "
                "point of correlation and not a privacy boundary. Independent operators are what "
                "makes the two views separate."),
        }

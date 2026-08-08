"""Constant-rate dispatch: emission time must not depend on caller behaviour.

Correctness is the easy half — a question goes out, an answer comes back. The half that matters is
`test_emission_is_identical_whether_the_user_is_busy_or_idle`: a user hammering the channel and a
user who has gone home must produce byte-identical observations at the provider. If those two
traces differ anywhere, the timing signal survived and the module is ceremony.

Four tests here pass by demonstrating a FAILURE — that a linkage, a reused token, a conversation
history, or an early send is refused rather than quietly permitted. A privacy control that has
never been observed refusing anything has not been observed working.

The clock is injected. These tests take milliseconds and assert on a one-minute interval, which is
the only way to test a scheduler without either sleeping or trusting it.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blindkeep.dispatch import (
    SIZE_BUCKETS,
    Channel,
    DispatchError,
    LinkageError,
    bucket_for,
    pad_payload,
    padding_headers,
    unpad_payload,
)


class FakeClock:
    """Advances only when a test says so, so 'one minute later' costs nothing."""

    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class Recorder:
    """Stands in for the provider, and records exactly what it could observe."""

    def __init__(self, fail=False):
        self.observed = []
        self.fail = fail

    def __call__(self, prompt, headers):
        body = len(prompt.encode("utf-8")) + sum(len(v) for v in headers.values())
        self.observed.append({"wire_bytes": body, "prompt": prompt})
        if self.fail:
            raise ConnectionError("provider unreachable")
        return f"answer to {prompt[:20]}"


def channel(recorder=None, **kw):
    clock = FakeClock()
    ch = Channel(send=recorder or Recorder(), clock=clock, **kw)
    return ch, clock


def expect(fn, contains=None, exc=DispatchError):
    try:
        fn()
    except exc as e:
        if contains:
            assert contains in str(e).lower(), f"wrong reason: {e}"
        return str(e)
    raise AssertionError("expected a refusal, got none")


# --- the property the whole thing exists for ---------------------------------

def test_emission_is_identical_whether_the_user_is_busy_or_idle():
    """The load-bearing test. Two opposite users, one indistinguishable trace."""
    busy_rec, idle_rec = Recorder(), Recorder()
    busy, busy_clock = channel(busy_rec, strict_linkage=False)
    idle, idle_clock = channel(idle_rec)

    for i in range(6):
        busy.submit(f"a distinct question number {i} about unrelated matters")

    busy_times, idle_times = [], []
    for _ in range(6):
        busy_times.append(busy.tick().at)
        idle_times.append(idle.tick().at)
        busy_clock.advance(60.0)
        idle_clock.advance(60.0)

    assert busy_times == idle_times, "a busy channel emitted on a different schedule than an idle one"
    assert len(busy_rec.observed) == len(idle_rec.observed) == 6, "slot counts diverged"
    busy_sizes = [o["wire_bytes"] for o in busy_rec.observed]
    idle_sizes = [o["wire_bytes"] for o in idle_rec.observed]
    assert busy_sizes == idle_sizes, (
        f"wire sizes distinguish real traffic from cover: {busy_sizes} vs {idle_sizes}")


def test_an_empty_slot_still_sends():
    """Skipping an empty slot would announce, every time, that nothing was queued."""
    rec = Recorder()
    ch, clock = channel(rec)
    for _ in range(3):
        sent = ch.tick()
        assert not sent.real, "expected cover"
        clock.advance(60.0)
    assert len(rec.observed) == 3, "an empty channel went quiet, which is itself a signal"
    assert ch.cost()["cover"] == 3


def test_a_burst_drains_one_per_slot():
    """Ten questions at once must not become ten requests at once."""
    rec = Recorder()
    ch, clock = channel(rec, strict_linkage=False)
    for i in range(10):
        ch.submit(f"question {i} concerning entirely separate topics of enquiry")

    ch.tick()
    assert len(rec.observed) == 1, "a burst escaped the schedule"
    assert ch.pending() == 9, "the queue drained faster than the clock"
    clock.advance(60.0)
    ch.tick()
    assert len(rec.observed) == 2


def test_cover_and_real_are_the_same_size_on_the_wire():
    """Padding is only privacy if it erases the distinction it was added for."""
    rec = Recorder()
    ch, clock = channel(rec, strict_linkage=False)
    ch.submit("x" * 400)
    ch.tick()
    clock.advance(60.0)
    ch.tick()
    sizes = {o["wire_bytes"] for o in rec.observed}
    assert len(sizes) == 1, f"real and cover requests were different sizes: {sizes}"


# --- refusals: these pass by demonstrating a failure -------------------------

def test_conversation_history_is_refused():
    """History carries previous turns verbatim; it is the strongest linkage there is."""
    ch, _ = channel()
    expect(lambda: ch.submit("a new question", history=[{"role": "user", "content": "earlier"}]),
           contains="history", exc=LinkageError)


def test_a_reused_entitlement_token_is_refused():
    """A token spent twice is a shared identifier across two requests."""
    ch, _ = channel()
    ch.submit("first question about some ordinary matter", token="tok-1")
    expect(lambda: ch.submit("second question on a different subject", token="tok-1"),
           contains="already been spent", exc=LinkageError)


def test_a_repeated_phrase_across_requests_is_refused():
    """A shared rare phrase is a join key, even when both questions are generic."""
    ch, _ = channel()
    ch.submit("what are the options for recovering an unpaid debt")
    expect(lambda: ch.submit("more on the options for recovering an unpaid debt"),
           contains="repeated", exc=LinkageError)


def test_sending_before_the_slot_is_refused():
    """Emitting early would put caller behaviour back into the timing."""
    ch, clock = channel()
    ch.tick()
    clock.advance(30.0)
    expect(lambda: ch.tick(), contains="not due")


# --- padding ------------------------------------------------------------------

def test_padding_reaches_the_bucket_exactly():
    for length in (1, 100, 511, 512, 513, 4095):
        headers = padding_headers(length)
        total = length + sum(len(v) for v in headers.values())
        assert total == bucket_for(length), f"{length} padded to {total}, not {bucket_for(length)}"


def test_an_oversized_question_is_refused_rather_than_given_its_own_bucket():
    """A bucket that fits one message is a measurement of that message."""
    expect(lambda: bucket_for(SIZE_BUCKETS[-1] + 1), contains="exceeds the largest bucket")


# --- failure must not change the shape ---------------------------------------

def test_a_provider_failure_does_not_alter_the_schedule():
    """A flaky provider must not become a timing side channel."""
    ch, clock = channel(Recorder(fail=True), strict_linkage=False)
    ticket = ch.submit("a question that will fail to be delivered anywhere")
    sent = ch.tick()
    assert sent.error is not None, "expected the failure to be recorded"
    assert ch.wait() == 60.0, "a failed slot did not schedule the next one normally"
    assert ch.result(ticket).error is not None, "the ticket lost its error"


def test_visibility_never_claims_the_api_key_is_hidden_when_sending_direct():
    """The one claim that would be false. Asserted so a future edit cannot introduce it."""
    ch, _ = channel()
    direct = ch.visibility(relay=False)
    assert "VISIBLE" in direct["who_holds_the_account"], (
        "direct sending claimed account identity was hidden; it is not")
    assert "VISIBLE" in direct["prompt_length_at_the_provider"], (
        "claimed prompt length is hidden from the provider; no header can do that")
    relayed = ch.visibility(relay=True)
    assert "VISIBLE" not in relayed["who_holds_the_account"]
    assert "not a privacy boundary" in relayed["relay_correlation"], (
        "a self-run relay was presented as a privacy boundary")


# --- response padding: the token-length side channel --------------------------

def test_responses_of_different_lengths_pad_to_one_size():
    """The whole point. Two answers, one observable size."""
    short = pad_payload(b"Yes.")
    long = pad_payload(b"Yes, though it depends on several factors worth setting out." * 3)
    assert len(short) == len(long), (
        f"a short and a long answer were distinguishable by size: {len(short)} vs {len(long)}")


def test_padding_is_reversible_at_every_boundary():
    for n in (0, 1, 4, 507, 508, 1000, 4090):
        data = bytes(range(256)) * (n // 256) + bytes(range(n % 256))
        assert unpad_payload(pad_payload(data)) == data, f"round trip failed at {n} bytes"


def test_token_length_sequence_is_erased_by_padding_the_whole_payload():
    """A streamed answer leaks a SEQUENCE of sizes; a buffered one leaks a single bucket."""
    tokens = [b"The", b" quick", b" brown", b" f", b"ox", b" jumped"]
    streamed = [len(t) for t in tokens]
    assert len(set(streamed)) > 1, "fixture should have varied token lengths"
    buffered = pad_payload(b"".join(tokens))
    assert len(buffered) in SIZE_BUCKETS, "buffered response did not land on a bucket"


def test_a_lying_length_prefix_is_refused():
    padded = bytearray(pad_payload(b"short"))
    padded[:4] = (9999).to_bytes(4, "big")
    expect(lambda: unpad_payload(bytes(padded)), contains="exceeds")


# --- Poisson timing -----------------------------------------------------------

def test_poisson_gaps_are_memoryless_not_fixed():
    ch, _ = channel(interval_mode="poisson")
    gaps = [ch._next_gap() for _ in range(400)]
    assert len(set(gaps)) > 350, "poisson mode produced repeated gaps; it is not sampling"
    mean = sum(gaps) / len(gaps)
    assert 0.75 * ch.interval < mean < 1.35 * ch.interval, (
        f"mean gap {mean:.1f}s is far from the {ch.interval}s interval")
    assert min(gaps) < ch.interval < max(gaps), "gaps did not straddle the mean"


def test_constant_mode_is_still_exactly_constant():
    ch, _ = channel()
    assert {ch._next_gap() for _ in range(50)} == {ch.interval}


def test_an_unknown_interval_mode_is_refused_not_downgraded():
    ch, _ = channel(interval_mode="jitter")
    expect(lambda: ch._next_gap(), contains="unknown interval_mode")


def test_poisson_does_not_advertise_a_latency_bound_it_cannot_keep():
    poisson, _ = channel(interval_mode="poisson")
    assert poisson.cost()["worst_case_latency_seconds"] is None, (
        "poisson mode claimed a worst-case bound; exponential gaps are unbounded")
    constant, _ = channel()
    assert constant.cost()["worst_case_latency_seconds"] == constant.interval


def run():
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed, failed = [], []
    for name, fn in tests:
        try:
            fn()
            passed.append(name)
            print(f"  PASS  {name}")
        except AssertionError as exc:
            failed.append(name)
            print(f"  FAIL  {name}")
            print(f"          {exc}")
        except Exception as exc:
            failed.append(name)
            print(f"  ERROR {name}")
            print(f"          {type(exc).__name__}: {exc}")
    print()
    print(f"{len(passed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())

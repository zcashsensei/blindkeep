"""The app's release gate: what an agent token may and may not be handed.

Until this suite existed the app had no gate at all. `blindkeep/memory_gate.py`
carried the whole engine — Sensitivity, Tier, DEFAULT_POLICY, encode_label — and
`app.py` never imported it, so an agent token reached `/api/read/<n>` and
`/api/state` unconditionally: every memory readable, every label enumerable.
The library held the guarantee and the product did not, which is the shape of
defect a library-only test suite cannot see.

Sensitivity is NOT a second encryption. Everything in the keep is sealed under
the one master key and the holder of that key reads all of it — that is why the
page is expected to read a secret here and the agent is not. The class decides
only what may be HANDED TO AN AI, which is a different question from what is
readable at all.

Runs against a throwaway node in a temp directory; it must never reach a real
keep, so every path constant the app owns is redirected before the server starts.
"""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

SERVERS = []
PROCS = []
TMPDIRS = []

NODE_PORT = 8796
APP_PORT = 8795

app = None
IDX = {}


def _boot():
    """Start a throwaway node, point the app at it, and seed four memories."""
    global app
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="blindkeep-gate-"))
    TMPDIRS.append(str(tmp))

    proc = subprocess.Popen(
        [sys.executable, "-m", "blindkeep", "node",
         "--data-dir", str(tmp / "keep"), "--port", str(NODE_PORT)],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        # Windowless: the engines were windowless but the code WATCHING them
        # was not, and supervisors popped a console every cycle for days.
        # A test harness spawning a child is the same shape.
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    PROCS.append(proc)

    node_url = f"http://127.0.0.1:{NODE_PORT}"
    for _ in range(80):
        try:
            urllib.request.urlopen(node_url + "/v1/head", timeout=1).read()
            break
        except Exception:
            time.sleep(0.25)
    else:
        raise RuntimeError("throwaway node never came up")

    import app as _app
    app = _app
    app.NODE_URL = node_url
    app.NODE_PORT = NODE_PORT
    app.PORT = APP_PORT
    app.KEY_PATH = tmp / "master.key"
    # The SEALED path is a separate constant and ensure_session_key() checks it
    # FIRST. Left pointing at the real data/, every write here refuses with
    # key_locked against whatever key the developer happens to have on disk.
    app.KEY_SEALED_PATH = tmp / "master.key.sealed"
    app.PIN_PATH = tmp / "pin.json"
    app.CAT_PATH = tmp / "catalogue.json"
    app.POLICY_PATH = tmp / "policy.json"
    app.ensure_node = lambda: (True, "test")

    httpd = ThreadingHTTPServer(("127.0.0.1", APP_PORT), app.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    SERVERS.append(httpd)
    time.sleep(0.4)

    write("my pin is 1234", "bank", "secret")
    write("i like pizza", "food", "public")
    write("no class given", "unlabelled")
    write("typo", "mistyped", "nonsense")

    _, st = req("/api/state")
    # Keyed by LABEL, not by class: two records share the secret class here, so
    # a dict keyed by class would silently keep only the last of them.
    IDX.update({r["label"]: r["index"] for r in st["list"]})


def req(path, body=None, token=None):
    tok = app.TOKEN if token is None else token
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(f"http://127.0.0.1:{APP_PORT}" + path,
                               data=data, method="POST" if data else "GET")
    r.add_header("X-Blindkeep-Token", tok)
    r.add_header("Host", "127.0.0.1")
    if data:
        r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            return resp.status, json.loads(resp.read() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or "{}")


def write(text, label, sensitivity=None):
    """The backup soft gate is a separate concern with its own tests, so use
    its documented escape hatch rather than patching around it."""
    body = {"text": text, "label": label, "i_accept_no_backup": True}
    if sensitivity is not None:
        body["sensitivity"] = sensitivity
    return req("/api/write", body)


def agent_on():
    _, a = req("/api/agent", {"enabled": True})
    return a["token"]


# --- classification ---------------------------------------------------------


def test_a_written_memory_carries_its_class():
    _, w = write("later", "later-note", "secret")
    assert w.get("sensitivity") == "secret", w


def test_an_unclassified_write_defaults_to_personal():
    """The engine's own default, not the strictest class: a memory nobody
    classified should still come back to the person who wrote it."""
    _, w = write("nothing stated", "plain", None)
    assert w.get("sensitivity") == "personal", w


def test_an_unreadable_class_fails_closed():
    """A typo must cost recall, never exposure."""
    _, w = write("garbled", "garbled", "nonsense")
    assert w.get("sensitivity") == "secret", w


def test_state_reports_the_class_breakdown():
    _, st = req("/api/state")
    assert st["by_sensitivity"]["public"] >= 1, st["by_sensitivity"]
    assert st["by_sensitivity"]["secret"] >= 2, st["by_sensitivity"]


# --- the policy -------------------------------------------------------------


def test_secret_is_pinned_to_local():
    """"The operator cannot read it" is still a claim about somebody else's
    hardware, so the top class never leaves this machine at all."""
    _, pol = req("/api/policy")
    assert pol["policy"]["secret"] == 5, pol["policy"]
    _, pol = req("/api/policy", {"policy": {"secret": 0}})
    assert pol["policy"]["secret"] == 5, pol["policy"]


def test_an_agent_starts_at_the_weakest_tier():
    """Blindkeep cannot verify what holds a token — a local script and a
    frontier model behind a relay are indistinguishable from in here — so the
    tier is a declaration and it starts at the bottom."""
    _, pol = req("/api/policy")
    assert pol["agent_tier"] == 0, pol


# --- release ----------------------------------------------------------------


def test_an_agent_is_given_a_public_memory():
    tok = agent_on()
    s, r = req(f"/api/read/{IDX['food']}", token=tok)
    assert s == 200 and "pizza" in r.get("text", ""), (s, r)


def test_an_agent_is_refused_a_secret():
    tok = agent_on()
    s, r = req(f"/api/read/{IDX['bank']}", token=tok)
    assert s == 403, (s, r)
    assert r.get("requires") == "local", r
    assert r.get("agent_tier") == "open", r


def test_an_agent_is_refused_an_unclassified_memory():
    """Unclassified is not public. Anything written before classes existed, or
    by another tool, reads as secret."""
    tok = agent_on()
    s, r = req(f"/api/read/{IDX['unlabelled']}", token=tok)
    assert s == 403, (s, r)


def test_the_page_still_reads_everything():
    """The key holder is not who the gate is about."""
    s, r = req(f"/api/read/{IDX['bank']}")
    assert s == 200 and "1234" in r.get("text", ""), (s, r)
    assert r["meta"]["sensitivity"] == "secret", r["meta"]
    assert r["meta"]["label"] == "bank", r["meta"]


def test_an_agent_cannot_enumerate_what_it_cannot_open():
    """A label is a disclosure by itself: "bank details" tells you plenty
    without the record behind it."""
    tok = agent_on()
    _, st = req("/api/state", token=tok)
    assert all(x["sensitivity"] == "public" for x in st["list"]), st["list"]


def test_widening_the_policy_takes_effect_on_the_next_read():
    """A rule nobody can change is a constant, not a policy — so prove the
    knob moves, in the direction that grants rather than the one that denies."""
    tok = agent_on()
    s, _ = req(f"/api/read/{IDX['unlabelled']}", token=tok)
    assert s == 403, "expected personal to be withheld at tier open"
    try:
        req("/api/policy", {"policy": {"personal": 0}})
        s, r = req(f"/api/read/{IDX['unlabelled']}", token=tok)
        assert s == 200, (s, r)
    finally:
        req("/api/policy", {"policy": {"personal": 1}})


# --- the agent cannot widen its own reach -----------------------------------


def test_an_agent_cannot_flip_its_own_switch():
    tok = agent_on()
    s, r = req("/api/agent", {"enabled": True}, token=tok)
    assert s == 403, (s, r)


def test_an_agent_cannot_widen_its_own_clearance():
    """Otherwise the whole policy is decorative: the thing being gated would
    hold the gate's key."""
    tok = agent_on()
    s, r = req("/api/policy", {"agent_tier": 5}, token=tok)
    assert s == 403, (s, r)
    _, pol = req("/api/policy")
    assert pol["agent_tier"] == 0, pol


def test_an_agent_cannot_reach_the_master_key():
    tok = agent_on()
    s, r = req("/api/key", token=tok)
    assert s == 403, (s, r)


# --- the read log -----------------------------------------------------------


def test_a_released_memory_is_recorded():
    agent_on()                      # a fresh token, but the log persists
    before = req("/api/agent")[1]["read_count"]
    tok = agent_on()
    req(f"/api/read/{IDX['food']}", token=tok)
    after = req("/api/agent")[1]["read_count"]
    assert after == before + 1, (before, after)


def test_a_refused_read_is_not_recorded_as_a_read():
    tok = agent_on()
    before = req("/api/agent")[1]["read_count"]
    req(f"/api/read/{IDX['bank']}", token=tok)
    after = req("/api/agent")[1]["read_count"]
    assert after == before, (before, after)


def test_the_log_survives_the_switch_going_off():
    """The switch is reversible and this is not. Turning access off stops the
    next read; it cannot reach into a model's context and unsee what left."""
    tok = agent_on()
    req(f"/api/read/{IDX['food']}", token=tok)
    before = req("/api/agent")[1]["read_count"]
    assert before > 0
    req("/api/agent", {"enabled": False})
    after = req("/api/agent")[1]
    assert after["read_count"] == before, after
    assert after["reads"], "the log emptied when access was switched off"


def run():
    _boot()
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed, failed = [], []
    for name, fn in tests:
        try:
            fn()
            passed.append(name)
            print(f"  PASS  {name}")
        except AssertionError as exc:
            failed.append(name)
            print(f"  FAIL  {name}\n          {exc}")
        except Exception as exc:
            failed.append(name)
            print(f"  ERROR {name}\n          {type(exc).__name__}: {exc}")
    for h in SERVERS:
        try:
            h.shutdown()
            h.server_close()
        except Exception:
            pass
    for p in PROCS:
        p.terminate()
        try:
            p.wait(timeout=5)
        except Exception:
            p.kill()
    for d in TMPDIRS:
        shutil.rmtree(d, ignore_errors=True)
    print(f"\n{len(passed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())

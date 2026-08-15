"""Gated cloud path tests.

The important assertions are negative: that this path cannot be entered by
accident, and that no default code path reaches it.
"""

import json
import os
import shutil
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oblivio.cloud_gate import (
    NOT_PRIVATE_NOTICE,
    CloudGateError,
    cloud_complete,
    redact,
    require_opt_in,
)

SERVERS = []
RECEIVED = []


def fake_provider(reply="hello from the cloud", status=200):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a, **k):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            RECEIVED.append({
                "body": json.loads(self.rfile.read(n) or b"{}"),
                "auth": self.headers.get("Authorization", ""),
            })
            body = json.dumps(
                {"choices": [{"message": {"content": reply}}]}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    SERVERS.append(httpd)
    return f"http://127.0.0.1:{httpd.server_address[1]}"


# --- the gate ---------------------------------------------------------------

def test_both_acknowledgements_are_required():
    for enable, accept in ((False, False), (True, False), (False, True)):
        try:
            require_opt_in(enable, accept)
        except CloudGateError:
            continue
        raise AssertionError(
            f"gate opened with enable={enable} accept={accept}")
    require_opt_in(True, True)      # only this must pass


def test_refusal_names_what_is_missing_and_warns():
    try:
        require_opt_in(True, False)
    except CloudGateError as exc:
        assert "accept_not_private" in str(exc)
        assert "NOT PRIVATE" in str(exc)
        return
    raise AssertionError("no refusal")


def test_defaults_are_closed():
    """Calling with no flags at all must refuse, not send."""
    RECEIVED.clear()
    base = fake_provider()
    try:
        cloud_complete("secret", api_base=base, api_key="k", model="m")
    except CloudGateError:
        assert not RECEIVED, "a request was sent despite the gate refusing"
        return
    raise AssertionError("cloud_complete sent with default flags")


def test_missing_credentials_refused_after_gate():
    try:
        cloud_complete("x", api_base="http://x", api_key="", model="m",
                       enable_cloud=True, accept_not_private=True)
    except CloudGateError as exc:
        assert "api_key" in str(exc)
        return
    raise AssertionError("empty api_key accepted")


# --- transmission -----------------------------------------------------------

def test_opted_in_request_reaches_the_provider():
    RECEIVED.clear()
    base = fake_provider("42")
    out = cloud_complete("what is six times seven?", api_base=base,
                         api_key="test-key", model="gpt-test",
                         enable_cloud=True, accept_not_private=True)
    assert out["reply"] == "42"
    assert out["private"] is False
    assert out["notice"] == NOT_PRIVATE_NOTICE
    assert RECEIVED[-1]["auth"] == "Bearer test-key"
    assert RECEIVED[-1]["body"]["model"] == "gpt-test"


def test_caller_can_see_exactly_what_was_sent():
    RECEIVED.clear()
    base = fake_provider()
    out = cloud_complete("plain question", api_base=base, api_key="k",
                         model="m", enable_cloud=True, accept_not_private=True)
    assert out["sent"] == "plain question"
    assert RECEIVED[-1]["body"]["messages"][-1]["content"] == "plain question"


def test_no_stored_memories_are_attached():
    """This module must send the prompt and nothing else."""
    RECEIVED.clear()
    base = fake_provider()
    cloud_complete("just this", api_base=base, api_key="k", model="m",
                   enable_cloud=True, accept_not_private=True)
    msgs = RECEIVED[-1]["body"]["messages"]
    assert len(msgs) == 1, f"unexpected extra messages: {msgs}"


def test_provider_errors_do_not_echo_the_api_key():
    base = fake_provider(status=500)
    try:
        cloud_complete("x", api_base=base, api_key="super-secret-key",
                       model="m", enable_cloud=True, accept_not_private=True)
    except CloudGateError as exc:
        assert "super-secret-key" not in str(exc), "the key leaked into an error"
        return
    raise AssertionError("a 500 did not raise")


# --- redaction, and its honest limits ---------------------------------------

def test_redaction_catches_obvious_secrets():
    text = ("key sk-abcdefghijklmnopqrstuvwxyz123456 and "
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 and "
            "me@example.com and 0x" + "a" * 40 +
            r" and C:\Users\someone\secret.txt")
    out, found = redact(text)
    for leaked in ("sk-abcdefghij", "ghp_ABCDEF", "me@example.com",
                   "0x" + "a" * 40, "someone"):
        assert leaked not in out, f"redaction missed {leaked}"
    assert found


def test_redaction_leaves_ordinary_prose_alone():
    text = "Remind me to call the dentist on Tuesday about the appointment."
    out, found = redact(text)
    assert out == text and not found


def test_redaction_is_documented_as_incomplete():
    """The honest limit: prose secrets survive redaction."""
    text = "my daughter attends St Mary's primary school in Camden"
    out, _ = redact(text)
    assert out == text, (
        "this test asserts the LIMITATION: pattern matching cannot find "
        "sensitive prose. If redaction ever changes, update the docs.")


def test_redaction_is_opt_in_per_call():
    RECEIVED.clear()
    base = fake_provider()
    out = cloud_complete("contact me@example.com", api_base=base, api_key="k",
                         model="m", enable_cloud=True, accept_not_private=True)
    assert "me@example.com" in out["sent"], "redaction applied without being asked"

    out = cloud_complete("contact me@example.com", api_base=base, api_key="k",
                         model="m", enable_cloud=True, accept_not_private=True,
                         apply_redaction=True)
    assert "me@example.com" not in out["sent"]


# --- isolation from the default paths ---------------------------------------

def test_no_default_module_imports_the_cloud_gate():
    """No default path may reach the cloud gate.

    Checks imports rather than mentions: a docstring pointing readers at the
    module is fine and useful. An import is what would make the cloud path
    reachable without a caller deliberately choosing it.
    """
    import ast

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # ENUMERATED, not listed. This guard protects the project's headline privacy claim, and
    # for most of its life it named eleven modules while the package held thirty — so a new
    # module could import the cloud gate and this test would still pass. Worse, the omitted
    # nineteen included `__init__.py`, which is what runs on `import oblivio`: the single
    # most default path there is was the one path never checked.
    #
    # These modules are allowed to reach the gate, and each is opt-in by construction:
    #   cli.py              imports it lazily, inside the one command that offers the cloud path
    #   vault_proxy.py      IS the pseudonymising cloud path; importing it is choosing it
    #   frontier_gateway.py IS the frontier cloud path, reachable only through the
    #                       `frontier` CLI commands, which import it lazily
    #   frontier_private.py same, for the blind-token variant of that path
    #
    # Adding a module here is a claim that nothing reaches it by default, and this list
    # is NOT the proof of that -- `test_importing_the_package_does_not_load_any_cloud_module`
    # is, because it imports in a clean interpreter and asks what actually loaded. Check a
    # new entry against that test rather than against this comment.
    allowed = {"cli.py", "vault_proxy.py", "cloud_gate.py",
               "frontier_gateway.py", "frontier_private.py"}
    pkg = os.path.join(root, "oblivio")
    names = sorted(f for f in os.listdir(pkg) if f.endswith(".py"))
    assert len(names) > 11, "module enumeration failed; this guard would pass vacuously"

    for name in names:
        path = os.path.join(pkg, name)
        if not os.path.exists(path) or name in allowed:
            continue
        tree = ast.parse(open(path, encoding="utf-8").read(), filename=name)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    assert "cloud_gate" not in a.name, f"{name} imports cloud_gate"
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                assert "cloud_gate" not in mod, f"{name} imports cloud_gate"
                for a in node.names:
                    assert "cloud_gate" not in a.name, f"{name} imports cloud_gate"


def test_importing_the_package_does_not_load_any_cloud_module():
    """The claim is about REACHABILITY, so test reachability rather than a proxy for it.

    Reading imports statically cannot see a module pulled in transitively, by a lazy import
    that runs at import time, or through a re-export. Importing the package in a clean
    interpreter and asking what actually loaded is the claim itself, stated executably.
    """
    import subprocess
    import sys

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for entry in ("oblivio", "oblivio.client", "oblivio.node", "oblivio.store",
                  "oblivio.cli"):
        code = (
            f"import sys; sys.path.insert(0, {root!r}); import {entry}; "
            "print(','.join(sorted(m for m in sys.modules "
            "if 'cloud_gate' in m or 'vault_proxy' in m)))"
        )
        out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                             text=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        assert out.returncode == 0, f"import {entry} failed: {out.stderr[-300:]}"
        loaded = out.stdout.strip()
        assert not loaded, f"import {entry} loaded a cloud path: {loaded}"


def _error_provider(status, message):
    """A provider that answers with a real error envelope rather than a body."""
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a, **k):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)) or 0)
            body = json.dumps({"type": "error",
                               "error": {"type": "invalid_request_error",
                                         "message": message}}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    SERVERS.append(httpd)
    return f"http://127.0.0.1:{httpd.server_address[1]}"


def test_provider_error_message_reaches_the_user():
    """Found against the live API: a 400 said only "HTTP 400".

    The real cause was "your credit balance is too low" -- nothing to do with
    the request -- and hiding it sent the search for a bug that did not exist.
    The request carries the key and must never be echoed; the response carries
    the provider's explanation and is the only thing that can say what to do.
    """
    base = _error_provider(400, "Your credit balance is too low to access the API.")
    try:
        cloud_complete("x", api_base=base, api_key="k", model="m",
                       enable_cloud=True, accept_not_private=True, dialect="anthropic")
        raise AssertionError("a 400 did not raise")
    except CloudGateError as exc:
        assert "credit balance" in str(exc), f"provider's reason was swallowed: {exc}"
        assert "400" in str(exc), f"status code lost: {exc}"


def test_a_credential_in_a_provider_error_is_scrubbed():
    """The response should not contain a key -- but that is a claim about
    someone else's server, so it is not relied upon."""
    # Deliberately not a realistic key shape. A convincing dummy in a public
    # repository trips GitHub's secret scanning and every gitleaks run a
    # cloner does, and a fixture is not worth a false alarm.
    planted = "sk-ant-EXAMPLE-NOT-A-REAL-KEY-000000"
    base = _error_provider(400, f"bad token {planted} supplied")
    try:
        cloud_complete("x", api_base=base, api_key="k", model="m",
                       enable_cloud=True, accept_not_private=True, dialect="anthropic")
        raise AssertionError("a 400 did not raise")
    except CloudGateError as exc:
        assert planted not in str(exc), \
            f"a credential-shaped string survived scrubbing: {exc}"
        assert "***" in str(exc), f"scrub left no marker: {exc}"


def test_a_404_blames_the_dialect_not_just_the_url():
    """Found by driving a real endpoint: the wrong dialect 404s, and used to say
    only "provider returned HTTP 404".

    Each provider puts its completion route at a different path, so speaking the
    wrong API means the request never reaches a handler. The bare status code
    sends the user to re-check their URL -- which is correct-looking and wrong,
    because the URL is fine and the API is not. The error has to name the dialect
    in play, or the one hypothesis worth testing is the one it never suggests.
    """
    base = fake_provider(status=404)
    try:
        cloud_complete("hi", api_base=base, api_key="k", model="m",
                       enable_cloud=True, accept_not_private=True, dialect="anthropic")
        raise AssertionError("a 404 should have raised")
    except CloudGateError as exc:
        msg = str(exc)
        assert "anthropic" in msg, f"error does not name the dialect in play: {msg}"
        assert "dialect" in msg.lower(), f"error does not suggest changing it: {msg}"
        assert "404" in msg, f"error drops the status code: {msg}"


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
    print(f"\n{len(passed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())

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

from blindkeep.cloud_gate import (
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
    for name in ("client.py", "store.py", "node.py", "replica.py",
                 "merkle.py", "crypto.py", "recovery.py", "ollama_mem.py",
                 "discover.py", "audit.py", "cli.py"):
        path = os.path.join(root, "blindkeep", name)
        if not os.path.exists(path):
            continue
        tree = ast.parse(open(path, encoding="utf-8").read(), filename=name)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    assert "cloud_gate" not in a.name, f"{name} imports cloud_gate"
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if "cloud_gate" in mod:
                    # cli.py may import it lazily inside its own command only
                    assert name == "cli.py", f"{name} imports cloud_gate"
                for a in node.names:
                    if "cloud_gate" in a.name:
                        assert name == "cli.py", f"{name} imports cloud_gate"


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

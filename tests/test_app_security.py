"""App security regressions: auth length, Host header, Heartwood session gate."""

import ast
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_auth_guards_compare_digest_length():
    """Unequal-length tokens must not reach compare_digest (ValueError → 500)."""
    src = open(os.path.join(os.path.dirname(__file__), "..", "app.py"),
               encoding="utf-8").read()
    assert "len(tok) == len(TOKEN)" in src
    assert "len(tok) == len(agent_tok)" in src or "len(tok) == len(AGENT" in src


def test_host_ok_rejects_empty_host():
    src = open(os.path.join(os.path.dirname(__file__), "..", "app.py"),
               encoding="utf-8").read()
    # Empty string must not be in the allow-list.
    assert '""' not in src.split("def _host_ok")[1].split("def ")[0] or (
        'host in ("127.0.0.1", "localhost", "::1")' in src
        or "host in ('127.0.0.1', 'localhost', '::1')" in src
    )
    assert '::1", "")' not in src and "::1', '')" not in src


def test_heartwood_install_uses_fixed_repo_url():
    src = open(os.path.join(os.path.dirname(__file__), "..", "app.py"),
               encoding="utf-8").read()
    assert "github.com/zcashsensei/heartwood" in src
    assert "def install_heartwood" in src
    assert "/api/hw/install" in src


def test_hw_run_requires_session_token():
    src = open(os.path.join(os.path.dirname(__file__), "..", "app.py"),
               encoding="utf-8").read()
    # The hw/run branch must call _require_session_token nearby.
    idx = src.find('path == "/api/hw/run"')
    assert idx > 0
    chunk = src[idx:idx + 400]
    assert "_require_session_token" in chunk


def test_app_parses():
    path = os.path.join(os.path.dirname(__file__), "..", "app.py")
    ast.parse(open(path, encoding="utf-8").read())


def run():
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = []
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except Exception as exc:
            failed.append(name)
            print(f"  FAIL  {name}: {exc}")
    print(f"\n{len(tests) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())

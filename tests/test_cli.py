"""Command-line interface tests.

The CLI had no tests at all, which is why a whole class of defect lived here
undisturbed: **every** client command created a 32-byte master key as a side
effect when one was missing. `head` and `list` do not use a key. A mistyped
`--key` minted a new secret rather than failing, so `put` would encrypt under a
key the user never chose and their real key could not read it back. Commands
that went on to fail still left a secret behind, in whatever directory they
happened to run in.

The invariant these tests exist to hold: **only `keygen` and `recover` create
key material.** Everything else either finds a key or explains how to make one.
"""

import io
import os
import shutil
import sys
import tempfile
import threading
from contextlib import redirect_stderr, redirect_stdout
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blindkeep.cli import main
from blindkeep.node import _Handler
from blindkeep.store import MemoryStore

SERVERS = []
TMPDIRS = []


def tmpdir():
    d = tempfile.mkdtemp(prefix="blindkeep-cli-")
    TMPDIRS.append(d)
    return d


def node():
    """A live node plus an empty working directory to run commands in."""
    d = tmpdir()
    store = MemoryStore(os.path.join(d, "node"))
    handler = type("B", (_Handler,), {"store": store,
                                      "log_message": lambda *a, **k: None})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    SERVERS.append(httpd)
    work = os.path.join(d, "work")
    os.makedirs(work, exist_ok=True)
    return f"http://127.0.0.1:{httpd.server_address[1]}", work


def cli(*argv, cwd=None):
    """Run the CLI in `cwd`, returning (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    prev = os.getcwd()
    if cwd:
        os.chdir(cwd)
    try:
        with redirect_stdout(out), redirect_stderr(err):
            try:
                code = main(list(argv))
            except SystemExit as exc:      # argparse exits rather than returning
                code = exc.code if isinstance(exc.code, int) else 1
    finally:
        os.chdir(prev)
    return code, out.getvalue(), err.getvalue()


def secrets_under(root):
    """Every key file anywhere beneath `root`."""
    found = []
    for dirpath, _, files in os.walk(root):
        for f in files:
            if f.endswith(".key"):
                found.append(os.path.relpath(os.path.join(dirpath, f), root))
    return sorted(found)


# --- the class: no command invents key material ------------------------------

def test_no_read_command_creates_key_material():
    """The invariant. Run every client command with no key present."""
    url, work = node()
    for argv in (["head", "--url", url],
                 ["list", "--url", url],
                 ["get", "--url", url, "--index", "0"],
                 ["put", "--url", url, "--text", "hi"],
                 ["get", "--url", url]):
        cli(*argv, cwd=work)
    stray = secrets_under(work)
    assert not stray, f"commands minted key material: {stray}"


def test_mistyped_key_path_does_not_mint_a_secret():
    """The dangerous variant: a typo used to silently become a new identity."""
    url, work = node()
    code, _, err = cli("put", "--url", url, "--text", "x",
                       "--key", "typo/master.key", cwd=work)
    assert code == 2, f"expected a usage failure, got {code}"
    assert not secrets_under(work), "a typo created a secret"
    assert "keygen" in err, f"error should name the fix: {err!r}"


def test_head_needs_no_key():
    """`head` verifies a signature. It has no use for a decryption key."""
    url, work = node()
    code, out, err = cli("head", "--url", url, cwd=work)
    assert code == 0, f"head failed without a key: {err!r}"
    assert "root_hex" in out, out
    assert not secrets_under(work)


def test_list_needs_no_key():
    """`list` returns metadata only; the client never decrypts it."""
    url, work = node()
    code, out, err = cli("list", "--url", url, cwd=work)
    assert code == 0, f"list failed without a key: {err!r}"
    assert not secrets_under(work)


def test_put_refuses_without_a_key_and_says_how_to_make_one():
    url, work = node()
    code, _, err = cli("put", "--url", url, "--text", "x", cwd=work)
    assert code == 2, code
    assert "no master key" in err, err
    assert "blindkeep keygen" in err, err


def test_get_refuses_without_a_key():
    url, work = node()
    code, _, err = cli("get", "--url", url, "--index", "0", cwd=work)
    assert code == 2, code
    assert "no master key" in err, err


# --- selector handling -------------------------------------------------------

def test_get_requires_a_selector():
    """`get` with neither flag used to surface as a TypeError about int()."""
    url, work = node()
    code, _, err = cli("get", "--url", url, cwd=work)
    assert code == 2, code
    assert "--index" in err and "--record-id" in err, err
    assert "int()" not in err, f"leaked an internal error: {err!r}"


def test_get_rejects_both_selectors():
    url, work = node()
    code, _, err = cli("get", "--url", url, "--index", "0",
                       "--record-id", "abc", cwd=work)
    assert code == 2, code
    assert "not both" in err, err


def test_get_rejects_a_non_numeric_index():
    url, work = node()
    code, _, err = cli("get", "--url", url, "--index", "abc", cwd=work)
    assert code == 2, code
    assert not secrets_under(work)


# --- keygen remains the one place keys are born ------------------------------

def test_keygen_creates_a_key():
    _, work = node()
    path = os.path.join(work, "k", "master.key")
    code, _, _ = cli("keygen", "--key", path, cwd=work)
    assert code == 0, code
    assert os.path.getsize(path) == 32


def test_keygen_refuses_to_overwrite_without_force():
    _, work = node()
    path = os.path.join(work, "k", "master.key")
    cli("keygen", "--key", path, cwd=work)
    with open(path, "rb") as f:
        original = f.read()

    code, _, err = cli("keygen", "--key", path, cwd=work)
    assert code == 1, code
    assert "refusing to overwrite" in err, err
    with open(path, "rb") as f:
        assert f.read() == original, "key was replaced despite the guard"

    code, _, _ = cli("keygen", "--key", path, "--force", cwd=work)
    assert code == 0
    with open(path, "rb") as f:
        assert f.read() != original, "--force did not rotate the key"


# --- end to end --------------------------------------------------------------

def test_roundtrip_through_the_cli():
    url, work = node()
    key = os.path.join(work, "master.key")
    pin = os.path.join(work, "pin.json")
    assert cli("keygen", "--key", key, cwd=work)[0] == 0

    code, out, err = cli("put", "--url", url, "--key", key, "--pin", pin,
                         "--text", "prefers concise answers", "--label", "prefs",
                         cwd=work)
    assert code == 0, err
    assert "record_id" in out, out

    code, out, err = cli("get", "--url", url, "--key", key, "--pin", pin,
                         "--index", "0", cwd=work)
    assert code == 0, err
    assert "prefers concise answers" in out, out


def test_roundtrip_leaves_exactly_one_key():
    """A full session creates the key you asked for and nothing else."""
    url, work = node()
    key = os.path.join(work, "master.key")
    pin = os.path.join(work, "pin.json")
    cli("keygen", "--key", key, cwd=work)
    cli("put", "--url", url, "--key", key, "--pin", pin, "--text", "a", cwd=work)
    cli("head", "--url", url, cwd=work)
    cli("list", "--url", url, cwd=work)
    assert secrets_under(work) == ["master.key"], secrets_under(work)


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
    for d in TMPDIRS:
        shutil.rmtree(d, ignore_errors=True)
    print(f"\n{len(passed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())

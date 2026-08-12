"""Console output must survive a non-UTF-8 stdout.

The defect these tests exist to hold shut: ``blindkeep progress`` built its report
from U+2713 CHECK MARK and U+2192 RIGHTWARDS ARROW, and Windows hands a redirected
or piped process a cp1252 stdout, which can encode neither. The command exited 1
having printed none of its 22 detector lines. In a terminal it printed all 22.

So the one place it worked was the one place a human was watching. Piped into a CI
step, a supervisor, or a dashboard refresh, it reported an empty board -- and an
empty board reads like a clean board, not a broken command.

The invariant: **every console entry point makes its streams UTF-8 before it
prints.** Not just ``progress`` -- the character set that broke it is used across
the package, so the guard belongs at each entry point rather than at the one call
site that happened to fail first.

These tests must run in a SUBPROCESS. Redirecting stdout in-process gives a
StringIO, which is Unicode-safe and would pass no matter how broken the code is --
which is precisely how a guard like this ends up green for its whole life without
ever having run.

``progress.py`` is a maintainer-only file (gitignored; CLI registers the
subcommand only when the file is present). Progress-specific tests skip on a
clean clone so the published suite stays green without the personal task board.
"""

import ast
import os
import subprocess
import sys
from io import StringIO

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blindkeep._console import use_utf8_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROGRESS_PY = os.path.join(ROOT, "blindkeep", "progress.py")
HAS_PROGRESS = os.path.isfile(PROGRESS_PY)

# Entry points are discovered, not listed, so a new one cannot quietly skip the
# guard. Anything with an ``if __name__ == "__main__"`` block is a console entry
# point; ``blindkeep/__main__.py`` delegates to ``cli.main`` and is covered there.
ENTRY_GLOBS = [ROOT, os.path.join(ROOT, "blindkeep")]


def _cp1252_env():
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "cp1252"
    return env


def _run(args, env=None):
    return subprocess.run(args, cwd=ROOT, env=env, capture_output=True,
                          timeout=120)


def _entry_points():
    """Every non-test module that runs as a script."""
    found = []
    for d in ENTRY_GLOBS:
        for name in sorted(os.listdir(d)):
            if not name.endswith(".py") or name.startswith("test_"):
                continue
            path = os.path.join(d, name)
            src = open(path, encoding="utf-8").read()
            if 'if __name__ == "__main__"' in src:
                found.append((os.path.relpath(path, ROOT), src))
    return found


def test_cp1252_actually_breaks_unguarded_output():
    """CONTROL. If this passes, the harness is not reproducing the bug.

    Without it, every other test here could be green because cp1252 was never
    really in force -- a test that cannot fail is not evidence.
    """
    r = _run([sys.executable, "-c", "print('\\u2713')"], env=_cp1252_env())
    assert r.returncode != 0, "cp1252 stdout did NOT fail on U+2713 — harness is not reproducing the defect"
    assert b"charmap" in r.stderr, f"expected a charmap codec error, got: {r.stderr[:200]!r}"


def test_guard_makes_the_same_print_succeed():
    """The mirror of the control: same char, same encoding, guard applied."""
    code = ("import sys; sys.path.insert(0, %r)\n"
            "from blindkeep._console import use_utf8_stdout\n"
            "use_utf8_stdout()\n"
            "print('\\u2713')\n" % ROOT)
    r = _run([sys.executable, "-c", code], env=_cp1252_env())
    assert r.returncode == 0, f"guard did not rescue the print: {r.stderr[:300]!r}"
    assert "\u2713" in r.stdout.decode("utf-8"), "check mark missing from output"


@pytest.mark.skipif(not HAS_PROGRESS,
                    reason="progress.py is maintainer-only (gitignored on clean clones)")
def test_progress_reports_fully_under_cp1252():
    """The original failure, end to end: exit 0 and a COMPLETE report."""
    r = _run([sys.executable, "-m", "blindkeep", "progress"], env=_cp1252_env())
    assert r.returncode == 0, f"progress exited {r.returncode}: {r.stderr[:300]!r}"
    out = r.stdout.decode("utf-8", errors="replace")
    assert "charmap" not in out and "charmap" not in r.stderr.decode("utf-8", errors="replace")
    # The bug printed the header and then zero detectors. A count, not a
    # substring: truncation after the first line is the shape of the defect.
    detectors = [ln for ln in out.splitlines() if ": " in ln and "[" in ln and "]" in ln]
    assert len(detectors) >= 15, f"expected the full detector list, got {len(detectors)} lines:\n{out[:400]}"


@pytest.mark.skipif(not HAS_PROGRESS,
                    reason="progress.py is maintainer-only (gitignored on clean clones)")
def test_progress_output_is_identical_piped_and_utf8():
    """Encoding must change nothing about WHAT is reported."""
    a = _run([sys.executable, "-m", "blindkeep", "progress"], env=_cp1252_env())
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    b = _run([sys.executable, "-m", "blindkeep", "progress"], env=env)
    assert a.returncode == b.returncode == 0
    assert a.stdout.decode("utf-8") == b.stdout.decode("utf-8"), \
        "report differs between cp1252 and utf-8 stdout"


def test_every_entry_point_calls_the_guard_first():
    """The CLASS guard. A new script must not reintroduce the defect.

    Checked structurally rather than by running each one: ``node`` and
    ``dashboard`` block on a server socket and cannot be smoke-tested here.

    Parsed, not grepped. An earlier version of this test searched the source for
    the name ``use_utf8_stdout`` -- and stayed green when the *call* was deleted,
    because the leftover ``import`` line still matched. A guard whose test passes
    with the guard removed is not a test. So this walks main()'s body and demands
    the call be its FIRST statement: anything printed before it is unprotected.
    """
    offenders = []
    for rel, src in _entry_points():
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.FunctionDef) and node.name == "main"):
                continue
            for i, stmt in enumerate(node.body):
                calls = [n for n in ast.walk(stmt)
                         if isinstance(n, ast.Call)
                         and getattr(n.func, "id", None) == "use_utf8_stdout"]
                if calls:
                    if i != 0:
                        offenders.append(f"{rel}: guard is statement {i + 1} of main()")
                    break
            else:
                offenders.append(f"{rel}: main() never calls the guard")
    assert not offenders, "; ".join(offenders)


@pytest.mark.skipif(not HAS_PROGRESS,
                    reason="progress.py is maintainer-only (gitignored on clean clones)")
def test_progress_still_runs_as_a_bare_script():
    """Adding the guard must not cost progress.py its script entry point.

    It is the one module here with no relative imports, so ``py -3
    blindkeep/progress.py`` worked. The first relative import silently removed
    that -- ``attempted relative import with no known parent package`` -- and the
    ``-m`` path kept passing, so nothing else here would have noticed.
    """
    r = _run([sys.executable, os.path.join("blindkeep", "progress.py"), "--dry-run"],
             env=_cp1252_env())
    assert r.returncode == 0, \
        f"progress.py no longer runs as a script: {r.stderr.decode('utf-8', 'replace')[:300]}"


def test_guard_tolerates_a_replaced_stream():
    """Under a capturing harness the streams have no ``reconfigure`` at all.

    The guard must be a no-op there, not an AttributeError that takes down a
    command which would otherwise have worked.
    """
    real_out, real_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = StringIO(), StringIO()
    try:
        use_utf8_stdout()          # must not raise
        print("\u2713 still works")
        captured = sys.stdout.getvalue()
    finally:
        sys.stdout, sys.stderr = real_out, real_err
    assert "\u2713" in captured


def test_guard_is_idempotent():
    """Called twice (module run under -m, then main) must stay harmless."""
    use_utf8_stdout()
    use_utf8_stdout()
    assert sys.stdout is not None


def run():
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed, failed, skipped = [], [], []
    for name, fn in tests:
        if name.startswith("test_progress") and not HAS_PROGRESS:
            skipped.append(name)
            print(f"  SKIP  {name}  (no progress.py)")
            continue
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
    print(f"\n{len(passed)} passed, {len(failed)} failed"
          + (f", {len(skipped)} skipped" if skipped else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())

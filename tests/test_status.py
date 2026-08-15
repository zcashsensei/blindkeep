"""Status inventory tests.

The bug this module exists to prevent: a hardcoded roster sitting beside an
enumerated one, where only the enumerated one stays current. The dashboard
listed nine module names in a tuple next to a directory glob for tests, and
showed nine of sixteen modules for months.

So the load-bearing assertions here are not "does it count correctly" but
**"can it omit anything"** — `test_modules_cannot_be_a_subset` and
`test_dashboard_uses_the_same_inventory`.
"""

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oblivio.status import (
    NOT_CLAIMED,
    capabilities,
    count_tests,
    list_modules,
    main,
    render,
    summary,
)

ROOT = Path(__file__).resolve().parent.parent
TMPDIRS = []


def tmproot():
    """A skeleton repo with nothing in it, for the negative cases."""
    d = Path(tempfile.mkdtemp(prefix="oblivio-status-"))
    TMPDIRS.append(d)
    (d / "oblivio").mkdir()
    (d / "tests").mkdir()
    return d


# --- counting ----------------------------------------------------------------

def test_counts_match_an_independent_count():
    """Count the files here, separately, and demand the same answer."""
    expected = 0
    suites = 0
    for p in sorted((ROOT / "tests").glob("test_*.py")):
        expected += sum(1 for line in p.read_text(encoding="utf-8").splitlines()
                        if line.startswith("def test_"))
        suites += 1
    got = count_tests(ROOT)
    assert got["total"] == expected, f"{got['total']} != {expected}"
    assert got["suites"] == suites


def test_count_is_positive_and_per_file():
    got = count_tests(ROOT)
    assert got["total"] > 0 and got["files"]
    assert sum(f["tests"] for f in got["files"]) == got["total"], (
        "per-file counts do not add up to the total")


def test_missing_tests_directory_counts_zero_not_crash():
    d = tmproot()
    shutil.rmtree(d / "tests")
    assert count_tests(d) == {"total": 0, "suites": 0, "files": []}


# --- the anti-omission guards ------------------------------------------------

def test_modules_cannot_be_a_subset():
    """Every .py in the package must appear. This is the bug that shipped.

    A roster that can omit is worse than no roster: the board reports a smaller
    system than exists and nobody notices, because what is missing is invisible
    by definition.
    """
    on_disk = {p.name for p in (ROOT / "oblivio").glob("*.py")}
    reported = {m["name"] for m in list_modules(ROOT)}
    missing = on_disk - reported
    assert not missing, f"modules omitted from the inventory: {sorted(missing)}"
    assert not reported - on_disk, "inventory reported a module that is not there"


def test_a_new_module_appears_with_no_edit():
    d = tmproot()
    (d / "oblivio" / "brand_new_thing.py").write_text("x = 1", encoding="utf-8")
    assert "brand_new_thing.py" in {m["name"] for m in list_modules(d)}


def test_dashboard_uses_the_same_inventory():
    """One implementation, so the board and the CLI cannot disagree."""
    dash = ROOT / "dashboard.py"
    if not dash.is_file():
        return                      # gitignored local tool; absent in a clone
    src = dash.read_text(encoding="utf-8", errors="replace")
    assert "from oblivio.status import" in src, (
        "dashboard.py built its own inventory again")
    for gone in ('"merkle.py", "crypto.py"', "def _count_tests("):
        assert gone not in src, f"dashboard.py still has its own {gone!r}"


# --- capabilities ------------------------------------------------------------

def test_capabilities_are_detected_not_asserted():
    d = tmproot()
    rows = capabilities(d)
    assert rows, "no capability rows at all"
    assert all(r["ok"] is False for r in rows), (
        "an empty repository reported shipped capabilities")


def test_capabilities_flip_on_what_is_present():
    d = tmproot()
    (d / "oblivio" / "merkle.py").write_text("", encoding="utf-8")
    (d / "tests" / "test_merkle.py").write_text("", encoding="utf-8")
    row = next(r for r in capabilities(d) if r["label"] == "Merkle + tests")
    assert row["ok"] is True


def test_every_row_carries_its_own_label():
    """Labels travel with the flags so no second roster is needed to render."""
    for r in capabilities(ROOT):
        assert r["label"] and isinstance(r["ok"], bool)


def test_sev_snp_enabled_is_read_from_the_live_registry():
    """Not a written value: it must flip by itself the day it is enabled."""
    row = next(r for r in capabilities(ROOT)
               if r["label"] == "SEV-SNP enabled by default")
    from oblivio.attest import default_registry
    from oblivio.sev_snp import SevSnpVerifier
    live = isinstance(default_registry().get("sev-snp"), SevSnpVerifier)
    assert row["ok"] is live
    assert row["ok"] is False, (
        "SEV-SNP is enabled by default but has not been validated against "
        "real hardware — see oblivio/sev_snp.py")


# --- honesty -----------------------------------------------------------------

def test_it_reports_what_is_not_done():
    """A status report that can only say 'done' is a brochure."""
    assert NOT_CLAIMED, "nothing is listed as unclaimed"
    joined = " ".join(NOT_CLAIMED).lower()
    # These changed once, when detection shipped and "witnessing" stopped being the honest
    # word for what is missing — prevention is. The test failing at that moment was correct
    # behaviour, and the fix belonged here rather than in the claim.
    for expected in ("hardware", "m1", "equivocation", "storage", "pir", "client"):
        assert expected in joined, f"{expected!r} missing from the non-claims"


def test_a_shipped_capability_is_not_still_listed_as_unclaimed():
    """The failure mode this file exists to prevent: claiming less than is true is a lie too.

    A non-claim left behind after the work lands makes the report wrong in the *safe* direction,
    which is still wrong — and it is exactly the drift nobody notices, because nobody audits a
    list of things you say you cannot do.
    """
    joined = " ".join(NOT_CLAIMED).lower()
    for shipped, why in (
        ("access-pattern privacy", "read_private ships trivial PIR"),
        ("anti-equivocation", "witness.py detects and proves it"),
    ):
        assert shipped not in joined, f"{shipped!r} is still listed as unclaimed, but {why}"


def test_render_states_the_count_and_the_rule():
    out = render(ROOT)
    assert str(count_tests(ROOT)["total"]) in out
    assert "counted, not stated" in out
    assert "the document is wrong" in out
    assert "Not claimed:" in out


def test_summary_is_json_serialisable():
    json.dumps(summary(ROOT))


def test_json_flag_emits_valid_json(capsysless=None):
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        assert main(["--json"]) == 0
    d = json.loads(buf.getvalue())
    assert d["tests"]["total"] > 0 and d["not_claimed"]


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
    for d in TMPDIRS:
        shutil.rmtree(d, ignore_errors=True)
    print(f"\n{len(passed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())

#!/usr/bin/env python3
"""Fail if any document states a test count that the source does not support.

This repository has shipped stale counts five times. Every occurrence had the
same shape: a commit adds a suite, and the totals in the documents a reader
actually checks are not updated with it. The numbers are computable, so no
human should be retyping them.

`blindkeep status` already computes the truth. Nothing forced anyone to compare
against it. This does, from `pre-push`.

Three checks, because the bug has appeared in three different shapes:

  1. totals      -- "475 tests", the badge, "N suites". A stale headline.
  2. roster      -- the per-suite list. A corrected total sitting above a table
                    that still omits the new suite is still wrong; that was
                    the fourth occurrence, in six places at once.
  3. completeness-- every suite on disk appears in the roster. Catches the
                    failure the other two cannot: a suite nobody mentioned.

Usage:
    py -3 tools/check_counts.py              # check, exit 1 on drift
    py -3 tools/check_counts.py --print-roster   # emit the roster to paste
    py -3 tools/check_counts.py --run-tests      # also run all suites (~7 min)
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from blindkeep.status import count_tests  # noqa: E402

# A per-suite count and a grand total are both "<n> tests". They are told apart
# by size: the largest suite is 42, the total is in the hundreds. Anything above
# this is read as a total claim. If a single suite ever crosses it, this check
# starts failing loudly -- which is the safe direction. A false alarm costs one
# commit; a missed drift is the bug we are closing.
TOTAL_CLAIM_FLOOR = 50

# Suite file -> the label it goes by in prose. Kept explicit: a suite added
# without a label here fails the completeness check rather than being skipped.
LABELS = {
    "test_adversarial.py": "adversarial",
    "test_anon_token.py": "anon-token",
    "test_attest.py": "attestation",
    "test_audit.py": "audit",
    "test_cli.py": "CLI",
    "test_cloud_gate.py": "cloud gate",
    "test_console.py": "console",
    "test_delegate.py": "delegate",
    "test_dialects.py": "dialects",
    "test_discover.py": "discovery",
    "test_frontier_gateway.py": "frontier-gateway",
    "test_frontier_private.py": "frontier-private",
    "test_dispatch.py": "dispatch",
    "test_hardening.py": "hardening",
    "test_hpke.py": "HPKE",
    "test_memory_gate.py": "memory gate",
    "test_merkle.py": "Merkle",
    "test_metadata.py": "metadata",
    "test_oblivious.py": "oblivious HTTP",
    "test_ollama_mem.py": "local-model memory",
    "test_poseidon.py": "poseidon",
    "test_private_read.py": "private read",
    "test_recovery.py": "recovery",
    "test_replication.py": "replication",
    "test_sev_snp.py": "SEV-SNP",
    "test_status.py": "status",
    "test_store.py": "store",
    "test_vault_proxy.py": "vault proxy",
    "test_witness.py": "witness",
    "test_zk.py": "zk",
    "test_zk_keep.py": "zk-keep",
}

ROSTER_MARKER = "<!-- roster -->"

# "475 tests", "tests-475%20passing", "28 suites".
# Up to two words may sit between the number and the noun -- the count that hid
# longest was "337 automated tests", which an adjacency-only pattern walks past.
RE_TESTS = re.compile(r"(\d+)\s*(?:%20)?\s*(?:\w+\s+){0,2}tests?\b", re.IGNORECASE)
RE_BADGE = re.compile(r"tests-(\d+)%20passing", re.IGNORECASE)
RE_SUITES = re.compile(r"(\d+)\s+(?:test\s+)?suites?\b", re.IGNORECASE)


def truth() -> dict:
    t = count_tests(ROOT)
    t["by_name"] = {f["name"]: f["tests"] for f in t["files"]}
    return t


def build_roster(t: dict) -> str:
    """The roster is generated, never typed. Sorted by label so it is stable."""
    parts = []
    for name in sorted(t["by_name"], key=lambda n: LABELS.get(n, n).lower()):
        label = LABELS.get(name)
        if label is None:
            continue
        parts.append(f"{label} {t['by_name'][name]}")
    return " · ".join(parts)


def docs() -> list[Path]:
    found = [p for p in sorted(ROOT.glob("*.md"))]
    found += [p for p in sorted((ROOT / "docs").glob("*.md"))]
    return [p for p in found if p.is_file()]


def check_totals(t: dict) -> list[str]:
    problems = []
    for path in docs():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            where = f"{path.relative_to(ROOT).as_posix()}:{lineno}"

            for m in RE_BADGE.finditer(line):
                if int(m.group(1)) != t["total"]:
                    problems.append(
                        f"{where}  badge says {m.group(1)} tests, source has {t['total']}"
                    )

            for m in RE_SUITES.finditer(line):
                if int(m.group(1)) != t["suites"]:
                    problems.append(
                        f"{where}  states {m.group(1)} suites, source has {t['suites']}"
                    )

            for m in RE_TESTS.finditer(line):
                n = int(m.group(1))
                if n > TOTAL_CLAIM_FLOOR and n != t["total"]:
                    problems.append(
                        f"{where}  states {n} tests, source has {t['total']}"
                    )
    return problems


def check_roster(t: dict) -> list[str]:
    """Verify every roster line, and that each names every suite."""
    problems = []
    expected = {LABELS[n]: c for n, c in t["by_name"].items() if n in LABELS}
    seen_any = False

    for path in docs():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if ROSTER_MARKER not in line:
                continue
            seen_any = True
            where = f"{path.relative_to(ROOT).as_posix()}:{lineno}"

            stated = {}
            for chunk in line.split(ROSTER_MARKER, 1)[1].split("·"):
                m = re.match(r"\s*(.+?)\s+(\d+)\s*$", chunk.strip().rstrip("."))
                if m:
                    stated[m.group(1).strip()] = int(m.group(2))

            for label, count in sorted(expected.items()):
                if label not in stated:
                    problems.append(f"{where}  roster omits '{label}' ({count} tests)")
                elif stated[label] != count:
                    problems.append(
                        f"{where}  roster says {label} {stated[label]}, source has {count}"
                    )
            for label in sorted(set(stated) - set(expected)):
                problems.append(f"{where}  roster names '{label}', which is not a suite")

    if not seen_any:
        problems.append(
            f"no roster found -- expected a line containing '{ROSTER_MARKER}' "
            f"in at least one document"
        )
    return problems


def check_completeness(t: dict) -> list[str]:
    unlabelled = sorted(set(t["by_name"]) - set(LABELS))
    return [
        f"tests/{name} has no label in tools/check_counts.py -- add one so it "
        f"cannot be silently left out of the docs"
        for name in unlabelled
    ]


def run_tests() -> list[str]:
    failed = []
    for path in sorted((ROOT / "tests").glob("test_*.py")):
        # Exit code only. The suites print 'ok', 'PASS', 'N passed' and
        # '13 merkle tests passed'; any parser of that text mislabels them.
        r = subprocess.run(
            [sys.executable, str(path)],
            cwd=ROOT,
            capture_output=True,
        )
        if r.returncode != 0:
            failed.append(f"tests/{path.name} exited {r.returncode}")
    return failed


def main() -> int:
    t = truth()

    if "--print-roster" in sys.argv:
        print(f"{ROSTER_MARKER} {build_roster(t)}")
        return 0

    problems = check_completeness(t) + check_totals(t) + check_roster(t)

    if "--run-tests" in sys.argv:
        problems += run_tests()

    if problems:
        print(f"Counts disagree with the source ({t['total']} tests, {t['suites']} suites).\n")
        for p in problems:
            print(f"  {p}")
        print(
            "\nFix the documents, or re-generate the roster with:\n"
            "  py -3 tools/check_counts.py --print-roster\n"
            "\nTo push anyway (it will be wrong): git push --no-verify"
        )
        return 1

    print(f"counts agree: {t['total']} tests across {t['suites']} suites")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Rewrite every stated count in the documentation from the live report.

This exists because the counts have shipped stale twice. Both times the cause was the same:
a number was typed once, the code moved, and nothing connected the two. A count that a human
maintains is a count that is wrong; the only question is when someone notices.

Two rules, learned from those two failures:

  1. **Rewrite by pattern, never by guessing the previous value.** Searching for the old number
     works until a document disagrees with the one you remembered, and then it silently skips.
  2. **Fail loudly.** The previous scripts died mid-run and the commit went out anyway. This one
     exits non-zero on any residual mismatch, so a broken sync cannot look like a clean one.

Run:  py -3 tools/sync_docs.py [--check]
      --check verifies without writing, which is what a pre-commit hook wants.
"""

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from blindkeep.status import summary  # noqa: E402

# The label each suite is called by in prose. A suite missing from here is a hard error rather
# than a silent omission — that asymmetry is the whole point of the file.
LABELS = {
    "test_merkle.py": "Merkle",
    "test_store.py": "store",
    "test_metadata.py": "metadata",
    "test_adversarial.py": "adversarial",
    "test_replication.py": "replication",
    "test_recovery.py": "recovery",
    "test_hardening.py": "hardening",
    "test_discover.py": "discovery",
    "test_audit.py": "audit",
    "test_ollama_mem.py": "local-model memory",
    "test_cloud_gate.py": "cloud gate",
    "test_cli.py": "CLI",
    "test_console.py": "console",
    "test_vault_proxy.py": "vault proxy",
    "test_attest.py": "attestation",
    "test_memory_gate.py": "memory gate",
    "test_sev_snp.py": "SEV-SNP",
    "test_status.py": "status",
    "test_zk.py": "zk",
    "test_zk_keep.py": "zk-keep",
    "test_poseidon.py": "poseidon",
    "test_delegate.py": "delegate",
    "test_anon_token.py": "anon-token",
    "test_private_read.py": "private read",
    "test_witness.py": "witness",
}

DOCS = ["README.md", "WHITEPAPER.md", "SECURITY.md", "COORDINATION.md",
        "GRANT_ONE_PAGER.md", "GRANT_PROPOSAL.md", "GRANT_ZCG_ZK.md",
        "HANDOFF_NEXT_TODOS.md"]

# A per-suite count is a small number next to a suite's name; a total is a large one standing
# alone. Anything at or above this is treated as a claim about the whole project.
TOTAL_FLOOR = 100


def live():
    s = summary(ROOT)
    counts = {f["name"]: f["tests"] for f in s["tests"]["files"]}
    missing = set(counts) - set(LABELS)
    if missing:
        raise SystemExit(
            f"sync_docs: {sorted(missing)} have no prose label. Add them to LABELS — a suite "
            f"that is not named here would be silently left out of the roster.")
    return s["tests"]["total"], s["tests"]["suites"], len(s["modules"]), counts


def roster(counts, keep=()):
    """The `·`-separated enumeration, regenerated so it cannot drift or omit.

    `keep` carries through entries that have no number — "sealed-tier composition" is a real
    claim about what is covered and is not a suite, so regenerating from LABELS alone would
    quietly delete it.
    """
    numbered = [f"{LABELS[n]} {counts[n]}"
                for n in sorted(counts, key=lambda n: LABELS[n].lower())]
    return " · ".join(numbered + list(keep))


def _replace_roster(line, counts):
    """Rewrite the roster on one line, bounded by the em-dash and the end of the line.

    Bounded, not chained. The chained version — a run of `label N` groups joined by ` · ` —
    matched a *portion* of the roster whenever one entry lacked a number, so substituting left
    the unmatched tail in place and duplicated everything before it.
    """
    head, sep, tail = line.rpartition("— ")
    if not sep or tail.count(" · ") < 4:
        return line
    body = tail.rstrip()
    trailing = "." if body.endswith(".") else ""
    entries = [e.strip() for e in body.rstrip(".").split(" · ")]
    unnumbered = [e for e in entries if not re.search(r" \d+$", e)]
    return f"{head}{sep}{roster(counts, unnumbered)}{trailing}"


def rewrite(text, total, suites, mods, counts):
    # Totals, in prose and in the shields.io badge URL. The badge is the reason this is done by
    # pattern: its number lives inside a URL-encoded string, so a search for "416 tests" updated
    # the alt text beside it and left the image itself reading the old value.
    text = re.sub(r"\b\d{%d,} tests\b" % len(str(TOTAL_FLOOR)), f"{total} tests", text)
    text = re.sub(r"tests-\d+%20passing", f"tests-{total}%20passing", text)
    text = re.sub(r"\b\d+ tests passing\b", f"{total} tests passing", text)
    text = re.sub(r"\b\d+ suites\b", f"{suites} suites", text)
    text = re.sub(r"\b\d+ modules\b", f"{mods} modules", text)
    # The roster line, regenerated wholesale rather than patched entry by entry.
    text = "\n".join(_replace_roster(line, counts) for line in text.split("\n"))
    return text


def check(total, suites, mods, counts):
    """Every residual disagreement, with a file:line, or nothing."""
    problems = []
    for p in sorted(ROOT.glob("*.md")) + sorted((ROOT / "docs").glob("*.md")):
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            for n in re.findall(r"\b(\d+) tests\b", line):
                if int(n) >= TOTAL_FLOOR and int(n) != total:
                    problems.append(f"{p.name}:{i} claims {n} tests, live total is {total}")
            for n in re.findall(r"tests-(\d+)%20passing", line):
                if int(n) != total:
                    problems.append(f"{p.name}:{i} badge reads {n}, live total is {total}")
            for n in re.findall(r"\b(\d+) suites\b", line):
                if int(n) != suites:
                    problems.append(f"{p.name}:{i} claims {n} suites, live is {suites}")
            # Per-suite counts, wherever a suite is named with a number after it.
            # finditer, not search: a line can name the same suite twice, and the version of
            # this check that stopped at the first match reported a clean sync over a line
            # that read "anon-token 16 · ... · anon-token 15".
            for name, label in LABELS.items():
                for m in re.finditer(rf"\b{re.escape(label)} (\d+)\b", line):
                    if int(m.group(1)) != counts[name]:
                        problems.append(
                            f"{p.name}:{i} says {label} {m.group(1)}, live is {counts[name]}")
    return problems


def main(argv=None):
    # The roster separator is "·", and a Windows console defaults to a codepage that cannot
    # encode it. Guard the entry point, not the call sites: this has bitten three times, each
    # time in a tool that read fine in a terminal and garbled into whatever consumed it.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

    args = argparse.ArgumentParser()
    args.add_argument("--check", action="store_true", help="verify only; write nothing")
    opts = args.parse_args(argv)

    total, suites, mods, counts = live()
    print(f"live: {total} tests · {suites} suites · {mods} modules")

    if not opts.check:
        touched = []
        for name in DOCS:
            p = ROOT / name
            if not p.is_file():
                continue
            before = p.read_text(encoding="utf-8")
            after = rewrite(before, total, suites, mods, counts)
            if after != before:
                p.write_text(after, encoding="utf-8")
                touched.append(name)
        print(f"rewritten: {', '.join(touched) if touched else 'nothing needed'}")

    problems = check(total, suites, mods, counts)
    if problems:
        print(f"\n{len(problems)} stale count(s) remain — these need a human:")
        for p in problems:
            print(f"    {p}")
        return 1
    print("verified: every stated count matches the live report")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

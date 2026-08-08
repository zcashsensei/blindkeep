"""What this repository actually contains, counted rather than claimed.

Published test counts here have drifted five times. Every one of those drifts
happened the same way: a number was typed into a document, more work shipped,
and nobody went back. A number this module computes on every run cannot drift —
so if a document and `blindkeep status` disagree, **the document is wrong.**

Two design rules, both learned from the failures they prevent:

**Enumerate, never list.** The dashboard this replaced kept a hardcoded tuple of
nine module names beside a directory glob for tests. The glob stayed current for
months; the tuple showed nine of sixteen modules and none of the memory-path
work. When one function builds two rosters and only one is a glob, the typed one
is already stale.

**Detect the negatives too.** A status report that can only say "done" is a
brochure. Whether the SEV-SNP verifier is *enabled* is read from the live
registry rather than asserted here, so it flips on its own the day someone
validates it against real hardware — and stays honest until then.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

PACKAGE = "blindkeep"
TESTS = "tests"


def _root(root: Optional[Path] = None) -> Path:
    return Path(root) if root else Path(__file__).resolve().parent.parent


def count_tests(root: Optional[Path] = None) -> dict[str, Any]:
    """Count test functions by reading them. The authoritative total."""
    tests_dir = _root(root) / TESTS
    suites, total = [], 0
    if tests_dir.is_dir():
        for p in sorted(tests_dir.glob("test_*.py")):
            try:
                n = sum(1 for line in
                        p.read_text(encoding="utf-8", errors="replace").splitlines()
                        if line.startswith("def test_"))
            except OSError:
                continue
            suites.append({"name": p.name, "tests": n})
            total += n
    return {"total": total, "suites": len(suites), "files": suites}


def list_modules(root: Optional[Path] = None) -> list[dict[str, Any]]:
    """Every module in the package. Enumerated, so nothing can be omitted."""
    pkg = _root(root) / PACKAGE
    if not pkg.is_dir():
        return []
    return [{"name": p.name, "bytes": p.stat().st_size}
            for p in sorted(pkg.glob("*.py"))]


def _sev_snp_enabled() -> bool:
    """Read the live registry rather than assert a value.

    The real SEV-SNP verifier exists but is deliberately excluded from the
    default registry until it has been checked against a report from real
    hardware. Reading the registry means this line becomes true by itself on
    the day that changes, and cannot be true before.
    """
    try:
        from .attest import default_registry
        from .sev_snp import SevSnpVerifier
        return isinstance(default_registry().get("sev-snp"), SevSnpVerifier)
    except Exception:
        return False


def capabilities(root: Optional[Path] = None) -> list[dict[str, Any]]:
    """Implemented capabilities, each detected from what is on disk."""
    r = _root(root)
    pkg, tests_dir = r / PACKAGE, r / TESTS

    def mod(*names):
        return all((pkg / n).is_file() for n in names)

    def suite(*names):
        return all((tests_dir / n).is_file() for n in names)

    rows = [
        ("Merkle + tests", mod("merkle.py") and suite("test_merkle.py")),
        ("Store / node / CLI", mod("store.py", "node.py", "client.py", "cli.py")),
        ("Adversarial tests", suite("test_adversarial.py")),
        ("Replication", mod("replica.py") and suite("test_replication.py")),
        ("Peer discovery", mod("discover.py") and suite("test_discover.py")),
        ("Retrieval audits", mod("audit.py") and suite("test_audit.py")),
        ("Key recovery", mod("recovery.py") and suite("test_recovery.py")),
        ("Local-model memory", mod("ollama_mem.py") and suite("test_ollama_mem.py")),
        ("Gated cloud path", mod("cloud_gate.py") and suite("test_cloud_gate.py")),
        ("Pseudonymisation proxy", mod("vault_proxy.py") and suite("test_vault_proxy.py")),
        ("Delegated inference (abstraction + gate)", mod("delegate.py") and suite("test_delegate.py")),
        ("Anonymous entitlement (blind signatures)", mod("anon_token.py")
         and suite("test_anon_token.py")),
        ("SEALED tier: abstraction AND attestation", mod("delegate.py", "attest.py",
         "memory_gate.py") and suite("test_delegate.py", "test_memory_gate.py")),
        ("Attestation (5 checks)", mod("attest.py") and suite("test_attest.py")),
        ("Memory gate (tiers)", mod("memory_gate.py") and suite("test_memory_gate.py")),
        ("ZK property proofs (sigma)", mod("zk.py") and suite("test_zk.py")),
        ("ZK membership in the keep", mod("zk_keep.py") and suite("test_zk_keep.py")),
        ("Poseidon tree (circuit-compatible)", mod("poseidon.py", "zk_tree.py")
         and suite("test_poseidon.py")),
        ("Access-pattern privacy (trivial PIR)", mod("private_read.py")
         and suite("test_private_read.py")),
        ("Timing + size privacy (constant-rate dispatch)", mod("dispatch.py")
         and suite("test_dispatch.py")),
        ("Equivocation detection + gossip", mod("witness.py")
         and suite("test_witness.py")),
        # The SNARK had no row here for as long as it existed, and the documentation drifted
        # into saying there was no SNARK in the repository while the circuit was proving and
        # verifying in CI. What the status report cannot see, the docs eventually contradict.
        ("Succinct membership circuit (halo2)", _circuit_present(r)),
        ("SEV-SNP verifier written", mod("sev_snp.py") and suite("test_sev_snp.py")),
        ("SEV-SNP enabled by default", _sev_snp_enabled()),
    ]
    return [{"label": label, "ok": bool(ok)} for label, ok in rows]


def _circuit_present(root: Path) -> bool:
    """True when the halo2 crate is on disk and actually proves, rather than merely existing.

    Detected, not asserted: a `merkle.rs` that never calls `create_proof` is a circuit you can
    only run under `MockProver`, which checks constraint satisfaction and generates no proof.
    That distinction is the whole claim, so it is the thing checked.
    """
    src = root / "circuits" / "src"
    merkle = src / "merkle.rs"
    if not merkle.is_file() or not (root / "circuits" / "Cargo.toml").is_file():
        return False
    text = merkle.read_text(encoding="utf-8", errors="replace")
    return "create_proof" in text and "verify_proof" in text


# Milestones that no file can prove. Kept deliberately short and next to the
# README's "not claimed as shipping" list, because a status report that only
# says "done" is a brochure. Anything here that becomes detectable should move
# into `capabilities()` and stop being a written line.
NOT_CLAIMED = [
    "SEV-SNP validated against real hardware — see docs/SEV_SNP_VALIDATION.md",
    "Run by anyone other than the author (milestone M1)",
    "Equivocation PREVENTION — detection and proof exist; stopping it needs consensus",
    "Proof of storage, as distinct from retrieval auditing",
    "Sub-linear private retrieval — trivial PIR works and costs the whole keep",
    "Integrity of the client's own machine — no server-side measure reaches it",
    "Sender anonymity when sending DIRECT — the provider's API key is an account identity, "
    "and constant-rate dispatch hides when and which, never whose key",
    "Network-layer identity — dispatch does not touch IP or TLS fingerprint",
    "An independent relay — a relay you operate yourself sees both IP and timing, "
    "so it correlates rather than separates them",
]


def summary(root: Optional[Path] = None) -> dict[str, Any]:
    return {
        "tests": count_tests(root),
        "modules": list_modules(root),
        "capabilities": capabilities(root),
        "not_claimed": list(NOT_CLAIMED),
    }


def render(root: Optional[Path] = None) -> str:
    s = summary(root)
    t = s["tests"]
    out = [
        "",
        f"  {t['total']} tests across {t['suites']} suites   (counted, not stated)",
        f"  {len(s['modules'])} modules",
        "",
    ]
    for row in s["capabilities"]:
        out.append(f"  {'OK' if row['ok'] else '..'}  {row['label']}")
    out.append("")
    out.append("  Not claimed:")
    for item in s["not_claimed"]:
        out.append(f"      - {item}")
    out.append("")
    out.append("  If a document disagrees with this, the document is wrong.")
    out.append("")
    return "\n".join(out)


def main(argv: Optional[list[str]] = None) -> int:
    import argparse

    p = argparse.ArgumentParser(description="What this repository contains")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    print(json.dumps(summary(), indent=2) if args.json else render())
    return 0

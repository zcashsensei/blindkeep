"""Retrieval auditing.

Integrity proofs show that what a node returns is genuine. They say nothing
about whether it will return anything at all. A node can pass every
cryptographic check and still be useless by quietly dropping data or going dark.

An audit samples records a node claims to hold, fetches them, and runs the full
client verification on each. The result separates three outcomes that a naive
uptime check would conflate:

* **offline** — the node did not answer. Unreliable, not dishonest.
* **failed** — the node answered but the record was missing or unreadable.
* **security failure** — the node answered with something that failed a
  cryptographic check. That is misbehaviour, and it is reported separately
  because it warrants a different response: drop the node, do not retry it.

**What this is not.** This is challenge-response retrieval, not a proof of
storage. It shows a node served the data *at the time of asking*. A node could
in principle fetch a record from elsewhere on demand and pass. Distinguishing
"stores" from "can obtain" needs proof-of-replication of the kind Filecoin
implements, which is a substantially larger undertaking and is not claimed here.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from .client import OblivioClient, SecurityError

DEFAULT_SAMPLE = 5


@dataclass
class Challenge:
    record_id: str
    ok: bool
    ms: float
    error: str = ""
    security_failure: bool = False


@dataclass
class AuditResult:
    url: str
    challenges: int = 0
    passed: int = 0
    failed: int = 0
    security_failures: int = 0
    offline: bool = False
    error: str = ""
    samples: list[Challenge] = field(default_factory=list)
    tree_size: Optional[int] = None

    @property
    def score(self) -> float:
        """Fraction of challenges answered correctly. 0.0 when unreachable."""
        return (self.passed / self.challenges) if self.challenges else 0.0

    @property
    def median_ms(self) -> float:
        if not self.samples:
            return 0.0
        vals = sorted(c.ms for c in self.samples)
        mid = len(vals) // 2
        return vals[mid] if len(vals) % 2 else (vals[mid - 1] + vals[mid]) / 2

    @property
    def trustworthy(self) -> bool:
        """A single cryptographic failure disqualifies a node.

        Availability is a matter of degree; honesty is not. A node that served
        one unverifiable answer has demonstrated it can, and no proportion of
        correct answers offsets that.
        """
        return self.security_failures == 0 and not self.offline

    def summary(self) -> str:
        if self.offline:
            return f"{self.url}  OFFLINE  ({self.error})"
        flag = "" if self.trustworthy else "  ** SECURITY FAILURE **"
        return (f"{self.url}  score {self.score:.2f} "
                f"({self.passed}/{self.challenges})  "
                f"median {self.median_ms:.0f}ms{flag}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "score": round(self.score, 4),
            "challenges": self.challenges,
            "passed": self.passed,
            "failed": self.failed,
            "security_failures": self.security_failures,
            "offline": self.offline,
            "trustworthy": self.trustworthy,
            "median_ms": round(self.median_ms, 2),
            "tree_size": self.tree_size,
            "error": self.error,
            "samples": [
                {"record_id": c.record_id, "ok": c.ok, "ms": round(c.ms, 2),
                 "error": c.error, "security_failure": c.security_failure}
                for c in self.samples
            ],
        }


def audit_node(client: OblivioClient,
               record_ids: Optional[list[str]] = None,
               sample_size: int = DEFAULT_SAMPLE,
               rng: Optional[random.Random] = None) -> AuditResult:
    """Challenge one node on a random sample of the records it claims to hold."""
    result = AuditResult(url=client.base_url)
    rng = rng or random.SystemRandom()

    if record_ids is None:
        try:
            head = client.head()
            result.tree_size = head.get("tree_size")
            record_ids = [r["record_id"] for r in client.list()]
        except SecurityError as exc:
            result.security_failures += 1
            result.error = str(exc)
            return result
        except Exception as exc:
            result.offline = True
            result.error = f"{type(exc).__name__}: {exc}"
            return result

    if not record_ids:
        result.error = "node holds no records to audit"
        return result

    # Sample rather than sweep: the point is to make cheating unprofitable, and
    # a node cannot predict which records it will be asked for.
    chosen = (rng.sample(record_ids, sample_size)
              if len(record_ids) > sample_size else list(record_ids))

    for rid in chosen:
        t0 = time.perf_counter()
        try:
            client.get_by_id(rid)
            ms = (time.perf_counter() - t0) * 1000
            result.samples.append(Challenge(rid, True, ms))
            result.passed += 1
        except SecurityError as exc:
            ms = (time.perf_counter() - t0) * 1000
            result.samples.append(Challenge(rid, False, ms, str(exc), True))
            result.security_failures += 1
            result.failed += 1
        except Exception as exc:
            ms = (time.perf_counter() - t0) * 1000
            result.samples.append(
                Challenge(rid, False, ms, f"{type(exc).__name__}: {exc}"))
            result.failed += 1
        result.challenges += 1

    return result


def audit_peers(urls: list[str], master_key: bytes, pin_dir: str,
                record_ids: Optional[list[str]] = None,
                sample_size: int = DEFAULT_SAMPLE) -> list[AuditResult]:
    """Audit several nodes. Each is judged on its own answers."""
    import concurrent.futures
    import os

    os.makedirs(pin_dir, exist_ok=True)
    from .replica import _pin_name

    def one(url: str) -> AuditResult:
        client = OblivioClient(url, master_key,
                                 pin_path=os.path.join(pin_dir, _pin_name(url)))
        try:
            return audit_node(client, record_ids, sample_size)
        except Exception as exc:
            return AuditResult(url=url, offline=True,
                               error=f"{type(exc).__name__}: {exc}")

    if not urls:
        return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(urls))) as pool:
        return list(pool.map(one, urls))


def rank(results: list[AuditResult]) -> list[AuditResult]:
    """Order nodes best-first: honest before fast, fast before slow."""
    return sorted(results,
                  key=lambda r: (not r.trustworthy, -r.score, r.median_ms))

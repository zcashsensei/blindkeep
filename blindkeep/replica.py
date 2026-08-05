"""Multi-node replication.

A single node can be verified but not survived. If it goes offline, refuses to
serve, or is seized, integrity proofs do not return the data. Replication adds
availability and cross-operator agreement to the guarantees the single-node
client already provides.

Design notes:

* **Encrypt once, upload identical bytes.** Every node receives byte-identical
  ciphertext, so every node commits to the same leaf hash. Divergence between
  nodes is then directly observable.

* **Address records by identifier, not index.** A record's index is a property
  of one node's log. If a write fails on one node, indices diverge permanently.
  The record identifier is chosen by the client and is stable everywhere.

* **Every node is verified independently before its answer is counted.** A node
  that fails a cryptographic check is excluded from the vote rather than being
  allowed to influence it.

* **Quorum is agreement, not availability.** A response is returned only when
  enough independently verified nodes produce the *same* plaintext.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import os
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

from .client import BlindkeepClient, SecurityError
from .store import client_encrypt


class ReplicationError(Exception):
    """Not enough nodes could satisfy the request."""


class DivergenceError(Exception):
    """Verified nodes returned conflicting content for the same record.

    This is not a transient failure. Each node proved its answer was in a log
    it signed, so a conflict means at least one operator is dishonest or a
    write was not applied uniformly.
    """


@dataclass
class NodeResult:
    url: str
    ok: bool
    value: Any = None
    error: str = ""
    security_failure: bool = False


@dataclass
class ReplicaStatus:
    url: str
    reachable: bool
    tree_size: Optional[int] = None
    root_hex: Optional[str] = None
    pubkey_hex: Optional[str] = None
    error: str = ""
    security_failure: bool = False


@dataclass
class PutReceipt:
    record_id: str
    leaf_hex: str
    placements: dict = field(default_factory=dict)   # url -> index
    failures: dict = field(default_factory=dict)     # url -> error
    quorum: int = 0
    written: int = 0
    nodes: int = 0


def _pin_name(url: str) -> str:
    """Stable, filesystem-safe pin filename for a node URL."""
    host = urlparse(url).netloc or url
    safe = "".join(c if c.isalnum() or c in "-._" else "_" for c in host)
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:8]
    return f"pin-{safe}-{digest}.json"


class ReplicatedClient:
    """A client that writes to and reads from several independent nodes."""

    def __init__(
        self,
        urls: list[str],
        master_key: bytes,
        pin_dir: str,
        quorum: Optional[int] = None,
        timeout_workers: int = 8,
    ):
        if not urls:
            raise ValueError("at least one node URL is required")
        self.urls = [u.rstrip("/") for u in urls]
        self.master_key = master_key
        self.pin_dir = pin_dir
        os.makedirs(pin_dir, exist_ok=True)
        # Default to a strict majority: the smallest number that cannot be
        # satisfied by two conflicting groups at once.
        self.quorum = quorum if quorum is not None else (len(self.urls) // 2 + 1)
        if not 1 <= self.quorum <= len(self.urls):
            raise ValueError(
                f"quorum {self.quorum} must be between 1 and {len(self.urls)}")
        self._workers = timeout_workers
        self.clients = {
            url: BlindkeepClient(
                url, master_key,
                pin_path=os.path.join(pin_dir, _pin_name(url)))
            for url in self.urls
        }

    # ---- fan-out -------------------------------------------------------------

    def _fanout(self, fn) -> list[NodeResult]:
        """Run fn(url, client) against every node, collecting failures.

        A cryptographic failure is recorded distinctly from an unreachable
        node: one is a broken operator, the other is an offline one, and they
        warrant different responses from an operator running this.
        """
        results: list[NodeResult] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self._workers) as pool:
            futures = {
                pool.submit(fn, url, self.clients[url]): url for url in self.urls
            }
            for fut in concurrent.futures.as_completed(futures):
                url = futures[fut]
                try:
                    results.append(NodeResult(url=url, ok=True, value=fut.result()))
                except SecurityError as exc:
                    results.append(NodeResult(url=url, ok=False, error=str(exc),
                                              security_failure=True))
                except Exception as exc:  # transport, HTTP, timeout
                    results.append(NodeResult(url=url, ok=False,
                                              error=f"{type(exc).__name__}: {exc}"))
        results.sort(key=lambda r: self.urls.index(r.url))
        return results

    # ---- writes --------------------------------------------------------------

    def put(self, plaintext: bytes | str, label: str = "") -> PutReceipt:
        """Encrypt once and replicate the identical ciphertext to every node."""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        record_id, ciphertext = client_encrypt(self.master_key, plaintext, label=label)

        results = self._fanout(
            lambda url, c: c.put_ciphertext(record_id, ciphertext, label=label))

        receipt = PutReceipt(record_id=record_id, leaf_hex="",
                             quorum=self.quorum, nodes=len(self.urls))
        leaves = set()
        for r in results:
            if r.ok:
                receipt.placements[r.url] = r.value["index"]
                leaves.add(r.value["leaf_hex"])
            else:
                receipt.failures[r.url] = r.error
        receipt.written = len(receipt.placements)

        # Identical input must produce an identical commitment everywhere.
        if len(leaves) > 1:
            raise DivergenceError(
                f"nodes committed different leaves for one ciphertext: {sorted(leaves)}")
        receipt.leaf_hex = leaves.pop() if leaves else ""

        if receipt.written < self.quorum:
            raise ReplicationError(
                f"wrote to {receipt.written}/{len(self.urls)} nodes, "
                f"quorum is {self.quorum}. Failures: {receipt.failures}")
        return receipt

    # ---- reads ---------------------------------------------------------------

    def get(self, record_id: str, label: Optional[str] = None) -> dict[str, Any]:
        """Read from every node, verify each, and return only on agreement."""
        results = self._fanout(
            lambda url, c: c.get_by_id(record_id, label=label))

        verified = {r.url: r.value for r in results if r.ok}
        failures = {r.url: r.error for r in results if not r.ok}
        compromised = [r.url for r in results if r.security_failure]

        if not verified:
            raise ReplicationError(
                f"no node served record {record_id}. Failures: {failures}")

        # Tally by plaintext. Nodes that failed verification never reach here.
        tally: dict[bytes, list[str]] = {}
        for url, rec in verified.items():
            tally.setdefault(rec["plaintext"], []).append(url)

        winner, backers = max(tally.items(), key=lambda kv: len(kv[1]))

        if len(tally) > 1 and len(backers) < self.quorum:
            raise DivergenceError(
                f"record {record_id}: verified nodes disagree and no group "
                f"reached quorum {self.quorum}. Groups: "
                f"{[(len(v), sorted(v)) for v in tally.values()]}")

        if len(backers) < self.quorum:
            raise ReplicationError(
                f"record {record_id}: only {len(backers)}/{self.quorum} nodes "
                f"agreed. Failures: {failures}")

        sample = verified[backers[0]]
        return {
            "record_id": record_id,
            "plaintext": winner,
            "label": sample.get("label", ""),
            "agreement": len(backers),
            "verified_nodes": len(verified),
            "nodes": len(self.urls),
            "quorum": self.quorum,
            "agreed_by": sorted(backers),
            "dissenting": sorted(
                u for group in tally.values() if group is not backers for u in group),
            "failures": failures,
            "security_failures": compromised,
        }

    # ---- operations ----------------------------------------------------------

    def status(self) -> list[ReplicaStatus]:
        """Fetch and verify every node's head, checking append-only behaviour."""
        results = self._fanout(lambda url, c: c.head())
        out = []
        for r in results:
            if r.ok:
                out.append(ReplicaStatus(
                    url=r.url, reachable=True,
                    tree_size=r.value["tree_size"],
                    root_hex=r.value["root_hex"],
                    pubkey_hex=r.value["public_key_hex"]))
            else:
                # A node that did not answer is not reachable, whatever the
                # reason. security_failure additionally distinguishes a node
                # that answered dishonestly from one that is merely down.
                out.append(ReplicaStatus(
                    url=r.url, reachable=False,
                    error=r.error, security_failure=r.security_failure))
        return out

    def healthy(self) -> bool:
        """True when enough nodes are verified and reachable to serve a read."""
        return sum(1 for s in self.status() if s.reachable and not s.security_failure) \
            >= self.quorum

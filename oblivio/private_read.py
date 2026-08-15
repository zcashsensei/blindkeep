"""Read a record without telling the node which one — and pad what remains visible.

`SECURITY.md` names access pattern as the one privacy gap a cipher cannot close: encryption hides
*what* a record says, and a `get(index)` still tells the node *which* record you wanted and when.

The construction that closes it is private information retrieval, and for a single server the
answer is blunt: **fetch everything, choose locally.** That is not a placeholder for a cleverer
scheme. Chor proved any information-theoretically private single-server retrieval must transfer
at least the whole database, so downloading it is not merely *a* solution — it is the optimal
one, and measured comparisons keep finding that computational PIR schemes run slower than the
trivial fetch they were meant to replace. Cleverness here needs *more servers*, not better maths.

    get(index)          O(1) bandwidth, the node learns which record
    read_private(index) O(n) bandwidth, the node learns nothing beyond "a read happened"

So the cost is honest and unavoidable, and the module says so rather than implying a free lunch.
Both calls remain, because a keep of forty records should use the private one and a keep of forty
thousand cannot.

**What is still visible, and what `pad` does about it.** Fetching everything hides *which*, never
*that*: the node still sees a read occurred, how large the log is, and when each record arrived.
Record count and write timing are not access-pattern leaks and are not fixed by PIR — they are
fixed, partially, by writing records that mean nothing. `pad_writes` does that deliberately, and
its limits are stated where it is defined.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from typing import Any, Optional, Sequence

# Beyond this, fetching the whole log to read one record stops being reasonable and the caller
# should be told rather than left waiting. Not a security boundary — a usability one.
DEFAULT_MAX_RECORDS = 2000


class RetrievalError(Exception):
    """The private read could not be performed. Nothing was fetched."""


@dataclass
class PrivateRead:
    """A record, and an honest account of what the node learned while serving it."""
    index: int
    label: str
    plaintext: bytes
    fetched: int
    bytes_transferred: int

    def cost(self) -> str:
        return (f"fetched {self.fetched} records ({self.bytes_transferred} bytes) to read one — "
                f"the node cannot tell which")


def read_private(client, index: int, max_records: int = DEFAULT_MAX_RECORDS) -> PrivateRead:
    """Fetch the whole log, return one record, and let the node learn nothing about which.

    Every record is verified on the way past exactly as a normal `get` would be, so this trades
    bandwidth for privacy and gives up no integrity: a node that tampers with any record is still
    caught, and one that tampers with the record you wanted is caught for the same reason.
    """
    records = client.list()
    if len(records) > max_records:
        raise RetrievalError(
            f"this keep holds {len(records)} records; fetching all of them to read one is "
            f"{len(records)}x the bandwidth of an ordinary read. Raise max_records to accept "
            f"that, or use client.get() and accept that the node learns which record you wanted. "
            f"There is no third option against a single server.")
    if not 0 <= index < len(records):
        raise RetrievalError(f"index {index} is outside a keep of {len(records)} records")

    wanted: Optional[PrivateRead] = None
    total = 0
    for i in range(len(records)):
        rec = client.get(i)
        total += len(rec.get("plaintext", b""))
        if i == index:
            wanted = PrivateRead(index=i, label=rec.get("label", ""),
                                 plaintext=rec["plaintext"], fetched=0, bytes_transferred=0)

    if wanted is None:                       # unreachable given the bounds check above
        raise RetrievalError("the requested record was not returned by the node")
    wanted.fetched = len(records)
    wanted.bytes_transferred = total
    return wanted


def read_private_by_label(client, label: str,
                          max_records: int = DEFAULT_MAX_RECORDS) -> list[PrivateRead]:
    """Every record carrying `label`, selected locally.

    Labels live inside the ciphertext, so this filter cannot be pushed to the node even in
    principle — which is why it is a natural fit here rather than an added cost.
    """
    out = []
    for i in range(len(client.list())):
        r = read_private(client, i, max_records=max_records)
        if r.label == label:
            out.append(r)
    return out


# ---- what PIR does not cover ------------------------------------------------


def pad_writes(client, count: int, size: int = 256, label: str = "") -> int:
    """Write `count` records of random bytes, so the log's length means less.

    Record count and write timing are visible for a reason no cipher addresses: they are
    properties of the conversation, not of its contents. A keep that grows by exactly one record
    each time something happens is a log of when things happened.

    **This is cover, not concealment.** It raises the count and blurs the timing; it does not make
    them meaningless, and a node that watches long enough can still see the shape of real activity
    underneath a constant rate of padding. Padding written in a burst is worse than useless — it
    announces exactly when the burst was — so a caller who cares should spread it, and this
    function will not pretend to do that for them.

    Padding records are indistinguishable from real ones to the node, because everything is
    ciphertext of a fixed-bucket size either way. They are distinguishable to *you*: they carry
    the label given here, so `read_private_by_label` can ignore them.
    """
    if count < 0:
        raise RetrievalError("cannot write a negative number of padding records")
    for _ in range(count):
        client.put(secrets.token_bytes(size), label=label)
    return count


def visibility(client) -> dict[str, Any]:
    """What the node can still see. Written as a report because it is not fixable, only known.

    Every entry here is true after `read_private`, and saying so plainly is the point: a privacy
    feature that leaves the user unsure what remains has not finished doing its job.
    """
    head = client.head()
    return {
        "record_count": int(head["tree_size"]),
        "which_record_was_read": "hidden by read_private; visible to client.get()",
        "when_records_were_written": "visible — creation times are in the log",
        "record_contents": "hidden — AES-256-GCM, and labels are inside the ciphertext",
        "record_sizes": "bucketed to 256 bytes, so exact lengths are hidden",
        "that_a_read_happened": "visible, and not addressable by any single-server scheme",
    }

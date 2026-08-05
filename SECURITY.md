# Security

**Version 0.1 · 2026-08-05 · applies to Blindkeep v0 alpha**

## Threat model

A Blindkeep storage node is **untrusted for both confidentiality and integrity**.
It is assumed to be capable of reading everything it stores, altering it,
withholding it, lying about it, and colluding with other nodes.

Every value the client returns has passed five checks:

| # | Check | Defeats |
|---|-------|---------|
| 1 | Response bound to the **request** | Answering a different question than the one asked |
| 2 | Ed25519 signature over `(tree_size, root)` | A forged or unsigned log state |
| 3 | Merkle **inclusion** proof | Serving a record it never committed to |
| 4 | Merkle **consistency** proof against a pinned head | Rewriting, reordering or dropping history |
| 5 | AES-256-GCM authenticated decryption | Any modification of the ciphertext |

Any check failing raises rather than returning data.

## Metadata minimisation

Encryption protects contents. Two further leaks are closed by how records are
framed before encryption:

- **Labels are encrypted with the record.** They were previously stored in
  plaintext on the node. A label is the piece of metadata a user is most likely
  to make descriptive — "medical", "passwords", "keys" — so leaving it readable
  undermined the guarantee the rest of the design provides. It now travels
  inside the AEAD, meaning the node can neither read it nor alter it, and it
  cannot be transplanted from one record onto another's contents.
- **Records are padded to 256-byte buckets** before encryption, so a stored
  length reveals a bucket rather than an exact size. Overhead is bounded at
  under one block per record.

Both are covered by `tests/test_metadata.py`, which searches the node's on-disk
state for the label as a canary and checks that payloads of 1 to 200 bytes are
indistinguishable by length.

## What is not protected

Stated plainly, because a security README that only lists strengths is not a
security README:

- **Access patterns.** The node observes *which* record is requested and when.
  This is the one privacy gap that encryption cannot close; it requires private
  information retrieval, which is not implemented.
- **Record count and creation timestamps** remain visible.
- **Availability.** A node can refuse to serve data. Integrity guarantees do not
  imply retrievability.
- **Equivocation.** A node showing different histories to different clients is
  not yet detectable; that requires gossip between clients or independent
  witnesses.
- **The client's own machine.** Compromised client software or a stolen
  `master.key` defeats everything above.

## Key recovery

Key loss was previously unrecoverable. That is a correct cryptographic property
and a fatal product defect, so three client-side recovery mechanisms exist. No
node participates in any of them: a recovery path that asks a server for help
would return the trust the rest of the design removes.

| Mechanism | Guards against | Its weakest link |
|-----------|----------------|------------------|
| Recovery code | Disk failure, device loss | Anyone reading the paper holds everything |
| Passphrase-wrapped backup | Losing the paper | The passphrase (scrypt, N=2^17) |
| `k`-of-`n` Shamir shares | Losing any single thing | `k` holders colluding |

All three protect the same 32-byte secret, so **the weakest mechanism actually
in use sets the security of the store**. A recovery code left in a desk drawer
is equivalent to leaving the key there.

Fewer than `k` shares are information-theoretically independent of the key.
Codes and shares carry checksums, so a transcription error is rejected rather
than silently producing a wrong key — the dangerous failure mode is not
"recovery failed" but "recovery appeared to succeed".

## Fixed vulnerabilities

All four were found by running genuinely malicious nodes against the real
client, not by reading the code. Each now has a regression test.

| # | Vulnerability | Impact | Test |
|---|---------------|--------|------|
| 1 | The client never compared the returned **index** to the requested one | A node asked for index 0 could serve index 1 together with index 1's authentic, valid inclusion proof. Every cryptographic check passed and the wrong record was returned as verified. | `test_index_substitution_detected` |
| 2 | Same omission for **record id** | Identical substitution through the lookup-by-id path. | `test_record_id_substitution_detected` |
| 3 | Head pinning compared **tree size only** | Equal size with a different root is a fork. No consistency proof can exist for one, so a size-only comparison passed silently and overwrote the pin. | `test_equal_size_fork_detected` |
| 4 | Label defaulted to empty while being used as **AEAD associated data** | A record stored with a label could not be decrypted by its owner. The fix defaults to the node-reported label, which makes it *authenticated* — a node that lies about a label now fails the GCM tag. | `test_labelled_record_is_readable` |

A node identity that changes relative to a pinned head is also now rejected.

### The generalised lesson

> **A valid proof is not an answer to your question.**

Vulnerabilities 1 and 2 shared a root cause: the client verified that a response
was internally *self-consistent* and never verified that it was *responsive to
the request*. Those are different properties, and only the second is what a
caller actually wants. Vulnerability 3 is the same error in another register — a
scalar comparison standing in for an identity check.

Every new endpoint must echo-check its request key before evaluating any proof
contained in the response.

## Operational hardening

A node accepts requests from anyone, so every bound a client could otherwise
choose is enforced by the node. Each item below was found by probing a running
node as a hostile client, and each has a regression test in
`tests/test_hardening.py`.

| Issue | Behaviour now |
|-------|---------------|
| Error text disclosed absolute filesystem paths, revealing the operating system, directory layout and account name | Unexpected errors are logged locally and reported as `internal error` |
| `Content-Length` was trusted, so one client could claim gigabytes it never sent and occupy a handler thread | Bodies above the limit are refused with `413` before any read |
| No cap on stored record size | Records above the limit are refused; nothing is written |
| `/v1/list` returned every record's metadata | Paginated with a bounded `limit` |
| Record lookup scanned the log linearly | Indexed, so lookup cost does not grow with log size |
| The client followed redirects supplied by a node | Redirects are refused |
| The client read responses without bound | Responses above the limit are refused |

### Deployment note

The reference node uses Python's `http.server` and has **no transport security
and no authentication**. Record contents are encrypted, so a network observer
learns no contents — but it observes access patterns, and any client can write.

Do not expose a node directly to the internet. Place it behind a reverse proxy
providing TLS, rate limiting and request quotas. This is a property of the
reference implementation, not a limitation of the design.

## Reporting a vulnerability

Open a security advisory through the repository's Security tab rather than a
public issue. Please include a reproduction — ideally as a failing test in the
style of `tests/test_adversarial.py`, which stands up a deliberately malicious
node and asserts the client refuses it.

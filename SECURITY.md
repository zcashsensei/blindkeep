# Security

**Version 0.3 · 2026-08-07 · applies to Blindkeep v0 alpha**

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

The first four were found by running genuinely malicious nodes against the real
client; the fifth by exercising the command line as a new user would. None came
from reading the code. Each now has a regression test.

| # | Vulnerability | Impact | Test |
|---|---------------|--------|------|
| 1 | The client never compared the returned **index** to the requested one | A node asked for index 0 could serve index 1 together with index 1's authentic, valid inclusion proof. Every cryptographic check passed and the wrong record was returned as verified. | `test_index_substitution_detected` |
| 2 | Same omission for **record id** | Identical substitution through the lookup-by-id path. | `test_record_id_substitution_detected` |
| 3 | Head pinning compared **tree size only** | Equal size with a different root is a fork. No consistency proof can exist for one, so a size-only comparison passed silently and overwrote the pin. | `test_equal_size_fork_detected` |
| 4 | Label defaulted to empty while being used as **AEAD associated data** | A record stored with a label could not be decrypted by its owner. The fix defaults to the node-reported label, which makes it *authenticated* — a node that lies about a label now fails the GCM tag. | `test_labelled_record_is_readable` |
| 5 | **Every CLI command created a master key** when none was found | A mistyped `--key` silently minted a new 32-byte secret instead of failing, so `put` encrypted under a key the user never chose and their real key could not read it back. `head` and `list`, which never use a key at all, wrote one into whatever directory they were run from; commands that then failed still left a secret behind. Only `keygen` and `recover` create key material now, and both refuse to overwrite without `--force`. | `test_no_read_command_creates_key_material` |

A node identity that changes relative to a pinned head is also now rejected.

### The generalised lessons

> **A valid proof is not an answer to your question.**

Vulnerabilities 1 and 2 shared a root cause: the client verified that a response
was internally *self-consistent* and never verified that it was *responsive to
the request*. Those are different properties, and only the second is what a
caller actually wants. Vulnerability 3 is the same error in another register — a
scalar comparison standing in for an identity check.

Every new endpoint must echo-check its request key before evaluating any proof
contained in the response.

Vulnerability 5 belongs to a different class and carries its own lesson:

> **Creating a secret must never be a side effect.**

Auto-creating a missing key reads as helpfulness and behaves as data loss. The
failure it removes — *this key does not exist* — is legible and recoverable. The
state it introduces — *a key you did not choose, holding records you cannot read*
— is neither, and it is discovered later, by someone who has already stored
something they wanted back. Where key material is concerned, prefer the error.

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

## Surfaces added since v0.1

Each new capability brought a way to attack it. Each is bounded, and each bound
has a test.

### Peer discovery

A peer list is an attractive thing to poison, because it decides who a client
talks to before any verification happens.

| Attack | Defence |
|--------|---------|
| Bootstrap names a cloud metadata address, turning clients into probes against their own infrastructure | `169.254.169.254`, `metadata.google.internal` and link-local addresses are refused outright |
| Bootstrap supplies `file://` or credentialed URLs | Only `http`/`https`, no credentials in a URL |
| Bootstrap redirects a probe elsewhere | Redirects refused |
| Bootstrap replaces a pinned node key with its own | First entry for a URL wins; a local pin cannot be displaced |
| Bootstrap returns an enormous or malformed body | Size-bounded, malformed entries skipped rather than fatal |

A peer list confers **no trust**. It supplies candidate addresses; every node is
still verified independently on use.

### Retrieval auditing

The audit distinguishes unreliable from dishonest, and treats them differently.
A single security failure disqualifies a node regardless of how many challenges
it passed: availability is a matter of degree, honesty is not. Ranking places an
honest slow node above a fast one that failed a cryptographic check.

The audit is challenge–response *retrieval*, not proof of storage. A node that
obtains a record on demand passes while storing nothing.

### Local-model memory

The endpoint must resolve to a loopback address; anything else is refused unless
a caller passes `allow_remote=True` deliberately. A test asserts the module
contains no reference to any hosted provider endpoint, so no code path there can
reach one.

### Gated hosted-model path

This path **discloses by design**, and the protection is that it cannot be
entered by accident:

- Two separate acknowledgements are required, neither defaulted on. One flag
  gets copied from a forum post without being read; two do not.
- No default module imports it. A test parses the import graph rather than
  matching text, so a passing mention in documentation is fine and an actual
  import is not.
- Provider errors never echo the request, because it carries the bearer token.
- Stored memories are never attached to a cloud request by this module.

**Redaction is not a privacy control.** It removes obvious secrets — API keys,
emails, wallet addresses, home paths — and cannot understand what is sensitive
in prose. A test asserts that `"my daughter attends St Mary's primary school"`
passes through **unchanged**, so the limitation is enforced rather than merely
documented. Treat anything sent through this path as disclosed.

### Pseudonymisation proxy

`vault_proxy.py` narrows what the gated path discloses: declared and detected
values are swapped for placeholders before the request leaves and restored in
the reply. **This reduces disclosure. It does not prevent it**, and it is not
comparable to the local-model path or to attested confidential inference.

Enforced properties:

- A declared value that survives substitution raises `LeakError` instead of
  being transmitted — a partial substitution reads as protected and is not.
- The leak check uses the *same* matcher as substitution. A guard that matches
  more loosely than the action it guards fires on correct input, and a guard
  that cries wolf gets switched off.
- Placeholders carry a per-vault random tag, so text arriving from elsewhere
  cannot forge one and have it expand into a real value on the way back.
- No default module imports it. That test enumerates the package rather than
  listing filenames, so a module added later is covered without anyone
  remembering to update the list.

Asserted limitations — these tests pass by demonstrating failure, so the claim
here cannot quietly outgrow the code:

- **Undeclared prose entities are transmitted verbatim.** Detection is
  deterministic patterns plus declared values; a regex cannot do named-entity
  recognition. `declare()` is the load-bearing part.
- **Quasi-identifiers survive and still identify.** Removing the name from
  "the only paediatric cardiologist in Truro" removes nothing.
- **Stable placeholders are a persistent pseudonym.** The provider can link
  every session mentioning `<PERSON_0>` without knowing who that is.
- **It is pseudonymisation, not anonymisation.** The mapping exists, so the
  data remains personal data under GDPR.

### Attestation of a model host

`attest.py` applies the client's refuse-on-failure discipline to the compute
side. Five checks, any failure raises, and there is no return value meaning
"partly attested".

The check worth naming is **binding to our nonce**. A report can be genuine,
correctly signed by real hardware, unexpired, and still describe a different
machine than the one about to see the data. `report_data` must contain
`sha256("blindkeep-attest-v1\0" || nonce)` for a nonce this client generated in
the same call — `attest_host` creates it internally so a caller cannot verify
against a nonce an attacker supplied. Redirects from an attestation endpoint are
refused for the reason the storage client refuses them: a host being asked to
prove it is trustworthy is by definition not yet trusted.

`attested_complete()` takes a verified `Result` rather than a boolean, so the
call cannot be made without having attested first. An ordering that matters is
not left to a caller remembering it.

**Explicit non-claims.** `tdx` and `nvidia-gpu` are registered as unimplemented
and **refuse**. Attestation also shifts trust to the silicon vendor and the
attestation chain — it narrows who must be trusted, it does not eliminate trust.

### SEV-SNP, implemented and disabled

`sev_snp.py` parses the real 1184-byte report, verifies ECDSA P-384 over
SHA-384 against a VCEK, walks ARK → ASK → VCEK, and handles AMD's little-endian
`r`/`s` encoding. It is **not** in `attest.default_registry()`, and `sev-snp`
refuses on the default path, because **no report from real hardware has ever
been run through it**.

An unvalidated parser fails one of two ways: it always errors, or it reads the
wrong 48 bytes as the measurement and passes. The second is unacceptable in a
component whose only job is that passing means something, so the code stays
unreachable until a known-answer vector from a real machine exists. A test
asserts it is absent from the default registry; if that test ever fails,
something was enabled without being validated.

The verifier also refuses when the envelope disagrees with the signed report —
measurement, debug flag, or nonce binding — so the outer checks cannot verify
one thing while the signature covers another. `report_data` must carry the
32-byte nonce hash and nothing else; bytes hidden in the remaining 32 are
refused.

### Release policy across model tiers

`memory_gate.py` decides what leaves. Sensitivity is carried in the encrypted,
AAD-authenticated label, so a node can neither read a record's class nor
relabel it. The plaintext index on disk is a convenience, never the authority: a
test forges it and asserts a `secret` record is still withheld.

- A tier that is claimed but not proven is **demoted to `OPEN`**, and the
  demotion is carried in the grant so the refusal names it. A user who believed
  they were talking to an enclave finds out when it matters.
- A prover that raises demotes rather than crashing; an unreadable sensitivity
  class parses as `SECRET`, and an unlabelled record is not public. Every
  ambiguity resolves toward withholding.
- `SECRET` is pinned to `LOCAL` in the default policy and does not leave the
  machine for any remote proof, because "the operator cannot read it" remains a
  claim about someone else's hardware.

This governs what is *sent*. It cannot govern what a model does with text after
it arrives.

### Not a privacy control: sending embeddings or hidden states

A recurring suggestion is to send vectors or intermediate activations instead of
text, on the intuition that they are opaque. They are not: embedding-inversion
attacks reconstruct source text from embeddings with high fidelity, and
intermediate activations leak at least as much. Split inference relocates the
disclosure; it does not reduce it. No path in this project does this.

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

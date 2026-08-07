# Blindkeep — Architecture and Feasibility

**Version 0.5 · 2026-08-07 · zcashsensei**
*v0.1 2026-08-05: initial. v0.2: peer discovery, retrieval auditing,
local-model memory and a gated hosted-model path implemented; limits revised.
v0.3: pseudonymisation, an attestation framework and a tiered release policy
implemented; a SEV-SNP verifier written but deliberately disabled; §7 revised to
state the load-bearing limit first — no node has ever been run by anyone but the
author, and no public network exists.
v0.4: §3.4 clarified — "confidentiality needs no ZK" is a claim about
confidentiality, not a claim that this design never needs proving; access-pattern
privacy and proof of storage still do.
v0.5: zero-knowledge membership implemented — a holder proves they hold a record
without naming it, bound to a signed head. Sigma protocols, O(n), no SNARK.*

---

## Abstract

Blindkeep is a zero-knowledge memory layer for AI. A storage operator cannot
read what it holds and cannot silently alter it: clients encrypt records
locally, and nodes hold only ciphertext committed to an append-only Merkle log
with signed heads, verified by the client rather than trusted from the operator.

The second half is what makes it a proving system rather than encrypted storage.
A signed log constrains the *node*; it gives the *holder* nothing to say, since
naming a record is the only way to reference it. Blindkeep therefore also proves
statements **about** records without identifying them — membership in a keep,
and range, equality and opening over committed values — with every proof bound
to a signed tree head so it transfers to no other keep or state.

This document states what is implemented and verified today, what is achievable
with established techniques, and — explicitly — what is **not** achievable as
originally conceived. A design document that only lists strengths is a sales
brochure, and the distinction matters more here than the ambition does.

---

## 1. Problem

Agentic AI systems accumulate long-lived memory: preferences, history, working
context, private documents. Today that memory lives either on a single local
disk (durable only as long as the device) or inside a provider's infrastructure
(readable by the provider, and by anyone who compels or breaches them).

The gap is a memory layer that is simultaneously:

- **durable** — survives device loss, replicated across operators
- **private** — the operator cannot read it, structurally rather than by policy
- **verifiable** — the operator cannot alter, reorder or drop it undetected

Existing decentralized storage solves durability. Encryption solves privacy.
Transparency logs solve verifiability. Blindkeep's contribution is combining
them into a memory API with a client that trusts no single operator, and being
honest about the boundary of what that achieves.

---

## 2. Threat model

A node is **untrusted for both confidentiality and integrity**. It is assumed
capable of reading everything it stores, modifying it, withholding it, lying
about it, and colluding with other nodes.

It is *not* assumed to be prevented from observing metadata. See §7.

---

## 3. Design

### 3.1 Encryption

Each record is encrypted client-side with AES-256-GCM under a key derived per
record via HKDF-SHA256 from a master key that never leaves the client. Per-record
derivation means compromise of one record key does not extend to the store.

The node receives a random record identifier, a ciphertext, and a length.

### 3.2 The log

Records are committed to an append-only Merkle tree using RFC 6962 hashing —
the construction underlying Certificate Transparency. Leaves and interior nodes
are domain-separated so a leaf can never be reinterpreted as a subtree.

The node publishes a **signed tree head**: an Ed25519 signature over exactly
`(tree_size, root)`. No unsigned fields ride alongside, so no metadata can be
altered without invalidating the signature.

### 3.3 Verification

Five checks, all client-side. Any failure raises rather than returning data.

| # | Check | Defeats |
|---|-------|---------|
| 1 | Response bound to the request | Answering a different question than asked |
| 2 | Signature over `(tree_size, root)` | Forged or unsigned log state |
| 3 | Merkle inclusion proof | Serving a record never committed to |
| 4 | Merkle consistency proof vs. a pinned head | Rewriting, reordering, dropping history |
| 5 | AES-256-GCM authenticated decryption | Modified ciphertext |

Check 1 is not decoration. Two vulnerabilities were found pre-release where the
client verified a response was internally self-consistent but never that it was
*responsive* — a node asked for index 0 could return index 1 together with index
1's authentic proof, and every cryptographic check passed. See `SECURITY.md`.

### 3.4 Which properties need a proof, and which need only a cipher

Both are used here, and the split is deliberate rather than a shortfall — a
proof is reached for where nothing cheaper works, and not where a cipher already
settles the question.

| Mechanism | Prevents | Property |
|-----------|----------|----------|
| AES-256-GCM, client-side | The node **reading** a record | **Confidentiality** |
| Merkle proofs + signed heads | The node **lying** about a record | **Integrity** |

Confidentiality here comes from encryption, not from proving. The system does
produce proofs continuously — one inclusion proof per read, one consistency
proof per observed log growth — but those proofs are not zero-knowledge. An
inclusion proof reveals the leaf and its full sibling path.

That leaks nothing, because **the leaf is ciphertext**. The result is
verifiability without the proof system needing to conceal anything, which is why
the design achieves both properties without a proving system in the critical
path.

The practical consequence, stated precisely because the loose version is
misleading: **the confidentiality guarantee does not depend on any future
zero-knowledge work.** It holds today, from a cipher.

That is a claim about confidentiality alone. It is *not* a claim that this
design never needs zero-knowledge. Two properties it does not have require
exactly that, and no amount of encryption substitutes:

- **access-pattern privacy** — hiding *which* record was read, which needs PIR
  (§5.4), and
- **proof of storage** — compelling a node to actually hold data rather than
  fetch it on demand (§5.2).

Both are open. Neither is bluffed here. Zero-knowledge work therefore belongs on
this roadmap for the things a cipher cannot do, and is deliberately absent from
the things it can — which is the whole of the argument in §3.4, not a rejection
of proving.

What IS implemented here is the third thing, and it is the reason this is a
zero-knowledge project: **a holder can prove a statement about a record without
naming the record.** The log constrains the node; these proofs let the holder
speak. Membership is bound to a signed tree head, so a proof is about a specific
keep in a specific state and transfers nowhere else.

They are sigma protocols, not SNARKs — which costs O(n) proof size for keep
membership and is exactly why §5.7's hash decision matters before circuits are
written, not after.

What encryption cannot do is hide *behaviour*. The node still observes which
record is requested and when. Closing that gap requires private information
retrieval (§5.4) — the one privacy property in this design that genuinely
requires advanced cryptography rather than a cipher.

Two adjacent leaks did *not* require advanced cryptography and have been closed
by framing rather than by adding a proof system:

- **Labels are encrypted with the record** rather than stored beside it. A label
  is the metadata most likely to be descriptive, and leaving it readable
  weakened the guarantee the rest of the design provides.
- **Records are padded to 256-byte buckets** before encryption, so stored length
  reveals a bucket rather than an exact size, at bounded overhead.

The distinction is worth noting for scoping: of the metadata originally exposed,
the portion removable by better framing has been removed, and what remains —
access pattern, record count, timing — is precisely the portion that needs PIR.

**Cryptographic status of these claims** is spelled out in
[`CRYPTO_FOUNDATIONS.md`](CRYPTO_FOUNDATIONS.md): security reduces to standard
assumptions on AES-GCM, HKDF, Ed25519, and SHA-256 under the RFC 6962 Merkle
construction (as used in Certificate Transparency). The repository provides
exhaustive and adversarial *implementation tests*; it does not claim a novel
peer-reviewed proving system or machine-checked formal verification of the
entire codebase. That honesty is intentional.

### 3.5 Cost

Inclusion and consistency proofs are `O(log n)` hashes. At one billion records a
proof is roughly 30 SHA-256 hashes — under a kilobyte, verified in microseconds.
The verification layer does not become the bottleneck at any realistic scale.

---

## 4. What is verified — as of 2026-08-07

Implemented, running, and covered by tests in this repository. **322 tests
across 20 suites**, plus an end-to-end demonstration.

| Component | Status | Evidence |
|-----------|--------|----------|
| RFC 6962 inclusion + consistency proofs | Complete | 13 tests, exhaustive over all index/size pairs for sizes 0–32 |
| Client encryption, per-record key derivation | Complete | 5 tests including wrong-key rejection and reload persistence |
| Signed tree heads | Complete | Signature verified against on-disk state |
| Client verification pipeline | Complete | 9 adversarial tests running genuinely malicious HTTP nodes |
| Single-node HTTP service + CLI | Complete | End-to-end demo |
| Metadata minimisation | Complete | 8 tests: encrypted labels, padded sizes, access pattern asserted still open |
| Multi-node replication, quorum reads | Complete | 12 tests: offline, tampered and dishonest nodes |
| Key recovery | Complete | 21 tests: codes, passphrase backups, k-of-n Shamir shares |
| Node resource and disclosure hardening | Complete | 12 tests: bounded bodies, paginated listing, no path disclosure |
| Peer discovery | Complete | 18 tests, including a hostile bootstrap endpoint |
| Retrieval auditing | Complete | 10 tests separating offline, lost-data and dishonest nodes |
| Local-model memory loop | Complete | 13 tests, loopback enforced, no hosted-provider path |
| Gated hosted-model path | Complete | 13 tests asserting it stays closed by default |
| Reversible pseudonymisation on that path | Complete | 30 tests, four of which pass by demonstrating the limits |
| Attestation framework | Complete | 30 tests; a replayed but genuine report is refused |
| Release policy across model tiers | Complete | 29 tests; an unproven tier claim is demoted, not honoured |
| SEV-SNP report verification | **Written, disabled** | 19 tests, all against synthetic reports; never run against real hardware, so it is excluded from the default registry |
| Self-reporting inventory | Complete | 14 tests; counts computed from source, non-claims listed |
| Command-line surface | Complete | 15 tests, including that no command creates a master key as a side effect |

The adversarial suites are the substantive claim. They stand up nodes that
substitute records, fork history at equal length, forge heads, tamper with
stored ciphertext, silently alter a payload during a write, probe the node as a
hostile client, and serve a poisoned peer list — and assert the client refuses
or excludes each one.

A recurring pattern in these suites is worth naming: several tests assert a
**limitation** rather than a capability. One asserts that access patterns remain
visible; another that redaction leaves sensitive prose untouched. If either
property ever changes, the test fails and forces the documentation to be
updated. A limitation that is only written down decays into an assumption.

**Not implemented:** witnessing against equivocation, proof of *storage* as
distinct from retrieval, incentives, private queries, verifiable inference.

---

## 5. Feasibility of the remaining layers

This section exists to separate what is engineering from what is research, and
to name one item that is neither.

### 5.1 Multi-node replication — **implemented**

`ReplicatedClient` (`blindkeep/replica.py`) writes byte-identical ciphertext to
N nodes and returns a value only when a quorum **independently verifies** and
**agrees**. Covered by 12 tests (offline, tampered, and dishonest nodes).

Peer lists come from `blindkeep/discover.py`, from a file or a bootstrap
endpoint. A bootstrap is treated as hostile input: URLs are validated before
contact, cloud metadata addresses are refused, redirects are not followed, and a
bootstrap cannot displace a locally pinned public key. The list supplies
candidate addresses and confers no trust — every node is still verified
independently on use.

Remaining problem: **equivocation** — a node showing different histories to
different clients. Consistency proofs bind a node to its own past, not to what
it told someone else. The standard solution is gossip between clients or
independent witnesses co-signing heads, as Certificate Transparency does. Known
technique; not yet in this repository.

### 5.2 Retrieval auditing — **implemented**; proof of storage — **not**

These are two different claims and the distinction is easy to blur.

**Implemented.** `blindkeep/audit.py` challenges a node on a random sample of
records and runs full client verification on each answer. Integrity proofs
establish that what a node returns is genuine; they say nothing about whether it
returns anything at all. The audit separates three outcomes a plain uptime check
would conflate:

| Outcome | Meaning | Consequence |
|---------|---------|-------------|
| offline | did not answer | unreliable |
| failed | answered, record missing or unreadable | unreliable |
| security failure | answered, cryptographic check failed | **disqualifying** |

A single security failure disqualifies a node outright. Availability is a matter
of degree and can be scored proportionally; honesty cannot. A node that served
one unverifiable answer has demonstrated that it can, and no proportion of
correct answers offsets that.

**Not implemented, and not claimed.** This is challenge–response *retrieval*. It
shows a node served data at the time of asking. A node could in principle obtain
a record from elsewhere on demand and pass every audit while storing nothing.
Distinguishing "stores" from "can obtain" requires proof of replication of the
kind Filecoin implements — genuinely different machinery.

That is also the natural first place zero-knowledge proving earns its cost here.
Filecoin generates enormous volumes of SNARKs for exactly this purpose, with no
machine learning involved anywhere: a real ZK application rather than branding.

### 5.3 Distributed model weights — **achievable, with a performance cost**

Sharding large model weights across volunteer nodes and streaming the needed
shards is demonstrated by Petals, which performs distributed inference of large
models over ordinary internet connections. Integrity of a shard needs only a
content hash; no proof system is required.

The honest caveat: it works and it is slower than local inference. Blindkeep
would add an incentive and privacy layer, not the sharding technique itself.

### 5.4 Private queries (PIR) — **achievable, expensive**

Hiding *which* record a client reads is the one privacy gap that cryptography
can close but Blindkeep's current design does not. Single-server private
information retrieval fundamentally requires the server to touch the entire
database per query, or to perform substantial preprocessing. Modern schemes make
this practical for modest databases. It is real, it is costly, and it should be
scoped to a specific dataset size before being promised.

### 5.5 Verifiable inference (zkML) — **not achievable at LLM scale today**

Proving that a model produced an output correctly, without revealing inputs, is
genuine and active research. Proving overhead is currently orders of magnitude
above native execution. Small models are demonstrable; a forward pass of a
multi-billion-parameter model is not practical today.

It belongs on a roadmap. It must not appear in any claim about what ships.

### 5.6 Distributed KV cache — **not achievable. This item is withdrawn.**

An earlier formulation of this project proposed holding transformer KV cache
across community nodes. That is not an engineering difficulty; it is ruled out
by arithmetic, and it is recorded here so it is not proposed again.

For a 7-billion-parameter model at fp16 with 32 layers, 32 heads and head
dimension 128, the cache per token per layer is
`2 × 32 × 128 × 2 bytes = 16 KiB`, so `512 KiB` per token across all layers. An
8,192-token context is therefore about **4 GiB of live state**.

Generating each token requires reading that entire cache. Local high-bandwidth
memory delivers it in single-digit milliseconds. A 10 Gbps network link delivers
roughly 1.25 GB/s, requiring over three seconds per token for transfer alone,
before round-trip latency. That is a gap of roughly three orders of magnitude on
bandwidth and considerably more on latency.

KV cache must sit next to the accelerator. No protocol design changes this.

---

## 5.7 Adding proofs later — does stored data have to change?

Largely **no**, with one exception that is worth deciding now because it is the
only part that would force a migration.

**No migration required for:**

- **Proof of retrievability.** A node proves it still holds bytes it already
  committed to. It operates on data at rest, exactly as written. No
  re-encryption, no rewriting, no new leaf format.
- **Proofs about the log.** The Merkle root is already an ideal public input to
  a circuit: a statement of the form "a record exists in the log with root R"
  can be proven without revealing the record. The commitment structure needed
  for this is what the log already is.
- **Shielded payment settlement.** Entirely orthogonal to how records are
  stored.

Records are committed as opaque ciphertext. Proof layers make statements *about*
those commitments; they do not require changing what the commitments are over.
The design is forward-compatible by construction.

**The exception: the hash function.**

The log uses SHA-256, per RFC 6962. That is the right choice for
interoperability — it matches Certificate Transparency and its tooling. But
SHA-256 is expensive to evaluate *inside* a zero-knowledge circuit: on the order
of tens of thousands of constraints per compression, against a few hundred for a
SNARK-friendly hash such as Poseidon. Roughly two orders of magnitude.

That difference only matters for one specific capability: proving Merkle
membership **inside** a circuit — for example, proving "I hold a record in this
log" without revealing which. A 30-deep path costs on the order of a million
constraints with SHA-256 versus tens of thousands with a SNARK-friendly hash;
the practical difference is a proof that takes minutes rather than seconds.

Three options, and the third avoids a migration entirely:

| Option | Cost | Consequence |
|--------|------|-------------|
| Keep SHA-256 only | None now | In-circuit membership proofs stay expensive |
| Switch the log to a SNARK-friendly hash | **Rebuild every log** | Loses RFC 6962 compatibility and existing tooling |
| Keep SHA-256; add a parallel accumulator from a checkpoint when needed | Extra hashing from that point forward | No migration; both properties available |

The third is recommended. Existing records stay exactly where they are; a
SNARK-friendly accumulator begins at a checkpoint and covers records from that
point on. Historic data is still verifiable under SHA-256, and new data is
additionally provable in-circuit.

The decision that must be made *before* significant data accumulates is only
whether in-circuit membership proofs are wanted at all. Nothing else about the
current format constrains a future proof system.

---

## 6. Prior art

Blindkeep is a combination of established components, and claiming otherwise
would invite justified criticism:

| Component | Prior art |
|-----------|-----------|
| Append-only verifiable log | Certificate Transparency (RFC 6962), Trillian, Tessera |
| Proofs of storage over time | Filecoin, Arweave, Storj |
| Distributed inference over volunteers | Petals, llama.cpp RPC |
| Client-side encrypted storage | Long-established practice |
| Shielded payments | Zcash |

The contribution is the composition — a memory API for AI agents where the
client verifies everything and the operator is trusted for nothing — plus a
usable free path. Not the primitives.

---

## 7. Limits

Stated plainly:

- **Access patterns are visible.** The node observes which record is requested
  and when, along with record count and creation times. Labels and exact sizes
  are no longer exposed (§3.4), but which record you read cannot be hidden by a
  cipher — that requires private retrieval (§5.4).
- **Availability is not integrity.** A node can refuse to serve. Replication
  addresses this; proofs do not. Auditing (§5.2) measures it but cannot compel it.
- **Retrieval is audited, storage is not proven.** A node that obtains a record
  on demand passes an audit while storing nothing (§5.2).
- **Equivocation is undetected** until witnessing exists (§5.1).
- **The client is trusted.** Compromised client software defeats every guarantee
  above, and no server-side measure can help.
- **Key loss is survivable but not automatic.** Three client-side recovery
  mechanisms exist — a written code, a passphrase-wrapped backup, and k-of-n
  shares — but each must be set up *before* the key is lost. Recovery material
  is also the security floor: whoever holds a recovery code holds the store.
- **The hosted-model path discloses.** It is opt-in, requires two separate
  acknowledgements, and is imported by no default code path — but a user who
  chooses it has disclosed that prompt. Redaction is best-effort pattern
  matching and is not a privacy control. Pseudonymisation narrows the
  disclosure and does not remove it: it substitutes identifiers, not
  identifiability.
- **No node has ever been run by anyone but the author.** This is the load-
  bearing limit and it is not technical. Every result in §4 was produced against
  nodes the author operates, while the entire design assumes a node is hostile.
  The cryptography is standard and the adversarial tests stand up genuinely
  malicious nodes, but "this survives a stranger's node" remains argued rather
  than observed. There is also no public node network, so a user today stores on
  hardware they own — which makes the accurate present description *encrypted,
  tamper-evident memory on your own machine*, not a distributed one.
- **Attestation is implemented, not validated.** The framework and its five
  checks are tested, and a full SEV-SNP report verifier exists — but it has
  never parsed a report from real hardware, so it is deliberately excluded from
  the default registry and that format refuses. Attestation would also shift
  trust to a silicon vendor rather than remove it.

---

## 8. Economics — the principal unverified risk

Everything above is a technical question with a technical answer. This section
is neither, and it is where comparable projects have failed.

The intended model is: MIT-licensed software, free self-hosting permanently, a
grant-funded free public tier, and optional paid capacity above quota.

**The supply side is buildable. The demand side is unproven.** Golem, iExec,
Akash and Render each built functioning decentralized capacity networks and then
had to go looking for paying load. A free tier funded by grants is a runway, not
a business model; when the grant ends, either paying demand exists or the free
capacity does not.

This is the risk that should govern sequencing. It argues for:

1. Making the free path genuinely useful to a real user before any incentive design
2. Metering on quantities that can be measured honestly — stored gigabyte-months,
   verified reads, egress — rather than per-token pricing for inference the
   project does not yet serve
3. Deferring any token until the free network demonstrably works

No amount of cryptographic rigour substitutes for someone choosing to store
their data here.

---

## 9. Verdict

| Layer | Verdict |
|-------|---------|
| Encrypted verifiable memory, single node | **Built and verified** |
| Metadata minimisation (labels, sizes) | **Built and verified** |
| Multi-node replication and quorum reads | **Built and verified** |
| Key recovery | **Built and verified** |
| Peer discovery | **Built and verified** |
| Retrieval auditing | **Built and verified** |
| Local-model memory loop | **Built and verified** |
| Witnessing against equivocation | Achievable — established technique (not shipped) |
| Proof of *storage* (not retrieval) | Achievable — production precedent, substantial work |
| Distributed model weights | Achievable — with a real speed penalty |
| Private queries (PIR) | Achievable — expensive, scope carefully |
| Verifiable inference (zkML) | Research. Roadmap only. Never a shipping claim |
| ZK property proofs + keep membership | **Built and verified** — sigma protocols, O(n), unaudited |
| Distributed KV cache | **Withdrawn — ruled out by bandwidth arithmetic** |
| **External validation** | **None. Every claim is self-verified** |
| Sustainable economics | **Unverified. The principal risk** |

The architecture is sound for what it claims, and the claims have been narrowed
to what the arithmetic supports. One original component was removed rather than
carried forward as an aspiration.

The two open items at the bottom of that table are the honest ones. Every
result in this document was produced by the author, on the author's machine,
against nodes the author controls. The system is designed on the premise that a
node is untrusted, and that premise has never been tested against a node the
author does not run. Until a second operator stands one up, "untrusted" is a
design intention rather than an observed property.

That, and not any remaining cryptography, is the next thing worth doing.

---

## References

- RFC 6962 — Certificate Transparency
- Filecoin — Proof of Replication and Proof of Spacetime
- Petals — collaborative inference of large language models
- Zcash — shielded transactions

# Prior art, and what is actually new here

**2026-08-13.** Encrypted memory for AI agents is a crowded category. This document names the
closest shipped work, states plainly what it already does, and confines Oblivio's novelty
claim to what survives that comparison. It exists because a novelty claim that has not been
checked against the field is worth nothing to a reviewer, and because the honest answer
narrows the claim rather than dropping it.

## The field

The MCP ecosystem lists **172 memory servers**. Encrypted, local-first agent memory is not a
gap — it is a category with shipped, competent entries. The two closest:

| Project | What it ships |
|---|---|
| [Compartment](https://github.com/MaxFreedomPollard/Compartment) | Fully offline encrypted vector memory as an MCP server. XChaCha20-Poly1305 AEAD over everything at rest *including embedding vectors*, Argon2id keyslots, per-record keys enabling crypto-shred deletion, a hash-chained tamper-evident audit log, GUI, one-click install. |
| [mnemo](https://github.com/sattyamjjain/mnemo) | MCP-native embedded memory database in Rust. AES-256-GCM, hybrid vector search, DuckDB/Postgres backends, SDKs in three languages. Every write and delete is a SHA-256 hash-chained entry, and an external verifier can detect post-hoc mutation offline without consulting the store. |

Also in the space: [Sovseal](https://glama.ai/mcp/servers/sovseal/mcp-server) (client-side
AES-256-GCM, server sees only ciphertext), [OpenMemory / Mem0], [ZeroDB], and
[Bitwarden's MCP server] (zero-knowledge, credentials rather than general memory).

**These are real properties, correctly implemented.** Nothing below disputes them.

## What this means for Oblivio's claim

**Client-side encryption of agent memory is not novel, and Oblivio should stop implying it
is.** AEAD at rest, encrypted embeddings, and a tamper-evident hash chain are table stakes in
this category as of 2026. A claim resting on those is refuted in ten minutes by a reviewer
with a search engine.

## What the audit found

Both repositories cloned and read on 2026-08-13. Counts are `git grep` over **source files
only** (`.py`, `.rs`, `.ts`, `.js`), excluding documentation:

| Primitive | Compartment | mnemo |
|---|---|---|
| Merkle tree | 0 | 0 |
| Inclusion proof | 0 | 0 |
| Consistency proof | 0 | 0 |
| RFC 6962 / Certificate Transparency | 0 | 0 |
| Signed tree head | 0 | 0 |
| Equivocation / split-view | 0 | 0 |
| Witness / gossip | 0 | 0 |
| Remote (hardware) attestation | 0 | 0 † |
| OHTTP / HPKE | 0 | 0 |
| PIR | 0 | 0 |
| Blind signatures | 0 | 0 |
| Zero-knowledge proofs | 0 | 0 |

† mnemo has an `attest` module, but it is **MCP tool-catalog attestation** — pinning a
SHA-256 of the advertised `tools/list` payload to defend against catalog poisoning. There is
no TEE, enclave, SEV-SNP, TDX or SGX vocabulary anywhere in the source. It is a different
mechanism addressing a different attack.

And the finding that explains all the zeros:

```
"untrusted server|node|operator" / "malicious server|node|operator"
    Compartment: 0 mentions      mnemo: 0 mentions
Compartment self-describes as "fully offline" / "no cloud": 10 mentions
```

**Neither project has a hostile serving party in its threat model.** The zeros are not an
oversight to be fixed in a later release; they are the correct engineering answer to the
problem those projects chose.

## The novelty statement

> A hash chain proves that **a store you control** was not edited behind your back. It is
> verified by you, over your own data, on your own machine.
>
> Oblivio proves that **a store somebody else controls** served you a history that is
> complete, unrewritten, and the same one it served everyone else — while that operator is
> assumed to be reading, dropping, reordering and lying about your records, and colluding
> with other operators.
>
> These are different problems. Oblivio is not a better hash chain; it is a transparency
> log (RFC 6962 hashing, Ed25519 heads signed over exactly `(tree_size, root)`, inclusion
> and consistency proofs verified client-side, equivocation detection with witness gossip)
> applied to agent memory, with a tiered release policy above it that governs what may
> cross the inference boundary at all.

Second, and independent of the storage argument: **every project surveyed stops at storage.**
Oblivio's memory gate, generative delegation, remote attestation, OHTTP/HPKE metadata
splitting, blind-signature entitlement, PIR and halo2 membership proofs have **no counterpart
in the category**. The storage layer is the least differentiated part of this project, and
historically the part its own documents led with.

## Proof of concept

`tools/demo_hash_chain_is_not_enough.py` runs three attacks against a correctly implemented
SHA-256 hash chain and against `oblivio.merkle`. The chain is not weakened to lose — it is
the real construction, verified correctly.

| Attack | Hash chain | Signed Merkle head |
|---|---|---|
| **Omission** — operator drops a record you never learn existed | verifies, client sees nothing wrong | refused: the signed `tree_size` makes absence detectable, and an inclusion proof for the dropped record still verifies |
| **Equivocation** — two clients shown two histories | **both** verify, **both** clients are lied to | two signed heads at the same size with different roots — that pair *is* a transferable fraud proof |
| **Rewrite** — yesterday's entry edited, log re-chained | verifies against its own new head | refused: a consistency proof binds new state to the pinned old head |

The chain fails not because it is badly built but because a chain over the records a server
selected cannot speak about records it withheld, or about what another client was shown.

## What this argument does not claim

- Not that Compartment or mnemo are insecure. For their threat model they are sound.
- Not that Oblivio is more mature. Compartment ships a GUI and one-click install; Oblivio
  does not.
- Not that any Oblivio node has yet been run by someone other than its author — see
  `NOT_CLAIMED` in `oblivio status`. **The untrusted-operator threat model is the novelty,
  and demonstrating it against a genuinely foreign operator is still the open milestone.**
  A design that anticipates a hostile operator, verified only against operators the author
  controls, is a strong design and an unfinished proof.

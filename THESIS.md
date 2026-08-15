# Oblivio — category and privacy thesis

**Updated:** 2026-08-05  
**Status:** product doctrine; implementation truth tracked in code and README  
**Binding for contributors:** [`CONTRIBUTING.md`](CONTRIBUTING.md)

---

## Intent

Oblivio is the **privacy answer for AI memory**: sensitive context stays inside the user’s ecosystem so cloud LLM providers **never receive** raw prompts or stored memories by default.

| Pillar | Position |
|--------|----------|
| Primary | Zero-knowledge memory infrastructure for AI — the operator is blind, and the holder can prove without disclosing |
| Network | DePIN — user-controlled nodes, no central data harvest |
| Now | **Two proving layers, both implemented.** A **halo2 SNARK** (no trusted setup) proves Poseidon Merkle membership in a **constant 3,040 bytes** — measured at 8 leaves and at 128. Sigma-protocol proofs cover keep membership, range, equality and opening with no toolchain at all, at O(n) |
| Later | Succinct proofs wired into the default read path, not an optional binary; verifiable inference (ZKML) only where cost is justified |
| Not | Public cloud AI SaaS, grid/power product, or coin-first launch |

Build sequence: encrypted verifiable memory → multi-node mesh → optional local inference glue → advanced proofs only when they earn their cost. Do not claim unshipped capabilities.

---

## One-liner

**DePIN privacy-preserving AI infrastructure** — decentralized nodes hold encrypted memory (and later compute) so raw prompts and agent data need not leave the ecosystem.

**Tags:** `PrivacyAI` · `ConfidentialAI` · `DePIN` · `SovereignAI` · `DeAI` · (later) `ZKML`

---

## Category ranking

| Rank | Category | Why |
|------|----------|-----|
| 1 | Privacy-preserving / confidential AI infrastructure | Structural privacy: data not sent |
| 2 | DePIN | Distributed storage/compute without central harvest |
| 3 | Sovereign / local AI | Keys and plaintext stay with the user |
| 4 | Verifiable AI memory | Cryptographic detection of log rewrites |
| Later | ZKML / verifiable inference | Prove computation without revealing inputs |
| Later | DeAI | Umbrella once multi-node + incentives exist |

### Name

Public product name: **Oblivio** only.

The mark was checked for conflicts (package indexes, GitHub, domains, crypto/AI projects) before adoption. Under MIT, forks may reuse code; **brand** is the exclusive surface—protect “Oblivio.” This project is **not** a grid or power-coordination product.

---

## Privacy model

If models and memory stay local (or only non-sensitive data leaves the system), external providers never receive the sensitive material. They cannot process what they never receive.

If the software ever forwards real user inputs to third-party LLM APIs, those providers process that traffic—even when they claim not to train on API data. Structural privacy requires **not sending** the data (or a carefully designed redacting gateway that is opt-in and labelled **not private**).

### Does this repository call cloud LLM APIs?

**No.** The current release is an encrypted memory node and client only. Future optional gateways must default to local-only.

---

## Today vs target

| Layer | Today | Target |
|-------|-------|--------|
| Content confidentiality | Client AES-256-GCM; node holds ciphertext | Same at multi-node scale |
| Metadata | Counts, sizes, timestamps, labels may be visible; omit labels if sensitive | Encrypted labels, padding, PIR later |
| Tamper evidence | Merkle inclusion + consistency + signed heads | Witnesses / gossip against equivocation |
| Deployment | Local node | Edge fleet + peer discovery |
| DePIN mesh | Multi-node replication shipped | Peer discovery, PoR, free public pool |
| ZKML | Not shipped | Optional where justified |
| Token / incentives | Parked | Only after free path is real |

**Doctrine:** reach for the cheapest primitive that delivers the property. Integrity and “node cannot read contents” are settled by hashes, AEAD and signed logs, so those do not get a circuit. What a cipher cannot do — letting a holder prove something about a record without naming it — is what the proofs are for, and both layers ship: sigma protocols for the toolchain-free path, and a halo2 circuit for succinct membership. ZKML stays reserved for proving inference without revealing inputs, and is not implemented.

---

## Claims discipline

**Safe today:**  
> Oblivio is privacy-preserving AI memory infrastructure: clients encrypt, nodes store ciphertext, and log rewrites are detectable.

**Not safe until true:**  
> Full ZKML private inference over DePIN with universal privacy against all cloud providers.

---

## Competitive context (orientation)

| Cluster | Overlap |
|---------|---------|
| Portable encrypted agent memory | Closest to current scope |
| Decentralized storage (Filecoin, Arweave, Storj) | Storage proofs lineage |
| Decentralized compute (Akash, Render, Petals) | Future compute layer |
| Local LLM runtimes (Ollama, llama.cpp) | Complementary — they run models; Oblivio stores memory |

---

## Pitch variants

**Infrastructure / DePIN:** Private nodes for AI storage (and later compute) that never need plaintext.  
**Technical:** Append-only Merkle memory log + client AEAD; node untrusted for confidentiality and integrity.  
**User:** Your AI can remember you without uploading that history to a cloud LLM provider.

---

Related docs: [`README.md`](README.md) · [`WHITEPAPER.md`](WHITEPAPER.md) · [`CRYPTO_FOUNDATIONS.md`](CRYPTO_FOUNDATIONS.md) · [`SECURITY.md`](SECURITY.md) · [`GRANT_ONE_PAGER.md`](GRANT_ONE_PAGER.md) · [`CONTRIBUTING.md`](CONTRIBUTING.md)

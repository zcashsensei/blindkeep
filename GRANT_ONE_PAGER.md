# Blindkeep — Grant one-pager

**Project:** Blindkeep  
**Applicant / maintainer:** zcashsensei ([GitHub](https://github.com/zcashsensei))  
**Repository:** https://github.com/zcashsensei/blindkeep  
**License:** MIT  
**Date:** 2026-08-05  
**Status:** Runnable open-source reference implementation (v0 alpha)

*One page for Zcash Community Grants / Zcash Foundation-style review. Full technical detail: [`WHITEPAPER.md`](WHITEPAPER.md), [`CRYPTO_FOUNDATIONS.md`](CRYPTO_FOUNDATIONS.md), [`SECURITY.md`](SECURITY.md).*

---

## 1. Problem

Agentic and local AI systems need **long-lived memory** (preferences, history, documents). Today that memory is either:

- **Fragile** — only on one device, or  
- **Readable by a provider** — stored in a cloud that can inspect, compel, or leak it.

The missing layer is memory that is **durable**, **structurally private** (operator cannot read contents), and **verifiable** (operator cannot alter history undetected).

---

## 2. Solution (one sentence)

**Blindkeep** is open-source infrastructure for AI memory: clients encrypt locally; nodes store only ciphertext in an append-only Merkle log with signed heads; clients verify every response before accepting data.

---

## 3. Why this fits Zcash-adjacent public good

| Alignment | How |
|-----------|-----|
| **Privacy by design** | Contents never need to leave the client unencrypted; privacy does not depend on a provider policy |
| **Open source** | MIT; anyone may self-host free of charge |
| **Honest cryptography** | Uses established primitives (not a novel unproven ZK scheme marketed as shipping) |
| **Path to ZEC utility** | Later optional paid capacity / settlement can use shielded ZEC; free tier can be grant-sponsored |
| **No coin-first launch** | No token required for v0 utility |

---

## 4. What is implemented — as of 2026-08-05 (evidence)

| Capability | Evidence in repo |
|------------|------------------|
| Client-side AES-256-GCM + HKDF per-record keys | `blindkeep/crypto.py`, store tests |
| RFC 6962-style Merkle inclusion + consistency | `blindkeep/merkle.py`, 10 exhaustive tests |
| Ed25519 signed tree heads | crypto + client verification |
| Full client verify pipeline (5 checks) | `blindkeep/client.py`, 9 adversarial tests with malicious HTTP nodes |
| Single-node HTTP API + CLI | `node.py`, `cli.py`, `demo.py` |
| Multi-node replication + quorum reads | `replica.py`, 12 tests |
| Security write-up of fixed bugs | `SECURITY.md` |
| Cryptographic claim boundaries | `CRYPTO_FOUNDATIONS.md` |

**Automated suite (2026-08-05):** 80 tests + end-to-end demo — Merkle 13 · store 5 · metadata 8 · adversarial 9 · replication 12 · recovery 21 · hardening 12.

**Not claimed as shipping:** peer discovery, anti-equivocation witnesses, proof-of-retrievability, PIR, zkML, token incentives.

---

## 5. Security basis (grant-safe wording)

Blindkeep does **not** invent a new zero-knowledge proving system.

| Property | Mechanism | Basis |
|----------|-----------|--------|
| **Confidentiality of contents** | Client AES-256-GCM | NIST SP 800-38D / standard AEAD assumptions |
| **Key separation** | HKDF-SHA256 | RFC 5869 |
| **Authentic log tips** | Ed25519 over `(tree_size, root)` | RFC 8032 |
| **Tamper evidence** | RFC 6962 Merkle inclusion + consistency | Same family as Certificate Transparency; SHA-256 collision resistance |

**Proofs in production path are hash proofs** (\(O(\log n)\) SHA-256 operations per verify), not SNARK proofs. Python with the `cryptography` library is an appropriate reference implementation for this cost model.

**Explicit non-claims:** formal machine-checked verification of the entire codebase; metadata privacy (access patterns, sizes, optional plaintext labels); availability if a node withholds data; single-node anti-equivocation without witnesses.

Full statement: [`CRYPTO_FOUNDATIONS.md`](CRYPTO_FOUNDATIONS.md).

---

## 6. Requested work (suggested milestones)

| Phase | Deliverable | Outcome |
|-------|-------------|---------|
| **M0** | Public MIT repo + docs (done) | Reproducible baseline |
| **M1** | Multi-node replication + quorum (done) | Durable writes without trusting one node |
| **M1b** | Production hardening: incremental Merkle tree, packaging, CI | Scale readiness |
| **M2** | Peer discovery + operator runbooks + free community pool design | Path to “masses” free tier |
| **M3** | Proof-of-retrievability / uptime audits | Score nodes that actually serve data |
| **M4** | Optional ZEC micropay above free quota (shielded where practical) | Sustainable free path + Zcash utility |
| **M5** | Local-model integration (e.g. Ollama) using Blindkeep memory | End-user privacy story |

**Illustrative use of grant capital** (adjustable): ~40% sponsored free-tier nodes · ~30% engineering · ~15% docs/community · ~15% audit/reserve.

---

## 7. Team / contact

| Role | |
|------|--|
| Creator & maintainer | **zcashsensei** |
| GitHub | https://github.com/zcashsensei/blindkeep |
| License | MIT — copyright retained by author; public may use and self-host freely |

---

## 8. Links

| Document | Purpose |
|----------|---------|
| [Repository](https://github.com/zcashsensei/blindkeep) | Source, tests, issues |
| [`WHITEPAPER.md`](WHITEPAPER.md) | Architecture and feasibility |
| [`CRYPTO_FOUNDATIONS.md`](CRYPTO_FOUNDATIONS.md) | What is established vs tested |
| [`SECURITY.md`](SECURITY.md) | Threat model and fixed issues |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Design constraints for contributors |
| [`AUTHORS.md`](AUTHORS.md) | Provenance |

---

## 9. Closing (copy for application forms)

> Blindkeep is MIT-licensed infrastructure for privacy-preserving AI memory. Clients encrypt; untrusted nodes store ciphertext in a Certificate Transparency–style append-only log; clients verify signatures and Merkle proofs before accepting data. The project ships a tested Python reference implementation (including multi-node quorum replication) and deliberately avoids claiming unshipped zero-knowledge or token systems. Grant support would fund production hardening, a free public capacity tier, and optional ZEC-settled paid overage so private local AI memory can scale as a public good aligned with Zcash privacy values.

---

*This one-pager is public documentation. Budget numbers are illustrative until a formal application is filed.*

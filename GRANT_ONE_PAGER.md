# Blindkeep — Grant one-pager

**Project:** Blindkeep  
**Applicant / maintainer:** zcashsensei ([GitHub](https://github.com/zcashsensei))  
**Repository:** https://github.com/zcashsensei/blindkeep  
**License:** MIT  
**Date:** 2026-08-08 (v0.4)  
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

## 4. What is implemented — as of 2026-08-08 (evidence)

| Capability | Evidence in repo |
|------------|------------------|
| Client-side AES-256-GCM + HKDF per-record keys | `blindkeep/crypto.py`, store tests |
| RFC 6962-style Merkle inclusion + consistency | `blindkeep/merkle.py`, 13 exhaustive tests |
| Ed25519 signed tree heads | crypto + client verification |
| Full client verify pipeline (5 checks) | `blindkeep/client.py`, 9 adversarial tests with malicious HTTP nodes |
| Single-node HTTP API + CLI | `node.py`, `demo.py` |
| Command-line surface, no implicit key creation | `cli.py`, 19 tests |
| Multi-node replication + quorum reads | `replica.py`, 12 tests |
| Metadata minimisation (encrypted labels, padded sizes) | `store.py`, 8 tests |
| Key recovery: codes, passphrase backups, k-of-n Shamir shares | `recovery.py`, 25 tests |
| Node resource + disclosure hardening | `node.py`, 14 tests |
| Peer discovery with hostile-bootstrap defences | `discover.py`, 23 tests |
| Retrieval auditing (offline vs lost vs dishonest) | `audit.py`, 10 tests |
| Local-model memory loop, loopback enforced | `ollama_mem.py`, 13 tests |
| Gated hosted-model path, closed by default | `cloud_gate.py`, 17 tests |
| Reversible pseudonymisation on that path | `vault_proxy.py`, 30 tests |
| Remote attestation framework, refuse on any failure | `attest.py`, 30 tests |
| Release policy across model tiers, proof required | `memory_gate.py`, 42 tests |
| SEV-SNP report verification, **disabled pending hardware validation** | `sev_snp.py`, 19 tests |
| ZK proofs of properties without disclosure (range, membership, equality) | `zk.py`, 31 tests |
| **ZK membership: prove you hold a record without naming it**, bound to a signed head | `zk_keep.py`, 12 tests |
| **Anonymous entitlement**: Chaum blind signatures — prove you may ask without saying who you are (the RFC 9578 construction) | `anon_token.py`, 16 tests |
| **SEALED tier**: abstraction AND attestation together, degrading to the strongest that still holds | `memory_gate.py`, same 42-test suite |
| **Delegated inference**: a local model abstracts, a leak gate verifies, only a question about nobody is sent | `delegate.py`, 31 tests |
| **Poseidon tree matching the halo2 circuit**, cross-checked against Rust known-answer vectors | `poseidon.py`, `zk_tree.py`, 15 tests |
| **HPKE (RFC 9180)**, verified against the RFC's own test vectors | `hpke.py`, 10 tests |
| **Oblivious HTTP (RFC 9458)**: who is asking is split from what is asked, across two independent operators | `oblivious.py`, 15 tests |
| **Timing and size privacy**: a constant-rate clock, not jitter; padding in a header, not the prompt | `dispatch.py`, 20 tests |
| Access-pattern privacy (trivial PIR) and equivocation detection | `private_read.py` 12 tests, `witness.py` 13 tests |
| Self-reporting inventory — counts computed, non-claims listed | `status.py`, 15 tests (`blindkeep status`) |
| Counts in these documents enforced against source at push time | `tools/check_counts.py` |
| Security write-up of fixed bugs | `SECURITY.md` |
| Cryptographic claim boundaries | `CRYPTO_FOUNDATIONS.md` |

**Automated suite (2026-08-08):** **499 tests** across 29 suites + end-to-end demo. Counts are computed from source by `blindkeep status`, and `tools/check_counts.py` blocks a push that would leave this line stale:

<!-- roster --> adversarial 9 · anon-token 16 · attestation 30 · audit 10 · CLI 19 · cloud gate 17 · console 8 · delegate 31 · dialects 10 · discovery 23 · dispatch 20 · hardening 14 · HPKE 10 · local-model memory 13 · memory gate 44 · Merkle 13 · metadata 8 · oblivious HTTP 15 · poseidon 15 · private read 12 · recovery 25 · replication 12 · SEV-SNP 19 · status 15 · store 5 · vault proxy 30 · witness 13 · zk 31 · zk-keep 12

**Not claimed as shipping** (this list is kept in step with `blindkeep status`, which prints the same disclaimers):

- **Validated hardware attestation.** The framework and its five checks are implemented and tested; a full SEV-SNP report parser and verifier is implemented (`sev_snp.py`, 19 tests) but has never been run against a report from real hardware, so it is deliberately excluded from the default registry and `sev-snp` refuses on the default path. TDX and NVIDIA GPU formats refuse outright. No vendor root certificates are bundled.
- **Equivocation *prevention*.** Detection and proof exist (`witness.py`); stopping it needs consensus.
- **Sub-linear private retrieval.** Trivial PIR works and costs the whole keep on every read.
- **Proof of storage**, as distinct from the retrieval auditing that is implemented.
- **Independent relay and gateway operators** — the single assumption OHTTP rests on. Run both yourself and every anonymity property in `oblivious.py` is void, not weakened.
- **Interoperability with a real OHTTP deployment.** The HPKE layer matches RFC 9180's vectors; the RFC 9458 framing has never been run against a production relay.
- **Sender anonymity on the direct path** — unchanged and unfixable there; a provider API key is an account identity.
- **General-purpose proving and zkML**, and token incentives.

**Not yet demonstrated:** every result above was produced by the author against nodes the author operates. The design assumes a node is untrusted; that assumption has not been tested against a node run by anyone else. Establishing that is milestone M1 below, and it is deliberately written so it cannot be satisfied alone.

---

## 5. Security basis (grant-safe wording)

Blindkeep does **not** invent a new zero-knowledge proving system.

| Property | Mechanism | Basis |
|----------|-----------|--------|
| **Confidentiality of contents** | Client AES-256-GCM | NIST SP 800-38D / standard AEAD assumptions |
| **Key separation** | HKDF-SHA256 | RFC 5869 |
| **Authentic log tips** | Ed25519 over `(tree_size, root)` | RFC 8032 |
| **Tamper evidence** | RFC 6962 Merkle inclusion + consistency | Same family as Certificate Transparency; SHA-256 collision resistance |

**The read path verifies with hash proofs** (\(O(\log n)\) SHA-256 operations per verify), which is why Python with the `cryptography` library is an appropriate reference implementation for that cost model. **Zero-knowledge is implemented in two layers on top of it:** sigma protocols in Python for range, equality, opening and keep membership, and a **halo2 SNARK** (`circuits/`, no trusted setup) proving Poseidon Merkle membership in a **constant 3,040 bytes** — measured at 8 leaves and at 128.

**Explicit non-claims:** formal machine-checked verification of the entire codebase; **access-pattern privacy** — the node still observes which record is read and when, which requires PIR and is not implemented; availability if a node withholds data; single-node anti-equivocation without witnesses; proof that a node *stores* data rather than obtaining it on demand.

*(Labels and exact record sizes were previously listed here as exposed. Both are now protected — labels are encrypted with the record and sizes are padded to fixed buckets. Access pattern is what remains.)*

Full statement: [`CRYPTO_FOUNDATIONS.md`](CRYPTO_FOUNDATIONS.md).

---

## 6. Requested work (suggested milestones)

| Phase | Deliverable | Status |
|-------|-------------|--------|
| **M0** | Public MIT repo, docs, 499 tests | **done** |
| **M0b** | Replication, peer discovery, retrieval auditing, key recovery, local-model memory | **done** |
| **M1** | **Three nodes operated by people who are not the applicant**, serving one client | **the next milestone** |
| **M2** | Operator runbooks, packaging, CI, free community pool design | funded work |
| **M3** | Proof of *storage* — a node must hold data, not merely obtain it | funded work |
| **M4** | Anti-equivocation witnessing: clients gossip signed heads | funded work |
| **M5** | Independent security review, published in full including findings | funded work |
| **M6** | Optional ZEC micropay above free quota, shielded where practical | funded work |

M1 is first deliberately. Everything before it is code the applicant could write
alone, and all of it is already written. What has not been shown is that
strangers will run a node — and that is the only thing that distinguishes this
from a well-tested single-user tool.

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

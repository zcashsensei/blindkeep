# Cryptographic foundations

**Version 0.1 · 2026-08-05 · applies to Oblivio v0 alpha**

**Audience:** grant reviewers, security readers, maintainers.  
**Purpose:** state precisely what is *mathematically established*, what is *implemented and tested*, and what is *not* claimed.  
**Not legal advice. Not a novel peer-reviewed paper.**

---

## 1. Executive answer (read this first)

| Question | Answer |
|----------|--------|
| Is Oblivio a new, peer-reviewed cryptographic invention? | **No.** It composes **standard** primitives. |
| Are those primitives mathematically / cryptographically established? | **Yes** — under standard assumptions (below). |
| Is the *composition* “proven in a theorem prover”? | **No** (not Coq/Lean formal verification today). |
| Is the *composition* sound if primitives are used correctly? | **Yes** — integrity and confidentiality reduce to known properties. |
| Does “millions of proofs” require ZK Rust circuits? | **No.** The read-path proofs are **Merkle / hash proofs**, not SNARKs, and **Python is appropriate** for them. The Rust circuit in `circuits/` is for succinct *membership*, a different statement, and is optional. |
| When would Rust / ZK languages matter? | Later: PIR, zkML, high-QPS edge services — optional, not v0. |

**Grant-safe claim:**

> Oblivio’s security rests on well-studied primitives (AES-GCM, HKDF, Ed25519, RFC 6962 Merkle trees as used in Certificate Transparency), not on novel zero-knowledge constructions. Confidentiality is encryption; integrity is transparency-log style proofs. The implementation is tested for correct proof verification and adversarial client behavior; it is not a formal machine-checked proof of the entire system.

**Unsafe claim (do not use):**

> “We invented a new mathematically proven ZK protocol in Python that generates millions of zero-knowledge proofs.”

That is false for this codebase and would damage a ZCG/ZF application.

---

## 2. What is mathematically / cryptographically established

These are **not** Oblivio’s inventions. Their security arguments live in the public literature and standards.

### 2.1 Confidentiality — AES-256-GCM + HKDF

| Item | Status |
|------|--------|
| Primitive | AES-GCM (AEAD); keys via HKDF-SHA256 |
| Standard | NIST SP 800-38D (GCM); HKDF RFC 5869 |
| Property | Confidentiality + integrity of the *ciphertext blob* under standard AEAD assumptions, if nonces are unique and keys are secret |
| Oblivio use | Client-only master key; per-record key via HKDF; node never sees key material |

**What this proves (informally):** an adversary without the client key cannot recover plaintext from stored blobs (computational security of AES-GCM).

**What it does not prove:** metadata privacy — access pattern, record count and
timing. Labels are no longer among these: they are encrypted with the record and
bound as AAD, so the node receives an empty label field
(`oblivio/client.py`). Sizes are padded to fixed buckets, which reveals a
bucket rather than an exact length.

### 2.2 Authenticity of tree heads — Ed25519

| Item | Status |
|------|--------|
| Primitive | Ed25519 signatures |
| Standard | RFC 8032 |
| Property | Existential unforgeability under chosen-message attack (EUF-CMA) in the standard model for EdDSA (widely accepted) |
| Oblivio use | Node signs canonical `oblivio-head-v1 ‖ tree_size ‖ root` |

**What this proves (informally):** without the node’s private key, an adversary cannot forge a signed head for a chosen root.

**What it does not prove:** that the node is honest about *which* data it stored — that needs Merkle proofs + client pins.

### 2.3 Integrity of the log — RFC 6962 Merkle trees

| Item | Status |
|------|--------|
| Construction | Domain-separated Merkle hashing as in **RFC 6962** (Certificate Transparency) |
| Literature | CT design and Merkle audit/consistency proofs; second-preimage domain separation via `0x00` / `0x01` prefixes |
| Properties (under collision resistance of SHA-256) | **Inclusion:** a valid proof binds a leaf to a root. **Consistency:** a valid proof binds an old root of size *m* to a new root of size *n ≥ m* for an append-only extension |

**What this proves (informally):** if SHA-256 is collision-resistant, a node cannot produce a root and proofs that simultaneously (a) include a forged leaf and (b) remain consistent with a previously pinned honest root, without detection by a client that checks proofs.

**What it does not prove:** availability (node can withhold data); privacy of which leaf was queried; that two clients saw the same head without gossip/witnesses (equivocation).

### 2.4 Composition (Oblivio’s design theorem — informal)

**Assumptions.**

1. AES-GCM is IND-CPA / AEAD-secure with unique nonces and secret keys.  
2. HKDF is a secure KDF for per-record key separation.  
3. Ed25519 is EUF-CMA secure.  
4. SHA-256 is collision-resistant (and preimage-resistant for practical leaf binding).  
5. Clients verify all five checks before accepting data (`SECURITY.md`).  
6. Clients retain at least one pinned signed head from a past honest observation.

**Informal theorem (integrity).**  
If assumptions hold and a client has pinned head \(H_m = (\mathsf{size}=m, \mathsf{root}=R_m)\) with a valid signature, then any later head \(H_n\) (\(n \ge m\)) that verifies as a consistent extension, together with an inclusion proof for leaf \(\ell\) at index \(i < n\), implies: \(\ell\) was in the append-only sequence of leaves committed by that node’s signed history from \(m\) onward. Altering, reordering, or dropping an earlier leaf breaks consistency or inclusion against \(R_m\) / \(R_n\).

**Informal theorem (confidentiality).**  
If assumptions hold and the master key never leaves the client, the node’s view (ciphertext, record ids, padded sizes, and timing) does not reveal record contents, except via those metadata side channels. Labels are inside the AEAD and bound as AAD, so they are neither readable by the node nor substitutable between records.

These are **standard composition arguments**, not a new complexity-theoretic breakthrough. They are the correct level of rigor for a CT-style storage log.

---

## 3. What the *code* proves (and does not)

### 3.1 Tested

| Suite | What it establishes |
|-------|---------------------|
| `tests/test_merkle.py` | Exhaustive inclusion/consistency over small sizes; rejects tampered paths, wrong leaves, history rewrites |
| `tests/test_store.py` | Encryption round-trip; persistence; consistency detects rewrite |
| `tests/test_adversarial.py` | Real malicious HTTP nodes cannot substitute index/id, fork equal-size, or break AAD/label binding |
| `tests/test_replication.py` | Quorum client behavior under offline/tampered nodes |

That is **empirical verification of the implementation**, not a machine-checked proof that every code path is free of bugs.

### 3.2 Not claimed

| Claim | Status |
|-------|--------|
| Coq/Lean/Isabelle formalization of the full protocol | **Not done** |
| Novel ZK soundness proof | **Not claimed.** `circuits/` is a halo2 SNARK, but its soundness rests on halo2 and Poseidon as published — nothing here is a new proving system, and the circuit is optional: the keep verifies without it |
| Constant-time side-channel proof of Python crypto | **Not claimed** (uses `cryptography` / OpenSSL for AEAD & Ed25519) |
| Perfect metadata privacy | **Not claimed** |

### 3.3 Implementation note for scale

Current Merkle `root()` over a full leaf list is a recursive recompute — fine for development and moderate sizes; **production at multi-million leaves should use an incremental tree** (store intermediate hashes, \(O(\log n)\) update). Verification of a single inclusion proof remains \(O(\log n)\) hashes either way.

---

## 4. “Millions of proofs” — language choice

### 4.1 What “proof” means in Oblivio v0

Each **read** produces a **Merkle inclusion proof** (sibling hashes).  
Each **log growth** can produce a **consistency proof**.  
These are **hash computations**, not ZK proving systems — a statement about
inclusion and consistency proofs specifically, not about the repository. The
zero-knowledge work is separate: sigma protocols in `oblivio/zk.py`, and a
halo2 membership circuit in `circuits/` (§3.2).

| Scale | Work per proof | Language recommendation |
|-------|----------------|-------------------------|
| 10⁶–10⁹ leaves | ~20–30 SHA-256 compressions per verify | **Python is fine** for clients; C/OpenSSL already backs hashes via `hashlib` |
| Millions of verifies/sec (hot path) | Same, but throughput-bound | Optional: Rust/C for node hot path later |
| ZK proof per inference | Seconds–minutes, huge RAM | **Rust + arkworks / halo2 / etc.** — only if you add zkML |

### 4.2 Python vs Rust vs “ZK language”

| Approach | Use when |
|----------|----------|
| **Python (current)** | Product logic, CT-style logs, AES-GCM via `cryptography`, grant demos, research velocity |
| **Rust** | Extreme QPS, WASM clients, optional rewrite of Merkle hot path — **not required for correctness** |
| **Circom / Noir / Leo / halo2 circuits** | Actual zero-knowledge *statements* (e.g. “I know plaintext such that H(pt)=… without revealing pt”) — **not** what v0 does |

**Recommendation for the grant:** keep **Python as the reference implementation**. State clearly that the design deliberately avoids ZK proving cost for the memory path. Budget Rust only if reviewers demand production hardening, not because “proofs must be ZK.”

### 4.3 Why not put everything in ZK Rust now

- Wrong tool for integrity of encrypted blobs (hash proofs suffice).  
- Wrong cost model for “millions of proofs” (SNARK prove ≠ Merkle verify).  
- Increases audit surface and delivery risk for a first grant milestone.  
- Reviewers who know CT will respect honesty more than a premature circuit.

---

## 5. Alignment with whitepaper and code

| Whitepaper claim | Code | Foundations |
|------------------|------|-------------|
| Client-side AEAD | `crypto.py` AESGCM + HKDF | §2.1 |
| Signed tree heads | `crypto.signed_head_message` + Ed25519 | §2.2 |
| RFC 6962-style log | `merkle.py` | §2.3 |
| Five client checks | `client.py` + adversarial tests | §2.4, §3 |
| Not ZK for confidentiality | Explicit in whitepaper §3.4 | This document §1, §4 |

---

## 6. Suggested wording for grant applications

**Security basis**

> Oblivio implements a Certificate Transparency–style append-only log (RFC 6962 hashing) over client-encrypted records (AES-256-GCM). Clients verify Ed25519-signed tree heads and Merkle inclusion/consistency proofs before accepting data. Confidentiality does not rely on zero-knowledge proofs; integrity does not require SNARKs. Security therefore reduces to standard assumptions on AES-GCM, HKDF, Ed25519, and SHA-256 collision resistance, plus correct client verification (enforced by automated adversarial tests).

**Implementation language**

> The reference implementation is Python 3 with the `cryptography` library for AEAD and signatures, and SHA-256 for Merkle proofs. This matches the cost model of hash-based transparency logs. A future optional rewrite of performance-critical paths in Rust does not change the cryptographic design. Zero-knowledge proving systems are out of scope for the memory path milestones.

**What you will not claim**

> We do not claim a new ZK proving system, formal machine-checked verification of the entire codebase, or metadata privacy equivalent to PIR.

---

## 7. Optional future work (if a grant funds “stronger assurance”)

1. **Incremental Merkle tree** — \(O(\log n)\) appends at multi-million scale.  
2. **Independent audit** of client verification paths.  
3. **Test vectors** against a second RFC 6962 implementation (interop).  
4. **Formal models** (Tamarin/ProVerif) of the pin + consistency protocol — research track.  
5. **ZK/PIR** only for access-pattern privacy or zkML — separate milestones.

---

## 8. References (primary)

1. Laurie, Langley, Kasper — *Certificate Transparency* (RFC 6962).  
2. NIST SP 800-38D — GCM.  
3. Krawczyk, Eronen — *HMAC-based Extract-and-Expand Key Derivation Function* (RFC 5869).  
4. Josefsson, Liusvaara — *Edwards-Curve Digital Signature Algorithm* (RFC 8032).  
5. Certificate Transparency industry practice: Merkle audit and consistency proofs as operational integrity tools.

---

*This file is the authoritative statement of cryptographic claims for Oblivio. If marketing copy conflicts with it, this file wins.*

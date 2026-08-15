# Path to free compute and memory at scale

**Status:** strategy document · 2026-08-05  
**Code today:** local encrypted, verifiable *memory* (replication in progress; not ZKML)  
**Goal:** an open network where most users get **free** private AI memory (and later compute); a **small** paid slice funds operations; Zcash-adjacent privacy economics where payment is needed.

---

## 1. Free for most users

| Layer | Free path | Paid path (optional) |
|-------|-----------|----------------------|
| **Software** | MIT — anyone may run a node | Same code |
| **Community capacity** | Volunteer and grant-sponsored nodes | Reserved bandwidth / SLA |
| **Operated public mesh** (if any) | Generous free quota | Micropay above quota |
| **Privacy** | Client encrypts; nodes never need plaintext | Same |

**Basically free** means a free tier strong enough that the large majority of users never pay.  
Paid capacity is for power users and commercial deployments that need guarantees—not a tax on ordinary use.

Prefer meters that map to real cost:

| Meter | Measures |
|-------|----------|
| GB-month encrypted storage | Memory footprint |
| Inclusion-proof reads / day | Retrieval load |
| Bandwidth egress | Network cost |
| GPU-seconds (later) | Compute |

Example (illustrative only): a small overage fee per GB-month above free quota, settleable in ZEC when a paid path exists. Pricing “per LLM token” only makes sense if the project itself serves inference.

---

## 2. Where zero-knowledge fits

| Property | Primitive | Horizon |
|----------|-----------|---------|
| Node cannot read data | Client-side AES-GCM | **Shipped** |
| Node cannot rewrite history | Merkle + signed heads | **Shipped** |
| Private payment | ZEC shielded transactions | When paid path exists |
| Storage held over time | PoRep / PoSt / audits (ZK optional) | Mesh phase |
| Honest inference without revealing inputs | ZKML | Later — expensive |
| Hide which record was requested | PIR | Research |

**Accurate today:** cryptographically verifiable encrypted memory for local AI; Zcash-adjacent privacy economics later.  
**Not accurate as a present claim:** full ZKML free LLM inference for everyone on community nodes.

---

## 3. MIT and fees

See [`LICENSE_RIGHTS.md`](LICENSE_RIGHTS.md).

| Retain under MIT | Not granted by MIT alone |
|------------------|---------------------------|
| Copyright | Exclusive ban on others commercializing forks |
| Right to host and sell services | Forced fees on self-hosted deployments |
| Trademark / brand control | “All rights reserved” while claiming full open source |

Fees belong on **operated network capacity**, not on a crippled license.

---

## 4. ZEC grants as capital

**Programs:**

- [Zcash Community Grants](https://zcashcommunitygrants.org/)  
- [Zcash Foundation grants](https://zfnd.org/grants/)  
- [Community forum — grants](https://forum.zcashcommunity.com/c/grants/33)

**Typically fund:** public-good privacy infrastructure, open source, Zcash adoption.  
**Poor fit:** closed tokens first, vapor roadmaps, no runnable software.

### Milestones

| ID | Deliverable | Rationale |
|----|-------------|-----------|
| **M0** | Public GitHub + MIT + runnable memory node | Repository live |
| **M1** | Multi-node replication + docs + demo | Network seed |
| **M2** | Free community quota + operator metrics | Scale story |
| **M3** | Optional ZEC micropay above free quota | Zcash-native settlement |
| **M4** | Local model integration (e.g. Ollama) using Oblivio memory | End-user product |
| **M5** | PoR / light ZK where cost is justified | Honest advanced path |

**Illustrative budget split for grant ZEC:**

- 40% — sponsored nodes for free tier  
- 30% — engineering (replication, UX, security audit)  
- 15% — documentation, demos, community  
- 15% — reserve / audit / legal  

---

## 5. Build order

```
M0  Public MIT release — node / client / tests
 ↓
M1  Multi-node replication; clients pin any honest head
 ↓
M2  Public free pool (grant-funded capacity) + metrics
 ↓
M3  Optional paid overage in ZEC — free path remains default
 ↓
M4+ Local inference glue; ZK only where it earns its cost
```

Free **compute** for the public is a later layer on free **memory**:

1. Memory network (this repository)  
2. Inference — local/edge open models; optional shared GPUs  
3. ZK — payments privacy and storage audits first; not full LLM SNARKs as v0  

---

## 6. Repository

**https://github.com/zcashsensei/oblivio**

---

## 7. One-line grant / GitHub pitch

> **Oblivio** is MIT-licensed, privacy-preserving AI memory infrastructure: clients encrypt, nodes store ciphertext, Merkle proofs detect tampering. Free tier for the public (grant-sponsored capacity); optional micropay for guaranteed capacity, settleable in ZEC. Compute and ZKML are later layers on a working free memory path.

---

## 8. Out of scope (until deliberately reopened)

- Marketing ZKML as shipping before it ships  
- Replacing MIT with a license that blocks self-host freedom without a recorded decision  
- Pricing the free path into uselessness  
- Absorbing unrelated grid/power-coordination products  
- Speculative token launches before a free mesh works  

Related files: [`LICENSE`](LICENSE) · [`LICENSE_RIGHTS.md`](LICENSE_RIGHTS.md) · [`CONTRIBUTING.md`](CONTRIBUTING.md) · [`THESIS.md`](THESIS.md) · [`WHITEPAPER.md`](WHITEPAPER.md)

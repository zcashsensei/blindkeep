# Endpoint math: what closes each gap, and what the receipt can compute

**Compiled 2026-08-14.** Companion to
[`ENDPOINT_PRIVACY_RESEARCH.md`](ENDPOINT_PRIVACY_RESEARCH.md), which catalogues
the attacks. This document maps each of the three structural blockers to the
mathematics that bounds it, under the project's standing constraint: **zero
provider cooperation.** Everything here runs on our side of the wire.

The organizing claim, stated first so the rest can be judged against it:

> **"True API privacy" against a frontier provider is not leak-zero. It is
> leak-BOUNDED — and every one of the three gaps has a mechanism whose residual
> leakage is a computable number.** ε for content and style (differential
> privacy), log₂(buckets) bits for response length, k-of-N unlinkable
> presentations for identity, and a disclosed-bits budget for the anonymity
> set. The receipt's job is to print the numbers. A receipt that carries
> quantified per-channel leakage bounds instead of assertions is a
> contribution no system in the survey makes.

---

## Blocker 1 — Content: the model must read plaintext

### The only true closure is not available to us

Fully homomorphic encryption over a transformer would close this gap outright,
and the field is moving: a 2024–2025 survey
([Private Transformer Inference](https://arxiv.org/pdf/2412.08145)) tracks
CKKS-based systems, and hybrid TEE+FHE designs
([Bifrost](https://arxiv.org/html/2606.17421)) now demonstrate GPT-2-class and
sub-10B models. One 2026 preprint
([FHE on Llama-3](https://arxiv.org/abs/2604.12168)) claims up to 80 tokens/s
on a CPU — treat that number with suspicion until independently reproduced; it
is orders of magnitude out of line with the survey consensus. Two facts stand
regardless:

1. Pure FHE at **frontier** scale (100B+ served weights) remains out of reach.
2. FHE requires the **provider** to run the FHE stack. That violates the
   zero-cooperation constraint. It is their move, not ours.

Same verdict for zkML (proves integrity, does not hide inputs from the prover)
and MPC (bandwidth arithmetic; see WHITEPAPER §5.5–5.6).

### The math that IS available: local differential privacy on the outbound text

This is the single biggest upgrade available to the project. LeakGate today is
a **mechanical refusal** — a heuristic that blocks named entities and refuses
on survival. The literature now provides the same function with a **provable
bound**:

- **[InferDPT](https://arxiv.org/abs/2310.12214)** (IEEE TDSC 2025) — the
  direct blueprint. A local *perturbation module* applies the exponential
  mechanism (their RANTEXT variant, robust to embedding-inversion) to produce a
  differentially private prompt; the frontier model answers the perturbed
  prompt; a local *extraction module* (a small model — our Ollama slot)
  reconstructs the coherent answer. Closed-box, works against any frontier API,
  no provider cooperation.
- **[DP-Fusion](https://arxiv.org/html/2507.04531v1)** — token-level DP
  inference: provably bounds what the outbound text reveals about designated
  sensitive tokens, tunable by ε (ε=0 hides the token class entirely). This is
  LeakGate's exact job, with a dial and a proof.
- **[DP-GTR](https://arxiv.org/html/2503.04990)** (group text rewriting) and
  **[CAPE](https://www.researchgate.net/publication/391657612_CAPE_Context-Aware_Prompt_Perturbation_Mechanism_with_Differential_Privacy)** —
  prompt-level rewriting mechanisms with formal DP accounting.

What changes for us: the abstraction step stops being "the local model
rephrased it, we hope that helps" and becomes a **sampled draw from a DP
mechanism with a stated ε**. The receipt then computes a claim of the form:

> *outbound text is (ε, δ)-indistinguishable with respect to the gated private
> facts; ε = 4.2 this session*

— a measured property, in the same voice as the transport receipt. Refusal
stays as the backstop when the ε budget is exhausted.

### The provider-side path: watch it, verify it, do not wait for it

- **[Anthropic's confidential inference sketch](https://www.anthropic.com/research/confidential-inference-trusted-vms)**
  (with Pattern Labs) — trusted-loader VM, untrusted inference server, TPM
  attestation, keyserver-gated decryption. **Design phase; attestation chains
  to Anthropic's keyserver, not to the user.** Not yet a privacy guarantee for
  us — but it is the frontier provider saying the architecture out loud.
- **[Apple PCC expanded onto Google Cloud / NVIDIA Blackwell](https://blogs.nvidia.com/blog/nvidia-confidential-computing-apple-private-cloud-compute/)**
  (2026) — attested frontier-scale inference with **two independent hardware
  roots** and a public transparency log now runs on rented cloud GPUs. The
  precedent Oblivio needs: user-side attestation verification at frontier
  scale is deployable, because someone deployed it.
- **[NVIDIA CC remote attestation](https://www.nvidia.com/en-us/glossary/confidential-computing/)** —
  GPU-signed report covering firmware and workload hash, verifiable before
  data is released.

Our `sev_snp.py` lineage is the right skill for this moment. The move is not
to build a TEE — it is to make the receipt able to **verify a provider's
attestation the day one becomes user-verifiable**, and to print `attestation:
none offered` until then. That line in the receipt is itself leverage.

---

## Blocker 2 — Metadata: length, timing, and the transport's own limits

### Length: deterministic buckets, because the leakage is then a number

[Whisper Leak](https://arxiv.org/abs/2511.03675) demonstrated >98% AUPRC topic
inference from packet sizes and timing, and evaluated the obvious mitigations —
random padding, batching, injection — finding each **reduces but does not
eliminate**. Random padding fails against averaging because it leaves a
distribution. The math that yields a printable bound:

- **Quantize every response into fixed size buckets.** With N buckets, the
  length channel leaks **exactly log₂(N) bits, worst case** — a
  quantitative-information-flow bound (min-entropy / maximal leakage), not a
  hope. 8 buckets = 3 bits. The receipt prints it.
- **Constant-rate release** (already doctrine: timing privacy is scheduling,
  not crypto) zeroes the inter-packet timing channel while active; the
  residual is total session duration — one more bounded, statable number.
- **Non-streaming mode is a free closure.** The intra-response channel exists
  only because tokens stream. Fetch the full completion, release it at once:
  channel eliminated, cost is latency. Offer it as a flag; receipt records
  which mode ran. (OpenAI/Azure/Mistral shipped obfuscation fields after
  Whisper Leak; ours must not depend on the provider's.)

### Identity: upgrade blind tokens to ARC

`anon_token.py` is one-shot Chaum — correct, but issuance-per-query creates a
linkable cadence and a DoS surface. The IETF Privacy Pass WG is standardizing
**[Anonymous Rate-Limited Credentials](https://datatracker.ietf.org/doc/draft-ietf-privacypass-arc-protocol/)**
([crypto companion](https://datatracker.ietf.org/doc/draft-ietf-privacypass-arc-crypto/)):
one issuance yields **N pairwise-unlinkable presentations**, each bound to a
presentation context, with rate limiting the issuer can enforce without
linking. Keyed-verification anonymous credentials, standards lineage on top of
[RFC 9578](https://www.rfc-editor.org/rfc/rfc9578). This solves entitlement +
rate-limiting + unlinkability in one object and replaces a solved-problem
reimplementation with the current standard's math.

### Transport residuals: already documented, now schedule them

The OHTTP items from the survey (§2.3) stay as operational math, not new
crypto: gateway key rotation bounds the no-forward-secrecy exposure window to
one rotation period (a number; print it), and relay-side delay/batching is
anonymity-set enlargement per the mix literature (batch size k = the set; print
it).

---

## Blocker 3 — The prompt is an identifier: stylometry and the anonymity set

### Style: the same DP math, applied at the sentence level

The survey's open question — does local abstraction normalize style? — should
not be answered empirically alone. It can be **forced by construction**:

- **[DP-Prompt](https://aclanthology.org/2023.findings-emnlp.566.pdf)** —
  zero-shot DP paraphrase: sample the paraphrase from the local model under
  temperature-calibrated decoding and the draw satisfies local DP at a
  computable ε.
- **[Mattern et al.](https://arxiv.org/html/2501.19022v1)** — sentence-level
  paraphrase with formal DP guarantees; **[DP-MLM](https://arxiv.org/html/2503.04990)**
  — token-wise privatization under the exponential mechanism.

The decisive property is **post-processing immunity**: anything computed from
an ε-DP output — including a stylometry classifier, including
[tournament-style attribution at scale](https://arxiv.org/html/2601.12407v2) —
inherits the same ε bound. Attribution advantage is capped by mathematics, not
by whether our prose "looks different." Since our abstraction is already
generated by the local model, this is a decoding-strategy change, not an
architecture change: **abstract, then privatize the abstraction.**

Run the survey's proposed measurement anyway (attribution AUC before/after) —
as the *validation* of the bound, not the substitute for it.

### The anonymity set: budget disclosed bits instead of gesturing

`max_specificity` gestures at re-identification without measuring it. The
honest computable proxy, from quantitative information flow: assign each
disclosed quasi-identifier category an entropy cost in bits against a stated
population model, and enforce a **per-session disclosed-bits budget**. 33 bits
identifies a human among 8 billion; a receipt that prints *"this session
disclosed ≤ 11 bits toward re-identification (budget 16)"* states exactly what
[subject-level inference evaluation](https://arxiv.org/pdf/2604.21211) says
PII-token counting cannot. It is a bound under a declared model — say the
model, print the number, refuse when the budget is spent. The εs from DP
mechanisms compose into the same ledger (sequential composition: εs add).

---

## Bonus closure — the keep's own metadata: PIR is no longer "later"

THESIS lists "PIR later" for node-side access patterns. That "later" is over:
**[SimplePIR / DoublePIR](https://eprint.iacr.org/2022/949)** (USENIX Sec '23)
serve single-server PIR at ~10 GB/s/core under plain LWE — for a 1 GB keep,
a one-time 16 MB hint (DoublePIR) then ~345 KB per query, unbounded queries.
At our scale, **which record was consulted** can be hidden from the node for
practically nothing. This composes with the frontier path: a node that cannot
see which memory fed a question cannot correlate keep reads with outbound
traffic. One caveat to carry: the hint must be re-fetched as the log grows;
amortize over an epoch, print the epoch in the receipt.

---

## What this buys, in one table

| Channel | Mechanism | Receipt line it enables |
|---|---|---|
| Private facts in content | Exponential-mechanism perturbation (InferDPT / DP-Fusion) | ε spent this session |
| Style fingerprint | DP paraphrase decoding (DP-Prompt lineage) + post-processing immunity | ε, attribution AUC from validation runs |
| Response length | Deterministic bucketing | log₂(N) bits, worst case |
| Timing | Constant-rate or non-streaming | channel active: yes/no |
| Who is asking | ARC (Privacy Pass WG) | k unlinkable presentations of N |
| Transport recording | OHTTP key rotation | exposure window in days |
| Anonymity set | Disclosed-bits budget (QIF) | bits spent / budget, population model named |
| Keep access pattern | DoublePIR | hint epoch, query cost |
| Provider plaintext handling | none ours; verify TEE attestation when offered | `attestation: none offered` |

Ordered by claim-per-effort: **(1)** DP perturbation replacing bare LeakGate —
it converts the project's central mechanism from heuristic to theorem;
**(2)** length bucketing + non-streaming flag — small code, closes the loudest
published attack; **(3)** disclosed-bits ledger — unifies every mechanism into
one budget the receipt prints; **(4)** ARC migration when the draft stabilizes;
**(5)** PIR on the keep read path; **(6)** attestation verification, armed and
waiting for the first user-verifiable frontier endpoint.

### Implementation status (2026-08-14)

`oblivio/dp.py` ships the first tranche, with each guarantee scoped to what
the code actually delivers:

| Item | Shipped as | Scope of the claim |
|---|---|---|
| (1) EM selection | `dp.dp_delegate`, default on in `frontier_chat` | The **choice** among gate-cleared candidates is exponential-mechanism-randomised (preference ratio ≤ e^ε). **Not** end-to-end DP of the text: that needs the token-level embedding-metric mechanism (InferDPT), which stays roadmap. The gate is unchanged and still absolute. |
| (2) Length + streaming | `dp.pad_to_bucket` via a padding **header** in `cloud_gate`; non-streaming is how `cloud_complete` already reads | Deterministic buckets: padded length leaks ≤ log₂(N) bits, exactly. Receipt reports both **from the completer that ran**, never from a caller flag. Gateway/OHTTP leg not yet padded — the receipt correctly shows it unassessed. |
| (3) Ledger | `dp.PrivacyLedger`, charged **before** every send | ε adds by sequential composition; specificity is charged as the honest **proxy** it is (no invented "bits"). Budget exhausted ⇒ refusal. |
| (6) Attestation | `FrontierReceipt.attestation` | Prints `none offered` until a frontier provider ships user-verifiable attestation; verifying it becomes a value change, not a schema change. |
| (4) ARC, (5) PIR | not started | ARC waits on the IETF draft stabilising; PIR is a self-contained follow-up on the keep read path. |

## Where the ZK layer actually plugs in

The temptation is to point the halo2 work at the frontier path directly. The
survey already recorded the discipline: **ZK proves membership in the keep,
not anything about the frontier path — and it does not hide the prompt from
the model.** Proving the LLM's own sampling in-circuit is zkML, ruled out at
scale (WHITEPAPER §5.5).

But everything in this document creates a *new, cheap* job for the existing
circuits, because every mechanism above reduces to small arithmetic:

- ε-ledger accounting is addition; a budget check is a **range proof** —
  already shipped as a sigma protocol.
- Length bucketing is a quantization; "this response fits bucket b of N" is a
  range proof.
- The disclosed-bits budget is a sum of committed per-category costs against a
  cap — range proof over Pedersen-committed values, again already in the
  toolbox.
- ARC presentations are themselves keyed-verification anonymous credentials —
  the same algebra family as our sigma proofs.

So the composition available to no other project in the survey: **a
proof-carrying receipt** — the client attaches a succinct proof that the
session respected its declared budgets (ε spent ≤ ε_max, bits disclosed ≤
budget, bucket discipline held) *without revealing the prompts, the facts, or
the per-item costs*. The gateway, or any third party, verifies the proof
instead of trusting the client's self-report — and the receipt's central claim
("measured, not asserted") becomes **verified, not merely measured**. That is
the honest sense in which the ZK layer changes the game here: not private
inference, but **publicly verifiable privacy accounting** on top of it.

---

None of this makes "first private frontier chat" true. It makes something
better true: **the first endpoint whose receipt states, per channel, how much
it leaked — as numbers it computed, under assumptions it names — and can hand
anyone a proof that the budget held.**

# Endpoint privacy: what the field knows, and where Blindkeep stands

**Compiled 2026-08-13.** A survey of the published work on private endpoints to
frontier models, and an honest placement of this project inside it.

Written because the project was about to claim primacy it does not hold. Three
claims were checked and two of them failed. What survives is narrower, real, and
worth defending — but only if stated exactly.

---

## 1. What is already done, by whom

### Account decoupling (hiding WHO is asking)

This is solved, published, and shipped.

- **[LLM-Tor](https://github.com/prince776/LLM-Tor)** — a privacy layer for
  frontier LLMs. Users buy credits, the client generates blind tokens, the
  server blind-signs them, the client redeems over Tor. The server cannot link
  usage to identity. ([Show HN](https://news.ycombinator.com/item?id=47298201))
- **[A Practical and Privacy-Preserving Framework for Real-World LLM
  Services](https://arxiv.org/html/2411.01471)** — partially blind signatures
  for anonymous LLM access, with distinct schemes for subscription and
  per-request billing.
- **DuckDuckGo AI Chat**, **Brave Leo** — production proxies that hold the
  provider account so the provider never learns the end user.
- **[Privacy-preserving Loyalty Programs](https://arxiv.org/pdf/1411.3961)** and
  the blind-signature patent literature
  ([1](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/12341891),
  [2](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/8281149))
  — the primitive is decades old, from Chaum.

**Blindkeep's `anon_token.py` is a reimplementation of a solved problem.** It is
correct and it is ours, but it is not new. Claiming novelty here is the fastest
way to lose a referee.

### Encrypted / decentralised AI memory

Also occupied.

- **[Opal: Private Memory for Personal AI](https://arxiv.org/html/2604.02522)**
- **[ZetaChain encrypted agent memory](https://www.zetachain.com/blog/encrypted-ai-agent-memory-personalization)**
- **[Plurality Network's Open Context Layer](https://plurality.network/blogs/ai-memory-limitations-and-llm-memory-types/)** — portable context vaults
- **[COSMP / decentralized memory wallet](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/12517919)** (patented)
- **[Cryptographic Data Sovereignty for LLM Training](https://www.dataversity.net/articles/cryptographic-data-sovereignty-for-llm-training-personal-privacy-vaults/)**
- **[MIRIX](https://arxiv.org/pdf/2507.07957)** — multi-agent memory systems
- **[Privacy-Preserving Decentralized AI with Confidential Computing](https://arxiv.org/html/2410.13752v2)**

### Attested confidential inference

Ahead of us, at scale.

- **[Apple Private Cloud Compute](https://security.apple.com/blog/private-cloud-compute/)**
  — Secure Enclave attestation, an append-only transparency log of every
  production build, devices refusing to talk to nodes that cannot attest to
  publicly listed software, and attestation rooted in *two independent vendors*
  to resist supply-chain compromise.
  ([research access](https://security.apple.com/blog/pcc-security-research/),
  [expansion](https://security.apple.com/blog/expanding-pcc/),
  [CSA threat model](https://cloudsecurityalliance.org/articles/apple-intelligence-private-cloud-compute-pcc-initial-threat-modeling),
  [academic analysis](https://arxiv.org/html/2605.24239v1),
  [open alternative](https://www.edgeless.systems/blog/apple-private-cloud-compute-core-concepts-and-an-open-alternative))
- **[Narrowing the Gap between TEE Threat Models and Deployment](https://arxiv.org/pdf/2506.14964)**

Blindkeep's `sev_snp.py` has never seen real hardware. Against PCC's two
independent roots of trust and public transparency log, our attested tier is a
design, not a capability. Say so.

### The transport

- **[RFC 9458 Oblivious HTTP](https://www.ietf.org/rfc/rfc9458.html)**
  ([info](https://www.rfc-editor.org/info/rfc9458/), [ohttp.info](https://ohttp.info/))

### Zero-knowledge lineage

- **[Halo: Recursive Proof Composition without a Trusted Setup](https://eprint.iacr.org/2019/1021.pdf)**
  — Bowe, Grigg, Hopwood, 2019.
  ([ECC announcement](https://electriccoin.co/blog/halo-recursive-proof-composition-without-a-trusted-setup/),
  [what is Halo](https://z.cash/learn/what-is-halo-for-zcash/),
  [zkSummit talk](https://www.youtube.com/watch?v=OhkHDw54C04))
  Nested amortisation over cycles of elliptic curves removes the trusted setup;
  shipped in Zcash NU5 (Orchard, May 2022).

Our halo2 Merkle circuit inherits directly from this. That lineage is real and
worth stating — **and it proves membership in the keep, not anything about the
frontier path.** The two are orthogonal. ZK does not close the metadata gap.

---

## 2. Where the field says we are wrong

Four documented attacks that the current receipt does not mention. Each is a
disclosure gap in the one artifact whose entire job is honest disclosure.

### 2.1 Prompts are a behavioural biometric

- **[PromptPrint: Behavioral Biometrics Through Natural Language Prompting](https://arxiv.org/pdf/2606.06755)**
- **[Assessing Deanonymization Risks with Stylometry-Assisted LLM Agent](https://arxiv.org/abs/2602.23079v1)**
- **[De-Anonymization at Scale via Tournament-Style Attribution](https://arxiv.org/html/2601.12407v2)**
- **[Stylometry recognizes texts in short samples](https://www.sciencedirect.com/science/article/abs/pii/S0957417425026181)**
- **[Authorship Impersonation via LLM Prompting does not Evade Verification](https://arxiv.org/pdf/2603.29454)**

Word frequency, sentence length, syntax and punctuation form a fingerprint that
survives paraphrase. LeakGate removes **facts**. It does not touch **style**.

There is a plausible accidental defence: our abstraction is *generated by the
local model*, so what leaves is the local model's prose, not the user's. That is
a real argument and it is currently **untested**. It should be measured, not
assumed — the local model is conditioned on the user's phrasing, and the last
paper above finds that prompting a model to impersonate a style does not defeat
authorship verification.

### 2.2 Token-length and timing side channels

- **[Whisper Leak](https://arxiv.org/html/2511.03675v1)** — infers prompt topic
  from encrypted streaming traffic; 100% precision on some sensitive topics,
  recovering 5–20% of target conversations.
- **[Time Will Tell: Timing Side Channels via Output Token Count](https://arxiv.org/pdf/2412.15431)**
- **[When Speculation Spills Secrets](https://arxiv.org/pdf/2411.01076)** —
  speculative decoding leaks.
- **[Schneier's summary](https://www.schneier.com/blog/archives/2026/02/side-channel-attacks-against-llms.html)**

TLS hides text, not record lengths. Streaming responses emit packet sizes that
track token lengths. **This defeats content privacy without breaking any
crypto**, and OHTTP does not help. Documented mitigations — padding, batching,
packet injection — reduce it and none eliminate it.

### 2.3 OHTTP's own stated limits

Straight from RFC 9458, and none of it is in our receipt:

- **No forward secrecy** against gateway key compromise. Recorded ciphertexts
  are decryptable if the gateway private key later leaks.
- **A malicious relay can do traffic analysis** — it is not only network
  observers. The RFC's suggested mitigation is for the relay to *delay* requests
  to enlarge the anonymity set.
- Both hops must be HTTPS, and the relay must not be the gateway operator.

### 2.4 Re-identification is about anonymity sets, not PII tokens

- **[Subject-level Inference for Realistic Text Anonymization Evaluation](https://arxiv.org/pdf/2604.21211)**
- **[SurrogateShield: Beyond Redaction](https://arxiv.org/pdf/2606.29567)**
- **[Adaptive Text Anonymization: Privacy-Utility Trade-offs](https://arxiv.org/pdf/2602.20743)**
- **[Preempting Text Sanitization Utility](https://arxiv.org/pdf/2411.11521)**
- Practitioner pipelines: [Presidio-based](https://wavect.io/blog/pii-redaction-before-llm-prompts/),
  [gateway pattern](https://www.gravitee.io/blog/how-to-prevent-pii-leaks-in-ai-systems-automated-data-redaction-for-llm-prompt),
  [2026 overview](https://pctechmag.com/2026/06/pii-redaction-for-llms-in-2026-how-to-strip-sensitive-data-before-it-leaves-your-perimeter/)

The literature is blunt: no redaction approach guarantees anonymisation. The
real question is whether the *combination* of disclosed facts narrows the
anonymity set below a threshold — an open problem, and orthogonal to catching
explicit PII. Our `max_specificity` gestures at this without measuring it.

---

## 3. What actually survives as ours

Stated so a referee cannot knock it down:

> Every anonymising LLM proxy in section 1 hides **who** is asking and forwards
> the prompt **verbatim**. Blindkeep abstracts the question locally first and
> mechanically refuses to transmit when identifying terms survive, so the proxy
> operator — not only the provider — is denied the private facts. The trusted
> party is strictly smaller. It is MIT and self-hostable, so every role can be
> run by the user.

And the part with no counterpart found in any source above:

> The receipt computes each privacy property from the transport that actually
> ran, and refuses the claim when the facts do not hold. Privacy systems
> generally *assert* their properties. This one *measures* them and says no.

That is a modest, defensible, publishable contribution. "First private frontier
chat" is not.

---

## 4. What to do about it

Ordered by evidence, not by effort.

| # | Action | Source |
|---|---|---|
| 1 | Disclose §2 risks in the receipt's residual list | all of §2 |
| 2 | Measure whether local abstraction normalises style | §2.1 |
| 3 | Pad and batch responses; document that it mitigates, never eliminates | §2.2 |
| 4 | Rotate the gateway OHTTP key; state the lack of forward secrecy | §2.3 |
| 5 | Add relay-side delay to enlarge the anonymity set | RFC 9458 |
| 6 | Stop claiming primacy anywhere in the repo | §1 |

Item 1 is the honest floor: a receipt that omits four documented attacks is
overclaiming by silence, which is the same defect class as the transport bug
fixed on 2026-08-13 — a claim that outran what the code could support.

**Follow-up:** the mathematics that bounds each §2 attack — and what it lets
the receipt compute — is mapped in [`ENDPOINT_MATH.md`](ENDPOINT_MATH.md).

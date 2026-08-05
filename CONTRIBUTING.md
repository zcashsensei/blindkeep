# Contributing to Blindkeep

**Version 0.1 · 2026-08-05**

Read this before opening a pull request. It records the design constraints that
are not up for renegotiation, and the reasoning behind them.

## Design principles

### Privacy

| Rule | Meaning |
|------|---------|
| **Ciphertext only on nodes** | The client encrypts. A node must never receive a master key or plaintext. |
| **No third-party data paths by default** | Do not add a code path that forwards user prompts or records to an external API. If one is ever added it must be opt-in and explicitly labelled as not private. |
| **The current release calls no external model APIs** | Keep it that way until a deliberate gateway design exists. |
| **Privacy is structural, not contractual** | A guarantee holds because data is never sent, not because a provider promises not to look. |

### Cryptography

Reach for the cheapest primitive that actually delivers the property:

| Requirement | Use | Do not reach for first |
|-------------|-----|------------------------|
| Record untampered | Content hash / Merkle leaf | SNARK |
| Correct retrieval | Inclusion proof against a signed root | SNARK |
| Node cannot read data | Client-side AEAD | "ZK everything" |
| Append-only history | Consistency proof + pinned head | Trust |
| Hide *which* record was requested | PIR — hard, later | ZK branding |
| Prove inference was honest | zkML — hard, later | Claiming it ships today |

Zero-knowledge proving has a real place in this project's future: proof of
retrievability, storage audits, and shielded payments are all legitimate uses
that involve no machine learning at all. What is not acceptable is describing
any of it as shipping before it does.

### Scope discipline

| Do | Don't |
|----|-------|
| Ship runnable memory: put, get, verify | Convert the project into a specification with no implementation |
| Keep the adversarial tests green | "Simplify" by removing request-binding checks |
| Build peer discovery, witnessing, retrievability proofs next | Add tokenomics before the free path is useful |
| Keep README claims true today | Market capabilities that do not exist yet |

## The security invariant

> **A valid proof is not an answer to your question.**
>
> Bind a response to the **request** — index, record id, node identity — before
> trusting any proof inside it. Self-consistent is not the same as responsive.

This is not theoretical. Four vulnerabilities of exactly this shape were found
and fixed before the first release; see [`SECURITY.md`](SECURITY.md). Any new
endpoint must echo-check its request key and ship an adversarial test.

## Pull requests

1. **Never regress `tests/test_adversarial.py`.** It is the executable form of
   the security claims in the README.
2. **Never add a default code path that sends user data to a third party.**
3. New verification logic needs a test that fails without it.
4. Run the full suite before submitting:

```bash
python tests/test_merkle.py
python tests/test_store.py
python tests/test_adversarial.py
python demo.py
```

## Claims discipline

The README's credibility is the project's main asset. Two claims must stay
accurate as the code changes:

- **What is protected** — currently confidentiality of record contents, and
  detection of tampering, reordering, dropping and substitution.
- **What is not** — currently metadata: record counts, ciphertext sizes,
  timestamps, access patterns, and plaintext labels.

If a change alters either list, the README changes in the same pull request.

## Licensing

Contributions are accepted under the MIT license in [`LICENSE`](LICENSE). By
submitting one you affirm you have the right to license it under those terms.

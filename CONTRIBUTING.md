# Contributing to Blindkeep

**Version 0.2 · 2026-08-06**

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
| Build witnessing and proof of storage next | Add tokenomics before the free path is useful |
| Keep README claims true, and dated | Market capabilities that do not exist yet |

### Tests that assert limitations

Several tests exist to pin down what the system does **not** do:

| Test | Asserts |
|------|---------|
| `test_access_pattern_is_still_visible` | the node still sees which record is read |
| `test_redaction_is_documented_as_incomplete` | redaction leaves sensitive prose untouched |
| `test_no_default_module_imports_the_cloud_gate` | no default path can reach a hosted provider |

These fail when the limitation is fixed, which is the point: a limitation that
is only written in a document decays into an assumption. If one of them starts
failing, the correct response is to update the documentation in the same change,
not to delete the test.

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
- **What is not** — currently metadata: record counts, bucketed ciphertext
  sizes, timestamps, and access patterns. Labels used to be on this list and no
  longer are: they travel inside the AEAD, so the node stores an empty label
  field.

If a change alters either list, the README changes in the same pull request.

### Test counts are computed, never typed

Five separate times, a commit shipped a test suite and left the totals in the
documents behind it — twice in the files a grant reviewer reads first. The
numbers are derivable from the source, so no one should be retyping them.

Install the hook once per clone:

```
py -3 tools/install_hooks.py
```

`pre-push` then runs `tools/check_counts.py`, which fails the push if any
document states a total, a suite count, or a per-suite roster entry that the
source does not support. It takes about a second. To regenerate the roster
after adding a suite:

```
py -3 tools/check_counts.py --print-roster
```

Adding a suite therefore requires one deliberate step — a label in
`tools/check_counts.py` — and the checker refuses until it is there, so a new
suite cannot be silently left out of the documentation. To run every suite as
well (about seven minutes, and what CI should do):

```
py -3 tools/check_counts.py --run-tests
```

Note that `blindkeep status` **counts** tests by reading the source; it does not
run them. A green count is not a green run. Only `--run-tests` executes them,
and it trusts exit codes rather than output text — the suites print `ok`,
`PASS`, `N passed` and `13 merkle tests passed`, so any parser of that text
mislabels healthy suites as failures.

## Licensing

Contributions are accepted under the MIT license in [`LICENSE`](LICENSE). By
submitting one you affirm you have the right to license it under those terms.

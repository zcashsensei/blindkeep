<h1 align="center">Blindkeep</h1>

<p align="center">
  <strong>Verifiable, encrypted memory for local and sovereign AI.</strong><br>
  Your agent remembers you. The node holding those memories cannot read them,
  and cannot rewrite them without you finding out.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/tests-185%20passing-brightgreen.svg" alt="185 tests passing">
  <img src="https://img.shields.io/badge/status-v0%20alpha-orange.svg" alt="v0 alpha">
  <img src="https://img.shields.io/badge/dependencies-1-lightgrey.svg" alt="1 dependency">
</p>

<p align="center">
  <sub><b>Status as of 2026-08-06</b> · v0 alpha · 185 tests passing · replication,
  peer discovery, retrieval audits, key recovery and local-model memory
  implemented · no proving system implemented · not yet run by anyone but the author</sub>
</p>

---

## What it is

Blindkeep is privacy-preserving infrastructure for AI memory. Clients encrypt
everything locally; storage nodes hold **ciphertext they have no key for**,
committed to an **append-only Merkle log** they cannot alter undetected.

v0 ships the memory layer. There is no token, no chain, no SNARK, and **no calls
to any cloud LLM provider** — a design constraint, verified by a test.

## The guarantee

A Blindkeep node is untrusted for both confidentiality and integrity. Every value
the client returns has passed five independent checks:

| # | Check | Defeats |
|---|-------|---------|
| 1 | Response is bound to the **request** | A node answering a different question than asked |
| 2 | Ed25519 signature on the tree head | A forged or unsigned log state |
| 3 | Merkle **inclusion** proof | Serving a blob it never committed to |
| 4 | Merkle **consistency** proof vs. a pinned head | Rewriting, reordering or dropping history |
| 5 | AES-256-GCM authenticated decryption | Any modification of the ciphertext |

Any one failing raises instead of returning data. These are enforced by
[`tests/test_adversarial.py`](tests/test_adversarial.py), which stands up **real
malicious nodes** and asserts the client refuses them.

## Design choice: not zero-knowledge for v0

Integrity and confidentiality of stored memory do not require SNARKs. Cheaper,
auditable primitives are used first:

| Goal | Tempting default | What Blindkeep uses |
|------|------------------|---------------------|
| Record untampered | ZK proof | Content hash / Merkle leaf |
| Correct retrieval | ZK proof | Inclusion proof vs. signed root |
| Node cannot read data | ZK proof | Client-side AES-256-GCM |
| Append-only history | Trust | Consistency proof + pinned head |

Zero-knowledge remains appropriate later for private queries (PIR), storage
audits, and verifiable inference (zkML). None of those are claimed in the
current release.

## Building toward zero-knowledge: the hash is the decision

The long-term aim is for proving to become the heart of the system rather than a
layer on top — private queries and continuous storage proofs, not just a
tamper-evident log. That direction is a bet, not a claim: **there is no SNARK in
the code today.** But one decision has to be made before circuits are written,
because it cannot be retrofitted after heads are published.

**Inside a SNARK, the hash function dominates the cost.** Proving a Merkle
inclusion path means re-executing every hash on that path as arithmetic
constraints, and hashes differ by two orders of magnitude:

| Hash | Approx. constraints per compression | Depth-20 path (1M records) |
|------|------------------------------------|----------------------------|
| SHA-256 | ~25,000–30,000 | ~500,000+ constraints |
| Poseidon-family (ZK-native) | ~200–300 | ~5,000 constraints |

RFC 6962 mandates SHA-256, which is the correct choice for a *public
transparency log* — it is standard, widely implemented, and independently
auditable. It is also close to the worst case for a circuit. The resolution is
not to abandon one for the other but to run **two trees over the same records**:
SHA-256 for the public log and interoperability, a ZK-native hash for the tree
that circuits actually prove against.

That is why `merkle.CachedLog` takes `leaf_fn` / `node_fn` as parameters. The
tree structure, the promote-not-duplicate semantics, the audit-path logic and
the incremental append are all hash-independent; only the compression function
changes. The second tree is a constructor argument, not a rewrite.

**Measured 2026-08-05** on a 15 W laptop CPU, no GPU, CPython 3.14, over a log
of 1,000,000 records:

| Metric | Measured |
|--------|----------|
| Inclusion proofs | **263,000 / second** (20,000 proofs in 0.076 s) |
| One million proofs | **3.8 seconds** |
| Log construction | 22.4 seconds |
| Python heap for the tree | ~140 MB (`tracemalloc`) |

Reproduce it with `tests/test_merkle.py` and a million-leaf `CachedLog`.

SNARK proving is a different cost class entirely — seconds to minutes per proof
and gigabytes of memory, which is why Filecoin runs GPU fleets for PoRep/PoSt.
Any roadmap should price hash proofs and ZK proofs as separate line items;
conflating them is how ZK projects promise throughput they cannot reach.

## Install

Requires **Python 3.10+** and one dependency (`cryptography`).

```bash
pip install git+https://github.com/zcashsensei/blindkeep.git
```

Or from a clone — the option you want if you intend to run the tests:

```bash
git clone https://github.com/zcashsensei/blindkeep.git
cd blindkeep
pip install -e .
```

Either one installs a `blindkeep` command. From a clone you can equally skip
installing and use `python -m blindkeep ...` with `pip install -r
requirements.txt`; the two forms are interchangeable everywhere below.

## Quick start

```bash
# terminal A — run a node
blindkeep node --data-dir data/node --port 8741

# terminal B — store and retrieve a memory
blindkeep keygen --key data/client/master.key
blindkeep put --text "prefers concise answers" --label prefs
blindkeep list
blindkeep get --index 0
blindkeep head
```

<sub>On Windows, `python -m blindkeep` becomes `py -3 -m blindkeep`; the
`blindkeep` command itself works unchanged.</sub>

**Keep `master.key` secret, and set up recovery before you store anything you
care about.** The key is the only thing that can decrypt your records — no node
can help, by design.

## Key recovery

A correct encryption design makes key loss fatal. That is also how consumer
encryption products die, because people lose files. Recovery here is entirely
client-side: nodes are not involved, learn nothing, and cannot assist an
attacker.

```bash
# a written code — guards against disk failure
python -m blindkeep recover export
python -m blindkeep recover restore --code "LXDD-662S-..."

# a passphrase-protected file — safe to keep in cloud storage or email
python -m blindkeep recover backup --out master.key.backup
python -m blindkeep recover unbackup --file master.key.backup

# k-of-n shares — guards against losing any single thing
python -m blindkeep recover split --threshold 3 --shares 5
python -m blindkeep recover combine --share "1-..." --share "3-..." --share "5-..."
```

| Mechanism | Protects against | Cost of the weakest link |
|-----------|------------------|--------------------------|
| Recovery code | Disk failure, device loss | Anyone who reads the paper has everything |
| Passphrase backup | Losing the paper | Your passphrase (scrypt, ~128 MiB per guess) |
| `k`-of-`n` shares | Losing any one thing | Any `k` holders colluding; `k-1` learn nothing |

Shares use Shamir's Secret Sharing over GF(256): fewer than `k` are
*information-theoretically* independent of the key — not merely hard to invert,
but carrying no information about it at all.

Codes and shares are checksummed. A mistyped one is **rejected**, never silently
turned into a wrong key.

## Tests

```bash
python tests/test_merkle.py        # 13 — RFC 6962 proofs, exhaustive over sizes 0..32
python tests/test_store.py         #  5 — encryption, persistence, rewrite detection
python tests/test_metadata.py      #  8 — encrypted labels, size padding
python tests/test_adversarial.py   #  9 — real malicious nodes vs. the real client
python tests/test_replication.py   # 12 — offline, tampered and dishonest nodes
python tests/test_recovery.py      # 21 — recovery codes, backups, k-of-n shares
python tests/test_hardening.py     # 12 — resource limits, disclosure, redirects
python tests/test_discover.py      # 18 — peer discovery, hostile bootstrap
python tests/test_audit.py         # 10 — retrieval audits, offline vs dishonest
python tests/test_ollama_mem.py    # 13 — local model memory, privacy boundary
python tests/test_cloud_gate.py    # 13 — opt-in cloud path stays closed
python tests/test_cli.py           # 13 — only keygen/recover create key material
python demo.py                     # end-to-end walkthrough
```

## Security model

**Protects against**

- A node reading your memories — it never receives a key
- A node editing or dropping committed records — pin a head, verify consistency
- A node serving a blob it never committed to — inclusion proof
- A node answering with the wrong record — request binding
- A node reading your **labels** — they are encrypted with the record, not
  stored alongside it
- A node learning a record's **exact size** — records are padded to 256-byte
  buckets before encryption

**Does not protect against**

- **Access patterns.** The node sees *which* record is requested and when.
  Closing this requires private information retrieval; it is not implemented,
  and encryption alone cannot achieve it.
- **Record count and timing.** How many records exist, and when each was
  written, remain visible.
- Withheld data — availability is not integrity
- Equivocation: a node showing different histories to different clients
  (needs gossip + witnesses)
- Compromised client software on your own machine

## Project layout

```
blindkeep/
  merkle.py     RFC 6962 inclusion + consistency proofs
  crypto.py     Ed25519 node identity, AES-GCM envelopes, HKDF per-record keys
  store.py      append-only encrypted store + signed tree heads
  node.py       local HTTP memory node
  client.py     encrypt / put / get / verify / pin
  replica.py    multi-node replication with quorum reads
  recovery.py   recovery codes, passphrase backups, k-of-n shares
  discover.py   peer discovery with URL validation
  audit.py      retrieval audits: offline vs lost vs dishonest
  ollama_mem.py local-model memory loop (loopback enforced)
  cloud_gate.py  opt-in hosted-model path — NOT PRIVATE
  vault_proxy.py reversible pseudonymisation for that path — SMALLER disclosure
  _console.py   terminal output helpers
  cli.py        command-line interface
tests/          14 suites, 185 tests
```

## Replication

A single verified node can still go offline, refuse to serve, or be seized.
`ReplicatedClient` writes byte-identical ciphertext to several independent
nodes and returns a value only when enough of them **independently verify** and
**agree**.

```python
from blindkeep.replica import ReplicatedClient

client = ReplicatedClient(
    ["http://node-a:8741", "http://node-b:8741", "http://node-c:8741"],
    master_key, pin_dir="data/pins",       # quorum defaults to a majority
)

receipt = client.put(b"remember this", label="notes")
record = client.get(receipt.record_id)     # {'plaintext': ..., 'agreement': 3, ...}
```

Records are addressed by identifier rather than index, because an index belongs
to one node's log and diverges permanently after a failed write. A node failing
any cryptographic check is excluded from the vote rather than allowed to
influence it, and conflicting answers from verified nodes raise rather than
resolve silently.

### Finding nodes

```bash
cp data/peers.example.json data/peers.json     # then edit
python -m blindkeep peers                      # probe and list live nodes
```

A peer list supplies candidate addresses only. Every node is still verified
independently on use, so an entry grants no trust. URLs are validated before
contact — cloud metadata addresses are refused outright, and a bootstrap
endpoint cannot displace a locally pinned public key.

### Auditing nodes

Integrity proofs show that what a node returns is genuine. They say nothing
about whether it returns anything at all.

```bash
python -m blindkeep audit --sample 10
```

An audit fetches a random sample of records and fully verifies each, then
separates three outcomes a plain uptime check would conflate: **offline**
(unreliable), **failed** (lost data), and **security failure** (dishonest). One
security failure disqualifies a node outright — availability is a matter of
degree, honesty is not.

This is challenge–response retrieval, **not** a proof of storage. It shows a
node served data at the time of asking.

## Local model memory

The loop the project exists for: an assistant that remembers you, where memory
lives encrypted on storage you need not trust and the model runs on your machine.

```bash
python -m blindkeep chat --text "remember I prefer short answers"
python -m blindkeep chat --text "how do I like my answers?"
```

Prior memories are recalled and placed in the model's context automatically. The
endpoint **must** resolve to loopback; a non-local address requires
`--allow-remote` and is refused otherwise.

<details>
<summary>Optional: a hosted model — <b>not private</b></summary>

A gated path exists for when a frontier model is genuinely wanted. It requires
two separate acknowledgements and cannot be entered by accident:

```bash
python -m blindkeep cloud-chat --enable-cloud --i-accept-not-private \
  --model gpt-4o-mini --text "..." --redact
```

Nothing in the default paths imports it — enforced by a test. `--redact` removes
obvious secrets on a best-effort basis and is **not** a privacy control: pattern
matching catches an API key and misses "my daughter's school". Treat anything
sent this way as disclosed.

</details>

<details>
<summary>Optional: a hosted model with pseudonymised values — <b>smaller disclosure, still a disclosure</b></summary>

Values you declare are swapped for stable placeholders before the request leaves
and restored in the reply, so the provider sees the shape of the question
without the identities in it:

```bash
python -m blindkeep private-chat --enable-cloud --i-accept-not-private \
  --declare "Sarah Whitfield" --declare-as "ORG:Acme Holdings" \
  --text "Sarah Whitfield at Acme Holdings owes 4000"
# on the wire: <PERSON_0_b75298> at <ORG_0_b75298> owes 4000
```

The mapping is stored as a Blindkeep record, so the table that re-identifies
everything inherits encryption, a Merkle commitment and key recovery rather than
living in a session cache. Pass `--vault-record` to reuse it and keep
placeholders stable across sessions.

**What this does not do.** It removes identifiers, not identifiability: a
placeholder for the only paediatric cardiologist in Truro still names one
person. Undeclared entities in prose are sent verbatim — detection is patterns
plus what you declare, and `declare()` is the load-bearing part. Stable
placeholders are a persistent pseudonym the provider can link across sessions.
Each of these limits has a test that passes by demonstrating the failure.

</details>

### Which path is actually private

| Path | Provider sees | Trust required |
|------|---------------|----------------|
| `chat` — local model | nothing; no provider exists | none beyond your own machine |
| `private-chat` — pseudonymised | the question, minus declared identities | provider not to correlate what remains |
| `cloud-chat` — gated | everything you send | provider's policy and retention terms |

Storage trust is unchanged in all three: the node never holds plaintext. Only
the *model* side differs. Attested confidential inference — where the operator
is cryptographically prevented from reading rather than trusted not to — is the
route that would make a hosted model genuinely private, and is not implemented
here.

## Roadmap

1. Witnessing against equivocation — a node showing different histories to
   different clients is not yet detectable
2. Proof of *storage* rather than retrieval, so a node must hold data rather
   than merely obtain it
3. Sharded model-weight distribution (hash-addressed)
4. Optional paid capacity above a free quota — only once the free path is real
5. Specification written *from* the running code

## License

**MIT** — see [`LICENSE`](LICENSE). Copyright © 2026 zcashsensei.

Anyone may use, modify and **self-host free of charge, permanently**. The
**Blindkeep** name and the public network are operated by the author; optional
paid capacity may apply above free quotas.

## Documentation

| File | Contents |
|------|----------|
| [`GRANT_ONE_PAGER.md`](GRANT_ONE_PAGER.md) | ZCG/ZF-style one-page proposal summary |
| [`WHITEPAPER.md`](WHITEPAPER.md) | Architecture, feasibility, limits, open risks |
| [`CRYPTO_FOUNDATIONS.md`](CRYPTO_FOUNDATIONS.md) | What is cryptographically established vs tested |
| [`THESIS.md`](THESIS.md) | Category, privacy model, product doctrine |
| [`PATH_TO_MASSES.md`](PATH_TO_MASSES.md) | Free-tier economics and grant milestones |
| [`LICENSE_RIGHTS.md`](LICENSE_RIGHTS.md) | What MIT does and does not grant |
| [`SECURITY.md`](SECURITY.md) | Threat model, fixed vulnerabilities, reporting |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Design principles and contribution rules |
| [`AUTHORS.md`](AUTHORS.md) | Authorship and provenance |

## Contributing

Issues and pull requests are welcome. Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) first —
it records the non-negotiable design constraints. Two rules matter most:

1. **Never regress `tests/test_adversarial.py`.**
2. **Never add a default code path that sends user data to a third party.**

---

<p align="center">
  <sub>Created and maintained by <a href="https://github.com/zcashsensei">zcashsensei</a>.</sub>
</p>

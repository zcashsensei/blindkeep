<p align="center">
  <img src="assets/blindkeep-lockup.svg" alt="Blindkeep" width="330">
</p>

<p align="center">
  <strong>Zero-knowledge memory for local and sovereign AI.</strong><br>
  Your agent remembers you. The node holding those memories cannot read them
  and cannot rewrite them without you finding out — and you can prove things
  about what it holds without saying which record you mean.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/tests-562%20passing-brightgreen.svg" alt="562 tests passing">
  <img src="https://img.shields.io/badge/status-v0%20alpha-orange.svg" alt="v0 alpha">
  <img src="https://img.shields.io/badge/dependencies-1-lightgrey.svg" alt="1 dependency">
  <img src="https://img.shields.io/badge/zero--knowledge-sigma%20protocols%20%2B%20halo2-6E4B9E.svg" alt="Zero-knowledge: sigma protocols and a halo2 SNARK">
  <img src="https://img.shields.io/badge/SNARK-halo2%20%C2%B7%20no%20trusted%20setup-6E4B9E.svg" alt="halo2 SNARK, no trusted setup">
  <img src="https://img.shields.io/badge/frontier-content%20gate%20%2B%20account%20decoupled-6E4B9E.svg" alt="Frontier: content gate and account-decoupled gateway">
</p>

<p align="center">
  <sub><b>Status as of 2026-08-11</b> · v0 alpha · 562 tests ·
  encrypted keep · ZK membership · frontier stack ·
  <b>Heartwood</b> throttle audit (in-app install) ·
  <a href="STACK.md">STACK.md</a> · <a href="SECURITY.md">SECURITY.md</a> ·
  run <code>blindkeep status</code> ·
  <code>python tools/demo_historic_stack.py</code></sub>
</p>

---

## Try it in one command

```bash
git clone https://github.com/zcashsensei/blindkeep
cd blindkeep
python app.py
```

Opens a local app at `http://127.0.0.1:8743`. It starts your own node, creates
your own master key, and never sends either anywhere — everything is encrypted
on your machine before it reaches storage. Nothing to sign up for, no server of
ours involved, and it keeps working when we are offline.

Tabs: **Your keep** · **Remember** · **Security** (plain-English protections
for everyone) · **Heartwood** (is your AI throttling you?) · **Proof** ·
**Privacy truth** (deep threat model) · **How it works**.

A privacy strip on every page shows the posture at a glance. The first time you
save a memory you set a **passphrase** that (1) seals the key **at rest** as
`data/master.key.sealed` and (2) downloads `blindkeep-master-key.zip`. The raw
key lives in process memory only while unlocked — never as hex in the page, never
as a plaintext download. Agents that open the project folder or Downloads still
need your passphrase.

**Storage privacy ≠ frontier-model privacy.** The keep can stay unreadable to a
node; talking to a hosted model is a different threat model (API account, prompt
content, timing, IP). The app states that plainly and does not phone home.

### Historic stack: content-gated + account-decoupled frontier chat

Open-source path where the **client never holds the frontier API key**.
Entitlement is a **one-time blind token**. Private facts are **LeakGate-blocked**
before leave. Optional OHTTP relay for IP split (only if relay ≠ gateway operator).

```bash
# 1) Gateway (holds the API key; issues are separate)
python -m blindkeep frontier-gateway \
  --api-base https://api.x.ai --api-key "$BLINDKEEP_CLOUD_KEY" \
  --issuer-key data/gateway_issuer.pem --port 8751

# 2) Issue a one-time unlinkable token (same issuer key)
python -m blindkeep token issue --issuer-key data/gateway_issuer.pem --out token.json

# 3) Client: Ollama abstracts + gates; gateway redeems token; no client API key
python -m blindkeep frontier-chat \
  --enable-frontier --accept-residual-risks \
  --gateway-url http://127.0.0.1:8751 --token token.json --model <model> \
  --text "Sarah in Truro owes me £4000 — what can I do?"
```

**Defensible claim:** an open stack that combines encrypted keep + ZK membership
+ local abstraction + mechanical leak gate + Chaum blind entitlement + optional
OHTTP + a gateway that holds the provider credential so the client is not a
named API customer. Offline proof: `python tools/demo_historic_stack.py`.

**Not claimed:** zero-metadata anonymity; IP privacy when one party runs both
relay and gateway; a public multi-operator network. Receipts list residual risks.

**Direct path (content only, account still yours):** omit gateway; pass
`--api-base` and `--api-key` as before.

> **Remember the passphrase** — there is no reset. That is the point: an
> operator who could recover your data could also read it.

The local app binds to loopback only, never phones home, and never ships the
raw master key in page state. Prefer a terminal? The `blindkeep` CLI covers the
same surfaces and the full frontier stack — see [Install](#install).

**Docs for reviewers:** [STACK.md](STACK.md) · [SECURITY.md](SECURITY.md) ·
[CRYPTO_FOUNDATIONS.md](CRYPTO_FOUNDATIONS.md) · [WHITEPAPER.md](WHITEPAPER.md) ·
[CONTRIBUTING.md](CONTRIBUTING.md)

---

## What it is

Blindkeep is a zero-knowledge memory layer for AI. It does two things, and the
second is the one that makes it more than encrypted storage:

**1. The operator is blind.** Clients encrypt locally; storage nodes hold
**ciphertext they have no key for**, committed to an **append-only Merkle log**
they cannot alter undetected. Not a policy — a cipher and a transparency log.

**2. The holder can speak without disclosing.** A signed log proves the *node*
honest, but says nothing for *you* — `get(index)` names the index, and an
inclusion proof reveals the leaf and its whole sibling path. So Blindkeep also
proves statements **about** records without identifying them:

```bash
blindkeep prove-in-keep --index 1 --out p.json      # index is not in the proof
blindkeep verify-in-keep --proof p.json
# VERIFIED: the prover holds one of the 4 records in this keep.
#           Which one is not revealed.
```

Pedersen commitments and sigma protocols, bound to a signed tree head, in **one
dependency**. Range, membership, equality and opening are proven the same way.

Membership is also proven **succinctly**: `circuits/` is a halo2 SNARK (no trusted
setup) that proves the same statement over a Poseidon tree in a **constant 3,040
bytes** — measured at 8 leaves and at 128. It needs a Rust toolchain; the sigma
proofs above need nothing but Python, which is why both exist. Those sigma proofs
are a fixed set of algebraic predicates with kilobyte, O(n) proofs, priced
honestly further down. Neither layer is zkML: this proves membership, never
inference.

There is no token and no chain. Hosted
models are reachable through paths requiring two acknowledgements that say
plainly what they disclose, and **no default path imports them** — a constraint
a test verifies.

## The zero-knowledge layer

Every claim a holder makes about their own records is proven in zero knowledge:

| Claim | Mechanism | Reveals |
|-------|-----------|---------|
| **"I hold a record in this keep"** | **ZK membership, bound to a signed head** | **not which record** |
| "this committed value is within a bound" | ZK range proof | nothing but the bound |
| "these two commitments match" | ZK equality proof | nothing |
| "the value is one of these" | ZK set membership | not which one |
| "I know what this commits to" | ZK proof of opening | nothing |

Proofs are used **where they are the only thing that works**, and cheaper
primitives carry the rest — a design choice, not a shortfall. Encryption already
makes a record unreadable and a Merkle log already makes it unalterable; wrapping
either in a proof would cost orders of magnitude and prove nothing extra:

| Property | Mechanism | Why not a proof |
|----------|-----------|-----------------|
| Node cannot read a record | AES-256-GCM | A cipher already does this, in microseconds |
| Node cannot alter a record | Merkle leaf + signed head | Tamper-evidence needs a hash, not a circuit |
| History cannot be rewritten | Consistency proof vs. a pin | Same |

**The half a cipher cannot reach** is what the proofs are for. The log
proves the *node* honest. It does nothing for the *holder*, who cannot say
anything about a record without naming it — `get(index)` names the index, and an
inclusion proof reveals the leaf and its whole sibling path. So:

```bash
# prove you hold a record in this keep, without revealing which
blindkeep prove-in-keep --index 1 --out p.json
blindkeep verify-in-keep --proof p.json
# VERIFIED: the prover holds one of the 4 records in this keep.
#           Which one is not revealed.
```

The proof carries no index, and every record produces a proof of identical
shape. It is bound to a **signed tree head**, so a proof about a keep of 4
records does not verify against the same keep at 5, and never against a
different keep — the proof system and the transparency log are one mechanism,
not two.

Pedersen commitments and sigma protocols (Schnorr, OR-composition) made
non-interactive by Fiat-Shamir, over RFC 3526 MODP Group 14 — built from `int`
arithmetic and `hashlib`, so **the dependency count is still one.**

**The invariant that makes them proofs rather than theatre:** the Fiat-Shamir
challenge binds the entire statement — group, generators, commitments, tree head
— length-prefixed so no two statements serialise alike. This project's oldest
lesson, in its fourth register: *a valid proof is not an answer to your
question.*

**Honest costs.** The sigma proofs are a fixed set of algebraic predicates rather
than arbitrary computation, and their cost is O(n). The halo2 circuit in
`circuits/` pays a different price — a Rust toolchain and seconds of proving —
for a proof that stops growing. Neither is zkML. Keep membership is an OR-proof across
every leaf, so proofs are **O(n)** — about 1 KB per record, fine at 40 records
and impractical at 40,000, and `keep_leaves` refuses rather than hanging. Making
it O(log n) means proving a Merkle path inside a circuit. **That path now works
end to end**, and the next section is the measurement. The code is
standard, carefully written, adversarially tested, and **unaudited**, which is
not the same as reviewed by a cryptographer.

Still not claimed: *sub-linear* private queries (trivial PIR works, and reads the
whole keep to do it), proof of storage, verifiable inference.

## What you get today

Verified by cloning this repository fresh and running it with nothing else
present, so the list below is what actually happens rather than what is
intended.

**Works immediately** — one dependency, no account, no server of ours involved:

- run a node, store a memory, read it back, see a signed Merkle root
- confirm the node cannot read what it holds. Search its storage files for what
  you typed: neither the **contents** nor the **labels** are there
- back up your key as a written code, a passphrase file, or k-of-n shares
- run the adversarial suite, which stands up genuinely malicious nodes and
  asserts the client refuses them
- **prove you hold a record without revealing which one**, bound to the signed
  head so the proof transfers to no other keep
- `blindkeep status` — every capability detected from source, including what is
  *not* done

**Needs one more thing:**

| To do this | You need |
|------------|----------|
| `chat` — an AI that remembers you, nothing leaving the machine | Ollama installed |
| `private-chat` — a hosted model with identities substituted | an API key, and `--api-base` |
| `gate-chat --tier attested` | an enclave speaking the attestation protocol — **nobody runs one** |
| replication, `peers`, `audit` | more than one node, meaning a second machine |

**Expect these limits, stated plainly.** There is no public node network, so
`peers` finds nothing and you are storing on hardware you own. That makes the
honest description of Blindkeep today *encrypted, tamper-evident memory on your
own machine* — a real thing, and a smaller one than "distributed network".

And the headline property deserves the same honesty: the design treats a node as
hostile, the cryptography is standard, and the adversarial tests are real — but
**every node that has ever run Blindkeep was operated by its author.** That the
guarantee holds against a stranger's node is argued, not yet observed. Changing
that is the next milestone, and it cannot be done alone.

## The storage guarantee

The proofs above are what *you* can assert. This is the half the *node* is held
to, and it needs no zero-knowledge at all: a Blindkeep node is untrusted for both
confidentiality and integrity, and every value the client returns has passed five
independent checks:

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

## Succinct membership, end to end

The O(n) proof above is the honest version and it does not scale. The succinct
one is built, and the whole chain has been run:

```
  a record in the keep
    → Poseidon tree over the same committed leaves   blindkeep/zk_tree.py
    → witness (leaf + path private, root public)     blindkeep zk-witness
    → halo2 circuit                                  circuits/src/merkle.rs
    → 3,040-byte SNARK proof, verified               blindkeep-prove
```

| Records | Sigma OR-proof | halo2 Merkle proof |
|---------|----------------|--------------------|
| 8 | ~8 KB | **3,040 bytes** |
| 128 | ~128 KB | **3,040 bytes** |
| 40,000 | ~40 MB | **3,040 bytes** |

Flat, because a Merkle path is `log2(n)` hashes however large the log grows.

**The tree needed no node change and adds nothing to trust.** The Poseidon root
is a deterministic function of the leaf set the node already publishes and
already signs over via the SHA-256 head. A verifier fetches the leaves, checks
the signed head exactly as before, rebuilds the Poseidon tree themselves, and
verifies the proof against the root *they* computed:

- the **signed SHA-256 head** anchors *which* leaves exist
- the **Poseidon tree** makes a statement about them provable in a circuit

Either alone is worth nothing. A Poseidon root by itself proves membership in a
tree the prover could have built, which is why `zk-witness` carries the signed
head alongside the path and `verify_anchor` recomputes the root before any proof
is looked at.

**The two implementations are checked against each other, not trusted.** A
Poseidon that is subtly wrong still hashes, still builds a tree, and produces
proofs that verify against nothing — the prover simply fails, with no sign that
the implementations disagree rather than the witness being bad. So the
parameters are *generated* from `halo2_gadgets` rather than transcribed, and
`tests/test_poseidon.py` asserts this implementation reproduces the Rust one:
**7 known-answer hash vectors and 7 tree roots, including odd sizes where a
padding rule is most likely to drift.** A test on the Rust side then takes a
witness produced by the CLI above and proves it for real.

One step, and the private half never touches disk:

```bash
blindkeep zk-prove --index 5 --out proof.json
# [proving membership · depth 3 · root 1d5e3e4a5fb29328…]
# [proof written to proof.json (3040 bytes of proof)]
# [witness discarded — the proof reveals neither the record nor its position]

blindkeep-prove verify --proof proof.json
# VERIFIED: the prover holds a record under root 1d5e3e4a5fb29328…
#           depth 3 — which record is not revealed.
```

The prover is one binary, built from `circuits/` in this repository:

```bash
cd circuits && cargo build --release --bin blindkeep-prove
```

`zk-prove` finds it on `PATH`, via `BLINDKEEP_PROVER`, or with `--prover`. Without
it you still get `blindkeep zk-witness`, which exports the witness for proving
elsewhere — and the refusal says exactly that rather than failing obscurely.

## Making the proofs succinct: the hash is the decision

The proofs above are sigma protocols, and keep membership through them pays O(n).
That is not the whole story any more: **there is a SNARK in this repository, and
it proves and verifies.** `circuits/` is a halo2 crate holding a Poseidon Merkle
membership circuit — a holder proves a leaf sits under a published root without
revealing the leaf or the path.

Measured, not asserted (`cargo test --release -p blindkeep-circuits`, 14 tests):

| | |
|---|---|
| Proving system | halo2 (PLONKish, **no trusted setup**), Pallas/Vesta |
| In-circuit hash | Poseidon `P128Pow5T3`, checked against the Python tree |
| Proof size | **3,040 bytes at 8 leaves, 3,040 bytes at 128 leaves** — constant |
| Generation | real `keygen_vk → keygen_pk → create_proof → verify_proof`, not `MockProver` |
| Bound to its root | a proof against another root fails |

The two halves are deliberately separate. The sigma protocols run anywhere Python
runs, with no toolchain; the SNARK needs Rust and buys succinctness. The keep
verifies without the circuit — it is an addition, not a dependency, which is why
`zk-prove` refuses clearly when the prover binary is absent rather than failing
obscurely.

Still true, and not softened by any of the above: this proves **membership**, not
inference. Nothing here proves a model did anything — there is no zkML.

One decision has to be made before any circuit is written, because it cannot be
retrofitted once heads are published.

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

<sub>Not on PyPI yet, which is why the install line points at the repository.
`pip install blindkeep` does not work.</sub>

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

To see what the repository actually contains — counted from the source on every
run, including what is **not** done:

```bash
blindkeep status
```

Every number it prints is computed, and every capability is detected rather than
asserted: whether the SEV-SNP verifier is enabled, for instance, is read from
the live registry, so it flips on its own the day someone validates it. **If a
document in this repo disagrees with `blindkeep status`, the document is
wrong.**

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
  attest.py     remote attestation: 5 checks, refuse on any failure
  memory_gate.py one memory layer, any model, release by PROVEN tier
  zk.py         commitments + sigma proofs: prove a property, reveal nothing
  zk_keep.py    prove you hold a record here, without saying which
  poseidon.py   Poseidon over Pallas — the hash a circuit can afford
  zk_tree.py    the circuit-compatible tree, and witness export
circuits/       halo2 membership circuit + the blindkeep-prove binary (Rust)
  sev_snp.py    AMD SEV-SNP report verification — OFF by default, unvalidated
  status.py     what the repo contains, counted not claimed
  cloud_gate.py  opt-in hosted-model path — NOT PRIVATE
  vault_proxy.py reversible pseudonymisation for that path — SMALLER disclosure
  delegate.py   abstract locally, verify, send a question about nobody
  frontier_private.py  content gate + receipts
  frontier_gateway.py  account-decoupled gateway (holds API key)
  frontier_relay.py    OHTTP relay surface
  anon_token.py blind-signed entitlement: prove you may ask, not who you are
  _console.py   terminal output helpers
  cli.py        command-line interface
tests/          34 suites, 562 tests
STACK.md        historic frontier stack architecture
tools/demo_historic_stack.py   offline proof (no API key)
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

**There is no public node network, so this finds nothing unless you point it at
nodes you run.** The discovery, replication and audit machinery is implemented
and tested against nodes on one machine; what has not happened is anyone else
running one. If you stand up a node and are willing to be a stranger to the
author, that is the single most useful contribution this project can receive —
see [Contributing](#contributing).

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
  --api-base https://api.x.ai --model grok-4.3 --text "..." --redact
```

`--api-base` and `--model` are **required, with no default**, because Blindkeep
does not choose a provider for you, and on a path that discloses, that is the one
choice you should make consciously.

**Any model, closed or open weights.** The wire format is inferred from the
endpoint and can be overridden with `--dialect`:

```bash
--api-base https://api.anthropic.com  --model <claude model>   # dialect: anthropic
--api-base https://api.x.ai           --model <grok model>     # dialect: openai
--api-base https://api.openai.com     --model <gpt model>      # dialect: openai
--api-base http://127.0.0.1:8000      --model <self-hosted>    # vLLM, llama.cpp, TGI…
--api-base http://127.0.0.1:11434     --model <local>          # dialect: ollama
```

This is not a convenience feature. **Privacy that only holds if you pick one
particular company is not a property — it is a dependency on that company.** A
dialect decides bytes on the wire and nothing else: it never sees a record, a
sensitivity class, or a tier, so supporting a new provider cannot weaken a
guarantee. The tiers below read identically on every one of them.

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
  --api-base https://api.x.ai --model grok-4.3 \
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
| **`--tier sealed`** | **a generic question, and it cannot read even that** | **both must fail at once** |
| `--tier attested` | nothing; hardware prevents it | silicon vendor + attestation chain |
| `--tier delegated` | a generic question containing no fact about you | that the abstraction was complete — mechanically checked |
| `private-chat` — pseudonymised | the question, minus declared identities | provider not to correlate what remains |
| `cloud-chat` — gated | everything you send | provider's policy and retention terms |

### `sealed` — both, because they fail differently

The strongest tier that still uses somebody else's compute. It requires **both**
mechanisms to hold, and they are independent:

| Mechanism | Fails when | Covered by |
|-----------|-----------|------------|
| Abstraction | it carries something it should not | the host cannot read it |
| Enclave | hardware or attestation is broken | the question is about nobody |

An attacker needs both at once. A leaked identifier arrives at a host that
cannot read it; a broken enclave receives a question about nobody. That is not a
theoretical pairing — the `ecc::chip::mul` soundness bug sat inside the most
scrutinised circuit in the ecosystem for **four years**, and an enclave is a
trust assumption like any other. The argument is Bowe's argument for removing
trusted setups, applied one layer up: prefer designs where a single broken
assumption is not fatal.

**It degrades to the strongest tier that still holds, and says so.** Lose the
enclave and you are at `delegated`, not `open` — a host's problem should not
throw away a working abstraction. Lose the abstraction and you are at
`attested`. Lose both and you are at `open`, with only `public` memories moving.
Every demotion is named, because silently keeping the `sealed` label would be
the actual failure.

One detail worth stating: at the delegating tiers the **released memories are
abstracted alongside the message**, not appended after it. Sending a generic
question with your memories stapled underneath would defeat the whole
construction, and is the obvious way to get this wrong — so there is a test that
fails if anyone does.

**Delegated is the one that needs no special hardware.** A local model rewrites
your question into one any stranger could have asked; a leak gate checks it
mechanically and **refuses to send** if anything survived; the frontier model
answers in the abstract; the local model re-applies the answer to your real
situation, which never left:

```
  private   "Sarah Whitfield, my landlord in Truro who breeds Basenjis,
             owes me £4,000 since March"
  sent      "What are the options for recovering an unpaid debt from a
             private individual?"
  shown     that guidance, re-applied to Sarah, Truro and £4,000 — locally
```

Pseudonymisation is *subtractive*: it starts from your text and removes what it
recognises, so anything unrecognised ships. Delegation is *generative*: it
starts from nothing and writes a new question, so anything not deliberately
carried is absent. Substitution leaks what it missed; abstraction loses what it
failed to carry — and losing utility is recoverable where leaking is not.

The gate, not the abstraction, is what makes this safe. A local model asked to
be generic will sometimes not be, so nothing is sent on trust: rare words, proper
nouns, amounts and any shared 3-gram are compared against every private source,
and a hit **raises rather than sends**. A leaky attempt is retried with the
reason, and after three failures it gives up — *"ask the local model directly"*
is a real answer.

**Who is asking — `anon_token.py`.** A generic question sent from a named
subscriber still says *this person asked about debt recovery at 14:20*. Zcash
solved the equivalent problem for payments by preserving **unlinkability of
authorisation**, and [RFC 9578](https://datatracker.ietf.org/doc/rfc9578/)
standardises the web-shaped version. Blindkeep uses the construction underneath
it — Chaum blind signatures:

```
  client   picks a token, blinds it, sends the blinded value
  issuer   signs what it cannot read
  client   removes the blinding — a valid signature on a token never seen
  redeem   the issuer verifies it signed *something*, not *this*
```

The issuer counts its subscribers and refuses strangers; it cannot say which
subscriber asked which question. Full-domain hashing is what keeps it sound —
RSA's multiplicative structure is exactly what makes blinding work *and* what
makes naive blind signing forgeable, so a test multiplies two real signatures
and asserts the product verifies as nothing.

**How identifying the question itself is — measured, not solved.**
`specificity()` counts uncommon terms and `LeakGate(max_specificity=…)` refuses
an abstraction that is too detailed. It is off by default and it is a **proxy**:
nothing syntactic can tell that *"options after a diagnosis of a rare autoimmune
condition in a man under thirty"* — every word ordinary — names almost nobody. A
measurement honestly labelled a proxy beats a check implying a guarantee it
cannot give.

**What remains, stated plainly:** that a request happened at all. Timing and
volume are network properties, and no amount of rewriting hides them. Only
`local` avoids that, by not making a request.

Storage trust is unchanged in all four: the node never holds plaintext. Only the
*model* side differs.

## One memory layer, any AI

The model is swappable. The guarantee is not. Memory lives encrypted in the
keep, every backend sits on a **trust tier it has to prove**, and a policy
decides which memories may cross to which tier.

```bash
# strongest tier that still uses somebody else's compute
blindkeep token issue --out token.json
blindkeep gate-chat --tier sealed --text "what do you know about me?" \
  --local-model llama3.2 --anon-token token.json \
  --attest-url https://host.example/attest \
  --api-base https://host.example --model <model> \
  --measurement <approved-code-hash> --root <vendor-key>

# no special hardware needed — abstraction only, any provider
blindkeep gate-chat --tier delegated --text "..." --local-model llama3.2 \
  --api-base https://api.x.ai --model grok-4.3 --anon-token token.json

blindkeep gate-chat --tier attested --text "what do you know about me?" \
  --attest-url https://host.example/attest \
  --api-base https://host.example --model <model> \
  --measurement <approved-code-hash> --root <vendor-key>
```

`--tier local` needs no endpoint. Every tier that sends somewhere requires
`--api-base` explicitly — there is no default provider, by design.

| Sensitivity | Minimum tier | Reaches an open hosted model? |
|-------------|--------------|-------------------------------|
| `public` | `open` | yes |
| `personal` | `pseudonymous` | only with identities substituted |
| `sensitive` | `attested` | only inside a verified enclave |
| `secret` | `local` | never |

**A claimed tier is worth nothing.** A backend that says `attested` and fails
verification is demoted to `open` and the demotion is named in the output — so
memories its claim would have unlocked stay home:

```
[tier: attested: ... (5 checks passed)]
[memory: attested: released 3, withheld 1 (secret)]     # honest host

error: report_data does not bind this client's nonce     # replaying host
                                                         # -> nothing was sent
```

**The classification travels inside the ciphertext.** A record's class lives in
its encrypted label, authenticated as AAD, so the node can neither read it nor
relabel `secret` as `public` to coax a client into releasing it. Editing the
plaintext index on disk does not work either — the authenticated label is the
authority, and a test asserts a forged index cannot promote a record.

### Attestation

`blindkeep attest` challenges a host to prove it cannot read what it computes.
Five checks, mirroring the five the storage client already runs, in the
published SEV-SNP verification order:

| # | Check | Defeats |
|---|-------|---------|
| 1 | Format has a registered verifier | An unknown envelope waved through |
| 2 | Signature chains to a pinned root | A report signed by anyone at all |
| 3 | `report_data` binds **our** nonce | A genuine report replayed from another session |
| 4 | Measurement is on the allowlist | Real hardware, software you never approved |
| 5 | Debug disabled, not expired | An enclave opened for inspection |

Check 3 is the one that is easy to omit and fatal to. A correctly signed,
unexpired report proves something about *some* machine; without binding it to a
nonce this client just generated, a host can replay a report captured from a
genuinely confidential machine and process your request somewhere else.

**What is not implemented, stated plainly:** `tdx` and `nvidia-gpu` are
registered as *unimplemented*, which means requesting one **refuses** — it does
not mean the check is skipped. An unrecognised format must refuse, never pass
silently, because callers read the absence of an error as success.

### SEV-SNP: implemented, and off by default

`sev_snp.py` implements the AMD SEV-SNP report for real — the 1184-byte layout
from the Firmware ABI spec, ECDSA P-384 over SHA-384, AMD's little-endian
signature encoding, and the ARK → ASK → VCEK chain. 19 tests.

**It has never seen a report from real hardware, so it is not in the default
registry and `sev-snp` still refuses on the default path.** Enabling it is a
deliberate act:

```python
from blindkeep.attest import default_registry          # sev-snp REFUSES
from blindkeep.sev_snp import registry_with_sev_snp    # deliberate opt-in

registry = registry_with_sev_snp(ark_pem, ask_pem, vcek_pem)
```

The reasoning is the same one the rest of the project runs on. An unvalidated
parser fails in one of two ways: it always errors, which is merely useless, or
it reads the wrong 48 bytes as the measurement and **passes** — which is the
worst thing this codebase could ship, because the entire value of attestation is
that passing means something.

Validating it is not a coding task. It needs one report captured from a real
SEV-SNP guest (Azure DCasv5/DCadsv5, AWS SEV-SNP instances or GCP N2D
confidential VMs), its VCEK from AMD's KDS, and that report added to
`tests/test_sev_snp.py` as a known-answer vector — confirming specifically that
`MEASUREMENT` begins at `0x090`, that the signature covers exactly the first
`0x2A0` bytes, and that `r`/`s` really are 72-byte little-endian fields. Still
out of scope after that: VCEK fetch from AMD's KDS, revocation, and TCB policy
beyond an equality check.

## Roadmap

0. **Nodes run by people who are not the author.** Listed first and numbered
   zero because everything below is code one person can write alone, and all of
   it is already written. What has not been shown is that the untrusted-node
   design survives contact with an actual stranger's node — and that is the only
   thing separating this from a well-tested single-user tool.
1. Witnessing against equivocation — a node showing different histories to
   different clients is not yet detectable
2. Proof of *storage* rather than retrieval, so a node must hold data rather
   than merely obtain it
3. Prebuilt `blindkeep-prove` binaries per platform, so proving needs no Rust
   toolchain at all — the source builds today, the release artefacts do not exist
4. Validate the SEV-SNP verifier against real hardware and enable it
5. Sharded model-weight distribution (hash-addressed)
6. Optional paid capacity above a free quota — only once the free path is real
7. Specification written *from* the running code

## License

**MIT** — see [`LICENSE`](LICENSE). Copyright © 2026 zcashsensei.

Anyone may use, modify and **self-host free of charge, permanently**. The
**Blindkeep** name is the author's, as would be any public network operated
under it; optional paid capacity may apply above free quotas. No such network
runs today.

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

**The most valuable contribution is not code.** Run a node on hardware the
author does not control and point a client at it. That single act tests the
assumption the whole design rests on and cannot be performed by the author —
open an issue if you do, including anything that broke.

---

<p align="center">
  <sub>Created and maintained by <a href="https://github.com/zcashsensei">zcashsensei</a>.</sub>
</p>

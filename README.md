<h1 align="center">Blindkeep</h1>

<p align="center">
  <strong>Verifiable, encrypted memory for local and sovereign AI.</strong><br>
  Your agent remembers you. The node holding those memories cannot read them,
  and cannot rewrite them without you finding out.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/tests-279%20passing-brightgreen.svg" alt="279 tests passing">
  <img src="https://img.shields.io/badge/status-v0%20alpha-orange.svg" alt="v0 alpha">
  <img src="https://img.shields.io/badge/dependencies-1-lightgrey.svg" alt="1 dependency">
</p>

<p align="center">
  <sub><b>Status as of 2026-08-07</b> · v0 alpha · 279 tests passing ·
  replication, peer discovery, retrieval audits, key recovery, local-model
  memory, pseudonymisation and an attestation framework implemented · <b>no
  proving system here by design — see zk-encrypted-intelligence</b> ·
  <b>runs on one machine today — no public node
  network exists, and no node has ever been run by anyone but the author</b> ·
  run <code>blindkeep status</code> for a count computed from the source</sub>
</p>

---

## What it is

Blindkeep is privacy-preserving infrastructure for AI memory. Clients encrypt
everything locally; storage nodes hold **ciphertext they have no key for**,
committed to an **append-only Merkle log** they cannot alter undetected.

v0 ships the memory layer. There is no token, no chain and no SNARK. Hosted
models *are* reachable, through paths that require two separate
acknowledgements and say plainly what they disclose — but **no default path
imports them**, and that is the constraint a test actually verifies.

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

## Where zero-knowledge belongs, and where it does not

Integrity and confidentiality of stored memory do not require ZK at all. Using
proofs for them would be expensive decoration:

| Goal | Tempting default | What Blindkeep uses |
|------|------------------|---------------------|
| Record untampered | ZK proof | Content hash / Merkle leaf |
| Correct retrieval | ZK proof | Inclusion proof vs. signed root |
| Node cannot read data | ZK proof | Client-side AES-256-GCM |
| Append-only history | Trust | Consistency proof + pinned head |

**There is no zero-knowledge proving in this repository, and that is deliberate.**
Every property Blindkeep claims — the node cannot read a record, cannot alter
one, cannot rewrite history — is achieved with a cipher and a transparency log,
which are cheaper, auditable, and already standard.

Where ZK genuinely earns its cost is a different question: proving a property of
data *without disclosing the data*. That work lives in a separate project,
[zk-encrypted-intelligence](https://github.com/zcashsensei/zk-encrypted-intelligence)
— halo2 circuits and pure-Python sigma protocols — so this repository keeps its
single dependency and its narrow claim.

Still not claimed here: private queries (PIR), proof of storage, and verifiable
inference.

## Building toward zero-knowledge: the hash is the decision

The long-term aim is for proving to become the heart of the system rather than a
layer on top — private queries and continuous storage proofs, not just a
tamper-evident log. That direction is a bet, not a claim: **there is no proof
system in this repository at all**, and the circuits it would eventually use are
being built and tested separately, in
[zk-encrypted-intelligence](https://github.com/zcashsensei/zk-encrypted-intelligence).

But one decision has to be made *here*, before any circuit is written, because it
cannot be retrofitted once heads are published.

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
  sev_snp.py    AMD SEV-SNP report verification — OFF by default, unvalidated
  status.py     what the repo contains, counted not claimed
  cloud_gate.py  opt-in hosted-model path — NOT PRIVATE
  vault_proxy.py reversible pseudonymisation for that path — SMALLER disclosure
  _console.py   terminal output helpers
  cli.py        command-line interface
tests/          18 suites, 279 tests
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

`--api-base` and `--model` are **required, with no default**. Any endpoint
speaking the `/v1/chat/completions` format works — xAI, a self-hosted vLLM, or
anything else — because Blindkeep does not choose a provider for you, and on a
path that discloses, that is the one choice you should make consciously.

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
| `gate-chat --tier attested` | nothing; hardware prevents it | silicon vendor + attestation chain |
| `private-chat` — pseudonymised | the question, minus declared identities | provider not to correlate what remains |
| `cloud-chat` — gated | everything you send | provider's policy and retention terms |

Storage trust is unchanged in all four: the node never holds plaintext. Only the
*model* side differs.

## One memory layer, any AI

The model is swappable. The guarantee is not. Memory lives encrypted in the
keep, every backend sits on a **trust tier it has to prove**, and a policy
decides which memories may cross to which tier.

```bash
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
3. Validate the SEV-SNP verifier against real hardware and enable it
4. Sharded model-weight distribution (hash-addressed)
5. Optional paid capacity above a free quota — only once the free path is real
6. Specification written *from* the running code

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

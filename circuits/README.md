# blindkeep-circuits — succinct membership proofs over a keep

A halo2 circuit proving **"I hold a record committed in this keep"** without
revealing which record. The leaf and its Merkle path are private inputs; only
the Poseidon root is public, and the witness anchors that root to the keep's
**signed head**, so the statement is about a specific keep at a specific size —
not about a set the prover invented.

Built on [halo2](https://zcash.github.io/halo2/) — Zcash's proving system —
for two properties, not fashion: **no trusted setup** (a project whose argument
is "verify, don't trust" cannot rest on a ceremony), and **recursion-friendly
curves** (Pallas/Vesta), so proofs about a growing log stay cheap to check.

## Run it

```bash
# build + 14 circuit tests (positive and negative)
cargo test --release

# end-to-end against a real keep:
blindkeep zk-witness --index N --out w.json     # Python CLI exports the witness
./target/release/blindkeep-prove prove  --witness w.json --out proof.json
./target/release/blindkeep-prove verify --proof proof.json
```

## Measured (2026-08-14, consumer laptop, release build)

| Quantity | Value |
|---|---|
| Prove | ~1.4–2.0 s |
| Verify | ~1.0 s |
| Proof size, 4-record keep (depth 2) | **3,040 bytes** |
| Proof size, 32-record keep (depth 5) | **3,040 bytes** — constant, the point of a SNARK |
| Tampered proof (one flipped nibble) | refused: `the proof does not hold for this root`, exit 1 |
| Circuit tests | 14/14, including non-member and wrong-root refusals |

Numbers are from a real prover run, not `MockProver` — `MockProver` checks
constraints, it does not produce a proof, and the two must never be conflated.

## Dependency note a reviewer should check first

`halo2_gadgets` is pinned to **0.5** deliberately. The 0.3.x line contains the
2026-05 `ecc::chip::mul` soundness bug (unconstrained per-iteration base — a
malicious prover could substitute an arbitrary point) and is yanked. Any fork
of this crate that downgrades the pin reintroduces a proof-forgery vector.

## What this does NOT do

- **Not PIR.** It hides *which record a proof concerns*; it does not hide
  which record a client fetches from a node. Different problem
  (`blindkeep read-private` pays the whole-keep cost for that today).
- **Not zkML.** Nothing here proves a model computed anything.
- **The verifier checks the root, not the head signature.** Anchoring the
  root to a live keep is `blindkeep verify-in-keep`'s job; this binary states
  that plainly in its output rather than implying more than it checked.

MIT, same as the repository. The circuit reuses `halo2_gadgets` Poseidon;
constants in `poseidon_params.json` are **generated, never transcribed**.

//! merkle.rs — PROVE A RECORD IS IN THE LOG, WITHOUT SAYING WHICH RECORD.
//!
//! This is the circuit the Blindkeep keep needs, and the reason it is worth building: membership
//! there is currently an OR-proof across every leaf, so a proof costs about a kilobyte per record.
//! Fine at forty records. Useless at forty thousand.
//!
//! A Merkle path is `log2(n)` hashes regardless of how large the log grows, so proving one *inside*
//! a circuit turns O(n) into O(log n) — 20 hashes for a million records. That is the whole argument
//! for a SNARK here, and it is the only place in either project where succinctness changes what is
//! possible rather than merely what is cheap.
//!
//! ## What it proves
//!
//! ```text
//!     "I know a leaf, and a path from it to THIS public root."
//! ```
//!
//! The root is a public input. The leaf, the sibling hashes and the direction of each step are all
//! private, so a verifier learns that the prover holds *something* committed under that root and
//! nothing about which position it occupies.
//!
//! ## The two things that make it sound
//!
//! **1. Poseidon, not SHA-256.** A SHA-256 Merkle path is roughly 826,000 R1CS constraints; the
//! same path with Poseidon is a few thousand. That is not an optimisation, it is the difference
//! between a proof you can generate and one you cannot. It is also why `merkle.CachedLog` in
//! Blindkeep takes `leaf_fn`/`node_fn` — the ZK tree is a second tree over the same records, and
//! that decision had to be made before any head was published.
//!
//! **2. The swap must be constrained, not chosen.** At each level the prover supplies a direction
//! bit saying whether the current node is the left or right child. If that bit is unconstrained the
//! prover picks whichever ordering makes an arbitrary leaf hash to the root, and the circuit proves
//! nothing. So the bit is forced boolean and the swap is an arithmetic consequence of it:
//!
//! ```text
//!     left  = cur + bit·(sib − cur)      bit=0 → cur   bit=1 → sib
//!     right = sib + bit·(cur − sib)      bit=0 → sib   bit=1 → cur
//! ```
//!
//! Booleanity first, then meaning — the same habit `rails.rs` applies to `is_maker`.

use halo2_gadgets::poseidon::{
    primitives::{ConstantLength, P128Pow5T3},
    Hash as PoseidonHash, Pow5Chip, Pow5Config,
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Constraints, Error, Expression, Instance,
            Selector},
    poly::Rotation,
};
use pasta_curves::Fp;

#[derive(Clone, Debug)]
pub struct MerkleConfig {
    poseidon: Pow5Config<Fp, 3, 2>,
    /// cur | sibling | bit | left | right
    advice: [Column<Advice>; 5],
    instance: Column<Instance>,
    s_swap: Selector,
}

/// One level of the path: the sibling to combine with, and which side we are on.
#[derive(Clone, Copy, Debug, Default)]
pub struct Step {
    pub sibling: Value<Fp>,
    /// 0 = current node is the LEFT child, 1 = the right child. Constrained boolean in-circuit.
    pub bit: Value<Fp>,
}

#[derive(Default, Clone)]
pub struct MerkleCircuit {
    /// PRIVATE — the leaf being proven.
    pub leaf: Value<Fp>,
    /// PRIVATE — one step per level, leaf upward. Its LENGTH is public: it is the tree depth, and
    /// a verifier who did not fix it would accept a proof against a shorter tree.
    pub path: Vec<Step>,
}

impl Circuit<Fp> for MerkleCircuit {
    type Config = MerkleConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { leaf: Value::unknown(), path: vec![Step::default(); self.path.len()] }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let advice = [meta.advice_column(), meta.advice_column(), meta.advice_column(),
                      meta.advice_column(), meta.advice_column()];
        let instance = meta.instance_column();
        for c in &advice { meta.enable_equality(*c); }
        meta.enable_equality(instance);

        let s_swap = meta.selector();

        // The gate that stops the prover choosing its own tree shape.
        meta.create_gate("swap is boolean and correct", |meta| {
            let cur   = meta.query_advice(advice[0], Rotation::cur());
            let sib   = meta.query_advice(advice[1], Rotation::cur());
            let bit   = meta.query_advice(advice[2], Rotation::cur());
            let left  = meta.query_advice(advice[3], Rotation::cur());
            let right = meta.query_advice(advice[4], Rotation::cur());
            let sel   = meta.query_selector(s_swap);
            let one = Expression::Constant(Fp::one());
            Constraints::with_selector(sel, vec![
                // booleanity FIRST — an unconstrained "bit" of 7 makes the swap meaningless
                bit.clone() * (one - bit.clone()),
                left  - (cur.clone() + bit.clone() * (sib.clone() - cur.clone())),
                right - (sib.clone() + bit * (cur - sib)),
            ])
        });

        let state = [meta.advice_column(), meta.advice_column(), meta.advice_column()];
        let partial_sbox = meta.advice_column();
        let rc_a = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        let rc_b = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        meta.enable_constant(rc_b[0]);
        let poseidon = Pow5Chip::configure::<P128Pow5T3>(meta, state, partial_sbox, rc_a, rc_b);

        MerkleConfig { poseidon, advice, instance, s_swap }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>)
        -> Result<(), Error>
    {
        let mut cur: AssignedCell<Fp, Fp> = layouter.assign_region(
            || "witness leaf",
            |mut region| region.assign_advice(|| "leaf", config.advice[0], 0, || self.leaf),
        )?;

        for (i, step) in self.path.iter().enumerate() {
            // Order the pair according to the direction bit, with the ordering itself constrained.
            let (left, right) = layouter.assign_region(
                || format!("swap {i}"),
                |mut region| {
                    config.s_swap.enable(&mut region, 0)?;
                    let c = cur.copy_advice(|| "cur", &mut region, config.advice[0], 0)?;
                    let s = region.assign_advice(|| "sib", config.advice[1], 0, || step.sibling)?;
                    region.assign_advice(|| "bit", config.advice[2], 0, || step.bit)?;
                    let l = region.assign_advice(|| "left", config.advice[3], 0,
                        || c.value().copied() + step.bit * (s.value().copied() - c.value().copied()))?;
                    let r = region.assign_advice(|| "right", config.advice[4], 0,
                        || s.value().copied() + step.bit * (c.value().copied() - s.value().copied()))?;
                    Ok((l, r))
                },
            )?;

            // A fresh hasher per level: Pow5Chip consumes its region, and reusing one silently
            // shares state between levels.
            let chip = Pow5Chip::construct(config.poseidon.clone());
            let hasher = PoseidonHash::<_, _, P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                chip, layouter.namespace(|| format!("poseidon init {i}")))?;
            cur = hasher.hash(layouter.namespace(|| format!("hash level {i}")), [left, right])?;
        }

        // The computed root must equal the PUBLIC root. Without this the circuit hashes a path to
        // whatever it likes and calls it a proof.
        layouter.constrain_instance(cur.cell(), config.instance, 0)
    }
}

/// The same hash the circuit uses, outside it — for building trees and checking test vectors.
pub fn hash2(a: Fp, b: Fp) -> Fp {
    use halo2_gadgets::poseidon::primitives::Hash;
    Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([a, b])
}

/// Build a path for `index` in a tree over `leaves`, padded to a power of two.
///
/// Returned alongside the root so a caller cannot accidentally prove against a root computed from
/// a different padding rule — the two must come from the same construction to mean anything.
pub fn path_for(leaves: &[Fp], index: usize) -> (Fp, Vec<Step>) {
    let mut level: Vec<Fp> = leaves.to_vec();
    let mut idx = index;
    let mut steps = Vec::new();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            // Duplicate the last leaf rather than padding with zero: a zero pad is a value a
            // prover might also be able to produce, and then two different trees share a root.
            level.push(*level.last().unwrap());
        }
        let sib = if idx % 2 == 0 { level[idx + 1] } else { level[idx - 1] };
        steps.push(Step {
            sibling: Value::known(sib),
            bit: Value::known(if idx % 2 == 0 { Fp::zero() } else { Fp::one() }),
        });
        level = level.chunks(2).map(|p| hash2(p[0], p[1])).collect();
        idx /= 2;
    }
    (level[0], steps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    fn leaves(n: usize) -> Vec<Fp> {
        (0..n).map(|i| Fp::from(1000 + i as u64)).collect()
    }

    #[test]
    fn a_real_path_proves() {
        let ls = leaves(8);
        let (root, path) = path_for(&ls, 5);
        let circuit = MerkleCircuit { leaf: Value::known(ls[5]), path };
        let prover = MockProver::run(9, &circuit, vec![vec![root]]).unwrap();
        assert!(prover.verify().is_ok(), "an honest path must prove");
    }

    #[test]
    fn every_leaf_proves_against_the_same_root() {
        let ls = leaves(8);
        for i in 0..8 {
            let (root, path) = path_for(&ls, i);
            let circuit = MerkleCircuit { leaf: Value::known(ls[i]), path };
            let prover = MockProver::run(9, &circuit, vec![vec![root]]).unwrap();
            assert!(prover.verify().is_ok(), "leaf {i} failed");
        }
    }

    #[test]
    fn a_leaf_that_is_not_in_the_tree_cannot_prove() {
        let ls = leaves(8);
        let (root, path) = path_for(&ls, 5);
        let circuit = MerkleCircuit { leaf: Value::known(Fp::from(999_999)), path };
        let prover = MockProver::run(9, &circuit, vec![vec![root]]).unwrap();
        assert!(prover.verify().is_err(), "a foreign leaf proved membership");
    }

    #[test]
    fn a_proof_does_not_transfer_to_another_root() {
        let ls = leaves(8);
        let (_, path) = path_for(&ls, 5);
        let other = leaves(8).iter().map(|x| x + Fp::one()).collect::<Vec<_>>();
        let (other_root, _) = path_for(&other, 5);
        let circuit = MerkleCircuit { leaf: Value::known(ls[5]), path };
        let prover = MockProver::run(9, &circuit, vec![vec![other_root]]).unwrap();
        assert!(prover.verify().is_err(), "a path proved against a different tree");
    }

    /// The swap gate is what stops the prover choosing its own tree shape. Flip one direction bit
    /// and the path hashes to something else — if this ever passes, the ordering is unconstrained
    /// and ANY leaf can be walked to ANY root.
    #[test]
    fn a_flipped_direction_bit_breaks_the_path() {
        let ls = leaves(8);
        let (root, mut path) = path_for(&ls, 5);
        path[0].bit = path[0].bit.map(|b| Fp::one() - b);
        let circuit = MerkleCircuit { leaf: Value::known(ls[5]), path };
        let prover = MockProver::run(9, &circuit, vec![vec![root]]).unwrap();
        assert!(prover.verify().is_err(), "the swap ordering is unconstrained");
    }

    /// A non-boolean direction bit would let the prover interpolate between left and right and
    /// reach a root no honest ordering produces.
    #[test]
    fn a_non_boolean_direction_bit_is_rejected() {
        let ls = leaves(8);
        let (root, mut path) = path_for(&ls, 5);
        path[1].bit = Value::known(Fp::from(7));
        let circuit = MerkleCircuit { leaf: Value::known(ls[5]), path };
        let prover = MockProver::run(9, &circuit, vec![vec![root]]).unwrap();
        assert!(prover.verify().is_err(), "a bit of 7 was accepted as a direction");
    }

    #[test]
    fn depth_grows_logarithmically() {
        for (n, depth) in [(2usize, 1usize), (8, 3), (64, 6), (1024, 10)] {
            let (_, path) = path_for(&leaves(n), 0);
            assert_eq!(path.len(), depth, "{n} leaves should need {depth} hashes");
        }
    }

    #[test]
    fn an_odd_level_duplicates_rather_than_zero_pads() {
        // 5 leaves: index 4 is alone on its level and must pair with itself.
        let ls = leaves(5);
        let (root, path) = path_for(&ls, 4);
        let circuit = MerkleCircuit { leaf: Value::known(ls[4]), path };
        let prover = MockProver::run(9, &circuit, vec![vec![root]]).unwrap();
        assert!(prover.verify().is_ok(), "odd-sized trees must still prove");
    }
}

/// Real proving, not `MockProver`.
///
/// `MockProver` answers "are these constraints satisfiable" — useful, and NOT the same question as
/// "does a proof exist, and does a verifier accept it". A circuit can satisfy MockProver and still
/// fail to prove: too small a `k`, a missing `enable_equality`, blinding rows overflowing the
/// domain. Until a proof has actually been generated and verified, a halo2 circuit is a description
/// of a SNARK rather than a SNARK.
#[cfg(test)]
mod real_proof {
    use super::*;
    use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier};
    use halo2_proofs::poly::commitment::Params;
    use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
    use pasta_curves::EqAffine;
    use rand_core::OsRng;

    const K: u32 = 11;

    fn leaves(n: usize) -> Vec<Fp> {
        (0..n).map(|i| Fp::from(1000 + i as u64)).collect()
    }

    /// Generate a proof for `index` in a tree over `n` leaves; return the proof and the root.
    fn prove(n: usize, index: usize) -> (Vec<u8>, Fp, Params<EqAffine>,
                                         halo2_proofs::plonk::ProvingKey<EqAffine>) {
        let ls = leaves(n);
        let (root, path) = path_for(&ls, index);
        let circuit = MerkleCircuit { leaf: Value::known(ls[index]), path };

        let params: Params<EqAffine> = Params::new(K);
        let vk = keygen_vk(&params, &circuit).expect("verifying key");
        let pk = keygen_pk(&params, vk, &circuit).expect("proving key");

        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof(&params, &pk, &[circuit], &[&[&[root]]], OsRng, &mut transcript)
            .expect("proof generation");
        (transcript.finalize(), root, params, pk)
    }

    #[test]
    fn a_proof_is_generated_and_verifies() {
        let (proof, root, params, pk) = prove(8, 5);
        println!("  MERKLE MEMBERSHIP PROOF: {} bytes, depth 3", proof.len());

        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        assert!(
            verify_proof(&params, pk.get_vk(), strategy, &[&[&[root]]], &mut transcript).is_ok(),
            "a generated proof must verify");
    }

    /// Bound to its root. This is what makes it a proof of membership rather than a proof that
    /// some hashing occurred.
    #[test]
    fn a_generated_proof_is_bound_to_its_root() {
        let (proof, root, params, pk) = prove(8, 5);
        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        assert!(
            verify_proof(&params, pk.get_vk(), strategy, &[&[&[root + Fp::one()]]],
                         &mut transcript).is_err(),
            "the proof verified against a root it was not made for");
    }

    /// The point of the circuit: proof size must not track the size of the log. The sigma-protocol
    /// version in Blindkeep is O(n) — about a kilobyte per record — and this is what replaces it.
    #[test]
    fn proof_size_does_not_grow_with_the_tree() {
        let (small, _, _, _) = prove(8, 3);
        let (large, _, _, _) = prove(128, 3);
        println!("     8 leaves (depth 3)  -> {} bytes", small.len());
        println!("   128 leaves (depth 7)  -> {} bytes", large.len());
        assert!(large.len() <= small.len() + 1024,
                "proof grew from {} to {} bytes when the tree grew 16x",
                small.len(), large.len());
    }
}

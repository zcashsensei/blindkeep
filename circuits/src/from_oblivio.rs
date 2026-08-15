//! Prove a witness exported by Oblivio — the two halves, actually connected.
//!
//! Everything else in this repository proves claims about the trading system. This proves that the
//! *memory layer* and the *circuit* agree: a witness produced by `oblivio zk-witness`, over a
//! Poseidon tree Python built, is consumed here and turned into a real SNARK proof.
//!
//! Without this test the two sides agree only in principle. Python computing a root that Rust also
//! computes is necessary and not sufficient — the witness format, the bit convention, the leaf
//! encoding and the public-input layout all have to line up too, and each is a silent failure.

#[cfg(test)]
mod tests {
    use crate::merkle::{MerkleCircuit, Step};
    use ff::PrimeField;
    use halo2_proofs::circuit::Value;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier};
    use halo2_proofs::poly::commitment::Params;
    use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
    use pasta_curves::{EqAffine, Fp};
    use rand_core::OsRng;

    /// Big-endian hex -> Fp. The Oblivio side emits big-endian so this is a straight read.
    fn fp_from_hex(h: &str) -> Fp {
        let mut bytes = [0u8; 32];
        let raw = hex_bytes(h);
        // to_repr is little-endian, so reverse the big-endian input.
        for (i, b) in raw.iter().rev().enumerate() {
            bytes[i] = *b;
        }
        Fp::from_repr(bytes).expect("witness value is not a canonical field element")
    }

    fn hex_bytes(h: &str) -> Vec<u8> {
        (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn a_oblivio_witness_produces_a_real_proof() {
        let path = match std::env::var("OBLIVIO_WITNESS") {
            Ok(p) => p,
            // Not every environment has a keep to export from; skip rather than fail loudly on
            // something that is not a defect in this crate.
            Err(_) => { println!("  OBLIVIO_WITNESS not set — skipping"); return; }
        };
        let raw = std::fs::read_to_string(&path).expect("read witness");
        let w: serde_json::Value = serde_json::from_str(&raw).expect("parse witness");

        assert_eq!(w["circuit"].as_str().unwrap(), "merkle-poseidon-p128pow5t3",
                   "witness was exported for a different circuit");

        let leaf = fp_from_hex(w["leaf"].as_str().unwrap());
        let root = fp_from_hex(w["public"]["root"].as_str().unwrap());
        let steps: Vec<Step> = w["path"].as_array().unwrap().iter().map(|s| Step {
            sibling: Value::known(fp_from_hex(s["sibling"].as_str().unwrap())),
            bit: Value::known(Fp::from(s["bit"].as_u64().unwrap())),
        }).collect();

        println!("  witness: depth {}, anchored to head size {}",
                 steps.len(), w["anchor"]["tree_size"]);

        let circuit = MerkleCircuit { leaf: Value::known(leaf), path: steps };

        // Constraints first: a clearer failure than a proving error if the witness is wrong.
        let mock = MockProver::run(11, &circuit, vec![vec![root]]).unwrap();
        assert!(mock.verify().is_ok(), "the Oblivio witness does not satisfy the circuit");

        let params: Params<EqAffine> = Params::new(11);
        let vk = keygen_vk(&params, &circuit).expect("vk");
        let pk = keygen_pk(&params, vk, &circuit).expect("pk");
        let mut t = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof(&params, &pk, &[circuit], &[&[&[root]]], OsRng, &mut t).expect("proof");
        let proof = t.finalize();
        println!("  PROOF FROM A OBLIVIO RECORD: {} bytes", proof.len());

        let strategy = SingleVerifier::new(&params);
        let mut t = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        assert!(verify_proof(&params, pk.get_vk(), strategy, &[&[&[root]]], &mut t).is_ok(),
                "a proof built from a real keep must verify");
    }
}

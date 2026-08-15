//! Dump the exact Poseidon parameters and test vectors the circuits use.
//!
//! Oblivio needs a Poseidon tree in Python whose hash matches this circuit's byte for byte —
//! a root computed with different constants produces a proof that never verifies, and the failure
//! is silent until someone tries. So the constants are exported from the authoritative source
//! rather than transcribed, and vectors are exported alongside them so the other implementation
//! can be checked rather than trusted.

#[cfg(test)]
mod dump {
    use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash, P128Pow5T3, Spec};
    use pasta_curves::Fp;
    use ff::PrimeField;
    use std::io::Write;

    fn hex_be(v: &Fp) -> String {
        // to_repr is little-endian; emit big-endian so Python's int(x, 16) reads it directly.
        let mut b = v.to_repr().as_ref().to_vec();
        b.reverse();
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn export_poseidon_parameters_and_vectors() {
        let (round_constants, mds, _mds_inv) =
            <P128Pow5T3 as Spec<Fp, 3, 2>>::constants();

        let mut out = String::from("{\n");
        out.push_str(&format!("  \"spec\": \"P128Pow5T3\",\n  \"width\": 3,\n  \"alpha\": 5,\n"));
        out.push_str(&format!("  \"full_rounds\": {},\n",
            <P128Pow5T3 as Spec<Fp, 3, 2>>::full_rounds()));
        out.push_str(&format!("  \"partial_rounds\": {},\n",
            <P128Pow5T3 as Spec<Fp, 3, 2>>::partial_rounds()));

        out.push_str("  \"round_constants\": [\n");
        for (i, rc) in round_constants.iter().enumerate() {
            let row: Vec<String> = rc.iter().map(|v| format!("\"{}\"", hex_be(v))).collect();
            out.push_str(&format!("    [{}]{}\n", row.join(", "),
                                  if i + 1 < round_constants.len() { "," } else { "" }));
        }
        out.push_str("  ],\n");

        out.push_str("  \"mds\": [\n");
        for (i, row) in mds.iter().enumerate() {
            let r: Vec<String> = row.iter().map(|v| format!("\"{}\"", hex_be(v))).collect();
            out.push_str(&format!("    [{}]{}\n", r.join(", "),
                                  if i + 1 < mds.len() { "," } else { "" }));
        }
        out.push_str("  ],\n");

        // Vectors: the whole point. A Python implementation is only correct if it reproduces these.
        out.push_str("  \"vectors\": [\n");
        let cases: Vec<(u64, u64)> = vec![(0, 0), (1, 0), (0, 1), (1, 2), (42, 1337),
                                          (u64::MAX, 7), (123456789, 987654321)];
        for (i, (a, b)) in cases.iter().enumerate() {
            let h = Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init()
                .hash([Fp::from(*a), Fp::from(*b)]);
            out.push_str(&format!("    {{\"a\": \"{a}\", \"b\": \"{b}\", \"hash\": \"{}\"}}{}\n",
                                  hex_be(&h), if i + 1 < cases.len() { "," } else { "" }));
        }
        out.push_str("  ]\n}\n");

        let path = std::env::var("POSEIDON_OUT")
            .unwrap_or_else(|_| "poseidon_params.json".to_string());
        let mut f = std::fs::File::create(&path).expect("write params");
        f.write_all(out.as_bytes()).expect("write");
        println!("  wrote {path}");
    }
}

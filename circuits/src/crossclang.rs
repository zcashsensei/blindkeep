//! Cross-language agreement: the Python tree and this circuit's tree must produce one root.
//!
//! If they ever diverge, a proof generated from a Python-built path verifies against nothing and
//! the failure is silent — the prover just fails, with no indication that the trees disagree
//! rather than the witness being wrong. So the agreement is asserted, not assumed.

#[cfg(test)]
mod tests {
    use crate::merkle::path_for;
    use pasta_curves::Fp;
    use ff::PrimeField;
    use std::io::Write;

    fn hex_be(v: &Fp) -> String {
        let mut b = v.to_repr().as_ref().to_vec();
        b.reverse();
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn export_tree_roots_for_python_comparison() {
        let mut out = String::from("{\n  \"trees\": [\n");
        let cases = [1usize, 2, 3, 4, 5, 8, 13];
        for (i, n) in cases.iter().enumerate() {
            let leaves: Vec<Fp> = (0..*n).map(|j| Fp::from(1000 + j as u64)).collect();
            let (root, _) = path_for(&leaves, 0);
            out.push_str(&format!(
                "    {{\"n\": {n}, \"root\": \"{}\"}}{}\n",
                hex_be(&root), if i + 1 < cases.len() { "," } else { "" }));
        }
        out.push_str("  ]\n}\n");
        let path = std::env::var("TREES_OUT").unwrap_or_else(|_| "tree_roots.json".into());
        std::fs::File::create(&path).unwrap().write_all(out.as_bytes()).unwrap();
        println!("  wrote {path}");
    }
}

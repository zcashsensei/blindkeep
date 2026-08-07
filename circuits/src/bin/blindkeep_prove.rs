//! blindkeep-prove — turn a Blindkeep witness into a SNARK proof, and check one.
//!
//! The memory layer can already export everything a proof needs (`blindkeep zk-witness`). Until
//! now, using it meant a Rust toolchain and a `cargo test` invocation, which is a fine story for
//! a developer and no story at all for anyone else. This is the missing step: one binary, two
//! subcommands, no toolchain on the far side.
//!
//! ```text
//!     blindkeep-prove prove  --witness w.json --out proof.json
//!     blindkeep-prove verify --proof proof.json
//! ```
//!
//! **The proof bundle is self-contained on purpose.** A verifier needs the circuit's shape to
//! rebuild its verifying key, and that shape depends on the tree depth — so the depth travels with
//! the proof. It carries the public root too, and the anchor the witness was exported with, so
//! that "this proof is about that keep at that signed head" survives being emailed to someone.
//!
//! **What it does NOT do:** check the anchor against a live node. The proof establishes that a
//! leaf sits under the stated root; whether that root belongs to a keep you trust is a question
//! about the signed head, and answering it needs the node. `blindkeep verify-in-keep` does that
//! side. Both halves are required and neither is sufficient, which is why this prints the anchor
//! rather than quietly implying it checked it.

use std::process::ExitCode;

use ff::PrimeField;
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use pasta_curves::{EqAffine, Fp};
use rand_core::OsRng;
use blindkeep_circuits::merkle::{MerkleCircuit, Step};

/// Circuit size. Poseidon over a depth-20 path fits comfortably; larger keeps need a larger k,
/// and the failure is loud (`NotEnoughRowsAvailable`) rather than silent.
const K: u32 = 11;

fn hex_to_fp(h: &str) -> Result<Fp, String> {
    let raw: Vec<u8> = (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("not hex: {e}"))?;
    let mut le = [0u8; 32];
    for (i, b) in raw.iter().rev().enumerate() {
        if i >= 32 {
            return Err("value is wider than 32 bytes".into());
        }
        le[i] = *b;
    }
    Option::from(Fp::from_repr(le)).ok_or_else(|| "not a canonical field element".into())
}

fn fp_to_hex(v: &Fp) -> String {
    let mut b = v.to_repr().as_ref().to_vec();
    b.reverse();
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn read_json(path: &str) -> Result<serde_json::Value, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("{path} is not valid JSON: {e}"))
}

/// Rebuild the circuit from a witness. Shared by prove and verify so the two cannot drift: the
/// verifying key depends on the circuit's shape, and a verifier that builds it differently from
/// the prover rejects every honest proof.
fn circuit_from(w: &serde_json::Value) -> Result<(MerkleCircuit, Fp, usize), String> {
    let kind = w["circuit"].as_str().unwrap_or("");
    if kind != "merkle-poseidon-p128pow5t3" {
        return Err(format!(
            "witness is for circuit {kind:?}; this binary only proves \
             merkle-poseidon-p128pow5t3"));
    }
    let leaf = hex_to_fp(w["leaf"].as_str().ok_or("witness has no leaf")?)?;
    let root = hex_to_fp(w["public"]["root"].as_str().ok_or("witness has no public root")?)?;
    let path = w["path"].as_array().ok_or("witness has no path")?;

    let steps: Result<Vec<Step>, String> = path
        .iter()
        .map(|s| {
            let bit = s["bit"].as_u64().ok_or("path step has no bit")?;
            if bit > 1 {
                // The circuit would reject it, but failing here says why.
                return Err(format!("direction bit is {bit}; it must be 0 or 1"));
            }
            Ok(Step {
                sibling: Value::known(hex_to_fp(
                    s["sibling"].as_str().ok_or("path step has no sibling")?)?),
                bit: Value::known(Fp::from(bit)),
            })
        })
        .collect();
    let steps = steps?;
    let depth = steps.len();
    Ok((MerkleCircuit { leaf: Value::known(leaf), path: steps }, root, depth))
}

fn cmd_prove(witness_path: &str, out: Option<&str>) -> Result<(), String> {
    let w = read_json(witness_path)?;
    let (circuit, root, depth) = circuit_from(&w)?;

    eprintln!("proving membership · depth {depth} · root {}…", &fp_to_hex(&root)[..16]);
    let params: Params<EqAffine> = Params::new(K);
    let vk = keygen_vk(&params, &circuit).map_err(|e| format!("verifying key: {e:?}"))?;
    let pk = keygen_pk(&params, vk, &circuit).map_err(|e| format!("proving key: {e:?}"))?;

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof(&params, &pk, &[circuit], &[&[&[root]]], OsRng, &mut transcript)
        .map_err(|e| format!("proof generation failed: {e:?}"))?;
    let proof = transcript.finalize();

    let bundle = serde_json::json!({
        "circuit": "merkle-poseidon-p128pow5t3",
        "depth": depth,
        "public": { "root": fp_to_hex(&root) },
        // Carried so the proof still means "that keep, at that head" after it leaves this machine.
        // NOT checked here — see the module note.
        "anchor": w["anchor"],
        "proof_hex": proof.iter().map(|b| format!("{b:02x}")).collect::<String>(),
    });
    let text = serde_json::to_string_pretty(&bundle).unwrap();

    match out {
        Some(p) => {
            std::fs::write(p, &text).map_err(|e| format!("cannot write {p}: {e}"))?;
            eprintln!("proof written to {p} ({} bytes of proof)", proof.len());
        }
        None => println!("{text}"),
    }
    Ok(())
}

fn cmd_verify(proof_path: &str) -> Result<(), String> {
    let b = read_json(proof_path)?;
    let depth = b["depth"].as_u64().ok_or("proof bundle has no depth")? as usize;
    let root = hex_to_fp(b["public"]["root"].as_str().ok_or("bundle has no root")?)?;
    let hexed = b["proof_hex"].as_str().ok_or("bundle has no proof")?;
    let proof: Vec<u8> = (0..hexed.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hexed[i..i + 2], 16))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("proof is not hex: {e}"))?;

    // An empty-witness circuit of the same depth: the verifying key depends on shape, not values.
    let shape = MerkleCircuit {
        leaf: Value::unknown(),
        path: vec![Step { sibling: Value::unknown(), bit: Value::unknown() }; depth],
    };
    let params: Params<EqAffine> = Params::new(K);
    let vk = keygen_vk(&params, &shape).map_err(|e| format!("verifying key: {e:?}"))?;

    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    verify_proof(&params, &vk, strategy, &[&[&[root]]], &mut transcript)
        .map_err(|_| "the proof does not hold for this root".to_string())?;

    println!("VERIFIED: the prover holds a record under root {}…",
             &fp_to_hex(&root)[..16]);
    println!("          depth {depth} — which record is not revealed.");
    if let Some(a) = b["anchor"].as_object() {
        println!();
        println!("  This proof is about the keep whose signed head is:");
        println!("    sha256 root {}", a.get("sha256_root_hex")
            .and_then(|v| v.as_str()).unwrap_or("(absent)"));
        println!("    tree size   {}", a.get("tree_size")
            .map(|v| v.to_string()).unwrap_or_else(|| "(absent)".into()));
        println!("  NOT checked here. Confirm it against a node with:");
        println!("    blindkeep verify-in-keep --proof <membership bundle>");
    }
    Ok(())
}

fn usage() -> &'static str {
    "blindkeep-prove — SNARK proofs over a Blindkeep keep\n\n\
     USAGE:\n  \
       blindkeep-prove prove  --witness <w.json> [--out <proof.json>]\n  \
       blindkeep-prove verify --proof <proof.json>\n\n\
     Produce a witness with:  blindkeep zk-witness --index N --out w.json"
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let flag = |name: &str| -> Option<String> {
        args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
    };

    let result = match args.get(1).map(String::as_str) {
        Some("prove") => match flag("--witness") {
            Some(w) => cmd_prove(&w, flag("--out").as_deref()),
            None => Err(format!("prove needs --witness\n\n{}", usage())),
        },
        Some("verify") => match flag("--proof") {
            Some(p) => cmd_verify(&p),
            None => Err(format!("verify needs --proof\n\n{}", usage())),
        },
        _ => {
            println!("{}", usage());
            return ExitCode::from(2);
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

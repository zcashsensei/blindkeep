//! Zero-knowledge circuits for the Blindkeep keep.
//!
//! The Python side of this repository holds the encrypted memory, the transparency log, and the
//! sigma-protocol proofs that work with no toolchain at all. This crate is the succinct half: it
//! proves membership in the keep with a proof whose size does not grow with the log.
//!
//! ```text
//!     a record in the keep
//!       -> Poseidon tree over the same committed leaves   blindkeep/zk_tree.py
//!       -> witness, leaf and path private, root public    blindkeep zk-witness
//!       -> this crate                                     merkle.rs
//!       -> 3,040-byte proof, verified                     blindkeep-prove
//! ```
//!
//! `dump_params` and `crossclang` exist so the two languages are **checked rather than trusted**.
//! A Poseidon that is subtly wrong still hashes, still builds a tree, and produces proofs that
//! verify against nothing — the prover simply fails, with no sign that the implementations
//! disagree rather than the witness being bad.

pub mod merkle;

mod crossclang;
mod dump_params;
mod from_blindkeep;

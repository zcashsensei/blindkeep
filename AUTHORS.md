# Authors & provenance

## Creator

**Oblivio was created by zcashsensei** — original concept, product vision, category
thesis, licensing model, and direction.

- **Project conceived and first implemented:** 2026-08-05
- **GitHub:** [@zcashsensei](https://github.com/zcashsensei)
- **Role:** creator, original author, and maintainer
- **Rights:** copyright retained by the creator. See [`LICENSE`](LICENSE). MIT
  grants the public use of the code; it does not transfer authorship,
  copyright, or the **Oblivio** name and brand, which remain with the creator.

Design principles and the constraints implementation must respect are recorded
in [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Establishing priority

Authorship priority for this work rests on the public record:

1. **Git commit timestamps** — the initial public commit is the first
   independently verifiable timestamp for the repository.
2. **Dated design documents in-repo** — `WHITEPAPER.md`, `CONTRIBUTING.md`,
   `SECURITY.md`, and related doctrine files record design decisions as of
   2026-08-05, not only what was implemented.
3. **The signed Merkle log itself** — a Oblivio head is an Ed25519 signature
   over `(tree_size, root)`. A head published at a known time is a commitment
   to the exact contents of a log at that time.

### A note on wording, so the claim survives scrutiny

Claim what is true and verifiable: **creator and original author of Oblivio**,
first public release dated by the commit history.

Do **not** claim to be first to invent encrypted storage, Merkle transparency
logs, or verifiable memory — those are decades-old prior art (RFC 6962,
Certificate Transparency, Filecoin, Arweave), and asserting otherwise invites
avoidable criticism. Priority over *this project, its architecture, and its
name* is real, defensible, and sufficient.

## Contributors

Contributions are welcome under the MIT license. By submitting a contribution
you affirm you have the right to license it under the terms in `LICENSE`.

| Name | Role | Since |
|------|------|-------|
| zcashsensei ([@zcashsensei](https://github.com/zcashsensei)) | Creator, original author, maintainer | 2026-08-05 |

"""Zero-knowledge proofs about stored records: prove a property, reveal nothing.

The rest of this project proves *facts about the log* — that a record is
committed, that history was not rewritten. This proves **facts about a record's
contents** without disclosing them:

    "this trade was inside my risk limit"      without revealing the position
    "this record's account is one of these"    without revealing which
    "these two records concern the same thing" without revealing what

**What this is.** Pedersen commitments and sigma protocols made non-interactive
by Fiat-Shamir, over RFC 3526 MODP Group 14. Classical, textbook, and composed
from `int` arithmetic and `hashlib` — no new dependency, and no curve
implementation of our own.

**What this is NOT — read before describing it.** It is *not* a SNARK. It proves
a small fixed set of algebraic predicates (opening, equality, set membership,
range), not arbitrary computation. It cannot prove "the model produced this
output" or "this program ran correctly"; that is zkML and general-purpose
proving, neither of which is here. Proofs are kilobytes, not hundreds of bytes,
and verification is linear in the statement rather than constant.

**It is also unaudited.** These are standard constructions implemented carefully
and tested adversarially, which is not the same as reviewed by a cryptographer.
Treat it accordingly.

**The invariant that matters most.** Fiat-Shamir derives the challenge by hashing
the statement. If the hash does not cover *every* public value the proof depends
on, the proof stops being a proof about the statement you asked about — a
verifier can be handed a valid proof of a *different* claim and accept it. That
is this project's oldest lesson in a third register: a valid proof is not an
answer to your question. `_transcript()` binds the group, the generators, the
statement type and every public input, length-prefixed so no two different
statements can serialise identically. `tests/test_zk.py` attacks exactly this.

**Cost.** ~17 ms per modular exponentiation at this parameter size, so an
opening proof is milliseconds and a 32-bit range proof is a couple of seconds.
Fine for proving a position was within limits; not a hot path.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Optional, Sequence

# RFC 3526 MODP Group 14. A safe prime, so the quadratic residues form a
# prime-order subgroup of order q = (p-1)/2 and every square except 1 generates
# it. Working in that subgroup avoids small-subgroup confusion entirely.
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
Q = (P - 1) // 2
G = 4                       # 2 squared: a quadratic residue, so it has order q
CHALLENGE_BITS = 256
DOMAIN = b"blindkeep-zk-v1"


class ProofError(Exception):
    """A proof could not be produced or does not verify."""


def _derive_h() -> int:
    """Second generator with no known discrete log relative to G.

    Nothing-up-my-sleeve: hash a fixed string, square it into the subgroup. If
    anyone knew log_G(H), commitments would stop being binding — so H must not
    be chosen, it must be derived in a way nobody can steer.
    """
    counter = 0
    while True:
        digest = hashlib.sha256(DOMAIN + b"-generator-h-" + str(counter).encode()).digest()
        candidate = pow(int.from_bytes(digest * 8, "big") % P, 2, P)
        if candidate not in (0, 1):
            return candidate
        counter += 1


H = _derive_h()


def _transcript(*items: bytes) -> int:
    """Fiat-Shamir challenge binding every public value, length-prefixed.

    Length prefixing is not decoration. With plain concatenation, the statements
    (`ab`, `c`) and (`a`, `bc`) hash identically, so a proof of one verifies as
    a proof of the other. Every element that a verifier will use must be inside
    this hash, in an unambiguous encoding.
    """
    h = hashlib.sha256()
    h.update(DOMAIN)
    for item in items:
        h.update(len(item).to_bytes(8, "big"))
        h.update(item)
    return int.from_bytes(h.digest(), "big") % (1 << CHALLENGE_BITS)


def _b(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")


def _params() -> tuple[bytes, ...]:
    """Group parameters, included in every transcript."""
    return (_b(P), _b(G), _b(H))


def _rand() -> int:
    return secrets.randbelow(Q - 1) + 1


# ---- commitments ------------------------------------------------------------


@dataclass(frozen=True)
class Commitment:
    """C = G^value * H^blinding mod P. Hiding perfectly, binding on discrete log."""
    value_hex: str

    @property
    def c(self) -> int:
        return int(self.value_hex, 16)

    def as_dict(self) -> dict:
        return {"commitment_hex": self.value_hex}


def commit(value: int, blinding: Optional[int] = None) -> tuple[Commitment, int]:
    """Commit to `value`. Returns the commitment and the blinding factor.

    Keep the blinding factor: it is required to prove anything about the value
    later, and revealing it reveals the value.
    """
    if value < 0:
        raise ProofError("only non-negative values can be committed")
    r = _rand() if blinding is None else blinding % Q
    c = (pow(G, value % Q, P) * pow(H, r, P)) % P
    return Commitment(f"{c:x}"), r


def _commit_to(value: int, r: int) -> int:
    return (pow(G, value % Q, P) * pow(H, r, P)) % P


# ---- proof of knowledge of an opening ---------------------------------------


@dataclass(frozen=True)
class Proof:
    kind: str
    data: dict

    def as_dict(self) -> dict:
        return {"kind": self.kind, **self.data}

    @classmethod
    def from_dict(cls, d: dict) -> "Proof":
        d = dict(d)
        kind = d.pop("kind", None)
        if not kind:
            raise ProofError("proof has no kind")
        return cls(kind=kind, data=d)


def prove_opening(commitment: Commitment, value: int, blinding: int,
                  context: bytes = b"") -> Proof:
    """Prove knowledge of (value, blinding) for a commitment, revealing neither."""
    w1, w2 = _rand(), _rand()
    t = (pow(G, w1, P) * pow(H, w2, P)) % P
    c = _transcript(*_params(), b"opening", context, _b(commitment.c), _b(t))
    s1 = (w1 + c * (value % Q)) % Q
    s2 = (w2 + c * (blinding % Q)) % Q
    return Proof("opening", {"t_hex": f"{t:x}", "s1_hex": f"{s1:x}", "s2_hex": f"{s2:x}"})


def verify_opening(commitment: Commitment, proof: Proof, context: bytes = b"") -> bool:
    if proof.kind != "opening":
        return False
    try:
        t = int(proof.data["t_hex"], 16)
        s1 = int(proof.data["s1_hex"], 16)
        s2 = int(proof.data["s2_hex"], 16)
    except (KeyError, ValueError):
        return False
    c = _transcript(*_params(), b"opening", context, _b(commitment.c), _b(t))
    left = (pow(G, s1, P) * pow(H, s2, P)) % P
    right = (t * pow(commitment.c, c, P)) % P
    return left == right


# ---- proof that two commitments hide the same value -------------------------


def prove_equality(c1: Commitment, c2: Commitment, blinding1: int, blinding2: int,
                   context: bytes = b"") -> Proof:
    """Prove c1 and c2 commit to the same value, without revealing it.

    C1/C2 = H^(r1-r2), so this reduces to knowing that difference — which is
    only possible when the committed values agree.
    """
    y = (c1.c * pow(c2.c, -1, P)) % P
    x = (blinding1 - blinding2) % Q
    w = _rand()
    t = pow(H, w, P)
    ch = _transcript(*_params(), b"equality", context, _b(c1.c), _b(c2.c), _b(t))
    s = (w + ch * x) % Q
    return Proof("equality", {"t_hex": f"{t:x}", "s_hex": f"{s:x}", "y_hex": f"{y:x}"})


def verify_equality(c1: Commitment, c2: Commitment, proof: Proof,
                    context: bytes = b"") -> bool:
    if proof.kind != "equality":
        return False
    try:
        t = int(proof.data["t_hex"], 16)
        s = int(proof.data["s_hex"], 16)
    except (KeyError, ValueError):
        return False
    # Recompute y rather than trusting the proof's copy: a prover who can choose
    # y proves a statement about a value the verifier never asked about.
    y = (c1.c * pow(c2.c, -1, P)) % P
    ch = _transcript(*_params(), b"equality", context, _b(c1.c), _b(c2.c), _b(t))
    return pow(H, s, P) == (t * pow(y, ch, P)) % P


# ---- set membership: prove the value is one of a public set -----------------


def prove_membership(commitment: Commitment, value: int, blinding: int,
                     candidates: Sequence[int], context: bytes = b"") -> Proof:
    """Prove the committed value is in `candidates`, without revealing which.

    A standard OR-composition: a real sigma proof for the true branch, simulated
    proofs for the rest, with the challenges constrained to sum to the
    Fiat-Shamir challenge so exactly one branch can have been real.
    """
    cands = list(candidates)
    if value not in cands:
        raise ProofError("value is not among the candidates")
    j = cands.index(value)
    n = len(cands)

    ys = [(commitment.c * pow(pow(G, v % Q, P), -1, P)) % P for v in cands]
    ts: list[int] = [0] * n
    cs: list[int] = [0] * n
    ss: list[int] = [0] * n

    w = _rand()
    for i in range(n):
        if i == j:
            ts[i] = pow(H, w, P)
        else:
            cs[i] = secrets.randbits(CHALLENGE_BITS)
            ss[i] = _rand()
            ts[i] = (pow(H, ss[i], P) * pow(pow(ys[i], cs[i], P), -1, P)) % P

    challenge = _transcript(*_params(), b"membership", context, _b(commitment.c),
                            *[_b(v) for v in cands], *[_b(t) for t in ts])
    cs[j] = (challenge - sum(cs[i] for i in range(n) if i != j)) % (1 << CHALLENGE_BITS)
    ss[j] = (w + cs[j] * (blinding % Q)) % Q

    return Proof("membership", {
        "t_hex": [f"{t:x}" for t in ts],
        "c_hex": [f"{c:x}" for c in cs],
        "s_hex": [f"{s:x}" for s in ss],
        "candidates": [str(v) for v in cands],
    })


def verify_membership(commitment: Commitment, proof: Proof,
                      candidates: Sequence[int], context: bytes = b"") -> bool:
    if proof.kind != "membership":
        return False
    try:
        ts = [int(x, 16) for x in proof.data["t_hex"]]
        cs = [int(x, 16) for x in proof.data["c_hex"]]
        ss = [int(x, 16) for x in proof.data["s_hex"]]
        claimed = [int(v) for v in proof.data["candidates"]]
    except (KeyError, ValueError, TypeError):
        return False

    # The verifier's candidate set is authoritative. Accepting the prover's list
    # would let them prove membership in a set they chose after the fact.
    cands = list(candidates)
    if claimed != cands or not (len(ts) == len(cs) == len(ss) == len(cands)):
        return False

    challenge = _transcript(*_params(), b"membership", context, _b(commitment.c),
                            *[_b(v) for v in cands], *[_b(t) for t in ts])
    if sum(cs) % (1 << CHALLENGE_BITS) != challenge:
        return False

    for i, v in enumerate(cands):
        y = (commitment.c * pow(pow(G, v % Q, P), -1, P)) % P
        if pow(H, ss[i], P) != (ts[i] * pow(y, cs[i], P)) % P:
            return False
    return True


# ---- range: prove 0 <= value < 2^bits ---------------------------------------


def prove_range(value: int, blinding: int, bits: int = 32,
                context: bytes = b"") -> tuple[Commitment, Proof]:
    """Prove a committed value fits in `bits` bits, revealing nothing else.

    The predicate a risk limit actually needs: *this position was within the
    cap* without disclosing the position. Decomposes the value into bit
    commitments, proves each is 0 or 1, and proves the bits reconstruct the
    original commitment.
    """
    if value < 0 or value >= (1 << bits):
        raise ProofError(f"value does not fit in {bits} bits")

    commitment = Commitment(f"{_commit_to(value, blinding):x}")
    bit_r = [_rand() for _ in range(bits)]
    bit_c = [_commit_to((value >> i) & 1, bit_r[i]) for i in range(bits)]

    bit_proofs = []
    for i in range(bits):
        bit_proofs.append(prove_membership(
            Commitment(f"{bit_c[i]:x}"), (value >> i) & 1, bit_r[i], [0, 1],
            context=context + b"|bit" + str(i).encode()).as_dict())

    # C / prod(C_i^(2^i)) = H^(r - sum(2^i r_i)): a discrete-log proof base H,
    # which ties the bits to this exact commitment rather than any other.
    aggregate = 1
    for i in range(bits):
        aggregate = (aggregate * pow(bit_c[i], 1 << i, P)) % P
    y = (commitment.c * pow(aggregate, -1, P)) % P
    z = (blinding - sum((1 << i) * bit_r[i] for i in range(bits))) % Q

    w = _rand()
    t = pow(H, w, P)
    ch = _transcript(*_params(), b"range", context, _b(commitment.c),
                     _b(bits), *[_b(c) for c in bit_c], _b(t))
    s = (w + ch * z) % Q

    return commitment, Proof("range", {
        "bits": bits,
        "bit_commitments_hex": [f"{c:x}" for c in bit_c],
        "bit_proofs": bit_proofs,
        "t_hex": f"{t:x}",
        "s_hex": f"{s:x}",
    })


def verify_range(commitment: Commitment, proof: Proof, bits: int = 32,
                 context: bytes = b"") -> bool:
    if proof.kind != "range":
        return False
    try:
        if int(proof.data["bits"]) != bits:
            return False
        bit_c = [int(x, 16) for x in proof.data["bit_commitments_hex"]]
        bit_proofs = proof.data["bit_proofs"]
        t = int(proof.data["t_hex"], 16)
        s = int(proof.data["s_hex"], 16)
    except (KeyError, ValueError, TypeError):
        return False
    if len(bit_c) != bits or len(bit_proofs) != bits:
        return False

    for i in range(bits):
        if not verify_membership(Commitment(f"{bit_c[i]:x}"),
                                 Proof.from_dict(bit_proofs[i]), [0, 1],
                                 context=context + b"|bit" + str(i).encode()):
            return False

    aggregate = 1
    for i in range(bits):
        aggregate = (aggregate * pow(bit_c[i], 1 << i, P)) % P
    y = (commitment.c * pow(aggregate, -1, P)) % P
    ch = _transcript(*_params(), b"range", context, _b(commitment.c),
                     _b(bits), *[_b(c) for c in bit_c], _b(t))
    return pow(H, s, P) == (t * pow(y, ch, P)) % P

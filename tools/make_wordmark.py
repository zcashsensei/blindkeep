#!/usr/bin/env python3
"""Generate the lockup: a Merkle tree, then the word filled with the maths.

    python tools/make_wordmark.py

Writes assets/oblivio-wordmark-mono.svg (black, light ground) and
assets/oblivio-wordmark-mono-inverse.svg (white, dark ground).

The mark
--------
A Merkle tree, because it is the one structure the whole project rests on:
sealed leaves at the bottom (encrypted data), a single node at the top (the
signed head a client pins), and one bolded route between them (an inclusion
proof). Encrypted data, verified proofs, drawn as the structure that does it.

It replaced a shield. A shield is the most generic secure looking object there
is, and BRAND.md already rules out padlocks, vaults and keyholes on exactly that
ground: it said nothing this project could not have claimed before writing any
code.

The mark is solid, not filled with maths like the word. At 44px the formulae
would be an illegible smear, and a mark showing text nobody can read is the same
defect as a proof nobody can check.

The word
--------
UNCHANGED. The letterforms are a clipping path filled with the statements this
project implements, seven staggered rows cycling five families. Every parameter
below the WORD heading is carried over verbatim; the only difference from the
previous lockup is the anchor, which moves from centred to start because the
mark now occupies the left. If you are editing this file, the word's appearance
is the one thing not to touch.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

W, H = 330, 96

# ---------------------------------------------------------------- WORD ----
# One line per module, in the order a record actually travels through them.
# Keep these true: the mark is only worth having if the maths on it is the maths
# in the files named beside it.
FORMULAE = [
    # crypto.py / store.py -- per-record key, AEAD, and what "secure" means
    "k_r = HKDF(K, tag ‖ id)   c = AES-GCM(k_r, nonce, m, aad)   Adv(A) ≤ negl(λ)",
    # merkle.py -- RFC 6962 domain separation, proof size, signed head
    "leaf = H(0x00 ‖ rec)   node = H(0x01 ‖ L ‖ R)   |π| = ⌈log₂ N⌉   σ = Sign(sk, N ‖ root)",
    # zk.py -- Schnorr sigma protocol, and the simulator that makes it zero-knowledge
    "t = g^k   c = H(x ‖ t)   z = k + c·w   g^z = t·y^c ✓   ∃ S : S(x) ≈ view(V)",
    # dp.py -- the differential privacy bound and sequential composition
    "Pr[M(D) ∈ S] ≤ e^ε · Pr[M(D') ∈ S]   Σ ε_i ≤ ε   proven held",
    # anon_token.py -- Chaum blind signature: blind, sign, unblind, verify
    "m* = H(t)·r^e mod n   s* = (m*)^d   s = s*·r⁻¹   s^e ≡ H(t) (mod n) ✓",
]

BASELINE = 62
FONT_SIZE = 40
TRACKING = 6.5
WORD_X = 94            # start anchor, clear of the mark
STACK = ("ui-sans-serif, -apple-system, 'Segoe UI', Roboto, "
         "Helvetica, Arial, sans-serif")

MATH_SIZE = 5.4
MATH_STEP = 5.6
MATH_TOP, MATH_BOTTOM = 30, 64
MATH_CHARS = 128       # overruns the canvas on purpose so rows bleed past it
BACKING = 0.30         # solid under the maths, so the letterforms hold their shape
MATH_STACK = ("ui-monospace, SFMono-Regular, Consolas, "
              "'Liberation Mono', monospace")

# ---------------------------------------------------------------- MARK ----
# Absolute coordinates in the 330x96 canvas, drawn directly rather than scaled
# from a 96 grid, so the stroke weights are the real rendered ones. 44 square
# against a 28px cap height: matching the cap exactly makes a mark look timid,
# much past 1.5x makes it shout over the name.
ROOT_XY = (52, 28)
MID = [(40, 45), (64, 45)]
LEAF_X = [33, 45, 59, 71]
LEAF_Y = 62            # top edge of the leaf squares; the word's baseline too
LEAF = 8
EDGE, PROOF = 2.4, 3.6
DIM = "0.42"


def rows() -> list[tuple[float, float, str]]:
    """(x, y, text) per row, staggered so the columns never line up.

    Aligned rows would draw vertical seams down the letterforms, which reads as a
    printing fault rather than as structure.
    """
    out = []
    i = 0
    y = float(MATH_TOP)
    while y <= MATH_BOTTOM:
        line = FORMULAE[i % len(FORMULAE)]
        filled = line
        while len(filled) < MATH_CHARS:
            filled = f"{filled}   {line}"
        # Rounded because accumulating a float step writes coordinates like
        # 63.60000000000001 into the file: noise that survives every future diff.
        out.append((round(-8.0 - (i * 13) % 40, 2), round(y, 2),
                    filled[:MATH_CHARS]))
        y += MATH_STEP
        i += 1
    return out


def mark(ink: str) -> str:
    rx, ry = ROOT_XY
    (m1x, m1y), (m2x, m2y) = MID
    # Leaf 0 is the one the proof path reaches, so it is at full weight and the
    # rest are dimmed: the mark shows one record proved, not four highlighted.
    leaf_lines = []
    for i, x in enumerate(LEAF_X):
        dim = "" if i == 0 else f' opacity="{DIM}"'
        leaf_lines.append(
            f'    <rect x="{x}" y="{LEAF_Y}" width="{LEAF}" height="{LEAF}"'
            f' rx="1.5" fill="{ink}"{dim}/>')
    leaves = "\n".join(leaf_lines)
    return f"""  <g>
    <path d="M{rx} {ry} L{m2x} {m2y} M{m1x} {m1y} L{LEAF_X[1] + LEAF / 2} {LEAF_Y}
             M{m2x} {m2y} L{LEAF_X[2] + LEAF / 2} {LEAF_Y}
             M{m2x} {m2y} L{LEAF_X[3] + LEAF / 2} {LEAF_Y}"
          fill="none" stroke="{ink}" stroke-width="{EDGE}" opacity="{DIM}"
          stroke-linecap="round"/>
    <path d="M{rx} {ry} L{m1x} {m1y} L{LEAF_X[0] + LEAF / 2} {LEAF_Y}"
          fill="none" stroke="{ink}" stroke-width="{PROOF}"
          stroke-linecap="round" stroke-linejoin="round"/>
    <circle cx="{m2x}" cy="{m2y}" r="3" fill="{ink}" opacity="{DIM}"/>
    <circle cx="{m1x}" cy="{m1y}" r="3.6" fill="{ink}"/>
    <circle cx="{rx}" cy="{ry}" r="5.2" fill="{ink}"/>
{leaves}
  </g>"""


def svg(ink: str, ground: str) -> str:
    # NB: no "--" anywhere in the comment below. XML forbids it inside a comment,
    # and GitHub renders README SVGs through a sanitiser that drops the file
    # rather than repairing it, so the mark would simply not appear.
    band = "\n".join(
        f'      <text x="{x}" y="{y}" font-family="{MATH_STACK}" '
        f'font-size="{MATH_SIZE}" fill="{ink}">{text}</text>'
        for x, y, text in rows())
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}"
     role="img" aria-label="Oblivio">
  <title>Oblivio</title>
  <!-- GENERATED by tools/make_wordmark.py. Edit that, not this.

       A Merkle tree, then the word. Sealed leaves at the bottom are the
       encrypted data, the node at the top is the signed head a client pins, and
       the one bolded route between them is an inclusion proof. Encrypted data,
       verified proofs, drawn as the structure that does it.

       The letterforms are a clipping path filled with the statements this
       project implements: the per record key derivation and AEAD from crypto.py
       and store.py, the RFC 6962 leaf and node hashing with the signed head from
       merkle.py, the Schnorr sigma protocol and its simulator from zk.py, the
       differential privacy bound and sequential composition from dp.py, and the
       Chaum blind signature from anon_token.py. If any of those files change
       what they prove, this mark is wrong and has to be regenerated.

       The tree is solid rather than filled the same way: at 44px the formulae
       would be an illegible smear, and a mark showing text nobody can read is
       the same defect as a proof nobody can check.

       Ink {ink} on a {ground} ground. The pair is switched by
       prefers-color-scheme in the README: a single ink mark needs both inks, or
       half the readers get nothing.

       The wordmark is live <text>, so the clip depends on the reader's font
       stack. Convert to outlines before print, embroidery, or handing this to
       anyone whose renderer you do not control. -->
{mark(ink)}
  <defs>
    <clipPath id="oblivio-wordmark">
      <text x="{WORD_X}" y="{BASELINE}"
            font-family="{STACK}"
            font-size="{FONT_SIZE}" letter-spacing="{TRACKING}"
            font-weight="700">OBLIVIO</text>
    </clipPath>
  </defs>
  <g clip-path="url(#oblivio-wordmark)">
    <rect x="0" y="0" width="{W}" height="{H}" fill="{ink}" opacity="{BACKING}"/>
    <g>
{band}
    </g>
  </g>
</svg>
"""


def main() -> int:
    targets = [
        ("assets/oblivio-wordmark-mono.svg", "#000000", "light"),
        ("assets/oblivio-wordmark-mono-inverse.svg", "#FFFFFF", "dark"),
    ]
    for rel, ink, ground in targets:
        (ROOT / rel).write_text(svg(ink, ground), encoding="utf-8")
        print(f"wrote {rel}  (merkle mark + maths-filled word, {ink} on {ground})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

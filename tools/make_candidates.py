#!/usr/bin/env python3
"""Generate candidate marks to replace the shield.

    python tools/make_candidates.py

Writes assets/marks/candidates/*.svg and a manifest.json beside them. The
dashboard's Logos tab reads that directory, so adding or changing a candidate
here shows up there without touching dashboard.py.

The brief
---------
The shield is out. It is the most generic secure-looking shape there is, and
BRAND.md already rules out the neighbouring cliches for the same reason: a mark
that merely looks secure is a mark any password manager could wear. The wordmark
is settled, so this is only the glyph that sits in front of it.

Every candidate below encodes a claim this project can actually defend, named in
CLAIM. That is the cut: if a shape cannot be tied to something in the repo, it
does not belong here however handsome it is.

Drawing rules
-------------
* 96x96, safe area roughly 10..86.
* currentColor, never a hex. These are monochrome by design and the page decides
  the ink, so one file works on both grounds.
* Stroke 7 for primary structure, 4.5 for secondary. BRAND.md records that the
  old shield's 4px line disappeared below about 20px; a favicon is the size that
  matters, so weight is chosen for 16px and allowed to look heavy at 96.
* No cut-outs against a panel colour. The existing marks fake knockouts with a
  background fill, which breaks the moment the ground changes; these use real
  geometry so they survive inversion.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets" / "marks" / "candidates"

S1, S2 = 7, 4.5      # primary / secondary stroke

CANDIDATES = [
    {
        "id": "inclusion-path",
        "name": "Inclusion Path",
        "claim": "This record is in the log, and the path is the proof",
        "why": "merkle.py. The one picture of an inclusion proof: a tree with a "
               "single route from leaf to root picked out. Reads as structure "
               "even when the thin edges vanish at favicon size.",
        "body": f"""
  <path d="M48 24 L28 48 M48 24 L68 48 M68 48 L58 72 M68 48 L80 72"
        fill="none" stroke="currentColor" stroke-width="{S2}" opacity=".45"
        stroke-linecap="round"/>
  <path d="M48 24 L28 48 L18 72" fill="none" stroke="currentColor"
        stroke-width="{S1}" stroke-linecap="round" stroke-linejoin="round"/>
  <circle cx="48" cy="20" r="7" fill="currentColor"/>
  <circle cx="18" cy="76" r="7" fill="currentColor"/>
  <circle cx="38" cy="76" r="4" fill="currentColor" opacity=".45"/>
  <circle cx="58" cy="76" r="4" fill="currentColor" opacity=".45"/>
  <circle cx="80" cy="76" r="4" fill="currentColor" opacity=".45"/>""",
    },
    {
        "id": "three-move",
        "name": "Three Move",
        "claim": "Commit, challenge, response — the sigma protocol itself",
        "why": "zk.py. Two parties, three messages, and the middle one comes "
               "back the other way. The only mark here that draws a protocol "
               "rather than an object.",
        "body": f"""
  <path d="M14 18 V78 M82 18 V78" stroke="currentColor" stroke-width="{S2}"
        stroke-linecap="round"/>
  <path d="M20 32 H70 M62 24 L72 32 L62 40" fill="none" stroke="currentColor"
        stroke-width="{S1}" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M76 48 H26 M34 40 L24 48 L34 56" fill="none" stroke="currentColor"
        stroke-width="{S1}" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M20 64 H70 M62 56 L72 64 L62 72" fill="none" stroke="currentColor"
        stroke-width="{S1}" stroke-linecap="round" stroke-linejoin="round"/>""",
    },
    {
        "id": "commitment",
        "name": "Commitment",
        "claim": "Bound to a value before the challenge, without showing it",
        "why": "zk.py commit(). Brackets that have closed on something you "
               "cannot see. Binding and hiding in one shape, which is exactly "
               "the two properties a commitment has.",
        "body": f"""
  <path d="M34 16 H20 V80 H34" fill="none" stroke="currentColor"
        stroke-width="{S1}" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M62 16 H76 V80 H62" fill="none" stroke="currentColor"
        stroke-width="{S1}" stroke-linecap="round" stroke-linejoin="round"/>
  <circle cx="48" cy="48" r="15" fill="currentColor"/>""",
    },
    {
        "id": "the-gap",
        "name": "The Gap",
        "claim": "You learn the boundary. You do not learn the centre",
        "why": "The whole thesis in two circles: an open ring is what the "
               "verifier gets, the solid core is what stays. The break in the "
               "ring is where the information would have escaped and does not.",
        "body": f"""
  <path d="M48 14 A34 34 0 1 1 14 48" fill="none" stroke="currentColor"
        stroke-width="{S1}" stroke-linecap="round"/>
  <circle cx="48" cy="48" r="14" fill="currentColor"/>""",
    },
    {
        "id": "append-only",
        "name": "Append Only",
        "claim": "History grows one way and cannot be rewritten unseen",
        "why": "merkle.py consistency proofs. Rungs that stack upward off a "
               "sealed base. The bar widths differ so it never reads as a "
               "signal-strength icon.",
        "body": f"""
  <rect x="20" y="72" width="56" height="10" rx="3" fill="currentColor"/>
  <path d="M26 60 H70 M26 46 H62 M26 32 H54" stroke="currentColor"
        stroke-width="{S1}" stroke-linecap="round"/>
  <path d="M62 24 L72 14 L82 24" fill="none" stroke="currentColor"
        stroke-width="{S2}" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M72 14 V34" stroke="currentColor" stroke-width="{S2}"
        stroke-linecap="round"/>""",
    },
    {
        "id": "signed-head",
        "name": "Signed Head",
        "claim": "One signed value commits to the entire history",
        "why": "crypto.py sign_head(). A stack of records collapsing into a "
               "single bar with a seal on it. The claim the node is held to, "
               "and the thing a client pins.",
        "body": f"""
  <rect x="18" y="18" width="60" height="12" rx="4" fill="currentColor"/>
  <path d="M26 42 H70 M30 56 H66 M34 70 H62" stroke="currentColor"
        stroke-width="{S2}" stroke-linecap="round" opacity=".5"/>
  <path d="M40 82 L48 74 L56 82 L48 88 Z" fill="currentColor"/>""",
    },
    {
        "id": "witness-discarded",
        "name": "Witness Discarded",
        "claim": "The proof survives. The thing that made it does not",
        "why": "zk-prove: the witness is destroyed once the proof exists. Solid "
               "proof, dashed witness. The only candidate whose meaning is an "
               "absence, which is also the riskiest to read at small size.",
        "body": f"""
  <rect x="14" y="30" width="34" height="38" rx="6" fill="none"
        stroke="currentColor" stroke-width="{S2}" stroke-dasharray="6 7"
        opacity=".55"/>
  <rect x="52" y="24" width="32" height="50" rx="6" fill="currentColor"/>
""",
    },
    {
        "id": "fiat-shamir",
        "name": "Fiat–Shamir",
        "claim": "The challenge comes from the statement, not from a verifier",
        "why": "zk.py _transcript(). A loop that feeds its own output back as "
               "its input — the transform that makes an interactive proof into "
               "a file you can hand someone.",
        "body": f"""
  <path d="M70 34 A28 28 0 1 0 76 54" fill="none" stroke="currentColor"
        stroke-width="{S1}" stroke-linecap="round"/>
  <path d="M60 30 L72 32 L70 44" fill="none" stroke="currentColor"
        stroke-width="{S1}" stroke-linecap="round" stroke-linejoin="round"/>
  <circle cx="48" cy="48" r="9" fill="currentColor"/>""",
    },
    {
        "id": "one-of-many",
        "name": "One of Many",
        "claim": "One of these is mine. Which one is not revealed",
        "why": "prove-in-keep, the membership proof. A row with one member "
               "ringed and deliberately no brighter than the rest — the ring "
               "marks the set, not the element.",
        "body": f"""
  <circle cx="20" cy="48" r="7" fill="currentColor"/>
  <circle cx="38" cy="48" r="7" fill="currentColor"/>
  <circle cx="58" cy="48" r="7" fill="currentColor"/>
  <circle cx="76" cy="48" r="7" fill="currentColor"/>
  <rect x="8" y="26" width="80" height="44" rx="20" fill="none"
        stroke="currentColor" stroke-width="{S2}" opacity=".55"/>""",
    },
    {
        "id": "verified-void",
        "name": "Verified Void",
        "claim": "Checked, and there was nothing to see",
        "why": "The receipt in one glyph: a tick cut out of a solid block, so "
               "the confirmation is made of the absence rather than drawn on "
               "top of it. Strongest at 16px of anything here.",
        "body": f"""
  <path fill-rule="evenodd" fill="currentColor"
        d="M16 16 H80 V80 H16 Z
           M32 50 L43 62 L66 34 L59 28 L43 48 L38 43 Z"/>""",
    },
]


def svg(c: dict) -> str:
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96" width="96" height="96"
     role="img" aria-label="{c['name']}">
  <title>{c['name']}</title>
  <!-- GENERATED by tools/make_candidates.py. Edit that, not this.
       Candidate mark. Claim: {c['claim']}
       Drawn in currentColor so one file works on either ground. -->
{c['body'].rstrip()}
</svg>
"""


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    manifest = []
    for c in CANDIDATES:
        (OUT / f"{c['id']}.svg").write_text(svg(c), encoding="utf-8")
        manifest.append({k: c[k] for k in ("id", "name", "claim", "why")})
    (OUT / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(manifest)} candidates + manifest.json to {OUT}")
    for c in manifest:
        print(f"  {c['id']:20} {c['claim']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

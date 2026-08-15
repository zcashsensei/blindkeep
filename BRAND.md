# Brand

## The mark

`assets/oblivio-lockup.svg` is the primary lockup: the **wordmark alone**, centred.
The shield is not in it. A name and a symbol shown together every time teaches nobody
which one carries the identity, and the wordmark has to survive on its own anyway — in
a commit signature, a forum post, a plain-text sponsor list. `assets/oblivio-mark.svg`
is the shield alone, for square crops and anywhere the name is already present.

`assets/oblivio-wordmark-mono.svg` is the black-and-white proof — one ink, no colour.
It is the check that the mark still reads through a photocopier, a single-colour print
run, or a partner's house style. `assets/oblivio-wordmark-mono-inverse.svg` is the same
in white, drawn rather than derived: inverting the gold gives a muddy olive and screening
black gives grey.

**The README uses the mono pair, not the gold lockup**, switched by
`prefers-color-scheme` through `<picture>`. Gold `#F4B728` is legible on the near-black
this brand assumes, and thin on the white half of GitHub's readership — a logo that only
works in one of a host's two themes is broken for whoever gets the other one. The gold
lockup remains primary everywhere the ground is ours to choose.

`assets/favicon.svg` is a separately drawn variant with a
heavier stroke and a wider door, because the full mark's 4px shield line disappears below
about 20px and its door closes into a solid block. Scaling one file down is not the same
as drawing for the size it will be seen at.

Colour is Zcash gold `#F4B728` on a dark ground. Gold is an accent, never a surface: at
scale it reads as a warning colour, and on near-black it is what makes the mark legible.

The wordmark in the lockup is live `<text>` on a system font stack, not outlined paths.
That is fine for web and README use. It is **not** fine for print, embroidery, or handing
to a third party — convert the glyphs to outlines first, or it renders in whatever font
the recipient happens to have.

## Alternates

`assets/marks/` holds the marks that were considered and kept. They are grouped by the
claim each one encodes, because a mark that merely looks secure is a mark any password
manager could wear:

| Claim | Marks |
|---|---|
| The holder cannot read it | `sealed-keep` (chosen), `blind-eye`, `redacted`, `cipher-grid`, `eclipse`, `aperture`, `blindfold` |
| The holder cannot alter it undetected | `merkle-keep`, `append-log`, `wax-seal` |
| You can prove without revealing | `zero-knowledge`, `zk-ligature` |
| No single operator sees the whole request | `split-trust`, `prism-split` |

## Deliberately not used

- **A chain or block motif.** There is no chain and no token here, and a mark saying
  otherwise recruits the wrong audience and contradicts the first page of the README.
- **A bare Zcash Z.** It leans on an identity this project has not earned and could read
  as an official Zcash product. Adjacent and aligned, not affiliated.
- **Generic padlocks, vaults, keyholes.** Handsome and interchangeable.

## Gap

No mark yet draws *durability* — memory surviving a dead device without trusting a host.
Every mark above draws secrecy or integrity. That is one of the stronger claims and it has
no picture.

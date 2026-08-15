"""Render assets/oblivio-mark.svg to a Windows .ico, stdlib only.

There is no Pillow on this machine and adding a dependency to draw one icon is
a poor trade, so this rasterises the mark directly: sample the SVG's two cubic
segments into a polygon, scanline-fill it with 4x supersampling, deflate to
PNG, and wrap the PNGs in an ICO directory.

Colour follows BRAND.md: Zcash gold #F4B728 on near-black. Gold is the accent
and never the surface, so the keep is drawn as an outline with the door knocked
out, exactly as the SVG does -- a solid gold shield would read as a warning
sign at size.

Run: python tools/make_icon.py
"""
import pathlib
import struct
import zlib

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE.parent / "assets" / "oblivio.ico"

GOLD = (0xF4, 0xB7, 0x28)
GROUND = (0x0A, 0x0E, 0x14)          # the dashboard's own background
SIZES = (256, 128, 64, 48, 32, 16)
SS = 4                                # supersampling factor


def cubic(p0, c0, c1, p1, n=48):
    """Sample a cubic bezier into points, endpoint excluded."""
    out = []
    for i in range(n):
        t = i / n
        u = 1 - t
        out.append((
            u*u*u*p0[0] + 3*u*u*t*c0[0] + 3*u*t*t*c1[0] + t*t*t*p1[0],
            u*u*u*p0[1] + 3*u*u*t*c0[1] + 3*u*t*t*c1[1] + t*t*t*p1[1]))
    return out


# The mark's outline, in the SVG's own 96x96 coordinate space:
#   M48 8 L80 19 v28 c0 19,-13 32,-32 40 C29 79,16 66,16 47 V19 Z
SHIELD = ([(48, 8), (80, 19), (80, 47)]
          + cubic((80, 47), (80, 66), (67, 79), (48, 87))
          + [(48, 87)]
          + cubic((48, 87), (29, 79), (16, 66), (16, 47))
          + [(16, 47), (16, 19)])

# The crenellated block with its doorway, drawn as two polygons: the second is
# knocked back out to ground so the door reads as an opening, not a panel.
BLOCK = [(33, 44), (39, 44), (39, 37), (45, 37), (45, 44), (51, 44),
         (51, 37), (57, 37), (57, 44), (63, 44), (63, 70), (33, 70)]
DOOR = [(44, 57), (52, 57), (52, 70), (44, 70)]


def centroid(poly):
    return (sum(x for x, _ in poly) / len(poly),
            sum(y for _, y in poly) / len(poly))


def scaled(poly, k):
    cx, cy = centroid(poly)
    return [(cx + (x - cx) * k, cy + (y - cy) * k) for x, y in poly]


def fill(buf, w, poly, colour, scale):
    """Scanline-fill a polygon with the even-odd rule."""
    pts = [(x * scale, y * scale) for x, y in poly]
    ys = [p[1] for p in pts]
    for py in range(max(0, int(min(ys))), min(w, int(max(ys)) + 1)):
        yc = py + 0.5
        xs = []
        for i in range(len(pts)):
            (x1, y1), (x2, y2) = pts[i], pts[(i + 1) % len(pts)]
            if (y1 <= yc < y2) or (y2 <= yc < y1):
                xs.append(x1 + (yc - y1) / (y2 - y1) * (x2 - x1))
        xs.sort()
        for i in range(0, len(xs) - 1, 2):
            for px in range(max(0, int(xs[i])), min(w, int(xs[i + 1]) + 1)):
                buf[py * w + px] = colour


def render(size):
    w = size * SS
    buf = [GROUND] * (w * w)
    s = w / 96.0
    # Outline: fill the shield, then knock a smaller copy back to ground. An
    # inset by scaling about the centroid is an approximation of a true offset
    # curve, and at icon sizes the difference is invisible.
    fill(buf, w, SHIELD, GOLD, s)
    fill(buf, w, scaled(SHIELD, 0.90), GROUND, s)
    fill(buf, w, BLOCK, GOLD, s)
    fill(buf, w, DOOR, GROUND, s)

    # Downsample the supersampled buffer -- this is what softens the edges.
    px = bytearray()
    for y in range(size):
        px.append(0)                                   # PNG filter: none
        for x in range(size):
            r = g = b = 0
            for dy in range(SS):
                for dx in range(SS):
                    c = buf[(y * SS + dy) * w + (x * SS + dx)]
                    r += c[0]; g += c[1]; b += c[2]
            n = SS * SS
            px += bytes((r // n, g // n, b // n, 255))
    return bytes(px)


def png(size, raw):
    def chunk(tag, data):
        c = tag + data
        return (struct.pack(">I", len(data)) + c
                + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9))
            + chunk(b"IEND", b""))


def main():
    images = [png(s, render(s)) for s in SIZES]
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = len(header) + 16 * len(images)
    entries, blob = b"", b""
    for s, data in zip(SIZES, images):
        entries += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32,
                               len(data), offset)
        offset += len(data)
        blob += data
    OUT.write_bytes(header + entries + blob)
    print(f"wrote {OUT}  ({len(header+entries+blob):,} bytes, "
          f"{len(SIZES)} sizes: {', '.join(map(str, SIZES))})")


if __name__ == "__main__":
    main()

"""Render the NullRoute icon at every size the extension and apps need.

The mark is a route line that ends in a null circle: traffic goes in, nothing
comes out. Drawn at 8x and downsampled so small sizes stay crisp.

    python scripts/make_icons.py
"""
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
INK = (27, 35, 51, 255)
ROUTE = (47, 91, 234, 255)
WHITE = (255, 255, 255, 255)


def draw(size: int, rounded: bool = True) -> Image.Image:
    s = size * 8
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    radius = int(s * 0.22) if rounded else 0
    d.rounded_rectangle([0, 0, s - 1, s - 1], radius=radius, fill=INK)
    w = max(int(s * 0.085), 8)
    # incoming route
    y = int(s * 0.5)
    d.line([(int(s * 0.16), y), (int(s * 0.44), y)], fill=ROUTE, width=w)
    d.ellipse([int(s * 0.12), y - w, int(s * 0.12) + 2 * w, y + w], fill=ROUTE)
    # null sink: ring with a slash
    cx, cy, r = int(s * 0.63), y, int(s * 0.2)
    d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=WHITE, width=w)
    off = int(r * 0.72)
    d.line([(cx - off, cy + off), (cx + off, cy - off)], fill=WHITE, width=w)
    return img.resize((size, size), Image.LANCZOS)


def main() -> None:
    ext = ROOT / "extension" / "icons"
    ext.mkdir(parents=True, exist_ok=True)
    for n in (16, 32, 48, 128):
        draw(n).save(ext / f"icon{n}.png")
    # Square, unrounded masters for the mobile apps (the OS applies its own mask).
    assets = ROOT / "assets"
    assets.mkdir(exist_ok=True)
    draw(1024, rounded=False).convert("RGB").save(assets / "icon-1024.png")
    draw(512).save(assets / "icon-512.png")
    print("icons written")


if __name__ == "__main__":
    main()

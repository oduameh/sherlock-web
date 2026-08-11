"""One-off icon generator: magnifying-glass glyph on dark rounded square."""
import math
from PIL import Image, ImageDraw

BG = (13, 17, 23, 255)        # #0d1117
ACCENT = (88, 166, 255, 255)  # #58a6ff

def make(size: int, path: str) -> None:
    img = Image.new("RGBA", (size, size), BG)
    d = ImageDraw.Draw(img)
    # Magnifying glass: ring at ~40% of size, handle to bottom-right.
    cx = cy = size * 0.44
    r = size * 0.26
    w = max(2, int(size * 0.075))  # stroke width
    d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=ACCENT, width=w)
    # handle from ring edge at 45deg to bottom-right
    a = math.radians(45)
    x1 = cx + (r + w * 0.3) * math.cos(a)
    y1 = cy + (r + w * 0.3) * math.sin(a)
    x2 = size * 0.82
    y2 = size * 0.82
    d.line([x1, y1, x2, y2], fill=ACCENT, width=w)
    img.save(path)
    print("wrote", path)

make(192, "static/icons/icon-192.png")
make(512, "static/icons/icon-512.png")
# Launcher icon densities for the Android app (opaque, on the same dark bg).
for dpi, px in [("mdpi", 48), ("hdpi", 72), ("xhdpi", 96), ("xxhdpi", 144), ("xxxhdpi", 192)]:
    make(px, f"android/app/src/main/res/mipmap-{dpi}/ic_launcher.png")

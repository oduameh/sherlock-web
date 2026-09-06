"""Tiny PNG thumbnails for embedding in saved reports.

A saved HTML report used to link each avatar to the subject's host, so
opening the file later fetched the image from there — the analyst's address
and user agent at reading time, the leak the avatar proxy (V11) closed for
the live console. The report now embeds a small ``data:`` thumbnail the
server produced from bytes it fetched through the same proxy path.

Pure: bytes in, data URI (or ``None``) out. Never raises for hostile input —
an undecodable body, an unsupported format or a decompression bomb all yield
``None`` and the report simply shows no picture.
"""

from __future__ import annotations

import base64
import io
import re

THUMB_PX = 56                    # 2× the 28 px avatar the report's CSS shows
MAX_PIXELS = 24_000_000          # decode cap: a 24 MP frame is ~96 MiB of RGBA
DATA_URI_PREFIX = "data:image/png;base64,"
_B64 = re.compile(r"[A-Za-z0-9+/]+={0,2}")


def thumbnail_data_uri(body: bytes, px: int = THUMB_PX) -> str | None:
    """A ``data:image/png;base64,`` URI of ``body`` scaled to fit ``px``×``px``,
    or ``None`` when the bytes are not an image Pillow can decode safely."""
    if not body or px <= 0:
        return None
    try:
        from PIL import Image
    except ImportError:          # pillow is a hard dependency; be honest if not
        return None
    try:
        with Image.open(io.BytesIO(body)) as im:
            w, h = im.size
            if w <= 0 or h <= 0 or w * h > MAX_PIXELS:
                return None
            im.draft(im.mode, (px, px))       # JPEG: decode at reduced scale
            has_alpha = im.mode in ("RGBA", "LA", "PA") or (
                im.mode == "P" and "transparency" in im.info)
            out = im.convert("RGBA" if has_alpha else "RGB")
        out.thumbnail((px, px))
        buf = io.BytesIO()
        out.save(buf, format="PNG", optimize=True)
    except Exception:            # DecompressionBombError, UnidentifiedImageError, truncated data…
        return None
    return DATA_URI_PREFIX + base64.b64encode(buf.getvalue()).decode("ascii")


def is_thumbnail_uri(value: object) -> bool:
    """True only for a URI this module produced (the renderer's allow-list):
    the PNG prefix followed by base64 alphabet — nothing that could close an
    attribute or open a tag can pass."""
    return isinstance(value, str) and value.startswith(DATA_URI_PREFIX) \
        and _B64.fullmatch(value[len(DATA_URI_PREFIX):]) is not None

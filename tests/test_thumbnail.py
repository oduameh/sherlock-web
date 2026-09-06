"""recon.thumbnail: server-made data: thumbnails for saved reports (V11)."""

import base64
import io

from PIL import Image

from recon import thumbnail
from recon.thumbnail import DATA_URI_PREFIX, is_thumbnail_uri, thumbnail_data_uri


def _png(size=(300, 200), mode="RGB", color=(200, 30, 30)):
    buf = io.BytesIO()
    Image.new(mode, size, color).save(buf, format="PNG")
    return buf.getvalue()


def _jpeg(size=(640, 480)):
    buf = io.BytesIO()
    Image.new("RGB", size, (10, 120, 220)).save(buf, format="JPEG", quality=85)
    return buf.getvalue()


def _decode(uri):
    assert uri.startswith(DATA_URI_PREFIX)
    return Image.open(io.BytesIO(base64.b64decode(uri[len(DATA_URI_PREFIX):])))


def test_scales_to_fit_and_keeps_the_aspect_ratio():
    im = _decode(thumbnail_data_uri(_jpeg((640, 480))))
    assert im.format == "PNG" and im.size == (56, 42)
    im = _decode(thumbnail_data_uri(_png((100, 400))))
    assert im.size == (14, 56)


def test_small_images_are_not_upscaled():
    assert _decode(thumbnail_data_uri(_png((20, 10)))).size == (20, 10)


def test_alpha_is_kept_and_opaque_images_stay_rgb():
    assert _decode(thumbnail_data_uri(_png(mode="RGBA", color=(1, 2, 3, 128)))).mode == "RGBA"
    assert _decode(thumbnail_data_uri(_png())).mode == "RGB"


def test_output_is_small():
    assert len(thumbnail_data_uri(_jpeg((2000, 2000)))) < 4000


def test_undecodable_bytes_yield_none_not_an_exception():
    assert thumbnail_data_uri(b"") is None
    assert thumbnail_data_uri(b"\x89PNG\r\n\x1a\n" + bytes(range(256))) is None
    assert thumbnail_data_uri(b"<svg xmlns='http://www.w3.org/2000/svg'/>") is None
    assert thumbnail_data_uri(_png()[:40]) is None          # truncated
    assert thumbnail_data_uri(_png(), px=0) is None


def test_decompression_bombs_are_refused_before_decoding(monkeypatch):
    # A 1-bit 6000×5000 PNG is a few KiB on the wire and 30 MP decoded.
    buf = io.BytesIO()
    Image.new("1", (6000, 5000)).save(buf, format="PNG")
    assert buf.tell() < 200_000
    assert thumbnail.MAX_PIXELS < 6000 * 5000
    assert thumbnail_data_uri(buf.getvalue()) is None
    monkeypatch.setattr(thumbnail, "MAX_PIXELS", 40_000_000)
    assert thumbnail_data_uri(buf.getvalue()) is not None


def test_is_thumbnail_uri_accepts_only_what_this_module_makes():
    assert is_thumbnail_uri(thumbnail_data_uri(_png()))
    for bad in (None, "", "https://cdn.example/a.png", "data:image/svg+xml,evil",
                "data:image/png;base64,é", "javascript:alert(1)",
                "DATA:IMAGE/PNG;BASE64,AAAA", b"data:image/png;base64,AAAA"):
        assert not is_thumbnail_uri(bad), bad

"""Visible signature appearance: style and the text shown in it (also used for the GUI preview)."""

import os
import sys
import time
from functools import lru_cache
from pathlib import Path

from fontTools.ttLib import TTFont
from pyhanko.pdf_utils.font.opentype import GlyphAccumulatorFactory
from pyhanko.pdf_utils.layout import AxisAlignment, Margins, SimpleBoxLayoutRule
from pyhanko.pdf_utils.text import TextBoxStyle
from pyhanko.stamp import TextStampStyle

DEFAULT_TEXT = "Digitally signed by\n%(signer)s\nDate: %(ts)s"
TS_FORMAT = "%d %b %Y, %H:%M:%S %Z"
FONT_SIZE = 9
FONT_FILE = Path(__file__).parent / "fonts" / "NotoSans-Regular.ttf"  # bundled (SIL OFL 1.1, fonts/OFL.txt): identical stamp on every machine
FALLBACK_WIDTH = 0.65  # em per character, conservative, when the bundled font is unusable and pyHanko's built-in font is used


@lru_cache(maxsize=1)
def _font():
    """(path, TTFont) of the bundled font, or (None, None) when it is missing or unreadable (pyHanko's standard font is used then)."""
    try:
        return str(FONT_FILE), TTFont(FONT_FILE)
    except Exception as e:  # missing, unreadable or corrupt: never crash a signing for it
        if os.environ.get("DSC_DEBUG"):
            print(f"tda-dsc-signer: bundled stamp font unusable ({e}); using pyHanko's standard font", file=sys.stderr)
        return None, None


def font_path():
    return _font()[0]


def _text_style(size, **kw):
    path = font_path()
    font = {"font": GlyphAccumulatorFactory(path)} if path else {}
    return TextBoxStyle(font_size=size, **font, **kw)


def stamp_name(name):
    """The signer name as drawn in the stamp: characters the font lacks become '?' (stamp only; the signature and certificate keep
    the real name). Noto Sans covers Latin, Greek and Cyrillic, not Devanagari or CJK. Returns (text, changed)."""
    _p, font = _font()
    has = font.getBestCmap().__contains__ if font else (lambda c: c < 256)
    out = "".join(c if c.isspace() or has(ord(c)) else "?" for c in name)
    return out, out != name


def render_text(template, signer, when=None):
    return template % {"signer": signer, "ts": time.strftime(TS_FORMAT, when or time.localtime())}


def make_style(text=DEFAULT_TEXT):
    return TextStampStyle(
        stamp_text=text,
        timestamp_format=TS_FORMAT,
        border_width=1,
        text_box_style=_text_style(FONT_SIZE),
    )


COMPACT_H, COMPACT_W = 40, 120  # a field smaller than this cannot hold the normal three-line stamp
MIN_FONT, PAD = 4, 2  # pyHanko's layout needs integer sizes


def _measure():
    _p, f = _font()
    if f is None:
        return lambda s, size: len(s) * FALLBACK_WIDTH * size
    cmap, hmtx, upm = f.getBestCmap(), f["hmtx"], f["head"].unitsPerEm
    return lambda s, size: sum(hmtx[cmap.get(ord(c), ".notdef")][0] for c in s) * size / upm


def _wrap(line, width, size, measure):
    """Greedy word wrap; a word wider than the line is cut by characters."""
    out, cur = [], ""
    for word in line.split():
        while measure(word, size) > width and len(word) > 1:
            k = next((i for i in range(1, len(word)) if measure(word[: i + 1], size) > width), len(word) - 1)
            if cur:
                out.append(cur)
                cur = ""
            out.append(word[: max(k, 1)])
            word = word[max(k, 1) :]
        trial = f"{cur} {word}".strip()
        if cur and measure(trial, size) > width:
            out.append(cur)
            trial = word
        cur = trial
    return [*out, cur] if cur else out


def _fit(variants, w, h, measure):
    """First variant (richest first) that fits at some size >= MIN_FONT; integer sizes from 8 down."""
    width, height = w - 2 * PAD - 2, h - 2 * PAD - 2
    for lines in variants:
        size = 8
        while size >= MIN_FONT:
            wrapped = [x for ln in lines for x in _wrap(ln, width, size, measure)]
            if len(wrapped) * (size + 1) <= height and all(measure(x, size) <= width for x in wrapped):
                return wrapped, size
            size -= 1
    return None


def make_field_style(stamp_text, signer, rect, when=None):
    """Appearance for an existing field: the normal stamp when the rect can hold it, else a compact one that never overflows."""
    w, h = abs(rect[2] - rect[0]), abs(rect[3] - rect[1])
    if h >= COMPACT_H and w >= COMPACT_W:
        return make_style(stamp_text)
    measure = _measure()
    day = time.strftime("%d %b %Y", when or time.localtime())
    name = stamp_name(signer)[0]
    variants = [["Digitally signed by", name, day], ["Digitally signed by", name], [name]]
    fit = _fit(variants, w, h, measure)
    while fit is None and len(name) > 1:  # last resort: ellipsize the name until it fits
        name = name[:-2] + "…" if len(name) > 2 else name[:-1]
        fit = _fit([[name]], w, h, measure)
    lines, size = fit or ([name[:1]], MIN_FONT)
    return TextStampStyle(
        stamp_text="\n".join(lines).replace("%", "%%"),
        border_width=1,
        text_box_style=_text_style(size, leading=size + 1),
        inner_content_layout=SimpleBoxLayoutRule(
            x_align=AxisAlignment.ALIGN_MIN, y_align=AxisAlignment.ALIGN_MID, margins=Margins(PAD, PAD, PAD, PAD)
        ),
    )

"""Cairo drawing of a placed box: translucent rectangle, corner handles, numbered badge, signer chip and stamp preview."""

from .. import geometry

LINE_GAP, MIN_FONT_PX = 1.2, 5.0
HANDLE_PX = 9  # grab radius around a corner, in pixels (converted by the caller)


def _badge(cr, x, y, n, active):
    cr.set_source_rgb(0.0, 0.45, 0.85) if active else cr.set_source_rgb(0.35, 0.4, 0.5)
    cr.arc(x, y, 8, 0, 6.2832)
    cr.fill()
    cr.set_source_rgb(1, 1, 1)
    cr.select_font_face("sans-serif")
    cr.set_font_size(10)
    ext = cr.text_extents(str(n))
    cr.move_to(x - ext.width / 2 - ext.x_bearing, y + ext.height / 2)
    cr.show_text(str(n))


def draw(cr, box, page_h, scale, text, number=1, active=True, chip=""):
    x, y, w, h = geometry.points_to_px(box, page_h, scale)
    cr.set_source_rgba(0, 0.67, 1, 0.15 if active else 0.08)
    cr.rectangle(x, y, w, h)
    cr.fill()
    cr.set_source_rgb(0, 0.67, 1) if active else cr.set_source_rgb(0.4, 0.5, 0.6)
    cr.set_line_width(1.5 if active else 1)
    cr.rectangle(x, y, w, h)
    cr.stroke()
    if active:
        for cx, cy in ((x, y), (x + w, y), (x, y + h), (x + w, y + h)):
            cr.rectangle(cx - 3, cy - 3, 6, 6)
            cr.fill()
    cr.save()
    cr.rectangle(x, y, w, h)
    cr.clip()
    cr.set_source_rgb(0.05, 0.1, 0.3)
    cr.select_font_face("sans-serif")
    lines = text.splitlines() or [""]
    left = 14 + 3 * scale
    fs = min(9 * scale, (h - 4) / (len(lines) * LINE_GAP))  # shrink so every line fits the box height...
    cr.set_font_size(max(fs, MIN_FONT_PX))
    widest = max(cr.text_extents(ln).x_advance for ln in lines)
    if widest > w - left - 2 > 0:  # ...and its width
        fs = min(fs, fs * (w - left - 2) / widest)
    fs = max(fs, MIN_FONT_PX)
    cr.set_font_size(fs)
    for i, line in enumerate(lines):
        cr.move_to(x + left, y + 2 + fs + i * fs * LINE_GAP)
        cr.show_text(line)
    cr.restore()
    _badge(cr, x + 10, y + 10, number, active)
    if chip:  # signer chip under the box so it never covers the stamp text
        cr.set_font_size(10)
        ext = cr.text_extents(chip)
        cr.set_source_rgba(0.1, 0.15, 0.25, 0.85)
        cr.rectangle(x, y + h + 2, ext.width + 8, 14)
        cr.fill()
        cr.set_source_rgb(1, 1, 1)
        cr.move_to(x + 4, y + h + 13)
        cr.show_text(chip)


MIN_FIELD_PX = 14  # a 50x20 pt form field is tiny: badge and hit area never shrink below this on screen


def field_px(rect, page_h, scale):
    """On-screen (x, y, w, h) of a form field, enlarged around its centre to at least MIN_FIELD_PX."""
    x, y, w, h = geometry.points_to_px(rect, page_h, scale)
    w2, h2 = max(w, MIN_FIELD_PX), max(h, MIN_FIELD_PX)
    return x - (w2 - w) / 2, y - (h2 - h) / 2, w2, h2


def draw_field(cr, rect, page_h, scale, number, active):
    """Dashed accent rectangle + numbered badge for an EMPTY form field (not draggable)."""
    x, y, w, h = field_px(rect, page_h, scale)
    cr.set_source_rgba(0.18, 0.44, 0.93, 0.22 if active else 0.1)
    cr.rectangle(x, y, w, h)
    cr.fill()
    cr.set_source_rgb(0.18, 0.44, 0.93)
    cr.set_line_width(2 if active else 1.5)
    cr.set_dash([5, 3])
    cr.rectangle(x, y, w, h)
    cr.stroke()
    cr.set_dash([])
    _badge(cr, x - 2, y - 2, number, True)

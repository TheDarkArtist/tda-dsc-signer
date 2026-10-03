"""Pure box maths. PDF points: origin bottom-left. Widget pixels: origin top-left. scale = pixels per point."""

MIN_W, MIN_H = 20, 10  # smallest box worth signing, in points


def points_to_px(box, page_h, scale):
    """(x1,y1,x2,y2) points -> (x,y,w,h) pixels."""
    x1, y1, x2, y2 = box
    return x1 * scale, (page_h - y2) * scale, (x2 - x1) * scale, (y2 - y1) * scale


def px_to_points(x, y, w, h, page_h, scale):
    """(x,y,w,h) pixels (w,h may be negative: drag direction) -> normalised (x1,y1,x2,y2) points."""
    xa, xb = sorted((x / scale, (x + w) / scale))
    ya, yb = sorted((page_h - (y + h) / scale, page_h - y / scale))
    return xa, ya, xb, yb


def clamp_box(box, page_w, page_h):
    x1, y1, x2, y2 = box
    return max(0, min(x1, page_w)), max(0, min(y1, page_h)), max(0, min(x2, page_w)), max(0, min(y2, page_h))


def is_valid(box):
    return box is not None and box[2] - box[0] > MIN_W and box[3] - box[1] > MIN_H


def parse_box(text):
    """'x1,y1,x2,y2' -> ints, validated and ordered."""
    try:
        x1, y1, x2, y2 = (int(float(v)) for v in text.split(","))
    except ValueError:
        raise ValueError(f"box must be X1,Y1,X2,Y2 numbers, got {text!r}") from None
    if x2 <= x1 or y2 <= y1:
        raise ValueError(f"box {text!r} has no area: need X2>X1 and Y2>Y1")
    return x1, y1, x2, y2

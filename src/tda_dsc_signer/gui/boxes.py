"""Signature boxes (pure, no GTK): any number, each with a page, a PDF-point rectangle and the signer key it belongs to.

Coordinates are PDF points, origin bottom-left. The badge number of a box is its position in `items` (signing order).
"""

from dataclasses import dataclass

from .. import geometry


@dataclass
class Placed:
    page: int  # 0-based
    box: tuple  # (x1, y1, x2, y2)
    signer: str = ""  # TokenCert.key: whose token signs this box (set at creation, changed only by assign)
    cert: object = None  # TokenCert snapshot taken with the signer: display name even after the token is unplugged

    @property
    def valid(self):
        return geometry.is_valid(self.box)


def _hit(p, page, pt, tol):
    """('resize', fixed_corner, grabbed_corner) | ('move',) | None for a point on `page`."""
    if p.page != page:
        return None
    x1, y1, x2, y2 = p.box
    for cx, cy, fx, fy in ((x1, y1, x2, y2), (x1, y2, x2, y1), (x2, y1, x1, y2), (x2, y2, x1, y1)):
        if abs(pt[0] - cx) <= tol and abs(pt[1] - cy) <= tol:
            return ("resize", (fx, fy), (cx, cy))
    return ("move",) if x1 <= pt[0] <= x2 and y1 <= pt[1] <= y2 else None


class Boxes:
    def __init__(self):
        self.items, self.active, self.locked = [], -1, False
        self._mode, self._fixed, self._origin, self._start, self._size = "", None, None, None, (0, 0)

    # -- queries ------------------------------------------------------------
    def __len__(self):
        return len(self.items)

    @property
    def current(self):
        return self.items[self.active] if 0 <= self.active < len(self.items) else None

    @property
    def all_valid(self):
        return bool(self.items) and all(p.valid for p in self.items)

    def at(self, page, pt, tol):
        """Index of the topmost box hit at pt, or -1."""
        for i in reversed(range(len(self.items))):
            if _hit(self.items[i], page, pt, tol):
                return i
        return -1

    # -- editing ----------------------------------------------------------------
    def add(self, page, box, signer="", cert=None):
        self.items.append(Placed(page, tuple(box), signer, cert))
        self.active = len(self.items) - 1

    def clear(self):
        self.items, self.active, self._mode = [], -1, ""

    def remove(self, i):
        if 0 <= i < len(self.items):
            del self.items[i]
            if i < self.active:
                self.active -= 1  # keep pointing at the same box
            self.active = min(self.active, len(self.items) - 1) if self.items else -1

    def move_order(self, i, delta):
        j = i + delta
        if 0 <= i < len(self.items) and 0 <= j < len(self.items):
            self.items[i], self.items[j] = self.items[j], self.items[i]
            if self.active in (i, j):
                self.active = j if self.active == i else i

    def assign(self, i, signer, cert=None):
        """The one explicit way to change a placed box's signer."""
        if 0 <= i < len(self.items):
            self.items[i].signer, self.items[i].cert = signer, cert

    # -- dragging (one gesture = one box) ----------------------------------------------
    def begin(self, page, pt, page_size, tol, signer="", cert=None):
        """Grab a corner (resize) or the inside (move) of the topmost box under the pointer, else start a new box."""
        self._size, self._start = page_size, pt
        if self.locked:
            self._mode = ""
            return
        i = self.at(page, pt, tol)
        if i >= 0:
            self.active = i
            h = _hit(self.items[i], page, pt, tol)
            if h[0] == "resize":
                self._mode, self._fixed, self._start = "resize", h[1], h[2]
            else:
                self._mode, self._origin = "move", self.items[i].box
            return
        self.add(page, (*pt, *pt), signer, cert)
        self._mode, self._fixed = "new", pt

    def update(self, dx, dy):
        """Drag offset in points (dy positive = up)."""
        p = self.current
        if p is None or not self._mode:
            return
        w, h = self._size
        if self._mode == "move":
            x1, y1, x2, y2 = self._origin
            dx, dy = max(-x1, min(dx, w - x2)), max(-y1, min(dy, h - y2))
            p.box = (x1 + dx, y1 + dy, x2 + dx, y2 + dy)
        else:
            fx, fy = self._fixed
            x, y = max(0, min(self._start[0] + dx, w)), max(0, min(self._start[1] + dy, h))
            p.box = (min(fx, x), min(fy, y), max(fx, x), max(fy, y))

    def end(self):
        """A stray click that made a tiny new box removes it."""
        p = self.current
        if self._mode == "new" and p is not None and not p.valid:
            self.remove(self.active)
        self._mode = ""

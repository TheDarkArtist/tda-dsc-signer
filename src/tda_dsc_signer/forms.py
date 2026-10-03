"""Signature fields already present in a PDF (MCA forms ship empty, PAN-named ones). Never touches PKCS#11."""

import re
from dataclasses import dataclass

from pyhanko.pdf_utils.misc import PdfError, PdfReadError
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.fields import enumerate_sig_fields

PAN_RE = re.compile(r"_([A-Z]{5}[0-9]{4}[A-Z])$")
LOCKED_FLAG = 128  # annotation /F bit 8 ("Locked")
MAX_PAGES = 100000  # a hostile page tree must not hang the walk


@dataclass(frozen=True)
class FormField:
    name: str
    page: int  # 1-based; 0 when the widget is on no page
    rect: tuple  # (x1, y1, x2, y2) PDF points, bottom-left origin (same convention as boxes)
    signed: bool
    locked: bool
    pan: str | None
    seed: dict

    @property
    def pan_masked(self):
        return f"{self.pan[:4]}…{self.pan[-5:]}" if self.pan else None


def pan_from_name(name):
    m = PAN_RE.search(str(name))
    return m.group(1) if m else None


def _pages(r):
    """Flat list of page dictionaries (indirect objects resolved), document order."""
    out, todo = [], [r.root["/Pages"]]
    while todo and len(out) < MAX_PAGES:
        node = todo.pop()
        node = node.get_object() if hasattr(node, "get_object") else node
        kids = node.get("/Kids")
        if kids is None:
            out.append(node)
        else:
            todo.extend(reversed([k for k in kids]))
    return out


def _ref_id(o):
    ref = getattr(o, "reference", None) or o
    return (getattr(ref, "idnum", None), getattr(ref, "generation", None)) if hasattr(ref, "idnum") else None


def _page_of(widget_ref, widget, pages):
    p = widget.get("/P")
    if p is not None:
        pid = _ref_id(p)
        for i, pg in enumerate(pages, 1):
            if pid and _ref_id(pg) == pid:
                return i
    wid = _ref_id(widget_ref)
    for i, pg in enumerate(pages, 1):
        for a in pg.get("/Annots") or []:
            if (wid and _ref_id(a) == wid) or a.get_object() is widget:
                return i
    return 0


def _seed(widget):
    out = {}
    sv = widget.get("/SV")
    if sv is not None:
        sv = sv.get_object()
        for k, label in (("/Filter", "Filter"), ("/SubFilter", "SubFilter"), ("/DigestMethod", "DigestMethod"), ("/Ff", "Flags")):
            if k in sv:
                v = sv[k]
                out[label] = [str(x) for x in v] if isinstance(v, list) else (int(v) if k == "/Ff" else str(v))
    lock = widget.get("/Lock")
    if lock is not None:
        lock = lock.get_object()
        out["Lock"] = {"Action": str(lock.get("/Action", "")), "Fields": [str(x) for x in lock.get("/Fields", [])]}
    return out


def _reader(f):
    try:
        return PdfFileReader(f, strict=True)
    except PdfReadError:  # same strict -> lenient fallback as signing.preflight
        f.seek(0)
        return PdfFileReader(f, strict=False)


def find_signature_fields(path):
    """ALL signature fields (signed or not) in document order of the AcroForm /Fields tree."""
    with open(path, "rb") as f:
        try:
            r = _reader(f)
            pages = _pages(r)
            res = []
            for name, value, ref in enumerate_sig_fields(r, filled_status=None):
                w = ref.get_object()
                rect = tuple(round(float(x), 2) for x in w.get("/Rect", (0, 0, 0, 0)))
                res.append(
                    FormField(
                        name=str(name),
                        page=_page_of(ref, w, pages),
                        rect=rect,
                        signed=value is not None,
                        locked=bool(int(w.get("/F", 0)) & LOCKED_FLAG),
                        pan=pan_from_name(name),
                        seed=_seed(w),
                    )
                )
        except PdfError as e:
            raise ValueError(f"not a readable PDF: {e}") from None
    return res

"""GTK-free logic of the MCA form-field mode: mode auto-detect, match -> row state, steps, result summary."""

from dataclasses import dataclass

from .. import pan as panmod
from .signrun import Step

NONE_TEXT = "No attached token matches this PAN: someone else must sign"


def detect_mode(n_empty, default="auto", override=None):
    """override (the user's per-file choice) > config default_mode > auto (>= 1 EMPTY signature field -> mca)."""
    if override in ("mca", "general"):
        return override
    if default in ("mca", "general"):
        return default
    return "mca" if n_empty else "general"


def shown(f, name=None):
    """Field name with its PAN masked: sigfield1_ABCDE1234F -> sigfield1_ABCD…1234F."""
    name = name or f.name
    return name.replace(f.pan, f.pan_masked) if f.pan else name


@dataclass
class Row:
    n: int
    field: object
    kind: str  # match | unknown | none | gone
    cert: object  # TokenCert | None
    cands: list
    checked: bool
    enabled: bool  # the checkbox is usable
    text: str  # the signer line

    @property
    def label(self):
        return f"Page {self.field.page} · {self.field.pan_masked or self.field.name}"


def build_rows(fields, certs, choice, current=None):
    """One Row per EMPTY field. choice: {field name: {checked, signer, cn}} owned by the caller (survives rescans)."""
    empty = [f for f in fields if not f.signed]
    matches = panmod.match(empty, certs)
    live = {c.key: c for c in certs}
    rows = []
    for n, f in enumerate(empty, 1):
        m, ch = matches[f.name], choice.setdefault(f.name, {})
        cands = panmod.candidates(f, certs)
        ckeys = [c.key for c in cands]
        sk, kind = ch.get("signer"), m.status
        if kind == "match":
            sk = sk if sk in ckeys else m.cert_key
        elif sk and sk not in live:
            kind = "gone"  # the token it was matched/assigned to is unplugged: remembered by key, so a replug restores it
        elif kind == "unknown":
            sk = sk if sk in ckeys else (current.key if current and current.key in ckeys else (ckeys[0] if ckeys else None))
        cert = live.get(sk) if kind != "gone" else None
        if cert:
            ch["signer"], ch["cn"] = sk, cert.cn
        text = {
            "match": f"{cert.cn} · PAN matches" if cert else "",
            "unknown": f"{cert.cn} · PAN cannot be checked" if cert else "Choose a token",
            "none": NONE_TEXT,
            "gone": f"{ch.get('cn', '')}: token removed",
        }[kind]
        if "checked" not in ch and kind in ("match", "unknown"):
            ch["checked"] = kind == "match"  # the default is fixed at first sight, so a later unplug keeps the row checked
        checked = ch.get("checked", False)
        enabled = kind != "none"
        rows.append(Row(n, f, kind, cert, cands, checked and enabled, enabled, text))
    return rows


def checked_rows(rows):
    return [r for r in rows if r.checked]


def steps_for(rows):
    """One Step per CHECKED field (page/box are unused by the backend when `field` is given)."""
    return [Step(i, r.field.page, tuple(round(v) for v in r.field.rect), r.cert, r.field.name) for i, r in enumerate(checked_rows(rows), 1)]


def problem(rows):
    """First reason a checked row cannot be signed, or None."""
    for r in checked_rows(rows):
        if r.kind == "gone":
            return f"{shown(r.field)}: its token is not connected ({r.text.split(':')[0]})."
        if r.cert is None:
            return f"{shown(r.field)} has no signer: pick one in the list."
        if r.field.pan and panmod.cert_matches_pan(r.cert, r.field.pan) is False:
            return f"{shown(r.field)} must be signed by the holder of that PAN; {r.cert.cn}'s certificate does not match."
    return None


def summary(signed_rows, all_rows):
    done = {r.field.name for r in signed_rows}
    left = [r for r in all_rows if r.field.name not in done]
    s = f"{len(signed_rows)} of {len(all_rows)} fields signed"
    if left:
        s += "; " + ", ".join(shown(r.field) for r in left) + (" needs its signer" if len(left) == 1 else " need their signers")
    return s

"""GTK-free GUI logic: labels, scaling, page lookup, sign preconditions, error wording. Unit-tested without a display."""

import datetime
import os
import sys

import pkcs11

from ..errors import HostTimeout
from ..safety import FinalTryNeedsConfirm, TokenLocked

MARGIN = 6  # px around the page column
GAP = 6  # px between pages
ZOOM_MIN, ZOOM_MAX, ZOOM_STEP = 0.4, 4.0, 1.1


def debug(msg):
    """Opt-in diagnostics on stderr (env DSC_DEBUG). Callers must never pass a PIN."""
    if os.environ.get("DSC_DEBUG"):
        print(f"[dsc] {msg}", file=sys.stderr, flush=True)


def signer_label(cert):
    return f"{cert.cn} · {cert.org}" if cert.org else cert.cn


def signer_tooltip(cert):
    lines = [f"{cert.cn} ({cert.org})", f"token: {cert.token}", f"serial: {cert.serial}", f"valid until {cert.end}"]
    if cert.expired():
        lines.append("EXPIRED: cannot sign with this certificate")
    if cert.pin.warning():
        lines.append(cert.pin.warning())
    return "\n".join(lines)


def index_for(certs, key):
    """Index of the cert whose key (serial/cert id) matches; 0 when unknown so the dropdown always has a selection."""
    keys = [c.key for c in certs]
    return keys.index(key) if key in keys else 0


def clamp_zoom(z):
    return max(ZOOM_MIN, min(ZOOM_MAX, z))


def fit_scale(avail_width, page_width, zoom=1.0):
    """Pixels per PDF point so the page fills `avail_width` (minus margins) at zoom 1.0."""
    return max(0.05, (avail_width - 2 * MARGIN) / page_width) * zoom


def page_at(offset, heights, gap=GAP, margin=MARGIN):
    """Page index shown at vertical `offset` (pixels from the top of the scrolled content). Clamped to the document."""
    y = margin
    for i, h in enumerate(heights):
        y += h + gap
        if offset < y - gap / 2:
            return i
    return max(0, len(heights) - 1)


def can_sign(has_cert, box_valid, has_doc, busy):
    return bool(has_cert and box_valid and has_doc and not busy)


def describe_error(exc):
    """(kind, text) for a failed sign. kinds: pin, recent ('Try anyway'), fatal, timeout, confirm, other."""
    if type(exc).__name__ == "RecentWrongPin":  # safety.RecentWrongPin (lockout memory); matched by name so the GUI runs without it
        return "recent", f"{exc}"
    if type(exc).__name__ in ("PanMismatch", "FieldAlreadySigned"):  # core's typed field errors: args[0] is the user message
        return "field", str(exc.args[0])
    if isinstance(exc, pkcs11.PinIncorrect):
        return "pin", "Wrong PIN. Nothing else was tried; the token counts failed attempts."
    if isinstance(exc, pkcs11.NoSuchToken):
        return "gone", "The token was removed while signing. Reinsert it and start again; completed signatures were kept."
    if isinstance(exc, (pkcs11.PinLocked, TokenLocked)):
        return "fatal", "The token's PIN is locked. It has to be unblocked by the issuing CA."
    if isinstance(exc, FinalTryNeedsConfirm):
        return "confirm", "Only one PIN try is left. Tick the confirmation box to continue."
    if isinstance(exc, HostTimeout):
        return "timeout", (
            "The token did not answer in time. The login may or may not have happened and nothing was resent: "
            "check the token, then try again deliberately."
        )
    return "other", f"{type(exc).__name__}: {exc}"


def pin_prompt_needed(cert, remembered):
    """The PIN popover is skipped only for a remembered PIN on a PIN-based token that is not on its final try."""
    return cert.pin.protected_auth or cert.pin.final_try or cert.key not in remembered


def scan_problem(errors):
    """Most important thing wrong with the last scan, or None. errors: {module path or 'usb': exception} from Backend.errors().

    Returns (kind, note, tip, level, full): kind busy | mismatch | module; note = short strip text, full = sentence for the toast.
    Classes are matched by name (errors.DriverBusy / errors.TokenCountMismatch live in core): works with older or newer cores.
    """
    if not errors:
        return None
    by = {}
    for mod, e in errors.items():
        by.setdefault(type(e).__name__, (mod, e))
    if "DriverBusy" in by:
        mod, e = by["DriverBusy"]
        pid = getattr(e, "holder_pid", None)
        who = f" (pid {pid})" if pid else ""
        full = f"Token driver is in use by another tda-dsc-signer{who}. Close it, then Refresh."
        return "busy", f"driver busy{f' · pid {pid}' if pid else ''}", f"{full}\n{e}\nmodule: {getattr(e, 'module', mod)}", "warn", full
    if "TokenCountMismatch" in by:
        mod, e = by["TokenCountMismatch"]
        found, expected = getattr(e, "found", "?"), getattr(e, "expected", "?")
        full = f"found {found} of {expected} token devices: Refresh"
        return "mismatch", full, f"{full}\n{e}", "warn", full
    lines = "\n".join(f"{m}: {type(e).__name__}: {e}" for m, e in errors.items())
    return "module", "module error", lines, "error", "module error: " + lines.splitlines()[0]


# -- v3 additions: layout, token status, file card, saved-PIN flow ---------------------------------
TWO_PANE_MIN = 900  # window width (px) from which the two-pane layout is used
EXPIRY_WARN_DAYS = 30
MCA_LIMIT = 2 * 1024 * 1024


def layout_for(width):
    return "two" if width >= TWO_PANE_MIN else "strip"


def valid_till(cert):
    try:
        return datetime.date.fromisoformat(cert.end).strftime("%-d %b %Y")
    except ValueError:
        return cert.end


def model_text(cert):
    """The token's own label (cert.token); no friendly-name table, no manufacturer/model."""
    return cert.token


def too_big(path):
    return bool(path) and os.path.getsize(path) > MCA_LIMIT


def token_status(cert, today=None):
    """(level, text) for a token's dot: ok (green) | warn (yellow) | err (red)."""
    if cert is None:
        return "err", "No token selected"
    if cert.expired():
        return "err", f"Certificate expired on {cert.end}"
    if cert.pin.locked:
        return "err", "PIN is locked"
    if cert.pin.final_try:
        return "warn", "Final PIN try left"
    if cert.pin.count_low:
        return "warn", "PIN retry count is low"
    try:
        left = (datetime.date.fromisoformat(cert.end) - (today or datetime.date.today())).days
    except ValueError:
        left = 10**6
    if left <= EXPIRY_WARN_DAYS:
        return "warn", f"Certificate expires in {left} days"
    return "ok", "Ready to sign"


def scan_status(scanning, driver_busy, mismatch, has_certs):
    """Overrides for the dot when the scan itself is the news: (level, text) or None."""
    if scanning:
        return "warn", "Scanning for tokens..."
    if driver_busy:
        return "warn", "Token driver is busy"
    if mismatch:
        return "warn", "Not every token device was found"
    if not has_certs:
        return "err", "No token found"
    return None


def saved_pin_usable(pins, cert):
    """The saved PIN to use without a popover, or None. Never for a token whose flags call for a deliberate look."""
    if pins is None or cert.pin.protected_auth or cert.pin.final_try or cert.pin.count_low or cert.pin.locked:
        return None
    try:
        return pins.saved_pin(cert.serial)
    except Exception as e:  # noqa: BLE001 - a broken/locked keyring means "ask", never a run that dies half-way
        debug(f"saved PIN lookup failed for {cert.serial}: {type(e).__name__}: {e}")
        return None


def pin_row(pins, cert, status=None):
    """Settings row facts for one token. status: pins.status() (pass it in: it may touch D-Bus)."""
    ok = bool(status and status.get("available"))
    return {
        "mode": pins.mode(cert.serial) if pins else "ask",
        "saved": bool(pins and pins.has_saved(cert.serial)),
        "can_session": bool(pins) and not cert.pin.protected_auth,
        "can_keyring": bool(pins) and ok and not cert.pin.protected_auth,
        "can_pin": bool(pins) and not cert.pin.protected_auth,
    }


SAVED_WRONG = "Saved PIN was wrong and has been removed: set it again in Settings."

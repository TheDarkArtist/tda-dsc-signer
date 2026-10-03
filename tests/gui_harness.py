"""GUI under test with a FAKE Backend (no hardware, no real PIN) that dumps its state as JSON for tests/gui_drive.py.

    DISPLAY=<xvfb> python tests/gui_harness.py OUT_DIR WIDTH HEIGHT [file.pdf]

Fake PIN: only 'right-pin' works; anything else raises PinIncorrect (counted). Create OUT_DIR/plug to simulate inserting a token.
"""

import json
import os
import sys
import time

if os.environ.get("DISPLAY", ":0") == ":0":
    sys.exit("refusing to run against DISPLAY=:0 (the real display)")
sys.path.insert(0, os.path.dirname(__file__))
out_dir, width, height = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
pdf = sys.argv[4] if len(sys.argv) > 4 else None
import isolate  # noqa: E402

isolate.isolate()  # never touch the real config

import gi  # noqa: E402

gi.require_version("Gtk", "4.0")
import conftest  # noqa: E402
import pkcs11  # noqa: E402
from asn1crypto import keys as akeys  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from gi.repository import Gio, GLib, Gtk  # noqa: E402
from pkcs11 import Mechanism  # noqa: E402
from pyhanko.sign import signers  # noqa: E402
from pyhanko_certvalidator.registry import SimpleCertificateStore  # noqa: E402

from tda_dsc_signer import config, signing, tokens, verify  # noqa: E402
from tda_dsc_signer.backend import Backend  # noqa: E402
from tda_dsc_signer.errors import HostTimeout  # noqa: E402
from tda_dsc_signer.gui import app as appmod  # noqa: E402
from tda_dsc_signer.gui.app import App  # noqa: E402
from tda_dsc_signer.safety import PinState  # noqa: E402

root, rk = conftest.make_cert("Test Root", ca=True, ku=conftest.ku(key_cert_sign=True))
sub, sk = conftest.make_cert("Test Sub CA", root, rk, ca=True, ku=conftest.ku(key_cert_sign=True))
leaf, lk = conftest.make_cert("Jane Doe", sub, sk, ku=conftest.ku(digital_signature=True, content_commitment=True))
CHAIN = (conftest.der(sub), conftest.der(root))


def cert(name, serial, end="2099-01-01", pin=None):
    return tokens.TokenCert(
        "fake.so", 0, f"Token {serial}", serial, "L", conftest.der(leaf), name, "Fake Org Pvt Ltd", end, CHAIN, "01", pin or PinState()
    )


CERTS = [cert("Jane Doe", "S1"), cert("Old Signer", "S2", end="2020-01-01")]
PLUGGED = cert("Plugged In", "S3", pin=PinState(final_try=True))
SECOND = cert("Bob Smith", "S4")
FORMS = bool(os.environ.get("FAKE_FORMS"))
if FORMS:  # MCA scenario: Jane holds the PAN of field 2, Carol's PAN is on no field, Bob (flag 'two') holds field 1's PAN
    import gui_formfix as ff

    CERTS = [ff.token("Jane Doe", "S1", ff.PAN2), ff.token("Carol Vance", "S2", "NOT-A-PAN")]
    SECOND = ff.token("Bob Smith", "S4", ff.PAN1)
log = {"attempts": 0, "pins": [], "discovers": 0, "calls": [], "prompts": [], "since_fail": 0}


def plug():
    return os.path.exists(os.path.join(out_dir, "plug"))


def flag(name):
    return os.path.exists(os.path.join(out_dir, name))


def discover(extra):
    log["discovers"] += 1
    if flag("busy"):
        return []
    if flag("partial"):
        return CERTS[:1]
    time.sleep(3.0 if flag("slow") else float(os.environ.get("FAKE_DETECT_SECONDS", "1.0")))
    return [c for c in CERTS if not (flag("unplug1") and c.serial == "S1")] + ([PLUGGED] if plug() else []) + ([SECOND] if flag("two") else [])


try:
    from tda_dsc_signer.errors import DriverBusy, TokenCountMismatch
except ImportError:  # core without the typed scan errors: same names/attributes, matched by class name in the GUI

    class DriverBusy(Exception):
        def __init__(self, message, module="", holder_pid=0):
            super().__init__(message)
            self.module, self.holder_pid = module, holder_pid

    class TokenCountMismatch(Exception):
        def __init__(self, expected, found):
            super().__init__(f"usb shows {expected} token devices, the driver listed {found}")
            self.expected, self.found = expected, found


def errors():
    if flag("busy"):
        return {"/opt/fake/libvendor.so": DriverBusy("driver busy (fake)", "/opt/fake/libvendor.so", 4242)}
    if flag("partial"):
        return {"usb": TokenCountMismatch(2, 1)}
    return {"/opt/fake/libvendor.so": RuntimeError("module host died")} if flag("moderr") else {}


FILLED = {}  # abs output path -> names of the form fields signed so far (the fake backend's stand-in for the PDF's contents)


def fields(path):
    import dataclasses

    from tda_dsc_signer import forms

    done = FILLED.get(os.path.abspath(path), set())
    return [dataclasses.replace(f, signed=f.signed or f.name in done) for f in forms.find_signature_fields(path)]


def sign_field(src, c, field, pin, out, **kw):
    import shutil

    log["calls"].append([os.path.basename(src), c.serial, field, os.path.basename(out), "field"])
    log["attempts"] += 1
    log["pins"].append(len(pin or ""))
    if pin != "right-pin":
        raise pkcs11.PinIncorrect("fake token: wrong PIN")
    if flag("slowsign"):
        time.sleep(2.5)
    shutil.copy(src, out)
    FILLED[os.path.abspath(out)] = FILLED.get(os.path.abspath(src), set()) | {field}
    return signing.SignResult(out, field, os.path.getsize(out))


def verify_fake(path, field_name=None):
    done = FILLED.get(os.path.abspath(path))
    if done is None:
        return verify.verify_signed(path, field_name)
    rows = (
        verify.Row("unmodified", verify.LABELS["unmodified"], verify.OK, "digest matches and the signature covers the whole file"),
        verify.Row("signature", verify.LABELS["signature"], verify.OK, "cryptographic check passed"),
        verify.Row("issuer", verify.LABELS["issuer"], verify.OK, "chains to the pinned CCA India root"),
        verify.Row("revocation", verify.LABELS["revocation"], verify.UNCHECKED, "no revocation data embedded or fetched"),
    )
    return verify.VerifyResult(
        rows,
        "Jane Doe",
        True,
        True,
        f"{len(done)} field(s) signed (fake backend)",
        (),
        tuple(verify.FieldResult(n, "Jane Doe" if n in done else "", True if n in done else None) for n in sorted(done)),
    )


def sign(src, c, *, visible=True, field=None, **kw):
    if field:
        return sign_field(src, c, field, kw.get("pin"), kw["out"])
    kw.pop("visible", None)
    if not visible:
        log.setdefault("invisible", []).append(c.serial)
        kw["page"], kw["box"] = (
            1,
            (20, 20, 120, 60),
        )  # ponytail: the fake backend still draws a box; the GUI contract (visible=False) is what is tested
    if flag("slowsign"):
        time.sleep(2.5)
    if flag("failat"):  # the Nth sign call after the flag appears fails like a hung token (HostTimeout)
        log["since_fail"] += 1
        if log["since_fail"] == int(open(os.path.join(out_dir, "failat")).read() or 1):
            os.unlink(os.path.join(out_dir, "failat"))
            log["since_fail"] = 0
            log["calls"].append([os.path.basename(src), c.serial, kw["page"], os.path.basename(kw["out"]), "TIMEOUT"])
            raise HostTimeout("fake token hung")
    log["calls"].append([os.path.basename(src), c.serial, kw["page"], os.path.basename(kw["out"]), "ok" if visible else "invisible"])
    log["attempts"] += 1
    log["pins"].append(len(kw["pin"] or ""))  # lengths only, never the PIN itself
    log.setdefault("ts", []).append(kw.pop("timestamp_url", ""))

    def open_session(cc, pin, confirm=False):
        if pin != "right-pin":
            raise pkcs11.PinIncorrect("fake token: wrong PIN")
        return type("S", (), {"close": lambda self: None})()

    def make_signer(session, signing_cert, ca_chain, **_kw):
        key = akeys.PrivateKeyInfo.load(lk.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        store = SimpleCertificateStore()
        store.register_multiple(ca_chain or [])
        return signers.SimpleSigner(signing_cert=signing_cert, signing_key=key, cert_registry=store, embed_roots=True)

    return signing.sign_pdf(src, c, open_session=open_session, make_signer=make_signer, mechanisms=lambda s: {Mechanism.SHA256_RSA_PKCS}, **kw)


def snapshot():
    return (("fake", 0),) if flag("nopoll") else (("fake", plug(), flag("unplug1"), flag("two")),)


saved = []
dialogs = []
pins_log = []
_cfg_box = config.Config()
_mode = os.environ.get("FAKE_PINS", "avail")  # avail | unavail | none
if _mode == "none":
    pins = None
else:
    from tda_dsc_signer import pinstore

    class LoggingPins(pinstore.PinManager):
        def saved_pin(self, serial):
            pins_log.append(["saved_pin", serial])
            return super().saved_pin(serial)

        def on_pin_incorrect(self, serial):
            pins_log.append(["on_pin_incorrect", serial])
            return super().on_pin_incorrect(serial)

    pins = LoggingPins(pinstore.MemoryStore() if _mode == "avail" else pinstore.UnavailableStore(), None, lambda: _cfg_box, lambda c: None)


def fake_save(self, parent, cancellable, callback):
    """No portal/file chooser under Xvfb: record the suggested name and 'choose' it, like a user pressing Save."""
    dialogs.append(self.get_initial_name())
    GLib.idle_add(lambda: parent.begin_sign(os.path.join(out_dir, f"signed-{len(dialogs)}.pdf")) and False)


Gtk.FileDialog.save = fake_save
_init = appmod.Window.__init__


def _sized_init(self, *a, **k):
    _init(self, *a, **k)
    self.set_default_size(width, height)
    ask = self.pin.ask

    def counting_ask(cert, count=1, error=None, *a):
        log["prompts"].append([cert.serial, count, error[0] if error else None])
        return ask(cert, count, error, *a)

    self.pin.ask = counting_ask


appmod.Window.__init__ = _sized_init
app = App(
    pdf,
    Backend(discover, sign, verify_fake, snapshot, lambda: None, errors, pins, fields),
    config.Config(),
    saved.append,
    app_id="in.tdacorp.DscSignerTest",
)


def dump():
    w = app.window
    if w is None:
        return True
    drop = os.path.join(out_dir, "drop")
    if os.path.exists(drop):  # real drag-and-drop can't be synthesised portably; this calls the same drop handler
        target = open(drop).read().strip()
        os.unlink(drop)
        w._dropped(None, Gio.File.new_for_path(target), 0, 0)
    ops = os.path.join(out_dir, "ops")
    if os.path.exists(ops):  # Settings widgets driven through their own handlers (pixel-clicking a second X window needs a WM)
        todo = json.load(open(ops))
        os.unlink(ops)
        for op in todo:
            run_op(w, *op)
    pages = []
    for p in w.stack.pages:
        ok, b = p.compute_bounds(w)
        pages.append([round(b.get_x()), round(b.get_y()), round(b.get_width()), round(b.get_height())] if ok else None)
    cur = w.boxes.current
    sel = type("S", (), {"page": cur.page if cur else -1, "box": cur.box if cur else None})

    def bounds(widget):
        ok, b = widget.compute_bounds(w)
        return [round(b.get_x()), round(b.get_y()), round(b.get_width()), round(b.get_height())] if ok else None

    d = {
        "bounds": {
            "strip": bounds(w.strip),
            "open": bounds(w.strip.open_btn),
            "refresh": bounds(w.strip.refresh_btn),
            "note": bounds(w.strip.note),
            "drop": bounds(w.picker),
            "card": bounds(w.card),
            "side": bounds(w.side),
            "sign2": bounds(w.sign2),
            "refresh2": bounds(w.refresh2),
            "filecard": bounds(w.filecard),
            "header": bounds(w.header),
            "options_btn": bounds(w.strip.options_btn),
            "gear": bounds(w.strip.gear),
            "visible_sw": bounds(w.options.visible_sw),
            "ts_sw": bounds(w.options.ts_sw),
            "pageno": bounds(w.strip.pageno),
            "sign": bounds(w.strip.sign_btn),
            "toast_line": bounds(w.toast.line) if w.toast.get_visible() else None,
        },
        "save_names": dialogs,
        "boxes": [[p.page, [round(v) for v in p.box], p.signer] for p in w.boxes.items],
        "active": w.boxes.active,
        "stamps": [w.stack.text_for(p) for p in w.boxes.items],
        "chips": [
            [_chip(c), c.has_css_class("dim")] for r in iter_children(w.options.sigs) for c in iter_children(r) if isinstance(c, Gtk.MenuButton)
        ],
        "sign_status": [c.get_text() for c in iter_children(w.options.status)],
        "sign_label": w.strip.sign_btn.get_label(),
        "busy_retries": w._busy_retries,
        "note_warn": w.strip.note.has_css_class("warnline"),
        "note_err": w.strip.note.has_css_class("errline"),
        "toast_warn": w.toast.line.has_css_class("warnline"),
        "layout": w._mode,
        "visible_on": w.visible,
        "ts_on": w.options.ts_sw.get_active(),
        "ts_enabled": w.options.ts_sw.get_sensitive(),
        "ts_hint": w.options.hint.get_visible(),
        "sig_title": w.options.sig_title.get_text(),
        "sign2_enabled": w.sign2.get_sensitive(),
        "card_dot_classes": dots(w.card),
        "options_parent": type(w.options.get_parent()).__name__,
        "card_name": w.filecard.name.get_text(),
        "card_tip": w.filecard.name.get_tooltip_text(),
        "card_btn": w.filecard.change.get_label(),
        "card_children": len(list(iter_children(w.filecard))),
        "window_title": w.get_title(),
        "settings_open": w.in_settings,
        "toplevels": len(Gtk.Window.list_toplevels()),
        "gear_on": w.gear2.has_css_class("on"),
        "gear_enabled": w.gear2.get_sensitive(),
        "settings": settings_dump(w.settings),
        "signature_format_cfg": getattr(w.cfg, "signature_format", None),
        "pins_calls": pins_log,
        "calls": log["calls"],
        "prompts": log["prompts"],
        "pin_title": w.pin.title.get_text(),
        "toast_path_btns": w.toast.open_btn.get_visible(),
        "pin_pointing": (lambda r: [r[1].x, r[1].y, r[1].width, r[1].height])(w.pin.get_pointing_to()),
        "pin_text_len": len(w.pin.entry.get_text()),
        "pin_busy": w.pin._busy,
        "pin_remember": [w.pin.remember.get_visible(), w.pin.remember.get_label()],
        "ts_urls": log.get("ts", []),
        "invisible_calls": log.get("invisible", []),
        "pin_focus": w.pin.entry.has_focus(),
        "focus_widget": type(w.get_focus()).__name__ if w.get_focus() else None,
        "pin_mapped": w.pin.get_mapped(),
        "pin_entry_vis": w.pin.entry.get_visible(),
        "pin_edit": w.pin.entry.get_editable(),
        "refresh_enabled": w.strip.refresh_btn.get_sensitive(),
        "note": w.strip.note.get_text() if w.strip.note.get_visible() else "",
        "note_tip": w.strip.note.get_tooltip_text(),
        "selected_pos": w.picker.drop.get_selected() if w.picker.cert else -1,
        "scanning": w.picker.spinner.get_visible(),
        "items": [w.picker.drop.get_model().get_string(i) for i in range(w.picker.drop.get_model().get_n_items())],
        "vadj": [
            round(v)
            for v in (w.stack.get_vadjustment().get_value(), w.stack.get_vadjustment().get_upper(), w.stack.get_vadjustment().get_page_size())
        ],
        "size": [w.get_width(), w.get_height()],
        "strip_h": w.strip.get_height(),
        "title": w.get_title(),
        "signer": w.picker.cert.cn if w.picker.cert else None,
        "dropdown_items": w.picker.drop.get_model().get_n_items(),
        "detecting": w.picker.spinner.get_visible(),
        "sign_enabled": w.strip.sign_btn.get_sensitive(),
        "page_label": w.strip.pageno.get_text(),
        "profile": w.cfg.profile,
        "mode": w.sign_mode,
        "mode_active": {k: b.get_active() for k, b in w.options.mode.btns.items()},
        "mode_enabled": w.options.mode.get_sensitive(),
        "visible_sw_shown": w.options.visible_sw.get_parent().get_visible(),
        "gen_list_shown": w.options.sig_title.get_visible(),
        "form_title": w.options.form.title.get_text(),
        "form_empty_shown": w.options.form.empty.get_visible(),
        "form_rows": [
            dict(
                label=r["label"].get_text(),
                tip=r["label"].get_tooltip_text(),
                line=r["line"].get_text(),
                checked=r["check"].get_active(),
                enabled=r["check"].get_sensitive(),
                chip=r["chip"] is not None,
            )
            for r in w.options.form.rows_w
        ],
        "marks": [[m[0], list(m[1]), m[2], m[3]] for m in w._marks()],
        "fields_loaded": [[f.name, f.page, f.signed] for f in w.fields],
        "default_mode_cfg": getattr(w.cfg, "default_mode", None),
        "to_general": bounds(w.options.form.to_general) if w.options.form.empty.get_visible() else None,
        "mode_btns": {k: bounds(b) for k, b in w.options.mode.btns.items()},
        "form_check_b": [bounds(r["check"]) for r in w.options.form.rows_w],
        "form_label_b": [bounds(r["label"]) for r in w.options.form.rows_w],
        "path": w.path,
        "sel": [sel.page, [round(v) for v in sel.box] if sel.box else None],
        "zoom": round(w.stack.zoom, 3),
        "pages": pages,
        "pin_open": w.pin.is_visible(),
        "pin_err": w.pin.err.get_text() if w.pin.err.get_visible() else "",
        "pin_entry_visible": w.pin.entry.get_visible(),
        "pin_confirm_visible": w.pin.confirm.get_visible(),
        "pin_warn": w.pin.warn.get_text() if w.pin.warn.get_visible() else "",
        "pin_go": w.pin.go.get_sensitive(),
        "toast": w.toast.line.get_text() if w.toast.get_visible() else "",
        "toast_open": w.toast.details.get_reveal_child(),
        "toast_rows": [c.get_text() for c in iter_children(w.toast.rows)],
        "toast_warns": [c.get_text() for c in iter_children(w.toast.warns)],
        "toast_h": w.toast.get_height(),
        "attempts": log["attempts"],
        "pin_lens": log["pins"],
        "discovers": log["discovers"],
        "saved_profile": saved[-1].profile if saved else None,
        "saved_token": saved[-1].last_token if saved else None,
        "saved_ts": saved[-1].timestamp_url if saved else None,
    }
    tmp = os.path.join(out_dir, "state.json.tmp")
    with open(tmp, "w") as f:
        json.dump(d, f)
    os.replace(tmp, os.path.join(out_dir, "state.json"))
    return True


def run_op(w, name, *a):
    if name == "open":
        w.open_settings()
        return
    if name in ("assign", "chip_open", "chip_pick"):  # the Signatures-list chip menu, through its real widgets
        mb = next(c for c in iter_children(list(iter_children(w.options.sigs))[a[0]]) if isinstance(c, Gtk.MenuButton))
        if name == "chip_open":
            mb.popup()
        elif name == "chip_pick":
            btn = next(b for b in iter_children(mb.get_popover().get_child()) if f"Token {a[1]}" in b.get_label())
            btn.emit("clicked")
        else:
            w._assign_box(a[0], next(c for c in w.picker.certs if c.serial == a[1]))
        return
    st = w.settings
    if name == "close":
        w.close_settings()
    elif name == "toggle":
        w.toggle_settings()
    elif name == "url":
        st.url.set_text(a[0])
        st.url_save.emit("clicked")
    elif name == "choice":
        getattr(st, a[0] + "_drop").set_selected(a[1])
    elif name == "forget_all":
        st.forget_all.emit("clicked")
    else:
        row = next(r for r in iter_children(st.rows) if hasattr(r, "radios") and r.cert.serial == a[0])
        if name == "mode":
            row.radios[a[1]].set_active(True)
        elif name == "save":
            row.entry.set_text(a[1])
            row.save_btn.emit("clicked")
        elif name == "forget":
            row.forget_btn.emit("clicked")


def _chip(mb):
    return mb.get_child().get_text()


def dots(card):
    """CSS classes of the card's currently shown dot (the dropdown button child)."""
    out = []

    def walk(wd):
        while wd:
            if wd.has_css_class("dot"):
                out.append([c for c in ("ok", "warn", "err") if wd.has_css_class(c)])
            walk(wd.get_first_child())
            wd = wd.get_next_sibling()

    walk(card.drop.get_first_child())
    return out[:1]


def settings_dump(st):
    if st is None:
        return None
    rows = []
    for r in iter_children(st.rows):
        if hasattr(r, "radios"):
            rows.append(
                {
                    "serial": r.cert.serial,
                    "mode": next(m for m, b in r.radios.items() if b.get_active()),
                    "keyring_enabled": r.radios["keyring"].get_sensitive(),
                    "entry_sensitive": r.entry.get_sensitive(),
                    "state": r.state_lbl.get_text(),
                    "forget": r.forget_btn.get_sensitive(),
                    "pin_text_len": len(r.entry.get_text()),
                }
            )
    return {
        "banner": st.banner.get_text(),
        "rows": rows,
        "url": st.url.get_text(),
        "msg": st.msg.get_text(),
        "bad": st.banner_box.has_css_class("bad"),
    }


def iter_children(box):
    c = box.get_first_child()
    while c:
        yield c
        c = c.get_next_sibling()


def start(_app):
    app.window.set_default_size(width, height)
    GLib.timeout_add(150, dump)


app.connect("activate", lambda a: GLib.idle_add(start, a))
sys.exit(app.run([]))

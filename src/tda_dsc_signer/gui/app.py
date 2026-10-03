"""GTK4 application: one slim strip + continuous page column + toast. Talks only to the Backend seam and a Worker."""

import os

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")
from gi.repository import Gdk, Gio, GLib, Gtk

from .. import config, safety, signing, stamp
from ..backend import default_backend
from ..watch import Poller
from ..worker import Worker
from . import formstate, state, style
from .boxes import Boxes
from .panel import FileCard, OptionsPanel, SidePanel, icon_button, make_header, sign_button
from .pdfview import PdfStack
from .pinpopover import PinPopover
from .settings import SettingsPage
from .signrun import SignRun, Step
from .strip import Strip
from .toast import Toast
from .tokencard import TokenCard

APP_ID = "in.tdacorp.DscSigner"
TITLE = "DSC Signer"
POLL_SECONDS = 2.0
BUSY_RETRIES, BUSY_RETRY_MS = 3, 3000


class Window(Gtk.ApplicationWindow):
    def __init__(self, app, path, backend, cfg, save_cfg=config.save):
        super().__init__(application=app, title=TITLE, default_width=1100, default_height=720, decorated=False)
        self.add_css_class("app")
        self.backend, self.cfg, self._save, self.path = backend, cfg, save_cfg, None
        self.boxes, self._busy, self._pins, self._run, self.poller = Boxes(), False, {}, None, None
        self._signing, self._scanning, self._wanted = False, False, cfg.last_token  # _wanted: the token the user picked (survives replug)
        self._driver_busy, self._busy_retries = False, 0
        # default priority: idle priority starves behind GTK redraws; starting now warms the driver while the window is usable
        self.worker = Worker(lambda f, *a: GLib.idle_add(f, *a, priority=GLib.PRIORITY_DEFAULT)).start()

        self._pins_store = getattr(backend, "pins", None)  # PinManager or None (older backend)
        self.sign_mode, self._mode_by_file, self.fields, self._form_choice, self._active_field = "general", {}, [], {}, None
        self.rows = []  # formstate.Row per EMPTY field (recomputed on every _refresh)
        self._mismatch, self._note, self.visible, self.settings, self._mode = False, ("", "error", ""), True, None, None
        self.strip = Strip(
            self._choose_pdf, lambda user=False: self._picked(self.picker, user), self.on_sign, self.refresh_tokens, self.open_settings
        )
        self.picker = self.strip.picker
        self.card = TokenCard(lambda user=False: self._picked(self.card, user))
        self.refresh2 = icon_button("view-refresh-symbolic", "Rescan tokens (F5 / Ctrl+R)", self.refresh_tokens)
        self.sign2 = sign_button(self.on_sign)
        self.options = OptionsPanel(
            self._set_visible,
            lambda on: self._refresh(),
            self.open_settings,
            self._move_box,
            self._delete_box,
            self._select_box,
            self._assign_box,
            self._user_mode,
            (self._form_check, self._form_select, self._form_assign, lambda: self._user_mode("general")),
        )
        self.options.set_size_request(300, -1)
        self.side = SidePanel(self.card, self.refresh2, self.options, self.sign2)
        self.filecard = FileCard(self._choose_pdf)
        self._pickers = (self.picker, self.card)
        self.stack = PdfStack(self.boxes, self._refresh, self.strip.set_page)
        self.stack.current_cert = lambda: self.picker.cert  # the dropdown only decides the signer of boxes drawn from now on
        self.stack.name_for = self._name_for
        self.stack.marks_on = lambda: self.sign_mode == "mca"
        self.stack.marks = self._marks
        self.stack.on_field = lambda n: self._form_select(self.rows[n - 1].field.name, scroll=False)
        self.stack.text_for = lambda p: stamp.render_text(self.cfg.stamp_text, self._name_for(p) or "(signer)")
        self.stack.certs, self.stack.assign = lambda: self.picker.certs, self._assign_box
        self.toast = Toast(self)
        self.pin = PinPopover(self.strip.sign_btn, self._pin_submitted, self._pin_cancelled, self._try_anyway, self.refresh_tokens)

        over = Gtk.Overlay(child=self.stack, vexpand=True)
        over.add_overlay(self.toast)
        self.canvas = Gtk.Box(vexpand=True)
        self.canvas.add_css_class("canvas")
        self.canvas.append(over)
        self.left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, hexpand=True)
        self.left.append(self.filecard)
        self.left.append(self.canvas)
        self.body = Gtk.Box(spacing=12, vexpand=True)
        self.body.append(self.left)
        self.body.append(self.side)
        self.header, self.gear2 = make_header(self.toggle_settings)
        main = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        main.append(Gtk.WindowHandle(child=self.strip))  # decorated=False: i3 (or any WM) draws the title bar; header and strip drag
        main.append(self.body)
        self.pages = Gtk.Stack(vexpand=True, hhomogeneous=False, vhomogeneous=False)  # no transition: the main page keeps all its state
        self.pages.add_named(main, "main")
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        outer.append(Gtk.WindowHandle(child=self.header))
        outer.append(self.pages)
        self.set_child(outer)
        self.apply_layout("strip")  # the narrow layout has the smaller minimum width: the real one is chosen at realize from the requested size
        self.connect("realize", lambda *_: self.apply_layout(state.layout_for(self.get_default_size()[0])))
        self.add_tick_callback(self._tick)
        self._config_changed()

        keys = Gtk.EventControllerKey()
        keys.connect("key-pressed", self._key)
        self.add_controller(keys)
        drop = Gtk.DropTarget.new(Gio.File, Gdk.DragAction.COPY)
        drop.connect("drop", self._dropped)
        self.add_controller(drop)
        self.connect("close-request", self._closing)

        self.stack.set_focusable(True)
        self.stack.grab_focus()
        self._each("detecting")
        self._scanning = True
        self.worker.submit(lambda: (self.backend.discover(self.cfg.extra_modules), self.backend.snapshot()), self._tokens_ready)
        if path:
            self.load(path)

    # -- layout ---------------------------------------------------------------
    def _tick(self, *_):
        w = self.get_width()
        if w > 0 and state.layout_for(w) != self._mode:
            self.apply_layout(state.layout_for(w))
        return True

    def apply_layout(self, mode):
        """One state, two presentations: 'two' (>= 900 px) or 'strip'. The options panel and the PIN popover move to the active one."""
        self._mode = mode
        two = mode == "two"
        self.header.get_parent().set_visible(two)
        self.strip.get_parent().set_visible(not two)
        self.filecard.set_visible(two)
        self.side.set_visible(two)
        for side in ("start", "end", "bottom"):
            getattr(self.body, f"set_margin_{side}")(16 if two else 0)
        self.body.set_spacing(12 if two else 0)
        self.left.set_spacing(12 if two else 0)
        (self.canvas.add_css_class if two else self.canvas.remove_css_class)("canvas")
        if getattr(self, "_opts_mode", None) != mode:  # the options panel lives in exactly one host
            if self.options.get_parent() is self.side.options_slot:
                self.side.options_slot.remove(self.options)
            elif self.options.get_parent() is not None:
                self.strip.options_pop.set_child(None)
            (self.side.options_slot.append if two else self.strip.options_pop.set_child)(self.options)
            self._opts_mode = mode
        self.pin.retarget(self.sign2 if two else self.strip.sign_btn)

    @property
    def sign_btns(self):
        return (self.strip.sign_btn, self.sign2)

    def _each(self, name, *a):
        for p in self._pickers:
            getattr(p, name)(*a)

    # -- tokens ---------------------------------------------------------------
    def _picked(self, src, user=False):
        c = src.cert
        if c:
            self._wanted = c.key
            for p in self._pickers:
                if p is not src:
                    p.select_key(c.key)
        self._refresh()

    def refresh_tokens(self, auto=False):
        """Rescan on the worker (never the GTK thread). Ignored while a scan or a sign request is in flight (a pending PIN prompt is fine)."""
        if self._scanning or self._signing:
            return
        if not auto:
            self._busy_retries = 0  # a manual Refresh restarts the automatic DriverBusy retries
        self._scanning = True
        self._each("scanning", True)
        self._refresh()
        self.worker.submit(lambda: (self.backend.discover(self.cfg.extra_modules), self.backend.snapshot()), self._tokens_ready)

    def _set_note(self, text, tip="", level="error", full=""):
        self.strip.set_note(text, tip, level)
        self._note = (full or text, level, tip)

    def _tokens_ready(self, result, err):
        self._scanning = False
        self._each("scanning", False)
        certs, snap = result if not err else ([], None)
        problem = state.scan_problem(self.backend.errors())
        note, tip, level, full = "", "", "error", ""
        self._driver_busy = bool(problem and problem[0] == "busy")
        self._mismatch = bool(problem and problem[0] == "mismatch")
        if err:
            note, tip = "scan failed", f"{type(err).__name__}: {err}"
        elif problem:
            _kind, note, tip, level, full = problem
            if problem[0] in ("busy", "mismatch"):  # the strip is narrow: the whole sentence goes to the toast
                self.toast.show_text(full, "warn")
            if problem[0] == "busy":
                self._retry_busy()
        if not (problem and problem[0] == "busy"):
            self._busy_retries = 0
        if not certs:
            for p in self._pickers:
                p.problem(note, tip) if (problem or err) else p.none(tip)
            self._lost()
            note = note or ("token removed" if self._had else "no token found")
            if not self._had and not problem and not err:
                self.toast.show_text("No DSC token found. Run: tda-dsc-signer doctor", "error")
        else:
            gone = self._wanted and self._wanted not in [c.key for c in certs] and self._had
            for p in self._pickers:
                p.set_certs(certs, self._wanted, allow_none=bool(gone))
            if gone:
                self._lost()
                note = note or "token removed"
        if certs and self.poller is None:
            self.poller = Poller(self.backend.snapshot, lambda _s: GLib.idle_add(self._rescan), POLL_SECONDS)
            self.poller.start(snap)
        self._had = bool(certs)
        self._set_note(note, tip, level, full)
        if self.settings is not None and self.settings.serials != {c.serial for c in certs}:
            self.settings.rebuild()
        self._refresh()

    def _retry_busy(self):
        """DriverBusy only: look again 3 s later, at most 3 times, then keep the message and wait for the user's Refresh."""
        if self._busy_retries >= BUSY_RETRIES:
            return
        self._busy_retries += 1
        GLib.timeout_add(BUSY_RETRY_MS, lambda: (self.refresh_tokens(auto=True), False)[1])

    _had = False

    def _lost(self):
        """The signing token is gone: a pending PIN prompt must not outlive it (a running sign stops by itself)."""
        if self._run and not self._signing:
            self._run.cancel("The token was removed; signing stopped.")
        elif not self._run:
            self.pin.popdown()

    @staticmethod
    def _name_for(p):
        """Display name of a box's own signer (its snapshot: survives the token being unplugged)."""
        return p.cert.cn if p.cert else ""

    def _rescan(self):
        self.refresh_tokens()
        return False

    # -- state ----------------------------------------------------------------
    def _refresh(self):
        certs = {c.key: c for c in self.picker.certs}
        self.rows = formstate.build_rows(self.fields, self.picker.certs, self._form_choice, self.picker.cert) if self.fields else []
        mca = self.sign_mode == "mca"
        if mca:
            ready = bool(formstate.checked_rows(self.rows))  # a row whose token is gone is refused with a message in on_sign
        elif self.visible:
            ready = self.boxes.all_valid  # an unplugged signer is refused with a message in on_sign, not by a dead button
        else:
            ready = self.picker.cert is not None  # an invisible signature needs no box, only a token
        ready = ready and not self._driver_busy
        self.stack.redraw()
        self.strip.set_count(len(formstate.checked_rows(self.rows)) if mca else len(self.boxes) if self.visible else 0)
        ok = state.can_sign(bool(certs), ready, self.path, self._busy)
        for b in self.sign_btns:
            b.set_sensitive(ok)
        for b in (self.strip.refresh_btn, self.refresh2):
            b.set_sensitive(not (self._scanning or self._signing))
        for g in (self.strip.gear, self.gear2):
            g.set_sensitive(not self._busy)  # no Settings while a sign run is in progress
        self.card.set_status(state.scan_status(self._scanning, self._driver_busy, self._mismatch, bool(certs)))
        self.options.set_signatures(self.boxes.items, self.picker.certs, self.boxes.active, self.boxes.locked)
        self.options.form.set_rows(self.rows, [f for f in self.fields if f.signed], self._active_field, self._busy)
        self.options.mode.set_sensitive(not self._busy)
        text, level, tip = self._note
        lines = [(text, level, tip)] if text else []
        if gone := ([] if mca else self._unplugged()):
            lines.append((self._gone_text(gone), "error", ""))
        if state.too_big(self.path) and self.cfg.profile == "mca":
            lines.append(("File is over 2 MB: the signed output may exceed the MCA upload limit (reported, not verified).", "warn", ""))
        self.options.set_status(lines)

    # -- MCA mode ---------------------------------------------------------------
    def _marks(self):
        if self.sign_mode != "mca":
            return []
        return [(r.field.page - 1, r.field.rect, r.n, r.field.name == self._active_field) for r in self.rows]

    def _set_mode(self, mode):
        self.sign_mode = mode
        self.options.set_mode(mode)
        self._refresh()

    def _user_mode(self, mode):
        """The user picked a mode: remembered for this file for the window session."""
        if self.path:
            self._mode_by_file[self.path] = mode
        self._set_mode(mode)

    def _form_check(self, name, on):
        self._form_choice.setdefault(name, {})["checked"] = on
        self._refresh()

    def _form_select(self, name, scroll=True):
        self._active_field = name
        if scroll and (r := next((r for r in self.rows if r.field.name == name), None)):
            self.stack.scroll_to_field(r.field.page - 1, r.field.rect)
        self._refresh()

    def _form_assign(self, name, cert):
        self._form_choice.setdefault(name, {}).update(signer=cert.key, checked=True)
        self._refresh()

    def _set_visible(self, on):
        self.visible = on
        self.boxes.locked = self._busy or not on
        self._refresh()

    def _config_changed(self):
        """Settings changed the timestamp URL: the toggle is usable (and on) once a server is set."""
        was = self.options.ts_sw.get_sensitive()
        self.options.set_timestamp_available(bool(self.cfg.timestamp_url))
        if self.cfg.timestamp_url and not was:
            self.options.ts_sw.set_active(True)

    def _move_box(self, i, d):
        self.boxes.move_order(i, d)
        self._refresh()

    def _delete_box(self, i):
        self.boxes.remove(i)
        self._refresh()

    def _select_box(self, i):
        self.boxes.active = i  # selecting a box never touches the dropdown
        self._refresh()

    def _assign_box(self, i, cert):
        if not self.boxes.locked:
            self.boxes.assign(i, cert.key, cert)
            self._refresh()

    def _unplugged(self):
        """Boxes whose own signer token is not among the scanned ones (visible mode only; matched by key, so a replug restores them)."""
        keys = {c.key for c in self.picker.certs}
        return [p for p in self.boxes.items if self.visible and p.signer and p.signer not in keys]

    @staticmethod
    def _gone_text(gone):
        return "A box uses a token that is not connected: " + ", ".join(dict.fromkeys(p.cert.cn if p.cert else p.signer for p in gone))

    def _persist(self, _cfg=None):
        if hasattr(self.cfg, "pin_modes"):  # pins.py owns pin_modes on disk: never overwrite it with a stale copy
            self.cfg.pin_modes = config.load().pin_modes
        self._save(self.cfg)

    @property
    def in_settings(self):
        return self.pages.get_visible_child_name() == "settings"

    def toggle_settings(self):
        self.close_settings() if self.in_settings else self.open_settings()

    def open_settings(self):
        if self._busy or self.in_settings:
            return
        if self.settings is None:
            self.settings = SettingsPage(self.backend, self.cfg, self._persist, lambda: self.picker.certs, self._config_changed, self.close_settings)
            self.pages.add_named(self.settings, "settings")
        else:
            self.settings.rebuild()
        self.pin.popdown()
        self.pages.set_visible_child_name("settings")
        self._gear_state()

    def close_settings(self):
        self.pages.set_visible_child_name("main")
        self._gear_state()
        self.stack.grab_focus()

    def _gear_state(self):
        for g in (self.strip.gear, self.gear2):
            (g.add_css_class if self.in_settings else g.remove_css_class)("on")

    def load(self, path, keep_boxes=False, keep_mode=False):
        try:
            self.stack.load(os.path.abspath(path))
        except GLib.Error as e:
            self.toast.show_text(f"Cannot open PDF: {e.message}", "error")
            return
        self.path = os.path.abspath(path)
        self.filecard.set_file(self.path)
        self.set_title(f"{os.path.basename(path)} - {TITLE}")
        if not keep_boxes:
            self.stack.clear_boxes()
        reader = getattr(self.backend, "fields", None)  # never touches PKCS#11; ponytail: read on the GTK thread, move to the worker if slow
        try:
            self.fields = list(reader(self.path)) if reader else []
        except Exception as e:  # noqa: BLE001 - an unreadable form is General mode, with a note
            self.fields = []
            self.toast.show_text(f"Could not read signature fields: {e}", "warn")
        if not keep_mode:
            self._form_choice, self._active_field = {}, None
        n_empty = sum(not f.signed for f in self.fields)
        self._set_mode(
            formstate.detect_mode(n_empty, getattr(self.cfg, "default_mode", "auto"), self._mode_by_file.get(self.path))
            if not keep_mode
            else self.sign_mode
        )

    def _choose_pdf(self):
        d = Gtk.FileDialog(title="Open PDF")
        flt = Gtk.FileFilter(name="PDF")
        flt.add_mime_type("application/pdf")
        d.set_default_filter(flt)
        d.open(self, None, self._opened)

    def _opened(self, dlg, res):
        try:
            self.load(dlg.open_finish(res).get_path())
        except GLib.Error:
            pass  # dismissed

    def _dropped(self, _target, value, _x, _y):
        p = value.get_path()
        if not p or not p.lower().endswith(".pdf"):
            self.toast.show_text(f"Not a PDF: {p or value.get_uri()}", "error")
            return False
        self.load(p)
        return True

    def _key(self, _c, keyval, _code, mods):
        if keyval == Gdk.KEY_F5:  # works even with the PIN popover open (a token may have been unplugged under it)
            self.refresh_tokens()
            return True
        if self.in_settings:  # entries and buttons own their keys here; only Esc / Ctrl+, / F5 are ours
            if keyval == Gdk.KEY_Escape or (mods & Gdk.ModifierType.CONTROL_MASK and keyval == Gdk.KEY_comma):
                self.close_settings()
                return True
            return False
        if self.pin.is_visible():
            return False  # typing a PIN must never trigger shortcuts (zoom on '-', sign on Enter...)
        K = Gdk
        ctrl = bool(mods & Gdk.ModifierType.CONTROL_MASK)
        if keyval in (K.KEY_Return, K.KEY_KP_Enter) and self.strip.sign_btn.get_sensitive() and not ctrl:
            self.on_sign()
        elif keyval in (K.KEY_Escape, K.KEY_Delete, K.KEY_BackSpace):
            if self._busy:
                return False
            if self.sign_mode == "general" and self.boxes.current:
                self.stack.remove_active()  # the active box only; the others stay
            elif keyval == K.KEY_Escape:
                self.toast.dismiss()
        elif ctrl and keyval in (K.KEY_r,):
            self.refresh_tokens()
        elif ctrl and keyval == K.KEY_s:
            self.on_sign()
        elif ctrl and keyval == K.KEY_comma:
            self.open_settings()
        elif ctrl and keyval == K.KEY_o:
            self._choose_pdf()
        elif ctrl and keyval in (K.KEY_q, K.KEY_w):
            self.close()
        elif keyval in (K.KEY_plus, K.KEY_equal, K.KEY_KP_Add):
            self.stack.set_zoom(self.stack.zoom * state.ZOOM_STEP)
        elif keyval in (K.KEY_minus, K.KEY_KP_Subtract):
            self.stack.set_zoom(self.stack.zoom / state.ZOOM_STEP)
        elif keyval in (K.KEY_0, K.KEY_KP_0):
            self.stack.set_zoom(1.0)
        elif nav := {K.KEY_Home: "home", K.KEY_End: "end", K.KEY_Page_Up: "pgup", K.KEY_Page_Down: "pgdn"}.get(keyval):
            self.stack.scroll_to(nav)
        else:
            return False
        return True

    # -- signing ----------------------------------------------------------------
    def _certs_for_boxes(self):
        by_key = {c.key: c for c in self.picker.certs}
        return [by_key.get(p.signer) for p in self.boxes.items]

    def _sign_certs(self):
        """One cert per signature: the checked fields' signers (MCA), the box owners (visible) or just the selected token (invisible)."""
        if self.sign_mode == "mca":
            return [r.cert for r in formstate.checked_rows(self.rows)]
        return self._certs_for_boxes() if self.visible else [self.picker.cert]

    def on_sign(self):
        if self._busy or not self.sign_btns[0].get_sensitive():
            return
        mca = self.sign_mode == "mca"
        if mca:
            if msg := formstate.problem(self.rows):
                self.toast.show_text(msg, "error")
                return
        elif gone := self._unplugged():
            self.toast.show_text(self._gone_text(gone), "error")
            return
        for n, c in enumerate(self._sign_certs(), 1):
            who = f"Field {n}" if mca else f"Box {n}" if self.visible else "Signature"
            if c is None:
                self.toast.show_text(f"{who} has no signer: pick one in the Signatures list.", "error")
                return
            if c.expired():
                self.toast.show_text(f"{who}: the certificate of {c.cn} expired on {c.end}.", "error")
                return
            try:
                safety.guard_login(c.pin, confirm_final_try=True)  # only a locked token stops here; a final try asks in the popover
            except safety.TokenLocked:
                self.toast.show_text(f"{who}: " + state.describe_error(safety.TokenLocked())[1], "error")
                return
        d = Gtk.FileDialog(title="Save signed PDF", initial_name=os.path.basename(signing.default_output(self.path)))
        d.set_initial_folder(Gio.File.new_for_path(os.path.dirname(self.path)))
        d.save(self, None, self._out_chosen)

    def _out_chosen(self, dlg, res):
        try:
            out = dlg.save_finish(res).get_path()
        except GLib.Error:
            return  # dismissed
        self.begin_sign(out)

    def begin_sign(self, out):
        """Output chosen: run every box in badge order, one PIN prompt per token."""
        try:
            signing.check_output(self.path, out, overwrite=True)  # the save dialog already asked before replacing; input==output still refused
        except ValueError as e:
            self.toast.show_text(str(e), "error")
            return
        certs = self._sign_certs()
        mca = self.sign_mode == "mca"
        self._run_rows = formstate.checked_rows(self.rows) if mca else []
        if mca:
            steps = formstate.steps_for(self.rows)
        elif self.visible:
            steps = [Step(i + 1, p.page + 1, tuple(round(v) for v in p.box), c) for i, (p, c) in enumerate(zip(self.boxes.items, certs, strict=True))]
        else:
            steps = [Step(1, 1, (0, 0, 0, 0), certs[0])]
        stamped = self.options.ts_sw.get_active() and bool(self.cfg.timestamp_url)
        opts = {
            "stamp_text": self.cfg.stamp_text,
            "profile": self.cfg.profile,
            "timestamp_url": self.cfg.timestamp_url if stamped else "",
            "visible": self.visible or mca,
            "signature_format": None if getattr(self.cfg, "signature_format", "auto") == "auto" else self.cfg.signature_format,
        }
        self._busy, self.boxes.locked = True, True
        self._run = SignRun(
            steps,
            self.path,
            out,
            backend=self.backend,
            submit=self.worker.submit,
            ui=self,
            opts=opts,
            remembered=self._pins,
            overwrite_final=True,  # the save dialog already asked before replacing an existing file
            remember=self._remember,
            saved_pin=lambda c: state.saved_pin_usable(self._pins_store, c),
            on_saved_wrong=self._saved_wrong,
        )
        self._refresh()
        self._run.start()

    def _remember(self, key, pin):
        if self._pins_store is None:
            self._pins[key] = pin  # older backend: the old in-window session memory
        else:
            self._pins_store.remember_session(key.split("/")[0], pin)  # only acts when that token's mode is 'session'

    def _saved_wrong(self, cert):
        self._pins_store.on_pin_incorrect(cert.serial)
        if self.settings is not None:
            self.settings.rebuild()

    # SignRun ui ------------------------------------------------------------------
    def working(self, on):
        self._signing = on
        self._refresh()

    def progress(self, done, total):
        self._set_note(f"{done + 1}/{total} signing…", level="info")
        self._refresh()

    def ask_pin(self, cert, count, error):
        if self._pins_store is None:
            label = "Remember for this session"
        else:
            label = "Remember until I close the app" if self._pins_store.mode(cert.serial) == "session" else ""
        self.pin.ask(cert, count, error, label)

    def _pin_submitted(self, pin, remember, confirm):
        self._run.pin_given(pin, remember, confirm)

    def _try_anyway(self):
        self._run.retry_anyway()

    def _pin_cancelled(self):
        if self._run:
            self._run.cancel()

    def _run_over(self):
        self._run, self._busy, self._signing, self.boxes.locked = None, False, False, not self.visible
        self.pin.popdown()
        self._set_note("")

    def finished(self, path, ver, results):
        used_saved = self._run.used_saved
        c = self._run.steps[-1].cert
        self._run_over()
        mca = self.sign_mode == "mca"
        self.cfg.last_token = c.key if c else ""
        if self.visible and not mca:
            last = self.boxes.items[-1]
            self.cfg.last_page, self.cfg.last_box = last.page + 1, [round(v) for v in last.box]
        self._persist()
        notes = ("Used the saved PIN.",) if used_saved else ()
        head = formstate.summary(self._run_rows, self.rows) if mca else ""
        self.toast.show_result(ver, path, [w for r in results for w in r.warnings], notes, head)
        self.load(path, keep_mode=mca)  # reload so more boxes can be placed / the remaining fields stay listed

    def aborted(self, text, partial, done, total):
        """The run stopped. Finished signatures live in `partial`; the unsigned boxes stay in place on top of it."""
        self._run_over()
        if partial and done:
            self.toast.show_text(f"{text} Stopped after {done} of {total}; partial result saved as {partial}", "error", path=partial)
            mca = self.sign_mode == "mca"
            for _ in range(0 if mca else done):
                self.boxes.remove(0)
            self.load(partial, keep_boxes=True, keep_mode=mca)
        else:
            self.toast.show_text(text, "error")
            self._refresh()

    def _closing(self, *_):
        self.pin.popdown()
        self.pin.unparent()  # a parented popover with a focused entry warns about a missing focus-out on exit
        if self.poller:
            self.poller.stop()
        self.worker.stop()
        self.backend.close()
        return False


class App(Gtk.Application):
    """Unique application (D-Bus name in.tdacorp.DscSigner): a second launch, or opening another PDF, is forwarded to the
    running window instead of starting a second process (which could not share the vendor driver anyway)."""

    def __init__(self, path=None, backend=None, cfg=None, save_cfg=config.save, app_id=APP_ID):
        GLib.set_application_name(TITLE)
        super().__init__(application_id=app_id, flags=Gio.ApplicationFlags.HANDLES_OPEN)
        self._path, self._rest = path, (backend or default_backend(), cfg or config.load(), save_cfg)
        self.window = None

    def _show(self, path):
        if self.window is None:
            Gtk.Window.set_default_icon_name("tda-dsc-signer")
            style.install()
            self.window = Window(self, path, *self._rest)
        elif path:
            if self.window._busy:
                self.window.toast.show_text(f"Busy signing: not opening {os.path.basename(path)} now.", "warn")
            else:
                self.window.load(path)
        self.window.present()

    def do_activate(self):
        self._show(self._path)

    def do_open(self, files, _n, _hint):
        self._show(files[0].get_path())


def run_gui(path=None, backend=None):
    if path and not os.path.isfile(path):
        raise SystemExit(f"No such file: {path}")
    return App(backend=backend).run(["tda-dsc-signer", os.path.abspath(path)] if path else ["tda-dsc-signer"])

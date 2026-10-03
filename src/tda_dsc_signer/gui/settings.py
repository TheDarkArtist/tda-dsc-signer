"""Settings screen (a page of the main window's Gtk.Stack): secret store, per-token PIN memory, timestamp URL.

A PIN is only ever held in the masked entry until Save is clicked, then handed to backend.pins and cleared; never shown back.
"""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, Pango

from . import state

MODES = (("ask", "Ask every time"), ("session", "Remember until I close the app"), ("keyring", "Remember always (system keyring)"))
NO_PINS = "This build has no PIN storage; PINs are always asked."
HOWTO = "To use the system keyring, either enable KeePassXC > Settings > Secret Service Integration (database unlocked), or install gnome-keyring."
TS_NOTE = "Only use a timestamp server you trust. Whether the MCA accepts timestamped signatures is unverified."


MODE_CHOICES = (("auto", "Auto"), ("mca", "MCA"), ("general", "General"))
FORMAT_CHOICES = (("auto", "Auto"), ("adbe", "Adobe standard"), ("pades", "PAdES"))
FORMAT_NOTE = "MCA's expected signature format is unverified: Auto uses Adobe standard for form fields and PAdES for drawn boxes."


def _dim(text, **kw):
    lab = Gtk.Label(label=text, xalign=0, wrap=True, **kw)
    lab.add_css_class("dim")
    return lab


class TokenRow(Gtk.Box):
    def __init__(self, cert, pins, status, on_error):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.add_css_class("card")
        self.cert, self.pins, self._status, self._err, self._quiet = cert, pins, status, on_error, False
        head = Gtk.Box(spacing=8)
        name = Gtk.Label(label=f"{cert.cn}  •  {state.model_text(cert)}", xalign=0, hexpand=True, ellipsize=Pango.EllipsizeMode.END)
        name.add_css_class("filename")
        self.state_lbl = Gtk.Label(xalign=1)
        self.state_lbl.add_css_class("dim")
        head.append(name)
        head.append(self.state_lbl)
        self.append(head)
        self.append(_dim(f"serial {cert.serial}"))
        self.radios = {}
        first = None
        for mode, label in MODES:
            r = Gtk.CheckButton(label=label, group=first)
            first = first or r
            r.connect("toggled", lambda b, m=mode: b.get_active() and not self._quiet and self._set_mode(m))
            self.radios[mode] = r
            self.append(r)
        ent = Gtk.Box(spacing=6)
        self.entry = Gtk.PasswordEntry(show_peek_icon=True, placeholder_text="Token PIN", hexpand=True)
        self.save_btn = Gtk.Button(label="Save")
        self.forget_btn = Gtk.Button(label="Forget")
        self.save_btn.connect("clicked", lambda *_: self._save())
        self.entry.connect("activate", lambda *_: self._save())
        self.forget_btn.connect("clicked", lambda *_: (self.pins.forget(cert.serial), self.refresh()))
        for w in (self.entry, self.save_btn, self.forget_btn):
            ent.append(w)
        self.append(ent)
        self.refresh()

    def refresh(self):
        f = state.pin_row(self.pins, self.cert, self._status)
        self._quiet = True
        self.radios[f["mode"]].set_active(True)
        self._quiet = False
        self.radios["session"].set_sensitive(f["can_session"])
        self.radios["keyring"].set_sensitive(f["can_keyring"])
        why = "This token enters its PIN on its own pad." if not f["can_session"] else (self._status.get("reason") or "Secret store unavailable.")
        self.radios["keyring"].set_tooltip_text(None if f["can_keyring"] else why)
        self.radios["session"].set_tooltip_text(None if f["can_session"] else why)
        self.state_lbl.set_text("PIN saved" if f["saved"] else "not saved")
        usable = f["can_pin"] and f["mode"] != "ask"
        self.entry.set_visible(f["can_pin"])
        self.save_btn.set_visible(f["can_pin"])
        self.entry.set_sensitive(usable)
        self.save_btn.set_sensitive(usable)
        self.entry.set_tooltip_text(None if usable else "Choose a Remember option first.")
        self.forget_btn.set_sensitive(f["saved"])

    def _set_mode(self, mode):
        try:
            self.pins.set_mode(self.cert.serial, mode)
        except Exception as e:  # PinStoreUnavailable (matched loosely: the GUI must not depend on core's class)
            self._err(f"{type(e).__name__}: {e}")
        self.refresh()

    def _save(self):
        pin = self.entry.get_text()
        mode = next(m for m, r in self.radios.items() if r.get_active())
        self.entry.set_text("")  # the PIN leaves the widget before anything can fail
        if not pin or mode == "ask":
            return
        try:
            self.pins.save(self.cert.serial, pin, mode, protected_auth=self.cert.pin.protected_auth)
        except Exception as e:
            self._err(f"{type(e).__name__}: {e}")
        pin = None
        self.refresh()


class SettingsPage(Gtk.Box):
    def __init__(self, backend, cfg, save_cfg, certs, on_changed, on_back):
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.add_css_class("settingspage")
        self.backend, self.cfg, self._save_cfg, self._certs, self._on_changed = backend, cfg, save_cfg, certs, on_changed
        self.pins = getattr(backend, "pins", None)
        self.top = Gtk.Box(spacing=12, margin_top=10, margin_bottom=4, margin_start=16, margin_end=16)
        self.back = Gtk.Button(label="\u2190 Back", tooltip_text="Back (Esc)")
        self.back.add_css_class("flat-card")
        self.back.connect("clicked", lambda *_: on_back())
        title = Gtk.Label(label="Settings", xalign=0)
        title.add_css_class("title")
        self.top.append(self.back)
        self.top.append(title)
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10, margin_top=10, margin_bottom=14, margin_start=16, margin_end=16)
        self.append(self.top)
        self.append(Gtk.ScrolledWindow(child=root, vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER))
        h = Gtk.Label(label="Saved PINs", xalign=0)
        h.add_css_class("section")
        root.append(h)
        self.banner = Gtk.Label(xalign=0, wrap=True)
        bb = Gtk.Box()
        bb.add_css_class("banner")
        bb.append(self.banner)
        self.banner_box = bb
        self.msg = Gtk.Label(xalign=0, wrap=True)
        self.msg.add_css_class("errline")
        root.append(bb)
        root.append(self.msg)
        self.rows = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        root.append(self.rows)
        self.forget_all = Gtk.Button(label="Forget all", halign=Gtk.Align.START)
        self.forget_all.connect("clicked", lambda *_: (self.pins.forget_all(), self.rebuild()))
        root.append(self.forget_all)
        root.append(Gtk.Separator())
        t = Gtk.Label(label="Timestamp server URL", xalign=0)
        t.add_css_class("section")
        root.append(t)
        row = Gtk.Box(spacing=6)
        self.url = Gtk.Entry(text=cfg.timestamp_url, placeholder_text="https://", hexpand=True)
        self.url_save = Gtk.Button(label="Save")
        self.url.connect("activate", lambda *_: self._save_url())
        self.url_save.connect("clicked", lambda *_: self._save_url())
        row.append(self.url)
        row.append(self.url_save)
        root.append(row)
        root.append(_dim(TS_NOTE))
        root.append(Gtk.Separator())
        root.append(self._choice("Default mode", "default_mode", MODE_CHOICES))
        root.append(self._choice("Signature format", "signature_format", FORMAT_CHOICES))
        root.append(_dim(FORMAT_NOTE))
        self.rebuild()

    def _choice(self, title, attr, choices):
        """A labelled drop-down saved to cfg.<attr> (older configs lack the key: getattr default = first choice)."""
        row = Gtk.Box(spacing=12)
        lab = Gtk.Label(label=title, xalign=0, hexpand=True)
        keys = [k for k, _t in choices]
        drop = Gtk.DropDown(model=Gtk.StringList.new([t for _k, t in choices]))
        drop.set_selected(keys.index(getattr(self.cfg, attr, keys[0])) if getattr(self.cfg, attr, keys[0]) in keys else 0)
        drop.connect("notify::selected", lambda d, _p: self._set_choice(attr, keys[d.get_selected()]))
        setattr(self, attr + "_drop", drop)
        row.append(lab)
        row.append(drop)
        return row

    def _set_choice(self, attr, value):
        setattr(self.cfg, attr, value)
        self._save_cfg(self.cfg)

    def _error(self, text):
        self.msg.set_text(text)

    def rebuild(self):
        """Re-read the secret-store status and the token list (after a rescan or a change)."""
        while c := self.rows.get_first_child():
            self.rows.remove(c)
        self.msg.set_text("")
        self.serials = {c.serial for c in self._certs()}
        if self.pins is None:
            st = {"available": False, "reason": NO_PINS}
        else:
            st = self.pins.status()
        ok = st.get("available")
        self.banner.set_text(
            "System keyring available: PINs are stored in your secret store."
            if ok
            else (st.get("reason") or "No secret store.") + ("" if "KeePassXC" in (st.get("reason") or "") else "\n" + HOWTO)
        )
        (self.banner_box.remove_css_class if ok else self.banner_box.add_css_class)("bad")
        seen = set()
        certs = [c for c in self._certs() if not (c.serial in seen or seen.add(c.serial))]
        if self.pins is not None:
            for c in certs:
                self.rows.append(TokenRow(c, self.pins, st, self._error))
        if not certs or self.pins is None:
            self.rows.append(_dim("No tokens found yet: plug one in and Refresh." if self.pins is not None else NO_PINS))
        self.forget_all.set_sensitive(self.pins is not None and bool(certs))

    def _save_url(self):
        url = self.url.get_text().strip()
        self.cfg.timestamp_url = url
        self._save_cfg(self.cfg)
        self._on_changed()

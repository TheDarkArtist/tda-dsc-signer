"""Pieces of the two-pane layout: header, file card, options (switches + signature list + status lines), side panel."""

import os

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gdk, GdkPixbuf, Gtk, Pango

from .. import config
from .formpanel import FormPanel, ModeSwitch
from .signerpicker import signer_list

HERE = os.path.dirname(os.path.abspath(__file__))


def logo_path():
    """The user's own logo wins; otherwise the bundled TDACorp logo."""
    base = os.path.dirname(config.default_path())
    for n in ("logo.svg", "logo.png"):
        if os.path.isfile(os.path.join(base, n)):
            return os.path.join(base, n)
    return os.path.join(HERE, "tda-logo.svg")


LOGO_PX = 44


def set_logo(pic):
    """Render at LOGO_PX times the window scale factor so the vector/bitmap is never upscaled (blurry)."""
    px = LOGO_PX * max(1, pic.get_scale_factor())
    try:
        pic.set_paintable(Gdk.Texture.new_for_pixbuf(GdkPixbuf.Pixbuf.new_from_file_at_size(logo_path(), px, px)))
    except Exception:  # noqa: BLE001 - a broken user logo must not stop the app
        pic.set_paintable(None)


def icon_button(icon, tip, cb, css="iconbtn"):
    b = Gtk.Button(icon_name=icon, tooltip_text=tip)
    b.add_css_class(css)
    b.connect("clicked", lambda *_: cb())
    return b


def make_header(on_settings):
    """Logo, title, subtitle, gear. No window buttons (the window manager draws them)."""
    box = Gtk.Box(spacing=12)
    box.add_css_class("header")
    logo = Gtk.Picture(can_shrink=False, halign=Gtk.Align.CENTER, valign=Gtk.Align.CENTER)
    logo.set_size_request(LOGO_PX, LOGO_PX)
    logo.connect("realize", lambda p: set_logo(p))
    logo.connect("notify::scale-factor", lambda p, _s: set_logo(p))
    logo.add_css_class("logo")
    col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, valign=Gtk.Align.CENTER, hexpand=True)
    t = Gtk.Label(label="DSC Signer", xalign=0)
    t.add_css_class("title")
    s = Gtk.Label(label="Sign PDF documents using your DSC tokens", xalign=0, ellipsize=Pango.EllipsizeMode.END)
    s.add_css_class("subtitle")
    col.append(t)
    col.append(s)
    gear = icon_button("emblem-system-symbolic", "Settings (Ctrl+,)", on_settings)
    for w in (logo, col, gear):
        box.append(w)
    return box, gear


class FileCard(Gtk.Box):
    """File name only (middle-ellipsized, tooltip = full path); muted 'No file open' until a file is loaded."""

    def __init__(self, on_change):
        super().__init__(spacing=12, vexpand=False, valign=Gtk.Align.START)
        self.add_css_class("card")
        self.name = Gtk.Label(xalign=0, hexpand=True, ellipsize=Pango.EllipsizeMode.MIDDLE, single_line_mode=True)
        self.change = Gtk.Button(tooltip_text="Open PDF (Ctrl+O)", valign=Gtk.Align.CENTER)
        self.change.add_css_class("flat-card")
        self.change.connect("clicked", lambda *_: on_change())
        self.append(self.name)
        self.append(self.change)
        self.set_file(None)

    def set_file(self, path):
        has = bool(path)
        self.name.set_text(os.path.basename(path) if has else "No file open")
        self.name.set_tooltip_text(path if has else None)
        (self.name.remove_css_class if has else self.name.add_css_class)("dim")
        (self.name.add_css_class if has else self.name.remove_css_class)("filename")
        self.change.set_label("Change File" if has else "Open File")


def _switch_row(icon, text, cb, active=False):
    row = Gtk.Box(spacing=12)
    img = Gtk.Image(icon_name=icon)
    img.add_css_class("dim")
    lab = Gtk.Label(label=text, xalign=0, hexpand=True)
    sw = Gtk.Switch(valign=Gtk.Align.CENTER, active=active)
    sw.connect("notify::active", lambda s, _p: cb(s.get_active()))
    for w in (img, lab, sw):
        row.append(w)
    return row, sw


class OptionsPanel(Gtk.Box):
    """Signing Options + Signatures list + status lines. Reparented between the side panel and the narrow 'Options' popover."""

    def __init__(self, on_visible, on_timestamp, on_settings, on_move, on_delete, on_select, on_assign, on_mode, form_cbs):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10, vexpand=True)
        self.mode = ModeSwitch(on_mode)
        self.form = FormPanel(*form_cbs)
        self._cb = (on_move, on_delete, on_select)
        self._assign = on_assign
        sec = Gtk.Label(label="Signing Options", xalign=0)
        sec.add_css_class("section")
        r1, self.visible_sw = _switch_row("view-reveal-symbolic", "Visible signature on PDF", on_visible, True)
        r2, self.ts_sw = _switch_row("alarm-symbolic", "Add timestamp", on_timestamp)
        self.hint = Gtk.Label(xalign=0, wrap=True, use_markup=True)
        self.hint.add_css_class("dim")
        self.hint.connect("activate-link", lambda *_: (on_settings(), True)[1])
        self.sig_title = Gtk.Label(xalign=0)
        self.sig_title.add_css_class("section")
        self.sigs = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        scroll = Gtk.ScrolledWindow(child=self.sigs, vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER, min_content_height=40)
        self.status = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.r1, self._gen = r1, (self.sig_title, scroll)
        for w in (self.mode, sec, r1, r2, self.hint, Gtk.Separator(), self.sig_title, scroll, self.form, self.status):
            self.append(w)
        self.set_mode("general")
        self.set_timestamp_available(False)

    def set_mode(self, mode):
        """MCA: no 'Visible signature' toggle, no box list: the form-field list instead."""
        mca = mode == "mca"
        self.mode.set_mode(mode)
        self.r1.set_visible(not mca)
        for w in self._gen:
            w.set_visible(not mca)
        self.form.set_visible(mca)

    def set_timestamp_available(self, url_set):
        self.ts_sw.set_sensitive(url_set)
        if not url_set:
            self.ts_sw.set_active(False)
        self.hint.set_visible(not url_set)
        self.hint.set_markup('Needs a trusted timestamp server: <a href="settings">set one in Settings</a>.')

    def set_signatures(self, items, certs, active, locked):
        """certs: the scanned tokens. A box whose signer is not among them keeps its row, marked 'token removed'."""
        live = {c.key for c in certs}
        on_move, on_delete, on_select = self._cb
        while c := self.sigs.get_first_child():
            self.sigs.remove(c)
        invisible = not self.visible_sw.get_active()
        self.sig_title.set_text("Signatures (1)" if invisible else f"Signatures ({len(items)})")
        if invisible:
            self.sigs.append(self._row("Invisible signature", "", None, False, False))
            return
        if not items:
            hint = Gtk.Label(label="Drag on the page to place a signature box.", xalign=0, wrap=True)
            hint.add_css_class("dim")
            self.sigs.append(hint)
        for i, p in enumerate(items):
            gone = bool(p.signer) and p.signer not in live
            row = self._row(f"{i + 1}.  Page {p.page + 1}", p.cert.cn if p.cert else "", i, True, locked, i == active, len(items), certs, p, gone)
            self.sigs.append(row)

    def _row(self, text, chip, i, editable, locked, active=False, n=0, certs=(), p=None, gone=False):
        row = Gtk.Box(spacing=6)
        row.add_css_class("sigrow")
        lab = Gtk.Label(label=text, xalign=0, hexpand=True, ellipsize=Pango.EllipsizeMode.END)
        row.append(lab)
        if chip and editable:  # the signer chip is a menu button: the one deliberate way to change THIS box's signer
            label = Gtk.Label(label="token removed" if gone else chip, ellipsize=Pango.EllipsizeMode.END, max_width_chars=16)
            tip = f"{chip}: token removed" if gone else f"Change signer of box {i + 1}"
            c = Gtk.MenuButton(child=label, has_frame=False, sensitive=not locked, tooltip_text=tip)
            c.add_css_class("chip")
            if gone:  # muted: the colour is set on label.dim, so both carry the class
                c.add_css_class("dim")
                label.add_css_class("dim")
            pop = Gtk.Popover()
            pop.set_child(signer_list(certs, p.signer, lambda cert: (pop.popdown(), self._assign(i, cert))))
            c.set_popover(pop)
            row.append(c)
        if editable:
            on_move, on_delete, on_select = self._cb
            click = Gtk.GestureClick()
            click.connect("pressed", lambda *_: on_select(i))
            lab.add_controller(click)
            for icon, tip, fn, ok in (
                ("go-up-symbolic", "Sign earlier", lambda: on_move(i, -1), i > 0),
                ("go-down-symbolic", "Sign later", lambda: on_move(i, 1), i < n - 1),
                ("user-trash-symbolic", "Delete", lambda: on_delete(i), True),
            ):
                b = Gtk.Button(icon_name=icon, tooltip_text=tip, has_frame=False, sensitive=ok and not locked)
                b.connect("clicked", lambda _b, f=fn: f())
                row.append(b)
        return row

    def set_status(self, lines):
        """lines: [(text, level warn|error|info, tooltip)]"""
        while c := self.status.get_first_child():
            self.status.remove(c)
        for text, level, tip in lines:
            lab = Gtk.Label(label=text, xalign=0, wrap=True, tooltip_text=tip or None)
            lab.add_css_class({"warn": "warnline", "error": "errline"}.get(level, "dim"))
            self.status.append(lab)


def sign_button(on_sign):
    b = Gtk.Button(sensitive=False, tooltip_text="Sign every placed box, in badge order (Ctrl+S)")
    b.add_css_class("primary")
    row = Gtk.Box(spacing=10, halign=Gtk.Align.CENTER)
    row.append(Gtk.Image(icon_name="document-edit-symbolic"))
    row.append(Gtk.Label(label="Sign Document"))
    k = Gtk.Label(label="Ctrl S")
    k.add_css_class("kbd")
    row.append(k)
    b.set_child(row)
    b.connect("clicked", lambda *_: on_sign())
    return b


class SidePanel(Gtk.Box):
    WIDTH = 340

    def __init__(self, card, refresh_btn, options, sign_btn):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.add_css_class("sidepanel")
        self.set_size_request(self.WIDTH, -1)
        self.set_hexpand(False)
        title = Gtk.Label(label="DSC Token", xalign=0)
        title.add_css_class("section")
        top = Gtk.Box(spacing=8)
        top.append(card)
        top.append(refresh_btn)
        self.options_slot = Gtk.Box(vexpand=True)
        for w in (title, top, Gtk.Separator(), self.options_slot, sign_btn):
            self.append(w)

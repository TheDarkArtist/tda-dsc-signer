"""The narrow-window strip (~28px): [Open] [signer ▾] [refresh] [Options] [p3/12] [gear] [SIGN]."""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, Pango

from .signerpicker import SignerPicker


class Strip(Gtk.Box):
    def __init__(self, on_open, on_signer, on_sign, on_refresh, on_settings):
        super().__init__(spacing=4)
        self.add_css_class("strip")
        self.open_btn = Gtk.Button(icon_name="document-open-symbolic", tooltip_text="Open PDF (Ctrl+O)")
        self.open_btn.connect("clicked", lambda *_: on_open())
        self.picker = SignerPicker(on_signer)
        self.refresh_btn = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text="Rescan tokens (F5)")
        self.refresh_btn.connect("clicked", lambda *_: on_refresh())
        self.note = Gtk.Label(visible=False, ellipsize=Pango.EllipsizeMode.END, max_width_chars=34)
        self.options_pop = Gtk.Popover()
        self.options_btn = Gtk.MenuButton(
            icon_name="open-menu-symbolic", popover=self.options_pop, tooltip_text="Signing options and the signature list"
        )
        self.gear = Gtk.Button(icon_name="emblem-system-symbolic", tooltip_text="Settings (Ctrl+,)")
        self.gear.connect("clicked", lambda *_: on_settings())
        self.pageno = Gtk.Label(label="", visible=False)
        self.pageno.add_css_class("pageno")
        self.sign_btn = Gtk.Button(label="SIGN", sensitive=False, tooltip_text="Sign every placed box, in badge order (Ctrl+S)")
        self.sign_btn.add_css_class("suggested-action")
        self.sign_btn.connect("clicked", lambda *_: on_sign())
        for w in (self.open_btn, self.picker, self.refresh_btn, self.note, self.options_btn, self.pageno, self.gear, self.sign_btn):
            self.append(w)

    def set_page(self, i, n):
        self.pageno.set_text(f"p{i + 1}/{n}")
        self.pageno.set_visible(n > 0)

    def set_count(self, n):
        self.sign_btn.set_label(f"SIGN {n}" if n else "SIGN")

    def set_note(self, text, tooltip="", level="error"):
        """Non-modal status next to the refresh button; level error (red) | warn (yellow) | info (plain). '' hides it."""
        for c, name in (("errline", "error"), ("warnline", "warn")):
            (self.note.add_css_class if level == name else self.note.remove_css_class)(c)
        self.note.set_text(text)
        self.note.set_tooltip_text(tooltip or None)
        self.note.set_visible(bool(text))

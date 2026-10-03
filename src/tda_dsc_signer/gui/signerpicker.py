"""Compact signer dropdown. Detecting/none states live inside it; expired certificates are red; tooltip carries the details."""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, Pango

from . import state

DETECTING, NONE, REMOVED = "detecting tokens…", "no token found", "(token removed)"


class SignerPicker(Gtk.Box):
    def __init__(self, on_change):
        super().__init__(spacing=2, hexpand=True)
        self._certs, self._on_change, self._quiet, self._off = [], on_change, False, 0  # _off=1: a placeholder row precedes the certs
        self.spinner = Gtk.Spinner(spinning=True)
        self.drop = Gtk.DropDown(model=Gtk.StringList.new([DETECTING]), sensitive=False, hexpand=True)
        self.drop.set_factory(self._make_factory())
        self.drop.connect("notify::selected", lambda *_: self._changed(True))
        self.append(self.spinner)
        self.append(self.drop)

    def _make_factory(self):
        factory = Gtk.SignalListItemFactory()
        factory.connect("setup", lambda f, li: li.set_child(Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.END, width_chars=1)))
        factory.connect("bind", self._bind)
        return factory

    def select_key(self, key):
        """Mirror a selection made in the other presentation (no callback)."""
        c = self.cert
        if self._certs and not (c and c.key == key) and key in [x.key for x in self._certs]:
            self._quiet = True
            self.drop.set_selected(state.index_for(self._certs, key) + self._off)
            self._quiet = False
            self.drop.set_tooltip_text(state.signer_tooltip(self.cert))

    def _bind(self, _f, item):
        label = item.get_child()
        label.set_text(item.get_item().get_string())
        pos = item.get_position() - self._off
        expired = bool(self._certs) and 0 <= pos < len(self._certs) and self._certs[pos].expired()
        (label.add_css_class if expired else label.remove_css_class)("error")

    def _changed(self, user=False):
        """user=True only for a selection made by the person (not for a rescan rebuilding the list)."""
        if self._quiet:
            return
        c = self.cert
        self.drop.set_tooltip_text(state.signer_tooltip(c) if c else None)
        self._on_change(user)

    def _show_status(self, text, busy):
        self._certs, self._off = [], 0
        self.drop.set_model(Gtk.StringList.new([text]))
        self.drop.set_sensitive(False)
        self.spinner.set_visible(busy)
        self.spinner.set_spinning(busy)
        self.drop.set_tooltip_text(None)

    def detecting(self):
        self._show_status(DETECTING, True)

    def scanning(self, on):
        """Spinner while a rescan runs; the list stays so the selection is not lost."""
        self.spinner.set_visible(on)
        self.spinner.set_spinning(on)

    def problem(self, text, tip=""):
        """The scan failed in a typed way (driver busy, ...): say so instead of claiming there are no tokens."""
        self._show_status(text, False)
        self.drop.set_tooltip_text(tip or None)

    def none(self, why=""):
        self._show_status(NONE, False)
        self.drop.set_tooltip_text(why or None)

    def set_certs(self, certs, preferred_key="", allow_none=False):
        """allow_none: leave NOTHING selected when preferred_key is absent (the chosen token was unplugged)."""
        self._certs = list(certs)
        self.scanning(False)
        self._quiet = True  # rebuilding the model resets the selection; report only the final one
        absent = allow_none and preferred_key not in [c.key for c in self._certs]
        self._off = 1 if absent else 0  # GtkDropDown re-selects row 0 when asked for 'nothing', so a placeholder row stands for it
        rows = ([REMOVED] if absent else []) + [state.signer_label(c) for c in self._certs]
        self.drop.set_model(Gtk.StringList.new(rows))
        self.drop.set_selected(0 if absent else state.index_for(self._certs, preferred_key))
        self._quiet = False
        self.drop.set_sensitive(bool(self._certs))
        self._changed()

    @property
    def certs(self):
        return list(self._certs)

    @property
    def cert(self):
        i = self.drop.get_selected() - self._off
        return self._certs[i] if 0 <= i < len(self._certs) else None


def signer_list(certs, current_key, pick):
    """Menu body for changing ONE box's signer: a flat button per scanned token (CN + token label), the current one ticked."""
    col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
    for c in certs:
        b = Gtk.Button(label=f"{'✓ ' if c.key == current_key else ''}{c.cn} · {c.token}", has_frame=False, halign=Gtk.Align.FILL)
        b.get_child().set_xalign(0)
        b.connect("clicked", lambda _b, c=c: pick(c))
        col.append(b)
    if not certs:
        col.append(Gtk.Label(label="no token connected", sensitive=False))
    return col

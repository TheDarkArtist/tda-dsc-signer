"""The right-pane 'DSC Token' card: a dropdown whose rows are [status dot | CN / token model / Valid till]. Same API as SignerPicker."""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, Pango

from . import state
from .signerpicker import SignerPicker


def _lbl(css):
    lab = Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.END, width_chars=1, hexpand=True)
    lab.add_css_class(css)
    return lab


class TokenCard(SignerPicker):
    status_text = ""

    def __init__(self, on_change):
        super().__init__(on_change)
        self.add_css_class("tokencard")
        self.drop.add_css_class("tokenbtn")

    def _make_factory(self):
        factory = Gtk.SignalListItemFactory()
        factory.connect("setup", self._setup)
        factory.connect("bind", self._bind)
        return factory

    def _setup(self, _f, li):
        row = Gtk.Box(spacing=10)
        dot = Gtk.Box(valign=Gtk.Align.START, margin_top=5)
        dot.add_css_class("dot")
        col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, hexpand=True)
        for css in ("tk-name", "tk-model", "tk-valid"):
            col.append(_lbl(css))
        row.append(dot)
        row.append(col)
        li.set_child(row)

    def _bind(self, _f, item):
        row = item.get_child()
        dot, col = row.get_first_child(), row.get_last_child()
        name, model, valid = col.get_first_child(), col.get_first_child().get_next_sibling(), col.get_last_child()
        pos = item.get_position() - self._off
        c = self._certs[pos] if self._certs and 0 <= pos < len(self._certs) else None
        for css in ("ok", "warn", "err"):
            dot.remove_css_class(css)
        if c is None:  # detecting / none / removed / problem: the string row
            name.set_text(item.get_item().get_string())
            model.set_text("")
            valid.set_text("")
            dot.add_css_class("err")
            dot.set_tooltip_text(self.status_text or "No token selected")
            return
        lvl, why = state.token_status(c)
        dot.add_css_class(lvl)
        dot.set_tooltip_text(why)
        name.set_text(c.cn)
        model.set_text(state.model_text(c))
        valid.set_text(f"Valid till {state.valid_till(c)}")

    def set_status(self, override):
        """override: (level, text) from state.scan_status or None. 'stale' turns every dot yellow in CSS (scanning / busy / count low)."""
        (self.add_css_class if override and override[0] == "warn" else self.remove_css_class)("stale")
        self.status_text = override[1] if override else ""
        self.drop.set_tooltip_text(override[1] if override else state.signer_tooltip(self.cert) if self.cert else None)

"""MCA mode widgets: the 'MCA | General' switch and the 'Form signatures (n)' list."""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, Pango

from . import formstate
from .signerpicker import signer_list


class ModeSwitch(Gtk.Box):
    """Segmented 'MCA | General' switch. set_mode() never calls back; only a click does."""

    def __init__(self, on_mode):
        super().__init__(css_classes=["linked"], homogeneous=True)
        self._quiet = True  # the initial set_active below is not a user click
        self.btns = {}
        first = None
        for key, text in (("mca", "MCA"), ("general", "General")):
            b = Gtk.ToggleButton(label=text, group=first, tooltip_text=f"{text} mode")
            first = first or b
            b.connect("toggled", lambda w, k=key: w.get_active() and not self._quiet and on_mode(k))
            self.btns[key] = b
            self.append(b)
        self.btns["general"].set_active(True)
        self._quiet = False

    def set_mode(self, mode):
        self._quiet = True
        self.btns[mode].set_active(True)
        self._quiet = False


class FormPanel(Gtk.Box):
    def __init__(self, on_check, on_select, on_assign, on_general):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6, vexpand=True)
        self._cb = (on_check, on_select, on_assign)
        self.title = Gtk.Label(xalign=0)
        self.title.add_css_class("section")
        self.list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.empty = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.empty_lbl = Gtk.Label(label="No signature fields in this PDF", xalign=0, wrap=True)
        self.empty_lbl.add_css_class("dim")
        self.to_general = Gtk.Button(label="Switch to General", halign=Gtk.Align.START)
        self.to_general.connect("clicked", lambda *_: on_general())
        self.empty.append(self.empty_lbl)
        self.empty.append(self.to_general)
        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        inner.append(self.empty)
        inner.append(self.list)
        scroll = Gtk.ScrolledWindow(child=inner, vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER, min_content_height=150)
        for w in (self.title, scroll):
            self.append(w)
        self.rows_w = []  # per row: dict(check, label, line, chip, box): read by tests

    def set_rows(self, rows, signed, active, locked):
        on_check, on_select, on_assign = self._cb
        while c := self.list.get_first_child():
            self.list.remove(c)
        self.rows_w = []
        self.title.set_text(f"Form signatures ({len(rows)})")
        self.empty.set_visible(not rows)
        for r in rows:
            self._row(r, r.field.name == active, locked, on_check, on_select, on_assign)
        for f in signed:
            lab = Gtk.Label(label=f"Signed: {formstate.shown(f)}", xalign=0, ellipsize=Pango.EllipsizeMode.MIDDLE, tooltip_text=f.name)
            lab.add_css_class("dim")
            self.list.append(lab)

    def _row(self, r, active, locked, on_check, on_select, on_assign):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        box.add_css_class("sigrow")
        if active:
            box.add_css_class("active")
        top = Gtk.Box(spacing=8)
        check = Gtk.CheckButton(active=r.checked, sensitive=r.enabled and not locked)
        check.connect("toggled", lambda w, n=r.field.name: on_check(n, w.get_active()))
        num = Gtk.Label(label=str(r.n))
        num.add_css_class("badge")
        label = Gtk.Label(label=r.label, xalign=0, hexpand=True, ellipsize=Pango.EllipsizeMode.END, tooltip_text=r.field.name)
        click = Gtk.GestureClick()
        click.connect("pressed", lambda *_, n=r.field.name: on_select(n))
        label.add_controller(click)
        for w in (check, num, label):
            top.append(w)
        line_box = Gtk.Box(spacing=6, margin_start=26)
        mark = Gtk.Label(label="✓" if r.kind == "match" else "")
        mark.add_css_class("row-ok")
        line = Gtk.Label(label=r.text, xalign=0, hexpand=True, wrap=True)
        line.add_css_class({"match": "row-ok", "none": "warnline", "gone": "errline"}.get(r.kind, "dim"))
        line_box.append(mark)
        line_box.append(line)
        chip = None
        if r.enabled and (r.kind == "unknown" or len(r.cands) > 1):
            chip = Gtk.MenuButton(label="Change…", has_frame=False, sensitive=not locked, tooltip_text="Tokens allowed for this field")
            chip.add_css_class("chip")
            pop = Gtk.Popover()
            pop.set_child(signer_list(r.cands, r.cert.key if r.cert else "", lambda c, n=r.field.name: (pop.popdown(), on_assign(n, c))))
            chip.set_popover(pop)
            line_box.append(chip)
        box.append(top)
        box.append(line_box)
        self.list.append(box)
        self.rows_w.append(dict(check=check, label=label, line=line, chip=chip, box=box))

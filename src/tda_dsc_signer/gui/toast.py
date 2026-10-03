"""Bottom toast: one line, click to expand the four verification rows; Open / Show in folder; yellow warnings."""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gio, Gtk

MARK = {"ok": "✓", "info": "ℹ", "unchecked": "–", "fail": "✗"}


class Toast(Gtk.Box):
    def __init__(self, parent_window):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, valign=Gtk.Align.END, visible=False)
        self.add_css_class("toast")
        self._win, self._path = parent_window, None
        top = Gtk.Box(spacing=6)
        self.line = Gtk.Label(xalign=0, hexpand=True, ellipsize=3, single_line_mode=True, selectable=False)  # 3 = Pango END
        self.open_btn = Gtk.Button(label="Open")
        self.folder_btn = Gtk.Button(label="Show in folder")
        close = Gtk.Button(icon_name="window-close-symbolic")
        close.connect("clicked", lambda *_: self.dismiss())
        self.open_btn.connect("clicked", lambda *_: self._launch(False))
        self.folder_btn.connect("clicked", lambda *_: self._launch(True))
        for w in (self.line, self.open_btn, self.folder_btn, close):
            top.append(w)
        click = Gtk.GestureClick()
        click.connect("released", lambda *_: self.details.set_reveal_child(not self.details.get_reveal_child()))
        self.line.add_controller(click)
        self.warns = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.rows = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.details = Gtk.Revealer(child=self.rows)
        for w in (top, self.warns, self.details):
            self.append(w)

    def _clear(self, box):
        while c := box.get_first_child():
            box.remove(c)

    def dismiss(self):
        self.set_visible(False)
        self.details.set_reveal_child(False)

    def show_text(self, text, level="info", path=None):
        """Plain message (errors etc.): level ok | info | error. A path adds Open / Show in folder (partial results)."""
        self._reset(text, path)
        self.line.remove_css_class("errline")
        self.line.remove_css_class("warnline")
        if level in ("error", "warn"):
            self.line.add_css_class("errline" if level == "error" else "warnline")
        self.line.set_tooltip_text(text)
        self.set_visible(True)

    def show_result(self, verify_result, path, warnings=(), notes=(), headline=""):
        self._reset(f"{headline}  ·  {verify_result.detail}" if headline else verify_result.detail, path)
        for f in getattr(verify_result, "fields", ()):  # MCA forms: one line per signature field
            pm = {True: "PAN matches", False: "PAN does NOT match", None: ""}[f.pan_match]
            lab = Gtk.Label(label=f"{f.name}: " + (f"{f.signer}" + (f" · {pm}" if pm else "") if f.signer else "not signed"), xalign=0, wrap=True)
            lab.add_css_class("row-fail" if f.pan_match is False else "row-info")
            self.rows.append(lab)
        for r in verify_result.rows:
            lab = Gtk.Label(label=f"{MARK[r.state]} {r.label}: {r.detail}", xalign=0, wrap=True)
            lab.add_css_class(f"row-{r.state}")
            self.rows.append(lab)
        for w in warnings:
            lab = Gtk.Label(label=f"⚠ {w}", xalign=0, wrap=True)
            lab.add_css_class("warnline")
            self.warns.append(lab)
        for n in notes:  # plain info lines (e.g. 'using saved PIN')
            lab = Gtk.Label(label=n, xalign=0, wrap=True)
            lab.add_css_class("row-info")
            self.warns.append(lab)
        self.line.set_tooltip_text("Click for details")
        self.line.remove_css_class("errline")
        self.line.add_css_class("row-ok" if verify_result.ok else "row-fail")
        self.set_visible(True)

    def _reset(self, text, path):
        self._clear(self.rows)
        self._clear(self.warns)
        self.details.set_reveal_child(False)
        for c in ("row-ok", "row-fail"):
            self.line.remove_css_class(c)
        self.line.set_text(text)
        self._path = path
        self.open_btn.set_visible(bool(path))
        self.folder_btn.set_visible(bool(path))

    def _launch(self, folder):
        fl = Gtk.FileLauncher.new(Gio.File.new_for_path(self._path))
        (fl.open_containing_folder if folder else fl.launch)(self._win, None, None, None)

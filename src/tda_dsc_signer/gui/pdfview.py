"""Fit-to-width continuous page column. Drag on any page edits the shared Boxes (see boxes/boxoverlay)."""

import cairo
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")
gi.require_version("Poppler", "0.18")
from gi.repository import Gdk, GLib, Gtk, Poppler

from .. import geometry
from . import boxoverlay, state
from .signerpicker import signer_list

HANDLE_PX = boxoverlay.HANDLE_PX


class PageView(Gtk.DrawingArea):
    def __init__(self, index, page, stack):
        super().__init__(halign=Gtk.Align.CENTER, focusable=True)  # focus stays in the document so Enter/Esc reach the window
        self.index, self.page, self.stack = index, page, stack
        self.pw, self.ph = page.get_size()
        self.scale, self._inert = 1.0, False
        self._surface = None  # ponytail: one cached surface per viewed page, no eviction; evict if huge PDFs matter
        self.add_css_class("page")
        self.set_cursor_from_name("crosshair")
        self.set_draw_func(self._draw)
        g = Gtk.GestureDrag()
        g.connect("drag-begin", self._begin)
        g.connect("drag-update", lambda g, dx, dy: self._update(dx, dy))
        g.connect("drag-end", lambda g, dx, dy: self._end())
        self.add_controller(g)
        rc = Gtk.GestureClick(button=3)
        rc.connect("pressed", lambda c, n, x, y: self.stack.chip_menu(self, x, y))
        self.add_controller(rc)

    def set_scale(self, scale):
        if abs(scale - self.scale) < 1e-3 and self._surface is not None:
            return
        self.scale, self._surface = scale, None
        self.set_content_width(max(1, int(self.pw * scale)))
        self.set_content_height(max(1, int(self.ph * scale)))
        self.queue_draw()

    def _render(self):
        s = cairo.ImageSurface(cairo.FORMAT_ARGB32, max(1, int(self.pw * self.scale)), max(1, int(self.ph * self.scale)))
        c = cairo.Context(s)
        c.set_source_rgb(1, 1, 1)
        c.paint()
        c.scale(self.scale, self.scale)
        self.page.render(c)
        return s

    def _draw(self, _area, cr, _w, _h):
        self._surface = self._surface or self._render()
        cr.set_source_surface(self._surface, 0, 0)
        cr.paint()
        bx = self.stack.boxes
        for page, rect, n, active in self.stack.marks():  # MCA mode: empty form fields (and no General boxes)
            if page == self.index:
                boxoverlay.draw_field(cr, rect, self.ph, self.scale, n, active)
        for i, p in enumerate(bx.items if not self.stack.marks_on() else ()):
            if p.page == self.index:
                boxoverlay.draw(cr, p.box, self.ph, self.scale, self.stack.text_for(p), i + 1, i == bx.active, self.stack.name_for(p))

    def _begin(self, g, x, y):
        self.grab_focus()
        self._inert = self.stack.marks_on()
        if self._inert:  # form fields are selected by click, never dragged or resized
            self.stack.click_field(self, x, y)
            return
        self.stack.begin_drag(self, (x / self.scale, self.ph - y / self.scale))

    def _update(self, dx, dy):
        if self._inert:
            return
        self.stack.boxes.update(dx / self.scale, -dy / self.scale)
        self.stack.refresh()

    def _end(self):
        if self._inert:
            return
        self.stack.boxes.end()
        self.stack.refresh()
        self.stack.changed()


class PdfStack(Gtk.ScrolledWindow):
    """on_change(): selection changed. on_page(index, count): visible page changed."""

    def __init__(self, boxes, on_change, on_page=lambda i, n: None):
        super().__init__(vexpand=True, hexpand=True, hscrollbar_policy=Gtk.PolicyType.AUTOMATIC)
        self.boxes, self._on_change, self._on_page = boxes, on_change, on_page
        self.current_cert = lambda: None  # () -> TokenCert given to a newly drawn box (the dropdown's)
        self.name_for = lambda p: ""  # Placed -> chip text
        self.text_for = lambda p: ""  # Placed -> stamp preview text
        self.certs = lambda: []  # () -> scanned tokens, for the 'Change signer' menu
        self.assign = lambda i, cert: None  # (box index, TokenCert): explicit signer change
        self.marks = lambda: []  # () -> [(page0, rect, number, active)]: the form fields drawn in MCA mode
        self.marks_on = lambda: False  # True in MCA mode: no box drawing
        self.on_field = lambda name: None  # a field rectangle was clicked
        self.pages, self.zoom, self._shown = [], 1.0, -1
        self._col = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=state.GAP,
            margin_top=state.MARGIN,
            margin_bottom=state.MARGIN,
            margin_start=state.MARGIN,
            margin_end=state.MARGIN,
        )
        self._col.set_valign(Gtk.Align.START)  # a vertical box measured width-for-height warns otherwise
        self.set_child(self._col)
        self.get_child().set_scroll_to_focus(False)  # focusing a tall page must not scroll the viewport to its end
        self.get_hadjustment().connect("notify::page-size", lambda *_: GLib.idle_add(self._relayout_idle))
        self.get_vadjustment().connect("value-changed", lambda *_: self._track_page())
        scroll = Gtk.EventControllerScroll(flags=Gtk.EventControllerScrollFlags.VERTICAL)
        scroll.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
        scroll.connect("scroll", self._on_scroll)
        self.add_controller(scroll)

    # -- loading / layout ---------------------------------------------------
    def load(self, path):
        doc = Poppler.Document.new_from_file(GLib.filename_to_uri(path, None), None)
        while child := self._col.get_first_child():
            self._col.remove(child)
        self.pages = [PageView(i, doc.get_page(i), self) for i in range(doc.get_n_pages())]
        for p in self.pages:
            self._col.append(p)
        self._shown = -1
        self.relayout()
        self.get_vadjustment().set_value(0)

    def _relayout_idle(self):
        # not inside size-allocate: resizing children while the viewport allocates them squashed the column to the viewport height
        self.relayout()
        return False

    def relayout(self):
        avail = self.get_hadjustment().get_page_size() or self.get_width()
        if avail <= 0:
            return
        for p in self.pages:
            p.set_scale(state.fit_scale(avail, p.pw, self.zoom))
        self._track_page()

    def set_zoom(self, z):
        adj = self.get_vadjustment()
        frac = adj.get_value() / max(1.0, adj.get_upper())
        self.zoom = state.clamp_zoom(z)
        self.relayout()
        GLib.idle_add(lambda: adj.set_value(frac * adj.get_upper()) and False)

    def _on_scroll(self, ctl, _dx, dy):
        if not ctl.get_current_event_state() & Gdk.ModifierType.CONTROL_MASK:
            return False
        self.set_zoom(self.zoom * (state.ZOOM_STEP ** (-1 if dy > 0 else 1)))
        return True

    def _track_page(self):
        if not self.pages:
            return
        heights = [p.get_content_height() for p in self.pages]
        i = state.page_at(self.get_vadjustment().get_value() + self.get_height() / 2, heights)
        if i != self._shown:
            self._shown = i
            self._on_page(i, len(self.pages))

    def scroll_to(self, where):
        adj = self.get_vadjustment()
        step = adj.get_page_size() * 0.9
        target = {
            "home": adj.get_lower(),
            "end": adj.get_upper() - adj.get_page_size(),
            "pgup": adj.get_value() - step,
            "pgdn": adj.get_value() + step,
        }[where]
        adj.set_value(max(adj.get_lower(), min(target, adj.get_upper() - adj.get_page_size())))

    # -- form fields ---------------------------------------------------------
    def click_field(self, view, x, y):
        for page, rect, n, _a in reversed(self.marks()):
            if page == view.index:
                fx, fy, fw, fh = boxoverlay.field_px(rect, view.ph, view.scale)
                if fx <= x <= fx + fw and fy <= y <= fy + fh:
                    self.on_field(n)
                    return

    def scroll_to_field(self, page, rect):
        """Scroll so the field sits a third of the way down the viewport."""
        if not 0 <= page < len(self.pages):
            return
        v = self.pages[page]
        ok, b = v.compute_bounds(self._col)
        if not ok:
            return
        _x, y, _w, h = boxoverlay.field_px(rect, v.ph, v.scale)
        adj = self.get_vadjustment()
        adj.set_value(max(0, min(b.get_y() + y - adj.get_page_size() / 3, adj.get_upper() - adj.get_page_size())))

    # -- boxes -----------------------------------------------------------------
    def begin_drag(self, view, pt):
        c = self.current_cert()
        self.boxes.begin(view.index, pt, (view.pw, view.ph), HANDLE_PX / view.scale, c.key if c else "", c)
        self.redraw()

    def redraw(self):
        for p in self.pages:
            p.queue_draw()

    refresh = redraw

    def changed(self):
        self._on_change()

    def clear_boxes(self):
        self.boxes.clear()
        self.redraw()
        self._on_change()

    def remove_active(self):
        self.boxes.remove(self.boxes.active)
        self.redraw()
        self._on_change()

    def add_box(self, page, box, signer):
        """Place a stored box (page 0-based)."""
        if 0 <= page < len(self.pages):
            v = self.pages[page]
            self.boxes.add(page, geometry.clamp_box(box, v.pw, v.ph), signer)
            self.redraw()
            self._on_change()

    def chip_menu(self, view, x, y):
        """Right-click on a box: Move up / Move down / Change signer / Delete (its badge number is its signing order)."""
        if self.marks_on():
            return
        i = self.boxes.at(view.index, (x / view.scale, view.ph - y / view.scale), HANDLE_PX / view.scale)
        if i < 0 or self.boxes.locked:
            return
        self.boxes.active = i
        pop = Gtk.Popover(has_arrow=False)
        pop.set_parent(view)
        r = Gdk.Rectangle()  # keyword construction of this boxed type silently leaves the fields at 0
        r.x, r.y, r.width, r.height = int(x), int(y), 1, 1
        pop.set_pointing_to(r)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        for label, act in (
            ("Move up (earlier)", lambda: self.boxes.move_order(i, -1)),
            ("Move down (later)", lambda: self.boxes.move_order(i, 1)),
            ("Delete", lambda: self.boxes.remove(i)),
        ):
            b = Gtk.Button(label=label, has_frame=False)
            b.connect("clicked", lambda _b, a=act: (a(), pop.popdown(), self.redraw(), self._on_change()))
            box.append(b)
        change = Gtk.Button(label="Change signer…", has_frame=False)  # swaps this popover's content for the token list
        pick = lambda c: (pop.popdown(), self.assign(i, c))  # noqa: E731
        change.connect("clicked", lambda *_: pop.set_child(signer_list(self.certs(), self.boxes.items[i].signer, pick)))
        box.insert_child_after(change, box.get_first_child().get_next_sibling())  # after "Move down"
        pop.set_child(box)
        pop.connect("closed", lambda p: GLib.idle_add(p.unparent))
        pop.popup()
        self.redraw()

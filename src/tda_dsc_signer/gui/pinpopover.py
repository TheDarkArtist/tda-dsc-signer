"""PIN popover anchored under SIGN. One user action = one attempt: the popover never retries by itself."""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")
from gi.repository import Gdk, GLib, Gtk


class PinPopover(Gtk.Popover):
    """on_submit(pin|None, remember, confirm_final_try) is called once per click/Enter. show_error() keeps it open."""

    def __init__(self, anchor, on_submit, on_cancel=lambda: None, on_again=lambda: None, on_refresh=lambda: None):
        super().__init__(autohide=True, has_arrow=True)
        # parent is the button's CONTAINER, not the button: SIGN is insensitive while a run is busy and an insensitive parent
        # would make the whole popover (entry included) unusable
        self._anchor = anchor
        self.set_parent(anchor.get_parent())
        self.add_css_class("pin")
        self._on_submit, self._on_cancel, self._on_again, self._cert, self._submitted = on_submit, on_cancel, on_again, None, False
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.title = Gtk.Label(xalign=0, wrap=True, max_width_chars=34)
        self.warn = Gtk.Label(xalign=0, wrap=True, max_width_chars=34)
        self.warn.add_css_class("warnline")
        self.confirm = Gtk.CheckButton(label="I understand: last attempt")
        self.entry = Gtk.PasswordEntry(show_peek_icon=True, placeholder_text="Token PIN")
        self.remember = Gtk.CheckButton(label="Remember for this session")
        self.err = Gtk.Label(xalign=0, wrap=True, max_width_chars=34)
        self.err.add_css_class("errline")
        self.again = Gtk.Button(label="Try anyway", halign=Gtk.Align.END, visible=False)
        self.go = Gtk.Button(label="Sign", halign=Gtk.Align.END)
        self.go.add_css_class("suggested-action")
        for w in (self.title, self.warn, self.confirm, self.entry, self.remember, self.err, self.again, self.go):
            box.append(w)
        self.set_child(box)
        self.entry.connect("activate", lambda *_: self._submit())
        self.go.connect("clicked", lambda *_: self._submit())
        self.again.connect("clicked", lambda *_: self._try_anyway())
        self.confirm.connect("toggled", lambda *_: self._sync())
        self.connect("closed", lambda *_: self._closed())
        keys = Gtk.EventControllerKey()  # popover key events do not reach the window's controller
        keys.connect("key-pressed", lambda c, kv, kc, st: kv == Gdk.KEY_F5 and (on_refresh() or True))
        self.add_controller(keys)

    def ask(self, cert, count=1, error=None, remember_label="Remember for this session"):
        """remember_label: text of the remember checkbox; '' hides it."""
        self._cert, self._submitted = cert, False
        many = f" ({count} signatures with this token)" if count > 1 else ""
        self.title.set_text(f"PIN for '{cert.token}'\nsigning as {cert.cn}{many}")
        self.warn.set_text(cert.pin.warning())
        self.warn.set_visible(bool(cert.pin.warning()))
        self.confirm.set_visible(cert.pin.final_try)
        self.confirm.set_active(False)
        self.entry.set_visible(not cert.pin.protected_auth)
        self.entry.set_text("")
        self.remember.set_label(remember_label or "")
        self.remember.set_visible(bool(remember_label) and not cert.pin.protected_auth)
        self.remember.set_active(False)
        self.err.set_text("")
        self.err.set_visible(False)
        self.again.set_visible(False)
        self.title.set_text(self.title.get_text() + ("\nEnter the PIN on the token's own keypad/reader." if cert.pin.protected_auth else ""))
        self.set_busy(False)
        self._aim()
        self.popup()
        self._focus()
        if error:  # the run is paused here until the user acts: the next attempt is theirs, never ours
            (self.show_recent if error[0] == "recent" else self.show_error)(error[1])

    def retarget(self, anchor):
        """The layout changed: hang the popover on the other SIGN button."""
        if anchor is self._anchor:
            return
        self.popdown()
        self.unparent()
        self._anchor = anchor
        self.set_parent(anchor.get_parent())

    def _aim(self):
        ok, b = self._anchor.compute_bounds(self.get_parent())
        if ok:
            r = Gdk.Rectangle()  # keyword construction of this boxed type silently leaves x/y/width/height at 0
            r.x, r.y, r.width, r.height = int(b.get_x()), int(b.get_y()), int(b.get_width()), int(b.get_height())
            self.set_pointing_to(r)

    def _focus(self):
        if self._cert is not None:
            (self.go if self._cert.pin.protected_auth else self.entry).grab_focus()

    def _sync(self):
        c = self._cert
        ready = c is not None and (not c.pin.final_try or self.confirm.get_active())
        self.go.set_sensitive(ready and not self._busy)
        self.entry.set_editable(not self._busy)  # not set_sensitive: losing focus that way warns about a missing focus-out

    _busy = False

    def set_busy(self, busy):
        self._busy = busy
        self._sync()

    def show_error(self, text, retry=True):
        """Inline error; the entry is cleared (never keep a wrong PIN around). retry=False disables further attempts."""
        self.err.set_text(text)
        self.err.set_visible(True)
        self.entry.set_text("")
        self._submitted = False
        self.set_busy(False)
        if not retry:
            self.go.set_sensitive(False)
            self.entry.set_editable(False)
        else:
            GLib.idle_add(lambda: self.entry.grab_focus() and False)  # after the entry is sensitive again

    def show_recent(self, text):
        """A wrong PIN was entered moments ago: warn inline and offer an explicit 'Try anyway' (never automatic)."""
        self.show_error(text, retry=False)
        self.again.set_visible(True)

    def _try_anyway(self):
        self.again.set_visible(False)
        self.err.set_visible(False)
        self._submitted = True
        self.set_busy(True)
        self._on_again()

    def _submit(self):
        if self._busy or not self.go.get_sensitive():
            return
        pin = None if self._cert.pin.protected_auth else (self.entry.get_text() or None)
        if pin is None and not self._cert.pin.protected_auth:
            self.show_error("Enter the PIN.")
            return
        self._submitted = True
        self.set_busy(True)
        self._on_submit(pin, self.remember.get_active(), self.confirm.get_active())

    def _closed(self):
        if not self._submitted:
            self._on_cancel()

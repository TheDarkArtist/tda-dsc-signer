"""Theme: dark by default (the mockup), light when the system theme says so. Palette as @define-color, 10px cards, 12-13px type."""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")
from gi.repository import Gdk, Gtk

DARK = dict(bg="#0b1220", panel="#111a2b", card="#0e1626", line="#1f2a3d", text="#e6ebf5", dim="#8a96ad", canvas="#080d18", field="#17223a")
LIGHT = dict(bg="#eef1f6", panel="#ffffff", card="#f6f8fb", line="#d5dbe6", text="#18202e", dim="#5d6a80", canvas="#d9dee8", field="#ffffff")
ACCENT, OK, WARN, ERR = "#2f6fed", "#2ecc71", "#f2b134", "#ef5350"

CSS = (
    """
window.app { background: @bg; color: @text; }
window.app label { color: @text; font-size: 13px; }
.dim, window.app label.dim { color: @dim; font-size: 12px; }
.header { padding: 12px 16px 6px 16px; }
.header .title, .settingspage .title { font-size: 20px; font-weight: 700; }
.header .subtitle { color: @dim; font-size: 12px; }
.logo { min-width: 44px; min-height: 44px; }
.card { background: @panel; border: 1px solid @line; border-radius: 10px; padding: 10px 14px; }
.sidepanel { background: @panel; border: 1px solid @line; border-radius: 10px; padding: 14px; }
.section { font-size: 15px; font-weight: 700; margin-top: 4px; }
.canvas { background: @canvas; border: 1px solid @line; border-radius: 10px; }
.page { box-shadow: 0 2px 10px rgba(0,0,0,0.65); }
.filename { font-size: 14px; font-weight: 600; }
button.flat-card, window.app button.flat-card { background: @card; border: 1px solid @line; border-radius: 8px; padding: 8px 14px;
  color: @text; box-shadow: none; }
button.iconbtn.on, window.app button.iconbtn.on { background: @field; border-color: #2f6fed; }
button.iconbtn, window.app button.iconbtn { background: @card; border: 1px solid @line; border-radius: 8px;
  min-width: 38px; min-height: 38px; padding: 0; color: @text; box-shadow: none; }
.tokencard dropdown { min-width: 0; }
.tokencard dropdown > button, .tokencard dropdown > button.toggle { background: @card; border: 1px solid @line;
  border-radius: 8px; padding: 8px 10px; box-shadow: none; }
.tokencard .dot { min-width: 12px; min-height: 12px; border-radius: 6px; }
.dot.ok { background: """
    + OK
    + """; } .dot.warn { background: """
    + WARN
    + """; } .dot.err { background: """
    + ERR
    + """; }
.tokencard.stale .dot.ok { background: """
    + WARN
    + """; }
.tk-name { font-weight: 600; font-size: 13px; } .tk-model, .tk-valid { color: @dim; font-size: 12px; }
separator { background: @line; min-height: 1px; }
window.app switch { background: @field; border: 1px solid @line; min-width: 44px; min-height: 24px; }
window.app switch:checked { background: """
    + ACCENT
    + """; }
window.app switch slider { background: white; min-width: 20px; min-height: 20px; }
button.primary, window.app button.primary { background: """
    + ACCENT
    + """; color: white; border-radius: 8px; padding: 12px; font-size: 15px; font-weight: 700; box-shadow: none; border: none; }
button.primary:disabled { background: @field; color: @dim; }
.kbd { background: rgba(255,255,255,0.18); border-radius: 5px; padding: 1px 6px; font-size: 11px; }
.sigrow { background: @card; border: 1px solid @line; border-radius: 8px; padding: 4px 8px; }
.sigrow.active { border-color: #2f6fed; }
.badge { background: #2f6fed; color: white; border-radius: 9px; min-width: 18px; min-height: 18px; font-size: 11px; font-weight: 700; }
.linked button.text-button:checked, window.app .linked button:checked { background: #2f6fed; color: white; }
.chip { background: @field; border-radius: 9px; padding: 0 8px; font-size: 11px; }
.strip { padding: 2px 4px; min-height: 0; background: @panel; }
.strip button, .strip dropdown button, .strip label { font-size: 12px; }
.strip button { padding: 1px 8px; min-height: 22px; min-width: 0; }
.strip dropdown { min-width: 0; }
.strip dropdown button { padding: 0 6px; min-height: 22px; }
.strip .pageno { padding: 0 6px; opacity: 0.75; }
.toast { padding: 6px 12px; font-size: 12px; background: @panel; border-top: 1px solid @line; }
.toast label { font-size: 12px; }
.toast button { padding: 0 6px; min-height: 20px; font-size: 12px; }
.row-ok { color: """
    + OK
    + """; } .row-info { opacity: 0.75; } .row-unchecked { opacity: 0.6; }
.row-fail { color: """
    + ERR
    + """; } .warnline, window.app label.warnline { color: """
    + WARN
    + """; } .errline, window.app label.errline { color: """
    + ERR
    + """; }
popover.pin contents { padding: 6px; }
popover.pin label, popover.pin check { font-size: 12px; }
window.app .settingspage entry, window.app .settingspage passwordentry { background: @field; color: @text; }
.banner { border-radius: 8px; padding: 8px 12px; background: @card; border: 1px solid @line; }
.banner.bad { border-color: """
    + WARN
    + """; }
"""
)


def system_prefers_light(theme_name):
    """Dark unless the system theme name says light (a hint: GTK4 has no portal read without libadwaita)."""
    n = (theme_name or "").lower()
    return "light" in n and "dark" not in n


def css(light=False):
    pal = LIGHT if light else DARK
    return "".join(f"@define-color {k} {v};\n" for k, v in pal.items()) + CSS


def install():
    settings = Gtk.Settings.get_default()
    light = system_prefers_light(settings.get_property("gtk-theme-name"))
    settings.set_property("gtk-application-prefer-dark-theme", not light)
    prov = Gtk.CssProvider()
    prov.load_from_data(css(light).encode())
    Gtk.StyleContext.add_provider_for_display(Gdk.Display.get_default(), prov, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

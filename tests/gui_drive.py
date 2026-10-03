"""Drive tests/gui_harness.py on a THROWAWAY Xvfb with xdotool, assert behaviours, save screenshots.

python tests/gui_drive.py OUT_DIR [WIDTH]          (aborts if DISPLAY would be :0)
"""

import json
import os
import pathlib
import subprocess
import sys
import time

OUT = os.path.abspath(sys.argv[1])
W = int(sys.argv[2]) if len(sys.argv) > 2 else 1100
H = 720
MODE = sys.argv[3] if len(sys.argv) > 3 else "basic"


class Done(Exception):
    pass


XDISPLAY = ":97"
HERE = os.path.dirname(os.path.abspath(__file__))
os.makedirs(OUT, exist_ok=True)
import conftest_path  # noqa: E402,F401
import isolate  # noqa: E402

ENV = {
    **os.environ,
    "DISPLAY": XDISPLAY,
    "FAKE_DETECT_SECONDS": "3",
    "GSK_RENDERER": "cairo",
    "FAKE_PINS": "unavail" if MODE == "settings-unavail" else "avail",
    **({"FAKE_FORMS": "1"} if MODE == "formfields" else {}),
}
isolate.isolate(os.path.join(OUT, "xdg"))  # the parent too, so nothing here can reach the real config
ENV.update({k: os.environ[k] for k in isolate.XDG})  # Vulkan on Xvfb stalls startup
checks = []
WID = []


def x(*cmd):
    """Run an X tool ONLY against the Xvfb display; refuse anything else."""
    assert ENV["DISPLAY"] == XDISPLAY != ":0", "DISPLAY must be the Xvfb"
    return subprocess.run(cmd, env=ENV, capture_output=True, text=True, check=False).stdout.strip()


def state():
    for _ in range(50):
        try:
            return json.load(open(os.path.join(OUT, "state.json")))
        except (OSError, ValueError):
            time.sleep(0.05)
    raise RuntimeError("no state")


def wait(pred, what, timeout=15):
    t = time.time()
    while time.time() - t < timeout:
        try:
            s = state()
            if pred(s):
                return s
        except RuntimeError:
            pass
        time.sleep(0.1)
    checks.append((False, f"TIMEOUT waiting for {what}"))
    print(f"FAIL TIMEOUT waiting for {what}; last state: {state() if os.path.exists(os.path.join(OUT, 'state.json')) else None}", flush=True)
    raise SystemExit(report())


def check(cond, what):
    checks.append((bool(cond), what))
    print(("PASS " if cond else "FAIL ") + what, flush=True)


def shot(name):
    x("import", "-window", "root", os.path.join(OUT, f"w{W}-{name}.png"))


def report():
    bad = [c for c in checks if not c[0]]
    print(f"\n{len(checks) - len(bad)}/{len(checks)} checks passed")
    return 1 if bad else 0


def click(px, py, button="1"):
    x("xdotool", "mousemove", str(px), str(py), "click", button)


def center(b):
    return b[0] + b[2] // 2, b[1] + b[3] // 2


def drag(x1, y1, x2, y2):
    x("xdotool", "mousemove", str(x1), str(y1), "mousedown", "1")
    for i in range(1, 7):
        x("xdotool", "mousemove", str(x1 + (x2 - x1) * i // 6), str(y1 + (y2 - y1) * i // 6))
    x("xdotool", "mouseup", "1")


def key(*k):
    x("xdotool", "key", "--clearmodifiers", *k)
    time.sleep(0.25)


import conftest  # noqa: E402


def touch(n):
    open(os.path.join(OUT, n), "w").close()


def rm(n):
    if os.path.exists(os.path.join(OUT, n)):
        os.unlink(os.path.join(OUT, n))


def pick_signer(index_down):
    if os.environ.get("SKIP_PICK"):
        return
    """Open the dropdown and move down `index_down` rows with the keyboard, then Return."""
    s = state()
    click(*center(s["bounds"]["card" if s["layout"] == "two" else "drop"]))
    time.sleep(0.5)
    for _ in range(abs(index_down)):
        key("Down" if index_down > 0 else "Up")
    key("Return")
    time.sleep(0.5)
    x("xdotool", "windowfocus", "--sync", WID[0])  # a GtkDropDown popup leaves the bare-Xvfb input focus confused (no WM here)
    time.sleep(0.3)


def place_three():
    """Three disjoint boxes on page 1, drawn one after another with Jane selected."""
    key("Home")
    s = state()
    px, py, pwid, _ = s["pages"][0]
    ys = [py + 80, py + 220, py + 360]
    for y in ys:
        drag(px + 40, y, px + 40 + pwid // 3, y + 70)
        time.sleep(0.3)


def ops(*todo):
    json.dump([list(t) for t in todo], open(os.path.join(OUT, "ops.tmp"), "w"))
    os.replace(os.path.join(OUT, "ops.tmp"), os.path.join(OUT, "ops"))
    time.sleep(0.6)


def draw_box_p1(dy=80):
    key("Home")
    px, py, pwid, _ = state()["pages"][0]
    drag(px + 30, py + dy, px + 30 + pwid // 3, py + dy + 60)
    time.sleep(0.4)


def run_twopane():
    s = state()
    b = s["bounds"]
    check(s["layout"] == "two" and s["options_parent"] == "Box", f"width {W}: two-pane layout, options in the side panel")
    check(330 <= b["side"][2] <= 350, f"right panel is ~340 px wide: {b['side'][2]}")
    check(b["side"][0] + b["side"][2] <= s["size"][0], "side panel inside the window (nothing clipped)")
    check(b["sign2"][1] + b["sign2"][3] <= b["side"][1] + b["side"][3], "Sign Document button anchored inside the bottom of the side panel")
    check(b["sign2"][1] > b["ts_sw"][1] + 100, "Sign button sits well below the options (bottom anchored)")
    check(b["filecard"][3] > 0 and b["header"][3] > 0, "file card and header are shown")
    check(s["card_dot_classes"] == [["ok"]], f"ready token: green dot {s['card_dot_classes']}")
    check(not s["ts_enabled"] and not s["ts_on"] and s["ts_hint"], "timestamp toggle OFF + disabled with a hint until a server URL is set")
    check(not s["sign2_enabled"], "Sign disabled with no box (visible mode)")
    check(
        s["card_name"] == "three.pdf" and s["card_btn"] == "Change File" and s["card_tip"].endswith("/three.pdf") and s["card_children"] == 2,
        f"file card: name only {s['card_name']!r}, button {s['card_btn']!r}, tooltip = full path",
    )
    shot("two-pane-empty")
    draw_box_p1()
    s = state()
    check(s["sign2_enabled"] and s["sig_title"] == "Signatures (1)" and len(s["boxes"]) == 1, f"box placed -> Sign enabled, {s['sig_title']}")
    shot("two-pane")
    click(*center(s["bounds"]["visible_sw"]))
    time.sleep(0.4)
    s = state()
    check(
        not s["visible_on"] and s["sig_title"] == "Signatures (1)" and s["sign2_enabled"],
        "Visible OFF: single 'Invisible signature' row, Sign enabled",
    )
    shot("two-pane-invisible")
    click(*center(s["bounds"]["refresh2"]))
    time.sleep(0.4)
    check(state()["scanning"] or state()["discovers"] >= 2, "refresh icon button rescans")


def run_invisible():
    s = state()
    click(*center(s["bounds"]["visible_sw"]))
    time.sleep(0.4)
    s = state()
    check(not s["boxes"] and s["sign2_enabled"] and not s["visible_on"], "invisible: no box needed, Sign enabled with a token selected")
    click(*center(s["bounds"]["sign2"]))
    s = wait(lambda s: s["pin_open"], "PIN popover")
    time.sleep(0.4)
    pt, sg = state()["pin_pointing"], state()["bounds"]["sign2"]
    sx = state()["bounds"]["side"][0]  # the popover's parent is the side panel: pointing coords are relative to it
    check(sg[0] <= sx + pt[0] + pt[2] // 2 <= sg[0] + sg[2], f"popover aimed at the side-panel Sign button {pt} (+{sx}) vs {sg}")
    shot("invisible-pin")
    x("xdotool", "type", "--delay", "30", "right-pin")
    key("Return")
    s = wait(lambda s: s["toast"] and s["attempts"] == 1, "invisible sign finished", 30)
    check(s["invisible_calls"] == ["S1"] and s["calls"][0][4] == "invisible", f"backend got visible=False: {s['calls']}")
    check(s["ts_urls"] == [""], f"no timestamp requested: {s['ts_urls']}")
    out = subprocess.run(["pdfsig", os.path.join(OUT, "signed-1.pdf")], capture_output=True, text=True, check=False, env=isolate.poppler_env()).stdout
    check(out.count("Signature #") == 1 and "Signature is Valid" in out, "signed file carries one valid signature")
    shot("invisible-done")


def run_settings(avail):
    pre = state()
    ops(("open",))
    s = wait(lambda s: s["settings_open"], "settings screen")
    check(s["toplevels"] == 1 and s["gear_on"], f"Settings is in-window: {s['toplevels']} top-level, gear shown active")
    st = s["settings"]
    check([r["serial"] for r in st["rows"]] == ["S1", "S2"], f"one row per scanned token: {[r['serial'] for r in st['rows']]}")
    check(
        all(r["mode"] == "ask" and r["state"] == "not saved" and not r["entry_sensitive"] for r in st["rows"]),
        "default: Ask every time, not saved, PIN entry off",
    )
    if avail:
        check(
            st["banner"].startswith("System keyring available") and not st["bad"] and all(r["keyring_enabled"] for r in st["rows"]),
            "store available: keyring option enabled",
        )
        ops(("mode", "S1", "session"), ("save", "S1", "right-pin"))
        st = state()["settings"]
        r = st["rows"][0]
        check(
            r["mode"] == "session" and r["state"] == "PIN saved" and r["pin_text_len"] == 0 and r["forget"],
            f"saved in session mode, entry cleared: {r}",
        )
        ops(("mode", "S1", "keyring"))
        r = state()["settings"]["rows"][0]
        check(r["mode"] == "keyring" and r["state"] == "not saved", "changing mode drops the PIN saved under the old mode (core rule)")
        ops(("save", "S1", "right-pin"))
        check(state()["settings"]["rows"][0]["state"] == "PIN saved", "saved to the keyring store")
        ops(("forget_all",))
        check(all(r["state"] == "not saved" for r in state()["settings"]["rows"]), "Forget all clears every row")
    else:
        check(
            st["bad"] and "No Secret Service provider" in st["banner"] and "KeePassXC" in st["banner"] and "gnome-keyring" in st["banner"],
            f"banner explains the two ways: {st['banner'][:90]!r}",
        )
        check(not any(r["keyring_enabled"] for r in st["rows"]), "keyring option disabled while no secret store runs")
        ops(("mode", "S1", "keyring"))
        r = state()["settings"]["rows"][0]
        check(r["mode"] == "ask", "forcing keyring without a store leaves the mode on Ask")
    ops(("url", "https://tsa.example.invalid/ts"))
    s = state()
    check(
        s["settings"]["url"] == "https://tsa.example.invalid/ts" and s["ts_enabled"] and s["ts_on"],
        "timestamp URL saved: main toggle becomes enabled and ON",
    )
    check(s["saved_ts"] == "https://tsa.example.invalid/ts", f"timestamp_url written through save_cfg: {s['saved_ts']!r}")
    if avail:  # 4 tokens: the page must scroll, nothing cut
        touch("plug")
        touch("two")
        key("F5")
        wait(lambda s: s["settings"] and len(s["settings"]["rows"]) == 4 and not s["scanning"], "4 token rows", 20)
    shot("settings")
    key("Escape")
    s = state()
    check(not s["settings_open"] and not s["gear_on"], "Esc goes back to the main screen")
    check(
        (s["path"], s["boxes"], s["vadj"][0], s["ts_on"], s["signer"]) == (pre["path"], pre["boxes"], pre["vadj"][0], True, pre["signer"]),
        "main-screen state (file, boxes, scroll, signer) survived the round trip",
    )
    key("ctrl+comma")
    check(state()["settings_open"], "Ctrl+, opens Settings again")
    ops(("toggle",))
    check(not state()["settings_open"], "the gear action toggles back")


def run_savedpin():
    ops(("open",), ("mode", "S1", "session"), ("save", "S1", "right-pin"), ("close",))
    draw_box_p1()
    key("ctrl+s")
    s = wait(lambda s: s["toast"] and s["attempts"] == 1, "signed with the saved PIN, no popover", 30)
    check(s["prompts"] == [] and not s["pin_open"], f"popover skipped: prompts {s['prompts']}")
    check(len(s["calls"]) == 1 and s["pin_lens"] == [9], "backend called once with the saved PIN")
    check(any("saved PIN" in t for t in s["toast_warns"]), f"toast says it used the saved PIN: {s['toast_warns']}")
    check(["saved_pin", "S1"] in s["pins_calls"], "saved PIN fetched through pins.saved_pin")
    # wrong saved PIN: removed, told, no retry
    ops(("open",), ("save", "S1", "wrong-pin"), ("close",))
    draw_box_p1(200)
    key("ctrl+s")
    s = wait(lambda s: s["toast"] and "Saved PIN was wrong" in s["toast"], "wrong saved PIN message", 30)
    check(s["attempts"] == 2 and len(s["calls"]) == 2, "exactly one more attempt: no retry after the wrong saved PIN")
    check(["on_pin_incorrect", "S1"] in s["pins_calls"] and s["prompts"] == [], "pins.on_pin_incorrect called; no popover")
    ops(("open",))
    r = state()["settings"]["rows"][0]
    check(r["state"] == "not saved" and r["mode"] == "ask", f"the saved PIN was removed and the mode dropped to Ask: {r}")
    ops(("close",))
    # a final-try token never auto-uses a saved PIN
    touch("plug")
    key("F5")
    wait(lambda s: s["dropdown_items"] == 3 and not s["scanning"], "plugged final-try token", 20)
    ops(("open",), ("mode", "S3", "session"), ("save", "S3", "right-pin"), ("close",))
    pick_signer(2)
    key("Delete")  # the earlier unsigned box keeps its own signer (S1): drop it so only the new final-try box is signed
    draw_box_p1(320)
    key("ctrl+s")
    s = wait(lambda s: s["pin_open"], "popover for the FINAL TRY token despite a saved PIN", 15)
    check(s["prompts"][-1][0] == "S3" and s["pin_confirm_visible"], "flags (final try) force the popover and its warning")
    shot("savedpin-final-try")
    key("Escape")


def run_overwrite():
    """Saved PIN + three boxes + an existing output file the user confirmed replacing: one start signs everything."""
    open(os.path.join(OUT, "signed-1.pdf"), "wb").write(b"old")
    ops(("open",), ("mode", "S1", "session"), ("save", "S1", "right-pin"), ("close",))
    place_three()
    check(len(state()["boxes"]) == 3, "three boxes placed")
    key("ctrl+s")
    s = wait(lambda s: s["toast"] and len(s["calls"]) >= 3 and s["path"].endswith("signed-1.pdf"), "run finished", 30)
    check(s["prompts"] == [] and len(s["save_names"]) == 1, f"no PIN prompt, one Save dialog: {s['prompts']} {s['save_names']}")
    check([c[4] for c in s["calls"]] == ["ok"] * 3 and "Stopped" not in s["toast"], f"all three signed, no stop: {s['toast'][:80]!r}")
    check(open(os.path.join(OUT, "signed-1.pdf"), "rb").read() != b"old" and not s["boxes"], "existing output replaced, boxes consumed")
    shot("overwrite-three-saved-pin")


def run_nofile():
    s = state()
    check(
        s["path"] is None and s["card_name"] == "No file open" and s["card_btn"] == "Open File", f"empty card: {s['card_name']!r} / {s['card_btn']!r}"
    )
    check(s["card_children"] == 2 and s["window_title"] == "DSC Signer", "card = name + button only (no icon); window title is 'DSC Signer'")
    shot("nofile")


def run_strip():
    s = state()
    b = s["bounds"]
    check(s["layout"] == "strip" and "Popover" in s["options_parent"], f"width {W}: strip layout, options in the popover")
    check(b["sign"][0] + b["sign"][2] <= s["size"][0] and b["gear"][0] + b["gear"][2] <= s["size"][0], "nothing clipped in the strip")
    click(*center(b["options_btn"]))
    time.sleep(0.7)
    shot("strip-options")
    key("Escape")


def run_signers():
    """A placed box keeps its signer; the dropdown only decides the next box; per-box change; unplugged signer is refused."""
    touch("two")
    key("F5")
    wait(lambda s: s["dropdown_items"] == 3 and not s["scanning"], "second valid token", 20)
    draw_box_p1(60)
    s = state()
    check([b[2] for b in s["boxes"]] == ["S1/01"] and "Jane Doe" in s["stamps"][0], f"box 1 drawn with Jane: {s['boxes']} / {s['stamps']}")
    pick_signer(2)
    draw_box_p1(200)
    s = state()
    check(s["signer"] == "Bob Smith", "dropdown now Bob")
    check([b[2] for b in s["boxes"]] == ["S1/01", "S4/01"], f"box 1 still Jane, box 2 (drawn after the change) is Bob: {[b[2] for b in s['boxes']]}")
    check(["Jane" in s["stamps"][0], "Bob" in s["stamps"][1]] == [True, True], f"stamp previews follow each box's own signer: {s['stamps']}")
    check(
        [c[0] for c in s["chips"]] == ["Jane Doe", "Bob Smith"] and not any(c[1] for c in s["chips"]),
        f"Signatures list rows show each box's own signer: {s['chips']}",
    )
    shot("20-two-signers")
    pick_signer(-1)  # dropdown to Old Signer, then back to Jane: still nothing moves
    pick_signer(-1)
    s = state()
    check(s["signer"] == "Jane Doe", "dropdown back on Jane")
    check([b[2] for b in s["boxes"]] == ["S1/01", "S4/01"] and "Jane" in s["stamps"][0], "further dropdown changes leave both boxes untouched")
    ops(("chip_pick", 0, "S4"))
    s = state()
    check(
        [b[2] for b in s["boxes"]] == ["S4/01", "S4/01"] and "Bob" in s["stamps"][0] and s["chips"][0][0] == "Bob Smith",
        "explicit chip-menu change moves box 1 to Bob (model, stamp, row)",
    )
    ops(("assign", 0, "S1"))
    check([b[2] for b in state()["boxes"]] == ["S1/01", "S4/01"], "chip handler back to Jane")
    # queue signing uses each box's own cert
    base = len(state()["calls"])
    click(*center(state()["bounds"]["sign" if state()["layout"] == "strip" else "sign2"]))
    s = wait(lambda s: s["pin_open"] and len(s["prompts"]) >= 1, "PIN prompt token 1")
    x("xdotool", "type", "--delay", "30", "right-pin")
    key("Return")
    s = wait(lambda s: len(s["prompts"]) >= 2 and s["pin_open"], "PIN prompt token 2")
    x("xdotool", "type", "--delay", "30", "right-pin")
    key("Return")
    s = wait(lambda s: len(s["calls"]) >= base + 2 and s["path"].endswith("signed-1.pdf"), "two-box run done", 30)
    check(
        [c[1] for c in s["calls"][base:]] == ["S1", "S4"], f"Backend.sign got Jane for box 1 and Bob for box 2: {[c[1] for c in s['calls'][base:]]}"
    )
    check(sorted(p[0] for p in s["prompts"]) == ["S1", "S4"], f"one PIN prompt per distinct token: {s['prompts']}")
    # token removed
    key("Home")
    draw_box_p1(60)
    draw_box_p1(200)
    s = state()
    check([b[2] for b in s["boxes"]] == ["S1/01", "S1/01"], "two fresh boxes with Jane")
    ops(("assign", 1, "S4"))
    touch("unplug1")
    key("F5")
    s = wait(lambda s: not s["scanning"] and s["signer"] is None, "Jane unplugged (dropdown cleared)", 20)
    check(
        [b[2] for b in s["boxes"]] == ["S1/01", "S4/01"] and s["chips"][0] == ["token removed", True] and s["chips"][1] == ["Bob Smith", False],
        f"box 1 kept (token removed, muted); box 2 unaffected: {s['chips']}",
    )
    check(any("not connected: Jane Doe" in t for t in s["sign_status"]), f"status line names the missing token: {s['sign_status']}")
    shot("21-token-removed")
    base = len(state()["calls"])
    click(*center(state()["bounds"]["sign" if state()["layout"] == "strip" else "sign2"]))
    s = wait(lambda s: "not connected" in s["toast"], "Sign refused")
    check(
        s["toast"] == "A box uses a token that is not connected: Jane Doe" and not s["pin_open"] and len(s["calls"]) == base,
        f"Sign refuses with a clear message, nothing silently switched: {s['toast']!r}",
    )
    check([b[2] for b in s["boxes"]] == ["S1/01", "S4/01"], "refusal changed no box")
    rm("unplug1")
    key("F5")
    s = wait(lambda s: not s["scanning"] and s["dropdown_items"] == 3, "Jane reconnected", 20)
    s = state()
    check(s["chips"][0] == ["Jane Doe", False] and not s["sign_status"], f"reconnect + refresh restores the row by key: {s['chips']}")


def field_center(s, page_idx, rect):
    """Screen point of a form field's centre (page widget bounds / 612 pt wide letter page)."""
    px, py, pw, _ = s["pages"][page_idx]
    sc = pw / 612
    return round(px + (rect[0] + rect[2]) / 2 * sc), round(py + (792 - (rect[1] + rect[3]) / 2) * sc)


def sign_with_pins(*serials):
    """Ctrl+S, then type the fake right PIN for each expected prompt (one per token)."""
    base = len(state()["prompts"])
    key("ctrl+s")
    for n, serial in enumerate(serials, base + 1):
        wait(
            lambda s, n=n, serial=serial: s["pin_open"] and len(s["prompts"]) >= n and s["prompts"][n - 1][0] == serial,
            f"PIN prompt {n} for {serial}",
        )
        time.sleep(0.4)
        x("xdotool", "type", "--delay", "30", "right-pin")
        key("Return")


def run_formfields():
    F1, F2 = "sigfield1_ABCDE1234F", "sigfield2_PQRST5678K"
    s = state()
    if s["layout"] == "strip":
        check(s["mode"] == "mca" and s["mode_active"] == {"mca": True, "general": False}, "strip: auto-selected MCA for the form")
        click(*center(s["bounds"]["options_btn"]))
        time.sleep(0.8)
        s = state()
        check(
            s["mode_btns"]["mca"] is not None and s["form_title"] == "Form signatures (2)",
            f"strip: switch is the first item of Options; {s['form_title']}",
        )
        check(len(s["form_rows"]) == 2 and s["sign_label"] == "SIGN 1", f"strip: 2 rows, 1 checked -> {s['sign_label']!r}")
        shot("strip-options-mca")
        click(*center(s["mode_btns"]["general"]))
        time.sleep(0.6)
        s = state()
        check(s["mode"] == "general" and not s["marks"] and s["gen_list_shown"], "strip: General via the switch")
        shot("strip-options-general")
        key("Escape")
        return
    # ---- A: auto-detect, rows, marks (Jane holds field 2's PAN; no token holds field 1's)
    check(s["mode"] == "mca" and s["mode_active"] == {"mca": True, "general": False}, f"auto: >=1 empty field -> MCA ({s['mode']})")
    check(s["form_title"] == "Form signatures (2)" and [f[0] for f in s["fields_loaded"]] == [F1, F2], f"rows: {s['form_title']}")
    r1, r2 = s["form_rows"]
    check(r1["label"] == "Page 7 · ABCD…1234F" and r1["tip"] == F1 and not r1["enabled"] and not r1["checked"], f"row 1 disabled+unchecked: {r1}")
    check("No attached token matches this PAN" in r1["line"], f"row 1 line: {r1['line']!r}")
    check(
        r2["label"] == "Page 8 · PQRS…5678K" and r2["enabled"] and r2["checked"] and r2["line"] == "Jane Doe · PAN matches",
        f"row 2 matched+checked: {r2}",
    )
    check(not s["visible_sw_shown"] and not s["gen_list_shown"], "MCA: no 'Visible signature' toggle and no box list")
    check([m[2] for m in s["marks"]] == [1, 2] and s["sign2_enabled"] and s["sign_label"] == "SIGN 1", f"two numbered marks, SIGN 1: {s['marks']}")
    check(s["mode"] == "mca" and s["card_name"].endswith("sample-form.pdf"), "file opened")
    # drawing is disabled: a drag on page 1 adds no box
    key("Home")
    time.sleep(0.4)
    draw_box_p1()
    check(not state()["boxes"], "MCA: dragging draws no box")
    click(*center(state()["form_label_b"][1]))
    time.sleep(0.8)
    s = state()
    check(s["marks"][1][3] and not s["marks"][0][3] and s["vadj"][0] > 0, f"row click selects the field and scrolls to it (vadj {s['vadj']})")
    check(s["page_label"] == "p8/10" or s["page_label"] == "p7/10", f"page indicator at the field page: {s['page_label']}")
    x("xdotool", "mousemove", "400", "400")  # park the pointer so no tooltip is in the screenshot
    time.sleep(0.8)
    shot("mca-1100-field2")
    click(*center(state()["form_label_b"][0]))
    time.sleep(0.8)
    s = state()
    check(s["marks"][0][3] and not s["marks"][1][3], "unmatched row is selectable too")
    click(*center(s["form_label_b"][1]))  # select field 2 (scrolls to page 8), then wheel back up to field 1's rectangle and click it
    time.sleep(0.6)
    x("xdotool", "mousemove", "300", "400")
    for _ in range(25):
        s = state()
        cx, cy = field_center(s, 6, s["marks"][0][1])
        if 170 < cy < s["size"][1] - 60:
            break
        x("xdotool", "click", "4")
        time.sleep(0.15)
    check(s["marks"][1][3], "field 2 still the selected one before the click")
    click(cx, cy)
    time.sleep(0.5)
    s = state()
    check(s["marks"][0][3], f"clicking the rectangle selects its row (at {cx},{cy}): {s['marks']}")
    check(not s["boxes"], "clicking a field draws nothing")
    # field 1 first (page 7) so the screenshot shows both the badge and the dashed rectangle
    click(*center(s["form_label_b"][0]))
    time.sleep(0.8)
    x("xdotool", "mousemove", "1400", "800")  # keep a tooltip off the screenshot
    time.sleep(0.5)
    shot("mca-1100-field1")
    # ---- B: General on the same file: preserved file/token/scroll; boxes drawn there are not signed in MCA
    v0 = state()["vadj"][0]
    click(*center(state()["mode_btns"]["general"]))
    time.sleep(0.6)
    s = state()
    check(
        s["mode"] == "general" and not s["marks"] and s["visible_sw_shown"] and s["gen_list_shown"], "General: marks hidden, toggle and box list back"
    )
    check(
        s["path"].endswith("sample-form.pdf") and s["signer"] == "Jane Doe" and abs(s["vadj"][0] - v0) <= 2,
        f"file/token/scroll kept (vadj {v0} -> {s['vadj'][0]})",
    )
    check(not s["sign2_enabled"], "General with no box: Sign disabled (the form rows do not count)")
    key("Home")
    time.sleep(0.4)
    draw_box_p1()
    s = state()
    check(len(s["boxes"]) == 1 and s["sign2_enabled"], "General: box drawing works again")
    shot("general-1100")
    click(*center(s["mode_btns"]["mca"]))
    time.sleep(0.6)
    s = state()
    check(
        s["mode"] == "mca" and len(s["boxes"]) == 1 and s["form_title"] == "Form signatures (2)",
        "back to MCA: the General box is kept (not shown, not signed)",
    )
    # token removed: Jane unplugged -> row flagged, Sign refuses with a message
    touch("unplug1")
    key("F5")
    s = wait(lambda s: s["signer"] is None and not s["scanning"], "Jane unplugged", 15)
    r2 = s["form_rows"][1]
    check("token removed" in r2["line"] and r2["checked"], f"matched token gone -> {r2['line']!r}")
    key("ctrl+s")
    s = wait(lambda s: s["toast"], "refusal toast")
    check("not connected" in s["toast"] and not s["calls"] and not s["pin_open"], f"Sign refuses: {s['toast']!r}")
    rm("unplug1")
    key("F5")
    s = wait(lambda s: s["signer"] == "Jane Doe" and not s["scanning"], "Jane back", 15)
    r2 = s["form_rows"][1]
    check(r2["line"] == "Jane Doe · PAN matches" and r2["checked"], "replug restores the row by key, checkbox choice kept")
    # ---- C: partial fill: only Jane's field
    sign_with_pins("S1")
    s = wait(lambda s: s["path"].endswith("signed-1.pdf") and s["toast"], "partial fill finished + reload", 30)
    check(len(s["save_names"]) == 1 and len(s["prompts"]) == 1, f"one Save dialog, one PIN prompt: {s['save_names']} {s['prompts']}")
    check(s["calls"] == [["sample-form.pdf", "S1", F2, "signed-1.pdf", "field"]], f"Backend.sign(field=...) for the checked field only: {s['calls']}")
    check("1 of 2 fields signed; sigfield1_ABCD…1234F needs its signer" in s["toast"], f"toast: {s['toast']!r}")
    check(
        s["mode"] == "mca" and s["form_title"] == "Form signatures (1)" and s["form_rows"][0]["label"] == "Page 7 · ABCD…1234F",
        "reloaded in MCA with the other field still listed",
    )
    check([f[2] for f in s["fields_loaded"]] == [False, True], f"field 2 is now signed: {s['fields_loaded']}")
    click(*center(s["bounds"]["toast_line"]))
    s = wait(lambda s: s["toast_open"], "toast expanded")
    check(
        any(F2 in r and "Jane Doe" in r and "PAN matches" in r for r in s["toast_rows"]),
        f"per-field result in the expanded toast: {s['toast_rows']}",
    )
    click(*center(s["form_label_b"][0]))  # scroll the preview to the remaining field for the screenshot
    time.sleep(0.8)
    x("xdotool", "mousemove", "400", "400")
    time.sleep(0.5)
    shot("mca-after-partial")
    # ---- D: the next signer (Bob) opens the same file and signs THEIR field
    touch("two")
    key("F5")
    s = wait(lambda s: s["dropdown_items"] == 3 and not s["scanning"], "Bob appears", 20)
    r1 = s["form_rows"][0]
    check(r1["line"] == "Bob Smith · PAN matches" and r1["checked"], f"field 1 now matched to Bob: {r1}")
    sign_with_pins("S4")
    s = wait(lambda s: s["path"].endswith("signed-2.pdf") and s["toast"], "second fill finished", 30)
    check(s["calls"][1] == ["signed-1.pdf", "S4", F1, "signed-2.pdf", "field"], f"chained from the first output: {s['calls'][1]}")
    check("2 of 2" in s["toast"] or "1 of 1 fields signed" in s["toast"], f"toast: {s['toast']!r}")
    check(s["form_title"] == "Form signatures (0)" and s["form_empty_shown"], "every field signed: the hint is shown")
    # ---- E: fresh copy, both tokens: one Save dialog, one prompt per token, order = field order
    n_calls, n_dialogs = len(s["calls"]), len(s["save_names"])
    open(os.path.join(OUT, "drop"), "w").write(os.path.join(OUT, "sample-form.pdf"))
    s = wait(lambda s: s["path"].endswith("sample-form.pdf") and s["form_title"] == "Form signatures (2)", "fresh copy")
    check(
        s["mode"] == "mca" and [r["checked"] for r in s["form_rows"]] == [True, True] and s["sign_label"] == "SIGN 2",
        f"both matched and checked: {s['sign_label']}",
    )
    p0 = len(s["prompts"])
    sign_with_pins("S4", "S1")
    s = wait(lambda s: s["path"].endswith(f"signed-{n_dialogs + 1}.pdf") and s["toast"] and len(s["calls"]) >= n_calls + 2, "both fields signed", 40)
    new = s["calls"][n_calls:]
    check([c[1:3] for c in new] == [["S4", F1], ["S1", F2]], f"per-field sign calls in field order: {new}")
    check(len(s["save_names"]) == n_dialogs + 1 and len(s["prompts"]) == p0 + 2, "one Save dialog, one PIN prompt per token")
    check("2 of 2 fields signed" in s["toast"], f"toast: {s['toast']!r}")
    # ---- F: a PDF without signature fields: auto General; MCA shows the hint
    open(os.path.join(OUT, "drop"), "w").write(os.path.join(OUT, "three.pdf"))
    s = wait(lambda s: s["path"].endswith("three.pdf"), "plain pdf")
    check(s["mode"] == "general" and not s["marks"], "no signature fields -> General")
    click(*center(s["mode_btns"]["mca"]))
    time.sleep(0.6)
    s = state()
    check(
        s["mode"] == "mca" and s["form_empty_shown"] and s["to_general"] and not s["sign2_enabled"],
        "MCA on a fieldless PDF: hint + 'Switch to General', Sign disabled",
    )
    shot("mca-no-fields")
    click(*center(s["to_general"]))
    time.sleep(0.5)
    check(state()["mode"] == "general", "'Switch to General' switches")
    ops(("open",), ("choice", "default_mode", 1), ("choice", "signature_format", 2))
    s = state()
    check(s["settings"] is not None and s["default_mode_cfg"] == "mca", f"Settings 'Default mode' saved: {s['default_mode_cfg']}")
    shot("settings-modes")


NEW = {
    "formfields": run_formfields,
    "signers": run_signers,
    "twopane": run_twopane,
    "invisible": run_invisible,
    "settings": lambda: run_settings(True),
    "settings-unavail": lambda: run_settings(False),
    "savedpin": run_savedpin,
    "strip": run_strip,
    "nofile": run_nofile,
    "overwrite": run_overwrite,
}


def run_multi():
    touch("two")
    key("F5")
    s = wait(lambda s: s["dropdown_items"] == 3 and not s["scanning"], "second valid token", 20)
    check(s["items"][2].startswith("Bob Smith"), f"two valid signers available: {s['items']}")
    place_three()
    s = state()
    print("   vadj after place_three", s["vadj"], s["pages"][0], s["boxes"])
    check(len(s["boxes"]) == 3 and s["sign_label"] == "SIGN 3", f"3 boxes placed, button reads {s['sign_label']!r}")
    check(all(b[2] == "S1/01" for b in s["boxes"]), "every new box takes the signer selected in the dropdown (Jane)")
    # box 2 selected, dropdown -> Bob: NO placed box changes; box 2 is then changed deliberately via the chip menu
    px, py, pwid, _ = s["pages"][0]
    click(px + 40 + pwid // 6, py + 220 + 35)
    time.sleep(0.3)
    check(state()["active"] == 1 and len(state()["boxes"]) == 3, "clicking inside a box makes it active without adding one")
    check(state()["signer"] == "Jane Doe", "selecting a box does not touch the dropdown")
    pick_signer(2)
    s = state()
    check(
        [b[2] for b in s["boxes"]] == ["S1/01"] * 3 and s["signer"] == "Bob Smith",
        f"dropdown change with box 2 selected leaves every placed box alone: {[b[2] for b in s['boxes']]}",
    )
    ops(("chip_open", 1))
    shot("12-chip-menu")
    ops(("chip_pick", 1, "S4"))
    s = state()
    check([b[2] for b in s["boxes"]] == ["S1/01", "S4/01", "S1/01"], f"chip menu changes box 2 only: {[b[2] for b in s['boxes']]}")
    click(px + 40 + pwid // 6, py + 220 + 35)  # focus back into the document so Enter reaches the window
    time.sleep(0.3)
    shot("13-three-boxes")

    key("Return")
    s = wait(lambda s: s["pin_open"] and len(s["prompts"]) >= 1, "first PIN prompt")
    check(
        s["prompts"][0] == ["S1", 2, None] and "2 signatures" in s["pin_title"],
        f"first prompt names token S1 and its 2 signatures: {s['pin_title']!r}",
    )
    shot("14-pin-two-signatures")
    time.sleep(0.4)
    x("xdotool", "type", "--delay", "30", "right-pin")
    time.sleep(0.3)
    print(
        "   after typing:",
        {k: state()[k] for k in ("pin_text_len", "pin_focus", "pin_busy", "focus_widget", "pin_mapped", "pin_entry_vis", "pin_edit")},
    )
    key("Return")
    s = wait(lambda s: len(s["prompts"]) >= 2 and s["pin_open"], "second PIN prompt (other token)")
    check(s["prompts"][1] == ["S4", 1, None], f"second token prompts once: {s['prompts'][1]}")
    time.sleep(0.3)
    x("xdotool", "type", "--delay", "30", "right-pin")
    key("Return")
    s = wait(lambda s: s["toast"] and len(s["calls"]) >= 3 and s["path"].endswith("signed-1.pdf"), "run finished and reloaded", 30)
    calls = s["calls"]
    check(len(s["prompts"]) == 2, f"3 boxes / 2 tokens -> exactly {len(s['prompts'])} PIN prompts")
    check([c[1] for c in calls] == ["S1", "S4", "S1"] and [c[2] for c in calls] == [1, 1, 1], f"sign order follows badges: {[c[1] for c in calls]}")
    check(
        calls[0][0] == "three.pdf" and calls[1][0] == calls[0][3] and calls[2][0] == calls[1][3] and calls[2][3] == "signed-1.pdf",
        f"output of step k is input of step k+1: {[(c[0], c[3]) for c in calls]}",
    )
    check(s["sign_label"] == "SIGN" and not s["boxes"], "after the run: boxes cleared, button back to SIGN")
    final = os.path.join(OUT, "signed-1.pdf")
    out = subprocess.run(["pdfsig", final], capture_output=True, text=True, check=False, env=isolate.poppler_env()).stdout
    check(
        out.count("Signature #") == 3 and out.count("Signature is Valid") == 3,
        f"pdfsig: {out.count('Signature #')} signatures, {out.count('Signature is Valid')} valid",
    )
    check("." + "dsc-step" not in " ".join(os.listdir(OUT)), "no intermediate files left behind")
    shot("15-multi-done")

    # stop-on-failure: 3 boxes with the current signer (Bob): the 3rd sign call fails like a hung token
    key("Home")
    place_three()
    check(len(state()["boxes"]) == 3, "three boxes on the signed document")
    base = len(state()["calls"])
    open(os.path.join(OUT, "failat"), "w").write("3")
    key("Return")
    wait(lambda s: s["pin_open"] and len(s["prompts"]) >= 3, "PIN prompt for the failure run")
    x("xdotool", "type", "--delay", "30", "right-pin")
    key("Return")
    s = wait(lambda s: s["toast"] and "Stopped after" in s["toast"], "stop message", 30)
    new = s["calls"][base:]
    check([c[4] for c in new] == ["ok", "ok", "TIMEOUT"], f"two signatures done, third failed, nothing retried: {[c[4] for c in new]}")
    check(len(s["prompts"]) == 3, "one prompt for the three same-token boxes")
    check("2 of 3" in s["toast"] and "partial" in s["toast"], f"toast: {s['toast'][:140]!r}")
    check(
        s["path"].endswith("-partial.pdf") and len(s["boxes"]) == 1 and s["toast_path_btns"],
        "partial result loaded; the one unsigned box stays; Open/Show buttons offered",
    )
    out = subprocess.run(["pdfsig", s["path"]], capture_output=True, text=True, check=False, env=isolate.poppler_env()).stdout
    check(out.count("Signature #") == 5, f"partial file has the 3 earlier + 2 new signatures: {out.count('Signature #')}")
    time.sleep(2.5)
    check(len(state()["calls"]) == len(s["calls"]), "no automatic retry after the failure")
    check(not [f for f in os.listdir(OUT) if f.startswith(".dsc-step")], "intermediates cleaned up after the failure")
    shot("16-stopped-partial")


def run_errors():
    """Typed scan errors (core DriverBusy / TokenCountMismatch): never 'no tokens', partial result still signable."""
    key("Home")
    s = state()
    px, py, pwid, _ = s["pages"][0]
    drag(px + 40, py + 120, px + 40 + pwid // 3, py + 190)
    time.sleep(0.3)
    s = state()
    check(s["sign_enabled"] and len(s["boxes"]) == 1, "baseline: one box, Jane selected, SIGN enabled")

    touch("nopoll")
    time.sleep(3)  # let the Poller's reaction to the probe change settle
    touch("partial")
    key("F5")
    s = wait(lambda s: s["note"].startswith("found 1 of 2"), "partial-result warning", 15)
    check(s["note"] == "found 1 of 2 token devices: Refresh", f"strip says {s['note']!r}")
    check(s["note_warn"] and not s["note_err"], "partial warning is yellow, not red")
    check(
        s["toast"] == "found 1 of 2 token devices: Refresh" and s["toast_warn"],
        f"full sentence in the toast (the strip ellipsizes at 560 px): {s['toast']!r}",
    )
    check(s["items"][0].startswith("Jane"), f"the token that WAS found is still listed: {s['items']}")
    check(s["sign_enabled"] and s["signer"] == "Jane Doe", "signing stays enabled for the found token")
    check(
        "no token" not in " ".join(s["items"]).lower() and "no dsc token" not in s["toast"].lower(), "no empty-state text while an error is present"
    )
    shot("17-partial")

    rm("partial")
    touch("busy")
    d0 = state()["discovers"]
    key("F5")
    s = wait(lambda s: "driver busy" in " ".join(s["items"]) and not s["scanning"], "busy state", 15)
    check(s["items"] == ["driver busy · pid 4242"] and s["note"] == "driver busy · pid 4242", f"dropdown/strip: {s['items']} / {s['note']!r}")
    check(not s["sign_enabled"], "SIGN disabled while the driver is busy")
    check(
        s["toast"] == "Token driver is in use by another tda-dsc-signer (pid 4242). Close it, then Refresh." and s["toast_warn"],
        f"toast: {s['toast']!r}",
    )
    check("no token" not in (s["toast"] + " ".join(s["items"])).lower(), "busy is not reported as 'no tokens found'")
    check(len(s["boxes"]) == 1, "the placed box is kept")
    shot("18-busy")
    # automatic retries: after 3 s, at most 3, then the message stays
    s = wait(lambda s: s["discovers"] >= d0 + 4, "three automatic retries", 25)
    time.sleep(4.5)
    s = state()
    check(
        s["discovers"] == d0 + 4 and s["busy_retries"] == 3,
        f"exactly 3 automatic retries after the manual scan (discovers {d0} -> {s['discovers']}), then it stops",
    )
    check("driver busy" in s["note"] and not s["sign_enabled"], "message kept after the retries ran out")
    rm("busy")
    key("F5")
    s = wait(lambda s: s["signer"] == "Jane Doe" and not s["scanning"], "recovery after Refresh", 15)
    check(s["note"] == "" and s["sign_enabled"] and s["busy_retries"] == 0, "Refresh after closing the other process recovers; SIGN enabled again")
    rm("nopoll")


def sample_page(c, i, top=720):
    c.setFont("Helvetica-Bold", 16)
    c.drawString(72, top, "Sample Declaration Form (synthetic)")
    c.setFont("Helvetica", 10)
    c.drawString(72, top - 20, f"Part {i} of 10. Generic placeholder text for documentation screenshots only.")
    for n in range(4):
        c.drawString(72, top - 50 - 14 * n, "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor.")
    for r in range(4):  # a small table
        for col in range(3):
            c.rect(72 + col * 130, top - 160 - r * 22, 130, 22)
            c.drawString(80 + col * 130, top - 152 - r * 22, ("Item", "Description", "Value")[col] if r == 0 else f"{('A', 'B', 'C')[col]}{r}")
    if i in (7, 8):
        c.drawString(300, 181, f"Signature of subscriber {i - 6}")
        c.line(296, 177, 508, 177)


pdf = conftest.make_pdf(os.path.join(OUT, "three.pdf"), 3, drawer=lambda c, i: sample_page(c, i, top=480))
if MODE == "formfields":
    import gui_formfix

    pdf = os.path.join(OUT, "sample-form.pdf")  # synthetic ten-page MCA-style form (never a real filing)

    conftest.make_form_pdf(
        pathlib.Path(pdf),
        ((gui_formfix.F1.name, 7, gui_formfix.F1.rect), (gui_formfix.F2.name, 8, gui_formfix.F2.rect)),
        pages=10,
        pagesize=(612, 792),
        drawer=sample_page,
    )
for f in os.listdir(OUT):
    if f.startswith("signed-") or f in ("plug", "state.json", "unplug1", "slow", "slowsign", "nopoll", "moderr", "drop", "two", "failat"):
        os.unlink(os.path.join(OUT, f))
xvfb = subprocess.Popen(["Xvfb", XDISPLAY, "-screen", "0", "1700x1000x24"], stderr=subprocess.DEVNULL)
time.sleep(1.5)
errlog = open(os.path.join(OUT, f"w{W}-stderr.log"), "w")
app = subprocess.Popen(
    [sys.executable, os.path.join(HERE, "gui_harness.py"), OUT, str(W), str(H), *([] if MODE == "nofile" else [pdf])], env=ENV, stderr=errlog
)
try:
    s = wait(lambda s: (s["path"] or MODE == "nofile") and s["detecting"], "window + 'detecting tokens…'", 20)
    check(s["detecting"] and not s["sign_enabled"], "starts usable with the spinner inside the dropdown, Sign disabled")
    shot("1-detecting")
    s = wait(lambda s: s["signer"] and not s["detecting"], "tokens detected")
    wid = x("xdotool", "search", "--onlyvisible", "--pid", str(app.pid)).split()[0]
    WID.append(wid)
    x("xdotool", "mousemove", "600", "400")
    x("xdotool", "windowfocus", "--sync", wid)
    time.sleep(0.5)
    if MODE in NEW:
        NEW[MODE]()
        raise Done
    s = state()
    b = s["bounds"]
    check(s["signer"] == "Jane Doe" and s["dropdown_items"] == 2, f"dropdown lists 2 tokens, selected {s['signer']}")
    check(s["strip_h"] <= 32, f"strip height {s['strip_h']}px (<=32)")
    check(
        b["sign"][0] + b["sign"][2] <= s["size"][0], f"nothing clipped: SIGN right edge {b['sign'][0] + b['sign'][2]} <= window width {s['size'][0]}"
    )
    pw = s["pages"][0][2]
    print(f"INFO window {s['size']}, page width {pw}px => page fills {100 * pw / s['size'][0]:.0f}% of the width; page_label {s['page_label']!r}")
    check(s["page_label"] == "p1/3", "page indicator shows p1/3")
    shot("2-ready")
    if MODE == "multi":
        run_multi()
        raise Done
    if MODE == "errors":
        run_errors()
        raise Done

    # draw a box on page 2: scroll until it is visible, then drag inside it
    for _ in range(6):
        s = state()
        px, py, pwid, phei = s["pages"][1]
        if py > s["strip_h"] and py + 120 < s["size"][1]:
            break
        key("Next")
    s = state()
    px, py, pwid, phei = s["pages"][1]
    x1, y1 = px + pwid // 5, max(py, s["strip_h"] + 10) + 40
    drag(x1, y1, x1 + pwid // 3, y1 + 70)
    time.sleep(0.4)
    s = state()
    check(s["sel"][0] == 1 and s["sel"][1] is not None, f"box drawn on page 2 -> page index {s['sel'][0]}, PDF box {s['sel'][1]}")
    check(s["sign_enabled"], "Sign enabled once a valid box exists")
    check(s["page_label"] in ("p2/3", "p3/3"), f"page indicator follows scrolling: {s['page_label']}")
    shot("3-box")

    key("Escape")
    check(state()["sel"][1] is None and not state()["sign_enabled"], "Esc clears the box and disables Sign")
    drag(x1, y1, x1 + pwid // 3, y1 + 70)
    time.sleep(0.3)
    box_before = state()["sel"]
    # resize by the bottom-right corner, then move from inside
    bx2, by2 = x1 + pwid // 3, y1 + 70
    drag(bx2, by2, bx2 + 30, by2 + 20)
    time.sleep(0.3)
    resized = state()["sel"]
    check(
        resized[1][2] > box_before[1][2] and resized[1][0] == box_before[1][0],
        f"corner drag resizes keeping the opposite corner {box_before[1]} -> {resized[1]}",
    )
    drag(x1 + 20, y1 + 20, x1 + 60, y1 + 20)
    time.sleep(0.3)
    moved = state()["sel"]
    check(
        moved[1][0] > resized[1][0] and abs((moved[1][2] - moved[1][0]) - (resized[1][2] - resized[1][0])) <= 1,
        f"inside drag moves without resizing {resized[1]} -> {moved[1]}",
    )

    # Esc with the popover open must not clear the box
    key("Return")
    s = wait(lambda s: s["pin_open"], "PIN popover")
    check(s["save_names"] == ["three-signed.pdf"], f"save dialog suggests {s['save_names']}")
    check(s["pin_entry_visible"] and not s["pin_confirm_visible"], "popover has a PIN entry, no last-attempt checkbox for a normal token")
    time.sleep(0.4)
    pt, sg = state()["pin_pointing"], state()["bounds"]["sign"]
    check(sg[0] <= pt[0] + pt[2] // 2 <= sg[0] + sg[2] and pt[3] > 0, f"PIN popover is aimed at SIGN: pointing {pt} vs button {sg}")
    shot("4-pin-popover")
    key("Escape")
    s = wait(lambda s: not s["pin_open"], "popover closed by Esc")
    check(s["sel"][1] is not None and s["attempts"] == 0, "Esc cancels the popover only: box kept, no sign attempt")

    # wrong PIN: inline error, popover stays, box kept, exactly one attempt
    key("Return")
    wait(lambda s: s["pin_open"], "PIN popover again")
    time.sleep(0.3)
    x("xdotool", "type", "--delay", "40", "wrong-pin")
    key("Return")
    s = wait(lambda s: s["pin_err"] and s["attempts"] == 1, "inline wrong-PIN error")
    check(
        "Wrong PIN" in s["pin_err"] and s["pin_open"] and s["sel"][1] is not None,
        f"wrong PIN -> inline error {s['pin_err']!r}; popover open; box kept",
    )
    time.sleep(1.0)
    check(state()["attempts"] == 1, "no automatic retry after the wrong PIN (attempts stay 1)")
    shot("5-wrong-pin")

    # correct PIN: second, user-initiated attempt
    x("xdotool", "type", "--delay", "40", "right-pin")
    key("Return")
    s = wait(lambda s: "unmodified" in s["toast"] and s["attempts"] == 2, "success toast")
    check(
        not s["pin_open"] and s["path"].endswith("signed-2.pdf") or s["path"].endswith(".pdf"), f"signed file reloaded: {os.path.basename(s['path'])}"
    )
    check("unmodified" in s["toast"] and "signature valid" in s["toast"], f"toast line: {s['toast']!r}")
    check(s["pin_lens"] == [9, 9], "PIN lengths sent: two user actions, never more (values not logged)")
    check(s["sel"][1] is None, "signed file reloaded with no box, ready for a second one")
    check(s["saved_profile"] == "mca" and s["saved_token"] == "S1/01", f"config saved token {s['saved_token']} profile {s['saved_profile']}")
    shot("6-toast")
    tl = s["bounds"]["toast_line"]
    click(*center(tl))
    s = wait(lambda s: s["toast_open"], "toast expanded")
    time.sleep(0.4)
    rows = [r for r in s["toast_rows"] if r[0] in "✓ℹ–✗"]  # the per-signature header row is not a verification row
    check(len(rows) == 4, "expanded toast has 4 rows")
    for r in rows:
        print("   ", r)
    check(rows[2].startswith("ℹ") and "informational" in rows[2], "issuer-not-trusted is INFO (ℹ), not a failure")
    check(rows[0].startswith("✓") and rows[1].startswith("✓") and rows[3].startswith("–"), "unmodified ✓, signature ✓, revocation unchecked –")
    shot("7-toast-expanded")

    # zoom and navigation
    key("plus")
    z1 = state()["zoom"]
    key("0")
    key("End")
    time.sleep(0.5)
    e = state()
    key("Home")
    time.sleep(0.5)
    h = state()
    check(z1 > 1.0 and state()["zoom"] == 1.0, f"+ zooms in ({z1}), 0 resets")
    check(
        h["pages"][0][1] >= e["pages"][0][1] and h["pages"][0][1] > 0,
        f"Home/End scroll: page1 y {e['pages'][0][1]} (End) -> {h['pages'][0][1]} (Home)",
    )
    x("xdotool", "mousemove", "300", "300")
    x("xdotool", "keydown", "ctrl", "click", "4", "keyup", "ctrl")
    time.sleep(0.4)
    check(state()["zoom"] > 1.0, f"Ctrl+scroll zooms ({state()['zoom']})")
    key("0")

    check(state()["layout"] == "strip" and "Popover" in state()["options_parent"], "narrow window: strip layout, options live in the popover")

    # drop (handler only) and hot-plug
    other = conftest.make_pdf(os.path.join(OUT, "other.pdf"), 2)
    open(os.path.join(OUT, "drop"), "w").write(other)
    s = wait(lambda s: s["path"] == other, "drop handler loads the PDF")
    check(s["page_label"] == "p1/2", "dropped PDF opened (handler call, not a real DnD)")

    # ---- manual refresh (poller disabled by the 'nopoll' flag so only the button can change the list)
    def touch(n):
        open(os.path.join(OUT, n), "w").close()

    def rm(n):
        if os.path.exists(os.path.join(OUT, n)):
            os.unlink(os.path.join(OUT, n))

    d_before = state()["discovers"]
    touch("nopoll")  # switching the probe itself looks like a change to the Poller: let its one rescan finish first
    t_end = time.time() + 16
    while time.time() < t_end:
        s = state()
        if s["discovers"] > d_before and not s["scanning"]:
            break
        time.sleep(0.3)
    key("Escape")
    key("Home")
    p0 = state()["pages"][0]  # fresh geometry: the document was replaced by the drop test
    drag(p0[0] + 40, max(p0[1], 60) + 100, p0[0] + 40 + p0[2] // 3, max(p0[1], 60) + 170)  # a box that must survive refreshes
    time.sleep(0.4)
    s = state()
    box0 = s["sel"]
    check(
        box0[1] is not None and s["refresh_enabled"],
        f"refresh button present and enabled with a box placed (box={box0}, enabled={s['refresh_enabled']}, scanning={s['scanning']})",
    )
    b = s["bounds"]
    check(b["refresh"] is not None and b["refresh"][0] + b["refresh"][2] <= s["size"][0], f"refresh button {b['refresh']} fits in the strip")
    shot("9-strip-with-refresh")
    touch("plug")
    time.sleep(2.5)
    check(state()["dropdown_items"] == 2, "with the poller off, a plugged token does NOT appear by itself")
    touch("slow")
    click(*center(state()["bounds"]["refresh"]))
    s = wait(lambda s: s["scanning"], "spinner while scanning")
    check(not s["refresh_enabled"], "refresh button disabled while a scan is in flight")
    d0 = s["discovers"]
    key("F5")
    click(*center(s["bounds"]["refresh"]))
    shot("10-scanning")
    s = wait(lambda s: not s["scanning"] and s["dropdown_items"] == 3, "scan result with the plugged token", 15)
    check(s["discovers"] == d0, "F5/click during a scan are ignored (no second discover)")
    check(
        s["signer"] == "Jane Doe" and s["sel"] == box0 and s["refresh_enabled"],
        "token list refreshed; selection by key kept; box kept; button re-enabled",
    )
    rm("slow")
    touch("unplug1")
    key("F5")
    s = wait(lambda s: s["discovers"] > d0 and not s["scanning"], "rescan after unplug", 15)
    check(
        s["signer"] is None and s["selected_pos"] == -1 and s["chips"] == [["token removed", True]],
        f"selected token unplugged -> dropdown cleared, the box keeps its row marked 'token removed' (signer={s['signer']}, chips={s['chips']})",
    )
    check(s["note"] == "token removed" and s["sel"] == box0, f"strip says {s['note']!r}; the placed box is untouched")
    shot("11-token-removed")
    rm("unplug1")
    key("ctrl+r")
    s = wait(lambda s: s["signer"] == "Jane Doe" and not s["scanning"], "token reappears", 15)
    check(s["note"] == "" and s["sign_enabled"], "token plugged back -> reselected by serial, note cleared, SIGN enabled again (Ctrl+R)")
    touch("moderr")
    key("F5")
    s = wait(lambda s: s["note"] == "module error", "module error note", 15)
    check(
        "/opt/fake/libvendor.so" in (s["note_tip"] or "") and s["signer"] == "Jane Doe",
        f"module failure shown non-modally; tooltip {s['note_tip']!r}",
    )
    shot("12-module-error")
    rm("moderr")
    # refresh during a sign: disabled, ignored, and an unplug mid-sign dialog closes the popover
    touch("slowsign")
    key("Return")
    wait(lambda s: s["pin_open"], "popover for the slow sign")
    time.sleep(0.4)
    x("xdotool", "type", "--delay", "40", "right-pin")
    key("Return")
    s = wait(lambda s: not s["refresh_enabled"] and not s["sign_enabled"], "sign in flight", 6)
    d1 = s["discovers"]
    key("F5")
    time.sleep(0.5)
    check(state()["discovers"] == d1, "refresh disabled and F5 ignored while a sign is in flight")
    wait(lambda s: s["attempts"] == 3 and s["path"].endswith("signed-3.pdf"), "slow sign finished and reloaded", 15)
    time.sleep(0.6)
    rm("slowsign")
    s = state()
    check(s["refresh_enabled"], "refresh enabled again after the sign")
    key("Escape")
    # unplug the signing token while its PIN popover is open: the popover must close
    p0 = state()["pages"][0]
    drag(p0[0] + 40, max(p0[1], 60) + 100, p0[0] + 40 + p0[2] // 3, max(p0[1], 60) + 170)
    time.sleep(0.3)
    key("Return")
    wait(lambda s: s["pin_open"], "popover before unplug")
    touch("unplug1")
    key("F5")  # F5 is honoured even while the PIN popover is open
    s = wait(lambda s: s["signer"] is None and not s["scanning"], "unplug while popover open", 15)
    check(
        not s["pin_open"] and s["chips"][0] == ["token removed", True],
        "unplugging the token closes a pending PIN popover; the box is marked 'token removed'",
    )
    rm("unplug1")
    rm("nopoll")
    # automatic hot-plug (Poller back on): unplugging the extra token, then inserting it again, with no button press
    rm("plug")
    s = wait(
        lambda s: s["signer"] == "Jane Doe" and s["items"] == ["Jane Doe · Fake Org Pvt Ltd", "Old Signer · Fake Org Pvt Ltd"],
        "automatic removal",
        25,
    )
    check(
        s["note"] == "" and s["sign_enabled"] is not None,
        "Poller noticed the removal by itself; Jane Doe re-selected by serial after her token came back",
    )
    touch("plug")
    s = wait(lambda s: s["dropdown_items"] == 3 and s["signer"] == "Jane Doe", "automatic insertion", 25)
    check(True, "inserting a token refreshes the dropdown live (Poller) and keeps the selection")
    shot("8-after-hotplug")
except Done:
    pass
finally:
    app.terminate()
    try:
        app.wait(5)
    except subprocess.TimeoutExpired:
        app.kill()
    xvfb.terminate()
    errlog.close()
warn = [
    ln
    for ln in open(os.path.join(OUT, f"w{W}-stderr.log"))
    if ("WARNING" in ln or "Traceback" in ln or "Error" in ln) and "Unable to acquire session bus" not in ln
]  # deliberate: no bus
check(not warn, f"no GTK warnings/tracebacks on stderr ({len(warn)}): {warn[:3]}")
sys.exit(report())

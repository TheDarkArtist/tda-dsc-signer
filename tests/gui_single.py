"""Single-instance check on a throwaway Xvfb with a PRIVATE session bus (dbus-run-session), real app id, fake backend.

python tests/gui_single.py OUT_DIR        (outer: starts Xvfb + dbus-run-session; refuses DISPLAY=:0)
python tests/gui_single.py --inner OUT_DIR   (runs inside the private bus)
"""

import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
XDISPLAY = ":97"


def outer(out):
    os.makedirs(out, exist_ok=True)
    xvfb = subprocess.Popen(["Xvfb", XDISPLAY, "-screen", "0", "1280x1000x24"], stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    env = {**os.environ, "DISPLAY": XDISPLAY, "GSK_RENDERER": "cairo", "REAL_BUS": os.environ.get("DBUS_SESSION_BUS_ADDRESS", "")}
    try:
        return subprocess.run(["dbus-run-session", "--", sys.executable, os.path.abspath(__file__), "--inner", out], env=env, check=False).returncode
    finally:
        xvfb.terminate()


def launcher(out, path):
    """One GUI process exactly as `tda-dsc-signer [file]` starts it (cli -> run_gui), minus the real token backend."""
    sys.path.insert(0, HERE)
    import isolate

    isolate.isolate(dbus=True)
    import gi

    gi.require_version("Gtk", "4.0")
    from gi.repository import GLib

    from tda_dsc_signer.backend import Backend
    from tda_dsc_signer.gui import app as appmod

    fake = Backend(lambda extra: [], lambda *a, **k: None, lambda *a, **k: None)
    init = appmod.Window.__init__

    def init_and_dump(self, *a, **k):
        init(self, *a, **k)
        me = os.path.join(out, f"state-{os.getpid()}.json")
        GLib.timeout_add(
            150, lambda: (open(me, "w").write(json.dumps({"pid": os.getpid(), "path": self.path, "app_id": a[0].get_application_id()})), True)[1]
        )

    appmod.Window.__init__ = init_and_dump
    sys.exit(appmod.run_gui(path, backend=fake))


def states(out):
    res = []
    for f in os.listdir(out):
        if f.startswith("state-"):
            res.append(json.load(open(os.path.join(out, f))))
    return res


def inner(out):
    assert os.environ["DISPLAY"] == XDISPLAY and os.environ.get("DBUS_SESSION_BUS_ADDRESS"), "need the private bus and the Xvfb"
    assert os.environ["DBUS_SESSION_BUS_ADDRESS"] != os.environ.get("REAL_BUS"), "refusing to run on the user's real session bus"
    sys.path.insert(0, HERE)
    bus = os.environ["DBUS_SESSION_BUS_ADDRESS"]
    import conftest  # its import-time isolation points the bus at a dead socket: restore the private bus for the children

    os.environ["DBUS_SESSION_BUS_ADDRESS"] = bus

    a, b = conftest.make_pdf(os.path.join(out, "a.pdf"), 1), conftest.make_pdf(os.path.join(out, "b.pdf"), 2)
    for f in os.listdir(out):
        if f.startswith("state-"):
            os.unlink(os.path.join(out, f))
    me = [sys.executable, os.path.abspath(__file__), "--launch", out]
    checks = []

    def check(c, what):
        checks.append(bool(c))
        print(("PASS " if c else "FAIL ") + what, flush=True)

    first = subprocess.Popen([*me, a])
    t = time.time()
    while time.time() - t < 20 and not any(s["path"] == a for s in states(out)):
        time.sleep(0.2)
    check(any(s["path"] == a for s in states(out)), "first launch opened a.pdf")
    t0 = time.time()
    second = subprocess.run([*me, b], timeout=30, check=False)
    took = time.time() - t0
    check(second.returncode == 0 and took < 10, f"second launch (b.pdf) returned {second.returncode} after {took:.1f}s instead of starting a GUI")
    t = time.time()
    while time.time() - t < 10 and not any(s["path"] == b for s in states(out)):
        time.sleep(0.2)
    st = states(out)
    check(len(st) == 1 and st[0]["pid"] == first.pid, f"exactly one GUI process (state files: {[s['pid'] for s in st]}, first pid {first.pid})")
    check(st and st[0]["path"] == b, f"the running window opened the forwarded file: {st[0]['path'] if st else None}")
    check(st and st[0]["app_id"] == "in.tdacorp.DscSigner", f"application id {st[0]['app_id'] if st else None}")
    third = subprocess.run(me, timeout=30, check=False)  # no file: just raise the existing window
    check(third.returncode == 0 and first.poll() is None, "launch without a file activates the running instance and exits")
    first.terminate()
    first.wait(10)
    print(f"\n{sum(checks)}/{len(checks)} checks passed")
    return 0 if all(checks) else 1


if __name__ == "__main__":
    if "--inner" in sys.argv:
        sys.exit(inner(sys.argv[2]))
    if "--launch" in sys.argv:
        launcher(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
    else:  # the outer process never talks to X itself; it starts the Xvfb and hands only DISPLAY=:97 to its children
        sys.exit(outer(sys.argv[1]))

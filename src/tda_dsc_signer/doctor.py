"""Diagnose the system pieces a DSC token needs on Arch. Prints the sudo fix; never runs it."""

import os
import shlex
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass

from . import driverlock
from .quirks import INNAIT_DRIVER, usb_token_devices

USB_ID = "338c:0031"
HOOK_TEXT = """[Trigger]
Operation = Install
Operation = Upgrade
Type = Package
Target = ccid

[Action]
Description = Re-adding InnaitKey DSC (338c:0031) to CCID device list
When = PostTransaction
Exec = /usr/local/sbin/innait-ccid-patch
"""


@dataclass(frozen=True)
class Paths:
    plist: str = "/usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist"
    hook: str = "/etc/pacman.d/hooks/innait-ccid.hook"
    patch_script: str = "/usr/local/sbin/innait-ccid-patch"
    driver: str = INNAIT_DRIVER
    desktop_dirs: tuple = (
        os.path.join(os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share"), "applications"),
        "/usr/share/applications",
    )


DEFAULT_PATHS = Paths()


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str
    fix: str = ""


def run(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return p.returncode, p.stdout
    except (OSError, subprocess.SubprocessError) as e:
        return 127, str(e)


def _active(unit, runner):
    return runner(["systemctl", "is-active", unit])[1].strip() == "active"


def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def probe_dlopen(path, timeout=20):
    """dlopen the vendor library in a throwaway child (cwd=/, minimal env, no PIN, killed after `timeout`), never in this process."""
    code = "import ctypes, sys; ctypes.CDLL(sys.argv[1])"
    try:
        p = subprocess.run(
            [sys.executable, "-I", "-c", code, path],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd="/",
            env={"PATH": os.environ.get("PATH", "")},
        )
    except subprocess.TimeoutExpired:
        raise OSError(f"loading {path} did not finish in {timeout}s") from None
    if p.returncode != 0:
        raise OSError(p.stderr.strip().splitlines()[-1] if p.stderr.strip() else f"loader exited {p.returncode}")


def root_script(path):
    """True only for a root-owned regular file nobody else can modify: the only kind we suggest running under sudo."""
    try:
        st = os.stat(path)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022


DESKTOP_FILE = "in.tdacorp.DscSigner.desktop"
MINIMAL_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"  # what i3/rofi and most display managers give a launcher


def check_desktop_entry(dirs):
    """The installed launcher must start under a minimal PATH: an absolute existing Exec, or a bare name found on MINIMAL_PATH."""
    found = next((os.path.join(d, DESKTOP_FILE) for d in dirs if os.path.exists(os.path.join(d, DESKTOP_FILE))), None)
    if not found:
        return Check("desktop entry", True, f"no {DESKTOP_FILE} installed (only matters for launchers such as rofi)")
    text = _read(found) or ""
    line = next((ln for ln in text.splitlines() if ln.startswith("Exec=")), "")
    try:
        prog = shlex.split(line[5:])[0]
    except (ValueError, IndexError):
        prog = ""
    if prog.startswith("/"):
        ok, resolved = os.path.isfile(prog) and os.access(prog, os.X_OK), prog
    else:
        resolved = shutil.which(prog, path=MINIMAL_PATH) if prog else None
        ok = bool(resolved)
    if ok:
        return Check("desktop entry", True, f"{found}: Exec -> {resolved}")
    want = shutil.which("tda-dsc-signer") or os.path.expanduser("~/.local/bin/tda-dsc-signer")
    fix = f"re-run `make install`, or: sed -i 's|^Exec=.*|Exec={want} %f|' {found}"
    return Check("desktop entry", False, f"{found}: Exec={prog or '(missing)'} is not found on the launcher's PATH ({MINIMAL_PATH})", fix)


def check_driver_exclusivity(holders=driverlock.holders, usb=usb_token_devices):
    """Vendor drivers and PC/SC readers can not be shared: another running tda-dsc-signer makes this one see no tokens."""
    n = len(usb())
    others = [i for _, i in holders() if int(i.get("ppid") or 0) != os.getpid() and int(i["pid"]) != os.getpid()]
    if others:
        who = "; ".join(
            f"pid {i.get('ppid') or i['pid']} ({i.get('cmd') or 'tda-dsc-signer'}) holds {os.path.basename(str(i.get('module', '?')))}"
            for i in others
        )
        return Check("driver exclusivity", False, f"another tda-dsc-signer is using the token driver: {who}", "close it (then Refresh / re-run)")
    return Check("driver exclusivity", True, f"no other tda-dsc-signer holds a driver ({n} known token USB device(s) in /sys, informational)")


def diagnose(paths=DEFAULT_PATHS, runner=run, dlopen=probe_dlopen):
    out = []
    active = [u for u in ("pcscd.service", "pcscd.socket") if _active(u, runner)]
    out.append(
        Check(
            "pcscd",
            bool(active),
            f"active: {', '.join(active)}" if active else "neither pcscd.service nor pcscd.socket is active",
            "sudo systemctl enable --now pcscd.socket",
        )
    )
    usb = runner(["lsusb"])[1]
    out.append(
        Check(
            "usb token",
            USB_ID in usb,
            f"{USB_ID} present" if USB_ID in usb else f"{USB_ID} not listed by lsusb",
            "plug the token in directly (not via a flaky hub), then re-run",
        )
    )
    plist = _read(paths.plist)
    has = plist is not None and "0x338c" in plist.lower() and "0x0031" in plist.lower()
    patch_ok = root_script(paths.patch_script)
    if has:
        detail = "entry 0x338C/0x0031 present"
    else:
        detail = f"{paths.plist} lacks 0x338C/0x0031" if plist is not None else f"{paths.plist} unreadable"
    fix = (
        f"sudo {paths.patch_script} && sudo systemctl restart pcscd.service pcscd.socket"
        if patch_ok
        else f"add 0x338C / 0x0031 / 'InnaitKey DSC' to ifdVendorID / ifdProductID / ifdFriendlyName in {paths.plist}"
        # (also the answer when the script exists but is not root-owned / is group- or world-writable: never suggest sudo for that)
    )
    out.append(Check("ccid plist", has, detail, fix))
    hook = os.path.exists(paths.hook)
    out.append(
        Check(
            "pacman hook",
            hook,
            paths.hook if hook else f"{paths.hook} missing (plist patch is lost on ccid upgrades)",
            f"sudo install -Dm644 /dev/stdin {paths.hook} <<'EOF'\n{HOOK_TEXT}EOF",
        )
    )
    loaded, why = False, ""
    if os.path.exists(paths.driver):
        try:
            dlopen(paths.driver)
            loaded = True
        except OSError as e:
            why = str(e)
    out.append(
        Check(
            "pkcs11 driver",
            loaded,
            paths.driver if loaded else (why or f"{paths.driver} not found"),
            "install the vendor's InnaIT DSC driver package (this tool does not bundle any PKCS#11 driver)",
        )
    )
    out.append(check_driver_exclusivity())
    out.append(check_desktop_entry(paths.desktop_dirs))
    return out


def report(checks, write=print):
    for c in checks:
        write(f"[{'ok' if c.ok else 'FAIL'}] {c.name}: {c.detail}")
        if not c.ok and c.fix:
            write(f"       fix: {c.fix}")
    return 0 if all(c.ok for c in checks) else 1

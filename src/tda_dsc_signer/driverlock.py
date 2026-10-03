"""One process per PKCS#11 driver at a time. Vendor drivers and PC/SC readers cannot be shared: a second process silently sees no
tokens. The module host takes an exclusive flock on a per-module file BEFORE loading the .so and keeps it for its whole life (the
kernel drops it on any exit, SIGKILL included, so there are no stale locks)."""

import fcntl
import glob
import hashlib
import json
import os
import time

from . import safety
from .errors import DriverBusy

HOST_MARK = "tda_dsc_signer.host"


def lock_path(module, directory=None):
    name = "driver-" + hashlib.sha256(os.path.realpath(module).encode()).hexdigest()[:16] + ".lock"
    return os.path.join(directory or safety.state_dir(), name)


def _cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().replace(b"\0", b" ").decode(errors="replace").strip()[:300]
    except OSError:
        return ""


def _holder_error(module, info):
    pid = int(info.get("ppid") or info.get("pid") or 0)  # the front-end the user can close, not its host child
    started = time.strftime("%H:%M", time.localtime(info["started"])) if info.get("started") else "?"
    who = f"pid {pid}, started {started}" if pid else "pid unknown"
    msg = f"token driver {os.path.basename(module)} is in use by another tda-dsc-signer ({who}); close it or wait"
    return DriverBusy(msg, module, pid, str(info.get("cmd", "")))


def acquire(module, wait=0.0, directory=None, sleep=time.sleep):
    """Returns the locked fd (keep it open for the life of the process) or raises DriverBusy after `wait` seconds."""
    path = lock_path(module, directory)
    d = os.path.dirname(path)
    os.makedirs(d, mode=0o700, exist_ok=True)
    os.chmod(d, 0o700)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    os.fchmod(fd, 0o600)
    deadline = time.monotonic() + wait
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            if time.monotonic() >= deadline:
                try:
                    info = json.loads(os.pread(fd, 4096, 0) or b"{}")
                except ValueError:
                    info = {}
                os.close(fd)
                raise _holder_error(module, info) from None
            sleep(0.2)
    info = {"pid": os.getpid(), "ppid": os.getppid(), "cmd": _cmdline(os.getppid()), "started": time.time(), "module": module}
    os.ftruncate(fd, 0)
    os.pwrite(fd, json.dumps(info).encode(), 0)
    return fd


def holders(directory=None):
    """[(lock file, info)] of driver locks whose host process is alive. Read from the files, never by probing the lock itself
    (a probe would make a starting host see DriverBusy)."""
    out = []
    for f in sorted(glob.glob(os.path.join(directory or safety.state_dir(), "driver-*.lock"))):
        try:
            with open(f) as fh:
                info = json.load(fh)
            if HOST_MARK in _cmdline(int(info["pid"])):
                out.append((f, info))
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return out

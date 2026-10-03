"""Client side of the module-host pipe: per-request timeout, kill on hang, lazy restart. Sign requests are never auto-retried."""

import glob
import json
import os
import select
import subprocess
import sys
import threading
import time

from . import quirks
from .errors import HostBusy, HostError, HostTimeout, from_wire

POLL = 0.2
MAX_LINE = 8 * 1024 * 1024  # one protocol line; a host that sends more is broken or hostile
ENV_KEEP = ("PATH", "HOME", "LANG", "LC_ALL", "XDG_RUNTIME_DIR", "TMPDIR")  # nothing else (PIN env, tokens, LD_*, PYTHON*) reaches the host


KILL_WAIT = 10.0  # seconds a SIGKILLed host gets to be reaped before we give up spawning a replacement


def default_argv(module, wait=0.0):
    # -I: no cwd/PYTHONPATH/user-site on sys.path, so a ./tda_dsc_signer/ or ./pkcs11.py in the caller's cwd cannot shadow the
    # package inside the process that receives the PIN.
    argv = [sys.executable, "-I", "-m", "tda_dsc_signer.host", module]
    return [*argv, "--wait", str(wait)] if wait else argv


def minimal_env():
    return {k: os.environ[k] for k in ENV_KEEP if k in os.environ}


class ModuleHost:
    def __init__(self, module, argv=None, clock=time.monotonic, env=minimal_env, wait_driver=0.0):
        """wait_driver: seconds the host may wait for another tda-dsc-signer to release the driver (0 = fail fast, DriverBusy)."""
        self.module, self._clock, self._env, self.wait_driver = module, clock, env, float(wait_driver)
        self._argv = argv or (lambda m: default_argv(m, self.wait_driver))
        self._proc = None
        self._warm = False
        self._ids = 0
        self._buf = b""
        self._lock = threading.Lock()

    # -- lifecycle -------------------------------------------------------
    def _spawn(self):
        err = None if os.environ.get("DSC_DEBUG") else subprocess.DEVNULL
        self._proc = subprocess.Popen(self._argv(self.module), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err, env=self._env(), cwd="/")
        self._warm, self._buf = False, b""

    def kill(self):
        p, self._proc = self._proc, None
        if p and p.poll() is None:
            p.kill()
        if p:
            for f in (p.stdin, p.stdout):
                try:
                    f.close()
                except OSError:
                    pass
            try:  # the driver lock is only free once the old host is really gone: never spawn a replacement before that
                p.wait(timeout=KILL_WAIT)
            except subprocess.TimeoutExpired:
                raise HostError(f"module host pid {p.pid} for {self.module} did not exit after SIGKILL (stuck in the driver?)") from None

    close = kill

    @property
    def running(self):
        return self._proc is not None and self._proc.poll() is None

    # -- requests --------------------------------------------------------
    def call(self, method, params=None, timeout=quirks.CALL_TIMEOUT, blocking=True):
        if not self._lock.acquire(blocking):
            raise HostBusy(f"{self.module} is busy")
        try:
            if not self.running:
                self.kill()
                self._spawn()
            limit = timeout if self._warm else max(timeout, quirks.FIRST_CALL_TIMEOUT) + self.wait_driver
            started = time.time()
            try:
                reply = self._roundtrip(method, params or {}, limit)
            except HostError:
                if method == "sign":
                    self._remove_temp_outputs((params or {}).get("out"), started)
                raise
            self._warm = True
        finally:
            self._lock.release()
        if not reply["ok"]:
            try:
                exc = from_wire(reply["error"])
            except (TypeError, ValueError, AttributeError, KeyError) as e:  # a known class that rejects the message
                raise HostError(f"module host sent an unusable error: {type(e).__name__}") from None
            raise exc
        return reply["result"]

    @staticmethod
    def _remove_temp_outputs(out, since):
        """A killed sign leaves its `.dsc-*.pdf` temp file in the output directory; remove ours (created since `since`)."""
        if not isinstance(out, str):
            return
        for f in glob.glob(os.path.join(glob.escape(os.path.dirname(os.path.abspath(out))), ".dsc-*.pdf")):
            try:
                if os.path.getmtime(f) >= since - 1:
                    os.unlink(f)
            except OSError:
                pass

    def _roundtrip(self, method, params, limit):
        self._ids += 1
        rid = self._ids
        try:
            self._proc.stdin.write((json.dumps({"id": rid, "method": method, "params": params}) + "\n").encode())
            self._proc.stdin.flush()
            line = self._readline(self._clock() + limit)
        except (BrokenPipeError, OSError) as e:
            self.kill()
            raise HostError(f"module host for {self.module} died: {type(e).__name__}") from None
        except HostError:
            self.kill()  # a hung/oversized driver is unrecoverable in-process; the next call starts a fresh host
            raise
        try:
            reply = json.loads(line)
            ok = isinstance(reply, dict) and reply.get("id") == rid and isinstance(reply.get("ok"), bool)
            if ok and not reply["ok"]:
                ok = isinstance(reply.get("error"), dict) and all(isinstance(reply["error"].get(k), str) for k in ("type", "message"))
            if ok and reply["ok"]:
                ok = "result" in reply
        except ValueError:  # JSONDecodeError and UnicodeDecodeError
            ok = False
        if not ok:
            self.kill()
            raise HostError("module host sent a malformed or out-of-sequence reply")
        return reply

    def _readline(self, deadline):
        fd = self._proc.stdout.fileno()
        while b"\n" not in self._buf:
            left = deadline - self._clock()
            if left <= 0:
                raise HostTimeout(f"{self.module} did not answer in time")
            ready, _, _ = select.select([fd], [], [], min(left, POLL))
            if not ready:
                if self._proc.poll() is not None:  # a driver child may keep the pipe open after the host died
                    raise OSError("module host exited")
                continue
            chunk = os.read(fd, 65536)
            if not chunk:
                raise OSError("EOF from module host")
            self._buf += chunk
            if len(self._buf) > MAX_LINE and b"\n" not in self._buf[:MAX_LINE]:
                raise HostError(f"{self.module}: protocol line over {MAX_LINE} bytes")
        line, _, self._buf = self._buf.partition(b"\n")
        return line

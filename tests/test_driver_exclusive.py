"""Driver exclusivity: two processes can not share a vendor driver, so the second must say so instead of reporting 'no tokens'."""

import os
import re
import signal
import subprocess
import sys
import time

import pytest

from tda_dsc_signer import cli, config, doctor, driverlock, errors, hostclient, quirks, tokens
from tda_dsc_signer.errors import DriverBusy, TokenCountMismatch
from tda_dsc_signer.hostclient import ModuleHost
from tda_dsc_signer.service import TokenService

MODULE = "/nonexistent/libfake-driver.so"  # never loaded: the lock is taken before (and independent of) loading the .so


def gone(pid, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        try:
            os.kill(pid, 0)
            if open(f"/proc/{pid}/stat").read().split()[2] == "Z":
                return True
        except (ProcessLookupError, FileNotFoundError):
            return True
        time.sleep(0.05)
    return False


# ---- (a) two real processes ----------------------------------------------------------------------------------------------


def test_second_process_gets_a_typed_driver_busy_and_the_first_is_unaffected():
    first, second = ModuleHost(MODULE), ModuleHost(MODULE)
    try:
        assert first.call("ping") == "pong"
        with pytest.raises(DriverBusy) as e:
            second.call("ping")
        err = e.value
        assert err.module == MODULE and err.holder_pid == os.getpid()  # the front-end (us), not its host child
        assert re.fullmatch(
            r"token driver libfake-driver\.so is in use by another tda-dsc-signer \(pid \d+, started \d\d:\d\d\); close it or wait", err.args[0]
        )
        assert err.holder_cmd  # the parent's command line is recorded for diagnostics
        assert first.call("ping") == "pong"
        assert gone(second._proc.pid)  # the busy host answered once and exited without touching the .so
    finally:
        first.kill()
        second.kill()


def test_lock_file_is_private_and_describes_the_holder():
    h = ModuleHost(MODULE)
    try:
        h.call("ping")
        path = driverlock.lock_path(MODULE)
        assert oct(os.stat(path).st_mode & 0o777) == "0o600" and oct(os.stat(os.path.dirname(path)).st_mode & 0o777) == "0o700"
        info = __import__("json").load(open(path))
        assert info["pid"] == h._proc.pid and info["ppid"] == os.getpid() and info["started"] > 0
    finally:
        h.kill()


def test_service_reports_busy_driver_without_retry_storm(monkeypatch):
    mod = "/nonexistent/libInnaITPKCS11Driver.so"  # a driver that serves 338c:0031: its busy state explains the missing device
    holder = ModuleHost(mod)
    sleeps, spawns = [], []

    class Src:
        def modules(self):
            return [mod]

    class Counting(ModuleHost):
        def _spawn(self):
            spawns.append(1)
            super()._spawn()

    try:
        holder.call("ping")
        svc = TokenService(sources=[Src()], fallback=Nothing(), make_host=Counting, usb_devices=lambda: ["338c:0031"], sleep=sleeps.append)
        assert svc.discover() == []
        err = svc.errors[mod]
        assert isinstance(err, DriverBusy) and err.holder_pid == os.getpid() and "in use by another tda-dsc-signer" in err.args[0]
        assert "usb" not in svc.errors, "busy explains the shortfall: no mismatch noise"
        assert sleeps == [] and len(spawns) == 1, "no rescans, no respawn storm"
        assert svc.snapshot() == () and len(spawns) == 1, "the poller does not respawn a host against a busy driver"
        svc.close()
    finally:
        holder.kill()


# ---- (b) SIGKILL releases the lock ---------------------------------------------------------------------------------------


def test_lock_is_released_when_the_holder_is_sigkilled():
    a, b = ModuleHost(MODULE), ModuleHost(MODULE)
    try:
        a.call("ping")
        pid = a._proc.pid
        os.kill(pid, signal.SIGKILL)
        a._proc.wait()
        assert b.call("ping") == "pong", "no stale lock after SIGKILL"
        assert pid != b._proc.pid
    finally:
        a.kill()
        b.kill()


def test_wait_driver_waits_politely_then_succeeds():
    a = ModuleHost(MODULE)
    a.call("ping")
    b = ModuleHost(MODULE, wait_driver=10)
    import threading

    threading.Timer(1.0, a.kill).start()
    t0 = time.time()
    try:
        assert b.call("ping") == "pong" and 0.8 < time.time() - t0 < 9
    finally:
        a.kill()
        b.kill()


def test_default_argv_only_adds_wait_when_asked():
    assert "--wait" not in hostclient.default_argv("m")
    assert hostclient.default_argv("m", 5)[-2:] == ["--wait", "5"]


# ---- (c) USB count vs scan -----------------------------------------------------------------------------------------------


class FakeHost:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = 0

    def call(self, method, params=None, **kw):
        self.calls += 1
        r = self.replies[min(self.calls - 1, len(self.replies) - 1)]
        if isinstance(r, Exception):
            raise r
        return r

    def kill(self):
        pass


def cert_dict(serial):
    return tokens.cert_to_dict(tokens.TokenCert("m", 0, "T", serial, "L", b"\x00", "N", "O", "2099-01-01"))


class Nothing:
    def modules(self):
        return []


class One:
    def modules(self):
        return ["m"]


def svc_with(replies, usb, sleeps):
    host = FakeHost(replies)
    return TokenService(sources=[One()], fallback=Nothing(), make_host=lambda m: host, usb_devices=lambda: usb, sleep=sleeps.append), host


def test_empty_scan_with_usb_present_retries_then_records_mismatch():
    sleeps = []
    svc, host = svc_with([{"certs": [], "skipped": []}], ["338c:0031"], sleeps)
    assert svc.discover() == []
    assert sleeps == [quirks.RESCAN_BACKOFF] * quirks.RESCANS and host.calls == 1 + quirks.RESCANS
    err = svc.errors["usb"]
    assert isinstance(err, TokenCountMismatch) and (err.expected, err.found) == (1, 0)
    assert err.args[0] == "1 token device(s) detected but the driver returned 0; it may be busy or still starting: try Refresh"
    assert svc.expected_devices() == 1


def test_partial_result_also_warns():
    sleeps = []
    svc, _ = svc_with([[cert_dict("S1")]], ["338c:0031", "338c:0031"], sleeps)
    assert len(svc.discover()) == 1
    assert (svc.errors["usb"].expected, svc.errors["usb"].found) == (2, 1)


def test_rescan_that_recovers_clears_the_warning():
    sleeps = []
    svc, _ = svc_with([[cert_dict("S1")], [cert_dict("S1"), cert_dict("S2")]], ["338c:0031", "338c:0031"], sleeps)
    assert len(svc.discover()) == 2 and "usb" not in svc.errors and sleeps == [quirks.RESCAN_BACKOFF]


def test_no_usb_devices_means_no_rescans_and_no_warning():
    sleeps = []
    svc, host = svc_with([[]], [], sleeps)
    assert svc.discover() == [] and sleeps == [] and "usb" not in svc.errors and host.calls == 1


def test_usb_token_devices_reads_sysfs_ids(tmp_path):
    for name, vid, pid in (("1-2", "338c", "0031"), ("1-3", "096e", "080a"), ("1-4", "046d", "c52b"), ("1-2:1.0", None, None)):
        d = tmp_path / name
        d.mkdir()
        if vid:
            (d / "idVendor").write_text(vid + "\n")
            (d / "idProduct").write_text(pid + "\n")
    assert quirks.usb_token_devices(str(tmp_path)) == ["338c:0031", "096e:080a"]
    assert {"338c:0031", "096e:0807", "096e:080a", "096e:080f"} <= set(quirks.KNOWN_USB)


# ---- (d) restart waits for the old host ----------------------------------------------------------------------------------

HANG = """
import time, tda_dsc_signer.host as h
class B(h.ModuleBackend):
    def present(self, p):
        time.sleep(60)
h.ModuleBackend = B
h.main([%r])
"""


def test_restart_after_timeout_never_sees_its_own_old_host_as_busy(monkeypatch):
    monkeypatch.setattr(quirks, "FIRST_CALL_TIMEOUT", 1)
    h = ModuleHost(MODULE, argv=lambda m: [sys.executable, "-I", "-c", HANG % m])
    try:
        h.call("ping")
        old = h._proc.pid
        with pytest.raises(errors.HostTimeout):
            h.call("present", timeout=1)
        assert gone(old, 0.01), "kill() returned only after the old host was reaped"
        assert h.call("ping") == "pong" and h._proc.pid != old  # a DriverBusy here would mean the lock was still held
    finally:
        h.kill()


def test_unreapable_host_blocks_the_replacement_with_a_clear_error(monkeypatch):
    class Stuck:
        pid = 4242
        stdin = stdout = type("P", (), {"close": lambda s: None})()

        def poll(self):
            return None

        def kill(self):
            pass

        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired("x", timeout)

    h = ModuleHost("m")
    h._proc = Stuck()
    with pytest.raises(errors.HostError, match="did not exit after SIGKILL"):
        h.kill()


# ---- (e) the host dies with its parent ------------------------------------------------------------------------------------

PARENT = """
import sys, time
from tda_dsc_signer.hostclient import ModuleHost
h = ModuleHost(%r)
h.call("ping")
print(h._proc.pid, flush=True)
time.sleep(120)
"""


def test_host_exits_and_releases_the_lock_when_its_parent_is_sigkilled():
    parent = subprocess.Popen([sys.executable, "-I", "-c", PARENT % MODULE], stdout=subprocess.PIPE, text=True, env=dict(os.environ))
    try:
        host_pid = int(parent.stdout.readline())
        # (g) doctor sees the live holder
        c = doctor.check_driver_exclusivity()
        assert not c.ok and str(parent.pid) in c.detail and "close it" in c.fix
        os.kill(parent.pid, signal.SIGKILL)
        parent.wait()
        assert gone(host_pid), "host still alive after its parent was SIGKILLed"
        fd = driverlock.acquire(MODULE)  # the lock is free again
        os.close(fd)
        assert doctor.check_driver_exclusivity().ok
    finally:
        parent.kill()
        parent.wait()


# ---- CLI ------------------------------------------------------------------------------------------------------------------


class BusySvc:
    def __init__(self, *a, **kw):
        BusySvc.kw = kw
        self.errors = {
            "/m.so": DriverBusy("token driver m.so is in use by another tda-dsc-signer (pid 7, started 10:00); close it or wait", "/m.so", 7)
        }

    def discover(self, extra=()):
        return []

    def check_recent_failure(self, *a):
        pass

    def close(self):
        pass


def test_cli_list_and_sign_report_busy_prominently_and_sign_exits_3(monkeypatch, capsys, tmp_path, pdf3):
    monkeypatch.setattr(cli, "TokenService", BusySvc)
    monkeypatch.setattr(cli.config, "load", lambda: config.Config())
    assert cli.main(["list", "--wait-driver", "2.5"]) == 3
    assert BusySvc.kw["wait_driver"] == 2.5
    assert "WARNING: token driver m.so is in use by another tda-dsc-signer (pid 7" in capsys.readouterr().err
    with pytest.raises(SystemExit) as e:
        cli.main(["sign", str(pdf3), "-o", str(tmp_path / "o.pdf")])
    assert e.value.code == 3 and "WARNING: token driver m.so" in capsys.readouterr().err


def test_cli_prints_the_usb_mismatch_warning(capsys):
    class S:
        errors = {"usb": TokenCountMismatch(2, 1)}

    cli.warn_errors(S())
    assert "WARNING: 2 token device(s) detected but the driver returned 1" in capsys.readouterr().err


def test_wire_roundtrip_keeps_driver_busy_attributes():
    e = errors.from_wire(errors.to_wire(DriverBusy("msg", "/m.so", 9, "cmd")))
    assert isinstance(e, DriverBusy) and (e.args[0], e.module, e.holder_pid, e.holder_cmd) == ("msg", "/m.so", 9, "cmd")


def test_doctor_check_with_no_holder_is_ok_and_reports_usb_count():
    c = doctor.check_driver_exclusivity(holders=lambda: [], usb=lambda: ["338c:0031"])
    assert c.ok and "1 known token USB device" in c.detail


# ---- CLI as a real process: exit status and message ------------------------------------------------------------------------

CLI_SCRIPT = """
import sys
from tda_dsc_signer import cli, quirks, tokens
quirks.SYSFS_USB = "/nonexistent"
mod = sys.argv[1]
cli.default_sources = lambda extra=(), allow=(): [tokens.VettedSource(tokens.GlobSource([mod]), allow)]
sys.exit(cli.main(sys.argv[2:]))
"""


@pytest.mark.parametrize("sub", ["list", "sign"])
def test_cli_process_exits_3_with_the_busy_hint_and_not_the_plugged_in_hint(tmp_path, pdf3, sub):
    dummy = tmp_path / "libdummy.so"
    dummy.write_bytes(b"\x7fELF")
    dummy.chmod(0o755)
    holder = ModuleHost(str(dummy))
    try:
        holder.call("ping")  # another "tda-dsc-signer" (this test process) owns the driver
        args = ["list"] if sub == "list" else ["sign", str(pdf3), "-o", str(tmp_path / "o.pdf")]
        env = {**os.environ, "XDG_CONFIG_HOME": str(tmp_path / "cfg")}
        r = subprocess.run(
            [sys.executable, "-I", "-c", CLI_SCRIPT, str(dummy), *args, "--allow-user-module", str(dummy)],
            capture_output=True, text=True, env=env, timeout=60, stdin=subprocess.DEVNULL,
        )  # fmt: skip
        assert r.returncode == 3, (r.returncode, r.stdout, r.stderr)  # the process's own status
        both = r.stdout + r.stderr
        assert f"Another tda-dsc-signer (pid {os.getpid()}) is using the token driver. Close it, then retry (or use --wait-driver SECONDS)." in both
        assert "WARNING: token driver libdummy.so is in use by another tda-dsc-signer" in r.stderr
        assert "plugged in" not in both and "pcscd" not in both
        assert not (tmp_path / "o.pdf").exists()
    finally:
        holder.kill()

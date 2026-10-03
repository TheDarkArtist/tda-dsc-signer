"""Findings 1, 2, 3, 15, 16: how the module host is spawned, what it inherits, and how the client reacts to a misbehaving host."""

import json
import os
import signal
import subprocess
import sys
import time

import pytest

from tda_dsc_signer import cli, errors, hostclient, quirks
from tda_dsc_signer.hostclient import ModuleHost

SHADOW_HOST = "import pathlib; pathlib.Path(__file__).with_name('PWNED').write_text('shadow host ran')\n"


@pytest.fixture
def shadow_cwd(tmp_path, monkeypatch):
    """A cwd that contains look-alikes of the package and of the PKCS#11 binding (finding 1)."""
    d = tmp_path / "evil"
    (d / "tda_dsc_signer").mkdir(parents=True)
    (d / "tda_dsc_signer" / "__init__.py").write_text("")
    (d / "tda_dsc_signer" / "host.py").write_text(SHADOW_HOST)
    (d / "pkcs11.py").write_text("raise SystemExit('shadow pkcs11 imported')\n")
    monkeypatch.chdir(d)
    return d


def test_unhardened_spawn_would_be_shadowed_control(shadow_cwd):
    # control: the OLD argv (no -I, caller's cwd) really does import the shadow package, so the next test is meaningful
    env = {"PATH": os.environ["PATH"], "PYTHONPATH": ""}
    subprocess.run([sys.executable, "-m", "tda_dsc_signer.host", "x"], cwd=shadow_cwd, env=env, stdin=subprocess.DEVNULL, timeout=20)
    assert (shadow_cwd / "tda_dsc_signer" / "PWNED").exists()


def test_host_imports_the_real_package_even_with_a_shadow_package_in_cwd(shadow_cwd):
    h = ModuleHost("/nonexistent/module.so")
    try:
        assert h.call("ping") == "pong"
        assert h.call("enumerate") == {"certs": [], "skipped": []}
    finally:
        h.kill()
    assert not (shadow_cwd / "tda_dsc_signer" / "PWNED").exists()
    argv = hostclient.default_argv("m")
    assert "-I" in argv and argv.index("-I") < argv.index("-m")


DUMP = """
import json, os, sys
from tda_dsc_signer.host import serve
class B:
    def ping(self, p):
        return {"env": dict(os.environ), "argv": sys.argv, "cwd": os.getcwd()}
serve(sys.stdin, sys.stdout, B())
"""


def test_host_gets_minimal_env_and_cwd_root_and_no_pin(monkeypatch):
    monkeypatch.setenv(cli.PIN_ENV, "SECRET-PIN-123")
    monkeypatch.setenv("LD_PRELOAD", "/x/evil.so")
    monkeypatch.setenv("PYTHONPATH", "/x/evil")
    h = ModuleHost("m", lambda m: [sys.executable, "-I", "-c", DUMP, m])
    try:
        got = h.call("ping")
    finally:
        h.kill()
    assert set(got["env"]) <= set(hostclient.ENV_KEEP) | {"LC_CTYPE"}  # python may add LC_CTYPE when coercing the C locale
    assert "SECRET-PIN-123" not in json.dumps(got)
    assert got["cwd"] == "/"


def test_cli_pops_pin_from_environ_immediately(monkeypatch):
    monkeypatch.setenv(cli.PIN_ENV, "SECRET-PIN-123")
    seen = {}

    class Doctor:
        @staticmethod
        def diagnose():
            seen["env"] = dict(os.environ)

        @staticmethod
        def report(_):
            return 0

    monkeypatch.setattr(cli, "doctor", Doctor)
    assert cli.main(["doctor"]) == 0
    assert cli.PIN_ENV not in seen["env"] and cli.PIN_ENV not in os.environ


class FakeSvc:
    def __init__(self, cert):
        self.cert, self.signed, self.checked = cert, [], []
        self.errors = {}

    def discover(self, extra=()):
        return [self.cert]

    def check_recent_failure(self, cert, confirm):
        self.checked.append(confirm)

    def sign(self, src, cert, **kw):
        self.signed.append(kw)
        from tda_dsc_signer.signing import SignResult

        return SignResult(kw["out"], "Sig1", 1, ())


def _cert(**kw):
    from tda_dsc_signer import tokens

    return tokens.TokenCert("m", 0, "T", "S1", "L", b"\x00", "N", "O", "2099-01-01", **kw)


def test_pin_fd_is_read_from_the_inherited_descriptor_and_wins_over_env(monkeypatch, tmp_path, pdf3):
    from tda_dsc_signer import config, verify

    r, w = os.pipe()
    os.write(w, b"fd-pin-1\nignored\n")
    os.close(w)
    monkeypatch.setattr(verify, "verify_signed", lambda *a, **k: verify.VerifyResult((), "", False, True, "ok"))
    a = cli._parser(config.Config()).parse_args(["sign", str(pdf3), "--pin-fd", str(r), "-o", str(tmp_path / "o.pdf")])
    svc = FakeSvc(_cert())
    assert cli._sign(a, config.Config(), svc, env_pin="env-pin") is True
    assert svc.signed[0]["pin"] == "fd-pin-1"
    assert svc.checked == [False]  # the wrong-PIN memory is consulted before any prompt


def test_cli_exit_code_is_nonzero_when_verification_fails(monkeypatch, tmp_path, pdf3, capsys):
    from tda_dsc_signer import config, verify

    monkeypatch.setattr(cli.config, "load", lambda: config.Config())
    monkeypatch.setattr(cli, "TokenService", lambda *_, **__: FakeSvc(_cert()))
    monkeypatch.setattr(FakeSvc, "close", lambda self: None, raising=False)
    bad = verify.VerifyResult((), "", False, False, "MODIFIED, certificate REVOKED")
    monkeypatch.setattr(verify, "verify_signed", lambda *a, **k: bad)
    rc = cli.main(["sign", str(pdf3), "-o", str(tmp_path / "o.pdf"), "--pin-fd", str(_pipe_with(b"1\n"))])
    assert rc == 2
    assert "Verification: FAILED" in capsys.readouterr().out


def _pipe_with(data):
    r, w = os.pipe()
    os.write(w, data)
    os.close(w)
    return r


# ---- finding 3 ---------------------------------------------------------------------------------------------------------


def test_host_disables_core_dumps_and_ptrace_access():
    code = (
        "import resource, ctypes\n"
        "import tda_dsc_signer.host as h\n"
        "class B(h.ModuleBackend):\n"
        "    def ping(self, p):\n"
        "        return [list(resource.getrlimit(resource.RLIMIT_CORE)), ctypes.CDLL(None).prctl(3, 0, 0, 0, 0)]\n"
        "h.ModuleBackend = B\n"
        "h.main(['/nonexistent/module.so'])\n"
    )
    h = ModuleHost("x", lambda m: [sys.executable, "-I", "-c", code])
    try:
        core, dumpable = h.call("ping")
    finally:
        h.kill()
    assert core == [0, 0] and dumpable == 0  # PR_GET_DUMPABLE == 0


# ---- finding 16 / 15 ---------------------------------------------------------------------------------------------------

FAKE_BAD = r"""
import json, os, subprocess, sys, time
mode, pidfile = sys.argv[1], sys.argv[2]
req = json.loads(sys.stdin.readline())
rid = req["id"]
if mode == "garbage":
    sys.stdout.write("this is not json\n")
elif mode == "binary":
    sys.stdout.buffer.write(b"\xff\xfe\x00\n")
elif mode == "list":
    sys.stdout.write("[1, 2]\n")
elif mode == "noerror":
    sys.stdout.write(json.dumps({"id": rid, "ok": False}) + "\n")
elif mode == "huge":
    sys.stdout.write("x" * 100000)
elif mode == "orphan_exit":  # a driver child keeps stdout open after the host dies
    p = subprocess.Popen(["sleep", "30"])
    open(pidfile, "w").write(str(p.pid))
    sys.stdout.flush()
    os._exit(3)
elif mode == "temp_then_hang":
    open(os.path.join(os.path.dirname(req["params"]["out"]), ".dsc-abc123.pdf"), "w").write("partial")
    time.sleep(60)
sys.stdout.flush()
time.sleep(60)
"""


def bad_host(mode, tmp_path):
    return ModuleHost("m", lambda m: [sys.executable, "-I", "-c", FAKE_BAD, mode, str(tmp_path / "pid")])


@pytest.mark.parametrize("mode", ["garbage", "binary", "list", "noerror"])
def test_garbage_reply_kills_host_and_raises_host_error(mode, tmp_path):
    h = bad_host(mode, tmp_path)
    t0 = time.time()
    with pytest.raises(errors.HostError):
        h.call("ping")
    assert time.time() - t0 < 10 and not h.running  # killed, not left hanging


def test_oversized_line_is_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(hostclient, "MAX_LINE", 4096)
    h = bad_host("huge", tmp_path)
    with pytest.raises(errors.HostError, match="over 4096"):
        h.call("ping")
    assert not h.running


def test_default_line_cap_is_8_mb():
    assert hostclient.MAX_LINE == 8 * 1024 * 1024


def test_host_exit_is_noticed_without_waiting_for_the_timeout(tmp_path):
    h = bad_host("orphan_exit", tmp_path)
    t0 = time.time()
    try:
        with pytest.raises(errors.HostError) as e:  # the pipe never closes because of the orphan: only poll() sees the exit
            h.call("ping", timeout=60)
        assert not isinstance(e.value, errors.HostTimeout) and time.time() - t0 < 10
    finally:
        pid = (tmp_path / "pid").read_text()
        os.kill(int(pid), signal.SIGKILL)


def test_killed_sign_removes_its_temp_output(tmp_path, monkeypatch):
    monkeypatch.setattr(quirks, "FIRST_CALL_TIMEOUT", 1)  # a fresh host otherwise gets the 60 s first-call allowance
    out = tmp_path / "o.pdf"
    h = bad_host("temp_then_hang", tmp_path)
    with pytest.raises(errors.HostTimeout):
        h.call("sign", {"out": str(out)}, timeout=1)
    assert list(tmp_path.glob(".dsc-*.pdf")) == []
    (tmp_path / ".dsc-old.pdf").write_text("x")  # not ours (older than the call): untouched by a later kill
    old = time.time() - 3600
    os.utime(tmp_path / ".dsc-old.pdf", (old, old))
    with pytest.raises(errors.HostTimeout):
        h.call("sign", {"out": str(out)}, timeout=1)
    assert (tmp_path / ".dsc-old.pdf").exists()

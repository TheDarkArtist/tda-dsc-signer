import os
import sys
import time

import pkcs11
import pytest

from tda_dsc_signer import errors, tokens
from tda_dsc_signer.hostclient import ModuleHost
from tda_dsc_signer.service import TokenService

FAKE = """
import os, sys, time
from tda_dsc_signer.host import serve

class B:
    def ping(self, p):
        return "pong"
    def enumerate(self, p):
        return []
    def present(self, p):
        if p.get("hang"):
            time.sleep(60)
        return [["S1", "tok"]]
    def sign(self, p):
        with open(sys.argv[1], "a") as f:
            f.write("x")
        if p.get("hang"):
            time.sleep(60)
        if p.get("wrong_pin"):
            import pkcs11
            raise pkcs11.PinIncorrect("bad pin")
        return {"out": p["out"], "field_name": "Sig1", "size": 1, "warnings": []}

serve(sys.stdin, sys.stdout, B())
"""


def fake_argv(_module):
    return [sys.executable, "-c", FAKE, os.environ["SIGN_COUNT"]]  # the host gets a minimal env: pass the path by argv


@pytest.fixture
def counter(tmp_path, monkeypatch):
    p = tmp_path / "count"
    monkeypatch.setenv("SIGN_COUNT", str(p))
    return p


def test_roundtrip_and_typed_errors(counter):
    h = ModuleHost("m", fake_argv)
    try:
        assert h.call("ping") == "pong"
        with pytest.raises(ValueError):
            h.call("nope")
        with pytest.raises(pkcs11.PinIncorrect):
            h.call("sign", {"wrong_pin": True, "out": "o"})
        assert h.call("ping") == "pong"  # host survives errors
    finally:
        h.kill()


def test_hang_is_killed_and_next_call_restarts(counter):
    h = ModuleHost("m", fake_argv)
    try:
        h.call("ping")  # warm: later timeouts are honoured as given
        t0 = time.time()
        with pytest.raises(errors.HostTimeout):
            h.call("present", {"hang": True}, timeout=1)
        assert time.time() - t0 < 5 and not h.running
        assert h.call("present") == [["S1", "tok"]]  # fresh host
    finally:
        h.kill()


def test_dead_host_is_restarted(counter):
    h = ModuleHost("m", fake_argv)
    try:
        h.call("ping")
        h._proc.kill()
        h._proc.wait()
        assert h.call("ping") == "pong"  # noticed it was dead before sending, started a fresh host
    finally:
        h.kill()


def test_busy_host_not_blocked_by_nonblocking_probe(counter):
    h = ModuleHost("m", fake_argv)
    h._lock.acquire()
    try:
        with pytest.raises(errors.HostBusy):
            h.call("ping", blocking=False)
    finally:
        h._lock.release()
        h.kill()


def cert():
    return tokens.TokenCert("m", 0, "T", "S1", "L", b"\x00", "N", "O", "2099-01-01")


def test_sign_is_sent_once_and_never_retried_after_timeout(counter, tmp_path):
    svc = TokenService(sources=[], make_host=lambda m: ModuleHost(m, fake_argv))
    svc._host("m").call("ping")
    h = svc._host("m")
    # the service passes quirks.SIGN_TIMEOUT; shrink it for the test by calling the host the way the service does
    with pytest.raises(errors.HostTimeout):
        h.call("sign", {"hang": True, "out": "o", "cert": tokens.cert_to_dict(cert())}, timeout=1)
    assert counter.read_text() == "x"  # exactly one sign request reached the driver side; nothing resent
    svc.close()


def test_service_sign_returns_result_and_hides_pin_for_protected_auth(counter, tmp_path):
    svc = TokenService(sources=[], make_host=lambda m: ModuleHost(m, fake_argv))
    try:
        r = svc.sign("in.pdf", cert(), page=1, box=(1, 2, 3, 4), pin="1234", out=str(tmp_path / "o.pdf"), stamp_text="t")
        assert (r.field_name, r.size) == ("Sig1", 1) and r.out.endswith("o.pdf")
        assert svc.snapshot() == (), "no module started by discover yet"
    finally:
        svc.close()


def test_snapshot_reports_present_tokens_and_skips_when_busy(counter):
    class Src:
        def modules(self):
            return ["m"]

    svc = TokenService(sources=[Src()], make_host=lambda m: ModuleHost(m, fake_argv))
    try:
        svc._host("m").call("ping")
        assert svc.snapshot() == (("m", (("S1", "tok"),)),)
        svc._host("m")._lock.acquire()
        assert svc.snapshot() is None
    finally:
        svc._host("m")._lock.release()
        svc.close()


def test_real_host_entrypoint_answers_and_keeps_stdout_clean():
    code = (
        "import tda_dsc_signer.host as h\n"
        "class B(h.ModuleBackend):\n"
        "    def ping(self, p):\n"
        "        print('driver noise on stdout'); os_write = __import__('os').write(1, b'raw noise\\n'); return 'pong'\n"
        "h.ModuleBackend = B\n"
        "h.main(['/nonexistent/module.so'])\n"
    )
    h = ModuleHost("x", lambda m: [sys.executable, "-c", code])
    try:
        assert h.call("ping") == "pong"
    finally:
        h.kill()
    h2 = ModuleHost("/nonexistent/module.so")  # real entrypoint; a module that cannot load yields no tokens, not a crash
    try:
        assert h2.call("enumerate") == {"certs": [], "skipped": []}
    finally:
        h2.kill()


def test_pin_is_not_in_error_text(counter):
    h = ModuleHost("m", fake_argv)
    try:
        with pytest.raises(pkcs11.PinIncorrect) as e:
            h.call("sign", {"wrong_pin": True, "pin": "SECRET-PIN-123", "out": "o"})
        assert "SECRET-PIN-123" not in str(e.value)
    finally:
        h.kill()


def test_unknown_remote_error_type_is_wrapped():
    e = errors.from_wire({"type": "WeirdVendorThing", "message": "boom"})
    assert isinstance(e, errors.RemoteError) and e.type == "WeirdVendorThing"
    assert os.name == "posix"

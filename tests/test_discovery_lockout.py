"""Findings 4 (discovery survives hostile modules/objects), 9 (wrong-PIN memory across invocations)."""

import os
import stat
import threading

import pkcs11
import pytest
from conftest import der
from pkcs11 import Attribute

from tda_dsc_signer import safety, tokens
from tda_dsc_signer.errors import HostError
from tda_dsc_signer.service import TokenService
from tda_dsc_signer.watch import Poller


class Src:
    def __init__(self, *mods):
        self._m = list(mods)

    def modules(self):
        return self._m


class FakeHost:
    """Stands in for ModuleHost: the reply (or exception) per method comes from `script`."""

    def __init__(self, script):
        self.script, self.calls = script, []

    def call(self, method, params=None, **kw):
        self.calls.append(method)
        r = self.script[method]
        if isinstance(r, Exception):
            raise r
        return r

    def kill(self):
        pass


def good_cert():
    return tokens.cert_to_dict(tokens.TokenCert("good", 0, "T", "S1", "L", b"\x00", "N", "O", "2099-01-01"))


@pytest.mark.parametrize(
    "exc",
    [ValueError("x"), UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad"), KeyError("k"), AttributeError("a"), HostError("h"), RuntimeError("r")],
)
def test_one_failing_module_never_aborts_discovery_of_the_others(exc):
    hosts = {"bad": FakeHost({"enumerate": exc}), "good": FakeHost({"enumerate": [good_cert()]})}
    svc = TokenService(sources=[Src("bad", "good")], fallback=Src(), make_host=hosts.__getitem__, wrong_pins=safety.WrongPinMemory())
    found = svc.discover()
    assert [c.module for c in found] == ["good"]
    assert type(svc.errors["bad"]) is type(exc)


def test_garbage_certificate_dict_from_a_module_is_recorded_not_fatal():
    hosts = {"bad": FakeHost({"enumerate": [{"nonsense": 1}]}), "good": FakeHost({"enumerate": {"certs": [good_cert()], "skipped": ["slot 0: x"]}})}
    svc = TokenService(sources=[Src("bad", "good")], fallback=Src(), make_host=hosts.__getitem__)
    assert len(svc.discover()) == 1
    assert "bad" in svc.errors and "unreadable object" in str(svc.errors["good"])  # skipped objects are reported, certs kept


def test_snapshot_survives_a_module_that_raises():
    host = FakeHost({"present": ValueError("boom")})
    svc = TokenService(sources=[Src("m")], make_host=lambda m: host)
    svc._host("m")
    assert svc.snapshot() == ()
    assert isinstance(svc.errors["m"], ValueError)


def test_poller_thread_survives_exceptions_and_reports_them():
    calls, errs, fired = [], [], threading.Event()

    def snap():
        calls.append(1)
        if len(calls) < 3:
            raise ValueError("flaky host")
        fired.set()
        return "A"

    p = Poller(snap, lambda s: None, interval=0.01, on_error=errs.append)
    p.start("A")
    assert fired.wait(5), "thread died after the first exception"
    p.stop()
    assert len(errs) == 2 and all(isinstance(e, ValueError) for e in errs) and isinstance(p.last_error, ValueError)


# ---- malformed certificate objects on a (fake) token --------------------------------------------------------------------


class Obj(dict):
    pass


class Session:
    def __init__(self, objs):
        self.objs = objs

    def get_objects(self, template):
        return list(self.objs)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass


class Token:
    label, serial, flags = "T\x1b[31m", b"S1", pkcs11.TokenFlag(0)

    def __init__(self, objs):
        self.objs = objs

    def open(self):
        return Session(self.objs)


class Slot:
    def __init__(self, objs):
        self.objs = objs

    def get_token(self):
        return Token(self.objs)


def obj(value, label="L", ident=b"\x01"):
    return Obj({Attribute.VALUE: value, Attribute.LABEL: label, Attribute.ID: ident})


def test_malformed_certificate_object_is_skipped_and_good_one_kept(pki):
    objs = [obj(b"\x30\x03garbage"), obj(object()), obj(der(pki["leaf"]))]
    skipped = []
    out = tokens.signing_certs("m", lambda path: type("L", (), {"get_slots": lambda s: [Slot(objs)]})(), skipped=skipped)
    assert [c.cn for c in out] == ["Test Signer"] and len(skipped) == 2
    assert out[0].token == "T?[31m"  # finding 22: ESC from the token label is neutralised


def test_clean_strips_control_and_bidi_characters():
    assert tokens.clean("a\x1b[2Jb‮c\x00") == "a?[2Jb?c?"


def test_signing_certs_survives_a_slot_that_raises_oddly():
    class BadSlot:
        def get_token(self):
            raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")

    skipped = []
    assert tokens.signing_certs("m", lambda p: type("L", (), {"get_slots": lambda s: [BadSlot()]})(), skipped=skipped) == []
    assert skipped and "UnicodeDecodeError" in skipped[0]


# ---- finding 9: wrong-PIN memory ------------------------------------------------------------------------------------------


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def cert():
    return tokens.TokenCert("m", 0, "T", "S1", "L", b"\x00", "N", "O", "2099-01-01")


class SignHost:
    def __init__(self, fail=True):
        self.signs, self.fail = 0, fail

    def call(self, method, params=None, **kw):
        assert method == "sign"
        self.signs += 1
        if self.fail:
            raise pkcs11.PinIncorrect("bad pin")
        return {"out": params["out"], "field_name": "Sig1", "size": 1, "warnings": []}

    def kill(self):
        pass


def make_svc(tmp_path, host, clock):
    mem = safety.WrongPinMemory(str(tmp_path / "wp"), clock=clock)
    return TokenService(sources=[], make_host=lambda m: host, wrong_pins=mem), mem


def do_sign(svc, tmp_path, **kw):
    return svc.sign(str(tmp_path / "in.pdf"), cert(), page=1, box=(1, 2, 3, 4), pin="1234", out=str(tmp_path / "o.pdf"), stamp_text="t", **kw)


def test_second_attempt_within_window_refuses_before_any_login_call(tmp_path):
    clock, host = Clock(), SignHost()
    svc, _ = make_svc(tmp_path, host, clock)
    with pytest.raises(pkcs11.PinIncorrect):
        do_sign(svc, tmp_path)
    assert host.signs == 1
    clock.t += 30
    with pytest.raises(safety.RecentWrongPin) as e:
        do_sign(svc, tmp_path)
    assert host.signs == 1, "refused BEFORE the host (and so before C_Login) was asked"
    assert (e.value.serial, e.value.count) == ("S1", 1) and 269 < e.value.remaining <= 270


def test_memory_is_shared_across_service_instances_like_separate_invocations(tmp_path):
    clock = Clock()
    svc1, _ = make_svc(tmp_path, SignHost(), clock)
    with pytest.raises(pkcs11.PinIncorrect):
        do_sign(svc1, tmp_path)
    host2 = SignHost()
    svc2, _ = make_svc(tmp_path, host2, clock)
    with pytest.raises(safety.RecentWrongPin):
        do_sign(svc2, tmp_path)
    assert host2.signs == 0


def test_confirm_after_failure_allows_the_attempt_and_counts_failures(tmp_path):
    clock, host = Clock(), SignHost()
    svc, mem = make_svc(tmp_path, host, clock)
    with pytest.raises(pkcs11.PinIncorrect):
        do_sign(svc, tmp_path)
    with pytest.raises(pkcs11.PinIncorrect):
        do_sign(svc, tmp_path, confirm_after_failure=True)
    assert host.signs == 2
    with pytest.raises(safety.RecentWrongPin) as e:
        mem.check("S1")
    assert e.value.count == 2


def test_record_expires_after_five_minutes(tmp_path):
    clock, host = Clock(), SignHost()
    svc, _ = make_svc(tmp_path, host, clock)
    with pytest.raises(pkcs11.PinIncorrect):
        do_sign(svc, tmp_path)
    clock.t += 299
    with pytest.raises(safety.RecentWrongPin):
        do_sign(svc, tmp_path)
    clock.t += 2  # 301 s after the failure
    with pytest.raises(pkcs11.PinIncorrect):
        do_sign(svc, tmp_path)
    assert host.signs == 2


def test_successful_login_clears_the_record(tmp_path):
    clock, host = Clock(), SignHost()
    svc, mem = make_svc(tmp_path, host, clock)
    with pytest.raises(pkcs11.PinIncorrect):
        do_sign(svc, tmp_path)
    host.fail = False
    do_sign(svc, tmp_path, confirm_after_failure=True)
    mem.check("S1")  # no longer raises
    do_sign(svc, tmp_path)  # and no confirmation needed any more


def test_other_tokens_are_not_affected(tmp_path):
    mem = safety.WrongPinMemory(str(tmp_path / "wp"), clock=Clock())
    mem.record("S1")
    mem.check("S2")


def test_state_dir_is_0700_file_0600_and_holds_no_pin(tmp_path):
    mem = safety.WrongPinMemory(str(tmp_path / "wp"), clock=Clock())
    mem.record("S1")
    d = tmp_path / "wp"
    (f,) = d.iterdir()
    assert stat.S_IMODE(d.stat().st_mode) == 0o700 and stat.S_IMODE(f.stat().st_mode) == 0o600
    assert "1234" not in f.read_text() and "S1" not in f.name


def test_default_location_prefers_xdg_runtime_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    safety.WrongPinMemory(clock=Clock()).record("S1")
    assert os.listdir(tmp_path / "run" / "tda-dsc-signer")
    monkeypatch.delenv("XDG_RUNTIME_DIR")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    safety.WrongPinMemory(clock=Clock()).record("S1")
    assert os.listdir(tmp_path / "home" / ".cache" / "tda-dsc-signer")


def test_corrupt_record_is_ignored_rather_than_locking_the_user_out(tmp_path):
    mem = safety.WrongPinMemory(str(tmp_path / "wp"), clock=Clock())
    mem.record("S1")
    (f,) = (tmp_path / "wp").iterdir()
    f.write_text("{not json")
    mem.check("S1")


# ---- finding 5: module vetting and dedupe --------------------------------------------------------------------------------


def lib(tmp_path, name="m.so", mode=0o755, dirmode=0o755):
    d = tmp_path / "libdir"
    d.mkdir(exist_ok=True)
    d.chmod(dirmode)
    f = d / name
    f.write_bytes(b"\x7fELF")
    f.chmod(mode)
    return str(f)


def test_user_owned_module_needs_an_explicit_allow(tmp_path):
    m = lib(tmp_path)
    assert "not allowed" in tokens.vet_module(m)
    assert tokens.vet_module(m, allow=[m]) == ""


def test_group_or_world_writable_module_or_dir_is_refused_even_if_allowed(tmp_path):
    m = lib(tmp_path, mode=0o775)
    assert "file is writable" in tokens.vet_module(m, allow=[m])
    m = lib(tmp_path, name="n.so", dirmode=0o777)
    assert "directory is writable" in tokens.vet_module(m, allow=[m])


def test_relative_missing_foreign_owner_and_non_regular_are_refused(tmp_path):
    assert "absolute" in tokens.vet_module("rel.so")
    assert "not accessible" in tokens.vet_module(str(tmp_path / "nope.so"))
    assert "not a regular file" in tokens.vet_module(str(tmp_path))
    m = lib(tmp_path)
    assert "owned by uid" in tokens.vet_module(m, uid=os.geteuid() + 1)


def test_root_owned_system_module_passes_without_allow():
    assert tokens.vet_module("/usr/lib/opensc-pkcs11.so") == "" if os.path.exists("/usr/lib/opensc-pkcs11.so") else True


def test_vetted_source_drops_and_reports_and_service_surfaces_it(tmp_path):
    m = lib(tmp_path)
    src = tokens.VettedSource(tokens.GlobSource([m]), allow=[])
    svc = TokenService(sources=[src], fallback=Src(), make_host=lambda m: FakeHost({"enumerate": []}), allow_user_modules=[])
    assert svc.discover() == []
    assert "module refused" in str(svc.errors[os.path.realpath(m)])
    ok = tokens.VettedSource(tokens.GlobSource([m]), allow=[m])
    assert ok.modules() == [os.path.realpath(m)] and ok.rejected == {}


def test_same_cert_seen_through_two_modules_is_listed_once():
    a, b = (
        tokens.TokenCert("/user/a.so", 0, "T", "S1", "L", b"\x01", "N", "O", "2099-01-01"),
        tokens.TokenCert("/usr/lib/libc.so.6", 0, "T", "S1", "L", b"\x01", "N", "O", "2099-01-01"),
    )
    from tda_dsc_signer.service import dedupe

    assert dedupe([a, b]) == [b]  # the root-owned module wins
    other = tokens.TokenCert("/user/a.so", 0, "T", "S2", "L", b"\x01", "N", "O", "2099-01-01")
    assert len(dedupe([a, other])) == 2

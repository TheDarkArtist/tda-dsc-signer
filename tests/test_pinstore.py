import os
import sys
import types

import pkcs11
import pytest
from test_host_hardening import FakeSvc, _cert

from tda_dsc_signer import cli, config, pinstore, verify
from tda_dsc_signer.errors import PinStoreUnavailable

PIN = "throwaway-PIN-7731"


def mgr(store=None):
    return pinstore.PinManager(store or pinstore.MemoryStore())


def tree(root):
    return sorted(os.path.join(d, f) for d, _, fs in os.walk(root) for f in fs)


def test_modes_default_to_ask_and_persist_without_any_pin():
    m = mgr()
    assert m.mode("S1") == "ask" and m.saved_pin("S1") is None
    m.save("S1", PIN, "keyring")
    assert m.mode("S1") == "keyring" and m.saved_pin("S1") == PIN and m.has_saved("S1")
    assert PIN not in open(config.default_path()).read()
    assert config.load().pin_modes == {"S1": "keyring"}


def test_session_mode_uses_memory_only_and_never_the_store():
    store = pinstore.MemoryStore()
    m = mgr(store)
    m.save("S1", PIN, "session")
    assert m.saved_pin("S1") == PIN and not store.has("S1")
    assert PIN not in open(config.default_path()).read()


def test_remember_session_only_in_session_mode():
    m = mgr()
    m.remember_session("S1", PIN)
    assert m.saved_pin("S1") is None
    m.set_mode("S1", "session")
    m.remember_session("S1", PIN)
    assert m.saved_pin("S1") == PIN


def test_changing_mode_away_from_keyring_deletes_the_secret():
    store = pinstore.MemoryStore()
    m = mgr(store)
    m.save("S1", PIN, "keyring")
    m.set_mode("S1", "session")
    assert not store.has("S1") and m.saved_pin("S1") is None
    m.set_mode("S1", "ask")
    assert config.load().pin_modes == {}


def test_forget_and_forget_all():
    store = pinstore.MemoryStore()
    m = mgr(store)
    m.save("S1", PIN, "keyring")
    m.save("S2", PIN, "keyring")
    m.forget("S1")
    assert not m.has_saved("S1") and m.has_saved("S2")
    m.forget_all()
    assert not m.has_saved("S2")


def test_wrong_pin_deletes_everywhere_and_resets_to_ask():
    store = pinstore.MemoryStore()
    m = mgr(store)
    m.save("S1", PIN, "keyring")
    assert m.on_pin_incorrect("S1") is True
    assert not store.has("S1") and m.mode("S1") == "ask"
    assert m.on_pin_incorrect("S1") is False


def test_unavailable_store_refuses_keyring_and_writes_nothing(tmp_path):
    before = tree(os.environ["XDG_CONFIG_HOME"]) + tree(os.environ["XDG_DATA_HOME"]) + tree(os.environ["XDG_STATE_HOME"])
    m = mgr(pinstore.UnavailableStore("nope"))
    with pytest.raises(PinStoreUnavailable, match="nope") as e:
        m.save("S1", PIN, "keyring")
    assert PIN not in str(e.value)
    with pytest.raises(PinStoreUnavailable):
        m.set_mode("S1", "keyring")
    after = tree(os.environ["XDG_CONFIG_HOME"]) + tree(os.environ["XDG_DATA_HOME"]) + tree(os.environ["XDG_STATE_HOME"])
    assert before == after and m.status() == {"available": False, "reason": "nope"}


def test_protected_auth_and_empty_pin_refused():
    with pytest.raises(ValueError):
        mgr().save("S1", PIN, "session", protected_auth=True)
    with pytest.raises(ValueError):
        mgr().save("S1", "", "session")


def test_default_store_is_unavailable_without_a_provider(monkeypatch):
    class Boom:
        class Service:
            @staticmethod
            def get_sync(*a):
                raise RuntimeError("no bus")

        ServiceFlags = types.SimpleNamespace(OPEN_SESSION=2)

    s = pinstore.LibsecretStore(secret=Boom)
    assert not s.available() and "Secret Service" in s.unavailable_reason()


def fake_secret():
    items = {}
    S = types.SimpleNamespace()
    S.COLLECTION_DEFAULT = "default"
    S.SchemaFlags = types.SimpleNamespace(NONE=0)
    S.SchemaAttributeType = types.SimpleNamespace(STRING=0)
    S.ServiceFlags = types.SimpleNamespace(OPEN_SESSION=2)
    S.Schema = types.SimpleNamespace(new=lambda name, flags, attrs: (name, attrs))
    S.Service = types.SimpleNamespace(get_sync=lambda flags, c: object())
    S.password_store_sync = lambda sch, a, coll, label, pw, c: items.__setitem__(a["serial"], (pw, label, sch[0], coll))
    S.password_lookup_sync = lambda sch, a, c: items.get(a["serial"], (None,))[0]
    S.password_clear_sync = lambda sch, a, c: items.clear() if not a else items.pop(a["serial"], None)
    return S, items


def test_libsecret_store_with_fake_module():
    S, items = fake_secret()
    s = pinstore.LibsecretStore(secret=S)
    assert s.available() and s.unavailable_reason() == ""
    m = mgr(s)
    m.save("S1", PIN, "keyring")
    assert items["S1"] == (PIN, "DSC Signer token PIN", "in.tdacorp.DscSigner.Pin", "default")
    assert m.saved_pin("S1") == PIN and m.has_saved("S1")
    m.forget_all()
    assert items == {}


def test_no_provider_on_the_bus_skips_libsecret_and_prints_nothing(capfd):
    S, _ = fake_secret()
    S.Service = types.SimpleNamespace(get_sync=lambda *a: pytest.fail("libsecret must not be called when the bus has no provider"))
    s = pinstore.LibsecretStore(secret=S, probe=lambda: False)
    assert not s.available() and s.unavailable_reason() == pinstore.NO_PROVIDER
    assert capfd.readouterr().err == ""


def test_real_probe_on_a_dead_bus_is_false(capfd):
    assert pinstore.secret_service_on_session_bus() is False  # tests/conftest isolates DBUS_SESSION_BUS_ADDRESS to a dead path
    assert "G_IS_OBJECT" not in capfd.readouterr().err


def test_libsecret_errors_never_carry_the_pin():
    S, _ = fake_secret()
    S.password_store_sync = lambda *a: (_ for _ in ()).throw(RuntimeError(f"bad {PIN}"))
    with pytest.raises(PinStoreUnavailable) as e:
        pinstore.LibsecretStore(secret=S).set("S1", PIN)
    assert PIN not in str(e.value)


# ---- CLI ----


class PinSvc(FakeSvc):
    def __init__(self, cert, error=None):
        super().__init__(cert)
        self.error = error

    def sign(self, src, cert, **kw):
        if self.error:
            self.signed.append(kw)
            raise self.error
        return super().sign(src, cert, **kw)


def run_sign(monkeypatch, tmp_path, pdf3, pins, svc, *extra):
    monkeypatch.setattr(verify, "verify_signed", lambda *a, **k: verify.VerifyResult((), "", False, True, "ok"))
    a = cli._parser(config.Config()).parse_args(["sign", str(pdf3), "-o", str(tmp_path / "o.pdf"), *extra])
    return cli._sign(a, config.Config(), svc, pins=pins)


def test_cli_saved_pin_is_used_exactly_once_and_never_leaks(monkeypatch, tmp_path, pdf3):
    pins = mgr()
    pins.save("S1", PIN, "keyring")
    monkeypatch.setattr(cli.getpass, "getpass", lambda *a: pytest.fail("must not prompt"))
    svc = PinSvc(_cert())
    assert run_sign(monkeypatch, tmp_path, pdf3, pins, svc, "--saved-pin") is True
    assert [k["pin"] for k in svc.signed] == [PIN]
    assert PIN not in open(config.default_path()).read()
    assert PIN not in "".join(os.environ.values()) and PIN not in " ".join(sys.argv)


def test_cli_without_flag_ignores_the_saved_pin(monkeypatch, tmp_path, pdf3):
    pins = mgr()
    pins.save("S1", PIN, "keyring")
    monkeypatch.setattr(cli.getpass, "getpass", lambda *a: "typed")
    svc = PinSvc(_cert())
    run_sign(monkeypatch, tmp_path, pdf3, pins, svc)
    assert svc.signed[0]["pin"] == "typed"


def test_cli_saved_pin_falls_back_to_prompt_when_none(monkeypatch, tmp_path, pdf3):
    monkeypatch.setattr(cli.getpass, "getpass", lambda *a: "typed")
    svc = PinSvc(_cert())
    run_sign(monkeypatch, tmp_path, pdf3, mgr(), svc, "--saved-pin")
    assert svc.signed[0]["pin"] == "typed"


def test_cli_wrong_saved_pin_is_deleted_and_not_retried(monkeypatch, tmp_path, pdf3, capsys):
    pins = mgr()
    pins.save("S1", PIN, "keyring")
    svc = PinSvc(_cert(), pkcs11.PinIncorrect())
    with pytest.raises(pkcs11.PinIncorrect):
        run_sign(monkeypatch, tmp_path, pdf3, pins, svc, "--saved-pin")
    assert len(svc.signed) == 1 and not pins.has_saved("S1") and pins.mode("S1") == "ask"
    assert "DELETED" in capsys.readouterr().err


def test_cli_pin_subcommands(monkeypatch, capsys):
    pins = mgr()
    svc = PinSvc(_cert())
    cfg = config.Config()
    parse = lambda *argv: cli._parser(cfg).parse_args(["pin", *argv])  # noqa: E731
    monkeypatch.setattr(cli.getpass, "getpass", lambda *a: PIN)
    assert cli._pin_cmd(parse("set", "-t", "1", "--mode", "session"), cfg, svc, pins) == 0
    assert pins.saved_pin("S1") == PIN
    capsys.readouterr()
    assert cli._pin_cmd(parse("status"), cfg, svc, pins) == 0
    out = capsys.readouterr().out
    assert "PIN saved" in out and "mode session" in out and PIN not in out
    assert cli._pin_cmd(parse("forget", "-t", "1"), cfg, svc, pins) == 0
    assert not pins.has_saved("S1")
    pins.save("S1", PIN, "session")
    assert cli._pin_cmd(parse("forget", "--all"), cfg, svc, pins) == 0
    assert not pins.has_saved("S1")


def test_cli_pin_set_keyring_unavailable_exits_cleanly(monkeypatch):
    monkeypatch.setattr(cli.getpass, "getpass", lambda *a: PIN)
    cfg = config.Config()
    a = cli._parser(cfg).parse_args(["pin", "set", "-t", "1"])
    with pytest.raises(SystemExit) as e:
        cli._pin_cmd(a, cfg, PinSvc(_cert()), mgr(pinstore.UnavailableStore("no provider")))
    assert "no provider" in str(e.value) and PIN not in str(e.value)

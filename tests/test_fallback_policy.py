"""OpenSC fallback policy, PC/SC serialisation, mismatch rules and the discover() wall-clock cap."""

import threading
import time

import pytest

from tda_dsc_signer import cli, config, quirks, tokens
from tda_dsc_signer.errors import DriverBusy, HostTimeout, TokenCountMismatch
from tda_dsc_signer.hostclient import ModuleHost
from tda_dsc_signer.service import TokenService

VENDOR = "/opt/x/libInnaITPKCS11Driver.so"
OPENSC = "/usr/lib/opensc-pkcs11.so"


class Src:
    def __init__(self, *mods):
        self.mods, self.rejected = list(mods), {}

    def modules(self):
        return self.mods


def cert(serial="S1", module=VENDOR):
    return tokens.cert_to_dict(tokens.TokenCert(module, 0, "T", serial, "L", b"\x00", "N", "O", "2099-01-01"))


class Hosts:
    """make_host double with a call log: which modules got a host, and what each answers."""

    def __init__(self, answers=None):
        self.answers, self.created, self.calls = answers or {}, [], []

    def __call__(self, module):
        self.created.append(module)
        outer = self

        class H:
            def call(self, method, params=None, **kw):
                outer.calls.append((module, method))
                r = outer.answers.get(module, [])
                if isinstance(r, Exception):
                    raise r
                return r

            def kill(self):
                pass

        return H()


def svc(primary, hosts, policy="auto", usb=(), sleeps=None):
    return TokenService(
        sources=[Src(*primary)],
        fallback=Src(OPENSC),
        make_host=hosts,
        usb_devices=lambda: list(usb),
        sleep=(sleeps if sleeps is not None else []).append,
        opensc_fallback=policy,
        allow_user_modules=[],
    )


# ---- (a) vendor module present, empty scan -> OpenSC never --------------------------------------------------------------


def test_vendor_module_present_and_empty_scan_never_creates_an_opensc_host():
    hosts = Hosts({VENDOR: []})
    s = svc([VENDOR], hosts)
    assert s.discover() == []
    assert hosts.created == [VENDOR] and OPENSC not in hosts.created


def test_a_vendor_module_refused_by_vetting_still_counts_as_present():
    hosts = Hosts()
    refused = Src()
    refused.rejected = {VENDOR: "not allowed"}
    s = TokenService(sources=[refused], fallback=Src(OPENSC), make_host=hosts, usb_devices=lambda: [], opensc_fallback="auto", allow_user_modules=[])
    s.discover()
    assert hosts.created == [] and "module refused" in str(s.errors[VENDOR])


# ---- (b) policies ---------------------------------------------------------------------------------------------------------


def test_no_modules_at_all_auto_uses_the_fallback_once():
    hosts = Hosts({OPENSC: [cert("S9", OPENSC)]})
    s = svc([], hosts, "auto")
    assert [c.serial for c in s.discover()] == ["S9"]
    assert hosts.created == [OPENSC] and hosts.calls == [(OPENSC, "enumerate")]


def test_never_never_uses_it_even_with_no_modules():
    hosts = Hosts()
    assert svc([], hosts, "never").discover() == [] and hosts.created == []


def test_always_uses_it_when_the_primary_scan_is_empty_even_with_a_vendor_module():
    hosts = Hosts({VENDOR: [], OPENSC: [cert("S9", OPENSC)]})
    s = svc([VENDOR], hosts, "always")
    assert [c.serial for c in s.discover()] == ["S9"] and OPENSC in hosts.created


def test_invalid_policy_is_rejected():
    with pytest.raises(ValueError, match="opensc_fallback"):
        TokenService(sources=[], fallback=Src(), opensc_fallback="sometimes", allow_user_modules=[])


def test_config_and_cli_expose_the_policy(monkeypatch):
    assert config.Config().opensc_fallback == "auto"
    seen = {}

    class S:
        errors = {}

        def __init__(self, *a, **kw):
            seen.update(kw)

        def discover(self, extra=()):
            return []

        def close(self):
            pass

    monkeypatch.setattr(cli, "TokenService", S)
    monkeypatch.setattr(cli.config, "load", lambda: config.Config(opensc_fallback="never"))
    cli.main(["list"])
    assert seen["opensc_fallback"] == "never"
    cli.main(["list", "--opensc-fallback", "always"])
    assert seen["opensc_fallback"] == "always"


# ---- (c) busy -> no fallback, not even with 'always' -----------------------------------------------------------------------


@pytest.mark.parametrize("policy", ["auto", "always"])
def test_driver_busy_means_no_fallback(policy):
    hosts = Hosts({VENDOR: DriverBusy("busy", VENDOR, 7)})
    s = svc([VENDOR], hosts, policy)
    assert s.discover() == [] and OPENSC not in hosts.created and isinstance(s.errors[VENDOR], DriverBusy)


# ---- (d) mismatch vs busy ---------------------------------------------------------------------------------------------------


def test_busy_unrelated_module_does_not_hide_the_usb_mismatch():
    other = "/usr/lib/softhsm/libsofthsm2.so"
    hosts = Hosts({VENDOR: [], other: DriverBusy("softhsm busy", other, 3)})
    sleeps = []
    s = svc([VENDOR, other], hosts, usb=["338c:0031"], sleeps=sleeps)
    s.discover()
    assert isinstance(s.errors["usb"], TokenCountMismatch) and isinstance(s.errors[other], DriverBusy)
    assert len(sleeps) == quirks.RESCANS


def test_busy_module_that_serves_the_missing_device_suppresses_mismatch_and_rescans():
    hosts = Hosts({VENDOR: DriverBusy("InnaIT busy", VENDOR, 3)})
    sleeps = []
    s = svc([VENDOR], hosts, usb=["338c:0031"], sleeps=sleeps)
    s.discover()
    assert "usb" not in s.errors and sleeps == [] and s.errors[VENDOR].args[0] == "InnaIT busy"


def test_serves_matches_by_basename_and_usb_id():
    assert quirks.serves("/opt/p/libInnaITPKCS11Driver.so", ["338c:0031"])
    assert not quirks.serves("/opt/p/libInnaITPKCS11Driver.so", ["096e:080a"])
    assert quirks.serves("/usr/lib/libcastle_v2.so", ["096e:080a"])
    assert not quirks.serves("/usr/lib/softhsm/libsofthsm2.so", ["338c:0031"])


# ---- PC/SC serialisation -------------------------------------------------------------------------------------------------


def test_pcsc_modules_are_never_initialised_concurrently_but_others_are():
    state = {"in": 0, "max": 0}
    lock = threading.Lock()

    def make(module):
        class H:
            def call(self, method, params=None, **kw):
                with lock:
                    state["in"] += 1
                    state["max"] = max(state["max"], state["in"])
                time.sleep(0.2)
                with lock:
                    state["in"] -= 1
                return []

            def kill(self):
                pass

        return H()

    s = TokenService(sources=[Src(VENDOR, "/usr/lib/libcastle_v2.so")], fallback=Src(), make_host=make, usb_devices=lambda: [], allow_user_modules=[])
    s.discover()
    assert state["max"] == 1, "two PC/SC drivers were scanned at the same time"
    state.update({"in": 0, "max": 0})
    s2 = TokenService(sources=[Src("/a/libfoo.so", "/b/libbar.so")], fallback=Src(), make_host=make, usb_devices=lambda: [], allow_user_modules=[])
    s2.discover()
    assert state["max"] == 2, "non-PC/SC modules still scan in parallel"


# ---- (e) wall-clock cap -----------------------------------------------------------------------------------------------------


def test_discover_is_capped_and_reports_the_stuck_module(monkeypatch):
    monkeypatch.setattr(quirks, "DISCOVER_CAP", 0.5)
    release = threading.Event()
    killed = []

    def make(module):
        class H:
            def call(self, method, params=None, **kw):
                if module == "/a/libstuck.so":
                    release.wait(20)
                    raise OSError("killed")
                return [cert("S1", module)]

            def kill(self):
                killed.append(module)
                release.set()

        return H()

    s = TokenService(sources=[Src("/a/libstuck.so", "/b/libgood.so")], fallback=Src(), make_host=make, usb_devices=lambda: [], allow_user_modules=[])
    t0 = time.time()
    found = s.discover()
    assert time.time() - t0 < 5 and [c.module for c in found] == ["/b/libgood.so"]
    assert isinstance(s.errors["/a/libstuck.so"], HostTimeout) and killed == ["/a/libstuck.so"]
    time.sleep(0.2)
    assert isinstance(s.errors["/a/libstuck.so"], HostTimeout), "the killed worker must not overwrite the timeout with its own error"


def test_no_more_rescans_once_the_total_budget_is_used(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(quirks, "DISCOVER_TOTAL", 10)
    hosts = Hosts({VENDOR: []})
    s = TokenService(
        sources=[Src(VENDOR)], fallback=Src(), make_host=hosts, usb_devices=lambda: ["338c:0031"], sleep=lambda d: now.__setitem__(0, now[0] + 20),
        clock=lambda: now[0], allow_user_modules=[],
    )  # fmt: skip
    s.discover()
    assert hosts.calls.count((VENDOR, "enumerate")) == 2 and "usb" in s.errors


# ---- (f) two real processes with fallback enabled -------------------------------------------------------------------------

PRIMARY = "/nonexistent/libInnaITPKCS11Driver.so"


def test_second_process_with_fallback_enabled_does_not_start_opensc_when_primary_is_busy():
    holder = ModuleHost(PRIMARY)
    created = []

    class Spy(ModuleHost):
        def _spawn(self):
            created.append(self.module)
            super()._spawn()

    try:
        holder.call("ping")  # process A owns the driver
        second = TokenService(
            sources=[Src(PRIMARY)], fallback=Src("/nonexistent/opensc-pkcs11.so"), make_host=Spy, usb_devices=lambda: [], opensc_fallback="auto",
            allow_user_modules=[],
        )  # fmt: skip
        assert second.discover() == []
        assert isinstance(second.errors[PRIMARY], DriverBusy)
        assert created == [PRIMARY], "no OpenSC host was ever spawned by the second process"
        second.close()
    finally:
        holder.kill()

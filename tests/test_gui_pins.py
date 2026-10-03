"""GUI-side saved-PIN flow, status dot, layout switch and settings facts (no display; fake PinManager over a MemoryStore)."""

import datetime

import pkcs11
import pytest
from test_signrun import UI, FakeBackend, _sync, cert

from tda_dsc_signer import config, pinstore
from tda_dsc_signer.gui import state
from tda_dsc_signer.gui.signrun import SignRun, Step
from tda_dsc_signer.safety import PinState

STEP = (1, 2, 3, 4)


def manager(store=None):
    cfg = config.Config()
    return pinstore.PinManager(store or pinstore.MemoryStore(), None, lambda: cfg, lambda c: None)


def cert_with(pin=None, end="2099-01-01", serial="A"):
    c = cert(serial)
    return type(c)(*[getattr(c, f) for f in ("module", "slot", "token", "serial", "label", "der", "cn", "org")], end, (), "01", pin or PinState())


def run_with(tmp_path, pins, c, backend, typed=("typed",), remember=False, **kw):
    src = tmp_path / "in.pdf"
    src.write_bytes(b"%PDF-")
    ref, wrong, remembered = [], [], {}

    class U(UI):
        def ask_pin(self, cert_, count, error):
            self.prompts.append((cert_.serial, count, error))
            self.run_ref[0].pin_given(self.pins.pop(0), remember)

    ui = U(ref, list(typed))
    run = SignRun(
        [Step(1, 1, STEP, c)],
        str(src),
        str(tmp_path / "out.pdf"),
        backend=backend,
        submit=_sync,
        ui=ui,
        opts={"stamp_text": "t", "profile": "mca", "timestamp_url": "", **kw},
        remember=lambda key, pin: remembered.__setitem__(key, pin),
        saved_pin=lambda cc: state.saved_pin_usable(pins, cc),
        on_saved_wrong=lambda cc: (wrong.append(cc.serial), pins.on_pin_incorrect(cc.serial)),
    )
    ref.append(run)
    run.start()
    return run, ui, wrong, remembered


def test_saved_pin_skips_the_popover_and_signs_once_with_it(tmp_path):
    pins = manager()
    pins.save("A", "s3cret", "session")
    be = FakeBackend()
    run, ui, _, _ = run_with(tmp_path, pins, cert("A"), be)
    assert ui.prompts == [] and [c[3] for c in be.calls] == ["s3cret"] and len(be.calls) == 1
    assert run.used_saved and ui.finish is not None


@pytest.mark.parametrize("flags", [PinState(final_try=True), PinState(count_low=True), PinState(locked=True)])
def test_pin_flags_force_the_popover_even_with_a_saved_pin(tmp_path, flags):
    pins = manager()
    pins.save("A", "s3cret", "session")
    be = FakeBackend()
    _, ui, _, _ = run_with(tmp_path, pins, cert_with(flags), be)
    assert [p[0] for p in ui.prompts] == ["A"] and be.calls[0][3] == "typed"


def test_wrong_saved_pin_is_removed_told_and_never_retried(tmp_path):
    pins = manager()
    pins.save("A", "bad", "session")
    be = FakeBackend(fail_at=0, fail_with=pkcs11.PinIncorrect())
    _, ui, wrong, _ = run_with(tmp_path, pins, cert("A"), be)
    assert len(be.calls) == 1 and ui.prompts == [] and wrong == ["A"]
    assert ui.abort[0] == state.SAVED_WRONG and not pins.has_saved("A") and pins.mode("A") == "ask"


def test_typed_pin_is_remembered_only_after_it_worked(tmp_path):
    ok = FakeBackend()
    _, _, _, remembered = run_with(tmp_path, manager(), cert("A"), ok, remember=True)
    assert remembered == {"A/01": "typed"}
    bad = FakeBackend(fail_at=0, fail_with=pkcs11.PinIncorrect())
    _, ui, _, remembered = run_with(tmp_path, manager(), cert("A"), bad, typed=("typed", None), remember=True)
    assert remembered == {} and ui.prompts[-1][2][0] == "pin"


def test_invisible_passes_visible_false_only_to_a_backend_that_takes_it(tmp_path):
    class Vis(FakeBackend):
        def sign(self, src, cert, *, page, box, pin, out, stamp_text, profile, timestamp_url, confirm_final_try, visible=True, **kw):
            return super().sign(
                src,
                cert,
                page=page,
                box=box,
                pin=pin,
                out=out,
                stamp_text=stamp_text,
                profile=profile,
                timestamp_url=timestamp_url,
                confirm_final_try=confirm_final_try,
                visible=visible,
                **kw,
            )

    be = Vis()
    run_with(tmp_path, manager(), cert("A"), be, visible=False)
    assert be.calls[0][5]["visible"] is False


def test_pin_row_facts_follow_store_and_token():
    ok, off = manager(), manager(pinstore.UnavailableStore())
    assert state.pin_row(ok, cert("A"), ok.status()) == {"mode": "ask", "saved": False, "can_session": True, "can_keyring": True, "can_pin": True}
    r = state.pin_row(off, cert("A"), off.status())
    assert r["can_session"] and not r["can_keyring"]
    pad = state.pin_row(ok, cert_with(PinState(protected_auth=True)), ok.status())
    assert not (pad["can_session"] or pad["can_keyring"] or pad["can_pin"])
    none = state.pin_row(None, cert("A"), {"available": False})
    assert not none["can_session"] and none["mode"] == "ask"
    ok.save("A", "p", "session")
    assert state.pin_row(ok, cert("A"), ok.status())["saved"] and state.pin_row(ok, cert("A"), ok.status())["mode"] == "session"


def test_unavailable_store_refuses_keyring_and_stores_no_pin():
    off = manager(pinstore.UnavailableStore())
    with pytest.raises(Exception):  # noqa: B017  (PinStoreUnavailable)
        off.set_mode("A", "keyring")
    assert off.mode("A") == "ask" and off.saved_pin("A") is None and off.status()["reason"]


@pytest.mark.parametrize(
    ("kw", "level"),
    [
        ({}, "ok"),
        ({"end": "2000-01-01"}, "err"),
        ({"pin": PinState(locked=True)}, "err"),
        ({"pin": PinState(final_try=True)}, "warn"),
        ({"pin": PinState(count_low=True)}, "warn"),
        ({"end": (datetime.date.today() + datetime.timedelta(days=10)).isoformat()}, "warn"),
        ({"end": (datetime.date.today() + datetime.timedelta(days=31)).isoformat()}, "ok"),
    ],
)
def test_token_status_dot(kw, level):
    assert state.token_status(cert_with(**kw))[0] == level
    assert state.token_status(None)[0] == "err"


def test_scan_status_overrides():
    assert state.scan_status(True, False, False, True)[0] == "warn"
    assert state.scan_status(False, True, False, True)[0] == "warn"
    assert state.scan_status(False, False, True, True)[0] == "warn"
    assert state.scan_status(False, False, False, False)[0] == "err"
    assert state.scan_status(False, False, False, True) is None


@pytest.mark.parametrize(("w", "mode"), [(560, "strip"), (899, "strip"), (900, "two"), (1100, "two"), (1600, "two")])
def test_layout_switch_thresholds(w, mode):
    assert state.layout_for(w) == mode


def test_file_card_text(tmp_path):
    p = tmp_path / "a.pdf"
    p.write_bytes(b"x" * 2_516_582)
    assert state.too_big(str(p))
    p.write_bytes(b"x" * 2048)
    assert not state.too_big(str(p))
    assert state.valid_till(cert_with(end="2027-11-18")) == "18 Nov 2027"


def test_model_text_is_the_token_label():
    c = cert("A")
    assert state.model_text(c) == c.token


def test_packaged_logo_and_desktop_name():
    import os

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assert open(os.path.join(root, "data", "in.tdacorp.DscSigner.desktop")).read().count("Name=DSC Signer\n") == 1
    assert os.path.getsize(os.path.join(root, "src", "tda_dsc_signer", "gui", "tda-logo.svg")) == os.path.getsize(
        os.path.join(root, "data", "tda-logo.svg")
    )


# -- saved PINs for both tokens: one click signs every box (regression guards) -------------------------------------------


class BrokenStore(pinstore.MemoryStore):
    def get(self, serial):
        raise pinstore.PinStoreUnavailable("Secret Service error (GError)")


def test_a_failing_keyring_means_ask_not_a_dead_run(tmp_path):
    pins = manager(BrokenStore())
    pins._load().pin_modes["A"] = "keyring"
    assert state.saved_pin_usable(pins, cert("A")) is None
    run, ui, _, _ = run_with(tmp_path, pins, cert("A"), FakeBackend())
    assert [p[0] for p in ui.prompts] == ["A"]  # the popover asks instead of the run dying inside _next


def chain(tmp_path, pins, certs, backend=None):
    src = tmp_path / "in.pdf"
    src.write_bytes(b"%PDF-")
    ref = []
    ui = UI(ref, ["typed"] * 3)
    be = backend or FakeBackend()
    run = SignRun(
        [Step(i + 1, i + 1, STEP, c) for i, c in enumerate(certs)],
        str(src),
        str(tmp_path / "out.pdf"),
        backend=be,
        submit=_sync,
        ui=ui,
        opts={"stamp_text": "t", "profile": "mca", "timestamp_url": ""},
        saved_pin=lambda cc: state.saved_pin_usable(pins, cc),
        overwrite_final=True,
    )
    ref.append(run)
    run.start()
    return run, ui, be


def test_three_boxes_two_keyring_tokens_one_start_no_prompt(tmp_path):
    pins = manager()
    cfg = pins._load()
    for s in "AB":
        pins._store.set(s, f"pin{s}")
        cfg.pin_modes[s] = "keyring"
    run, ui, be = chain(tmp_path, pins, [cert("A"), cert("B"), cert("A")])
    assert ui.prompts == [] and ui.finish and ui.abort is None
    assert [c[3] for c in be.calls] == ["pinA", "pinB", "pinA"]


def test_existing_output_confirmed_in_the_save_dialog_is_replaced(tmp_path):
    (tmp_path / "out.pdf").write_bytes(b"old")
    seen = []

    class B(FakeBackend):
        def sign(self, *a, **kw):
            seen.append(kw.get("overwrite"))
            return super().sign(*a, **kw)

    run, ui, _ = chain(tmp_path, manager(), [cert("A"), cert("A")], B())
    assert seen == [True, True] and ui.finish


def test_cancel_during_verification_does_not_abort_a_finished_run(tmp_path):
    jobs = []
    src = tmp_path / "in.pdf"
    src.write_bytes(b"%PDF-")
    ui = UI([], [])
    run = SignRun(
        [Step(1, 1, STEP, cert("A"))],
        str(src),
        str(tmp_path / "out.pdf"),
        backend=FakeBackend(),
        submit=lambda fn, cb: jobs.append((fn, cb)),
        ui=ui,
        opts={"stamp_text": "t", "profile": "mca", "timestamp_url": ""},
        saved_pin=lambda cc: "p",
    )
    run.start()
    fn, cb = jobs.pop(0)
    cb(fn(), None)  # the signature exists; verification is queued
    run.cancel("The token was removed; signing stopped.")  # a late rescan
    assert ui.abort is None
    fn, cb = jobs.pop(0)
    cb(fn(), None)
    assert ui.finish


def test_debug_log_names_every_step_and_never_the_pin(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DSC_DEBUG", "1")
    pins = manager()
    pins._load().pin_modes["A"] = "keyring"
    pins._store.set("A", "s3cretpin")
    chain(tmp_path, pins, [cert("A"), cert("A")])
    err = capsys.readouterr().err
    assert "step 1/2" in err and "step 2/2 ok" in err and "token=A" in err and "s3cretpin" not in err

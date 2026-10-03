import pkcs11
import pytest

from tda_dsc_signer import tokens
from tda_dsc_signer.errors import HostTimeout
from tda_dsc_signer.gui import state
from tda_dsc_signer.safety import FinalTryNeedsConfirm, PinState, TokenLocked


def cert(serial="S1", cid="01", end="2099-01-01", org="Org", pin=None):
    return tokens.TokenCert("m", 0, "Tok", serial, "L", b"", "Jane Doe", org, end, (), cid, pin or PinState())


def test_labels_and_tooltip():
    c = cert()
    assert state.signer_label(c) == "Jane Doe · Org" and state.signer_label(cert(org="")) == "Jane Doe"
    tip = state.signer_tooltip(cert(end="2000-01-01", pin=PinState(final_try=True)))
    assert "serial: S1" in tip and "EXPIRED" in tip and "FINAL" in tip


def test_index_for_remembers_token_by_key_and_defaults_to_first():
    certs = [cert("A", "01"), cert("B", "02")]
    assert state.index_for(certs, "B/02") == 1 and state.index_for(certs, "gone/xx") == 0 and state.index_for([], "x") == 0


def test_fit_scale_fills_width_and_zoom_scales_it():
    assert state.fit_scale(600 + 2 * state.MARGIN, 600) == pytest.approx(1.0)
    assert state.fit_scale(600 + 2 * state.MARGIN, 600, 2.0) == pytest.approx(2.0)
    assert state.fit_scale(10, 600) > 0  # never zero/negative on a tiny window


def test_zoom_clamped():
    assert state.clamp_zoom(0.01) == state.ZOOM_MIN and state.clamp_zoom(99) == state.ZOOM_MAX and state.clamp_zoom(1.5) == 1.5


def test_page_at_offsets():
    h = [100, 100, 100]
    assert state.page_at(0, h) == 0
    assert state.page_at(state.MARGIN + 100 + state.GAP + 10, h) == 1
    assert state.page_at(10_000, h) == 2 and state.page_at(5, []) == 0


@pytest.mark.parametrize(
    "args,ok", [((1, 1, 1, 0), True), ((0, 1, 1, 0), False), ((1, 0, 1, 0), False), ((1, 1, 0, 0), False), ((1, 1, 1, 1), False)]
)
def test_can_sign(args, ok):
    assert state.can_sign(*args) is ok


def test_error_wording_kinds():
    assert state.describe_error(pkcs11.PinIncorrect("x"))[0] == "pin"
    assert state.describe_error(pkcs11.PinLocked("x"))[0] == "fatal" and state.describe_error(TokenLocked("x"))[0] == "fatal"
    assert state.describe_error(FinalTryNeedsConfirm("x"))[0] == "confirm"
    kind, text = state.describe_error(HostTimeout("t"))
    assert kind == "timeout" and "may or may not have happened" in text and "nothing was resent" in text
    assert state.describe_error(ValueError("boom")) == ("other", "ValueError: boom")


def test_pin_prompt_skipped_only_for_remembered_pin_based_tokens():
    c = cert()
    assert state.pin_prompt_needed(c, {}) and not state.pin_prompt_needed(c, {c.key: "x"})
    assert state.pin_prompt_needed(cert(pin=PinState(protected_auth=True)), {"S1/01": "x"})


def test_error_kinds_for_multi_sign():
    assert state.describe_error(pkcs11.NoSuchToken("x"))[0] == "gone"

    class RecentWrongPin(Exception):  # matched by name: the real one lives in safety once the lockout memory lands
        pass

    kind, text = state.describe_error(RecentWrongPin("a wrong PIN was entered 20 s ago"))
    assert kind == "recent" and "20 s ago" in text


class DriverBusy(Exception):  # stand-ins matched by class name, like the real core classes
    def __init__(self, pid):
        super().__init__("the vendor driver is held by another process")
        self.holder_pid, self.module = pid, "/opt/vendor/libdrv.so"


class TokenCountMismatch(Exception):
    def __init__(self, expected, found):
        super().__init__("usb shows more tokens than the driver listed")
        self.expected, self.found = expected, found


def test_scan_problem_none_without_errors():
    assert state.scan_problem({}) is None and state.scan_problem(None) is None


def test_driver_busy_message_names_the_holder_and_is_a_warning():
    kind, note, tip, level, full = state.scan_problem({"/opt/vendor/libdrv.so": DriverBusy(4242)})
    assert kind == "busy" and level == "warn" and "4242" in note
    assert full == "Token driver is in use by another tda-dsc-signer (pid 4242). Close it, then Refresh."
    assert "pid 4242" in tip and "/opt/vendor/libdrv.so" in tip


def test_driver_busy_without_pid_still_reads_well():
    full = state.scan_problem({"m": DriverBusy(None)})[4]
    assert full == "Token driver is in use by another tda-dsc-signer. Close it, then Refresh."


def test_count_mismatch_is_the_partial_result_warning():
    kind, note, tip, level, full = state.scan_problem({"usb": TokenCountMismatch(2, 1)})
    assert (kind, note, level) == ("mismatch", "found 1 of 2 token devices: Refresh", "warn")


def test_busy_outranks_mismatch_and_module_errors():
    errs = {"a": RuntimeError("x"), "usb": TokenCountMismatch(2, 1), "m": DriverBusy(7)}
    assert state.scan_problem(errs)[0] == "busy"
    assert state.scan_problem({"a": RuntimeError("x"), "usb": TokenCountMismatch(2, 1)})[0] == "mismatch"


def test_other_errors_are_module_errors_in_red():
    kind, note, tip, level, full = state.scan_problem({"/m.so": RuntimeError("host died")})
    assert (kind, note, level) == ("module", "module error", "error") and "/m.so: RuntimeError: host died" in tip

import pytest
from pkcs11 import TokenFlag

from tda_dsc_signer import safety
from tda_dsc_signer.watch import Poller


def test_flags_to_state():
    s = safety.PinState.from_flags(TokenFlag.USER_PIN_COUNT_LOW | TokenFlag.PROTECTED_AUTHENTICATION_PATH)
    assert s.count_low and s.protected_auth and not s.locked and not s.final_try


def test_locked_refused_even_with_confirm():
    with pytest.raises(safety.TokenLocked):
        safety.guard_login(safety.PinState(locked=True), confirm_final_try=True)


def test_final_try_needs_confirm_then_warns():
    st = safety.PinState(final_try=True)
    with pytest.raises(safety.FinalTryNeedsConfirm):
        safety.guard_login(st)
    assert "FINAL" in safety.guard_login(st, True)


def test_count_low_warns_without_blocking():
    assert "low" in safety.guard_login(safety.PinState(count_low=True))


def test_healthy_token_no_warning():
    assert safety.guard_login(safety.PinState()) == ""


def make_poller(snaps, debounce=2):
    it = iter(snaps)
    fired = []
    p = Poller(lambda: next(it), fired.append, debounce=debounce)
    p.known = "A"
    return p, fired


def test_change_needs_two_stable_polls():
    p, fired = make_poller(["B", "B"])
    assert not p.tick() and p.tick() and fired == ["B"]


def test_flapping_is_debounced_away():
    p, fired = make_poller(["B", "A", "B", "A"])
    assert not any(p.tick() for _ in range(4)) and fired == []


def test_busy_snapshot_is_skipped_and_resets():
    p, fired = make_poller(["B", None, "B", "B"])
    assert [p.tick() for _ in range(4)] == [False, False, False, True] and fired == ["B"]


def test_no_event_when_unchanged():
    p, fired = make_poller(["A", "A", "A"])
    assert not any(p.tick() for _ in range(3)) and fired == []

"""Token PIN-retry safety, decided from C_GetTokenInfo flags BEFORE any login. Pure functions."""

import hashlib
import json
import os
import tempfile
import time
from dataclasses import dataclass

from pkcs11 import TokenFlag

WRONG_PIN_WINDOW = 300  # seconds during which a recorded wrong PIN blocks the next login unless explicitly confirmed


class TokenLocked(Exception):
    """USER_PIN_LOCKED: logging in is pointless and can not help."""


class FinalTryNeedsConfirm(Exception):
    """USER_PIN_FINAL_TRY: one more wrong PIN locks the token; the caller must confirm explicitly."""


@dataclass(frozen=True)
class PinState:
    locked: bool = False
    final_try: bool = False
    count_low: bool = False
    protected_auth: bool = False  # PIN is entered on the token/reader: send no PIN

    @classmethod
    def from_flags(cls, flags):
        return cls(
            bool(flags & TokenFlag.USER_PIN_LOCKED),
            bool(flags & TokenFlag.USER_PIN_FINAL_TRY),
            bool(flags & TokenFlag.USER_PIN_COUNT_LOW),
            bool(flags & TokenFlag.PROTECTED_AUTHENTICATION_PATH),
        )

    # NOTE: InnaIT tokens set none of these flags, so "no warning" is not a guarantee of retries left.
    def warning(self):
        if self.final_try:
            return "FINAL PIN TRY: one more wrong PIN will lock the token."
        if self.count_low:
            return "PIN retry count is low: a wrong PIN may be one of the last attempts."
        return ""


def guard_login(state, confirm_final_try=False):
    """Raise before login when the token must not be tried; returns a warning string (maybe empty) otherwise."""
    if state.locked:
        raise TokenLocked("the token's user PIN is locked; it has to be unblocked by the issuer (PUK / CA)")
    if state.final_try and not confirm_final_try:
        raise FinalTryNeedsConfirm("only one PIN try left; confirm explicitly before trying")
    return state.warning()


class RecentWrongPin(Exception):
    """A wrong PIN was entered for this token moments ago; another try needs explicit confirmation (confirm_after_failure)."""

    def __init__(self, serial, count, remaining):
        super().__init__(
            f"token {serial}: wrong PIN {count} time(s), last {WRONG_PIN_WINDOW - int(remaining)}s ago; "
            f"refusing another try for {int(remaining)}s unless confirmed (--confirm-after-failure)"
        )
        self.serial, self.count, self.remaining = serial, count, remaining


def state_dir():
    base = os.environ.get("XDG_RUNTIME_DIR") or os.path.expanduser("~/.cache")
    return os.path.join(base, "tda-dsc-signer")


class WrongPinMemory:
    """Per-token-serial record of the last wrong PIN, so a retry in another process still sees it. Never stores the PIN."""

    def __init__(self, directory=None, clock=time.time, window=WRONG_PIN_WINDOW):
        self._dir, self._clock, self.window = directory, clock, window

    def _path(self, serial):
        return os.path.join(self._dir or state_dir(), hashlib.sha256(serial.encode()).hexdigest()[:24] + ".json")

    def _read(self, serial):
        try:
            with open(self._path(serial)) as f:
                d = json.load(f)
            return float(d["t"]), int(d["n"])
        except (OSError, ValueError, KeyError, TypeError):
            return None  # unreadable record = no record; locking the user out on a corrupt file would be worse

    def check(self, serial, confirm=False):
        rec = self._read(serial)
        if rec and not confirm:
            left = self.window - (self._clock() - rec[0])
            if left > 0:
                raise RecentWrongPin(serial, rec[1], left)

    def record(self, serial):
        rec = self._read(serial)
        d = self._dir or state_dir()
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(d, 0o700)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".wp-")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump({"t": self._clock(), "n": (rec[1] if rec else 0) + 1}, f)
            os.replace(tmp, self._path(serial))
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    def clear(self, serial):
        try:
            os.unlink(self._path(serial))
        except FileNotFoundError:
            pass

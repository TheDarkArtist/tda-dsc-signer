"""Exceptions that cross the module-host pipe by name, so callers keep catching real types (PinIncorrect, TokenLocked...)."""

import pkcs11.exceptions as p11

from .safety import FinalTryNeedsConfirm, TokenLocked
from .signing import FieldAlreadySigned, NoSupportedMechanism, OutputExists


class HostError(Exception):
    """The module host misbehaved (timeout, crash, protocol)."""


class HostTimeout(HostError):
    pass


class HostBusy(HostError):
    pass


class DriverBusy(Exception):
    """Another tda-dsc-signer process holds this PKCS#11 driver (vendor drivers / PC-SC readers cannot be shared): args[0] is the
    user-facing message. Crosses the host pipe with its attributes."""

    def __init__(self, message, module="", holder_pid=0, holder_cmd=""):
        super().__init__(message)
        self.module, self.holder_pid, self.holder_cmd = module, holder_pid, holder_cmd

    def extra(self):
        return {"module": self.module, "holder_pid": self.holder_pid, "holder_cmd": self.holder_cmd}

    @classmethod
    def from_extra(cls, message, extra):
        return cls(message, str(extra.get("module", "")), int(extra.get("holder_pid") or 0), str(extra.get("holder_cmd", "")))


class PanMismatch(Exception):
    """The certificate does not belong to the PAN in the signature field's name. args[0] is the user-facing message."""

    def __init__(self, message, field="", pan_masked="", cn=""):
        super().__init__(message)
        self.field, self.pan_masked, self.cn = field, pan_masked, cn

    def extra(self):
        return {"field": self.field, "pan_masked": self.pan_masked, "cn": self.cn}

    @classmethod
    def from_extra(cls, message, extra):
        return cls(message, str(extra.get("field", "")), str(extra.get("pan_masked", "")), str(extra.get("cn", "")))


class TokenCountMismatch(RuntimeError):
    """USB says N token devices are attached but the drivers returned fewer: busy, still starting, or pcscd trouble.
    args[0] is the user-facing message."""

    def __init__(self, expected, found, module="usb"):
        super().__init__(f"{expected} token device(s) detected but the driver returned {found}; it may be busy or still starting: try Refresh")
        self.module, self.expected, self.found = module, expected, found


class PinStoreUnavailable(Exception):
    """The system secret store (libsecret) is not usable; args[0] says why and how to get one."""


class RemoteError(Exception):
    def __init__(self, type_, message):
        super().__init__(f"{type_}: {message}")
        self.type, self.message = type_, message


KNOWN = {
    c.__name__: c
    for c in (
        *(v for v in vars(p11).values() if isinstance(v, type) and issubclass(v, p11.PKCS11Error)),
        TokenLocked,
        FinalTryNeedsConfirm,
        NoSupportedMechanism,
        OutputExists,
        FieldAlreadySigned,
        PanMismatch,
        DriverBusy,
        ValueError,
    )
}


def to_wire(exc):
    wire = {"type": type(exc).__name__, "message": str(exc)}
    if hasattr(exc, "extra"):
        wire["extra"] = exc.extra()
    return wire


def from_wire(err):
    cls = KNOWN.get(err["type"])
    if cls and hasattr(cls, "from_extra") and isinstance(err.get("extra"), dict):
        return cls.from_extra(err["message"], err["extra"])
    return cls(err["message"]) if cls else RemoteError(err["type"], err["message"])

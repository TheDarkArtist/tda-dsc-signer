"""Remembered token PINs. A PIN is only ever held in process memory or in the system secret store (libsecret / Secret Service).
There is NO plaintext fallback: without a secret store, 'keyring' mode is refused. Modes (not secret) live in config.toml."""

from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from typing import Protocol

from . import config
from .errors import PinStoreUnavailable

MODES = ("ask", "session", "keyring")
NO_PROVIDER = "No Secret Service provider is running. Enable KeePassXC > Settings > Secret Service Integration, or install gnome-keyring."
SCHEMA_NAME = "in.tdacorp.DscSigner.Pin"
LABEL = "DSC Signer token PIN"


class PinStore(Protocol):
    def available(self) -> bool: ...
    def unavailable_reason(self) -> str: ...
    def get(self, serial: str) -> str | None: ...
    def set(self, serial: str, pin: str) -> None: ...
    def delete(self, serial: str) -> None: ...
    def delete_all(self) -> None: ...
    def has(self, serial: str) -> bool: ...


class MemoryStore:
    """Process-local dict: tests and the 'until I close the app' mode."""

    def __init__(self):
        self._d = {}

    def available(self):
        return True

    def unavailable_reason(self):
        return ""

    def get(self, serial):
        return self._d.get(serial)

    def set(self, serial, pin):
        self._d[serial] = pin

    def delete(self, serial):
        self._d.pop(serial, None)

    def delete_all(self):
        self._d.clear()

    def has(self, serial):
        return serial in self._d


class UnavailableStore:
    def __init__(self, reason=NO_PROVIDER):
        self.reason = reason

    def available(self):
        return False

    def unavailable_reason(self):
        return self.reason

    def get(self, serial):
        return None

    def has(self, serial):
        return False

    def delete(self, serial):
        pass

    def delete_all(self):
        pass

    def set(self, serial, pin):
        raise PinStoreUnavailable(self.reason)


def secret_service_on_session_bus(timeout_ms=2000):
    """True when org.freedesktop.secrets has an owner or is bus-activatable. Asked first so libsecret is never called with no
    provider (it prints a noisy 'g_object_unref: assertion G_IS_OBJECT failed' warning). A dead or missing bus means False."""
    from gi.repository import Gio, GLib

    name = "org.freedesktop.secrets"
    try:
        bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)

        def call(method, args, reply):
            return bus.call_sync(
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                method,
                args,
                GLib.VariantType(reply),
                Gio.DBusCallFlags.NONE,
                timeout_ms,
                None,
            ).unpack()[0]

        return call("NameHasOwner", GLib.Variant("(s)", (name,)), "(b)") or name in call("ListActivatableNames", None, "(as)")
    except GLib.Error:
        return False


class LibsecretStore:
    """Secret Service through gi `Secret`. Every call runs in a worker thread bounded by `timeout` seconds
    (a locked collection can pop an unlock prompt; we never wait forever)."""

    def __init__(self, secret=None, timeout=10.0, probe=None):
        self._secret, self._timeout, self._reason = secret, timeout, ""
        self._probe = probe or (secret_service_on_session_bus if secret is None else (lambda: True))  # an injected module is a test double
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="libsecret")

    def _mod(self):
        if self._secret is None:
            import gi

            gi.require_version("Secret", "1")
            from gi.repository import Secret

            self._secret = Secret
        return self._secret

    def _schema(self):
        S = self._mod()
        return S.Schema.new(SCHEMA_NAME, S.SchemaFlags.NONE, {"serial": S.SchemaAttributeType.STRING})

    def _run(self, fn):
        return self._pool.submit(fn).result(timeout=self._timeout)

    def available(self):
        try:
            S = self._mod()
            if not self._probe():
                self._reason = NO_PROVIDER
                return False
            self._run(lambda: S.Service.get_sync(S.ServiceFlags.OPEN_SESSION, None))
            self._reason = ""
            return True
        except FutureTimeout:
            self._reason = "The Secret Service did not answer in time (is the keyring locked?)."
        except Exception:  # noqa: BLE001 - gi missing, typelib missing, no provider on the bus: all mean 'unavailable'
            self._reason = NO_PROVIDER
        return False

    def unavailable_reason(self):
        return self._reason or ("" if self.available() else self._reason)

    def _call(self, fn):
        try:
            return self._run(fn)
        except FutureTimeout:
            raise PinStoreUnavailable("The Secret Service did not answer in time (is the keyring locked?).") from None
        except Exception as e:  # noqa: BLE001 - never put the PIN (or backend text that may echo it) into the message
            raise PinStoreUnavailable(f"Secret Service error ({type(e).__name__})") from None

    def get(self, serial):
        S = self._mod()
        return self._call(lambda: S.password_lookup_sync(self._schema(), {"serial": serial}, None))

    def has(self, serial):
        return self.get(serial) is not None

    def set(self, serial, pin):
        S = self._mod()
        self._call(lambda: S.password_store_sync(self._schema(), {"serial": serial}, S.COLLECTION_DEFAULT, LABEL, pin, None))

    def delete(self, serial):
        S = self._mod()
        self._call(lambda: S.password_clear_sync(self._schema(), {"serial": serial}, None))

    def delete_all(self):
        S = self._mod()
        self._call(lambda: S.password_clear_sync(self._schema(), {}, None))  # no attribute filter = every item of our schema


def default_store():
    store = LibsecretStore()
    return store if store.available() else UnavailableStore(store.unavailable_reason())


class PinManager:
    """Per-token mode (config.toml) + where the PIN lives. A saved PIN is handed to sign() like a typed one."""

    def __init__(self, store=None, session=None, config_load=config.load, config_save=config.save):
        self._store_ = store
        self._session = MemoryStore() if session is None else session
        self._load, self._save_cfg = config_load, config_save

    @property
    def _store(self):
        if self._store_ is None:  # lazy: constructing a manager (default_backend) must not talk to D-Bus
            self._store_ = default_store()
        return self._store_

    def mode(self, serial):
        m = self._load().pin_modes.get(serial, "ask")
        return m if m in MODES else "ask"

    def set_mode(self, serial, mode):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        if mode == "keyring" and not self._store.available():
            raise PinStoreUnavailable(self._store.unavailable_reason())
        old = self.mode(serial)
        if old != mode:
            self.forget(serial)  # a PIN saved under the old mode must not survive into the new one
        cfg = self._load()
        modes = {k: v for k, v in cfg.pin_modes.items() if k != serial}
        if mode != "ask":
            modes[serial] = mode
        cfg.pin_modes = modes
        self._save_cfg(cfg)

    def saved_pin(self, serial):
        m = self.mode(serial)
        if m == "session":
            return self._session.get(serial)
        if m == "keyring":
            return self._store.get(serial) if self._store.available() else None
        return None

    def has_saved(self, serial):
        m = self.mode(serial)
        if m == "session":
            return self._session.has(serial)
        return m == "keyring" and self._store.available() and self._store.has(serial)

    def save(self, serial, pin, mode, *, protected_auth=False):
        """Set the mode and store the PIN there (never both places). No login happens: a wrong PIN is only found at sign time."""
        if protected_auth:
            raise ValueError("this token uses a protected authentication path (PIN pad): no PIN is stored for it")
        if mode not in ("session", "keyring"):
            raise ValueError("save needs mode 'session' or 'keyring'")
        if not pin:
            raise ValueError("empty PIN")
        self.set_mode(serial, mode)  # raises PinStoreUnavailable first: nothing is written then
        (self._store if mode == "keyring" else self._session).set(serial, pin)

    def remember_session(self, serial, pin):
        if self.mode(serial) == "session":
            self._session.set(serial, pin)

    def forget(self, serial):
        self._session.delete(serial)
        if self._store.available():
            self._store.delete(serial)

    def forget_all(self):
        self._session.delete_all()
        if self._store.available():
            self._store.delete_all()

    def on_pin_incorrect(self, serial):
        """A saved PIN was rejected: delete it everywhere, drop to 'ask'. True when something was deleted."""
        had = self.has_saved(serial)
        self.forget(serial)
        if self.mode(serial) != "ask":
            self.set_mode(serial, "ask")
        return had

    def status(self):
        ok = self._store.available()
        return {"available": ok, "reason": "" if ok else self._store.unavailable_reason()}

"""Point every XDG directory at a fresh temp dir BEFORE anything reads config, and fail loudly if that did not work."""

import os
import tempfile

REAL_HOME = os.path.realpath(os.path.expanduser("~"))
XDG = ("XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR", "XDG_DATA_HOME")


def isolate(root=None, dbus=False):
    """dbus=True keeps the session bus the caller provides (only for tests that start their OWN private bus)."""
    # no session bus: a GUI under test must never register on (or forward to) the user's REAL running tda-dsc-signer
    if not dbus:
        os.environ["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=/nonexistent/dsc-test-bus"
    root = root or tempfile.mkdtemp(prefix="dsc-test-xdg-")
    for name in XDG:
        os.environ[name] = os.path.join(root, name.lower())
        os.makedirs(os.environ[name], mode=0o700, exist_ok=True)
    assert_isolated()
    return root


def assert_isolated():
    """Raise unless the config path resolves outside the real $HOME/.config (and every XDG dir is a temp one)."""
    from tda_dsc_signer import config

    real = os.path.join(REAL_HOME, ".config")
    path = os.path.realpath(config.default_path())
    if path == real or path.startswith(real + os.sep):
        raise RuntimeError(f"test would touch the REAL config: {path}")
    for name in XDG:
        v = os.path.realpath(os.environ.get(name, ""))
        if not v or v == REAL_HOME or v.startswith(os.path.join(REAL_HOME, ".config")) or v.startswith(os.path.join(REAL_HOME, ".local")):
            raise RuntimeError(f"{name}={v!r} is not isolated")


def poppler_env():
    """Environment for pdfsig/pdftotext. An EMPTY XDG_CONFIG_HOME makes pdfsig's NSS init stall ~10 s and then crash (measured:
    'double free or corruption'), so poppler tools see the process environment without the isolated config dir."""
    return {k: v for k, v in os.environ.items() if k != "XDG_CONFIG_HOME"}

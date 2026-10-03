"""~/.config/tda-dsc-signer/config.toml (read with tomllib, written by hand: flat keys only)."""

import json
import os
import sys
import tempfile
import tomllib
from dataclasses import asdict, dataclass, field, fields

from .stamp import DEFAULT_TEXT


@dataclass
class Config:
    extra_modules: list = field(default_factory=list)
    opensc_fallback: str = "auto"  # auto | never | always: see TokenService._fallback_allowed
    allowed_modules: list = field(default_factory=list)  # user-owned PKCS#11 modules that may be loaded (see tokens.vet_module)
    stamp_text: str = DEFAULT_TEXT
    default_box: list = field(default_factory=lambda: [300, 40, 560, 110])
    last_token: str = ""
    last_page: int = 0  # 1-based; 0 = none
    last_box: list = field(default_factory=list)
    profile: str = "mca"  # mca | general
    timestamp_url: str = ""  # set to enable PAdES-B-T
    signature_format: str = "auto"  # auto | pades | adbe: auto = adbe for existing form fields, pades for drawn boxes
    default_mode: str = "auto"  # auto | mca | general: used by the GUI only
    pin_modes: dict = field(default_factory=dict)  # token serial -> "ask" | "session" | "keyring" (modes only, never a PIN)


def default_path():
    return os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "tda-dsc-signer", "config.toml")


def load(path=None):
    try:
        with open(path or default_path(), "rb") as f:
            raw = tomllib.load(f)
    except FileNotFoundError:
        return Config()
    except (OSError, tomllib.TOMLDecodeError) as e:
        print(f"WARNING: ignoring unreadable config {path or default_path()}: {e}", file=sys.stderr)
        return Config()
    known = {f.name for f in fields(Config)}
    cfg = Config(**{k: v for k, v in raw.items() if k in known})
    for key, allowed in (("signature_format", ("auto", "pades", "adbe")), ("default_mode", ("auto", "mca", "general"))):
        if getattr(cfg, key) not in allowed:
            print(f"WARNING: config {key} must be one of {allowed}; using the default", file=sys.stderr)
            setattr(cfg, key, getattr(Config(), key))
    return cfg


def _toml(v):
    if isinstance(v, dict):  # inline table: only string keys/values are used
        return "{" + ", ".join(f"{json.dumps(str(k))} = {_toml(x)}" for k, x in v.items()) + "}"
    return json.dumps(v)


def save(cfg, path=None):
    path = str(path or default_path())
    os.makedirs(os.path.dirname(path), exist_ok=True)
    # json.dumps output (strings, int lists, escaped newlines) is valid TOML for these value types
    text = "".join(f"{k} = {_toml(v)}\n" for k, v in asdict(cfg).items())
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".config-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise

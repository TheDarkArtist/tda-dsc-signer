"""PKCS#11 discovery: find driver modules, enumerate tokens, list signing certificates (no login needed)."""

import base64
import glob
import os
import stat
import time
import unicodedata
from dataclasses import asdict, dataclass
from typing import Protocol

import pkcs11
from asn1crypto import x509
from pkcs11 import Attribute, ObjectClass

from .quirks import INNAIT_DRIVER, find
from .safety import PinState, guard_login

VENDOR = [
    INNAIT_DRIVER,
    "/usr/lib/libeToken.so",
    "/usr/lib/libeTPkcs11.so",
    "/usr/lib/libcastle*.so",
    "/usr/lib/libwdpkcs*.so",
    "/usr/lib/libepsng_p11.so",
    "/usr/lib/libshuttle_p11*.so",
    "/usr/lib/libcmP11.so",
    "/usr/local/lib/libwdpkcs*.so",
]
FALLBACK = ["/usr/lib/opensc-pkcs11.so"]  # only tried when no vendor driver finds a token (it costs ~5s)
SIGN_USAGES = {"digital_signature", "non_repudiation"}
EXPIRED_MARK = "  [EXPIRED]"


@dataclass(frozen=True)
class TokenCert:
    """A signing certificate plus where it lives. slot is the INDEX from lib.get_slots() of the same enumeration."""

    module: str
    slot: int
    token: str
    serial: str
    label: str
    der: bytes
    cn: str
    org: str
    end: str  # YYYY-MM-DD
    chain: tuple = ()  # DER of the issuer certs found on the same token, nearest issuer first
    cert_id: str = ""  # CKA_ID, hex: what signing selects by (label is display only)
    pin: PinState = PinState()  # token PIN-retry flags read at enumeration time

    @property
    def key(self):
        return f"{self.serial}/{self.cert_id or self.label}"

    @property
    def subject_serial(self):
        """Subject serialNumber (Indian DSCs: sha256 of the holder's PAN), lowercase; '' if absent."""
        return (x509.Certificate.load(self.der).subject.native.get("serial_number") or "").lower()

    def expired(self, today=None):
        return self.end < (today or time.strftime("%Y-%m-%d"))

    def display(self):
        return f"{self.cn} ({self.org}) - {self.token}, until {self.end}" + (EXPIRED_MARK if self.expired() else "")


class ModuleSource(Protocol):
    """Where PKCS#11 module paths come from. Callers only see the list of paths."""

    def modules(self) -> list[str]: ...


class GlobSource:
    """Glob patterns -> existing real paths."""

    def __init__(self, patterns):
        self.patterns = list(patterns)

    def modules(self):
        return sorted({os.path.realpath(p) for pat in self.patterns for p in glob.glob(pat)})


class EnvSource(GlobSource):
    """DSC_MODULES (colon separated) plus modules named in the config file."""

    def __init__(self, extra=()):
        super().__init__([m for m in os.environ.get("DSC_MODULES", "").split(":") if m] + list(extra))


P11KIT_DIRS = ("/usr/share/p11-kit/modules", "/etc/pkcs11/modules", "~/.config/pkcs11/modules")
P11KIT_LIBDIR = "/usr/lib/pkcs11"
# never load these through us: the trust store is not a token, the proxy loads every driver into one process, and OpenSC is
# the fallback only (it costs ~5s and sees nothing on InnaIT tokens)
P11KIT_SKIP = ("p11-kit-trust.so", "p11-kit-proxy.so", "opensc-pkcs11.so")


class P11KitSource:
    """Modules registered with p11-kit (`module: path` in *.module files). Relative paths live under /usr/lib/pkcs11."""

    def __init__(self, dirs=P11KIT_DIRS, libdir=P11KIT_LIBDIR, skip=P11KIT_SKIP):
        self.dirs, self.libdir, self.skip = [os.path.expanduser(d) for d in dirs], libdir, skip

    def modules(self):
        found = set()
        for d in self.dirs:
            for f in sorted(glob.glob(os.path.join(d, "*.module"))):
                try:
                    lines = open(f).read().splitlines()
                except OSError:
                    continue
                for line in lines:
                    key, _, val = line.partition(":")
                    path = val.strip()
                    if key.strip() != "module" or not path or os.path.basename(path) in self.skip:
                        continue
                    path = path if os.path.isabs(path) else os.path.join(self.libdir, path)
                    if os.path.exists(path):
                        found.add(os.path.realpath(path))
        return sorted(found)


def vet_module(path, allow=(), uid=None):
    """'' when `path` may be dlopen'd by a module host, else the reason. A PKCS#11 module runs with the PIN in its process, so:
    absolute regular file, owned by root or us, neither it nor its directory group/world-writable, and anything that the current
    user controls (file or directory) must be explicitly allowed (--allow-user-module / `allowed_modules` in the config)."""
    uid = os.geteuid() if uid is None else uid
    if not os.path.isabs(path):
        return "not an absolute path"
    try:
        real = os.path.realpath(path)
        st, pst = os.stat(real), os.stat(os.path.dirname(real))
    except OSError as e:
        return f"not accessible ({e.strerror})"
    if not stat.S_ISREG(st.st_mode):
        return "not a regular file"
    for what, s in (("file", st), ("directory", pst)):
        if s.st_uid not in (0, uid):
            return f"{what} is owned by uid {s.st_uid}"
        if s.st_mode & 0o022:
            return f"{what} is writable by group/other"
    if (st.st_uid != 0 or pst.st_uid != 0) and real not in {os.path.realpath(a) for a in allow}:
        return "controlled by the current user and not allowed (use --allow-user-module PATH or `allowed_modules` in the config)"
    return ""


class VettedSource:
    """Wraps a source and drops modules that fail vet_module; the reasons stay in .rejected {path: reason}."""

    def __init__(self, inner, allow=()):
        self.inner, self.allow, self.rejected = inner, list(allow), {}

    def modules(self):
        ok, self.rejected = [], {}
        for m in self.inner.modules():
            reason = vet_module(m, self.allow)
            if reason:
                self.rejected[m] = reason
            else:
                ok.append(m)
        return ok


def default_sources(extra=(), allow=None):
    from . import config  # local: config is a leaf, but tokens is imported by the module host which needs no config

    allow = config.load().allowed_modules if allow is None else allow
    return [VettedSource(s, allow) for s in (P11KitSource(), GlobSource(VENDOR), EnvSource(extra))]


def is_signing_cert(cert):
    """Non-CA, and (when key usage is present) allowed to sign. Missing key usage = allowed."""
    if cert.ca:
        return False
    ku = set(cert.key_usage_value.native) if cert.key_usage_value else None
    return ku is None or bool(ku & SIGN_USAGES)


def build_chain(leaf, cas):
    """Issuer path leaf -> root from the CA certs on the token (matched by name, key id when present). Loop-safe."""
    chain, cur = [], leaf
    while cur.issuer != cur.subject and len(chain) < 8:
        cands = [c for c in cas if c.subject == cur.issuer and c.sha256 != cur.sha256]
        akid = cur.authority_key_identifier
        exact = [c for c in cands if akid and c.key_identifier == akid]
        nxt = (exact or cands or [None])[0]
        if nxt is None:
            break
        chain.append(nxt)
        cur = nxt
    return chain


def clean(text):
    """Token-supplied display strings: control/format characters (ESC, bidi overrides...) become '?' before printing or GUI use."""
    return "".join("?" if unicodedata.category(ch)[0] == "C" else ch for ch in str(text))


def _info(slot, tok):
    return clean(tok.label.strip()), tok.serial.decode().strip(), PinState.from_flags(tok.flags)


def _cert_row(path, idx, label, serial, pin, o, c, cas):
    subj = c.subject.native
    return TokenCert(
        path,
        idx,
        label,
        serial,
        o[Attribute.LABEL],
        bytes(o[Attribute.VALUE]),
        clean(subj.get("common_name", "?")),
        clean(subj.get("organization_name", "")),
        c.not_valid_after.strftime("%Y-%m-%d"),
        tuple(x.dump() for x in build_chain(c, cas)),
        bytes(o[Attribute.ID] or b"").hex(),
        pin,
    )


def signing_certs(path, load_lib=pkcs11.lib, skipped=None):
    """Everything a module offers, read WITHOUT login. A bad slot or a malformed object is skipped (reason appended to
    `skipped` when given); it never aborts the rest of the module."""
    out = []
    skipped = [] if skipped is None else skipped
    try:
        slots = load_lib(path).get_slots()
    except Exception:  # a driver that fails to load must not hide the others
        return out
    for idx, slot in enumerate(slots):
        try:
            tok = slot.get_token()
            label, serial, pin = _info(slot, tok)
            with tok.open() as s:
                objs = []
                for o in find(s, {Attribute.CLASS: ObjectClass.CERTIFICATE}):
                    try:
                        c = x509.Certificate.load(bytes(o[Attribute.VALUE]))
                        _ = (c.ca, c.key_usage_value, c.subject.native, c.not_valid_after, c.issuer)  # asn1crypto parses lazily: force it here
                        objs.append((o, c))
                    except Exception as e:  # noqa: BLE001 - malformed DER / attribute from a buggy or hostile token
                        skipped.append(f"slot {idx}: unreadable certificate object ({type(e).__name__})")
                cas = [c for _, c in objs if c.ca]
                for o, c in objs:
                    try:
                        if is_signing_cert(c):
                            out.append(_cert_row(path, idx, label, serial, pin, o, c, cas))
                    except Exception as e:  # noqa: BLE001
                        skipped.append(f"slot {idx}: unusable certificate ({type(e).__name__})")
        except (pkcs11.TokenNotPresent, pkcs11.DeviceRemoved, pkcs11.SlotIDInvalid, pkcs11.PKCS11Error):
            continue  # unplugged / replaced mid-enumeration: the next poll sees the new state
        except Exception as e:  # noqa: BLE001
            skipped.append(f"slot {idx}: {type(e).__name__}")
    return out


def present_tokens(path, load_lib=pkcs11.lib):
    """Cheap hot-plug probe: sorted (serial, label) of tokens currently in slots. No sessions opened."""
    seen = []
    try:
        slots = load_lib(path).get_slots()
    except Exception:
        return seen
    for slot in slots:
        try:
            tok = slot.get_token()
            seen.append((tok.serial.decode().strip(), tok.label.strip()))
        except (pkcs11.TokenNotPresent, pkcs11.DeviceRemoved, pkcs11.SlotIDInvalid, pkcs11.PKCS11Error):
            continue
    return sorted(seen)


def token_for(cert, load_lib=pkcs11.lib):
    """Locate the token by SERIAL in a fresh enumeration (slot order is not stable across plug events)."""
    for slot in load_lib(cert.module).get_slots():
        try:
            tok = slot.get_token()
        except pkcs11.PKCS11Error:
            continue
        if tok.serial.decode().strip() == cert.serial:
            return tok
    raise pkcs11.NoSuchToken(f"token {cert.serial} is not present")


def open_session(cert, pin, confirm_final_try=False, load_lib=pkcs11.lib):
    """The ONE login. Flags are checked first; a wrong PIN raises and is never retried by anything in this package."""
    tok = token_for(cert, load_lib)
    guard_login(PinState.from_flags(tok.flags), confirm_final_try)
    if PinState.from_flags(tok.flags).protected_auth:
        return tok.open(user_pin=pkcs11.PROTECTED_AUTH)
    return tok.open(user_pin=pin)


def cert_to_dict(c):
    """JSON-safe form for the host pipe (public data only)."""
    d = asdict(c)
    d["der"] = base64.b64encode(c.der).decode()
    d["chain"] = [base64.b64encode(x).decode() for x in c.chain]
    return d


def cert_from_dict(d):
    d = dict(d)
    d["der"] = base64.b64decode(d["der"])
    d["chain"] = tuple(base64.b64decode(x) for x in d["chain"])
    d["pin"] = PinState(**d["pin"])
    return TokenCert(**d)

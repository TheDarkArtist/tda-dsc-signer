"""tda-dsc-signer [file.pdf] -> GUI;  list | sign | doctor -> scriptable commands."""

import argparse
import getpass
import os
import shutil
import sys
import tempfile
import time

import pkcs11

from . import config, doctor, forms, geometry, pan, safety, signing, verify
from .errors import DriverBusy, PinStoreUnavailable, TokenCountMismatch
from .pinstore import PinManager
from .service import TokenService
from .tokens import clean, default_sources
from .trust import commands as trust_commands

COMMANDS = {"list", "sign", "doctor", "trust", "pin", "fields"}
PIN_ENV = "PYHANKO_PKCS11_PIN"


def _version():
    try:
        from importlib.metadata import version

        return version("tda-dsc-signer")
    except Exception:
        return "0.1.0"


def busy_hint(svc):
    """Non-empty when another tda-dsc-signer holds a driver: an empty list then means 'busy', not 'no token'."""
    pids = sorted({e.holder_pid for e in svc.errors.values() if isinstance(e, DriverBusy) and e.holder_pid})
    if not any(isinstance(e, DriverBusy) for e in svc.errors.values()):
        return ""
    who = f" (pid {', '.join(map(str, pids))})" if pids else ""
    return f"Another tda-dsc-signer{who} is using the token driver. Close it, then retry (or use --wait-driver SECONDS)."


def show(certs, write=print, busy=""):
    if not certs and busy:
        write(busy)
    elif not certs:
        write("No DSC token with a signing certificate found. Is it plugged in and is pcscd running? Try: tda-dsc-signer doctor")
    for i, c in enumerate(certs, 1):
        flag = "  ** EXPIRED **" if c.expired() else ""
        write(f"[{i}] {c.cn}  ({c.org})  | token '{c.token}' {clean(c.serial)}  | valid until {c.end}{flag}  | module {clean(c.module)}")


def warn_errors(svc, write=None):
    """Module failures, driver-busy and count-mismatch notes: prominently on stderr, never silent."""
    for m, e in svc.errors.items():
        text = e.args[0] if isinstance(e, DriverBusy | TokenCountMismatch) else f"module {m}: {type(e).__name__}: {e}"
        print(f"WARNING: {text}", file=write or sys.stderr)


def pick(certs, want):
    if not certs:
        show(certs)
        sys.exit(1)
    if want:
        if not 1 <= want <= len(certs):
            sys.exit(f"-t {want} out of range (1..{len(certs)})")
        return certs[want - 1]
    if len(certs) == 1:
        return certs[0]
    show(certs)
    if not sys.stdin.isatty():
        sys.exit("Several tokens attached: pass -t N.")
    return certs[int(input(f"Sign with which one [1-{len(certs)}]? ")) - 1]


def _parser(cfg):
    p = argparse.ArgumentParser(
        prog="tda-dsc-signer",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="PAGE is 1-based, -1 = last. Box is PDF points, origin bottom-left. "
        f"PIN: prompted (preferred), --pin-fd N, or {PIN_ENV} (visible in /proc/PID/environ of the launcher); never stored. "
        "No args / a .pdf path opens the GUI.",
    )
    p.add_argument("--version", action="version", version=f"tda-dsc-signer {_version()}")
    sub = p.add_subparsers(dest="cmd", required=True)
    allow = argparse.ArgumentParser(add_help=False)
    allow.add_argument(
        "--wait-driver",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="wait this long for another tda-dsc-signer to release the driver (default 0)",
    )
    allow.add_argument(
        "--opensc-fallback",
        choices=("auto", "never", "always"),
        default=None,
        help="OpenSC probe: auto (default; only if no vendor module exists and no driver is busy), never, always",
    )
    allow.add_argument("--allow-user-module", action="append", default=[], metavar="PATH", help="permit this user-owned PKCS#11 module for this run")
    sub.add_parser("list", parents=[allow], help="list signing certificates on attached tokens (no PIN)")
    trust_commands.add_parser(sub)
    sub.add_parser("doctor", help="check pcscd / USB / CCID plist / pacman hook / driver; prints sudo fixes")
    fl = sub.add_parser("fields", parents=[allow], help="list the signature fields of a PDF and which attached token matches each PAN (no PIN)")
    fl.add_argument("input")
    s = sub.add_parser("sign", parents=[allow], help="sign a PDF")
    s.add_argument("input")
    s.add_argument("-o", "--output", help="default: <name>-signed.pdf (never the input)")
    s.add_argument("-p", "--page", type=int, default=1)
    s.add_argument("-b", "--box", default=",".join(map(str, cfg.default_box)))
    s.add_argument("-t", "--token", type=int, help="number from `list`")
    s.add_argument("--profile", choices=signing.PROFILES, default=cfg.profile, help="mca (default): size-checked for MCA uploads; general")
    s.add_argument("--confirm-final-try", action="store_true", help="allow the login when the token reports its LAST PIN try")
    s.add_argument("--confirm-after-failure", action="store_true", help="allow a login within 5 minutes of a recorded wrong PIN on this token")
    s.add_argument("--force", action="store_true", help="overwrite the output file if it already exists")
    s.add_argument("--pin-fd", type=int, metavar="N", help="read the PIN (one line) from inherited file descriptor N; the prompt is preferred")
    s.add_argument("--saved-pin", action="store_true", help="use the PIN saved for this token (see `pin set`); prompts when none is saved")
    s.add_argument("--invisible", action="store_true", help="invisible signature: no box, page ignored")
    s.add_argument("--field", metavar="NAME", help="sign into this existing EMPTY signature field (see `fields`); box/page/--invisible do not apply")
    s.add_argument("--all-fields", action="store_true", help="sign every empty field whose PAN matches an attached token; the rest are listed")
    s.add_argument("--allow-pan-mismatch", action="store_true", help="sign a PAN-named field with a certificate that does not match the PAN")
    s.add_argument("--format", choices=signing.FORMATS, default=cfg.signature_format, help="auto: adbe.pkcs7.detached for fields, PAdES for boxes")
    pn = sub.add_parser("pin", parents=[allow], help="manage remembered token PINs (never performs a login)")
    ps = pn.add_subparsers(dest="pin_cmd", required=True)
    ps.add_parser("status", help="per token: mode and whether a PIN is saved (never prints a PIN)")
    st = ps.add_parser("set", help="save a PIN (read with a prompt or --pin-fd)")
    st.add_argument("-t", "--token", type=int, required=True, help="number from `list`")
    st.add_argument("--mode", choices=("session", "keyring"), default="keyring")
    st.add_argument("--pin-fd", type=int, metavar="N")
    fg = ps.add_parser("forget", help="delete a saved PIN")
    fg.add_argument("-t", "--token", type=int, help="number from `list`")
    fg.add_argument("--all", action="store_true")
    return p


def read_pin_fd(fd):
    with os.fdopen(fd, "r", closefd=True) as f:
        return f.readline().rstrip("\r\n")


def _pin_cmd(a, cfg, svc, pins):
    """`pin status|set|forget`: no login anywhere. `session` mode only lives in this process, so it is of little use on the CLI."""
    if a.pin_cmd == "forget" and a.all:
        pins.forget_all()
        print("All saved PINs forgotten.")
        return 0
    if a.pin_cmd == "forget" and not a.token:
        sys.exit("pin forget: pass --token N or --all")
    certs = svc.discover(cfg.extra_modules)
    warn_errors(svc)
    if a.pin_cmd == "status":
        st = pins.status()
        print(f"Secret store: {'available' if st['available'] else 'NOT available: ' + st['reason']}")
        for i, c in enumerate(certs, 1):
            saved = "PIN saved" if pins.has_saved(c.serial) else "not saved"
            print(f"[{i}] {c.cn} | token '{clean(c.token)}' {clean(c.serial)} | mode {pins.mode(c.serial)} | {saved}")
        return 0
    cert = pick(certs, a.token)
    if a.pin_cmd == "forget":
        pins.forget(cert.serial)
        pins.set_mode(cert.serial, "ask")
        print(f"Forgot the PIN of '{cert.token}'.")
        return 0
    pin = read_pin_fd(a.pin_fd) if a.pin_fd is not None else getpass.getpass(f"PIN to save for '{cert.token}': ")
    try:
        pins.save(cert.serial, pin, a.mode, protected_auth=cert.pin.protected_auth)
    except (ValueError, PinStoreUnavailable) as e:
        sys.exit(f"pin set: {e}")
    print(f"PIN saved for '{cert.token}' (mode {a.mode}). It was NOT verified: a wrong PIN is only found when signing.")
    return 0


def _certs(a, cfg, svc):
    certs = svc.discover(cfg.extra_modules)
    warn_errors(svc)
    busy = {m for m, e in svc.errors.items() if isinstance(e, DriverBusy)}
    if busy and (not certs or any(c.module in busy for c in certs)):
        print(busy_hint(svc), file=sys.stderr)
        sys.exit(3)  # another instance owns the driver: an empty/partial list here means "busy", not "no token"
    return certs


def _pin_for(a, svc, cert, pins, env_pin):
    """Guards first (locked / final try / recent wrong PIN), then the PIN. Returns (pin, used_saved)."""
    state = cert.pin
    note = safety.guard_login(state, a.confirm_final_try)  # refuses locked / unconfirmed final try before asking for a PIN
    if note:
        print(f"WARNING: {note}", file=sys.stderr)
    svc.check_recent_failure(cert, a.confirm_after_failure)  # before asking for a PIN, not after
    pin, used_saved = None, False
    if not state.protected_auth and a.saved_pin and pins:
        pin = pins.saved_pin(cert.serial)
        used_saved = pin is not None
        if not used_saved:
            print("No saved PIN for this token; asking instead.", file=sys.stderr)
    if not state.protected_auth and pin is None:
        pin = read_pin_fd(a.pin_fd) if a.pin_fd is not None else env_pin or getpass.getpass(f"PIN for '{cert.token}': ")
    return pin, used_saved


def _sign_one(a, cfg, svc, cert, pins, env_pin, src, out, field=None, overwrite=None, pin_cache=None):
    cache = pin_cache if pin_cache is not None else {}
    if cert.serial in cache:
        pin, used_saved = cache[cert.serial]
    else:
        pin, used_saved = cache[cert.serial] = _pin_for(a, svc, cert, pins, env_pin)
    try:
        return _do_sign(a, cfg, svc, cert, geometry.parse_box(a.box), pin, out, src, field, a.force if overwrite is None else overwrite)
    except pkcs11.PinIncorrect:
        if used_saved and pins.on_pin_incorrect(cert.serial):
            print("The saved PIN was rejected and has been DELETED. Nothing was retried. Save the right PIN again with `pin set`.", file=sys.stderr)
        raise


def _sign(a, cfg, svc, env_pin=None, pins=None):
    """Returns True when the post-sign verification is ok."""
    if (a.field or a.all_fields) and a.invisible:
        sys.exit("--invisible does not apply to signature fields (a field has its own geometry)")
    if a.field and a.all_fields:
        sys.exit("pass --field NAME or --all-fields, not both")
    geometry.parse_box(a.box)
    out = a.output or signing.default_output(a.input)
    signing.check_output(a.input, out, a.force)
    certs = _certs(a, cfg, svc)
    if a.all_fields:
        return _sign_all(a, cfg, svc, certs, pins, env_pin, out)
    cert = pick(certs, a.token)
    res = _sign_one(a, cfg, svc, cert, pins, env_pin, a.input, out, a.field)
    return _report(a, cert, res, out)


def _sign_all(a, cfg, svc, certs, pins, env_pin, out):
    todo = [f for f in forms.find_signature_fields(a.input) if not f.signed]
    if not todo:
        sys.exit("no empty signature fields in this PDF")
    m = pan.match(todo, certs)
    by_key = {c.key: c for c in certs}
    plan = [(f, by_key[m[f.name].cert_key]) for f in todo if m[f.name].status == "match"]
    for f in todo:
        if m[f.name].status != "match":
            print(f"needs another signer: {f.name} (page {f.page}, PAN {f.pan_masked or 'none'})")
    if not plan:
        sys.exit("no attached token matches any empty field")
    # one PIN prompt per token (cached for the chain); one login per signature
    cache, src, ok = {}, a.input, True
    tmpdir = tempfile.mkdtemp(prefix=".dsc-fields-", dir=os.path.dirname(os.path.abspath(out)))
    try:
        for i, (f, cert) in enumerate(plan):
            last = i == len(plan) - 1
            dst = out if last else os.path.join(tmpdir, f"step{i}.pdf")
            res = _sign_one(a, cfg, svc, cert, pins, env_pin, src, dst, f.name, a.force if last else True, cache)
            src = dst
            if last:
                print(f"{len(plan)} of {len(todo)} empty field(s) signed -> {out}")
        for f, cert in plan:
            print(f"  {f.name}: {cert.cn} ({cert.token})")
        ok = _report(a, plan[-1][1], res, out)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return ok


def _do_sign(a, cfg, svc, cert, box, pin, out, src=None, field=None, overwrite=None):
    return svc.sign(
        src or a.input,
        cert,
        page=a.page,
        box=box,
        pin=pin,
        out=out,
        stamp_text=cfg.stamp_text,
        profile=a.profile,
        timestamp_url=cfg.timestamp_url,
        confirm_final_try=a.confirm_final_try,
        confirm_after_failure=a.confirm_after_failure,
        overwrite=a.force if overwrite is None else overwrite,
        visible=not a.invisible,
        field=field,
        allow_pan_mismatch=a.allow_pan_mismatch,
        signature_format=a.format,
    )


def _report(a, cert, res, out=None):
    where = f"field {a.field}" if a.field else f"page {a.page}, box {a.box}" if not a.all_fields else "form fields"
    print(f"Signed as {cert.cn} ({cert.token}) -> {res.out}  ({where}, profile {a.profile}, {res.size} bytes)")
    for w in res.warnings:
        print(f"WARNING: {w}", file=sys.stderr)
    v = verify.verify_signed(res.out, res.field_name)
    for r in v.rows:
        print(f"  [{r.state:9}] {r.label}: {r.detail}")
    for fr in v.fields:
        pm = {True: "PAN matches", False: "PAN does NOT match", None: ""}[fr.pan_match]
        print(f"  field {fr.name}: {'signed by ' + fr.signer if fr.signer else 'unsigned'}{' (' + pm + ')' if pm else ''}")
    print(f"Verification: {'OK' if v.ok else 'FAILED'}: {v.detail}")
    return v.ok


def _fields_cmd(a, cfg, svc):
    fl = forms.find_signature_fields(a.input)
    if not fl:
        print("No signature fields in this PDF.")
        return 0
    certs = svc.discover(cfg.extra_modules)
    warn_errors(svc)
    m = pan.match(fl, certs)
    by_key = {c.key: (i, c) for i, c in enumerate(certs, 1)}
    for f in fl:
        who = ""
        if not f.signed:
            hit = by_key.get(m[f.name].cert_key)
            if hit:
                who = f"[{hit[0]}] {hit[1].cn} / {clean(hit[1].token)}" + ("" if m[f.name].status == "match" else " (PAN not checkable)")
            else:
                who = "no attached token matches" if f.pan else "any token"
        print(f"{f.name}  page {f.page}  PAN {f.pan_masked or '-'}  {'signed' if f.signed else 'unsigned'}  {who}".rstrip())
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    env_pin = os.environ.pop(PIN_ENV, None)  # out of os.environ before anything (module host, GUI, children) can inherit it
    cfg = config.load()
    if not argv or (argv[0] not in COMMANDS and not argv[0].startswith("-")):
        from .gui.app import run_gui

        return run_gui(argv[0] if argv else None)
    a = _parser(cfg).parse_args(argv)
    if a.cmd == "doctor":
        return doctor.report(doctor.diagnose())
    if a.cmd == "trust":
        try:
            return trust_commands.run(a)
        except (ValueError, RuntimeError, OSError) as e:
            sys.exit(f"trust {a.trust_cmd}: {e}")
    pins = PinManager()
    allowed = [*cfg.allowed_modules, *a.allow_user_module]
    svc = TokenService(
        default_sources(cfg.extra_modules, allowed),
        allow_user_modules=allowed,
        wait_driver=a.wait_driver,
        opensc_fallback=a.opensc_fallback or cfg.opensc_fallback,
    )
    try:
        if a.cmd == "list":
            t0 = time.time()
            show(svc.discover(), busy=busy_hint(svc))
            warn_errors(svc)
            print(f"({time.time() - t0:.1f}s)", file=sys.stderr)
            return 3 if any(isinstance(e, DriverBusy) for e in svc.errors.values()) else 0
        if a.cmd == "pin":
            return _pin_cmd(a, cfg, svc, pins)
        if a.cmd == "fields":
            try:
                return _fields_cmd(a, cfg, svc)
            except (ValueError, OSError) as e:
                sys.exit(f"fields: {e}")
        try:
            return 0 if _sign(a, cfg, svc, env_pin, pins) else 2
        except Exception as e:  # one attempt only: surface the token's error, never retry a PIN
            sys.exit(f"{type(e).__name__}: {e}")
    finally:
        svc.close()

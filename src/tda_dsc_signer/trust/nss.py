"""Dedicated NSS database for poppler (pdfsig, Okular) and LibreOffice. Never ~/.pki/nssdb, never a Firefox profile."""

import os
import subprocess
import tempfile

from asn1crypto import pem

from . import pins, store

DEFAULT_DB = os.path.expanduser("~/.local/share/tda-dsc-signer/nssdb")
ANCHOR_FLAGS = ",C,"  # smallest that makes pdfsig report "Certificate is Trusted"; see README (CT,C,C is not needed)
INTERMEDIATE_FLAGS = ",,"
FORBIDDEN = ("~/.pki/nssdb", "~/.mozilla", "~/.config/chromium", "/etc/pki/nssdb")


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return p.returncode, p.stdout + p.stderr


def _within(path, base):
    return path == base or path.startswith(base + os.sep)


def check_db_path(db, force=False):
    """Allowlist: only under dirname(DEFAULT_DB) unless `force`; the denylist of other software's databases always applies."""
    real = os.path.realpath(os.path.expanduser(db))  # resolves symlinks and '..'
    for bad in FORBIDDEN:
        if _within(real, os.path.realpath(os.path.expanduser(bad))):
            raise ValueError(f"refusing to write {db}: that NSS database belongs to other software")
    home = os.path.realpath(os.path.dirname(DEFAULT_DB))
    if not force and not _within(real, home):
        raise ValueError(f"refusing {db} (resolves to {real}): outside {home}; pass --force-db if this really is a dedicated database")
    return real


def nicknames(db, runner=run, strict=False):
    rc, out = runner(["certutil", "-L", "-d", f"sql:{db}"])
    if rc != 0:
        if strict:
            raise RuntimeError(f"certutil -L failed on {db}: {out.strip()}")
        return {}
    rows = {}
    for line in out.splitlines()[4:]:
        if line.strip() and "  " in line.strip():
            nick, flags = line.rstrip().rsplit(None, 1)
            rows[nick.strip()] = flags
    return rows


def _must(runner, cmd):
    rc, out = runner(cmd)
    if rc != 0:
        raise RuntimeError(f"{' '.join(cmd[:3])} failed: {out.strip()}")


def _existing_matches(db, pin, runner):
    """True when the certificate stored under pin.name IS the pinned one. A nickname proves nothing."""
    rc, out = runner(["certutil", "-L", "-d", f"sql:{db}", "-n", pin.name, "-a"])
    if rc != 0:
        raise RuntimeError(f"cannot read '{pin.name}' back from {db} to check it against its pin: {out.strip()}")
    try:
        der = pem.unarmor(out[out.index("-----BEGIN") :].encode())[2]
    except ValueError:
        raise RuntimeError(f"certutil returned no certificate for '{pin.name}' in {db}") from None
    got = store.sha256_hex(der)
    if got != pin.sha256:
        raise RuntimeError(
            f"'{pin.name}' in {db} is a DIFFERENT certificate (SHA-256 {got}, pinned {pin.sha256}); refusing to change its trust. "
            f"Remove it first with: certutil -D -d sql:{db} -n '{pin.name}'"
        )
    return True


def install(db=DEFAULT_DB, include_old=False, anchor_flags=ANCHOR_FLAGS, runner=run, force=False):
    """Create the db if needed; import the anchor (trusted) and all intermediates (untrusted). Returns imported nicknames.
    An existing nickname is only touched when its certificate matches the pin; old roots not requested are demoted to ',,'."""
    db = check_db_path(db, force)
    os.makedirs(db, exist_ok=True)
    if not os.path.exists(os.path.join(db, "cert9.db")):
        _must(runner, ["certutil", "-N", "-d", f"sql:{db}", "--empty-password"])
    have = nicknames(db, runner, strict=True)
    wanted = [(pins.ANCHOR, anchor_flags), *((p, INTERMEDIATE_FLAGS) for p in pins.INTERMEDIATES)]
    wanted += [(p, anchor_flags) for p in pins.OLD_ROOTS] if include_old else []
    if not include_old:  # a previous --old-roots install must not keep trusting expired roots
        for pin in (p for p in pins.OLD_ROOTS if p.name in have):
            _must(runner, ["certutil", "-M", "-d", f"sql:{db}", "-n", pin.name, "-t", INTERMEDIATE_FLAGS])
    for pin, flags in wanted:
        if pin.name in have:
            _existing_matches(db, pin, runner)
            _must(runner, ["certutil", "-M", "-d", f"sql:{db}", "-n", pin.name, "-t", flags])
            continue
        der = store.bundled_der(pin)  # re-verifies the pin before anything touches NSS
        with tempfile.NamedTemporaryFile(suffix=".der") as f:
            f.write(der)
            f.flush()
            _must(runner, ["certutil", "-A", "-d", f"sql:{db}", "-n", pin.name, "-t", flags, "-i", f.name])
    return [p.name for p, _ in wanted]


def howto(db):
    return (
        f"pdfsig:        pdfsig -nssdir {db} file.pdf\n"
        f"Okular:        Settings > Configure Okular > Signatures > Certificate Database: Custom, folder {db}\n"
        f"LibreOffice:   Tools > Options > LibreOffice > Security > Certificate Path > Select... {db}\n"
        "(Adobe Acrobat uses its own AATL list, which already contains CCA India 2022; not testable here.)"
    )

"""Findings 6, 7, 8: NSS installer. Uses the real certutil on throwaway dbs under tmp_path when available."""

import os
import shutil
import subprocess

import pytest
from asn1crypto import pem
from conftest import der, make_cert

from tda_dsc_signer.trust import nss, pins, store

real_certutil = pytest.mark.skipif(not shutil.which("certutil"), reason="certutil not installed")


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "share" / "tda-dsc-signer"
    h.mkdir(parents=True)
    monkeypatch.setattr(nss, "DEFAULT_DB", str(h / "nssdb"))
    return h


# ---- 8 ---------------------------------------------------------------------------------------------------------------------


def test_db_inside_the_dedicated_directory_is_accepted(home):
    assert nss.check_db_path(str(home / "nssdb")) == str(home / "nssdb")
    assert nss.check_db_path(str(home / "other-db")).startswith(str(home))


@pytest.mark.parametrize("sub", ["../elsewhere", "nssdb/../../elsewhere", "/tmp/anywhere-else"])
def test_db_outside_is_refused_including_dotdot(home, sub):
    target = sub if sub.startswith("/") else str(home / sub)
    with pytest.raises(ValueError, match="--force-db"):
        nss.check_db_path(target)
    assert nss.check_db_path(target, force=True)  # an explicit override is possible


def test_symlink_leading_outside_is_refused(home, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (home / "link").symlink_to(outside)
    with pytest.raises(ValueError, match="outside"):
        nss.check_db_path(str(home / "link" / "db"))


def test_symlink_inside_pointing_at_a_forbidden_db_is_refused_even_with_force(home, tmp_path, monkeypatch):
    forbidden = tmp_path / "pki" / "nssdb"
    forbidden.mkdir(parents=True)
    monkeypatch.setattr(nss, "FORBIDDEN", (str(forbidden),))
    (home / "sneaky").symlink_to(forbidden)
    for force in (False, True):
        with pytest.raises(ValueError, match="belongs to other software"):
            nss.check_db_path(str(home / "sneaky"), force=force)


def test_install_refuses_outside_db_before_touching_anything(home, tmp_path):
    calls = []
    with pytest.raises(ValueError, match="--force-db"):
        nss.install(str(tmp_path / "elsewhere"), runner=lambda c: calls.append(c) or (0, ""))
    assert calls == [] and not (tmp_path / "elsewhere").exists()


# ---- 6 / 7 with the real certutil -----------------------------------------------------------------------------------------


def certutil(*args, **kw):
    return subprocess.run(["certutil", *args], capture_output=True, text=True, **kw)


def flags_of(db, name):
    return nss.nicknames(db)[name]


@real_certutil
def test_planted_wrong_cert_under_a_pinned_nickname_is_refused_and_trust_untouched(home):
    db = str(home / "nssdb")
    os.makedirs(db)
    assert certutil("-N", "-d", f"sql:{db}", "--empty-password").returncode == 0
    evil, _ = make_cert("Evil Root", ca=True)
    der_file = home / "evil.der"
    der_file.write_bytes(der(evil))
    r = certutil("-A", "-d", f"sql:{db}", "-n", pins.ANCHOR.name, "-t", ",,", "-i", str(der_file))
    assert r.returncode == 0, r.stderr
    with pytest.raises(RuntimeError, match="DIFFERENT certificate") as e:
        nss.install(db)
    print(e.value)
    assert flags_of(db, pins.ANCHOR.name).strip() == ",,", "the planted cert must NOT have been promoted to a trusted root"


@real_certutil
def test_genuine_cert_under_the_nickname_is_accepted_and_promoted_then_idempotent(home):
    db = str(home / "nssdb")
    nss.install(db)
    assert flags_of(db, pins.ANCHOR.name).strip() == nss.ANCHOR_FLAGS
    nss.install(db)  # second run: every existing nickname is read back and matches its pin
    assert flags_of(db, pins.ANCHOR.name).strip() == nss.ANCHOR_FLAGS


@real_certutil
def test_install_without_old_roots_demotes_previously_trusted_old_roots(home):
    db = str(home / "nssdb")
    nss.install(db, include_old=True)
    old = pins.OLD_ROOTS[0].name
    before = flags_of(db, old).strip()
    assert "C" in before
    nss.install(db)  # no --old-roots
    after = flags_of(db, old).strip()
    print(f"old root flags: {before!r} -> {after!r}")
    assert after == ",,"
    assert flags_of(db, pins.ANCHOR.name).strip() == nss.ANCHOR_FLAGS


def test_certutil_listing_failure_is_loud_not_silent(home):
    def failing(cmd):
        return (1, "certutil: could not open the database") if cmd[1] == "-L" else (0, "")

    (home / "nssdb").mkdir()
    (home / "nssdb" / "cert9.db").write_text("")
    with pytest.raises(RuntimeError, match="certutil -L failed"):
        nss.install(str(home / "nssdb"), runner=failing)


def test_unreadable_existing_cert_stops_the_install(home):
    def runner(cmd):
        if cmd[1] == "-L" and "-n" in cmd:
            return 255, "certutil: Could not find cert"
        if cmd[1] == "-L":
            return 0, f"\nhdr\n  x\n\n{pins.ANCHOR.name}    CT,C,C"
        return 0, ""

    (home / "nssdb").mkdir()
    (home / "nssdb" / "cert9.db").write_text("")
    with pytest.raises(RuntimeError, match="cannot read"):
        nss.install(str(home / "nssdb"), runner=runner)


def test_pem_roundtrip_helper_matches_pin():
    d = store.bundled_der(pins.ANCHOR)
    assert store.sha256_hex(pem.unarmor(pem.armor("CERTIFICATE", d))[2]) == pins.ANCHOR.sha256

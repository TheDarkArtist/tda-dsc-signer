"""`make install` writes the desktop entry with an ABSOLUTE Exec; the repo copy stays bare (the AUR package installs to /usr/bin)."""

import hashlib
import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DESKTOP = os.path.join(ROOT, "data", "in.tdacorp.DscSigner.desktop")
pytestmark = pytest.mark.skipif(not shutil.which("make"), reason="make not installed")


def make_vars(p):
    return [f"TDA_DATA={p}/share", f"TDA_BIN={p}/bin", f"TDA_APPS={p}/apps", f"TDA_ICONS={p}/icons", f"TDA_META={p}/meta"]


def run_make(args, **kw):
    return subprocess.run(["make", *args], cwd=ROOT, capture_output=True, text=True, **kw)


def test_dry_run_rewrites_exec_to_the_absolute_installed_command(tmp_path):
    r = run_make(["-n", "install", *make_vars(tmp_path)])
    assert r.returncode == 0, r.stderr
    assert f"Exec={tmp_path}/bin/tda-dsc-signer %f" in r.stdout


def test_repo_desktop_file_keeps_the_bare_exec():
    assert "Exec=tda-dsc-signer %f" in open(DESKTOP).read().splitlines()


@pytest.mark.parametrize("bad", ["relative/bin", "/tmp/with space/bin", "/tmp/a;b", "/tmp/a|b"])
def test_unsafe_bin_prefix_is_refused_before_anything_is_installed(tmp_path, bad):
    before = hashlib.sha256(open(DESKTOP, "rb").read()).hexdigest()
    r = run_make(["install", f"TDA_BIN={bad}", f"TDA_DATA={tmp_path}/share", f"TDA_APPS={tmp_path}/apps"])
    assert r.returncode != 0 and ("absolute" in r.stderr or "cannot carry" in r.stderr)
    assert not (tmp_path / "share").exists() and not (tmp_path / "apps").exists()
    assert hashlib.sha256(open(DESKTOP, "rb").read()).hexdigest() == before


def test_the_sed_stage_alone_produces_a_valid_desktop_entry(tmp_path):
    r = run_make(["-n", "install", *make_vars(tmp_path)])
    sed_line = next(ln for ln in r.stdout.splitlines() if ln.startswith("sed "))
    out = subprocess.run(sed_line.split(" | ")[0], shell=True, cwd=ROOT, capture_output=True, text=True).stdout
    f = tmp_path / "x.desktop"
    f.write_text(out)
    if shutil.which("desktop-file-validate"):
        assert subprocess.run(["desktop-file-validate", str(f)], capture_output=True).returncode == 0
    assert f"Exec={tmp_path}/bin/tda-dsc-signer %f" in out.splitlines()

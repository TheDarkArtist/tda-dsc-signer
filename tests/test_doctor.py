import pytest

from tda_dsc_signer import doctor

PLIST_OK = "<key>ifdVendorID</key><array><string>0x338C</string></array><key>ifdProductID</key><array><string>0x0031</string></array>"


def env(tmp_path, plist=PLIST_OK, hook=True, driver=True):
    p = doctor.Paths(
        str(tmp_path / "Info.plist"), str(tmp_path / "x.hook"), str(tmp_path / "patch"), str(tmp_path / "drv.so"), (str(tmp_path / "apps"),)
    )
    if plist is not None:
        (tmp_path / "Info.plist").write_text(plist)
    if hook:
        (tmp_path / "x.hook").write_text("h")
    if driver:
        (tmp_path / "drv.so").write_text("x")
    (tmp_path / "patch").write_text("x")
    return p


def runner(active="pcscd.socket", usb="Bus 001 ID 338c:0031 InnaitKey"):
    def run(cmd):
        if cmd[0] == "systemctl":
            return 0, "active\n" if cmd[-1] == active else "inactive\n"
        return 0, usb

    return run


def names(checks):
    return {c.name: c for c in checks}


def test_healthy_exits_zero(tmp_path):
    checks = doctor.diagnose(env(tmp_path), runner(), dlopen=lambda p: None)
    assert doctor.report(checks, lambda *_: None) == 0


def test_plist_missing_entry_flagged_with_sudo_fix(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "root_script", lambda p: True)  # the real check needs a root-owned file
    c = names(doctor.diagnose(env(tmp_path, plist="<plist/>"), runner(), dlopen=lambda p: None))["ccid plist"]
    assert not c.ok and c.fix.startswith("sudo ") and "patch" in c.fix


def test_missing_hook_driver_usb_pcscd(tmp_path):
    p = env(tmp_path, hook=False, driver=False)
    checks = names(doctor.diagnose(p, runner(active="none", usb="nothing"), dlopen=lambda p: None))
    assert all(not checks[n].ok for n in ("pcscd", "usb token", "pacman hook", "pkcs11 driver"))
    assert "sudo" in checks["pacman hook"].fix and "sudo" in checks["pcscd"].fix
    assert doctor.report(list(checks.values()), lambda *_: None) == 1


def test_driver_that_does_not_dlopen_fails(tmp_path):
    def boom(_p):
        raise OSError("bad ELF")

    c = names(doctor.diagnose(env(tmp_path), runner(), dlopen=boom))["pkcs11 driver"]
    assert not c.ok and "bad ELF" in c.detail


def test_sudo_is_only_suggested_for_a_root_owned_unwritable_script(tmp_path):
    # the temp "patch" script is owned by the test user, not root: no sudo line may point at it
    p = env(tmp_path, plist="<plist/>")
    c = names(doctor.diagnose(p, runner(), dlopen=lambda p: None))["ccid plist"]
    assert not c.ok and not c.fix.startswith("sudo ") and "&& sudo" not in c.fix and "add 0x338C" in c.fix
    assert not doctor.root_script(str(tmp_path / "patch"))
    assert doctor.root_script("/usr/bin/env")
    assert not doctor.root_script(str(tmp_path / "missing"))


def test_driver_is_probed_in_a_child_process_not_loaded_here(tmp_path):
    import sys

    marker = tmp_path / "ran"
    bad = tmp_path / "evil.so"
    bad.write_text("not an ELF")
    with pytest.raises(OSError):
        doctor.probe_dlopen(str(bad))  # a real dlopen failure is reported...
    assert "ctypes" not in doctor.__dict__ and "CDLL" not in vars(doctor)  # ...and this module no longer imports ctypes at all
    assert not marker.exists() and sys.executable


def test_driver_probe_times_out_instead_of_hanging(tmp_path, monkeypatch):
    import subprocess

    def hang(*a, **k):
        raise subprocess.TimeoutExpired("x", 1)

    monkeypatch.setattr(doctor.subprocess, "run", hang)
    with pytest.raises(OSError, match="did not finish"):
        doctor.probe_dlopen("/x.so", timeout=1)


# ---- desktop entry: the launcher's PATH ---------------------------------------------------------------------------------


def desktop(tmp_path, exec_line):
    d = tmp_path / "apps"
    d.mkdir(exist_ok=True)
    (d / doctor.DESKTOP_FILE).write_text(f"[Desktop Entry]\nType=Application\nName=x\n{exec_line}\n")
    return doctor.check_desktop_entry([str(d)])


def test_bare_exec_not_on_the_minimal_path_fails_with_the_exact_fix(tmp_path):
    c = desktop(tmp_path, "Exec=definitely-not-installed-xyz %f")
    assert not c.ok and "make install" in c.fix and "sed -i" in c.fix and str(tmp_path) in c.fix


def test_absolute_existing_executable_passes(tmp_path):
    exe = tmp_path / "bin" / "tda-dsc-signer"
    exe.parent.mkdir()
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    assert desktop(tmp_path, f"Exec={exe} %f").ok


def test_absolute_missing_or_non_executable_fails(tmp_path):
    assert not desktop(tmp_path, f"Exec={tmp_path}/nope %f").ok
    f = tmp_path / "plain"
    f.write_text("x")
    assert not desktop(tmp_path, f"Exec={f} %f").ok


def test_bare_exec_found_on_the_minimal_path_passes(tmp_path):
    assert desktop(tmp_path, "Exec=sh %f").ok  # /usr/bin/sh or /bin/sh


def test_no_desktop_entry_is_not_a_failure(tmp_path):
    assert doctor.check_desktop_entry([str(tmp_path / "none")]).ok


def test_diagnose_includes_the_desktop_entry_check(tmp_path):
    assert "desktop entry" in names(doctor.diagnose(env(tmp_path), runner(), dlopen=lambda p: None))

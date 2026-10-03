"""Real PKCS#11 against SoftHSM2 (throwaway tokens, invented PINs): the REAL C_Login path through the REAL module-host subprocess.

Everything SoftHSM-related happens in child processes (python-pkcs11 initialises a module once per process, and each test has its
own SoftHSM config). The host finds the config through HOME only: the production env allowlist is not widened.
Skips when SoftHSM2 is not installed."""

import glob
import json
import os
import shutil
import subprocess
import sys

import isolate
import pkcs11
import pytest
from conftest import der
from cryptography.hazmat.primitives import serialization

from tda_dsc_signer import safety, signing, tokens, verify
from tda_dsc_signer.hostclient import ModuleHost
from tda_dsc_signer.service import TokenService

SOFTHSM = shutil.which("softhsm2-util")
MODULES = glob.glob("/usr/lib/softhsm/libsofthsm2.so") + glob.glob("/usr/lib/*/softhsm/libsofthsm2.so")
pytestmark = pytest.mark.skipif(not (SOFTHSM and MODULES), reason="softhsm2-util / libsofthsm2.so not installed (pacman -S softhsm)")

PIN, SO_PIN, WRONG = "test-only-1234", "test-only-5678", "test-only-0000"
HERE = os.path.dirname(__file__)


class NoSource:
    def modules(self):
        return []


class Hsm:
    """A private SoftHSM config under tmp_path/home and helpers to create tokens in it."""

    def __init__(self, tmp_path, monkeypatch, pki):
        self.tmp, self.pki, self.module = tmp_path, pki, os.path.realpath(MODULES[0])
        self.home = tmp_path / "home"
        (self.home / ".config" / "softhsm2").mkdir(parents=True)
        (tmp_path / "tokens").mkdir()
        (self.home / ".config" / "softhsm2" / "softhsm2.conf").write_text(
            f"directories.tokendir = {tmp_path / 'tokens'}\nobjectstore.backend = file\nslots.removable = false\n"
        )
        monkeypatch.setenv("HOME", str(self.home))  # the ONLY way the host learns about this config
        monkeypatch.delenv("SOFTHSM2_CONF", raising=False)
        self.env = {"HOME": str(self.home), "PATH": os.environ["PATH"]}
        (tmp_path / "issuer.pem").write_bytes(
            pki["leaf_key"].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        )
        for n in ("sub", "root"):
            (tmp_path / f"{n}.der").write_bytes(der(pki[n]))

    def token(self, label, cn, pin=PIN, decoy=False, subject_serial=None):
        subprocess.run(
            [SOFTHSM, "--init-token", "--free", "--label", label, "--pin", pin, "--so-pin", SO_PIN], check=True, capture_output=True, env=self.env
        )
        spec = {
            "module": self.module,
            "label": label,
            "pin": pin,
            "cn": cn,
            "key_id_hex": "01",
            "key_label": "signer",
            "issuer_key_pem": str(self.tmp / "issuer.pem"),
            "chain_der": [str(self.tmp / "sub.der"), str(self.tmp / "root.der")],
            "decoy": decoy,
            "subject_serial": subject_serial,
            "leaf_out": str(self.tmp / f"{label}.leaf.der"),
        }
        (self.tmp / f"{label}.json").write_text(json.dumps(spec))
        subprocess.run([sys.executable, os.path.join(HERE, "softhsm_provision.py"), str(self.tmp / f"{label}.json")], check=True, env=self.env)

    def flags(self, label):
        out = subprocess.run(
            [sys.executable, os.path.join(HERE, "softhsm_flags.py"), self.module, label], check=True, capture_output=True, text=True, env=self.env
        )
        return pkcs11.TokenFlag(int(out.stdout))

    def service(self):
        src = tokens.VettedSource(tokens.GlobSource([self.module]), allow=[])  # the production vetting applies to the module
        svc = TokenService(sources=[src], fallback=NoSource(), allow_user_modules=[])
        self._svc = svc
        return svc

    def cert(self, svc, cn):
        (c,) = [c for c in svc.discover() if c.cn == cn]
        return c


@pytest.fixture
def hsm(tmp_path, monkeypatch, pki):
    h = Hsm(tmp_path, monkeypatch, pki)
    yield h
    if hasattr(h, "_svc"):
        h._svc.close()


def sign(svc, cert, src, out, *, pin=PIN, page=1, box=(50, 50, 300, 120), **kw):
    return svc.sign(str(src), cert, page=page, box=box, pin=pin, out=str(out), stamp_text="Digitally signed by %(signer)s", **kw)


def page_text(path, n):
    return subprocess.run(["pdftotext", "-f", str(n), "-l", str(n), str(path), "-"], capture_output=True, text=True, check=True).stdout


# ---- 1: page two through the real host ------------------------------------------------------------------------------------


def test_sign_page_two_through_the_real_module_host(hsm, pdf3, tmp_path):
    hsm.token("dsc-test", "SoftHSM Signer")
    svc = hsm.service()
    cert = hsm.cert(svc, "SoftHSM Signer")
    assert len(cert.chain) == 2 and cert.cert_id == "01" and cert.module == hsm.module
    out = tmp_path / "signed.pdf"
    res = sign(svc, cert, pdf3, out, page=2)
    assert isinstance(res, signing.SignResult) and isinstance(svc._hosts[hsm.module], ModuleHost)
    v = verify.verify_signed(str(out), res.field_name)
    assert v.ok and v.chain_embedded and v.signer == "SoftHSM Signer"
    assert "SoftHSM Signer" in page_text(out, 2) and "SoftHSM Signer" not in page_text(out, 1) + page_text(out, 3)
    assert "Signature is Valid" in subprocess.run(["pdfsig", str(out)], capture_output=True, text=True, check=True, env=isolate.poppler_env()).stdout


def test_host_does_not_see_softhsm_conf_from_the_environment(hsm, monkeypatch):
    hsm.token("dsc-test", "SoftHSM Signer")
    monkeypatch.setenv("SOFTHSM2_CONF", "/nonexistent/softhsm2.conf")  # would break the module if the host inherited it
    assert hsm.cert(hsm.service(), "SoftHSM Signer")


# ---- 2: two tokens, sequential signatures ---------------------------------------------------------------------------------


def test_two_tokens_sign_the_same_pdf_in_turn(hsm, pdf3, tmp_path):
    hsm.token("tok-a", "Signer A")
    hsm.token("tok-b", "Signer B")
    svc = hsm.service()
    a, b = hsm.cert(svc, "Signer A"), hsm.cert(svc, "Signer B")
    assert a.serial != b.serial and a.token == "tok-a" and b.token == "tok-b"
    ra = sign(svc, a, pdf3, tmp_path / "a.pdf", page=1, box=(50, 50, 250, 120))
    rb = sign(svc, b, tmp_path / "a.pdf", tmp_path / "ab.pdf", page=1, box=(300, 50, 500, 120))
    assert ra.field_name != rb.field_name
    v = verify.verify_signed(str(tmp_path / "ab.pdf"))
    assert v.ok and len(v.signatures) == 2
    assert [s.signer for s in v.signatures] == ["Signer A", "Signer B"]
    assert [s.field_name for s in v.signatures] == [ra.field_name, rb.field_name]
    assert all(r.state == verify.OK for s in v.signatures for r in s.rows if r.key in ("unmodified", "signature"))


# ---- 3: wrong PIN -----------------------------------------------------------------------------------------------------------


def test_wrong_pin_is_typed_not_retried_remembered_and_cleared(hsm, pdf3, tmp_path):
    hsm.token("dsc-test", "SoftHSM Signer")
    svc = hsm.service()
    cert = hsm.cert(svc, "SoftHSM Signer")
    assert not hsm.flags("dsc-test") & (pkcs11.TokenFlag.USER_PIN_COUNT_LOW | pkcs11.TokenFlag.USER_PIN_FINAL_TRY)
    with pytest.raises(pkcs11.PinIncorrect):
        sign(svc, cert, pdf3, tmp_path / "o.pdf", pin=WRONG)
    after_one = hsm.flags("dsc-test")
    # exactly ONE failed login reached the token: a retry would already show FINAL_TRY (SoftHSM allows 3 tries)
    assert after_one & pkcs11.TokenFlag.USER_PIN_COUNT_LOW and not after_one & pkcs11.TokenFlag.USER_PIN_FINAL_TRY
    with pytest.raises(safety.RecentWrongPin) as e:
        sign(svc, cert, pdf3, tmp_path / "o.pdf", pin=PIN)  # even the CORRECT pin is refused before any login
    assert e.value.count == 1 and hsm.flags("dsc-test") == after_one, "refused before any login: token state untouched"
    res = sign(svc, cert, pdf3, tmp_path / "o.pdf", pin=PIN, confirm_after_failure=True)
    assert verify.verify_signed(res.out).ok
    assert not hsm.flags("dsc-test") & pkcs11.TokenFlag.USER_PIN_COUNT_LOW, "a correct login resets SoftHSM's counter"
    res2 = sign(svc, cert, pdf3, tmp_path / "o2.pdf", pin=PIN)  # record cleared: no confirmation needed
    assert res2.out.endswith("o2.pdf")


# ---- 4: key selection by CKA_ID ----------------------------------------------------------------------------------------------


def test_key_is_selected_by_cka_id_when_two_keys_share_a_label(hsm, pdf3, tmp_path):
    hsm.token("dsc-test", "SoftHSM Signer", decoy=True)  # decoy key (id 0x99, same label "signer") is created FIRST
    svc = hsm.service()
    cert = hsm.cert(svc, "SoftHSM Signer")
    res = sign(svc, cert, pdf3, tmp_path / "o.pdf")
    v = verify.verify_signed(res.out)
    assert v.ok and v.row("signature").state == verify.OK, "signed with the key that matches the certificate"


# ---- 5: token flags and the guard -------------------------------------------------------------------------------------------
# MEASURED on SoftHSM 2.7.0: it only ever reports CKF_USER_PIN_COUNT_LOW (after the first wrong PIN). Even after 13 wrong PINs it
# never sets USER_PIN_FINAL_TRY or USER_PIN_LOCKED and the correct PIN still logs in. So the real flag -> PinState -> warning path is
# tested for COUNT_LOW here; the FINAL_TRY / LOCKED refusals are tested with a real host and real token but flags injected on the cert.


def test_count_low_flag_reaches_discovery_and_the_sign_warning(hsm, pdf3, tmp_path):
    hsm.token("dsc-test", "SoftHSM Signer")
    svc = hsm.service()
    cert = hsm.cert(svc, "SoftHSM Signer")
    assert cert.pin == safety.PinState()
    for _ in range(2):  # SoftHSM reports COUNT_LOW after the first failure and nothing more after the second
        with pytest.raises(pkcs11.PinIncorrect):
            sign(svc, cert, pdf3, tmp_path / "o.pdf", pin=WRONG, confirm_after_failure=True)
    cert = hsm.cert(svc, "SoftHSM Signer")
    assert cert.pin.count_low and not cert.pin.final_try and not cert.pin.locked
    assert hsm.flags("dsc-test") & pkcs11.TokenFlag.USER_PIN_COUNT_LOW
    res = sign(svc, cert, pdf3, tmp_path / "o.pdf", pin=PIN, confirm_after_failure=True)
    assert any("retry count is low" in w for w in res.warnings)  # finding 25 end to end


def test_locked_and_final_try_are_refused_before_any_login_on_a_real_token(hsm, pdf3, tmp_path):
    import dataclasses

    hsm.token("dsc-test", "SoftHSM Signer")
    svc = hsm.service()
    cert = hsm.cert(svc, "SoftHSM Signer")
    out = tmp_path / "o.pdf"
    clean = hsm.flags("dsc-test")
    assert not clean & pkcs11.TokenFlag.USER_PIN_COUNT_LOW
    for pin_state, exc in ((safety.PinState(locked=True), safety.TokenLocked), (safety.PinState(final_try=True), safety.FinalTryNeedsConfirm)):
        with pytest.raises(exc):  # a WRONG pin: had a login happened, the token would now report COUNT_LOW
            sign(
                svc,
                dataclasses.replace(cert, pin=pin_state),
                pdf3,
                out,
                pin=WRONG,
                confirm_after_failure=True,
                confirm_final_try=exc is safety.TokenLocked,
            )
        assert hsm.flags("dsc-test") == clean and not out.exists()
    res = sign(svc, dataclasses.replace(cert, pin=safety.PinState(final_try=True)), pdf3, out, pin=PIN, confirm_final_try=True)
    assert any("FINAL PIN TRY" in w for w in res.warnings)


def test_unloadable_module_yields_no_tokens_not_a_crash():
    svc = TokenService(sources=[], fallback=NoSource(), make_host=ModuleHost)
    h = svc._host("/nonexistent/libx.so")
    try:
        assert h.call("enumerate") == {"certs": [], "skipped": []}
    finally:
        h.kill()


def test_second_service_on_the_same_softhsm_driver_is_told_it_is_busy(hsm):
    hsm.token("dsc-test", "SoftHSM Signer")
    first = hsm.service()
    assert hsm.cert(first, "SoftHSM Signer")  # this host now owns the driver
    second = TokenService(
        sources=[tokens.VettedSource(tokens.GlobSource([hsm.module]), allow=[])],
        fallback=NoSource(),
        allow_user_modules=[],
        usb_devices=lambda: [],
    )
    try:
        assert second.discover() == []
        err = second.errors[hsm.module]
        assert type(err).__name__ == "DriverBusy" and "in use by another tda-dsc-signer" in err.args[0] and err.holder_pid == os.getpid()
        assert "usb" not in second.errors
        assert hsm.cert(first, "SoftHSM Signer")  # the first service is unaffected
    finally:
        second.close()

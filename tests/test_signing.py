import subprocess

import isolate
import pkcs11
import pytest
from asn1crypto import x509 as ax509
from conftest import der
from pkcs11 import Mechanism

from tda_dsc_signer import signing, tokens, verify


@pytest.fixture
def cert(pki):
    return tokens.TokenCert(
        "lib.so", 1, "T", "S1", "LBL", der(pki["leaf"]), "Test Signer", "Org", "2099-01-01", (der(pki["sub"]), der(pki["root"])), "0a0b"
    )


class Session:
    closed = False

    def close(self):
        self.closed = True


def run(src, cert, out, software_signer, *, fail_signer=0, login_error=None, tries=6, mechs=frozenset({Mechanism.SHA256_RSA_PKCS}), **kw):
    log = {"logins": 0, "signers": 0, "chain": None, "serial": None, "key_id": None, "use_raw": None, "confirm": None}

    def open_session(c, pin, confirm=False):
        log["logins"] += 1
        log["serial"], log["confirm"] = c.serial, confirm
        if login_error:
            raise login_error
        return Session()

    def make_signer(session, **k):
        log["signers"] += 1
        log["chain"], log["key_id"], log["use_raw"] = k["ca_chain"], k["key_id"], k["use_raw"]
        if log["signers"] <= fail_signer:
            raise pkcs11.NoSuchKey("flaky")
        return software_signer(session, **k)

    args = dict(
        page=2,
        box=(50, 50, 300, 120),
        pin="throwaway",
        out=str(out),
        open_session=open_session,
        make_signer=make_signer,
        mechanisms=lambda s: mechs,
        sleep=lambda _d: None,
        tries=tries,
    )
    try:
        return signing.sign_pdf(str(src), cert, **{**args, **kw}), log
    except Exception as e:
        return e, log


def text(path, page):
    return subprocess.run(["pdftotext", "-f", str(page), "-l", str(page), str(path), "-"], capture_output=True, text=True).stdout


def test_login_once_even_when_signing_retries(pdf3, cert, tmp_path, software_signer):
    res, log = run(pdf3, cert, tmp_path / "o.pdf", software_signer, fail_signer=2)
    assert isinstance(res, signing.SignResult)
    assert log["logins"] == 1 and log["signers"] == 3


def test_gives_up_after_n_tries_with_single_login(pdf3, cert, tmp_path, software_signer):
    err, log = run(pdf3, cert, tmp_path / "o.pdf", software_signer, fail_signer=99, tries=4)
    assert isinstance(err, pkcs11.PKCS11Error)
    assert log["logins"] == 1 and log["signers"] == 4
    assert not (tmp_path / "o.pdf").exists()


def test_wrong_pin_is_not_retried_and_signs_nothing(pdf3, cert, tmp_path, software_signer):
    err, log = run(pdf3, cert, tmp_path / "o.pdf", software_signer, login_error=pkcs11.PinIncorrect("bad"))
    assert isinstance(err, pkcs11.PinIncorrect)
    assert log["logins"] == 1 and log["signers"] == 0


def test_token_identified_by_serial_and_key_selected_by_cka_id(pdf3, cert, tmp_path, software_signer):
    _, log = run(pdf3, cert, tmp_path / "o.pdf", software_signer)
    assert log["serial"] == "S1" and log["key_id"] == bytes.fromhex("0a0b")


def test_mechanism_prefers_hash_on_token(pdf3, cert, tmp_path, software_signer):
    _, log = run(pdf3, cert, tmp_path / "o.pdf", software_signer, mechs={Mechanism.SHA256_RSA_PKCS, Mechanism.RSA_PKCS})
    assert log["use_raw"] is False


def test_mechanism_falls_back_to_raw_rsa(pdf3, cert, tmp_path, software_signer):
    _, log = run(pdf3, cert, tmp_path / "o.pdf", software_signer, mechs={Mechanism.RSA_PKCS})
    assert log["use_raw"] is True


def test_no_usable_mechanism_fails_without_signing(pdf3, cert, tmp_path, software_signer):
    err, log = run(pdf3, cert, tmp_path / "o.pdf", software_signer, mechs={Mechanism.RSA_PKCS_PSS})
    assert isinstance(err, signing.NoSupportedMechanism) and log["signers"] == 0 and log["logins"] == 1


def test_final_try_confirmation_is_forwarded(pdf3, cert, tmp_path, software_signer):
    _, log = run(pdf3, cert, tmp_path / "o.pdf", software_signer, confirm_final_try=True)
    assert log["confirm"] is True


def test_mca_profile_warns_over_attachment_limit_general_does_not(pdf3, cert, tmp_path, software_signer, monkeypatch):
    monkeypatch.setattr(signing, "MCA_ATTACHMENT_LIMIT", 100)
    mca, _ = run(pdf3, cert, tmp_path / "m.pdf", software_signer, profile="mca")
    gen, _ = run(pdf3, cert, tmp_path / "g.pdf", software_signer, profile="general")
    assert mca.warnings and "2 MB" in mca.warnings[0] and not gen.warnings


def test_unknown_profile_rejected(pdf3, cert, tmp_path, software_signer):
    err, log = run(pdf3, cert, tmp_path / "o.pdf", software_signer, profile="nope")
    assert isinstance(err, ValueError) and log["logins"] == 0


def test_timestamper_gives_pades_b_t(pdf3, cert, tmp_path, software_signer, pki):
    from asn1crypto import keys as akeys
    from conftest import make_cert
    from cryptography.hazmat.primitives import serialization
    from pyhanko.sign.timestamps import DummyTimeStamper
    from pyhanko_certvalidator.registry import SimpleCertificateStore

    tsa, tk = make_cert("Test TSA", pki["sub"], pki["leaf_key"], ku=None)
    ts = DummyTimeStamper(
        tsa_cert=ax509.Certificate.load(der(tsa)),
        tsa_key=akeys.PrivateKeyInfo.load(
            tk.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        ),
        certs_to_embed=SimpleCertificateStore(),
    )
    out = tmp_path / "ts.pdf"
    res, _ = run(pdf3, cert, out, software_signer, timestamper=ts)
    assert isinstance(res, signing.SignResult)
    from pyhanko.pdf_utils.reader import PdfFileReader

    with open(out, "rb") as f:
        sig = PdfFileReader(f).embedded_signatures[-1]
        unsigned = sig.signer_info["unsigned_attrs"]
        assert "signature_time_stamp_token" in [a["type"].native for a in unsigned]


def test_stamp_only_on_requested_page_and_pdf_valid(pdf3, cert, tmp_path, software_signer):
    out = tmp_path / "o.pdf"
    res, _ = run(pdf3, cert, out, software_signer, page=2)
    assert "Digitally signed by" in text(out, 2) and "Test Signer" in text(out, 2)
    assert "Digitally signed" not in text(out, 1) and "Digitally signed" not in text(out, 3)
    v = verify.verify_signed(str(out), res.field_name)
    assert v.ok and v.row("unmodified").state == "ok" and v.row("signature").state == "ok" and v.row("issuer").state == "info"
    pdfsig = subprocess.run(["pdfsig", str(out)], capture_output=True, text=True, env=isolate.poppler_env()).stdout
    assert "Signature is Valid" in pdfsig


def test_negative_page_means_last(pdf3, cert, tmp_path, software_signer):
    out = tmp_path / "o.pdf"
    run(pdf3, cert, out, software_signer, page=-1)
    assert "Digitally signed" in text(out, 3) and "Digitally signed" not in text(out, 2)


def test_chain_is_passed_and_embedded(pdf3, cert, tmp_path, software_signer):
    out = tmp_path / "o.pdf"
    res, log = run(pdf3, cert, out, software_signer)
    assert len(log["chain"]) == 2
    assert verify.verify_signed(str(out), res.field_name).chain_embedded


def test_no_chain_reported_when_token_has_none(pdf3, cert, tmp_path, software_signer):
    bare = tokens.TokenCert(*[getattr(cert, f) for f in ("module", "slot", "token", "serial", "label", "der", "cn", "org", "end")])
    out = tmp_path / "o.pdf"
    res, _ = run(pdf3, bare, out, software_signer)
    assert not verify.verify_signed(str(out), res.field_name).chain_embedded


def test_strict_to_lenient_fallback_on_sloppy_xref(pdf_sloppy, cert, tmp_path, software_signer):
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.pdf_utils.misc import PdfReadError

    with open(pdf_sloppy, "rb") as f, pytest.raises(PdfReadError):
        IncrementalPdfFileWriter(f, strict=True)  # precondition: strict really rejects it
    out = tmp_path / "o.pdf"
    res, _ = run(pdf_sloppy, cert, out, software_signer, page=3)
    assert isinstance(res, signing.SignResult)
    assert verify.verify_signed(str(out)).ok
    # the original objects must survive: all three pages still render their text, and poppler accepts the signature
    assert all(f"Body of page {b}" in text(out, n) for n, b in ((1, 1), (2, 1), (3, 2)))  # a.pdf + b.pdf
    assert "Digitally signed" in text(out, 3)
    assert "Signature is Valid" in subprocess.run(["pdfsig", str(out)], capture_output=True, text=True, env=isolate.poppler_env()).stdout


def test_output_equal_to_input_refused_and_input_untouched(pdf3, cert, tmp_path, software_signer):
    before = pdf3.read_bytes()
    for alias in (pdf3, tmp_path / "." / "doc.pdf"):
        err, log = run(pdf3, cert, alias, software_signer)
        assert isinstance(err, ValueError) and log["logins"] == 0
    assert pdf3.read_bytes() == before


def test_default_output_name():
    assert signing.default_output("/a/b/x.PDF") == "/a/b/x-signed.pdf"
    assert signing.default_output("/a/b/x") == "/a/b/x-signed.pdf"


def test_key_lookup_falls_back_from_cka_id_to_label(pdf3, cert, tmp_path, software_signer):
    calls = []

    def picky(session, **k):
        calls.append(k["key_id"])
        if k["key_id"] is not None:
            raise pkcs11.NoSuchKey("no key with that id")
        return software_signer(session, **k)

    out = tmp_path / "o.pdf"
    res = signing.sign_pdf(
        str(pdf3),
        cert,
        page=1,
        box=(50, 50, 300, 120),
        pin="x",
        out=str(out),
        open_session=lambda c, p, f=False: Session(),
        make_signer=picky,
        mechanisms=lambda s: {Mechanism.SHA256_RSA_PKCS},
        sleep=lambda _d: None,
    )
    assert isinstance(res, signing.SignResult) and calls == [bytes.fromhex("0a0b"), None]

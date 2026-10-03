"""Findings 10, 11, 12, 14, 21(verify part), 25: preflight before login, overwrite policy, multi-signature verification."""

import os
from types import SimpleNamespace

import pytest
from conftest import der
from test_signing import Session, run  # the signing harness: fake open_session / signer that counts logins

from tda_dsc_signer import signing, tokens, verify
from tda_dsc_signer.safety import PinState


@pytest.fixture
def cert(pki):
    return tokens.TokenCert(
        "lib.so", 1, "T", "S1", "LBL", der(pki["leaf"]), "Test Signer", "Org", "2099-01-01", (der(pki["sub"]), der(pki["root"])), "0a0b"
    )


# ---- 11: nothing that can fail without the token may happen after the login ---------------------------------------------


def test_bad_page_fails_with_no_login(pdf3, cert, tmp_path, software_signer):
    for page in (9, -9, 4):
        err, log = run(pdf3, cert, tmp_path / "o.pdf", software_signer, page=page)
        assert isinstance(err, ValueError) and "does not exist" in str(err) and "3 page" in str(err)
        assert log["logins"] == 0
    err, log = run(pdf3, cert, tmp_path / "o.pdf", software_signer, page=0)
    assert isinstance(err, ValueError) and log["logins"] == 0


def test_unwritable_output_dir_fails_with_no_login(pdf3, cert, tmp_path, software_signer):
    ro = tmp_path / "ro"
    ro.mkdir()
    ro.chmod(0o500)
    try:
        err, log = run(pdf3, cert, ro / "o.pdf", software_signer)
    finally:
        ro.chmod(0o700)
    assert isinstance(err, PermissionError) and log["logins"] == 0
    err, log = run(pdf3, cert, tmp_path / "missing" / "o.pdf", software_signer)
    assert isinstance(err, OSError) and log["logins"] == 0
    assert list(tmp_path.glob(".dsc-*")) == []


def test_unreadable_pdf_fails_with_no_login(cert, tmp_path, software_signer):
    junk = tmp_path / "junk.pdf"
    junk.write_bytes(b"this is not a pdf")
    err, log = run(junk, cert, tmp_path / "o.pdf", software_signer)
    assert isinstance(err, ValueError) and log["logins"] == 0


def test_final_try_refused_before_login_via_cert_flags(pdf3, cert, tmp_path, software_signer):
    final = tokens.TokenCert(
        *[getattr(cert, f) for f in ("module", "slot", "token", "serial", "label", "der", "cn", "org", "end")], pin=PinState(final_try=True)
    )
    err, log = run(pdf3, final, tmp_path / "o.pdf", software_signer)
    assert type(err).__name__ == "FinalTryNeedsConfirm" and log["logins"] == 0


# ---- 14: overwrite ------------------------------------------------------------------------------------------------------


def test_existing_output_refused_without_overwrite_and_untouched(pdf3, cert, tmp_path, software_signer):
    out = tmp_path / "o.pdf"
    out.write_bytes(b"precious")
    err, log = run(pdf3, cert, out, software_signer)
    assert isinstance(err, signing.OutputExists) and isinstance(err, FileExistsError) and log["logins"] == 0
    assert out.read_bytes() == b"precious"


def test_overwrite_true_replaces_the_existing_output(pdf3, cert, tmp_path, software_signer):
    out = tmp_path / "o.pdf"
    out.write_bytes(b"old")
    res, log = run(pdf3, cert, out, software_signer, overwrite=True)
    assert isinstance(res, signing.SignResult) and out.read_bytes().startswith(b"%PDF") and log["logins"] == 1


def test_file_appearing_after_the_preflight_is_not_clobbered(pdf3, cert, tmp_path, software_signer):
    out = tmp_path / "o.pdf"

    def racing(session, **k):
        out.write_bytes(b"created meanwhile")
        return software_signer(session, **k)

    err = None
    try:
        signing.sign_pdf(
            str(pdf3), cert, page=1, box=(1, 2, 3, 4), pin="x", out=str(out),
            open_session=lambda c, p, f=False: Session(), make_signer=racing,
            mechanisms=lambda s: {signing.Mechanism.SHA256_RSA_PKCS}, sleep=lambda _d: None,
        )  # fmt: skip
    except signing.OutputExists as e:
        err = e
    assert err is not None and out.read_bytes() == b"created meanwhile"
    assert list(tmp_path.glob(".dsc-*")) == []


def test_default_error_is_typed_over_the_wire():
    from tda_dsc_signer import errors

    e = errors.from_wire(errors.to_wire(signing.OutputExists("exists")))
    assert isinstance(e, signing.OutputExists)


# ---- 12 / 25: warnings --------------------------------------------------------------------------------------------------


def test_lenient_parse_is_reported_as_warning(pdf_sloppy, cert, tmp_path, software_signer):
    res, _ = run(pdf_sloppy, cert, tmp_path / "o.pdf", software_signer, page=3)
    assert any("leniently" in w for w in res.warnings)


def test_low_pin_count_warning_is_returned_in_sign_result(pdf3, cert, tmp_path, software_signer):
    low = tokens.TokenCert(
        *[getattr(cert, f) for f in ("module", "slot", "token", "serial", "label", "der", "cn", "org", "end")], pin=PinState(count_low=True)
    )
    res, _ = run(pdf3, low, tmp_path / "o.pdf", software_signer)
    assert any("retry count is low" in w for w in res.warnings)


def test_output_mode_follows_umask_via_fchmod(pdf3, cert, tmp_path, software_signer):
    old = os.umask(0o027)
    try:
        run(pdf3, cert, tmp_path / "o.pdf", software_signer)
    finally:
        os.umask(old)
    assert oct((tmp_path / "o.pdf").stat().st_mode & 0o777) == oct(0o640)


# ---- 10: every signature is evaluated -------------------------------------------------------------------------------------


def sign_into(src, out, cert, software_signer, box):
    res, _ = run(src, cert, out, software_signer, page=1, box=box)
    assert isinstance(res, signing.SignResult), res
    return res


def test_two_valid_signatures_are_both_reported(pdf3, cert, tmp_path, software_signer):
    sign_into(pdf3, tmp_path / "1.pdf", cert, software_signer, (50, 50, 200, 100))
    sign_into(tmp_path / "1.pdf", tmp_path / "2.pdf", cert, software_signer, (250, 50, 400, 100))
    v = verify.verify_signed(str(tmp_path / "2.pdf"))
    assert v.ok and len(v.signatures) == 2 and v.detail.startswith("2 signatures")
    assert all(r.state == verify.OK for s in v.signatures for r in s.rows if r.key in ("unmodified", "signature"))
    assert [r.key for r in v.rows] == ["unmodified", "signature", "issuer", "revocation"] and v.signatures[0].signer == "Test Signer"


def test_tampered_earlier_signature_with_valid_later_one_is_not_ok(pdf3, cert, tmp_path, software_signer):
    first = tmp_path / "1.pdf"
    sign_into(pdf3, first, cert, software_signer, (50, 50, 200, 100))
    data = bytearray(first.read_bytes())
    data[100] ^= 0x01  # inside the first signature's range, BEFORE the second signature covers the (now tampered) file
    first.write_bytes(data)
    sign_into(first, tmp_path / "2.pdf", cert, software_signer, (250, 50, 400, 100))
    v = verify.verify_signed(str(tmp_path / "2.pdf"))
    early, late = v.signatures
    assert late.rows[0].state == verify.OK and late.rows[1].state == verify.OK, "the later signature is fine on its own"
    assert early.rows[0].state == verify.FAIL
    assert not v.ok and v.row("unmodified").state == verify.FAIL and "MODIFIED" in v.detail
    assert early.field_name in v.row("unmodified").detail  # the worst row names the offending signature


def test_tampered_later_signature_with_valid_earlier_one_is_not_ok(pdf3, cert, tmp_path, software_signer):
    sign_into(pdf3, tmp_path / "1.pdf", cert, software_signer, (50, 50, 200, 100))
    sign_into(tmp_path / "1.pdf", tmp_path / "2.pdf", cert, software_signer, (250, 50, 400, 100))
    with open(tmp_path / "2.pdf", "ab") as f:
        f.write(b"\n%appended after the last signature\n")
    v = verify.verify_signed(str(tmp_path / "2.pdf"))
    assert not v.ok and v.signatures[1].rows[0].state == verify.FAIL


def test_field_name_only_selects_the_reported_signer(pdf3, cert, tmp_path, software_signer):
    r1 = sign_into(pdf3, tmp_path / "1.pdf", cert, software_signer, (50, 50, 200, 100))
    sign_into(tmp_path / "1.pdf", tmp_path / "2.pdf", cert, software_signer, (250, 50, 400, 100))
    assert verify.verify_signed(str(tmp_path / "2.pdf"), r1.field_name).ok
    assert not verify.verify_signed(str(tmp_path / "2.pdf"), "NoSuchField").ok


# ---- 21: revoked ---------------------------------------------------------------------------------------------------------


def test_revoked_certificate_fails_the_result_and_shows_in_the_summary(pdf3, cert, tmp_path, software_signer, monkeypatch):
    res, _ = run(pdf3, cert, tmp_path / "o.pdf", software_signer)
    real = verify.validate_pdf_signature

    def revoked(sig, vc):
        st = real(sig, vc)
        return SimpleNamespace(
            intact=st.intact, valid=st.valid, coverage=st.coverage, modification_level=st.modification_level, trusted=st.trusted,
            revoked=True, signing_cert=st.signing_cert,
        )  # fmt: skip

    monkeypatch.setattr(verify, "validate_pdf_signature", revoked)
    v = verify.verify_signed(str(tmp_path / "o.pdf"))
    assert not v.ok and v.row("revocation").state == verify.FAIL and "REVOKED" in v.detail and "REVOKED" in v.row("revocation").detail


# ---- unique signature field names ---------------------------------------------------------------------------------------


def field_names(path):
    from pyhanko.pdf_utils.reader import PdfFileReader

    with open(path, "rb") as f:
        return [s.field_name for s in PdfFileReader(f).embedded_signatures]


def test_back_to_back_signatures_get_distinct_fields_and_both_verify(pdf3, cert, tmp_path, software_signer):
    r1, _ = run(pdf3, cert, tmp_path / "1.pdf", software_signer, box=(50, 50, 200, 100))
    r2, _ = run(tmp_path / "1.pdf", cert, tmp_path / "2.pdf", software_signer, box=(250, 50, 400, 100))
    r3, _ = run(tmp_path / "2.pdf", cert, tmp_path / "3.pdf", software_signer, box=(50, 150, 200, 200))
    assert len({r1.field_name, r2.field_name, r3.field_name}) == 3
    assert field_names(tmp_path / "3.pdf") == [r1.field_name, r2.field_name, r3.field_name]
    v = verify.verify_signed(str(tmp_path / "3.pdf"))
    assert v.ok and len(v.signatures) == 3
    print(field_names(tmp_path / "3.pdf"))


def test_name_clash_with_an_existing_field_is_avoided(pdf3, cert, tmp_path, software_signer, monkeypatch):
    r1, _ = run(pdf3, cert, tmp_path / "1.pdf", software_signer, box=(50, 50, 200, 100))
    monkeypatch.setattr(signing.time, "time_ns", lambda: int(r1.field_name.removeprefix("Sig-")))  # next candidate == existing name
    r2, _ = run(tmp_path / "1.pdf", cert, tmp_path / "2.pdf", software_signer, box=(250, 50, 400, 100))
    assert isinstance(r2, signing.SignResult) and r2.field_name != r1.field_name
    assert verify.verify_signed(str(tmp_path / "2.pdf")).ok and len(field_names(tmp_path / "2.pdf")) == 2


def test_unique_field_name_skips_taken_names(monkeypatch):
    monkeypatch.setattr(signing.time, "time_ns", lambda: 5)
    assert signing.unique_field_name({"Sig-5"}) == "Sig-5-2"
    assert signing.unique_field_name({"Sig-5", "Sig-5-2"}) == "Sig-5-3"
    assert signing.unique_field_name(set()) == "Sig-5"


LIBREOFFICE = "/tmp/claude-1000/-home-tda/931ef579-73eb-4d97-ac6e-7ae8ef0f4e0a/scratchpad/h-in.pdf"


@pytest.mark.skipif(not os.path.exists(LIBREOFFICE), reason="LibreOffice-signed receipt copy not present")
def test_libreoffice_signed_file_with_signature1_field_is_handled(cert, tmp_path, software_signer):
    names = field_names(LIBREOFFICE)
    assert "Signature1" in names
    res, log = run(LIBREOFFICE, cert, tmp_path / "o.pdf", software_signer, page=1)
    assert isinstance(res, signing.SignResult), res
    assert res.field_name not in names and log["logins"] == 1
    assert field_names(tmp_path / "o.pdf") == [*names, res.field_name]
    print(names, "->", field_names(tmp_path / "o.pdf"))


def test_existing_non_signature_field_name_is_also_avoided(pdf3, cert, tmp_path, software_signer, monkeypatch):
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import fields

    with open(pdf3, "rb") as f:
        w = IncrementalPdfFileWriter(f)
        fields.append_signature_field(w, fields.SigFieldSpec("Sig-7", on_page=0, box=(1, 1, 50, 50)))  # an UNSIGNED field called Sig-7
        with open(tmp_path / "pre.pdf", "wb") as o:
            w.write(o)
    monkeypatch.setattr(signing.time, "time_ns", lambda: 7)
    res, _ = run(tmp_path / "pre.pdf", cert, tmp_path / "o.pdf", software_signer, box=(60, 60, 200, 100))
    assert isinstance(res, signing.SignResult) and res.field_name == "Sig-7-2"

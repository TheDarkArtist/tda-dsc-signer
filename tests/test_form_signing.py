import dataclasses
import os
import re
import shutil
import subprocess
from pathlib import Path

import isolate
import pytest
from asn1crypto import keys as akeys
from conftest import INC9_FIELDS, der, ku, make_cert, make_form_pdf, make_pdf
from cryptography.hazmat.primitives import serialization
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields as sigfields
from pyhanko.sign import signers
from pyhanko_certvalidator.registry import SimpleCertificateStore

from tda_dsc_signer import errors, forms, hostclient, pan, signing, tokens, verify
from tda_dsc_signer.errors import PanMismatch

P1, P2 = "ABCDE1234F", "PQRST5678K"
F1, F2 = INC9_FIELDS[0][0], INC9_FIELDS[1][0]
REAL = os.environ.get("DSC_TEST_INC9")  # optional real form, see test_forms.py


class Session:
    def close(self):
        pass


@pytest.fixture
def holders(pki):
    """Two token certs whose subject serialNumber = sha256(PAN), plus their software keys."""
    out = {}
    for pan_, cn in ((P1, "First Director"), (P2, "Second Director")):
        leaf, key = make_cert(cn, pki["sub"], pki["leaf_key"], ku=ku(digital_signature=True, content_commitment=True), serial=pan.pan_hash(pan_))
        tc = tokens.TokenCert("m", 0, cn, "S" + pan_, "l", der(leaf), cn, "O", "2099-01-01", (der(pki["sub"]), der(pki["root"])), "01")
        out[pan_] = (tc, key)
    return out


@pytest.fixture
def run(holders):
    log = {"logins": 0}

    def open_session(c, pin, confirm=False):
        log["logins"] += 1
        return Session()

    def make_signer(session, signing_cert, ca_chain, **_kw):
        key = next(k for tc, k in holders.values() if tc.der == signing_cert.dump())
        pk = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        store = SimpleCertificateStore()
        store.register_multiple(ca_chain or [])
        return signers.SimpleSigner(signing_cert=signing_cert, signing_key=akeys.PrivateKeyInfo.load(pk), cert_registry=store, embed_roots=True)

    def go(src, who, out, **kw):
        return signing.sign_pdf(
            str(src),
            holders[who][0],
            **{
                **dict(
                    page=1,
                    box=(0, 0, 1, 1),
                    pin="x",
                    out=str(out),
                    open_session=open_session,
                    make_signer=make_signer,
                    mechanisms=lambda s: {signing.Mechanism.SHA256_RSA_PKCS},
                    sleep=lambda _d: None,
                ),
                **kw,
            },
        )

    go.log = log
    return go


@pytest.fixture
def form(tmp_path):
    return make_form_pdf(tmp_path / "form.pdf")


def state(path):
    return {f.name: f.signed for f in forms.find_signature_fields(path)}


def widget(path, name):
    r = PdfFileReader(open(path, "rb"))
    return next(dict(ref.get_object()) for n, _v, ref in sigfields.enumerate_sig_fields(r, filled_status=None) if n == name)


def subfilter(path):
    (sig,) = PdfFileReader(open(path, "rb")).embedded_signatures
    return str(sig.sig_object["/SubFilter"])


def pdfsig(path):
    return subprocess.run(["pdfsig", str(path)], capture_output=True, text=True, check=True, env=isolate.poppler_env()).stdout


def test_sign_into_field_leaves_the_other_untouched(form, run, tmp_path):
    out = tmp_path / "o.pdf"
    before = widget(form, F1)
    res = run(form, P2, out, field=F2)
    assert res.field_name == F2 and run.log["logins"] == 1
    assert state(out) == {F1: False, F2: True}
    assert widget(out, F1) == before  # geometry, flags, no value: untouched
    assert [float(x) for x in widget(out, F2)["/Rect"]] == pytest.approx(INC9_FIELDS[1][2])
    v = verify.verify_signed(str(out), F2)
    assert v.ok and [(f.name, f.signer, f.pan_match) for f in v.fields] == [(F1, "", None), (F2, "Second Director", True)]
    text = pdfsig(out)
    assert text.count("not signed") == 1 and "Signature is Valid" in text


def test_both_fields_in_sequence(form, run, tmp_path):
    mid, out = tmp_path / "m.pdf", tmp_path / "o.pdf"
    run(form, P1, mid, field=F1)
    run(mid, P2, out, field=F2)
    assert state(out) == {F1: True, F2: True}
    v = verify.verify_signed(str(out))
    assert v.ok and [f.pan_match for f in v.fields] == [True, True] and "not signed" not in pdfsig(out)


def test_pan_mismatch_before_login(form, run, tmp_path):
    with pytest.raises(PanMismatch) as e:
        run(form, P1, tmp_path / "o.pdf", field=F2)
    assert run.log["logins"] == 0 and not (tmp_path / "o.pdf").exists()
    assert (e.value.field, e.value.pan_masked, e.value.cn) == (F2, "PQRS…5678K", "First Director")
    assert "must be signed by the holder of that PAN" in e.value.args[0] and "First Director" in e.value.args[0]


def test_allow_pan_mismatch_overrides(form, run, tmp_path):
    out = tmp_path / "o.pdf"
    run(form, P1, out, field=F2, allow_pan_mismatch=True)
    assert state(out)[F2] and verify.verify_signed(str(out), F2).fields[1].pan_match is False


def test_cert_without_serial_is_allowed_with_warning(form, run, holders, tmp_path, pki):
    leaf, key = make_cert("No Serial", pki["sub"], pki["leaf_key"], ku=ku(digital_signature=True))
    tc = tokens.TokenCert("m", 0, "T", "SX", "l", der(leaf), "No Serial", "O", "2099-01-01", (der(pki["sub"]),), "01")
    holders["X"] = (tc, key)
    res = run(form, "X", tmp_path / "o.pdf", field=F1)
    assert any("no serialNumber" in w for w in res.warnings)


def test_field_already_signed_and_missing(form, run, tmp_path):
    mid = tmp_path / "m.pdf"
    run(form, P2, mid, field=F2)
    logins = run.log["logins"]
    with pytest.raises(signing.FieldAlreadySigned):
        run(mid, P2, tmp_path / "o.pdf", field=F2)
    with pytest.raises(ValueError, match="no signature field named"):
        run(mid, P2, tmp_path / "o2.pdf", field="nope")
    assert run.log["logins"] == logins


def seeded(tmp_path, **kw):
    seed = sigfields.SigSeedValueSpec(**kw)
    return make_form_pdf(tmp_path / "s.pdf", ((F2, 2, (453, 177, 503, 197)),), seeds={F2: seed})


def test_seed_value_refusal_before_login(run, tmp_path):
    src = seeded(tmp_path, subfilters=[sigfields.SigSeedSubFilter.ETSI_RFC3161], flags=sigfields.SigSeedValFlags.SUBFILTER)
    with pytest.raises(ValueError, match="requires SubFilter"):
        run(src, P2, tmp_path / "o.pdf", field=F2)
    src = seeded(tmp_path, digest_methods=["sha512"], flags=sigfields.SigSeedValFlags.DIGEST_METHOD)
    with pytest.raises(ValueError, match="requires digest"):
        run(src, P2, tmp_path / "o.pdf", field=F2)
    assert run.log["logins"] == 0


def test_seed_subfilter_steers_auto_but_not_explicit(run, tmp_path):
    src = seeded(tmp_path, subfilters=[sigfields.SigSeedSubFilter.PADES], flags=sigfields.SigSeedValFlags.SUBFILTER)
    run(src, P2, tmp_path / "o.pdf", field=F2)
    assert subfilter(tmp_path / "o.pdf") == "/ETSI.CAdES.detached"
    with pytest.raises(ValueError, match="requires SubFilter"):
        run(src, P2, tmp_path / "o2.pdf", field=F2, signature_format="adbe")


@pytest.mark.parametrize(
    ("fmt", "field", "expected"),
    [
        ("adbe", True, "/adbe.pkcs7.detached"),
        ("pades", True, "/ETSI.CAdES.detached"),
        ("auto", True, "/adbe.pkcs7.detached"),
        (None, True, "/adbe.pkcs7.detached"),
        ("auto", False, "/ETSI.CAdES.detached"),
        ("adbe", False, "/adbe.pkcs7.detached"),
    ],
)
def test_subfilter(form, run, tmp_path, fmt, field, expected):
    out = tmp_path / "o.pdf"
    run(form, P2, out, signature_format=fmt, **({"field": F2} if field else {"page": 1}))
    assert subfilter(out) == expected


def test_bad_format(form, run, tmp_path):
    with pytest.raises(ValueError, match="signature format"):
        run(form, P2, tmp_path / "o.pdf", signature_format="x")


# ---- stamp fits the field --------------------------------------------------------------------------------------------------


def words(path, page):
    out = subprocess.run(["pdftotext", "-bbox", "-f", str(page), "-l", str(page), str(path), "-"], capture_output=True, text=True, check=True).stdout
    h = float(re.search(r'<page width="[\d.]+" height="([\d.]+)"', out).group(1))
    return [
        (m[4], float(m[0]), h - float(m[3]), float(m[2]), h - float(m[1]))
        for m in re.findall(r'xMin="([\d.]+)" yMin="([\d.]+)" xMax="([\d.]+)" yMax="([\d.]+)">([^<]*)<', out)
    ], h


def assert_inside(path, page, rect, names):
    ws, _h = words(path, page)
    mine = [w for w in ws if w[0] and set(w[0].split()) <= names]  # pdftotext may glue a line into one "word"
    assert any("Digitally" in w[0] for w in mine), ws
    for t, x1, y1, x2, y2 in mine:
        assert rect[0] - 0.5 <= x1 and x2 <= rect[2] + 0.5 and rect[1] - 0.5 <= y1 and y2 <= rect[3] + 0.5, (t, x1, y1, x2, y2, rect)


def test_stamp_fits_50x20_synthetic(form, run, tmp_path):
    out = tmp_path / "o.pdf"
    run(form, P2, out, field=F2, stamp_text="ignored")
    assert_inside(out, 3, INC9_FIELDS[1][2], {"Digitally", "signed", "by", "Second", "Director"})


def test_stamp_fits_real_inc9(run, tmp_path):
    if not REAL or not os.path.exists(REAL):
        pytest.skip("DSC_TEST_INC9 not set")
    src = shutil.copy(REAL, tmp_path / "inc9.pdf")
    out = tmp_path / "o.pdf"
    run(src, P2, out, field=F2)
    f2 = forms.find_signature_fields(out)[1]
    assert f2.signed and not forms.find_signature_fields(out)[0].signed
    assert_inside(out, f2.page, f2.rect, {"Digitally", "signed", "by", "Second", "Director"})


def test_large_rect_keeps_the_normal_stamp(tmp_path, run):
    src = make_form_pdf(tmp_path / "big.pdf", ((F2, 1, (50, 600, 350, 700)),))
    out = tmp_path / "o.pdf"
    run(src, P2, out, field=F2)
    ws, _ = words(out, 1)
    assert any(w[0].startswith("Date:") for w in ws)


def test_box_signing_unchanged(tmp_path, run):
    src = make_pdf(tmp_path / "p.pdf")
    out = tmp_path / "o.pdf"
    res = run(src, P2, out)
    assert res.field_name.startswith("Sig-") and subfilter(out) == "/ETSI.CAdES.detached"


# ---- wire round trip -------------------------------------------------------------------------------------------------------


def test_pan_mismatch_wire_roundtrip():
    e = PanMismatch("msg", F2, "PQRS…5678K", "Someone")
    back = errors.from_wire(errors.to_wire(e))
    assert type(back) is PanMismatch and back.args[0] == "msg" and (back.field, back.pan_masked, back.cn) == (F2, "PQRS…5678K", "Someone")
    again = errors.from_wire(errors.to_wire(signing.FieldAlreadySigned("x")))
    assert type(again) is signing.FieldAlreadySigned


def test_hostclient_importable():
    assert hostclient  # the typed error crosses via errors.KNOWN; the real host round trip is in test_cli_forms


# ---- bundled stamp font ----------------------------------------------------------------------------------------------------


def test_bundled_font_and_license_ship_together():
    from fontTools.ttLib import TTFont

    from tda_dsc_signer import stamp

    p = Path(stamp.font_path())
    assert p.is_file() and TTFont(p)["head"].unitsPerEm and (p.parent / "OFL.txt").read_text().count("SIL OPEN FONT LICENSE")


def test_stamp_name_replaces_only_missing_glyphs():
    from tda_dsc_signer.stamp import stamp_name

    assert stamp_name("José Muñoz Müller Иван") == ("José Muñoz Müller Иван", False)
    text, changed = stamp_name("राम Kumar")
    assert changed and text.endswith(" Kumar") and set(text[:-6]) == {"?"}
    assert stamp_name("王 Wei") == ("? Wei", True)


def test_stamp_fits_without_fontconfig(form, run, tmp_path, monkeypatch):
    real = subprocess.run

    def no_fc(cmd, *a, **k):
        if cmd and cmd[0] == "fc-match":
            raise FileNotFoundError("fc-match")
        return real(cmd, *a, **k)

    monkeypatch.setattr(subprocess, "run", no_fc)
    monkeypatch.setenv("PATH", "/nonexistent")
    out = tmp_path / "o.pdf"
    run(form, P2, out, field=F2)
    monkeypatch.undo()
    assert_inside(out, 3, INC9_FIELDS[1][2], {"Digitally", "signed", "by", "Second", "Director"})


def test_devanagari_cn_signs_with_question_marks_and_warning(form, run, holders, tmp_path):
    tc, key = holders[P2]
    holders[P2] = (dataclasses.replace(tc, cn="राम Director"), key)
    out = tmp_path / "o.pdf"
    res = run(form, P2, out, field=F2)
    assert any("'?'" in w for w in res.warnings)
    assert any("Director" in w[0] for w in words(out, 3)[0])


def test_missing_bundled_font_falls_back_and_still_signs(form, run, tmp_path, monkeypatch):
    from tda_dsc_signer import stamp

    monkeypatch.setattr(stamp, "FONT_FILE", tmp_path / "nope.ttf")
    stamp._font.cache_clear()
    try:
        assert stamp.font_path() is None
        out = tmp_path / "o.pdf"
        run(form, P2, out, field=F2)
        assert state(out)[F2]
        assert stamp.make_field_style("x", "Second Director", (0, 0, 50, 20)) is not None
    finally:
        monkeypatch.undo()
        stamp._font.cache_clear()

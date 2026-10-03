import os
import shutil

import pytest
from conftest import INC9_FIELDS, make_form_pdf

from tda_dsc_signer import forms
from tda_dsc_signer.forms import FormField

REAL = os.environ.get("DSC_TEST_INC9")  # optional: a real two-field MCA form (INC-9 layout); never committed


def test_synthetic_form_fields(tmp_path):
    fs = forms.find_signature_fields(make_form_pdf(tmp_path / "f.pdf"))
    assert [f.name for f in fs] == [n for n, _, _ in INC9_FIELDS]
    assert [f.page for f in fs] == [2, 3]
    assert [f.pan for f in fs] == ["ABCDE1234F", "PQRST5678K"]
    assert all(not f.signed and f.seed == {} for f in fs)
    assert fs[0].rect == pytest.approx(INC9_FIELDS[0][2])


def test_pan_masked_and_none_safe():
    f = FormField("x", 1, (0, 0, 1, 1), False, False, "ABCDE1234F", {})
    assert f.pan_masked == "ABCD…1234F"
    assert FormField("x", 1, (0, 0, 1, 1), False, False, None, {}).pan_masked is None


def test_pan_regex_rejects_non_pans(tmp_path):
    fs = forms.find_signature_fields(make_form_pdf(tmp_path / "f.pdf", (("sig_abcde1234f", 1, (0, 0, 50, 20)), ("Signature1", 1, (0, 60, 50, 80)))))
    assert [f.pan for f in fs] == [None, None]  # lowercase / no PAN suffix


def test_seed_summary(tmp_path):
    from pyhanko.sign import fields

    seed = fields.SigSeedValueSpec(
        subfilters=[fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED], flags=fields.SigSeedValFlags.SUBFILTER, digest_methods=["sha256"]
    )
    (f,) = forms.find_signature_fields(make_form_pdf(tmp_path / "f.pdf", (("s_ABCDE1234F", 1, (0, 0, 50, 20)),), seeds={"s_ABCDE1234F": seed}))
    assert f.seed["SubFilter"] == ["/adbe.pkcs7.detached"] and f.seed["Flags"] == 2 and "DigestMethod" in f.seed


@pytest.fixture
def inc9(tmp_path):
    if not REAL or not os.path.exists(REAL):
        pytest.skip("DSC_TEST_INC9 not set")
    return shutil.copy(REAL, tmp_path / "inc9.pdf")


def test_real_inc9(inc9):
    f1, f2 = forms.find_signature_fields(inc9)
    assert (f1.name, f1.pan, f2.name, f2.pan) == ("sigfield1_ABCDE1234F", "ABCDE1234F", "sigfield2_PQRST5678K", "PQRST5678K")
    assert (f1.page, f2.page) == (7, 8)  # widgets sit on pages 7 and 8 of 10 (their /P; the page /Annots confirm it)
    for f in (f1, f2):
        assert f.rect == pytest.approx((453.19, 177.4, 503.19, 197.4)) and f.locked and not f.signed and f.seed == {}


def test_config_format_and_mode_roundtrip_and_validation(tmp_path, capsys):
    from tda_dsc_signer import config

    p = tmp_path / "c.toml"
    assert config.load(p).signature_format == "auto" and config.load(p).default_mode == "auto"
    config.save(config.Config(signature_format="adbe", default_mode="mca"), p)
    cfg = config.load(p)
    assert (cfg.signature_format, cfg.default_mode) == ("adbe", "mca")
    p.write_text('signature_format = "docx"\ndefault_mode = "x"\n')
    cfg = config.load(p)
    assert (cfg.signature_format, cfg.default_mode) == ("auto", "auto") and "WARNING" in capsys.readouterr().err

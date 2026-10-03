"""Form fields through the REAL module host and two SoftHSM tokens (throwaway certs whose subject serialNumber = sha256(PAN))."""

import subprocess

import isolate
import pytest
from conftest import INC9_FIELDS, make_form_pdf
from test_softhsm_e2e import MODULES, PIN, SOFTHSM, hsm  # noqa: F401 - hsm is a fixture

from tda_dsc_signer import cli, config, forms, pan, signing, verify
from tda_dsc_signer.errors import PanMismatch

pytestmark = pytest.mark.skipif(not (SOFTHSM and MODULES), reason="softhsm2-util / libsofthsm2.so not installed")
P1, P2 = "ABCDE1234F", "PQRST5678K"
F1, F2 = INC9_FIELDS[0][0], INC9_FIELDS[1][0]
F3 = "sigfield3_" + P2[:-1] + "L"  # a third PAN that no attached token holds


@pytest.fixture
def two(hsm):  # noqa: F811
    hsm.token("tok-1", "First Director", subject_serial=pan.pan_hash(P1))
    hsm.token("tok-2", "Second Director", subject_serial=pan.pan_hash(P2))
    svc = hsm.service()
    return svc, hsm.cert(svc, "First Director"), hsm.cert(svc, "Second Director")


def args(*argv, form):
    return cli._parser(config.Config()).parse_args([*argv, str(form)] if argv[0] == "fields" else [argv[0], str(form), *argv[1:]])


def test_real_host_sign_field_and_typed_pan_mismatch(two, tmp_path):
    svc, c1, c2 = two
    form = make_form_pdf(tmp_path / "f.pdf")
    kw = dict(page=1, box=(0, 0, 1, 1), stamp_text="Digitally signed by %(signer)s")
    with pytest.raises(PanMismatch) as e:  # crosses the real host pipe typed, before any login
        svc.sign(str(form), c1, pin="wrong-never-used", out=str(tmp_path / "x.pdf"), field=F2, **kw)
    assert e.value.field == F2 and e.value.cn == "First Director" and not (tmp_path / "x.pdf").exists()
    out = tmp_path / "o.pdf"
    res = svc.sign(str(form), c2, pin=PIN, out=str(out), field=F2, **kw)
    assert res.field_name == F2
    assert {f.name: f.signed for f in forms.find_signature_fields(out)} == {F1: False, F2: True}
    text = subprocess.run(["pdfsig", str(out)], capture_output=True, text=True, check=True, env=isolate.poppler_env()).stdout
    assert text.count("not signed") == 1 and "Signature is Valid" in text
    v = verify.verify_signed(str(out), F2)
    assert v.ok and v.fields[1].pan_match is True


def test_fields_command(two, tmp_path, capsys):
    svc, c1, c2 = two
    form = make_form_pdf(tmp_path / "f.pdf", ((F1, 2, (1, 1, 51, 21)), (F2, 3, (1, 1, 51, 21)), (F3, 3, (60, 1, 110, 21))))
    assert cli._fields_cmd(args("fields", form=form), config.Config(), svc) == 0
    lines = capsys.readouterr().out.splitlines()
    assert "ABCD…1234F" in lines[0] and "page 2" in lines[0] and "unsigned" in lines[0] and "First Director" in lines[0]
    assert "Second Director" in lines[1] and "page 3" in lines[1]
    assert "no attached token matches" in lines[2]


def test_sign_all_fields_chains_with_one_prompt_per_token(two, tmp_path, monkeypatch, capsys):
    svc, c1, c2 = two
    form = make_form_pdf(tmp_path / "f.pdf", ((F1, 2, (1, 1, 51, 21)), (F2, 3, (1, 1, 51, 21)), (F3, 3, (60, 1, 110, 21))))
    prompts = []
    monkeypatch.setattr(cli.getpass, "getpass", lambda p: prompts.append(p) or PIN)
    out = tmp_path / "o.pdf"
    a = args("sign", "--all-fields", "-o", str(out), form=form)
    assert cli._sign(a, config.Config(), svc, pins=None) is True
    text = capsys.readouterr().out
    assert f"needs another signer: {F3}" in text and "2 of 3 empty field(s) signed" in text
    assert len(prompts) == 2  # one per token
    assert {f.name: f.signed for f in forms.find_signature_fields(out)} == {F1: True, F2: True, F3: False}
    assert len(verify.verify_signed(str(out)).signatures) == 2
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".dsc-")] == []  # chain temp dir cleaned up


def test_sign_field_option_and_rejections(two, tmp_path, monkeypatch, capsys):
    svc, c1, c2 = two
    form = make_form_pdf(tmp_path / "f.pdf")
    monkeypatch.setattr(cli.getpass, "getpass", lambda p: PIN)
    n1, n2 = (next(i for i, c in enumerate(svc.discover(), 1) if c.key == x.key) for x in (c1, c2))  # discovery order is not fixed
    with pytest.raises(SystemExit, match="--invisible"):
        cli._sign(args("sign", "--field", F2, "--invisible", form=form), config.Config(), svc)
    with pytest.raises(PanMismatch):
        cli._sign(args("sign", "--field", F2, "-t", str(n1), "-o", str(tmp_path / "a.pdf"), form=form), config.Config(), svc)
    assert not (tmp_path / "a.pdf").exists()
    out = tmp_path / "b.pdf"
    assert cli._sign(args("sign", "--field", F2, "-t", str(n2), "--format", "pades", "-o", str(out), form=form), config.Config(), svc) is True
    assert signing.forms.find_signature_fields(out)[1].signed and "PAN matches" in capsys.readouterr().out

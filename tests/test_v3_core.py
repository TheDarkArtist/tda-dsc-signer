import json

from conftest import der, make_pdf

from tda_dsc_signer import signing, tokens, verify
from tda_dsc_signer.tokens import TokenCert, cert_from_dict, cert_to_dict


def mk(pki):
    return TokenCert("lib.so", 1, "T", "S1", "LBL", der(pki["leaf"]), "Test Signer", "Org", "2099-01-01", (der(pki["sub"]), der(pki["root"])), "0a0b")


def sign(src, cert, out, signer, **kw):
    a = dict(
        page=1,
        box=(0, 0, 0, 0),
        pin="x",
        out=str(out),
        open_session=lambda c, p, f=False: type("S", (), {})(),
        make_signer=lambda s, **k: signer(s, **k),
        mechanisms=lambda s: frozenset(),
        sleep=lambda d: None,
    )
    from pkcs11 import Mechanism

    a["mechanisms"] = lambda s: {Mechanism.SHA256_RSA_PKCS}
    return signing.sign_pdf(str(src), cert, **{**a, **kw})


def test_invisible_signature_on_multipage_pdf_verifies(pki, tmp_path, software_signer):
    src = make_pdf(tmp_path / "m.pdf", 5)
    out = tmp_path / "o.pdf"
    res = sign(src, mk(pki), out, software_signer, visible=False, page=99)  # bogus page is ignored when invisible
    v = verify.verify_signed(str(out), res.field_name)
    assert v.ok and v.chain_embedded
    from pyhanko.pdf_utils.reader import PdfFileReader

    with open(out, "rb") as f:
        fld = PdfFileReader(f).root["/AcroForm"]["/Fields"][0].get_object()
        assert list(fld["/Rect"]) == [0, 0, 0, 0]


def test_invisible_after_visible_gets_unique_field_and_both_verify(pki, tmp_path, software_signer):
    src = make_pdf(tmp_path / "m.pdf", 3)
    first, second = tmp_path / "a.pdf", tmp_path / "b.pdf"
    r1 = sign(src, mk(pki), first, software_signer, page=2, box=(50, 50, 300, 120))
    r2 = sign(first, mk(pki), second, software_signer, visible=False)
    assert r1.field_name != r2.field_name
    assert verify.verify_signed(str(second), r2.field_name).ok


def test_visible_still_validates_page(pki, tmp_path, software_signer):
    import pytest

    with pytest.raises(ValueError, match="page 9"):
        sign(make_pdf(tmp_path / "m.pdf", 2), mk(pki), tmp_path / "o.pdf", software_signer, page=9, box=(1, 1, 50, 50))


def test_wire_format_roundtrip_and_old_dicts(pki):
    c = mk(pki)
    d = json.loads(json.dumps(cert_to_dict(c)))
    assert cert_from_dict(d) == c
    assert tokens.TokenCert.__dataclass_fields__.keys() >= {"cert_id", "pin"}


def test_service_sign_forwards_visible_to_host(pki, tmp_path):
    from tda_dsc_signer.service import TokenService

    seen = {}

    class H:
        def call(self, method, params=None, **k):
            seen.update(params)
            return {"out": params["out"], "field_name": "f", "size": 1, "warnings": []}

    svc = TokenService(sources=[], fallback=tokens.GlobSource([]), make_host=lambda m: H())
    svc.sign(str(tmp_path / "a.pdf"), mk(pki), page=1, box=(0, 0, 0, 0), pin="p", out=str(tmp_path / "o.pdf"), stamp_text="", visible=False)
    assert seen["visible"] is False

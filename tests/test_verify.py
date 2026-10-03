import os
import shutil

import pytest
from asn1crypto import x509 as ax
from conftest import der
from pyhanko_certvalidator import ValidationContext

from tda_dsc_signer import signing, tokens, verify
from tda_dsc_signer.safety import PinState


class Session:
    def close(self):
        pass


REAL = "/tmp/claude-1000/-home-tda/931ef579-73eb-4d97-ac6e-7ae8ef0f4e0a/scratchpad/receipt-signed.pdf"


@pytest.fixture
def signed(pdf3, pki, software_signer, tmp_path):
    cert = tokens.TokenCert(
        "m", 0, "T", "S", "L", der(pki["leaf"]), "Test Signer", "Org", "2099-01-01", (der(pki["sub"]), der(pki["root"])), "01", PinState()
    )
    out = tmp_path / "s.pdf"
    r = signing.sign_pdf(
        str(pdf3),
        cert,
        page=1,
        box=(50, 50, 300, 120),
        pin="x",
        out=str(out),
        open_session=lambda c, p, f=False: Session(),
        make_signer=lambda s, **k: software_signer(s, **k),
        mechanisms=lambda s: {signing.Mechanism.SHA256_RSA_PKCS},
    )
    return str(out), r


def test_four_separate_rows_in_order(signed):
    path, r = signed
    v = verify.verify_signed(path, r.field_name)
    assert [x.key for x in v.rows] == ["unmodified", "signature", "issuer", "revocation"]
    assert v.ok and v.chain_embedded and v.signer == "Test Signer"
    assert v.row("revocation").state == verify.UNCHECKED


def test_unknown_issuer_is_informational_never_a_failure(signed):
    v = verify.verify_signed(signed[0])
    assert v.row("issuer").state == verify.INFO and v.ok


def test_issuer_trusted_with_a_context_rooted_in_the_test_ca(signed, pki):
    ctx = ValidationContext(
        trust_roots=[ax.Certificate.load(der(pki["root"]))], other_certs=[ax.Certificate.load(der(pki["sub"]))], allow_fetching=False
    )
    v = verify.verify_signed(signed[0], context=ctx)
    assert v.row("issuer").state == verify.OK


def test_tampered_file_fails_unmodified_and_ok(signed):
    path, _ = signed
    data = bytearray(open(path, "rb").read())
    data[100] ^= 0x01  # inside the signed range (PDF header/objects)
    open(path, "wb").write(data)
    v = verify.verify_signed(path)
    assert not v.ok and v.row("unmodified").state == verify.FAIL


def test_appended_content_means_not_covering_whole_file(signed):
    path, _ = signed
    with open(path, "ab") as f:
        f.write(b"\n%junk appended after the signature\n")
    v = verify.verify_signed(path)
    assert v.row("unmodified").state == verify.FAIL


def test_no_signature_found(pdf3):
    v = verify.verify_signed(str(pdf3))
    assert not v.ok and v.rows[0].state == verify.FAIL


@pytest.mark.skipif(not os.path.exists(REAL), reason="real signed receipt copy not present")
def test_real_token_signed_file_chains_to_pinned_cca_root(tmp_path):
    p = tmp_path / "r.pdf"
    shutil.copy(REAL, p)
    v = verify.verify_signed(str(p))
    assert v.row("signature").state == verify.OK
    assert v.row("issuer").state == verify.OK, v.row("issuer")

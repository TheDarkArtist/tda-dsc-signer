import datetime
import os
import subprocess

import isolate
import pytest
from asn1crypto import keys as akeys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pyhanko.sign import signers
from pyhanko_certvalidator.registry import SimpleCertificateStore
from reportlab.pdfgen import canvas

isolate.isolate()  # at import: before any test module can touch config


@pytest.fixture(autouse=True)
def _no_real_config(tmp_path_factory, monkeypatch):
    """Every test gets its own XDG dirs; a test that would reach the real config fails instead of writing it."""
    isolate.isolate(str(tmp_path_factory.mktemp("xdg")))
    for name in isolate.XDG:
        monkeypatch.setenv(name, os.environ[name])
    yield
    isolate.assert_isolated()


def make_cert(cn, issuer=None, issuer_key=None, ca=False, ku=None, days=365, serial=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)] + ([x509.NameAttribute(NameOID.SERIAL_NUMBER, serial)] if serial else [])
    name = x509.Name(attrs)
    now = datetime.datetime.now(datetime.UTC)
    b = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer.subject if issuer else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if ku is not None:
        b = b.add_extension(ku, critical=True)
    if issuer is not None:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.public_key()), critical=False)
    cert = b.sign(issuer_key or key, hashes.SHA256())
    return cert, key


def ku(**kw):
    base = dict(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    return x509.KeyUsage(**{**base, **kw})


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path, tmp_path_factory, monkeypatch):
    """Wrong-PIN memory and friends must never touch the real runtime/cache dirs."""
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    monkeypatch.delenv("PYHANKO_PKCS11_PIN", raising=False)
    from tda_dsc_signer import quirks

    monkeypatch.setattr(quirks, "SYSFS_USB", str(tmp_path_factory.mktemp("usb")))  # never let the machine's real USB devices change a test


@pytest.fixture(scope="session")
def pki():
    root, rk = make_cert("Test Root", ca=True, ku=ku(key_cert_sign=True))
    sub, sk = make_cert("Test Sub CA", root, rk, ca=True, ku=ku(key_cert_sign=True))
    leaf, lk = make_cert("Test Signer", sub, sk, ku=ku(digital_signature=True, content_commitment=True))
    return dict(root=root, sub=sub, leaf=leaf, leaf_key=lk)


@pytest.fixture
def software_signer(pki):
    """A pyHanko signer backed by a throwaway software key + the chain (stands in for PKCS11Signer)."""

    def make(session, signing_cert, ca_chain, **_kw):
        pem = pki["leaf_key"].private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        store = SimpleCertificateStore()
        store.register_multiple(ca_chain or [])
        return signers.SimpleSigner(signing_cert=signing_cert, signing_key=akeys.PrivateKeyInfo.load(pem), cert_registry=store, embed_roots=True)

    return make


def make_pdf(path, pages=3, pagesize=(595, 842), drawer=None):
    c = canvas.Canvas(str(path), pagesize=pagesize)
    for i in range(1, pages + 1):
        (drawer or (lambda c, i: c.drawString(100, 700, f"Body of page {i}")))(c, i)
        c.showPage()
    c.save()
    return path


@pytest.fixture
def pdf3(tmp_path):
    return make_pdf(tmp_path / "doc.pdf")


@pytest.fixture
def pdf_sloppy(tmp_path):
    """pdfunite output: pyHanko rejects its xref in strict mode (exercises the lenient fallback)."""
    a, b = make_pdf(tmp_path / "a.pdf", 1), make_pdf(tmp_path / "b.pdf", 2)
    out = tmp_path / "united.pdf"
    subprocess.run(["pdfunite", str(a), str(b), str(out)], check=True)
    return out


INC9_FIELDS = (("sigfield1_ABCDE1234F", 2, (453.19, 177.4, 503.19, 197.4)), ("sigfield2_PQRST5678K", 3, (453.19, 177.4, 503.19, 197.4)))


def make_form_pdf(path, specs=INC9_FIELDS, seeds=None, pages=3, pagesize=(595, 842), drawer=None):
    """A synthetic MCA-style form: empty signature fields (name, 1-based page, rect), optionally with seed values {name: SigSeedValueSpec}."""
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import fields

    base = make_pdf(path.with_name("base-" + path.name), pages, pagesize, drawer)
    with open(base, "rb") as f:
        w = IncrementalPdfFileWriter(f)
        for name, page, rect in specs:
            spec = fields.SigFieldSpec(sig_field_name=name, on_page=page - 1, box=rect, seed_value_dict=(seeds or {}).get(name))
            fields.append_signature_field(w, spec)
        with open(path, "wb") as out:
            w.write(out)
    return path

"""Shared fixtures for the MCA form-field GUI tests and harness: certificates whose subject serialNumber = sha256(PAN), INC-9 fields."""

from cryptography import x509
from cryptography.x509.oid import NameOID

from tda_dsc_signer import pan, tokens
from tda_dsc_signer.forms import FormField
from tda_dsc_signer.safety import PinState

PAN1, PAN2 = "ABCDE1234F", "PQRST5678K"


def der_with_pan(cn, pan_text, issuer=None, issuer_key=None):
    """DER of a throwaway certificate whose subject has serialNumber = sha256(pan_text) (no serialNumber when pan_text is None)."""
    import datetime

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if pan_text:
        attrs.append(x509.NameAttribute(NameOID.SERIAL_NUMBER, pan.pan_hash(pan_text)))
    name = x509.Name(attrs)
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def token(cn, serial, pan_text, der=None):
    return tokens.TokenCert(
        "fake.so", 0, f"Token {serial}", serial, "L", der or der_with_pan(cn, pan_text), cn, "Fake Org", "2099-01-01", (), "01", PinState()
    )


def field(name, page, pan_text="", signed=False, rect=(453, 177, 503, 197)):
    return FormField(name, page, rect, signed, True, pan_text or None, {})


F1 = field(f"sigfield1_{PAN1}", 7, PAN1)
F2 = field(f"sigfield2_{PAN2}", 8, PAN2)

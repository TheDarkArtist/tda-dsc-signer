"""Read bundled certificates and check them against the pins. Every load re-verifies the SHA-256."""

import hashlib
from importlib import resources

from asn1crypto import x509

from . import pins


class PinMismatch(Exception):
    pass


def sha256_hex(der):
    return hashlib.sha256(der).hexdigest().upper()


def check(pin, der):
    """Raise PinMismatch unless der matches the pin (and parses as a certificate)."""
    got = sha256_hex(der)
    if got != pin.sha256:
        raise PinMismatch(f"{pin.name}: SHA-256 is {got}, pinned {pin.sha256}. Refusing it.")
    return x509.Certificate.load(der)


def bundled_der(pin):
    der = (resources.files("tda_dsc_signer.trust") / "certs" / pin.filename).read_bytes()
    check(pin, der)
    return der


def anchors(include_old=False):
    return [x509.Certificate.load(bundled_der(p)) for p in (pins.ANCHOR, *(pins.OLD_ROOTS if include_old else ()))]


def intermediates():
    return [x509.Certificate.load(bundled_der(p)) for p in pins.INTERMEDIATES]


def validation_context(embedded=(), include_old=False, **kw):
    """pyHanko ValidationContext rooted ONLY in the pinned anchor(s); other_certs = bundled intermediates + embedded chain."""
    from pyhanko_certvalidator import ValidationContext

    return ValidationContext(trust_roots=anchors(include_old), other_certs=[*intermediates(), *embedded], allow_fetching=False, **kw)

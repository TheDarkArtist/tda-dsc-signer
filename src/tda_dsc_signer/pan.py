"""PAN <-> certificate matching. An Indian DSC carries sha256(PAN) (lowercase hex) as its subject serialNumber."""

import hashlib
from typing import NamedTuple


class Match(NamedTuple):
    cert_key: str | None
    status: str  # match | unknown | none


def pan_hash(pan):
    return hashlib.sha256(pan.upper().encode()).hexdigest()


def serial_matches_pan(serial, pan):
    return None if not serial else serial == pan_hash(pan)


def cert_matches_pan(cert, pan):
    """True/False, or None when the certificate has no subject serialNumber (PAN cannot be checked)."""
    return serial_matches_pan(cert.subject_serial, pan)


def _results(field, certs):
    return [(c, cert_matches_pan(c, field.pan)) for c in certs]


def candidates(field, certs):
    if not field.pan:
        return list(certs)
    res = _results(field, certs)
    hit = [c for c, m in res if m is True]
    return hit or [c for c, m in res if m is None]


def match(fields, certs):
    out = {}
    for f in fields:
        if f.signed:
            continue
        if not f.pan:
            out[f.name] = Match(None, "unknown")
            continue
        res = _results(f, certs)
        yes = next((c for c, m in res if m is True), None)
        unk = next((c for c, m in res if m is None), None)
        out[f.name] = Match(yes.key, "match") if yes else Match(unk.key, "unknown") if unk else Match(None, "none")
    return out

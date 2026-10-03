"""Post-sign check with pyHanko: four SEPARATE rows, never one collapsed tick. EVERY embedded signature is evaluated; the
four rows show the worst state across them and `signatures` carries the per-signature detail."""

import logging
from dataclasses import dataclass

from pyhanko.pdf_utils.misc import PdfReadError
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.sign.validation.status import ModificationLevel, SignatureCoverageLevel

from . import forms, pan
from .trust import store

# An untrusted issuer is expected here; pyHanko would log it as an exception traceback.
logging.getLogger("pyhanko.sign.validation").setLevel(logging.CRITICAL)

OK, FAIL, INFO, UNCHECKED = "ok", "fail", "info", "unchecked"


@dataclass(frozen=True)
class Row:
    key: str  # unmodified | signature | issuer | revocation
    label: str
    state: str  # ok | fail | info | unchecked
    detail: str


@dataclass(frozen=True)
class SigDetail:
    field_name: str
    signer: str
    rows: tuple  # the same four Rows, for this signature alone


@dataclass(frozen=True)
class FieldResult:
    name: str
    signer: str  # '' for an unsigned field
    pan_match: bool | None  # signed field with a PAN in its name: does the signer's certificate match it; None = not applicable/unknown


@dataclass(frozen=True)
class VerifyResult:
    rows: tuple  # exactly four Rows, in the order above; each shows the WORST state across all signatures
    signer: str  # of the requested field, else the last signature
    chain_embedded: bool
    ok: bool  # unmodified AND signature valid for EVERY signature, and no certificate revoked. Issuer never makes it false.
    detail: str  # one-line summary for a toast
    signatures: tuple = ()  # one SigDetail per embedded signature, in document order
    fields: tuple = ()  # one FieldResult per signature field present (signed or not)

    def row(self, key):
        return next(r for r in self.rows if r.key == key)

    # compatibility with the skeleton GUI
    @property
    def intact(self):
        return self.row("signature").state == OK

    @property
    def trusted(self):
        return self.row("issuer").state == OK


KEYS = ("unmodified", "signature", "issuer", "revocation")
SEVERITY = {OK: 0, UNCHECKED: 1, INFO: 2, FAIL: 3}
LABELS = {
    "unmodified": "Document unmodified since signing",
    "signature": "Signature valid",
    "issuer": "Issuer trusted",
    "revocation": "Revocation",
}
OK_LATER_CHANGES = (ModificationLevel.NONE, ModificationLevel.LTA_UPDATES, ModificationLevel.FORM_FILLING)  # e.g. a later signature


def _none(msg):
    rows = tuple(Row(k, LABELS[k], FAIL if k == "unmodified" else UNCHECKED, msg) for k in KEYS)
    return VerifyResult(rows, "", False, False, msg)


def _unmodified(st, is_last):
    if st.coverage == SignatureCoverageLevel.ENTIRE_FILE:
        return st.intact, "the file has content after this signature"
    # an earlier signature of a multi-signature file legitimately stops short of EOF: later revisions may only add signatures
    earlier_ok = not is_last and st.coverage == SignatureCoverageLevel.ENTIRE_REVISION and st.modification_level in OK_LATER_CHANGES
    return st.intact and earlier_ok, "the file has content after this signature"


def _rows(st, is_last):
    unmodified, why = _unmodified(st, is_last)
    return (
        Row(
            "unmodified",
            LABELS["unmodified"],
            OK if unmodified else FAIL,
            "digest matches and the signature covers the whole file"
            if unmodified
            else ("signed bytes do not match the file" if not st.intact else why),
        ),
        Row("signature", LABELS["signature"], OK if st.valid else FAIL, "cryptographic check passed" if st.valid else "cryptographic check FAILED"),
        Row(
            "issuer",
            LABELS["issuer"],
            OK if st.trusted else INFO,
            "chains to the pinned CCA India root" if st.trusted else "issuer not in the pinned trust bundle (informational, not tampering)",
        ),
        Row(
            "revocation",
            LABELS["revocation"],
            FAIL if st.revoked else UNCHECKED,
            "certificate is REVOKED" if st.revoked else "unchecked: no revocation data embedded or fetched",
        ),
    )


def _worst(details):
    """Per key, the row of the most severe signature (first one on ties); with several signatures the field name prefixes the detail."""
    out = []
    for i in range(len(KEYS)):
        pairs = [(d.rows[i], d.field_name) for d in details]
        r, field = max(pairs, key=lambda p: SEVERITY[p[0].state])  # max keeps the first of equals
        out.append(Row(r.key, r.label, r.state, f"{field}: {r.detail}" if len(details) > 1 and r.state != OK else r.detail))
    return tuple(out)


def verify_signed(path, field_name=None, context=None, include_old_roots=False):
    """context: optional ValidationContext (tests); default trusts ONLY the pinned CCA India anchor(s).
    field_name only picks which signature is reported as `signer` (default: the last); all signatures are checked."""
    with open(path, "rb") as f:
        try:
            r = PdfFileReader(f)
        except PdfReadError:  # same strict -> lenient fallback as signing
            r = PdfFileReader(f, strict=False)
        sigs = list(r.embedded_signatures)
        if not sigs or (field_name and not any(s.field_name == field_name for s in sigs)):
            return _none("no signature found")
        details, chain, signer, serials = [], False, "", {}
        for i, sig in enumerate(sigs):
            embedded = list(sig.other_embedded_certs)
            try:
                st = validate_pdf_signature(sig, context or store.validation_context(embedded, include_old_roots))
                name, rows = st.signing_cert.subject.native.get("common_name", "?"), _rows(st, i == len(sigs) - 1)
                serials[sig.field_name] = (st.signing_cert.subject.native.get("serial_number") or "").lower()
            except Exception as e:  # noqa: BLE001 - a signature that cannot even be evaluated is a failed one, not a crash
                name, rows = (
                    "?",
                    tuple(
                        Row(k, LABELS[k], {"issuer": INFO, "revocation": UNCHECKED}.get(k, FAIL), f"could not be validated: {type(e).__name__}")
                        for k in KEYS
                    ),
                )
            details.append(SigDetail(sig.field_name, name, rows))
            chain = chain or bool(embedded)
            if sig.field_name == field_name or (not field_name and i == len(sigs) - 1):
                signer = name
    rows = _worst(details)
    signers_by_field = {d.field_name: d.signer for d in details}
    try:
        present = forms.find_signature_fields(path)
    except ValueError:
        present = []
    named = {f.name: f for f in present}
    result_fields = tuple(
        FieldResult(
            n,
            signers_by_field.get(n, ""),
            pan.serial_matches_pan(serials.get(n, ""), named[n].pan) if n in signers_by_field and named[n].pan else None,
        )
        for n in [*named, *(d.field_name for d in details if d.field_name not in named)]
    )
    by = {x.key: x for x in rows}
    ok = by["unmodified"].state == OK and by["signature"].state == OK and by["revocation"].state != FAIL
    n = len(details)
    parts = [
        "unmodified" if by["unmodified"].state == OK else "MODIFIED",
        "signature valid" if by["signature"].state == OK else "SIGNATURE INVALID",
        "chain embedded" if chain else "no chain embedded",
        "issuer trusted" if by["issuer"].state == OK else "issuer not trusted",
        "certificate REVOKED" if by["revocation"].state == FAIL else "revocation unchecked",
    ]
    detail = (f"{n} signatures: " if n > 1 else "") + ", ".join(parts)
    return VerifyResult(rows, signer, chain, ok, detail, tuple(details), result_fields)

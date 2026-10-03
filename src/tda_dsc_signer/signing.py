"""Sign a PDF with a token key. Login happens exactly once; only key lookup + signing are retried."""

import os
import tempfile
import time
from dataclasses import dataclass

from asn1crypto import x509
from pkcs11 import Mechanism
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.misc import PdfError, PdfReadError
from pyhanko.sign import fields, signers
from pyhanko.sign.pkcs11 import PKCS11Signer

from . import forms, pan, quirks, tokens
from .safety import guard_login
from .stamp import DEFAULT_TEXT, make_field_style, make_style, stamp_name

PROFILES = ("mca", "general")
FORMATS = ("auto", "pades", "adbe")
SUBFILTERS = {"adbe": fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED, "pades": fields.SigSeedSubFilter.PADES}
SV_SUBFILTER_REQUIRED, SV_DIGEST_REQUIRED = 2, 64  # /SV /Ff bits 2 and 7
MCA_ATTACHMENT_LIMIT = 2 * 1024 * 1024  # REPORTED limit of MCA form attachments, not verified against the portal


class NoSupportedMechanism(Exception):
    pass


class OutputExists(FileExistsError):
    """The output file exists and overwrite was not requested."""


class FieldAlreadySigned(Exception):
    """The named signature field already holds a signature."""


@dataclass(frozen=True)
class SignResult:
    out: str
    field_name: str
    size: int = 0
    warnings: tuple = ()


def default_output(src):
    root, ext = os.path.splitext(src)
    return f"{root}-signed.pdf" if ext.lower() == ".pdf" else f"{src}-signed.pdf"


def check_output(src, out, overwrite=False):
    """Never overwrite the input document; never overwrite any other existing file unless `overwrite`."""
    same = os.path.realpath(src) == os.path.realpath(out) or (os.path.exists(out) and os.path.samefile(src, out))
    if same:
        raise ValueError(f"output must differ from the input document: {out}")
    if not overwrite and os.path.lexists(out):
        raise OutputExists(f"output already exists: {out} (pass --force / confirm the overwrite)")


def pdf_page_index(page):
    """CLI/GUI page (1-based; negative = from the end, -1 = last) -> pyHanko index (0-based; negative kept)."""
    if page == 0:
        raise ValueError("page is 1-based; use -1 for the last page")
    return page - 1 if page > 0 else page


def uses_raw_rsa(mechanisms):
    """Prefer hash-on-token SHA256_RSA_PKCS; else raw RSA_PKCS with a locally built DigestInfo. No PSS by default."""
    if Mechanism.SHA256_RSA_PKCS in mechanisms:
        return False
    if Mechanism.RSA_PKCS in mechanisms:
        return True
    raise NoSupportedMechanism("the token supports neither SHA256_RSA_PKCS nor RSA_PKCS")


def _slot_mechanisms(session):
    return set(session.token.slot.get_mechanisms())


def make_pkcs11_signer(session, *, signing_cert, key_id, key_label, ca_chain, use_raw):
    return PKCS11Signer(
        session,
        signing_cert=signing_cert,
        key_id=key_id,
        key_label=None if key_id else key_label,
        ca_chain=ca_chain,
        use_raw_mechanism=use_raw,
    )


def _writer(f):
    """Strict parse first; fall back to lenient for PDFs with a sloppy xref table. Returns (writer, lenient_was_used)."""
    try:
        return IncrementalPdfFileWriter(f, strict=True), False
    except PdfReadError:
        f.seek(0)
        w = IncrementalPdfFileWriter(f, strict=False)
        # Sloppy files (e.g. pdfunite) declare a trailer /Size below their real highest object id; new objects would
        # then overwrite real ones and corrupt the document.
        # ponytail: touches pyHanko's private _lastobj_id; drop if pyHanko clamps it itself.
        xr = w.prev.xrefs
        top = max((r.idnum for rev in range(xr.total_revisions) for r in xr.explicit_refs_in_revision(rev)), default=0)
        w._lastobj_id = max(w._lastobj_id, top)
        return w, True


def _field_names(w):
    """Every AcroForm field name in the document (partial names at any depth, plus signature fields of earlier revisions)."""
    names, todo = set(), []
    try:
        todo = list(w.root["/AcroForm"].get("/Fields", []))
    except (KeyError, AttributeError, PdfError):
        pass
    seen = 0
    while todo and seen < 100000:  # bounded: a hostile /Kids loop must not hang the preflight
        seen += 1
        try:
            f = todo.pop()
            f = f.get_object() if hasattr(f, "get_object") else f
            if "/T" in f:
                names.add(str(f["/T"]))
            todo.extend(f.get("/Kids", []))
        except (AttributeError, TypeError, PdfError):
            continue
    try:
        names.update(sig.field_name for sig in w.prev.embedded_signatures)
    except Exception:  # noqa: BLE001 - a signature we cannot enumerate cannot collide in a way we could detect anyway
        pass
    return names


def unique_field_name(taken):
    """`Sig-<time_ns>`; never a name already in the document."""
    name = f"Sig-{time.time_ns()}"
    n = 1
    while name in taken:
        n += 1
        name = f"Sig-{time.time_ns()}-{n}"
    return name


def preflight(src, out, page, overwrite=False, visible=True):
    """Everything that can fail WITHOUT the token, checked before the one login. Returns (lenient_parse_used, field_names)."""
    check_output(src, out, overwrite)
    try:
        with open(src, "rb") as f:
            w, lenient = _writer(f)
            total = w.root["/Pages"].get("/Count", "?")
            names = _field_names(w)
            if visible:
                try:
                    w.find_page_for_modification(pdf_page_index(page))
                except PdfError:
                    raise ValueError(f"page {page} does not exist (the document has {total} page(s))") from None
    except PdfError as e:
        raise ValueError(f"not a readable PDF: {e}") from None
    fd, probe = tempfile.mkstemp(prefix=".dsc-probe-", dir=os.path.dirname(os.path.abspath(out)))  # raises OSError if not writable
    os.close(fd)
    os.unlink(probe)
    return lenient, names


def resolve_format(signature_format, field):
    if signature_format not in (None, *FORMATS):
        raise ValueError(f"signature format must be one of {FORMATS}")
    fmt = signature_format or "auto"
    return ("adbe" if field else "pades") if fmt == "auto" else fmt


def _seed_check(f, fmt, auto):
    """Honour the /SV constraints we can. Returns the format to use or raises ValueError (before any login)."""
    sv = f.seed
    flags = sv.get("Flags", 0)
    subs = sv.get("SubFilter")
    if subs:
        wanted = {str(name) for name in subs}
        ours = {k: v.value for k, v in SUBFILTERS.items()}
        if ours[fmt] not in wanted:
            options = [k for k, v in ours.items() if v in wanted]
            if auto and options:
                fmt = options[0]
            elif flags & SV_SUBFILTER_REQUIRED:
                raise ValueError(f"field {f.name} requires SubFilter {sorted(wanted)} which cannot be produced with format '{fmt}'")
    dig = sv.get("DigestMethod")
    if dig and flags & SV_DIGEST_REQUIRED and not {str(d).lstrip("/").upper().replace("-", "") for d in dig} & {"SHA256"}:
        raise ValueError(f"field {f.name} requires digest {dig}; only SHA-256 is supported")
    return fmt


def preflight_field(src, name, cert, fmt, auto, allow_pan_mismatch=False):
    """Field exists, is empty, seed values satisfiable, PAN guard. Returns (FormField, format, warnings)."""
    from .errors import PanMismatch

    found = {f.name: f for f in forms.find_signature_fields(src)}
    if name not in found:
        raise ValueError(f"no signature field named {name!r} (found: {', '.join(found) or 'none'})")
    f = found[name]
    if f.signed:
        raise FieldAlreadySigned(f"signature field {name} is already signed")
    fmt = _seed_check(f, fmt, auto)
    warnings = []
    if f.pan:
        ok = pan.cert_matches_pan(cert, f.pan)
        if ok is False and not allow_pan_mismatch:
            raise PanMismatch(
                f"Field {name.replace(f.pan, f.pan_masked)} must be signed by the holder of that PAN; {cert.cn}'s certificate does not match",
                name,
                f.pan_masked,
                cert.cn,
            )
        if ok is None:
            warnings.append(f"the certificate has no serialNumber, so it cannot be checked against the PAN of {name}")
    return f, fmt, warnings


def _sign_once(src, out, pdf_signer, overwrite=False, existing=False, text_params=None):
    fd, tmp = tempfile.mkstemp(prefix=".dsc-", suffix=".pdf", dir=os.path.dirname(os.path.abspath(out)))
    try:
        with open(src, "rb") as inf, os.fdopen(fd, "wb", closefd=False) as outf:
            pdf_signer.sign_pdf(_writer(inf)[0], output=outf, existing_fields_only=existing, appearance_text_params=text_params)
            umask = os.umask(0)
            os.umask(umask)
            os.fchmod(fd, 0o666 & ~umask)  # mkstemp makes it 0600
        if overwrite:
            os.replace(tmp, out)
        else:
            try:
                os.link(tmp, out)  # atomic create-if-absent: a file that appeared since the preflight is not clobbered
            except FileExistsError:
                raise OutputExists(f"output already exists: {out}") from None
    finally:
        os.close(fd)
        if os.path.exists(tmp):
            os.unlink(tmp)


def sign_pdf(
    src,
    cert,
    *,
    page,
    box,
    pin,
    out,
    profile="mca",
    stamp_text=DEFAULT_TEXT,
    timestamper=None,
    confirm_final_try=False,
    overwrite=False,
    visible=True,
    tries=quirks.TRIES,
    delay=quirks.SIGN_DELAY,
    open_session=tokens.open_session,
    make_signer=make_pkcs11_signer,
    mechanisms=_slot_mechanisms,
    sleep=time.sleep,
    field=None,
    allow_pan_mismatch=False,
    signature_format=None,
):
    """cert: tokens.TokenCert. The keyword seams (open_session, make_signer, mechanisms, sleep) are for tests/fakes.

    profile: 'mca' (default) and 'general' are both PAdES-B-B with the token's chain embedded and no revocation blobs;
    'mca' additionally warns when the output exceeds the (reported) 2 MB attachment limit. A timestamper makes it B-T.
    visible=False: invisible signature (no widget); page and box are ignored and not validated.
    field: name of an EXISTING empty signature field to sign into (visible/page/box ignored; PAN guard applies).
    signature_format: auto (adbe for a field, pades otherwise) | pades | adbe.
    """
    if profile not in PROFILES:
        raise ValueError(f"profile must be one of {PROFILES}")
    warnings = []
    fmt = resolve_format(signature_format, field)
    lenient, taken = preflight(src, out, page, overwrite, visible and not field)  # parse / page / output dir / output rules: all before the login
    if lenient:
        warnings.append("PDF has a damaged xref table: parsed leniently (the original objects were preserved)")
    note = guard_login(cert.pin, confirm_final_try)
    if note:
        warnings.append(note)
    if field:
        target, fmt, more = preflight_field(src, field, cert, fmt, (signature_format or "auto") == "auto", allow_pan_mismatch)
        warnings += more
        name, spec = field, None
    else:
        name = unique_field_name(taken)
        spec = (
            fields.SigFieldSpec(sig_field_name=name, on_page=pdf_page_index(page), box=tuple(box))
            if visible
            else fields.SigFieldSpec(sig_field_name=name)
        )
    meta = signers.PdfSignatureMetadata(field_name=name, subfilter=SUBFILTERS[fmt], md_algorithm="sha256", embed_validation_info=False)
    style = make_field_style(stamp_text, cert.cn, target.rect) if field else make_style(stamp_text)
    shown, changed = stamp_name(cert.cn)
    text_params = {"signer": shown} if changed and cert.cn else None  # the stamp font lacks some characters of the name
    if text_params:
        warnings.append(f"the stamp shows '?' for characters of '{cert.cn}' that its font cannot draw (the certificate is unchanged)")
    leaf = x509.Certificate.load(cert.der)
    chain = [x509.Certificate.load(d) for d in cert.chain] or None
    key_id = bytes.fromhex(cert.cert_id) or None
    # a wrong PIN counts against the token's retry limit: ONE login, never retried, errors propagate.
    # open_session also refuses locked tokens / unconfirmed final tries BEFORE the login.
    session = open_session(cert, pin, confirm_final_try)
    try:
        use_raw = uses_raw_rsa(mechanisms(session)) if leaf.public_key.algorithm == "rsa" else False

        tried = []

        def attempt():
            # select the key by CKA_ID first; if the key's ID differs from the cert's (unverified per vendor), alternate to the
            # label so the lookup retries cover both. Lookups need no extra login.
            by_id = bool(key_id) and (len(tried) % 2 == 0 or not cert.label)
            tried.append(by_id)
            signer = make_signer(session, signing_cert=leaf, key_id=key_id if by_id else None, key_label=cert.label, ca_chain=chain, use_raw=use_raw)
            pdf_signer = signers.PdfSigner(meta, signer=signer, stamp_style=style, new_field_spec=spec, timestamper=timestamper)
            _sign_once(src, out, pdf_signer, overwrite, bool(field), text_params)

        quirks.retry_lookup(attempt, tries, delay, sleep)
    finally:
        close = getattr(session, "close", None)
        if close:
            close()
    size = os.path.getsize(out)
    if profile == "mca" and size > MCA_ATTACHMENT_LIMIT:
        warnings.append(f"output is {size / 1048576:.1f} MB, over the reported 2 MB MCA attachment limit")
    return SignResult(out, name, size, tuple(warnings))

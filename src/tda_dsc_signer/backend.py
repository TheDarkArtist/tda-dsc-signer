"""The seam the GUI/CLI talk to. Swap fields for fakes in tests/smoke runs; defaults use module-host subprocesses."""

from collections.abc import Callable
from dataclasses import dataclass

from . import forms
from . import verify as verify_mod
from .pinstore import PinManager
from .service import TokenService


@dataclass
class Backend:
    discover: Callable  # (extra_modules) -> list[TokenCert]
    # (src, cert, *, page, box, pin, out, stamp_text, profile=, timestamp_url=, confirm_final_try=False, confirm_after_failure=False,
    #  overwrite=False, visible=True, field=None, allow_pan_mismatch=False, signature_format=None) -> SignResult;
    #  may raise safety.RecentWrongPin / signing.OutputExists / errors.PanMismatch / signing.FieldAlreadySigned
    sign: Callable
    verify: Callable  # (path, field_name=None) -> VerifyResult
    snapshot: Callable = lambda: None  # () -> comparable | None ; hot-plug probe (see watch.Poller)
    close: Callable = lambda: None
    errors: Callable = lambda: {}  # () -> {module path: exception} of modules that failed in the last scan
    pins: object = None  # pinstore.PinManager
    fields: object = None  # (path) -> list[forms.FormField]; never touches PKCS#11


def default_backend(service=None):
    svc = service or TokenService()
    return Backend(
        svc.discover, svc.sign, verify_mod.verify_signed, svc.snapshot, svc.close, lambda: dict(svc.errors), PinManager(), forms.find_signature_fields
    )

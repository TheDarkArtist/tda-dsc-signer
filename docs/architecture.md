# Architecture

Notes for contributors, derived from the code (`src/tda_dsc_signer/`) and its module docstrings.

## Layers

    cli.py / gui/app.py        front-ends (argparse; GTK4)
          |
    backend.py                 the seam: discover / sign / verify / snapshot / fields / pins, swappable for fakes
          |
    service.py -> hostclient.py ==pipe==> host.py     one module-host subprocess per PKCS#11 module
          |
    signing.py, forms.py, verify.py, stamp.py, pan.py  PDF and certificate logic (no GTK)

Front-ends talk only to `Backend`. Tests and the GUI harness replace its functions with fakes; the defaults use real module hosts.

## Module host (one process per PKCS#11 driver)

The vendor `.so` is loaded only inside `python -I -m tda_dsc_signer.host MODULE` (cwd `/`, minimal environment: PATH, HOME, LANG,
LC_ALL, XDG_RUNTIME_DIR, TMPDIR; no core dumps; not dumpable). The protocol is JSON lines on stdin/stdout: a request
`{"id", "method", "params"}` gets `{"id", "ok": true, "result"}` or `{"id", "ok": false, "error": {"type", "message"}}`. Methods:
`ping`, `enumerate`, `present`, `sign`. Requests are never logged because `sign` carries the PIN.

`hostclient.py` applies a per-request timeout (30 s; 60 s for the first call because the InnaIT driver is slow to initialise),
kills a hung host and restarts it lazily, caps a protocol line at 8 MB, and never resends a `sign` request.

**Driver lock** (`driverlock.py`): vendor drivers and PC/SC readers cannot be shared, so the host takes an exclusive `flock` on a
per-module file before loading the `.so` and keeps it for its whole life. The kernel drops it on any exit, so there are no stale
locks. A second process gets a typed `DriverBusy` (CLI exit code 3; GUI shows who holds it) instead of silently seeing no tokens.

Modules are discovered from p11-kit registrations, a table of known vendor libraries, `DSC_MODULES` and `extra_modules`;
OpenSC is a fallback only. A module must be an absolute regular file owned by root or you, not group/world-writable
(user-owned ones need `--allow-user-module` or `allowed_modules`). `quirks.py` holds everything specific to flaky drivers
(retrying key lookup; never retrying `C_Login`).

## PIN flow

A PIN exists in the front-end for one call and in the host for one `sign` request, and travels only over the host's stdin pipe.
Before any login, `safety.py` reads the token flags and refuses a locked token, requires confirmation for a final try, and
refuses within 5 minutes of a recorded wrong PIN (the record holds serial, time and count, never the PIN). Exactly one `C_Login`
per signing action. Saved PINs (`pinstore.py`) live in process memory (`session`) or the system Secret Service (`keyring`);
there is no plaintext fallback and the config stores only the mode. A saved PIN the token rejects is deleted at once.

## Signing pipeline

`signing.py`: everything that can fail without the token (PDF parse, page, output path rules, field and seed-value checks, PAN
guard) runs first, then one login, then key lookup and signing with pyHanko, written to a temp file and renamed on success. The
input is never overwritten. Mechanism `SHA256_RSA_PKCS` is preferred, raw `RSA_PKCS` with a local DigestInfo is the fallback, PSS is
not used by default.

Formats: PAdES (`ETSI.CAdES.detached`) for drawn boxes, `adbe.pkcs7.detached` for existing form fields under `auto`; a field's
`/SV` seed values are honoured or refused before login. The token's certificate chain is embedded. A timestamp URL makes it PAdES-B-T.
`stamp.py` builds the visible appearance (bundled Noto Sans); small fields get a compact stamp.

## Verification and trust

`verify.py` reports four separate rows (unmodified, signature valid, issuer trusted, revocation) for every embedded signature.
Revocation is always reported as unchecked. The only trust anchor is the pinned CCA India 2022 root; the SHA-256 pins are constants
in `trust/pins.py` and every load re-verifies them. `trust/nss.py` writes only a dedicated NSS database (never `~/.pki/nssdb` or a
browser profile) for poppler's `pdfsig`; `trust/fetch.py` re-downloads from an https host allowlist and checks every hop and pin.

## MCA form fields and PAN matching

`forms.py` lists signature fields (MCA forms ship empty fields named `sigfield<N>_<PAN>`). An Indian DSC carries `sha256(PAN)`
(lowercase hex) as its subject `serialNumber` (`pan.py`), so a field can be matched to the token allowed to sign it. Signing into a
PAN-named field with a non-matching certificate raises `PanMismatch` before any login unless `--allow-pan-mismatch`.

## GUI structure

GTK-free logic is separate from widgets so it can be unit-tested without a display:

| GTK-free | Widgets |
| --- | --- |
| `gui/state.py` (labels, scaling, preconditions, error wording), `gui/formstate.py` (mode auto-detect, field rows, steps), `gui/signrun.py` (multi-signature run: output of step k feeds step k+1, one PIN prompt per token, a wrong PIN pauses, any other failure keeps the last good file), `gui/boxes.py` | `gui/app.py` (window, wiring), `panel.py`, `strip.py` (narrow layout), `pdfview.py`, `boxoverlay.py`, `formpanel.py`, `pinpopover.py`, `settings.py`, `toast.py`, `tokencard.py`, `signerpicker.py` |

`worker.py` runs every PKCS#11 call on one dedicated thread and hands results back through `GLib.idle_add`. `watch.py` polls for
hot-plug and reports a change only after it is stable.

## Testing strategy

- Unit tests with fakes for the core and the GTK-free GUI logic (`uv run pytest -q --ignore=tests/smoke_gui.py`).
- Real PKCS#11 signing against SoftHSM2 with a throwaway token (`tests/test_softhsm_*.py`, skipped when SoftHSM is absent).
- GUI scenarios in `tests/gui_drive.py`: `tests/gui_harness.py` runs the real GTK app with a fake Backend on a private Xvfb
  display driven by xdotool, and asserts on a JSON state dump plus screenshots. No real token, PIN or keyring is touched.
- Tests that need a real form are gated behind `DSC_TEST_INC9` and skip otherwise; all other fixtures are synthetic.

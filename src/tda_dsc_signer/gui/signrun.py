"""A multi-signature run (GTK-free): sign boxes one after another, the output of step k being the input of step k+1.

One PIN prompt per token (serial) per run, held in memory only until the run ends. A wrong PIN pauses the run for the user
(never an automatic retry); every other failure, and Cancel, stops it and keeps the last good intermediate as a partial result.
"""

import inspect
import os
import time
from dataclasses import dataclass

from . import state


@dataclass(frozen=True)
class Step:
    n: int  # badge number (1-based)
    page: int  # 1-based, as Backend.sign expects
    box: tuple
    cert: object  # TokenCert
    field: str = ""  # MCA mode: name of the existing signature field to sign INTO (page/box then unused)


def accepts(fn, name):
    """True when fn takes keyword `name` (the Backend grows keywords over time; never guess with try/except TypeError)."""
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False
    return name in params or any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())


def partial_path(out):
    root, ext = os.path.splitext(out)
    return f"{root}-partial{ext or '.pdf'}"


class SignRun:
    """ui needs: progress(done, total), ask_pin(cert, count, error|None), finished(path, verify_result, results),
    aborted(text, partial_path|None, done, total). submit(fn, cb) runs fn off the GTK thread and calls cb(result, error)."""

    def __init__(
        self,
        steps,
        src,
        out,
        *,
        backend,
        submit,
        ui,
        opts,
        remembered=None,
        remember=lambda key, pin: None,
        overwrite_final=False,
        saved_pin=lambda cert: None,
        on_saved_wrong=lambda cert: None,
    ):
        self.steps, self.src, self.out, self.backend, self._submit, self.ui = steps, src, out, backend, submit, ui
        self.opts, self._remembered, self._remember = opts, remembered or {}, remember
        self.overwrite_final = overwrite_final  # the user confirmed replacing an existing file in the save dialog
        self._k, self._pins, self._confirm, self._results, self._tmps, self._over = 0, {}, {}, [], [], False
        self._saved_pin, self._on_saved_wrong = saved_pin, on_saved_wrong
        self._saved_used, self._typed_remember = set(), {}  # serials whose PIN came from the saved store / typed with 'remember' ticked

    # -- control ---------------------------------------------------------------
    def start(self):
        folder = os.path.dirname(os.path.abspath(self.out))
        if not os.access(folder, os.W_OK):  # fail before any login
            return self._abort(f"Cannot write to {folder}.")
        self._next()

    def pin_given(self, pin, remember=False, confirm_final_try=False):
        cert = self.steps[self._k].cert
        self._pins[cert.serial], self._confirm[cert.serial] = pin, confirm_final_try
        if remember and pin:
            self._typed_remember[cert.serial] = cert  # stored only after this PIN actually worked
        self._go(False)

    def retry_anyway(self):
        """The user pressed 'Try anyway' after a recent wrong PIN."""
        self._go(True)

    def cancel(self, reason="Cancelled."):
        if not self._over:
            self._abort(reason)

    # -- steps -------------------------------------------------------------------
    def _next(self):
        if self._k == len(self.steps):
            return self._finish()
        cert = self.steps[self._k].cert
        self.ui.progress(self._k, len(self.steps))
        if cert.pin.protected_auth or cert.serial in self._pins:
            return self._go(False)
        if (saved := self._saved_pin(cert)) is not None:  # the caller already refused flagged tokens (final try, low count, locked)
            self._pins[cert.serial] = saved
            self._saved_used.add(cert.serial)
            return self._go(False)
        if cert.key in self._remembered and not cert.pin.final_try:
            self._pins[cert.serial] = self._remembered[cert.key]
            return self._go(False)
        self.ui.ask_pin(cert, sum(s.cert.serial == cert.serial for s in self.steps), None)

    def _paths(self):
        last = self._k == len(self.steps) - 1
        src = self.src if self._k == 0 else self._tmps[-1]
        out = self.out if last else os.path.join(os.path.dirname(os.path.abspath(self.out)), f".dsc-step-{os.getpid()}-{self._k}.pdf")
        return src, out

    def _go(self, after_failure):
        step, (src, out) = self.steps[self._k], self._paths()
        pin = None if step.cert.pin.protected_auth else self._pins.get(step.cert.serial)
        extra = {"confirm_after_failure": True} if after_failure and accepts(self.backend.sign, "confirm_after_failure") else {}
        last = self._k == len(self.steps) - 1
        if not self.opts.get("visible", True) and accepts(self.backend.sign, "visible"):
            extra["visible"] = False
        if step.field and accepts(self.backend.sign, "field"):
            extra["field"] = step.field
        if self.opts.get("signature_format") and accepts(self.backend.sign, "signature_format"):
            extra["signature_format"] = self.opts["signature_format"]
        if accepts(self.backend.sign, "overwrite"):  # hidden intermediates may be stale leftovers; the final file only if confirmed
            extra["overwrite"] = self.overwrite_final if last else True

        def job():
            return self.backend.sign(
                src,
                step.cert,
                page=step.page,
                box=step.box,
                pin=pin,
                out=out,
                stamp_text=self.opts["stamp_text"],
                profile=self.opts["profile"],
                timestamp_url=self.opts["timestamp_url"],
                confirm_final_try=self._confirm.get(step.cert.serial, False),
                **extra,
            )

        n = len(self.steps)
        state.debug(
            f"step {self._k + 1}/{n} token={step.cert.serial} page={step.page} pin={'saved' if step.cert.serial in self._saved_used else 'typed'} "
            f"src={os.path.basename(src)} out={os.path.basename(out)}"
        )
        t0 = time.monotonic()
        self._working(True)
        self._submit(job, lambda r, e: self._step_done(r, e, out, t0))

    def _working(self, on):
        getattr(self.ui, "working", lambda _on: None)(on)  # optional ui hook: a sign request is (not) in flight

    def _step_done(self, res, err, out, t0=None):
        self._working(False)
        step = self.steps[self._k]
        took = f"{time.monotonic() - t0:.2f}s" if t0 is not None else "?"
        state.debug(f"step {self._k + 1}/{len(self.steps)} {'FAILED ' + type(err).__name__ + ': ' + str(err) if err else 'ok'} after {took}")
        if err:
            self._remembered.pop(step.cert.key, None)  # a PIN that failed (or was followed by any failure) is never replayed
            kind, text = state.describe_error(err)
            if kind == "pin" and step.cert.serial in self._saved_used:  # never retry a stored PIN: the token counts failures
                self._saved_used.discard(step.cert.serial)
                self._pins.pop(step.cert.serial, None)
                self._on_saved_wrong(step.cert)
                return self._abort(state.SAVED_WRONG)
            if kind in ("pin", "confirm", "recent"):
                self._pins.pop(step.cert.serial, None)
                self.ui.ask_pin(step.cert, sum(s.cert.serial == step.cert.serial for s in self.steps), (kind, text))
                return  # paused for the user; nothing is retried by itself
            return self._abort(text)
        self._results.append(res)
        if (c := self._typed_remember.pop(step.cert.serial, None)) is not None and self._pins.get(c.serial):
            self._remember(c.key, self._pins[c.serial])
        if self._k < len(self.steps) - 1:
            self._tmps.append(out)
        self._k += 1
        self._next()

    # -- end -----------------------------------------------------------------------
    def _finish(self):
        self._over = True  # every signature exists: a late 'token removed' rescan must not cancel the verification
        self._end()
        last = self._results[-1]
        self._submit(lambda: self.backend.verify(last.out, last.field_name), lambda v, e: self._finished(v, e))

    def _finished(self, ver, err):
        if err:
            return self.ui.aborted(f"Signed, but verification failed: {type(err).__name__}: {err}", self.out, len(self.steps), len(self.steps))
        self.ui.finished(self.out, ver, self._results)

    def _abort(self, text):
        state.debug(f"run stopped after {self._k} of {len(self.steps)}: {text}")
        done, partial = self._k, None
        if self._tmps:
            partial = partial_path(self.out)
            n = 1
            while os.path.lexists(partial):  # never replace someone's earlier partial file
                n += 1
                root, ext = os.path.splitext(partial_path(self.out))
                partial = f"{root}-{n}{ext}"
            os.replace(self._tmps.pop(), partial)  # the last good intermediate becomes a visible, clearly named file
        self._end()
        self._over = True
        self.ui.aborted(text, partial, done, len(self.steps))

    @property
    def used_saved(self):
        return bool(self._saved_used)

    def _end(self):
        self._pins.clear()  # the PINs lived only for this run
        self._confirm.clear()
        for t in self._tmps:
            if os.path.exists(t):
                os.unlink(t)
        self._tmps.clear()

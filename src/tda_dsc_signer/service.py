"""TokenService: owns one ModuleHost per PKCS#11 module and exposes discover/sign/snapshot to the CLI and GUI."""

import contextlib
import hashlib
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait

import pkcs11

from . import config, quirks, tokens
from .errors import DriverBusy, HostBusy, HostTimeout, TokenCountMismatch
from .hostclient import ModuleHost
from .safety import WrongPinMemory
from .signing import SignResult, check_output


def _root_owned(module):
    try:
        return os.stat(module).st_uid == 0
    except OSError:
        return False


def dedupe(certs):
    """The same certificate on the same token seen through several modules: keep one, preferring a root-owned module."""
    best = {}
    for c in certs:
        k = (hashlib.sha256(c.der).digest(), c.serial)
        if k not in best or (_root_owned(c.module) and not _root_owned(best[k].module)):
            best[k] = c
    return list(best.values())


class TokenService:
    def __init__(
        self,
        sources=None,
        fallback=None,
        make_host=None,
        wrong_pins=None,
        allow_user_modules=None,
        wait_driver=0.0,
        usb_devices=quirks.usb_token_devices,
        sleep=time.sleep,
        clock=time.monotonic,
        opensc_fallback=None,
    ):
        """wait_driver: seconds to wait for another tda-dsc-signer to release a driver. usb_devices() -> list of known token
        USB ids, to notice scans that came back short."""
        self._usb, self._sleep, self._clock, self._pcsc = usb_devices, sleep, clock, threading.Lock()
        self.fallback_policy = config.load().opensc_fallback if opensc_fallback is None else opensc_fallback
        if self.fallback_policy not in ("auto", "never", "always"):
            raise ValueError(f"opensc_fallback must be auto, never or always, not {self.fallback_policy!r}")
        self.allow = config.load().allowed_modules if allow_user_modules is None else list(allow_user_modules)
        self.sources = tokens.default_sources(allow=self.allow) if sources is None else sources
        self.fallback = tokens.VettedSource(tokens.GlobSource(tokens.FALLBACK), self.allow) if fallback is None else fallback
        self._make_host, self._hosts = make_host or (lambda m: ModuleHost(m, wait_driver=wait_driver)), {}
        self.wrong_pins = WrongPinMemory() if wrong_pins is None else wrong_pins
        self.errors = {}  # module -> last host error, so a broken driver is reported but never hides the others

    def _host(self, module):
        return self._hosts.setdefault(module, self._make_host(module))

    def _modules(self, sources):
        return sorted({m for s in sources for m in s.modules()})

    def _enumerate(self, modules):
        """Scan modules in parallel, but PC/SC-touching ones (one lock per service) never initialise concurrently. The whole
        scan is capped at quirks.DISCOVER_CAP seconds: a stuck module gets its host killed and a HostTimeout recorded."""
        abandoned = set()

        def one(m):
            try:
                with self._pcsc if quirks.is_pcsc_module(m) else contextlib.nullcontext():
                    if m in abandoned:
                        return []
                    self.errors.pop(m, None)
                    r = self._host(m).call("enumerate")
                if isinstance(r, dict):  # {"certs": [...], "skipped": [reason, ...]}; a bare list is accepted too
                    r, skipped = r["certs"], r.get("skipped") or []
                    if skipped:
                        self.errors[m] = ValueError(f"{len(skipped)} unreadable object(s) skipped: {skipped[0]}")
                return [tokens.cert_from_dict(d) for d in r]
            except Exception as e:  # noqa: BLE001 - one broken/hostile module must not abort discovery of the others
                if m not in abandoned:
                    self.errors[m] = e
                return []

        pool = ThreadPoolExecutor(max_workers=max(1, len(modules)))
        futures = {m: pool.submit(one, m) for m in modules}
        done, _ = wait(futures.values(), timeout=quirks.DISCOVER_CAP)
        found = []
        for m, f in futures.items():
            if f in done:
                found += f.result()
                continue
            abandoned.add(m)
            self.errors[m] = HostTimeout(f"{os.path.basename(m)} did not finish scanning within {quirks.DISCOVER_CAP:g}s")
            try:
                self._host(m).kill()  # unblocks the worker thread; the next scan starts a fresh host
            except Exception:  # noqa: BLE001
                pass
        pool.shutdown(wait=False, cancel_futures=True)
        return found

    def _usb_ids(self):
        try:
            return list(self._usb())
        except OSError:
            return []

    def expected_devices(self):
        """How many known token devices USB says are attached (0 when sysfs is unreadable)."""
        return len(self._usb_ids())

    def _busy(self):
        return [m for m, e in self.errors.items() if isinstance(e, DriverBusy)]

    def _busy_could_serve(self, usb_ids):
        """A busy driver explains a shortfall only if it is one that serves one of the attached USB devices."""
        return any(quirks.serves(m, usb_ids) for m in self._busy())

    def _fallback_allowed(self, primary_modules_present):
        """OpenSC probes the same PC/SC readers as the vendor driver and disturbs it (also in OTHER processes), and it can not use
        these tokens anyway. 'auto': only when the machine has no vendor/registered module at all and no driver is busy."""
        if self.fallback_policy == "never" or self._busy():
            return False
        return self.fallback_policy == "always" or not primary_modules_present

    def discover(self, extra=()):
        """Scan; when USB shows more token devices than came back and no busy driver explains it, rescan up to quirks.RESCANS
        times (quirks.RESCAN_BACKOFF apart, within quirks.DISCOVER_TOTAL), then record errors['usb'] = TokenCountMismatch.
        A partial result warns too."""
        start, usb_ids = self._clock(), self._usb_ids()
        expected = len(usb_ids)
        for attempt in range(quirks.RESCANS + 1):
            self.errors.pop("usb", None)
            found = self._scan(extra)
            n = len({(c.module, c.serial) for c in found})
            if expected <= n or self._busy_could_serve(usb_ids):
                return found
            if attempt < quirks.RESCANS and self._clock() - start < quirks.DISCOVER_TOTAL:
                self._sleep(quirks.RESCAN_BACKOFF)
            else:
                break
        self.errors["usb"] = TokenCountMismatch(expected, n)
        return found

    def _scan(self, extra=()):
        """Signing certs from every primary module; the OpenSC fallback only under the policy in _fallback_allowed."""
        sources = [*self.sources, tokens.VettedSource(tokens.EnvSource(extra), self.allow)]
        modules = self._modules(sources)
        found = self._enumerate(modules)
        present = bool(modules) or any(getattr(s, "rejected", None) for s in sources)  # a refused module still exists
        if not found and self._fallback_allowed(present):
            sources.append(self.fallback)
            found = self._enumerate(self._modules([self.fallback]))
        for s in sources:  # modules refused by the vetting are reported like any other module failure
            for m, why in getattr(s, "rejected", {}).items():
                self.errors[m] = ValueError(f"module refused: {why}")
        return dedupe(found)

    def check_recent_failure(self, cert, confirm_after_failure=False):
        """Raises safety.RecentWrongPin when this token saw a wrong PIN within the window (any process)."""
        self.wrong_pins.check(cert.serial, confirm_after_failure)

    def sign(
        self,
        src,
        cert,
        *,
        page,
        box,
        pin,
        out,
        stamp_text,
        profile="mca",
        timestamp_url="",
        confirm_final_try=False,
        confirm_after_failure=False,
        overwrite=False,
        visible=True,
        field=None,
        allow_pan_mismatch=False,
        signature_format=None,
    ):
        """ONE request, ONE login (inside the host). Never retried here, not even after a timeout."""
        src, out = os.path.abspath(src), os.path.abspath(out)  # the host runs with cwd=/
        check_output(src, out, overwrite)
        self.check_recent_failure(cert, confirm_after_failure)
        params = {
            "cert": tokens.cert_to_dict(cert),
            "src": src,
            "page": page,
            "box": list(box),
            "pin": None if cert.pin.protected_auth else pin,
            "out": out,
            "profile": profile,
            "stamp_text": stamp_text,
            "timestamp_url": timestamp_url,
            "confirm_final_try": confirm_final_try,
            "overwrite": overwrite,
            "visible": visible,
            "field": field,
            "allow_pan_mismatch": allow_pan_mismatch,
            "signature_format": signature_format,
        }
        try:
            r = self._host(cert.module).call("sign", params, timeout=quirks.SIGN_TIMEOUT)
        except pkcs11.PinIncorrect:
            try:
                self.wrong_pins.record(cert.serial)
            except OSError:
                pass  # no state dir: the PinIncorrect itself matters more than the memory of it
            raise
        self.wrong_pins.clear(cert.serial)
        return SignResult(r["out"], r["field_name"], r["size"], tuple(r["warnings"]))

    def snapshot(self):
        """Tokens currently present, as a comparable tuple; None when a host is busy (e.g. signing) so polling never interferes."""
        seen = []
        for m in self._modules(self.sources):
            if m not in self._hosts or isinstance(self.errors.get(m), DriverBusy):
                continue  # only poll modules discover() already started; never respawn a host against a busy driver every tick
            try:
                seen.append((m, tuple(map(tuple, self._hosts[m].call("present", blocking=False)))))
            except HostBusy:
                return None
            except Exception as e:  # noqa: BLE001 - a hostile/broken host must not break polling
                self.errors[m] = e
        return tuple(seen)

    def close(self):
        for h in self._hosts.values():
            h.kill()

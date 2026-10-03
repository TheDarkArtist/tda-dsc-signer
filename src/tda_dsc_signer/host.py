"""Module host: one subprocess per PKCS#11 module. The vendor .so is loaded ONLY here, never in the GUI/CLI process.

Protocol: JSON lines on stdin/stdout. Request {"id", "method", "params"}; reply {"id", "ok": true, "result"} or
{"id", "ok": false, "error": {"type", "message"}}. Requests are never logged: `sign` carries the PIN.
Run as: python -m tda_dsc_signer.host /path/to/module.so
"""

import ctypes
import json
import os
import resource
import sys

from . import driverlock, signing, tokens
from .errors import DriverBusy, to_wire


class ModuleBackend:
    def __init__(self, module):
        self.module = module

    def ping(self, _p):
        return "pong"

    def enumerate(self, _p):
        skipped = []
        certs = [tokens.cert_to_dict(c) for c in tokens.signing_certs(self.module, skipped=skipped)]
        return {"certs": certs, "skipped": skipped}

    def present(self, _p):
        return tokens.present_tokens(self.module)

    def sign(self, p):
        cert = tokens.cert_from_dict(p["cert"])
        stamper = None
        if p.get("timestamp_url"):
            from pyhanko.sign.timestamps import HTTPTimeStamper

            stamper = HTTPTimeStamper(p["timestamp_url"])
        res = signing.sign_pdf(
            p["src"],
            cert,
            page=p.get("page", 1),
            box=tuple(p.get("box") or (0, 0, 0, 0)),
            pin=p.get("pin"),
            out=p["out"],
            profile=p.get("profile", "mca"),
            stamp_text=p["stamp_text"],
            timestamper=stamper,
            confirm_final_try=bool(p.get("confirm_final_try")),
            overwrite=bool(p.get("overwrite")),
            visible=p.get("visible", True),
            field=p.get("field"),
            allow_pan_mismatch=bool(p.get("allow_pan_mismatch")),
            signature_format=p.get("signature_format"),
        )
        return {"out": res.out, "field_name": res.field_name, "size": res.size, "warnings": list(res.warnings)}


METHODS = ("ping", "enumerate", "present", "sign")


class BusyBackend:
    """Stands in for ModuleBackend when another process owns the driver: every request gets the same typed DriverBusy."""

    def __init__(self, error):
        self.error = error

    def __getattr__(self, _name):
        raise self.error


def serve(inp, outp, backend, once=False):
    for line in inp:
        if not line.strip():
            continue
        req = {}
        try:
            req = json.loads(line)
            if req["method"] not in METHODS:
                raise ValueError(f"unknown method {req['method']!r}")
            reply = {"id": req["id"], "ok": True, "result": getattr(backend, req["method"])(req.get("params") or {})}
        except Exception as e:  # noqa: BLE001 - every failure goes back typed; the host keeps serving
            reply = {"id": req.get("id"), "ok": False, "error": to_wire(e)}
        outp.write(json.dumps(reply) + "\n")
        outp.flush()
        if once:
            return


PR_SET_DUMPABLE = 4


def harden():
    """This process holds the PIN: no core dumps, and not ptrace/proc-mem readable by same-uid processes."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    ctypes.CDLL(None, use_errno=True).prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    wait = 0.0
    if "--wait" in argv:  # --wait SECONDS: how long to wait politely for another instance to release the driver
        i = argv.index("--wait")
        wait = float(argv[i + 1])
        del argv[i : i + 2]
    harden()
    # vendor drivers print to stdout: keep the protocol on a private copy of fd 1 and point fd 1 at stderr
    proto = os.fdopen(os.dup(1), "w", buffering=1)
    os.dup2(2, 1)
    try:
        lock = driverlock.acquire(argv[0], wait)  # BEFORE the .so is ever loaded; held (fd kept open) until this process exits
    except DriverBusy as e:
        serve(sys.stdin, proto, BusyBackend(e), once=True)
        return
    except OSError as e:  # no usable state dir: exclusivity can not be enforced, but signing must not break because of it
        print(f"driver lock unavailable ({e}); continuing without it", file=sys.stderr)
        lock = None
    serve(sys.stdin, proto, ModuleBackend(argv[0]))  # returns on stdin EOF = the parent died or closed us
    del lock


if __name__ == "__main__":
    main()

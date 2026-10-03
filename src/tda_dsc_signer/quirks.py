"""Everything specific to flaky vendor PKCS#11 drivers (InnaIT today) lives here.

- the driver sleeps ~7s on its FIRST call per process (so: one long-lived process, one worker thread);
- FindObjects intermittently returns EMPTY, and key lookup intermittently fails (so: retry lookups);
- C_Login is NEVER retried: a wrong PIN counts against the token's retry limit.
"""

import time

import pkcs11

INNAIT_DRIVER = "/opt/Precision_Biometric/InnaITDSC/libraries/libInnaITPKCS11Driver.so"
TRIES = 6
FIND_DELAY = 0.3
SIGN_DELAY = 0.5


def find(session, template, tries=TRIES, delay=FIND_DELAY, sleep=time.sleep):
    """Retry a lookup until it returns something."""
    for attempt in range(tries):
        got = list(session.get_objects(template))
        if got:
            return got
        if attempt < tries - 1:
            sleep(delay)
    return []


def retry_lookup(fn, tries=TRIES, delay=SIGN_DELAY, sleep=time.sleep):
    """Run fn (key lookup + sign, never login), retrying PKCS11Error up to `tries` times, then re-raise."""
    for attempt in range(1, tries + 1):
        try:
            return fn()
        except pkcs11.PKCS11Error:
            if attempt == tries:
                raise
            sleep(delay)


# Module-host timeouts (seconds). The first request to a fresh host absorbs the driver's ~7s first-call sleep.
FIRST_CALL_TIMEOUT = 60
CALL_TIMEOUT = 30
SIGN_TIMEOUT = 120


# USB token devices we know about (VID:PID -> name). Used to notice an EMPTY scan that should not be empty.
KNOWN_USB = {
    "338c:0031": "InnaIT DSC",
    "096e:0807": "ePass2003",
    "096e:080a": "ePass2003",
    "096e:080f": "ePass2003",
}
SYSFS_USB = "/sys/bus/usb/devices"
RESCANS = 3  # extra scans when USB shows more token devices than the drivers returned
RESCAN_BACKOFF = 1.5  # seconds between them: at most 3 * 1.5 = 4.5 s of waiting on top of the scans themselves


def usb_token_devices(sysfs=None):
    """VID:PID of every attached USB device in KNOWN_USB, one entry per device (read from sysfs, no subprocess)."""
    import glob
    import os

    found = []
    for d in sorted(glob.glob(os.path.join(sysfs or SYSFS_USB, "*"))):
        try:
            with open(os.path.join(d, "idVendor")) as v, open(os.path.join(d, "idProduct")) as p:
                vp = f"{v.read().strip()}:{p.read().strip()}".lower()
        except OSError:
            continue  # interfaces (1-2:1.0) and root hubs without ids
        if vp in KNOWN_USB:
            found.append(vp)
    return found


DISCOVER_CAP = 30.0  # seconds one scan of all modules may take; a module still silent then is killed and reported as HostTimeout
DISCOVER_TOTAL = 60.0  # no further rescans once a discover() has used this long

# Module basenames (fnmatch) that talk to PC/SC readers: never initialised concurrently within one service, and the only ones whose
# BUSY state can explain missing USB devices of the matching VID:PID.
PCSC_MODULES = ("libInnaITPKCS11Driver*", "opensc-pkcs11*", "libcastle*", "libshuttle_p11*", "libepsng_p11*", "libeTPkcs11*", "libeToken*")
DRIVERS_FOR_USB = (("338c:*", ("libInnaITPKCS11Driver*",)), ("096e:*", ("libcastle*", "libshuttle_p11*", "libepsng_p11*")))


def is_pcsc_module(path):
    import fnmatch
    import os

    return any(fnmatch.fnmatch(os.path.basename(path), pat) for pat in PCSC_MODULES)


def serves(module, usb_ids):
    """True when `module` is a driver for at least one of the attached USB ids (by basename)."""
    import fnmatch
    import os

    base = os.path.basename(module)
    return any(fnmatch.fnmatch(u, idpat) and fnmatch.fnmatch(base, mpat) for u in usb_ids for idpat, pats in DRIVERS_FOR_USB for mpat in pats)

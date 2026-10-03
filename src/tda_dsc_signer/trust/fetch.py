"""Re-download pinned certificates from the official URLs over HTTPS. Anything off the allowlist or off the pin is refused."""

import os
import urllib.parse
import urllib.request

from asn1crypto import pem

from . import pins, store

MAX_BYTES = 1_000_000


def check_url(url):
    u = urllib.parse.urlparse(url)
    if u.scheme != "https" or u.hostname not in pins.ALLOWED_HOSTS:
        raise ValueError(f"refusing {url}: only https on {', '.join(pins.ALLOWED_HOSTS)} is allowed")


class CheckedRedirects(urllib.request.HTTPRedirectHandler):
    """Every hop of a redirect chain must pass the same https + host allowlist as the first URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


OPEN = urllib.request.build_opener(CheckedRedirects).open


def fetch_one(pin, opener=OPEN):
    check_url(pin.url)
    with opener(pin.url, timeout=30) as r:
        data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"{pin.url}: response too large")
    der = pem.unarmor(data)[2] if pem.detect(data) else data
    store.check(pin, der)
    return der


def fetch_all(dest, opener=OPEN):
    """Download every pin that has an official URL into dest (verified). Returns [(name, 'ok' | error text)]."""
    os.makedirs(dest, exist_ok=True)
    out = []
    for pin in (p for p in pins.ALL if p.url):
        try:
            der = fetch_one(pin, opener)
            with open(os.path.join(dest, pin.filename), "wb") as f:
                f.write(der)
            out.append((pin.name, "ok"))
        except Exception as e:  # noqa: BLE001 - report per file, keep going
            out.append((pin.name, f"REFUSED: {e}"))
    return out

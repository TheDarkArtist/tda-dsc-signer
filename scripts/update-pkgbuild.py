#!/usr/bin/env python3
"""Set pkgver and sha256sums in packaging/PKGBUILD (pkgrel resets to 1 when pkgver changes)."""

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _release as r  # noqa: E402


def update(text: str, version: str, sha256: str) -> str:
    old = re.search(r"^pkgver=([^\s#]+)", text, re.M)
    if not old:
        raise SystemExit("PKGBUILD: no pkgver= line")
    text = re.sub(r"^pkgver=[^\s#]+", f"pkgver={version}", text, count=1, flags=re.M)
    if old.group(1) != version:
        text = re.sub(r"^pkgrel=.*$", "pkgrel=1", text, count=1, flags=re.M)
    text, n = re.subn(r"^sha256sums=\(.*$", f"sha256sums=('{sha256}' 'SKIP')   # tag archive; the .asc is checked by gpg", text, count=1, flags=re.M)
    if n != 1:
        raise SystemExit("PKGBUILD: no single-line sha256sums=(...)")
    return text


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--version", required=True, help="X.Y.Z")
    ap.add_argument("--sha256", required=True, help="sha256 of the GitHub tag archive, or SKIP")
    ap.add_argument("--root", type=Path, default=r.ROOT, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if not re.fullmatch(r"\d+\.\d+\.\d+", a.version):
        ap.error("--version must be X.Y.Z")
    if not re.fullmatch(r"[0-9a-f]{64}|SKIP", a.sha256):
        ap.error("--sha256 must be 64 lowercase hex digits (or SKIP)")
    path = a.root / r.PKGBUILD
    path.write_text(update(path.read_text(encoding="utf-8"), a.version, a.sha256), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

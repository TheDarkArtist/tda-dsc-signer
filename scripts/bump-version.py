#!/usr/bin/env python3
"""Bump the version everywhere: pyproject, PKGBUILD (stable only), metainfo <releases>, CHANGELOG (Unreleased -> dated section)."""

import argparse
import datetime
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _release as r  # noqa: E402

_UNRELEASED_LINK = re.compile(r"^\[Unreleased\]: (\S+?)/compare/(\S+?)\.\.\.(\S+)$", re.M)


def bump_pyproject(text: str, v: str) -> str:
    out, n = re.subn(r'^version = "[^"]*"', f'version = "{v}"', text, count=1, flags=re.M)
    if n != 1:
        raise SystemExit("pyproject.toml: no `version = ` line")
    return out


def bump_pkgbuild(text: str, v: str) -> str:
    text, n = re.subn(r"^pkgver=[^\s#]+", f"pkgver={v}", text, count=1, flags=re.M)
    if n != 1:
        raise SystemExit("PKGBUILD: no pkgver= line")
    text = re.sub(r"^pkgrel=.*$", "pkgrel=1", text, count=1, flags=re.M)
    # the old archive checksum is wrong for the new tag; update-pkgbuild.py fills the real one after tagging
    return re.sub(r"^sha256sums=\([^)]*\)", "sha256sums=('SKIP')", text, count=1, flags=re.M)


def bump_metainfo(text: str, v: str, date: str) -> str:
    kind = ' type="development"' if "-" in v else ""
    entry = f'<releases>\n    <release version="{v}" date="{date}"{kind}/>'
    out, n = re.subn(r"<releases>", entry, text, count=1)
    if n != 1:
        raise SystemExit("metainfo: no <releases>")
    return out


def bump_changelog(text: str, v: str, date: str) -> str:
    m = re.search(r"^## \[Unreleased\][^\n]*\n", text, re.M)
    if not m:
        raise SystemExit("CHANGELOG: no `## [Unreleased]` heading")
    if not r.changelog_section(text, "Unreleased"):
        raise SystemExit("CHANGELOG: `## [Unreleased]` is empty; nothing to release")
    out = text[: m.start()] + f"## [Unreleased]\n\n## [{v}] - {date}\n" + text[m.end() :]
    link = _UNRELEASED_LINK.search(out)
    if link:
        base, prev, _ = link.groups()
        new = f"[Unreleased]: {base}/compare/v{v}...HEAD\n[{v}]: {base}/compare/{prev}...v{v}"
        out = out[: link.start()] + new + out[link.end() :]
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("version", help="X.Y.Z or X.Y.Z-rc.1")
    ap.add_argument("--date", default=datetime.date.today().isoformat(), help="release date, YYYY-MM-DD (default: today)")
    ap.add_argument("--dry-run", action="store_true", help="validate and report, write nothing")
    ap.add_argument("--root", type=Path, default=r.ROOT, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if not r.SEMVER.fullmatch(a.version):
        ap.error("version must look like 1.2.3 or 1.2.3-rc.1")
    datetime.date.fromisoformat(a.date)

    steps = [
        (r.PYPROJECT, lambda t: bump_pyproject(t, a.version)),
        (r.METAINFO, lambda t: bump_metainfo(t, a.version, a.date)),
        (r.CHANGELOG, lambda t: bump_changelog(t, a.version, a.date)),
    ]
    if "-" not in a.version:  # AUR carries stable releases only
        steps.append((r.PKGBUILD, lambda t: bump_pkgbuild(t, a.version)))
    new = {rel: fn(r.read(a.root, rel)) for rel, fn in steps}  # compute all first: a failure writes nothing
    for rel, text in new.items():
        print(f"{'would update' if a.dry_run else 'updated'} {rel}")
        if not a.dry_run:
            (a.root / rel).write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

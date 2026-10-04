#!/usr/bin/env python3
"""Fail unless tag, pyproject, PKGBUILD, metainfo and CHANGELOG all name the same release, and its CHANGELOG section is non-empty."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _release as r  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tag", help="release tag, e.g. v0.2.0 (checked against the files)")
    ap.add_argument("--root", type=Path, default=r.ROOT, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)

    cl = r.read(a.root, r.CHANGELOG)
    released = [v for v in r.changelog_versions(cl) if v.lower() != "unreleased"]
    ver = r.pyproject_version(a.root)
    found = {
        "pyproject.toml version": ver,
        "metainfo newest release": r.metainfo_newest(a.root),
        "CHANGELOG newest heading": released[0] if released else "(none)",
    }
    # AUR packages only stable releases; pre-release versions are not mirrored into the PKGBUILD
    if "-" not in ver:
        found["PKGBUILD pkgver"] = r.pkgbuild_version(a.root)
    if a.tag:
        found = {"tag": a.tag.removeprefix("v"), **found}
    bad = len(set(found.values())) != 1
    for k, v in found.items():
        print(f"{k:28} {v}")
    if bad:
        print("FAIL: versions differ", file=sys.stderr)
        return 1
    if not r.changelog_section(cl, ver):
        print(f"FAIL: CHANGELOG section [{ver}] is missing or empty", file=sys.stderr)
        return 1
    print(f"OK: {ver}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

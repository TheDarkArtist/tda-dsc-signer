"""Shared readers for the release scripts (stdlib only). Every function takes the repo root so tests can use a temp copy."""

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = "pyproject.toml"
PKGBUILD = "packaging/PKGBUILD"
METAINFO = "data/in.tdacorp.DscSigner.metainfo.xml"
CHANGELOG = "CHANGELOG.md"
SEMVER = re.compile(r"\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?")
_HEADING = re.compile(r"^## \[([^\]]+)\]", re.M)


def read(root: Path, rel: str) -> str:
    return (root / rel).read_text(encoding="utf-8")


def pyproject_version(root: Path) -> str:
    return tomllib.loads(read(root, PYPROJECT))["project"]["version"]


def pkgbuild_version(root: Path) -> str:
    m = re.search(r"^pkgver=([^\s#]+)", read(root, PKGBUILD), re.M)
    if not m:
        raise SystemExit(f"{PKGBUILD}: no pkgver= line")
    return m.group(1)


def metainfo_newest(root: Path) -> str:
    m = re.search(r"<releases>\s*<release\s+version=\"([^\"]+)\"", read(root, METAINFO))
    if not m:
        raise SystemExit(f"{METAINFO}: no <release version=...> under <releases>")
    return m.group(1)


def changelog_versions(text: str) -> list[str]:
    return _HEADING.findall(text)


def changelog_section(text: str, version: str) -> str:
    """Body under `## [version]` up to the next `## [` heading or the trailing link-reference block."""
    m = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n", text, re.M)
    if not m:
        return ""
    rest = text[m.end() :]
    nxt = _HEADING.search(rest)
    body = rest[: nxt.start()] if nxt else rest
    body = re.split(r"^\[[^\]]+\]: \S+\s*$", body, maxsplit=1, flags=re.M)[0]
    return body.strip()

"""Release scripts run against a temp copy of the repo files (never the real ones)."""

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPTS = REPO / "scripts"
FILES = ["pyproject.toml", "packaging/PKGBUILD", "data/in.tdacorp.DscSigner.metainfo.xml"]
CHANGELOG = """# Changelog

## [Unreleased]

### Added

- A new thing.

## [0.1.0] - 2026-10-04

- First release.

[Unreleased]: https://github.com/o/r/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/o/r/releases/tag/v0.1.0
"""


@pytest.fixture
def root(tmp_path):
    for rel in FILES:
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO / rel, tmp_path / rel)
    (tmp_path / "CHANGELOG.md").write_text(CHANGELOG)
    # normalise the copies to a known 0.1.0 starting point
    for rel, pat, new in [
        (FILES[0], r'^version = "[^"]*"', 'version = "0.1.0"'),
        (FILES[2], r'(<releases>\s*<release version=")[^"]*', r"\g<1>0.1.0"),
    ]:
        f = tmp_path / rel
        f.write_text(re.sub(pat, new, f.read_text(), count=1, flags=re.M))
    run("update-pkgbuild.py", "--root", tmp_path, "--version", "0.1.0", "--sha256", "SKIP")
    return tmp_path


def run(script, *args, check=False):
    p = subprocess.run([sys.executable, str(SCRIPTS / script), *map(str, args)], capture_output=True, text=True)
    if check:
        assert p.returncode == 0, p.stderr
    return p


def test_help_works():
    for s in ["bump-version.py", "check-release.py", "release-notes.py", "update-pkgbuild.py"]:
        assert run(s, "--help").returncode == 0


def test_bump_updates_all_four_files_consistently(root):
    run("bump-version.py", "0.2.0", "--date", "2026-11-01", "--root", root, check=True)
    assert 'version = "0.2.0"' in (root / "pyproject.toml").read_text()
    pkg = (root / "packaging/PKGBUILD").read_text()
    assert "pkgver=0.2.0" in pkg and "pkgrel=1" in pkg and "sha256sums=('SKIP')" in pkg
    assert '<release version="0.2.0" date="2026-11-01"/>' in (root / FILES[2]).read_text()
    cl = (root / "CHANGELOG.md").read_text()
    assert "## [Unreleased]\n\n## [0.2.0] - 2026-11-01\n\n### Added" in cl
    assert "[Unreleased]: https://github.com/o/r/compare/v0.2.0...HEAD" in cl
    assert "[0.2.0]: https://github.com/o/r/compare/v0.1.0...v0.2.0" in cl
    assert run("check-release.py", "--tag", "v0.2.0", "--root", root).returncode == 0
    assert run("release-notes.py", "--tag", "v0.2.0", "--root", root).stdout.strip().endswith("- A new thing.")


def test_bump_dry_run_writes_nothing(root):
    before = {f: (root / f).read_text() for f in [*FILES, "CHANGELOG.md"]}
    run("bump-version.py", "0.2.0", "--dry-run", "--root", root, check=True)
    assert before == {f: (root / f).read_text() for f in before}


def test_bump_refuses_empty_unreleased_and_bad_version(root):
    assert run("bump-version.py", "not-a-version", "--root", root).returncode != 0
    run("bump-version.py", "0.2.0", "--root", root, check=True)
    again = run("bump-version.py", "0.3.0", "--root", root)  # Unreleased is now empty
    assert again.returncode != 0 and "empty" in again.stderr
    assert 'version = "0.2.0"' in (root / "pyproject.toml").read_text()  # nothing half-written


def test_check_release_passes_then_fails_on_mismatch(root):
    assert run("check-release.py", "--tag", "v0.1.0", "--root", root).returncode == 0
    assert run("check-release.py", "--tag", "v9.9.9", "--root", root).returncode == 1
    pkg = root / "packaging/PKGBUILD"
    pkg.write_text(pkg.read_text().replace("pkgver=0.1.0", "pkgver=0.1.1"))
    assert run("check-release.py", "--root", root).returncode == 1


def test_check_release_fails_on_empty_changelog_section(root):
    cl = root / "CHANGELOG.md"
    cl.write_text(cl.read_text().replace("- First release.\n", ""))
    assert run("check-release.py", "--root", root).returncode == 1


def test_release_notes_extracts_only_that_section(root):
    out = run("release-notes.py", "--tag", "v0.1.0", "--root", root, check=True).stdout
    assert out.strip() == "- First release."
    assert run("release-notes.py", "--tag", "v7.0.0", "--root", root).returncode == 1


def test_update_pkgbuild_sets_version_and_checksum(root):
    sha = "ab" * 32
    run("update-pkgbuild.py", "--version", "0.3.0", "--sha256", sha, "--root", root, check=True)
    pkg = (root / "packaging/PKGBUILD").read_text()
    assert "pkgver=0.3.0" in pkg and f"sha256sums=('{sha}')" in pkg and "pkgrel=1" in pkg
    assert run("update-pkgbuild.py", "--version", "0.3.0", "--sha256", "zz", "--root", root).returncode != 0

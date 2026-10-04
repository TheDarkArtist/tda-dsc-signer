#!/usr/bin/env python3
"""Print the CHANGELOG section for a release tag (used as the GitHub Release body)."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _release as r  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tag", required=True, help="e.g. v0.2.0")
    ap.add_argument("--root", type=Path, default=r.ROOT, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    body = r.changelog_section(r.read(a.root, r.CHANGELOG), a.tag.removeprefix("v"))
    if not body:
        print(f"CHANGELOG has no non-empty section for {a.tag}", file=sys.stderr)
        return 1
    print(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())

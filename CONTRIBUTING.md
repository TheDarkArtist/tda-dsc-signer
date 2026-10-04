# Contributing

Thanks for helping. Small, focused changes with tests are easiest to review.

## Privacy rule (read first)

**Never commit or paste real PANs, certificate serials or hashes, real names, filings, signed documents, PINs or token dumps** into
code, tests, fixtures, screenshots, issues or pull requests. Use the synthetic data already in the tests (`ABCDE1234F`,
`PQRST5678K`, Jane Doe, Bob Smith) and generated PDFs. Tests that need a real form are gated behind an environment variable and skip
otherwise. Tests must never use a real token, a real PIN or the real keyring.

## Dev setup

Python 3.12+, with system GTK4, poppler-glib and PyGObject (the venv must see the system `gi`):

    uv venv --system-site-packages --python /usr/bin/python3   # once
    uv sync
    uv run pytest -q --ignore=tests/smoke_gui.py
    uv run ruff check
    uv run ruff format --check

`tests/test_softhsm_*.py` run real PKCS#11 signing against a throwaway SoftHSM2 token and skip when `softhsm2-util` is missing.
Tests that need a display skip without one.

## GUI scenarios

`tests/gui_drive.py` drives the GUI on a throwaway Xvfb with fake backends, asserts behaviour and saves screenshots:

    GSK_RENDERER=cairo uv run python tests/gui_drive.py OUT_DIR [WIDTH] [MODE]   # MODE: formfields, signers, settings, ...

It uses its own display (`:97`) and refuses to run against `:0`. It never touches your real config, keyring or tokens.

Start with [docs/architecture.md](docs/architecture.md) for the layout and [docs/cli-reference.md](docs/cli-reference.md) for the commands.

## Commits and pull requests

- [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `ci:`.
- History is organised as small topical commits (one concern each), not one commit per work session. Keep tests and the code they cover in the same commit.
- Before opening a PR: tests, `ruff check` and `ruff format --check` pass; update `CHANGELOG.md` under *Unreleased* for user-visible changes.
- Security issues: do not open a public issue, see [SECURITY.md](SECURITY.md).

## Releasing

Maintainers: see [RELEASING.md](RELEASING.md).

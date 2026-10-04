## What and why

<!-- One or two sentences. Link the issue: Closes #123 -->

## Checklist

- [ ] Title follows Conventional Commits (`feat:`, `fix:`, `docs:`, `build:`, `ci:` ...)
- [ ] `uv run ruff check && uv run ruff format --check` pass
- [ ] `uv run pytest -q --ignore=tests/smoke_gui.py` passes (tests added or updated for the change)
- [ ] User-visible change: added a line under `## [Unreleased]` in CHANGELOG.md (or label `skip-changelog`)
- [ ] No PINs, PANs, certificates, signed documents or personal data in the diff, logs or screenshots

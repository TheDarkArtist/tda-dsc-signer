# Releasing

Maintainer runbook. Contributors do not need this file.

## Policy

- **SemVer** (`MAJOR.MINOR.PATCH`). While on `0.x`, a minor bump may break behaviour; say so in the changelog.
- **Conventional Commits** (`feat:`, `fix:`, `docs:`, `build:`, `ci:`, `chore:`, `test:`, `refactor:`). Release commits are `chore(release): vX.Y.Z`.
- **Changelog discipline**: every user-visible change adds a line under `## [Unreleased]` in `CHANGELOG.md` in the same PR
  (or the PR carries the `skip-changelog` label). The release notes are that section verbatim; an empty section blocks the release.
- A version lives in four places, kept in sync by `scripts/bump-version.py` and checked by `scripts/check-release.py`:
  `pyproject.toml`, `packaging/PKGBUILD` (`pkgver`), the newest `<release>` in the metainfo, the newest CHANGELOG heading.
  The git tag is `v` + that version.

## Cut a release

1. `main` is green in CI and `## [Unreleased]` in `CHANGELOG.md` describes the release.
2. `make release VERSION=X.Y.Z` runs the bump, the consistency check, the tests and ruff. It does **not** commit, tag or push.
   Preview the bump alone with `python3 scripts/bump-version.py X.Y.Z --dry-run` (`--date YYYY-MM-DD` to override today).
3. Review `git diff`, then run the three commands the target prints:
   ```
   git commit -am "chore(release): vX.Y.Z"
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push --follow-tags
   ```
4. Watch the **Release** workflow. Check the GitHub Release page: notes, `*.whl`, `*.tar.gz`, `SHA256SUMS`.
5. AUR: automatic if enabled (below); otherwise follow "Manual AUR fallback".

Pre-release: `make release VERSION=0.3.0-rc.1`. A tag containing a hyphen is published as a GitHub *pre-release*, the PKGBUILD is not
touched and the AUR job is skipped. The final `0.3.0` is a normal release.

Hotfix: branch from the release tag (`git switch -c hotfix/0.2.1 v0.2.0`), cherry-pick the fix, add it under `## [Unreleased]`,
run `make release VERSION=0.2.1`, push the branch and tag. Merge the changelog/version commit back to `main`.

## What CI does

| Workflow | Trigger | Does |
|---|---|---|
| `ci.yml` | push to `main`, PRs | ruff; full tests in an Arch container under Xvfb; `uv build` + wheel smoke test + desktop/AppStream validation; `makepkg` of the PKGBUILD from the working tree plus file-list assertions |
| `codeql.yml` | push, PRs, weekly | CodeQL for Python |
| `pages.yml` | push to `main` touching `docs/**` | deploys `docs/` to GitHub Pages |
| `release.yml` | tag `v*.*.*` (or manual with a `tag` input) | `verify` (check-release) -> `build` (sdist, wheel, `SHA256SUMS`, build-provenance attestation) -> `release` (GitHub Release with notes from the CHANGELOG, `--verify-tag`) -> `aur-prepare` + `aur` (optional) ; `pypi` is disabled |

All third-party actions are pinned to full commit SHAs; Dependabot (weekly for actions, monthly for uv) proposes bumps.

## AUR automation (optional, off by default)

The `aur` jobs run only when the repository **variable** `AUR_AUTO_PUBLISH` is `true`, and only for stable tags.
They hash the real GitHub tag archive, rewrite `pkgver`/`pkgrel`/`sha256sums` with `scripts/update-pkgbuild.py`, regenerate `.SRCINFO` with
`makepkg --printsrcinfo`, and push to `ssh://aur@aur.archlinux.org/tda-dsc-signer.git` with `KSXGitHub/github-actions-deploy-aur`.

Setup:

1. Generate a **dedicated** key, never your personal one: `ssh-keygen -t ed25519 -f aur-deploy -C "tda-dsc-signer CI"`.
2. Add `aur-deploy.pub` to your AUR account (Account Settings -> SSH Public Key). Note the key then authorises every package on that account.
3. `gh secret set AUR_SSH_PRIVATE_KEY < aur-deploy`, then delete the private key file.
4. `gh variable set AUR_DRY_RUN --body true` and `gh variable set AUR_AUTO_PUBLISH --body true`. With `AUR_DRY_RUN=true` the deploy action only tests
   (no push). Cut a release, read the log, then set `AUR_DRY_RUN` to `false` (or delete it).

The AUR package must already exist (first upload is manual), because the action pushes to the existing repository.

The committer identity is taken from the `# Maintainer:` line of the PKGBUILD. The version commit in this repo does not contain the real
checksum (it is `SKIP` until the tag exists); after a release, commit the updated `packaging/PKGBUILD` and `.SRCINFO` back if you want them to match.

## Verify a release

```
gh release download vX.Y.Z --repo TheDarkArtist/tda-dsc-signer
sha256sum -c SHA256SUMS
gh attestation verify tda_dsc_signer-X.Y.Z-py3-none-any.whl --repo TheDarkArtist/tda-dsc-signer
```

## Rollback

- Release workflow failed before `release`: fix, delete the tag locally and remotely (`git tag -d vX.Y.Z; git push origin :refs/tags/vX.Y.Z`),
  commit the fix, and re-tag. Nothing public existed yet.
- Bad release already published: `gh release delete vX.Y.Z` (add `--cleanup-tag` only if no one can have used it), publish a fixed `X.Y.Z+1`,
  and note the problem in the changelog. Do not move a published tag: the AUR checksum and attestations refer to it.
- Bad AUR push: push a new `pkgrel` or version; the AUR keeps history, do not force-push.

## Manual AUR fallback

```
git clone ssh://aur@aur.archlinux.org/tda-dsc-signer.git ~/Development/aur/tda-dsc-signer
cd ~/Development/aur/tda-dsc-signer
cp /path/to/repo/packaging/{PKGBUILD,tda-dsc-signer.install} .
python3 /path/to/repo/scripts/update-pkgbuild.py --root /path/to/repo --version X.Y.Z --sha256 "$(curl -fsSL https://github.com/TheDarkArtist/tda-dsc-signer/archive/refs/tags/vX.Y.Z.tar.gz | sha256sum | cut -d' ' -f1)"
cp /path/to/repo/packaging/PKGBUILD .
makepkg --printsrcinfo > .SRCINFO
makepkg -si --noconfirm   # test build
git add PKGBUILD .SRCINFO tda-dsc-signer.install && git commit -m "release vX.Y.Z" && git push
```

## One-time repository setup

`scripts/gh-bootstrap.sh` creates the labels from `.github/labels.yml` (idempotent). Pages must use "GitHub Actions" as its source,
and `main` should require the CI jobs `lint`, `test`, `build`, `packaging`.

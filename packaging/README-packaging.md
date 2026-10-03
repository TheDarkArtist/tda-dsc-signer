# Maintainer runbook: AUR package `tda-dsc-signer`

Files here: `PKGBUILD`, `.SRCINFO`, `tda-dsc-signer.install`, and the optional `ccid-innait/` package.
The AUR repo is a separate git repo that holds only `PKGBUILD`, `.SRCINFO` and `tda-dsc-signer.install`.

## Release / update checklist

1. Bump the version in three places and keep them equal: `version` in `pyproject.toml`, `pkgver` in `PKGBUILD`
   (reset `pkgrel=1`), and a new `<release version=".." date="..">` entry (newest first) in
   `data/in.tdacorp.DscSigner.metainfo.xml`. Update `CHANGELOG.md`.
2. Run the checks: `uv run pytest`, `appstreamcli validate --pedantic --no-net data/in.tdacorp.DscSigner.metainfo.xml`
   (the only expected note is `cid-contains-uppercase-letter`, dictated by the GTK application id),
   `desktop-file-validate data/in.tdacorp.DscSigner.desktop`.
3. Commit, then tag and push: `git tag -a vX.Y.Z -m vX.Y.Z && git push origin main vX.Y.Z`.
4. In `packaging/`: `updpkgsums` (downloads the tag archive and writes `sha256sums`), then
   `makepkg --printsrcinfo > .SRCINFO`. Commit both in the source repo.
5. Test build. Preferred, in a clean chroot (package `devtools`):
   `extra-x86_64-build` (AUR dependencies such as `python-pyhanko` are not in the chroot: build them first and pass
   each with `-- -I /path/to/pkg.tar.zst`). Quick alternative: `makepkg -f --nodeps`.
   Then `namcap PKGBUILD *.pkg.tar.zst` if namcap is installed, and check `tar tf` of the package.
6. Publish to the AUR:

       git clone ssh://aur@aur.archlinux.org/tda-dsc-signer.git aur-tda-dsc-signer
       cp PKGBUILD .SRCINFO tda-dsc-signer.install aur-tda-dsc-signer/
       cd aur-tda-dsc-signer
       makepkg --printsrcinfo | diff - .SRCINFO     # must be empty
       git add PKGBUILD .SRCINFO tda-dsc-signer.install
       git commit -m "Update to X.Y.Z"              # first upload: "Initial import: tda-dsc-signer X.Y.Z"
       git push

   The first push to the empty repo creates the package. The default branch must be `master`.

## Notes

- `python-pyhanko` is AUR-only (third-party maintained); AUR helpers resolve it, plain `makepkg -s` does not.
  Re-check that every `depends`/`optdepends` name still resolves before each release (`pacman -Si`, AUR RPC).
- `check()` runs only hardware- and display-free tests with `PYTHONPATH=src python -m pytest`. The SoftHSM
  end-to-end test is excluded; other SoftHSM-based tests skip themselves when `softhsm` is absent.
- Out-of-date flagging: use "Flag package out-of-date" on the AUR package page when a new upstream release is
  published and the AUR copy lags; as maintainer, just push the update.
- Never run sudo from the package. The `.install` message only tells the user to run `tda-dsc-signer doctor`
  and `tda-dsc-signer trust install` themselves.

## Optional: `ccid-innait/` split package (not published by default)

Pacman hook that adds the InnaIT token (USB `338c:0031`) to the `ccid` device list. It MODIFIES A FILE OWNED BY
`ccid` (`Info.plist`), so `pacman -Qkk ccid` reports it as altered and a `ccid` upgrade rewrites it until the hook
re-patches it. Publish it as a separate AUR package (`tda-dsc-signer-ccid-innait`) only if that trade-off is
acceptable; the package-free alternative is to apply the same edit by hand and protect the file with `NoUpgrade`.
Build and release steps are the same as above, from within `ccid-innait/`.

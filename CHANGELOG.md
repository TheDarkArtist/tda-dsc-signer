# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-04

First public release.

### Added

- **GUI**: native GTK4 window with an adaptive layout (two-pane down to a narrow strip), PDF preview, drag-to-draw signature
  boxes with move/resize, per-box signer, Signatures list, toast with verification details.
- **MCA mode**: detects empty `sigfield<N>_<PAN>` signature fields, matches each to the attached token by `sha256(PAN)`, signs the
  checked fields into their own geometry, leaves other fields empty for the next signer, chains outputs.
- **General mode**: visible or invisible PAdES signatures at free positions, several boxes with different signers in one run.
- **CLI** `tda-dsc-signer` (alias `dsc-sign`): `list`, `sign`, `fields`, `pin`, `trust`, `doctor`.
- **Tokens**: PKCS#11 discovery through p11-kit, known vendor libraries, `DSC_MODULES` and `extra_modules`, OpenSC fallback.
  Verified on InnaIT hardware only.
- **Module host**: each PKCS#11 driver runs in its own hardened subprocess with timeouts, an exclusive per-driver lock and strict module-file checks.
- **PIN safety**: one login per action, never retried; wrong-PIN memory; locked-token and final-try guards; optional saved PIN
  (session memory or system keyring through libsecret), no plaintext fallback.
- **Verification** after signing (unmodified, signature, issuer, revocation reported as unchecked) and a bundled, pinned CCA India
  2022 trust bundle with a dedicated NSS database for `pdfsig`.
- **Optional timestamping** (PAdES-B-T) through a configured timestamp server.
- **Packaging**: `make install`, desktop entry, icon, AppStream metainfo, AUR `PKGBUILD`, man page.
- **Tests**: unit tests, SoftHSM end-to-end signing, and a GUI harness on Xvfb with fake tokens (no hardware or PIN needed).

### Known limitations

- MCA portal acceptance and the signature format it expects are unverified.
- Tokens other than InnaIT are untested; Adobe Acrobat trust display is untested.
- Revocation is never checked.

[Unreleased]: https://github.com/TheDarkArtist/tda-dsc-signer/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/TheDarkArtist/tda-dsc-signer/releases/tag/v0.1.0

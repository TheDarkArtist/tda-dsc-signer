# Third-party notices

tda-dsc-signer itself is GPL-3.0-or-later (see `LICENSE`). The following bundled material has its own terms.

## Noto Sans Regular (font)

- File: `src/tda_dsc_signer/fonts/NotoSans-Regular.ttf`, license text in `src/tda_dsc_signer/fonts/OFL.txt`.
- License: SIL Open Font License 1.1.
- Copyright 2022 The Noto Project Authors (https://github.com/notofonts/latin-greek-cyrillic), as stated in the font's own name table (version 2.015).
- Used unmodified to draw the visible signature stamp.

## Public CA certificates

- Files: `src/tda_dsc_signer/trust/certs/*.der`.
- Public certificates published by the Controller of Certifying Authorities, India (CCA), and by the licensed certifying authorities named in `src/tda_dsc_signer/trust/pins.py`. They contain no secrets.
- Each file is pinned by SHA-256 in `trust/pins.py`; the official download URLs (cca.gov.in, certificate.digital) are recorded there.

## TDACorp logo

- Files: `src/tda_dsc_signer/gui/tda-logo.svg` and `data/tda-logo.svg`.
- The TDACorp brand mark, used with the owner's permission. It is not covered by the GPL; no right to reuse it elsewhere is granted.

## Python dependencies

Dependencies keep their own licenses (for example pyHanko, python-pkcs11 and asn1crypto are MIT). They are listed in `pyproject.toml`; `uv export` gives the resolved set.

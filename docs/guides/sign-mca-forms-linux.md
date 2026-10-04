title: How to sign MCA forms with a DSC on Linux
description: Step by step: sign the empty signature fields of an MCA form with a DSC USB token on Linux. PAN matching, GUI and command line, and what is unverified.
---
# How to sign MCA forms with a DSC on Linux

MCA forms ship **empty signature fields** named `sigfield<N>_<PAN>`, for example `sigfield2_PQRST5678K`.
DSC Signer fills those fields in place with your token's certificate. This guide shows the GUI and the command line.

## Before you start

- Install DSC Signer ([Arch/AUR guide](install-arch-aur.html) or from source) and your token vendor's PKCS#11 driver. No driver is bundled.
- Plug in the token and check it is seen: `tda-dsc-signer list`.
- If nothing is listed, see [troubleshooting](troubleshooting.html).

## How a field is matched to your token

An Indian DSC carries the SHA-256 of the holder's PAN (lowercase hex) as the subject `serialNumber`.
DSC Signer hashes the PAN from each field name and compares it with the certificate on each attached token. A match is shown as "PAN matches".
If a field's PAN does not match the certificate, signing is refused before any PIN is requested (override: `--allow-pan-mismatch`).

## In the window

1. Run `tda-dsc-signer FORM.pdf`. A PDF with empty signature fields opens in MCA mode.
2. The panel lists each field with its page and masked PAN, and which attached token matches it.
3. Tick the fields to sign, then press **Sign Document** (Ctrl+S).
4. Enter the token PIN in the popover. Each token is asked once per signing run.
5. Choose where to save. The input is never overwritten; fields you did not tick stay empty for the next signer.

## On the command line

```
tda-dsc-signer fields FORM.pdf                 # fields, pages, masked PANs, matching token (no PIN)
tda-dsc-signer sign FORM.pdf --field sigfield2_PQRST5678K -t 1
tda-dsc-signer sign FORM.pdf --all-fields      # every empty field with a matching attached token
```

When several people must sign, each signer repeats the run on the previous output. Outputs are never merged or overwritten.

## What is not verified

- **Acceptance by the MCA portal is not verified.** The portal's rules are not public to this tool. The signature subfilter the portal expects is unknown: the default is `adbe.pkcs7.detached` for fields, switchable with `--format pades`.
- Only InnaIT tokens have been tested. See [supported tokens](supported-tokens.html).
- The 2 MB size warning of the `mca` profile reflects reported limits, not a check against the portal.

DSC Signer is not affiliated with the Ministry of Corporate Affairs, the CCA or any certifying authority.

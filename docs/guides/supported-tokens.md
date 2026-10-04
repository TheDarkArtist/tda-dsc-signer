title: Supported DSC USB tokens on Linux
description: Which DSC USB tokens work with DSC Signer on Linux: InnaIT is verified, others are untested. How tokens are found and how to report your token.
---
# Supported DSC USB tokens on Linux

DSC Signer talks PKCS#11, so in principle any token with a Linux PKCS#11 library can work. In practice only some are verified.

| Token / driver | Status |
| --- | --- |
| InnaIT (Precision Biometric) | Verified |
| Other vendors (for example ePass2003, WatchData, eToken) | Untested |

"Untested" does not mean "unsupported", and it does not mean "works". If you try one, please report the result on the [issue tracker](https://github.com/TheDarkArtist/tda-dsc-signer/issues).

## How tokens are found

- Modules come from p11-kit registrations, a table of known vendor library paths, the `DSC_MODULES` environment variable and `extra_modules` in the config. OpenSC is a last-resort fallback.
- `p11-kit-proxy.so` is never used.
- The driver runs in its own subprocess, never inside the GUI or CLI process.
- Run `tda-dsc-signer list` to see what is found, and `tda-dsc-signer doctor` to diagnose.

## Class 3 certificates

DSC Signer reads whatever signing certificates the driver exposes. Whether a certificate is Class 2 or Class 3 is a property of the certificate your authority issued, not something this tool decides.

## No bundled driver

Install your vendor's driver yourself. See [install](install-arch-aur.html) and [troubleshooting](troubleshooting.html).

title: DSC USB token not detected on Linux: troubleshooting
description: Fix a DSC USB token that is not detected on Linux: pcscd, CCID, the vendor driver, driver clashes between programs, launcher PATH and Seahorse notes.
---
# DSC USB token not detected on Linux: troubleshooting

Start with `tda-dsc-signer doctor`. It checks pcscd, USB, the CCID plist, the pacman hook and the driver, and prints the sudo fixes it suggests. It never runs sudo.

## "No tokens found" although the token is plugged in

PC/SC readers and vendor drivers **cannot be shared between processes**. If another program (another signer, a browser extension host, an OpenSC tool) holds the driver, a second process silently sees no tokens.

- DSC Signer takes an exclusive per-driver lock. The message "token driver ... is in use by another tda-dsc-signer" names the holder's PID. Close that instance, or use `--wait-driver SECONDS`. `list` and `sign` exit with status 3 while the driver is busy.
- OpenSC is only a fallback and can disturb the vendor driver. Set `opensc_fallback = "never"` in `~/.config/tda-dsc-signer/config.toml` (or `--opensc-fallback never`) to switch it off.
- "N token device(s) detected but the driver returned M": the scan is repeated up to 3 times, then the mismatch is reported.

## The driver is not found

DSC Signer only loads modules that are absolute regular files owned by root or you, and not group- or world-writable. A module you own must be allowed explicitly with `--allow-user-module PATH` or `allowed_modules = [...]` in the config. Refusals are printed on stderr by `list`.

## First run is slow

The InnaIT driver sleeps about 7 seconds on its first call per process. The GUI starts it at launch.

## The launcher says "failed to open"

A graphical session's `PATH` often lacks `~/.local/bin`. `make install` writes the desktop entry with an absolute path; re-run it after moving the prefix. `tda-dsc-signer doctor` prints the exact one-line fix.

## Wrong PIN

Each signing run makes exactly one login and never retries: a wrong PIN counts against the token's retry limit. After a wrong PIN, the next attempt within 5 minutes needs confirmation ("Try anyway", or `--confirm-after-failure`). If the token reports its last try, `--confirm-final-try` is required. InnaIT tokens set no retry flags, so the absence of a warning does not mean retries are left.

## Seahorse and saved PINs

Saved PINs (optional, off by default) use the system Secret Service. KeePassXC with Secret Service Integration, or gnome-keyring, provides it; Seahorse is only a viewer for gnome-keyring. If no Secret Service is running, `keyring` mode is refused and there is no plaintext fallback. A PIN is never written to the config file.

## Still stuck

Run with `DSC_DEBUG=1 tda-dsc-signer ...` for one diagnostic line per step (a PIN is never printed) and open an issue: https://github.com/TheDarkArtist/tda-dsc-signer/issues

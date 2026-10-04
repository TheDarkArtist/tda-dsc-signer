# CLI reference

Derived from `tda-dsc-signer --help` and each subcommand's `--help`. The command `dsc-sign` is a short alias for `tda-dsc-signer`.

    tda-dsc-signer [--version] [file.pdf]
    tda-dsc-signer {list,trust,doctor,fields,sign,pin} ...

There is no `gui` subcommand: running `tda-dsc-signer` with no arguments, or with a `.pdf` path, opens the GUI.
`PAGE` is 1-based and `-1` is the last page. A box is `X1,Y1,X2,Y2` in PDF points, origin bottom-left.

## Options shared by `list`, `fields`, `sign` and `pin`

| Flag | Meaning |
| --- | --- |
| `--wait-driver SECONDS` | Wait this long for another tda-dsc-signer to release the driver (default 0). |
| `--opensc-fallback {auto,never,always}` | OpenSC probe. `auto` (default): only if no vendor module exists and no driver is busy. Overrides the config value. |
| `--allow-user-module PATH` | Permit this user-owned PKCS#11 module for this run. |

## `list`

Lists the signing certificates on attached tokens. No PIN, no login. The numbers shown are what `-t` takes elsewhere.

## `fields INPUT`

Lists the signature fields of a PDF: name, page, masked PAN, signed or unsigned, and which attached token matches each PAN. No PIN.

## `sign INPUT`

| Flag | Meaning |
| --- | --- |
| `-o, --output OUTPUT` | Default `<name>-signed.pdf`. Never the input file. |
| `-p, --page PAGE` | Page for a drawn box. |
| `-b, --box BOX` | Box `X1,Y1,X2,Y2`. |
| `-t, --token TOKEN` | Token number from `list`. Needed when several tokens are attached. |
| `--profile {mca,general}` | `mca` (default) is size-checked for MCA uploads (warns above 2 MB; that limit is as reported, not verified against the portal). |
| `--invisible` | Invisible signature: no box, page ignored. |
| `--field NAME` | Sign into this existing empty signature field (see `fields`). Box, page and `--invisible` do not apply. |
| `--all-fields` | Sign every empty field whose PAN matches an attached token; the rest are listed. Cannot be combined with `--field`. |
| `--allow-pan-mismatch` | Sign a PAN-named field with a certificate that does not match the PAN. |
| `--format {auto,pades,adbe}` | `auto`: `adbe.pkcs7.detached` for fields, PAdES for drawn boxes. |
| `--pin-fd N` | Read the PIN (one line) from inherited file descriptor N. The prompt is preferred. |
| `--saved-pin` | Use the PIN saved for this token (see `pin set`); prompts when none is saved. |
| `--confirm-final-try` | Allow the login when the token reports its last PIN try. |
| `--confirm-after-failure` | Allow a login within 5 minutes of a recorded wrong PIN on this token. |
| `--force` | Overwrite the output file if it already exists. |

## `pin`

| Command | Meaning |
| --- | --- |
| `pin status` | Per token: mode, and whether a PIN is saved. Never prints a PIN. |
| `pin set -t TOKEN [--mode {session,keyring}] [--pin-fd N]` | Save a PIN (prompt or `--pin-fd`). No login happens. |
| `pin forget [-t TOKEN] [--all]` | Delete a saved PIN. One of the two is required. |

## `trust`

| Command | Meaning |
| --- | --- |
| `trust install [--db DB] [--force-db] [--old-roots]` | Create or update the dedicated NSS database (default `~/.local/share/tda-dsc-signer/nssdb`). `--force-db` allows a `--db` outside that directory (other software's databases are always refused). `--old-roots` also trusts the expired CCA India 2014/2011 roots. |
| `trust status [--db DB]` | List pinned certificates and what the database contains. |
| `trust fetch [--dir DIR]` | Re-download the certificates from the official URLs and verify them against the pins. |

Check a signed file against the dedicated database with poppler: `pdfsig -nssdir ~/.local/share/tda-dsc-signer/nssdb signed.pdf`.

## `doctor`

Checks pcscd, USB, the CCID plist, the pacman hook, the driver, the desktop entry and driver exclusivity. Prints the fix (a `sudo` command where needed) and never runs it.

## Exit codes (read from `cli.py` and `doctor.py`)

| Code | Where | Meaning |
| --- | --- | --- |
| 0 | all | Success. |
| 1 | `doctor` | At least one check failed. Also: an error message exit (for example no token found, `-t` out of range, `pin forget` without `--token`/`--all`, a failed signing attempt with an exception). |
| 2 | `sign` | Signing ran but the post-sign verification failed. |
| 3 | `list`, `sign` | Another tda-dsc-signer holds the driver, so an empty or partial list means "busy". |

## PIN input

In order of preference: the interactive prompt, `--pin-fd N`, the `PYHANKO_PKCS11_PIN` environment variable. The variable is removed
from the process environment at startup so children cannot inherit it, but it stays visible to anything that can read the
launching shell's environment or history. The PIN is never stored (unless you opt in with `pin set`).

## Configuration

`~/.config/tda-dsc-signer/config.toml` (or `$XDG_CONFIG_HOME/tda-dsc-signer/config.toml`), flat keys, written atomically with mode 0600.
Unknown keys are ignored; an invalid `signature_format` or `default_mode` falls back to the default with a warning.

| Key | Default | Meaning |
| --- | --- | --- |
| `extra_modules` | `[]` | Extra PKCS#11 module paths to scan. |
| `allowed_modules` | `[]` | User-owned module paths that may be loaded. |
| `opensc_fallback` | `"auto"` | `auto`, `never` or `always`. |
| `stamp_text` | `"Digitally signed by\n%(signer)s\nDate: %(ts)s"` | Text of the visible signature. |
| `default_box` | `[300, 40, 560, 110]` | Box used when none is given. |
| `last_token`, `last_page`, `last_box` | | Remembered by the GUI. |
| `profile` | `"mca"` | `mca` or `general`. |
| `timestamp_url` | `""` | Set to enable PAdES-B-T. |
| `signature_format` | `"auto"` | `auto`, `pades` or `adbe`. |
| `default_mode` | `"auto"` | `auto`, `mca` or `general`; read by the GUI only. |
| `pin_modes` | `{}` | Token serial to `ask`, `session` or `keyring`. Modes only, never a PIN. |

## Environment variables

| Variable | Effect |
| --- | --- |
| `DSC_DEBUG` | Non-empty: one diagnostic line per signing step on stderr, and the module host's stderr. Never prints a PIN. |
| `DSC_MODULES` | Colon-separated PKCS#11 module paths added to the scan. |
| `PYHANKO_PKCS11_PIN` | One-off PIN (see above). |
| `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_RUNTIME_DIR` | Locations of the config, the desktop entry check, and runtime state (lock files and the wrong-PIN record). |

## Files

| Path | Content |
| --- | --- |
| `~/.config/tda-dsc-signer/config.toml` | Configuration (no PINs). |
| `~/.local/share/tda-dsc-signer/nssdb` | Dedicated NSS trust database. |
| `$XDG_RUNTIME_DIR/tda-dsc-signer/` (fallback `~/.cache/tda-dsc-signer/`) | Per-driver lock files and the wrong-PIN record (serial, time, count; mode 0700/0600). |

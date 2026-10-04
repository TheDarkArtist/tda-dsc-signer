# Security

## Threat model

Protected: the token PIN and the ability to sign. Not protected against: a fully compromised user account, a malicious vendor
driver, or someone with physical access to an unlocked session with the token plugged in.

In scope:

- other local processes of the same user that try to read the PIN (environment, core dumps, `/proc/PID/mem`, ptrace);
- a hostile working directory (shadow `tda_dsc_signer/`, `pkcs11.py`, `pyhanko/` in the cwd);
- hostile or buggy tokens and modules (malformed certificates, garbage on the host pipe, oversized replies, hangs);
- tampered or substituted trust anchors; accidental use of another application's NSS database;
- tricking the user into repeated wrong PINs that lock the token.

## PIN handling

- Never stored, logged or put on a command line. It exists in the GUI/CLI process for one call and in the module host for one
  `sign` request; it travels over the host's stdin pipe only.
- Preferred input is the interactive prompt (GUI popover or `getpass`). `--pin-fd N` reads one line from an inherited
  descriptor. `PYHANKO_PKCS11_PIN` is supported for one-offs, is popped from `os.environ` at startup and is never passed on,
  but it is visible to whoever can read the launching shell's environment or history.
- One `C_Login` per signing action, never retried. A wrong PIN is recorded (serial + time + count, no PIN) so the next attempt
  within 5 minutes needs explicit confirmation; locked tokens and a final try are refused before any login.

## Saved PINs (opt-in)

When the user enables it for a token, the PIN is kept in the system Secret Service (libsecret) or, for "until I close the app", in
process memory. Residual risk, stated plainly: anything running as your user while the keyring is unlocked can read that PIN and
therefore sign with a plugged-in token without you typing anything. PINs are stored only in libsecret because it is the one
store that is encrypted at rest and gated by the user's keyring unlock; no plaintext fallback exists (no keyring means the feature
refuses). The PIN is never in `config.toml` (only the mode is), logs, argv, environment, exception text or the wrong-PIN record. A
wrong saved PIN is deleted on the first rejection and never retried, so it cannot burn the token's retry counter. The save itself
performs no login. Signing still requires an explicit action each time.

## What the module host isolates

The vendor `.so` is loaded only in a per-module subprocess started as `python -I -m tda_dsc_signer.host` (cwd `/`, minimal
environment, no core dumps, not dumpable). The parent applies a timeout per request, kills a hung or misbehaving host, caps a
protocol line at 8 MB, and validates every reply. Modules must be root-owned (or explicitly allowed), not group/world-writable.
Signing a PDF runs inside the host; a sign request is never resent.

## Trust store

The CCA India 2022 root is the only trust anchor, pinned by SHA-256 in `trust/pins.py`. `trust install` only writes into the
dedicated NSS database under `~/.local/share/tda-dsc-signer` (anything else needs `--force-db`; other software's databases are
always refused), checks that an existing nickname really holds the pinned certificate before changing its trust, and demotes
the expired old roots unless `--old-roots` is given.

## MCA form fields: PAN guard

Signing into a PAN-named field requires the certificate subject `serialNumber` to equal `sha256(PAN)`; otherwise `PanMismatch` is raised
before any login (override: `--allow-pan-mismatch`). This is NOT verified: that the PAN belongs to the named director (only the
certificate-to-field PAN match is checked), what the MCA portal accepts server-side (SubFilter, appearance), XFA-dynamic forms,
certificates without a PAN hash in serialNumber (allowed with a warning), and field `/Lock` actions (read, not enforced).

## Known limitations

- The host is not sandboxed (same uid, no seccomp, no namespaces); a malicious but root-installed driver is trusted.
- python-pkcs11 leaves the session open after a failed login until the host exits.
- Revocation is never checked (nothing is embedded or fetched).
- A user with the same uid can still read the GUI/CLI process memory while a PIN is typed (the host is non-dumpable; the
  front-end is not).

## Reporting a vulnerability

Please report privately through GitHub: open the repository's **Security** tab, choose **Advisories**, then **Report a vulnerability**
(<https://github.com/TheDarkArtist/tda-dsc-signer/security/advisories/new>). Do not open a public issue for a vulnerability.
Include the version (`tda-dsc-signer --version`), what you ran and what happened. Do not include PINs, real documents or token dumps.

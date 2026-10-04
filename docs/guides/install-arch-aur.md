title: Install DSC Signer on Arch Linux (AUR)
description: Install the DSC Signer GTK4 PDF signer on Arch Linux from the AUR or from source, plus the token driver and pcscd setup it needs.
---
# Install DSC Signer on Arch Linux

## From the AUR

The AUR package is named `tda-dsc-signer`:

```
yay -S tda-dsc-signer        # or paru -S tda-dsc-signer, or build the PKGBUILD by hand
```

Check the package page and read the PKGBUILD before installing; AUR packages are user-submitted.

## From source

System dependencies: `gtk4`, `poppler-glib`, `python-gobject`, `pcsclite` and `ccid`.

```
git clone https://github.com/TheDarkArtist/tda-dsc-signer
cd tda-dsc-signer
uv venv --system-site-packages --python /usr/bin/python3
make install        # venv in ~/.local/share/tda-dsc-signer, command in ~/.local/bin
```

The virtual environment must see the system `gi`, which is why a plain `uv tool install` does not work.
Update by running `make install` again; remove with `make uninstall`.

## The token driver

DSC Signer does **not** bundle a vendor PKCS#11 driver. Install the one for your token.
For InnaIT tokens the library is `/opt/Precision_Biometric/InnaITDSC/libraries/libInnaITPKCS11Driver.so`.
Enable the smart card daemon:

```
sudo systemctl enable --now pcscd.socket
tda-dsc-signer doctor     # checks pcscd, USB, the CCID plist and the driver; prints the exact sudo fixes
tda-dsc-signer list       # shows the signing certificates on attached tokens
```

`doctor` never runs sudo itself. If `list` finds nothing, read [troubleshooting](troubleshooting.html).

## Manual page

`man tda-dsc-signer` documents every command and option.

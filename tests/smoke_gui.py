"""Manual GUI smoke with a fake token backend (no hardware, no real PIN). Run under a throwaway X server:

xvfb-run -a -s "-screen 0 1280x1000x24" .venv/bin/python tests/smoke_gui.py OUT_DIR
"""

import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
out_dir = sys.argv[1]
import isolate  # noqa: E402

isolate.isolate()  # never touch the real config

import conftest  # noqa: E402
from asn1crypto import keys as akeys  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from gi.repository import GLib  # noqa: E402
from pkcs11 import Mechanism  # noqa: E402
from pyhanko.sign import signers  # noqa: E402
from pyhanko_certvalidator.registry import SimpleCertificateStore  # noqa: E402

from tda_dsc_signer import config, signing, tokens, verify  # noqa: E402
from tda_dsc_signer.backend import Backend  # noqa: E402
from tda_dsc_signer.gui.app import App  # noqa: E402  # noqa: E402

root, rk = conftest.make_cert("Test Root", ca=True, ku=conftest.ku(key_cert_sign=True))
sub, sk = conftest.make_cert("Test Sub CA", root, rk, ca=True, ku=conftest.ku(key_cert_sign=True))
leaf, lk = conftest.make_cert("Fake Signer", sub, sk, ku=conftest.ku(digital_signature=True))
cert = tokens.TokenCert(
    "fake.so", 0, "Fake Token", "F1", "L", conftest.der(leaf), "Fake Signer", "Fake Org", "2099-01-01", (conftest.der(sub), conftest.der(root))
)
calls = {"pins": []}


def fake_sign(src, c, **kw):
    def open_session(cert, user_pin, confirm=False):
        calls["pins"].append(user_pin)
        return type("S", (), {"close": lambda self: None})()

    def make_signer(session, signing_cert, ca_chain, **_kw):
        key = akeys.PrivateKeyInfo.load(lk.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        store = SimpleCertificateStore()
        store.register_multiple(ca_chain or [])
        return signers.SimpleSigner(signing_cert=signing_cert, signing_key=key, cert_registry=store, embed_roots=True)

    return signing.sign_pdf(src, c, open_session=open_session, make_signer=make_signer, mechanisms=lambda s: {Mechanism.SHA256_RSA_PKCS}, **kw)


pdf = os.path.join(out_dir, "smoke.pdf")
conftest.make_pdf(pdf, 3)
signed = os.path.join(out_dir, "smoke-signed.pdf")


def fake_discover(extra):
    return [cert]


app = App(pdf, Backend(fake_discover, fake_sign, verify.verify_signed), config.Config())
state = {"step": 0}


def shot(name):
    subprocess.run(["import", "-window", "root", os.path.join(out_dir, name)], check=False)


def tick():
    w = app.window
    if state["step"] == 0 and w and w.picker.cert:
        w.stack.show_selection(1, (50, 50, 300, 120))
        state["step"] = 1
        GLib.timeout_add(600, lambda: (shot("smoke1.png"), w.do_sign(signed, "throwaway-pin"), False)[2])
    elif state["step"] == 1 and w.banner.get_visible():
        print("BANNER:", w.banner.label.get_text())
        print("PINS PASSED TO TOKEN:", calls["pins"])
        print("RELOADED:", w.path, "pages:", len(w.stack.pages))
        shot("smoke2.png")
        app.quit()
        return False
    return True


GLib.timeout_add(200, tick)
GLib.timeout_add(30000, lambda: (print("TIMEOUT"), app.quit(), False)[2])
app.run([])

"""Run in a child process (python-pkcs11 initialises a module once per process, so each throwaway token is built in a fresh one).

usage: softhsm_provision.py SPEC.json     (HOME must point at the dir holding .config/softhsm2/softhsm2.conf)
spec: {module, label, pin, cn, key_id_hex, key_label, issuer_key_pem, chain_der: [paths], decoy: bool}
decoy: also create a SECOND key pair with the same label but a different CKA_ID (and no certificate).
Writes the signer certificate DER to spec["leaf_out"].
"""

import json
import sys

import pkcs11
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pkcs11 import Attribute, CertificateType, KeyType, ObjectClass

spec = json.load(open(sys.argv[1]))
issuer_key = serialization.load_pem_private_key(open(spec["issuer_key_pem"], "rb").read(), None)
chain = [x509.load_der_x509_certificate(open(p, "rb").read()) for p in spec["chain_der"]]  # nearest issuer first
tok = next(t for t in (s.get_token() for s in pkcs11.lib(spec["module"]).get_slots(token_present=True)) if t.label == spec["label"])
kid = bytes.fromhex(spec["key_id_hex"])
with tok.open(rw=True, user_pin=spec["pin"]) as s:
    if spec.get("decoy"):  # created first, so a label-only lookup would find the WRONG key
        s.generate_keypair(KeyType.RSA, 2048, store=True, label=spec["key_label"], id=b"\x99")
    pub, _ = s.generate_keypair(KeyType.RSA, 2048, store=True, label=spec["key_label"], id=kid)
    nums = rsa.RSAPublicNumbers(int.from_bytes(pub[Attribute.PUBLIC_EXPONENT], "big"), int.from_bytes(pub[Attribute.MODULUS], "big"))
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, spec["cn"])]
        + ([x509.NameAttribute(NameOID.SERIAL_NUMBER, spec["subject_serial"])] if spec.get("subject_serial") else [])
    )
    ku = x509.KeyUsage(True, True, False, False, False, False, False, False, False)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(chain[0].subject)
        .public_key(nums.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(chain[0].not_valid_before_utc)
        .not_valid_after(chain[0].not_valid_after_utc)
        .add_extension(ku, critical=True)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(chain[0].public_key()), critical=False)
        .sign(issuer_key, hashes.SHA256())
    )
    open(spec["leaf_out"], "wb").write(leaf.public_bytes(serialization.Encoding.DER))
    for label, cert, ident in [("signer", leaf, kid), *((c.subject.rfc4514_string(), c, b"") for c in chain)]:
        s.create_object(
            {
                Attribute.CLASS: ObjectClass.CERTIFICATE,
                Attribute.CERTIFICATE_TYPE: CertificateType.X_509,
                Attribute.LABEL: label,
                Attribute.ID: ident,
                Attribute.SUBJECT: cert.subject.public_bytes(),
                Attribute.VALUE: cert.public_bytes(serialization.Encoding.DER),
                Attribute.TOKEN: True,
            }
        )

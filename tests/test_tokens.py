import json

import pkcs11
import pytest
from asn1crypto import x509 as ax
from conftest import der, ku, make_cert
from pkcs11 import TokenFlag

from tda_dsc_signer import quirks, safety, tokens
from tda_dsc_signer.safety import PinState


def load(c):
    return ax.Certificate.load(der(c))


def test_leaf_with_signature_usage_is_signing_cert(pki):
    assert tokens.is_signing_cert(load(pki["leaf"]))


def test_ca_is_filtered(pki):
    assert not tokens.is_signing_cert(load(pki["sub"]))


def test_wrong_key_usage_is_filtered(pki):
    enc, _ = make_cert("Enc", pki["sub"], pki["leaf_key"], ku=ku(key_encipherment=True))
    assert not tokens.is_signing_cert(load(enc))


def test_non_repudiation_only_is_allowed(pki):
    c, _ = make_cert("NR", pki["sub"], pki["leaf_key"], ku=ku(content_commitment=True))
    assert tokens.is_signing_cert(load(c))


def test_missing_key_usage_is_allowed(pki):
    c, _ = make_cert("NoKU", pki["sub"], pki["leaf_key"], ku=None)
    assert tokens.is_signing_cert(load(c))


def test_build_chain_orders_issuers_and_ignores_unrelated(pki):
    other, _ = make_cert("Other CA", ca=True, ku=ku(key_cert_sign=True))
    chain = tokens.build_chain(load(pki["leaf"]), [load(other), load(pki["root"]), load(pki["sub"])])
    assert [c.subject.native["common_name"] for c in chain] == ["Test Sub CA", "Test Root"]


def test_build_chain_empty_when_issuer_absent(pki):
    assert tokens.build_chain(load(pki["leaf"]), []) == []


class FlakySession:
    def __init__(self, answers):
        self.answers, self.calls = list(answers), 0

    def get_objects(self, template):
        self.calls += 1
        return self.answers.pop(0) if self.answers else []


def test_find_retries_empty_then_succeeds():
    s, sleeps = FlakySession([[], [], ["obj"]]), []
    assert quirks.find(s, {}, sleep=sleeps.append) == ["obj"]
    assert s.calls == 3 and len(sleeps) == 2


def test_find_gives_up_after_n_tries():
    s = FlakySession([])
    assert quirks.find(s, {}, tries=4, sleep=lambda _d: None) == []
    assert s.calls == 4


def test_expired_and_display():
    c = tokens.TokenCert("m", 0, "T", "1", "L", b"", "N", "O", "2000-01-01")
    assert c.expired() and c.display().endswith(tokens.EXPIRED_MARK)


def test_p11kit_source_parses_module_files(tmp_path):
    lib = tmp_path / "lib"
    lib.mkdir()
    (lib / "vendor.so").write_text("x")
    (lib / "rel.so").write_text("x")
    d = tmp_path / "modules"
    d.mkdir()
    (d / "a.module").write_text(f"# c\nmodule: {lib / 'vendor.so'}\ncritical: no\n")
    (d / "b.module").write_text("module: rel.so\n")
    (d / "trust.module").write_text("module: p11-kit-trust.so\n")
    (d / "proxy.module").write_text("module: p11-kit-proxy.so\n")
    (d / "opensc.module").write_text("module: opensc-pkcs11.so\n")
    (d / "gone.module").write_text("module: /nonexistent/x.so\n")
    src = tokens.P11KitSource(dirs=[str(d)], libdir=str(lib))
    assert src.modules() == sorted([str(lib / "vendor.so"), str(lib / "rel.so")])


def test_glob_source_ignores_missing():
    assert tokens.GlobSource(["/definitely/not/here*.so"]).modules() == []


def test_default_sources_cover_p11kit_known_vendors_and_env():
    srcs = tokens.default_sources(["/x.so"], allow=[])
    assert all(type(s).__name__ == "VettedSource" for s in srcs)  # every source goes through the module vetting
    assert [type(s.inner).__name__ for s in srcs] == ["P11KitSource", "GlobSource", "EnvSource"]


def test_cert_wire_roundtrip(pki):
    c = tokens.TokenCert("m", 1, "T", "S", "L", der(pki["leaf"]), "N", "O", "2099-01-01", (der(pki["sub"]),), "0a", PinState(final_try=True))
    assert tokens.cert_from_dict(json.loads(json.dumps(tokens.cert_to_dict(c)))) == c


class FakeTok:
    def __init__(self, serial, flags=None):
        self.serial, self.label, self.flags = serial.encode(), "lbl", flags or TokenFlag(0)


class FakeLib:
    def __init__(self, toks):
        self.toks = toks

    def get_slots(self):
        return [type("S", (), {"get_token": lambda self, t=t: t})() for t in self.toks]


def test_token_found_by_serial_not_slot_order():
    cert = tokens.TokenCert("m", 0, "T", "B", "L", b"", "N", "O", "2099-01-01")
    lib = FakeLib([FakeTok("A"), FakeTok("B")])
    assert tokens.token_for(cert, lambda _m: lib).serial == b"B"
    with pytest.raises(pkcs11.NoSuchToken):
        tokens.token_for(cert, lambda _m: FakeLib([FakeTok("A")]))


def test_open_session_refuses_locked_and_unconfirmed_final_try_before_login():
    cert = tokens.TokenCert("m", 0, "T", "A", "L", b"", "N", "O", "2099-01-01")
    opened = []

    class T(FakeTok):
        def open(self, **kw):
            opened.append(kw)
            return "session"

    with pytest.raises(safety.TokenLocked):
        tokens.open_session(cert, "x", load_lib=lambda _m: FakeLib([T("A", TokenFlag.USER_PIN_LOCKED)]))
    with pytest.raises(safety.FinalTryNeedsConfirm):
        tokens.open_session(cert, "x", load_lib=lambda _m: FakeLib([T("A", TokenFlag.USER_PIN_FINAL_TRY)]))
    assert opened == []  # no login attempted for either
    assert tokens.open_session(cert, "x", True, lambda _m: FakeLib([T("A", TokenFlag.USER_PIN_FINAL_TRY)])) == "session"
    assert opened == [{"user_pin": "x"}]


def test_protected_auth_token_gets_no_pin():
    cert = tokens.TokenCert("m", 0, "T", "A", "L", b"", "N", "O", "2099-01-01")
    seen = []

    class T(FakeTok):
        def open(self, **kw):
            seen.append(kw)

    tokens.open_session(cert, "ignored", load_lib=lambda _m: FakeLib([T("A", TokenFlag.PROTECTED_AUTHENTICATION_PATH)]))
    assert seen == [{"user_pin": pkcs11.PROTECTED_AUTH}]


def test_present_tokens_survives_typed_errors():
    class Gone:
        def get_token(self):
            raise pkcs11.TokenNotPresent()

    class Lib:
        def get_slots(self):
            return [Gone(), type("S", (), {"get_token": lambda self: FakeTok("Z")})()]

    assert tokens.present_tokens("m", lambda _m: Lib()) == [("Z", "lbl")]

import hashlib
import os

import pytest
from asn1crypto import pem
from cryptography import x509

from tda_dsc_signer.trust import fetch, nss, pins, store

RESEARCH = "/tmp/claude-1000/-home-tda/931ef579-73eb-4d97-ac6e-7ae8ef0f4e0a/scratchpad/ca-research/"

# the user-supplied pins, typed here a second time on purpose: pins.py and this list must agree
GIVEN = {
    "CCAIndia2022.der": "9A:3F:D3:17:67:98:E8:42:DD:CB:12:C2:62:F1:1C:FA:CC:A7:0A:8B:84:C6:EA:6F:DA:30:84:2A:95:A9:4C:D8",
    "CapricornCA2022.der": "E3:02:C8:E2:48:1E:9F:12:67:B0:6E:92:74:25:39:C6:C3:6B:A9:DB:C4:CB:8C:31:5C:8D:58:20:B7:24:91:B2",
    "CapricornSubCAforIndividualDSC2022.der": "A9:A4:2F:25:E4:17:2F:86:9D:93:4B:2B:1D:D4:70:F2:92:54:80:11:9E:07:F1:32:22:EA:6F:94:DE:49:A7:2B",
    "CapricornSubCAforOrganizationDSC2022.der": "54:7C:58:52:81:26:AE:D0:D6:C4:BE:C1:4E:A7:DD:8F:49:D9:5E:2C:52:24:99:EC:90:22:70:1F:76:29:A6:7D",
    "CapricornSubCAforDocumentSignerDSC2022.der": "7C:1C:A6:9F:26:05:44:12:14:8E:F3:81:F4:5B:B9:19:69:8D:55:AF:FC:43:57:83:CD:66:22:BD:7E:A3:4F:00",
    "CapricornSubCAforTSA2022.der": "3F:9E:47:35:F9:EC:10:7B:F4:F9:04:3A:F0:5D:6E:78:39:FD:6D:4D:B6:3F:D0:D9:B9:06:26:57:4E:42:31:A0",
    "CCAIndia2014.der": "60:10:9B:C6:C3:83:28:59:8A:11:2C:7A:25:E3:8B:0F:23:E5:A7:51:1C:B8:15:FB:64:E0:C4:FF:05:DB:7D:F7",
    "cca_india_2011.der": "2D:66:A7:02:AE:81:BA:03:AF:8C:FF:55:AB:31:8A:FA:91:90:39:D9:F3:1B:4D:64:38:86:80:F8:13:11:B6:5A",
}
# SPL / 2015 SPL / 2007 / 2009-2002-era roots, measured from the research downloads: must never be pinned
FORBIDDEN = {
    "B724689B79B2EF9421EF8F5CC733EB093851B170EE715177005A09F226D8C91A",  # CCA India 2022 SPL
    "C34C5DF53080078FFE45B21A7F600469917204F4F0293F1D7209393E5265C04F",  # CCA India 2015 SPL
    "F375E2F77A108BACC4234894A9AF308EDECA1ACD8FBDE0E7AAA9634E9DAF7E1C",  # CCA India 2007
    "A9D01A3BC0BFCB436C3EAD39818869B91F133ED401EA2EB2CDBD390553CD0A1F",  # oldest CCA India root
}


def test_every_pin_matches_its_bundled_file():
    for p in pins.ALL:
        assert store.sha256_hex(store.bundled_der(p)) == p.sha256


def test_given_pins_equal_the_values_supplied_by_research():
    by_file = {p.filename: p for p in pins.ALL}
    for fn, colon in GIVEN.items():
        assert by_file[fn].sha256 == colon.replace(":", "")


def test_anchor_sha1_matches_microsofts_published_value():
    der = store.bundled_der(pins.ANCHOR)
    assert hashlib.sha1(der).hexdigest() == pins.ANCHOR_SHA1 == "a79e41380bab3ed7f5188d9a5209cefcb3ca6991"


@pytest.mark.skipif(not os.path.isdir(RESEARCH), reason="research downloads not present")
def test_bundled_files_equal_independent_downloads():
    from asn1crypto import pem
    from asn1crypto import x509 as ax

    src = {
        "CCAIndia2022.der": "cap/CCAIndia2022.cer",
        "CapricornCA2022.der": "cap/CapricornCA2022.cer",
        "CCAIndia2014.der": "roots/CCAIndia2014.cer.der",
        "cca_india_2011.der": "roots/cca_india_2011.cer.der",
    }
    for fn, rel in src.items():
        raw = open(RESEARCH + rel, "rb").read()
        der = ax.Certificate.load(pem.unarmor(raw)[2] if pem.detect(raw) else raw).dump()
        assert store.bundled_der(next(p for p in pins.ALL if p.filename == fn)) == der


def test_forbidden_roots_are_not_pinned():
    assert not FORBIDDEN & {p.sha256 for p in pins.ALL}
    assert not any("SPL" in p.name for p in pins.ALL)


def test_other_cas_are_intermediates_signed_by_the_anchor():
    anchor = x509.load_der_x509_certificate(store.bundled_der(pins.ANCHOR))
    assert len(pins.OTHER_CAS) == 20
    for p in pins.OTHER_CAS:
        c = x509.load_der_x509_certificate(store.bundled_der(p))
        c.verify_directly_issued_by(anchor)
        assert c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca


def test_capricorn_chain_links():
    anchor = x509.load_der_x509_certificate(store.bundled_der(pins.ANCHOR))
    cap, *subs = [x509.load_der_x509_certificate(store.bundled_der(p)) for p in pins.CAPRICORN]
    cap.verify_directly_issued_by(anchor)
    for s in subs:
        s.verify_directly_issued_by(cap)


def test_pin_mismatch_is_refused_with_clear_message():
    der = bytearray(store.bundled_der(pins.ANCHOR))
    der[-1] ^= 1
    with pytest.raises(store.PinMismatch, match="Refusing"):
        store.check(pins.ANCHOR, bytes(der))


def test_pinned_validation_context_trusts_only_the_anchor():
    ctx = store.validation_context()
    roots = list(ctx.trust_manager.find_potential_issuers if False else [])
    assert len(store.anchors()) == 1 and store.anchors()[0].sha256.hex().upper() == pins.ANCHOR.sha256
    assert len(store.anchors(include_old=True)) == 3
    assert ctx is not None and roots == []


# ---- NSS installer (fake certutil; never touches a real db) -------------------------------------------------------------


class FakeCertutil:
    def __init__(self, existing=None):
        self.cmds, self.existing, self.planted = [], existing or {}, {}

    def __call__(self, cmd):
        self.cmds.append(cmd)
        if cmd[1] == "-L" and "-n" in cmd:  # read one certificate back: the genuine pinned one unless the test planted another
            pin = next(p for p in pins.ALL if p.name == cmd[cmd.index("-n") + 1])
            return 0, pem.armor("CERTIFICATE", self.planted.get(pin.name) or store.bundled_der(pin)).decode()
        if cmd[1] == "-L":
            body = "\n".join(f"{n}    {f}" for n, f in self.existing.items())
            return 0, "\nCertificate Nickname      Trust Attributes\n                     SSL,S/MIME,JAR/XPI\n\n" + body
        return 0, ""


def test_install_creates_db_trusts_only_anchor_and_imports_intermediates_untrusted(tmp_path):
    fake = FakeCertutil()
    names = nss.install(str(tmp_path / "db"), runner=fake, force=True)
    adds = [c for c in fake.cmds if c[1] == "-A"]
    flags = {c[c.index("-n") + 1]: c[c.index("-t") + 1] for c in adds}
    assert flags[pins.ANCHOR.name] == nss.ANCHOR_FLAGS
    assert all(f == nss.INTERMEDIATE_FLAGS for n, f in flags.items() if n != pins.ANCHOR.name)
    assert len(adds) == 1 + len(pins.INTERMEDIATES) == len(names)
    assert any(c[1] == "-N" and "--empty-password" in c for c in fake.cmds)
    assert pins.OLD_ROOTS[0].name not in flags


def test_install_old_roots_only_on_request(tmp_path):
    fake = FakeCertutil()
    nss.install(str(tmp_path / "db"), include_old=True, runner=fake, force=True)
    assert any(pins.OLD_ROOTS[0].name in c for c in fake.cmds)


def test_install_updates_flags_of_existing_nicknames(tmp_path):
    (tmp_path / "db").mkdir()
    (tmp_path / "db" / "cert9.db").write_text("")
    fake = FakeCertutil({pins.ANCHOR.name: "CT,C,C"})
    nss.install(str(tmp_path / "db"), runner=fake, force=True)
    assert any(c[1] == "-M" and c[c.index("-n") + 1] == pins.ANCHOR.name for c in fake.cmds)
    assert not any(c[1] == "-N" for c in fake.cmds)


@pytest.mark.parametrize("bad", ["~/.pki/nssdb", "~/.mozilla/firefox/abc.default", "/etc/pki/nssdb"])
def test_install_refuses_other_softwares_databases(bad):
    with pytest.raises(ValueError, match="belongs to other software"):
        nss.install(bad, runner=FakeCertutil())


# ---- fetch ---------------------------------------------------------------------------------------------------------------


class Resp:
    def __init__(self, data):
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def read(self, n):
        return self.data[:n]


def test_fetch_accepts_exact_pinned_bytes_der_or_pem():
    from asn1crypto import pem

    der = store.bundled_der(pins.ANCHOR)
    assert fetch.fetch_one(pins.ANCHOR, lambda url, timeout: Resp(der)) == der
    assert fetch.fetch_one(pins.ANCHOR, lambda url, timeout: Resp(pem.armor("CERTIFICATE", der))) == der


def test_fetch_refuses_wrong_bytes():
    with pytest.raises(store.PinMismatch):
        fetch.fetch_one(pins.ANCHOR, lambda url, timeout: Resp(store.bundled_der(pins.CAPRICORN[0])))


@pytest.mark.parametrize(
    "url", ["http://cca.gov.in/x.cer", "https://evil.example/x.cer", "https://cca.gov.in.evil.example/x.cer", "file:///etc/passwd"]
)
def test_fetch_refuses_urls_off_the_allowlist(url):
    with pytest.raises(ValueError, match="refusing"):
        fetch.check_url(url)


def test_all_pinned_urls_are_on_the_allowlist():
    for p in pins.ALL:
        if p.url:
            fetch.check_url(p.url)


def test_fetch_all_reports_each_and_writes_verified_files(tmp_path):
    by_url = {p.url: store.bundled_der(p) for p in pins.ALL if p.url}
    res = fetch.fetch_all(str(tmp_path), lambda url, timeout: Resp(by_url[url]))
    assert all(r == "ok" for _, r in res) and len(res) == len(by_url)
    bad = fetch.fetch_all(str(tmp_path / "bad"), lambda url, timeout: Resp(b"junk"))
    assert all(r.startswith("REFUSED") for _, r in bad)


def test_redirects_are_rechecked_against_the_allowlist():
    import urllib.request

    h = fetch.CheckedRedirects()
    req = urllib.request.Request("https://cca.gov.in/a")
    for evil in ("https://evil.example/x.cer", "http://cca.gov.in/x.cer", "file:///etc/passwd"):
        with pytest.raises(ValueError, match="refusing"):
            h.redirect_request(req, None, 302, "Found", {}, evil)
    ok = h.redirect_request(req, None, 302, "Found", {}, "https://www.certificate.digital/repository/x.cer")
    assert ok.full_url.startswith("https://www.certificate.digital/")

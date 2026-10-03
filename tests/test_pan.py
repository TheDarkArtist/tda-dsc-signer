from conftest import der, ku, make_cert

from tda_dsc_signer import pan, tokens
from tda_dsc_signer.forms import FormField

P1, P2 = "ABCDE1234F", "PQRST5678K"


def tcert(pki, cn, serial, token="T"):
    leaf, _ = make_cert(cn, pki["sub"], pki["leaf_key"], ku=ku(digital_signature=True), serial=serial)
    return tokens.TokenCert("m", 0, token, token + "S", "l", der(leaf), cn, "O", "2099-01-01", (), token.lower())


def ff(name, pan_=None, signed=False):
    return FormField(name, 1, (0, 0, 50, 20), signed, True, pan_, {})


def test_hash_vector():
    assert pan.pan_hash("pqrst5678k") == "f2c115f7c2d852700a308fa279dcad8177f50ac11ab8e4c4f103a48a7d75e668"  # sha256(b"PQRST5678K")


def test_cert_matches(pki):
    a, b = tcert(pki, "A", pan.pan_hash(P2)), tcert(pki, "B", pan.pan_hash(P1).upper())  # case-insensitive stored form
    n = tcert(pki, "N", None)
    assert a.subject_serial == pan.pan_hash(P2) and n.subject_serial == ""
    assert pan.cert_matches_pan(a, P2) is True and pan.cert_matches_pan(a, P1) is False
    assert pan.cert_matches_pan(b, P1) is True
    assert pan.cert_matches_pan(n, P1) is None


def test_match_and_candidates(pki):
    a, b, n = tcert(pki, "A", pan.pan_hash(P2), "A"), tcert(pki, "B", pan.pan_hash("NOT-A-PAN"), "B"), tcert(pki, "N", None, "N")
    f1, f2, free, done = ff("s1_" + P1, P1), ff("s2_" + P2, P2), ff("plain"), ff("d_" + P2, P2, signed=True)
    m = pan.match([f1, f2, free, done], [a, b, n])
    assert "d_" + P2 not in m
    assert m[f2.name] == pan.Match(a.key, "match")
    assert m[f1.name] == pan.Match(n.key, "unknown")  # nobody matches, the serial-less cert might
    assert m[free.name] == pan.Match(None, "unknown")
    assert pan.match([f1], [a, b])[f1.name] == pan.Match(None, "none")
    assert pan.candidates(f2, [a, b, n]) == [a] and pan.candidates(f1, [a, b, n]) == [n]
    assert pan.candidates(f1, [a, b]) == [] and pan.candidates(free, [a, b, n]) == [a, b, n]

"""A multi-signature chain through ONE real module host (SoftHSM): the second sign of the same token in the same host process must work."""

from test_softhsm_e2e import Hsm, hsm, pytestmark, sign  # noqa: F401 - fixture + skip mark

from tda_dsc_signer import verify


def test_three_step_chain_over_two_tokens_in_one_host(hsm, pdf3, tmp_path):  # noqa: F811
    hsm.token("tok-a", "Signer A")
    hsm.token("tok-b", "Signer B")
    svc = hsm.service()
    a, b = hsm.cert(svc, "Signer A"), hsm.cert(svc, "Signer B")
    cur = pdf3
    for i, c in enumerate((a, b, a, a, b), 1):
        out = tmp_path / f"s{i}.pdf"
        sign(svc, c, cur, out, box=(50, 50 + 80 * i, 300, 120 + 80 * i))
        cur = out
    v = verify.verify_signed(str(cur))
    assert v.ok and [s.signer for s in v.signatures] == ["Signer A", "Signer B", "Signer A", "Signer A", "Signer B"]

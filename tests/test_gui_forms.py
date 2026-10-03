"""MCA form-field GUI logic (no display): mode auto-detect, match -> row state, steps per mode, summary, error wording."""

from gui_formfix import F1, F2, PAN1, PAN2, field, token

from tda_dsc_signer.errors import PanMismatch
from tda_dsc_signer.gui import formstate, state
from tda_dsc_signer.gui.signrun import Step

JANE = token("Jane Doe", "S1", PAN2)  # matches field 2
BOB = token("Bob Smith", "S4", PAN1)  # matches field 1
NOSER = token("No Serial", "S5", None)  # certificate without a subject serialNumber


def test_detect_mode_auto_default_and_override():
    assert formstate.detect_mode(2) == "mca" and formstate.detect_mode(0) == "general"
    assert formstate.detect_mode(0, "mca") == "mca" and formstate.detect_mode(3, "general") == "general"
    assert formstate.detect_mode(3, "mca", "general") == "general" and formstate.detect_mode(0, "auto", "mca") == "mca"


def test_matched_unmatched_rows():
    rows = formstate.build_rows([F1, F2], [JANE], {})
    assert [r.kind for r in rows] == ["none", "match"]
    assert (rows[0].enabled, rows[0].checked) == (False, False) and "No attached token matches this PAN" in rows[0].text
    assert (rows[1].enabled, rows[1].checked, rows[1].cert) == (True, True, JANE) and rows[1].text == "Jane Doe · PAN matches"
    assert rows[1].label == "Page 8 · PQRS…5678K" and rows[0].label == "Page 7 · ABCD…1234F"


def test_unknown_status_offers_candidates_unchecked():
    rows = formstate.build_rows([F1, field("plain", 2)], [NOSER, JANE], {}, current=NOSER)
    assert rows[0].kind == "unknown" and rows[0].cands == [NOSER] and not rows[0].checked and rows[0].cert is NOSER
    assert rows[1].kind == "unknown" and rows[1].label == "Page 2 · plain" and rows[1].cands == [NOSER, JANE]


def test_signed_fields_are_not_rows():
    assert [r.field.name for r in formstate.build_rows([F1, field(F2.name, 8, PAN2, signed=True)], [BOB], {})] == [F1.name]


def test_choices_survive_a_rescan_and_removed_token_is_flagged():
    choice = {}
    rows = formstate.build_rows([F1, F2], [JANE, BOB], choice)
    assert [r.checked for r in rows] == [True, True]
    choice[F1.name]["checked"] = False
    rows = formstate.build_rows([F1, F2], [JANE], choice)  # Bob unplugged
    assert rows[0].kind == "gone" and not rows[0].checked and rows[0].enabled and "token removed" in rows[0].text
    rows = formstate.build_rows([F1, F2], [JANE, BOB], choice)  # replugged: restored, unchecked state kept
    assert rows[0].kind == "match" and not rows[0].checked


def test_gone_checked_row_blocks_signing_with_a_message():
    choice = {}
    formstate.build_rows([F1], [BOB], choice)
    rows = formstate.build_rows([F1], [], choice)
    assert rows[0].kind == "gone" and rows[0].checked
    assert "token is not connected" in formstate.problem(rows)


def test_steps_only_for_checked_rows_in_field_order():
    choice = {}
    rows = formstate.build_rows([F1, F2], [JANE, BOB], choice)
    steps = formstate.steps_for(rows)
    assert [(s.field, s.page, s.cert.serial) for s in steps] == [(F1.name, 7, "S4"), (F2.name, 8, "S1")]
    choice[F1.name]["checked"] = False
    assert [s.field for s in formstate.steps_for(formstate.build_rows([F1, F2], [JANE, BOB], choice))] == [F2.name]
    assert Step(1, 1, (0, 0, 1, 1), JANE).field == ""  # General steps carry no field


def test_problem_refuses_pan_mismatch_before_any_pin():
    rows = formstate.build_rows([F1], [JANE, NOSER], {})
    rows[0].cert, rows[0].checked, rows[0].kind = JANE, True, "unknown"  # a signer whose PAN is not field 1's
    assert "does not match" in formstate.problem(rows)


def test_summary_names_the_fields_left_for_others():
    rows = formstate.build_rows([F1, F2], [JANE], {})
    assert formstate.summary([rows[1]], rows) == "1 of 2 fields signed; sigfield1_ABCD…1234F needs its signer"


def test_typed_field_errors_show_their_message():
    assert state.describe_error(PanMismatch("Field x must be signed by the holder", "x", "ABCD…1234F", "Jane")) == (
        "field",
        "Field x must be signed by the holder",
    )

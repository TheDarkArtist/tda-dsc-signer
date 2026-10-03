import os

import pkcs11
import pytest

from tda_dsc_signer import tokens
from tda_dsc_signer.errors import HostTimeout
from tda_dsc_signer.gui.signrun import SignRun, Step, partial_path
from tda_dsc_signer.safety import PinState


def cert(serial, final_try=False, protected=False):
    return tokens.TokenCert(
        "m",
        0,
        f"Tok{serial}",
        serial,
        "L",
        b"",
        f"Name{serial}",
        "O",
        "2099-01-01",
        (),
        "01",
        PinState(final_try=final_try, protected_auth=protected),
    )


class Res:
    def __init__(self, out):
        self.out, self.field_name, self.size, self.warnings = out, "Sig1", 1, ()


class FakeBackend:
    def __init__(self, fail_at=None, fail_with=None):
        self.calls, self.fail_at, self.fail_with = [], fail_at, fail_with

    def sign(self, src, cert, *, page, box, pin, out, stamp_text, profile, timestamp_url, confirm_final_try, **kw):
        if self.fail_at == len(self.calls):
            self.calls.append(("FAIL", cert.serial))
            raise self.fail_with
        self.calls.append((src, cert.serial, page, pin, out, kw))
        with open(src, "rb") as f:
            data = f.read()
        with open(out, "wb") as f:  # chaining proof: each step appends a marker to its input
            f.write(data + f"[{cert.serial}:{page}]".encode())
        return Res(out)

    def verify(self, path, field_name=None):
        return "VERIFIED:" + os.path.basename(path)


class UI:
    def __init__(self, run_ref, pins):
        self.prompts, self.events, self.run_ref, self.pins = [], [], run_ref, list(pins)
        self.finish = self.abort = None

    def progress(self, done, total):
        self.events.append(("progress", done, total))

    def ask_pin(self, cert, count, error):
        self.prompts.append((cert.serial, count, error))
        pin = self.pins.pop(0)
        if pin is None:
            return self.run_ref[0].cancel()
        self.run_ref[0].pin_given(pin)

    def finished(self, path, ver, results):
        self.finish = (path, ver, [r.out for r in results])

    def aborted(self, text, partial, done, total):
        self.abort = (text, partial, done, total)


def make(tmp_path, steps, backend, pins):
    src = tmp_path / "in.pdf"
    src.write_bytes(b"%PDF-")
    ref = []
    ui = UI(ref, pins)
    run = SignRun(
        steps,
        str(src),
        str(tmp_path / "out.pdf"),
        backend=backend,
        submit=lambda fn, cb: _sync(fn, cb),
        ui=ui,
        opts={"stamp_text": "t", "profile": "mca", "timestamp_url": ""},
    )
    ref.append(run)
    return run, ui, src


def _sync(fn, cb):
    try:
        res, err = fn(), None
    except Exception as e:  # noqa: BLE001
        res, err = None, e
    cb(res, err)


A, B = cert("A"), cert("B")


def steps3():
    return [Step(1, 1, (1, 2, 3, 4), A), Step(2, 2, (1, 2, 3, 4), B), Step(3, 3, (1, 2, 3, 4), A)]


def test_three_boxes_two_tokens_exactly_two_prompts_and_chained_files(tmp_path):
    be = FakeBackend()
    run, ui, src = make(tmp_path, steps3(), be, ["pinA", "pinB"])
    run.start()
    assert [(s, c) for s, c, e in ui.prompts] == [("A", 2), ("B", 1)]  # one prompt per token, A names its 2 signatures
    srcs = [c[0] for c in be.calls]
    outs = [c[4] for c in be.calls]
    assert srcs[0] == str(src) and srcs[1] == outs[0] and srcs[2] == outs[1]  # output of k is input of k+1
    assert outs[2] == str(tmp_path / "out.pdf") and [c[1] for c in be.calls] == ["A", "B", "A"]
    assert [c[3] for c in be.calls] == ["pinA", "pinB", "pinA"]  # A's PIN reused without asking again
    assert (tmp_path / "out.pdf").read_bytes() == b"%PDF-[A:1][B:2][A:3]"
    assert ui.finish[1] == "VERIFIED:out.pdf" and ui.abort is None
    assert sorted(os.listdir(tmp_path)) == ["in.pdf", "out.pdf"], "intermediates removed"
    assert [e for e in ui.events if e[0] == "progress"] == [("progress", 0, 3), ("progress", 1, 3), ("progress", 2, 3)]
    assert run._pins == {}, "PINs dropped when the run ended"


def test_failure_stops_queue_keeps_partial_and_never_retries(tmp_path):
    be = FakeBackend(fail_at=2, fail_with=HostTimeout("t"))
    run, ui, _ = make(tmp_path, steps3(), be, ["pinA", "pinB"])
    run.start()
    assert len(be.calls) == 3 and be.calls[2][0] == "FAIL", "the failing sign was attempted exactly once"
    text, partial, done, total = ui.abort
    assert (done, total) == (2, 3) and partial == partial_path(str(tmp_path / "out.pdf")) and "may or may not" in text
    assert open(partial, "rb").read() == b"%PDF-[A:1][B:2]"
    assert not (tmp_path / "out.pdf").exists() and sorted(os.listdir(tmp_path)) == ["in.pdf", "out-partial.pdf"]
    assert ui.finish is None


def test_first_step_failure_has_no_partial(tmp_path):
    be = FakeBackend(fail_at=0, fail_with=ValueError("boom"))
    run, ui, _ = make(tmp_path, steps3(), be, ["pinA"])
    run.start()
    assert ui.abort[1] is None and ui.abort[2] == 0 and os.listdir(tmp_path) == ["in.pdf"]


def test_cancel_at_second_prompt_keeps_first_signature(tmp_path):
    be = FakeBackend()
    run, ui, _ = make(tmp_path, steps3(), be, ["pinA", None])
    run.start()
    assert len(be.calls) == 1 and ui.abort[2] == 1 and ui.abort[0] == "Cancelled."
    assert open(ui.abort[1], "rb").read() == b"%PDF-[A:1]"


def test_wrong_pin_pauses_for_the_user_and_does_not_retry_by_itself(tmp_path):
    class Flaky(FakeBackend):
        def sign(self, src, cert, **kw):
            if kw["pin"] == "bad":
                self.calls.append(("BAD", cert.serial))
                raise pkcs11.PinIncorrect("x")
            return super().sign(src, cert, **kw)

    be = Flaky()
    run, ui, _ = make(tmp_path, [Step(1, 1, (1, 2, 3, 4), A)], be, ["bad", "good"])
    run.start()
    assert [c[0] for c in be.calls] == ["BAD", str(tmp_path / "in.pdf")]  # second attempt only after the user supplied a new PIN
    assert ui.prompts[1][2][0] == "pin" and ui.finish is not None


def test_wrong_pin_then_user_dismisses_aborts_without_second_login(tmp_path):
    be = FakeBackend(fail_at=0, fail_with=pkcs11.PinIncorrect("x"))
    run, ui, _ = make(tmp_path, [Step(1, 1, (1, 2, 3, 4), A)], be, ["bad", None])
    run.start()
    assert len(be.calls) == 1 and ui.abort[0] == "Cancelled."


def test_token_removed_between_steps_stops_with_clear_message(tmp_path):
    be = FakeBackend(fail_at=1, fail_with=pkcs11.NoSuchToken("gone"))
    run, ui, _ = make(tmp_path, steps3(), be, ["pinA", "pinB"])
    run.start()
    assert "removed while signing" in ui.abort[0] and ui.abort[2] == 1 and ui.abort[1].endswith("-partial.pdf")


def test_unwritable_output_dir_fails_before_any_login(tmp_path):
    be = FakeBackend()
    run, ui, _ = make(tmp_path, steps3(), be, ["pinA"])
    run.out = "/proc/nope/out.pdf"
    run.start()
    assert be.calls == [] and ui.prompts == [] and "Cannot write" in ui.abort[0]


def test_remembered_pin_skips_prompt_but_final_try_never_does(tmp_path):
    be = FakeBackend()
    run, ui, _ = make(tmp_path, [Step(1, 1, (1, 2, 3, 4), A)], be, [])
    run._remembered = {A.key: "mem"}
    run.start()
    assert ui.prompts == [] and be.calls[0][3] == "mem"
    ft = cert("F", final_try=True)
    run2, ui2, _ = make(tmp_path, [Step(1, 1, (1, 2, 3, 4), ft)], FakeBackend(), ["p"])
    run2._remembered = {ft.key: "mem"}
    run2.start()
    assert len(ui2.prompts) == 1


def test_protected_auth_token_never_prompts_and_sends_no_pin(tmp_path):
    be = FakeBackend()
    run, ui, _ = make(tmp_path, [Step(1, 1, (1, 2, 3, 4), cert("P", protected=True))], be, [])
    run.start()
    assert ui.prompts == [] and be.calls[0][3] is None


def test_try_anyway_passes_confirm_after_failure_only_when_backend_supports_it(tmp_path):
    class New(FakeBackend):
        def sign(self, src, cert, *, confirm_after_failure=False, **kw):
            self.calls.append(("kw", confirm_after_failure))
            return super().sign(src, cert, **kw)

    be = New()
    run, ui, _ = make(tmp_path, [Step(1, 1, (1, 2, 3, 4), A)], be, [])
    run._pins = {"A": "p"}
    run._go(True)
    assert ("kw", True) in be.calls

    class Old(FakeBackend):
        def sign(self, src, cert, *, page, box, pin, out, stamp_text, profile, timestamp_url, confirm_final_try):
            self.calls.append(("old", True))
            return super().sign(
                src,
                cert,
                page=page,
                box=box,
                pin=pin,
                out=out,
                stamp_text=stamp_text,
                profile=profile,
                timestamp_url=timestamp_url,
                confirm_final_try=confirm_final_try,
            )

    old = Old()
    run2, _, _ = make(tmp_path, [Step(1, 1, (1, 2, 3, 4), A)], old, [])
    run2._pins = {"A": "p"}
    run2._go(True)
    assert old.calls[0] == ("old", True) and old.calls[1][5] == {}


@pytest.mark.parametrize("out,expected", [("/a/b.pdf", "/a/b-partial.pdf"), ("/a/b", "/a/b-partial.pdf")])
def test_partial_path(out, expected):
    assert partial_path(out) == expected


def test_overwrite_flag_only_for_confirmed_final_file_and_intermediates(tmp_path):
    seen = []

    class OW(FakeBackend):
        def sign(self, src, cert, *, overwrite=False, **kw):
            seen.append(overwrite)
            return super().sign(src, cert, **kw)

    run, ui, _ = make(tmp_path, steps3(), OW(), ["a", "b"])
    run.start()
    assert seen == [True, True, False], "intermediates may replace stale temp files; the final file only when the dialog confirmed"
    run2, ui2, _ = make(tmp_path, steps3(), OW(), ["a", "b"])
    run2.overwrite_final = True
    seen.clear()
    run2.start()
    assert seen == [True, True, True]


def test_partial_file_never_replaces_an_existing_one(tmp_path):
    (tmp_path / "out-partial.pdf").write_bytes(b"precious")
    run, ui, _ = make(tmp_path, steps3(), FakeBackend(fail_at=1, fail_with=ValueError("x")), ["a", "b"])
    run.start()
    assert ui.abort[1].endswith("out-partial-2.pdf") and (tmp_path / "out-partial.pdf").read_bytes() == b"precious"

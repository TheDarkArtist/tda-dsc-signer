from tda_dsc_signer.gui.boxes import Boxes

SIZE = (595, 842)


def drag(b, page, start, delta, signer="k1"):
    b.begin(page, start, SIZE, 5, signer)
    b.update(*delta)
    b.end()


def test_boxes_accumulate_in_badge_order_with_their_signer():
    b = Boxes()
    drag(b, 1, (100, 100), (80, 40), "k1")
    drag(b, 0, (300, 300), (60, 30), "k2")
    assert [(p.page, p.signer) for p in b.items] == [(1, "k1"), (0, "k2")] and b.active == 1 and b.all_valid


def test_click_without_drag_adds_nothing_and_keeps_others():
    b = Boxes()
    drag(b, 0, (100, 100), (80, 40))
    drag(b, 0, (400, 400), (0, 0))
    assert len(b) == 1 and b.active == 0


def test_move_and_resize_target_the_box_under_the_pointer_not_the_last_one():
    b = Boxes()
    drag(b, 0, (100, 100), (100, 50), "a")  # box 1: 100..200 x 100..150
    drag(b, 0, (400, 400), (100, 50), "b")  # box 2
    b.begin(0, (150, 120), SIZE, 5)
    b.update(10, 0)
    b.end()
    assert b.active == 0 and b.items[0].box == (110, 100, 210, 150) and b.items[1].box == (400, 400, 500, 450)
    b.begin(0, (500, 450), SIZE, 5)  # top-right corner of box 2
    b.update(20, 10)
    assert b.active == 1 and b.items[1].box == (400, 400, 520, 460)


def test_overlap_picks_topmost():
    b = Boxes()
    b.add(0, (100, 100, 200, 200), "a")
    b.add(0, (150, 150, 250, 250), "b")
    assert b.at(0, (170, 170), 5) == 1 and b.at(0, (110, 110), 5) == 0 and b.at(1, (170, 170), 5) == -1


def test_move_clamped_to_page_and_resize_flips_over_fixed_corner():
    b = Boxes()
    drag(b, 0, (100, 100), (100, 50))
    b.begin(0, (150, 120), SIZE, 5)
    b.update(1000, -1000)
    assert b.items[0].box == (495, 0, 595, 50)
    b2 = Boxes()
    b2.add(0, (100, 100, 200, 150))
    b2.begin(0, (200, 150), SIZE, 5)
    b2.update(-150, -100)
    assert b2.items[0].box == (50, 50, 100, 100)


def test_remove_reorder_and_reassign():
    b = Boxes()
    for i, s in enumerate("abc"):
        b.add(0, (10 * i, 10, 10 * i + 50, 40), s)
    b.move_order(0, 1)
    assert [p.signer for p in b.items] == ["b", "a", "c"] and b.active == 2
    b.move_order(2, -1)
    assert [p.signer for p in b.items] == ["b", "c", "a"] and b.active == 1
    b.assign(1, "z")
    assert b.items[1].signer == "z"
    b.remove(0)
    assert [p.signer for p in b.items] == ["z", "a"] and b.active == 0
    b.move_order(0, -1)
    b.move_order(1, 1)
    assert [p.signer for p in b.items] == ["z", "a"]


def test_locked_boxes_ignore_drags():
    b = Boxes()
    b.add(0, (100, 100, 200, 150))
    b.locked = True
    b.begin(0, (150, 120), SIZE, 5)
    b.update(50, 50)
    assert b.items[0].box == (100, 100, 200, 150)
    b.begin(0, (400, 400), SIZE, 5)
    assert len(b) == 1


def test_changing_the_current_signer_never_touches_placed_boxes_only_the_next_one():
    b = Boxes()
    a_cert, b_cert = object(), object()
    current = ("A", a_cert)  # what the dropdown says; the model never reads it after a box exists
    b.begin(0, (100, 100), SIZE, 5, *current)
    b.update(80, 40)
    b.end()
    current = ("B", b_cert)  # dropdown changed while box 1 is active
    assert (b.items[0].signer, b.items[0].cert) == ("A", a_cert)
    b.begin(0, (300, 300), SIZE, 5, *current)
    b.update(80, 40)
    b.end()
    assert [(p.signer, p.cert) for p in b.items] == [("A", a_cert), ("B", b_cert)]
    b.begin(0, (150, 120), SIZE, 5, "B", b_cert)  # moving box 1 under a different dropdown value keeps its signer
    b.update(10, 0)
    b.end()
    assert b.items[0].signer == "A" and b.items[0].cert is a_cert


def test_explicit_assign_changes_exactly_that_box_and_its_cert_snapshot():
    b = Boxes()
    a_cert, b_cert = object(), object()
    b.add(0, (10, 10, 60, 40), "A", a_cert)
    b.add(0, (100, 10, 160, 40), "A", a_cert)
    b.assign(1, "B", b_cert)
    assert [(p.signer, p.cert) for p in b.items] == [("A", a_cert), ("B", b_cert)]
    b.assign(9, "Z")  # out of range: ignored
    assert len(b) == 2

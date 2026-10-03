import pytest

from tda_dsc_signer import geometry as g
from tda_dsc_signer.signing import pdf_page_index


def test_px_points_roundtrip_origin_bottom_left():
    box = (100, 50, 300, 150)
    x, y, w, h = g.points_to_px(box, page_h=842, scale=1.25)
    assert (x, y, w, h) == (125, (842 - 150) * 1.25, 250, 125)
    assert g.px_to_points(x, y, w, h, 842, 1.25) == pytest.approx(box)


def test_drag_in_any_direction_is_normalised():
    assert g.px_to_points(200, 300, -100, -50, 800, 1.0) == (100, 500, 200, 550)


@pytest.mark.parametrize("page_h", [842, 595, 1000])
def test_roundtrip_for_several_page_sizes(page_h):
    box = (10, 20, 110, 70)
    assert g.px_to_points(*g.points_to_px(box, page_h, 2.0), page_h, 2.0) == pytest.approx(box)


@pytest.mark.parametrize("page,idx", [(1, 0), (2, 1), (7, 6), (-1, -1), (-2, -2)])
def test_page_index_positive_minus_one_negative_kept(page, idx):
    assert pdf_page_index(page) == idx


def test_page_zero_rejected():
    with pytest.raises(ValueError):
        pdf_page_index(0)


def test_parse_box():
    assert g.parse_box("300,40,560,110") == (300, 40, 560, 110)
    for bad in ("1,2,3", "5,5,5,9", "a,b,c,d"):
        with pytest.raises(ValueError):
            g.parse_box(bad)


def test_clamp_and_valid():
    assert g.clamp_box((-5, 0, 700, 900), 595, 842) == (0, 0, 595, 842)
    assert g.is_valid((0, 0, 30, 20)) and not g.is_valid((0, 0, 10, 20)) and not g.is_valid(None)

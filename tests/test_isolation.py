import os

import isolate
import pytest

from tda_dsc_signer import config


def test_config_path_is_under_the_test_tmp_dir_not_the_real_home():
    p = os.path.realpath(config.default_path())
    assert not p.startswith(os.path.join(isolate.REAL_HOME, ".config")), p
    assert "xdg" in p


def test_all_xdg_dirs_are_isolated():
    isolate.assert_isolated()
    assert all("xdg" in os.environ[n] for n in isolate.XDG)


def test_guard_fires_when_pointed_at_the_real_config(monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", os.path.join(isolate.REAL_HOME, ".config"))
    with pytest.raises(RuntimeError, match="REAL config"):
        isolate.assert_isolated()
    monkeypatch.undo()


def test_save_and_load_roundtrip_stays_in_tmp():
    cfg = config.Config(profile="general", last_token="X")
    config.save(cfg)
    assert "xdg" in config.default_path() and config.load().profile == "general"

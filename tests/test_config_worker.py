import threading

from tda_dsc_signer import config
from tda_dsc_signer.worker import Worker


def test_config_roundtrip_and_defaults(tmp_path):
    p = tmp_path / "d" / "config.toml"
    assert config.load(p) == config.Config()
    cfg = config.Config(last_token="S/L", last_page=2, last_box=[1, 2, 3, 4], stamp_text='a\n%(signer)s "q"')
    config.save(cfg, p)
    assert config.load(p) == cfg


def test_corrupt_config_falls_back(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text("this is = = bad")
    assert config.load(p) == config.Config()


def test_worker_runs_everything_on_one_thread_and_reports_errors():
    done, ids = threading.Event(), []
    res = []
    w = Worker().start()
    w.submit(lambda: ids.append(threading.get_ident()), lambda r, e: res.append(e))
    w.submit(lambda: 1 / 0, lambda r, e: res.append(e))
    w.submit(lambda: ids.append(threading.get_ident()), lambda r, e: done.set())
    assert done.wait(5)
    assert ids[0] == ids[1] != threading.get_ident()
    assert isinstance(res[1], ZeroDivisionError)
    w.stop()


def test_save_is_0600_and_leaves_no_temp_file(tmp_path):
    import stat

    p = tmp_path / "d" / "config.toml"
    config.save(config.Config(), p)
    assert stat.S_IMODE(p.stat().st_mode) == 0o600 and [x.name for x in p.parent.iterdir()] == ["config.toml"]


def test_corrupt_config_warns_on_stderr(tmp_path, capsys):
    p = tmp_path / "c.toml"
    p.write_text("= = bad")
    assert config.load(p) == config.Config()
    assert "ignoring unreadable config" in capsys.readouterr().err
    assert config.load(tmp_path / "absent.toml") == config.Config() and capsys.readouterr().err == ""

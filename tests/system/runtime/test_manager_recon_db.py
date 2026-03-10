"""Tests for D810Manager.recon_db property."""
import pathlib
import tempfile

from d810.manager import D810Manager


class _StubStore:
    def __init__(self, db_path: pathlib.Path) -> None:
        self.db_path = db_path


class _StubRuntime:
    def __init__(self, db_path: pathlib.Path) -> None:
        self._store = _StubStore(db_path)


class TestReconDbProperty:
    def test_recon_db_none_before_start(self):
        mgr = D810Manager(log_dir=pathlib.Path(tempfile.gettempdir()))
        assert mgr.recon_db is None

    def test_recon_db_returns_path_when_runtime_set(self):
        mgr = D810Manager(log_dir=pathlib.Path(tempfile.gettempdir()))
        mgr._recon_runtime = _StubRuntime(pathlib.Path("/tmp/d810_recon.db"))
        assert mgr.recon_db == pathlib.Path("/tmp/d810_recon.db")

    def test_recon_db_none_when_runtime_is_none(self):
        mgr = D810Manager(log_dir=pathlib.Path(tempfile.gettempdir()))
        mgr._recon_runtime = None
        assert mgr.recon_db is None

"""Tests for D810Manager.recon_db property."""
import pathlib
import tempfile
from unittest.mock import MagicMock

from d810.manager import D810Manager


class TestReconDbProperty:
    def test_recon_db_none_before_start(self):
        mgr = D810Manager(log_dir=pathlib.Path(tempfile.gettempdir()))
        assert mgr.recon_db is None

    def test_recon_db_returns_path_when_runtime_set(self):
        mgr = D810Manager(log_dir=pathlib.Path(tempfile.gettempdir()))
        mock_store = MagicMock()
        mock_store.db_path = pathlib.Path("/tmp/d810_recon.db")
        mock_runtime = MagicMock()
        mock_runtime._store = mock_store
        mgr._recon_runtime = mock_runtime
        assert mgr.recon_db == pathlib.Path("/tmp/d810_recon.db")

    def test_recon_db_none_when_runtime_is_none(self):
        mgr = D810Manager(log_dir=pathlib.Path(tempfile.gettempdir()))
        mgr._recon_runtime = None
        assert mgr.recon_db is None

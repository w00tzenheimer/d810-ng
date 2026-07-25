"""Tests for D810Manager.analysis_db property."""

import pathlib
import tempfile

from d810.manager import D810Manager


class _StubBundle:
    def __init__(self, db_path: pathlib.Path) -> None:
        self.db_path = db_path


class TestAnalysisDbProperty:
    def test_analysis_db_none_before_start(self):
        mgr = D810Manager(log_dir=pathlib.Path(tempfile.gettempdir()))
        assert mgr.analysis_db is None

    def test_analysis_db_returns_path_when_runtime_set(self):
        mgr = D810Manager(log_dir=pathlib.Path(tempfile.gettempdir()))
        mgr._analysis_bundle = _StubBundle(pathlib.Path("/tmp/d810_analysis.db"))
        assert mgr.analysis_db == pathlib.Path("/tmp/d810_analysis.db")

    def test_analysis_db_none_when_runtime_is_none(self):
        mgr = D810Manager(log_dir=pathlib.Path(tempfile.gettempdir()))
        mgr._analysis_bundle = None
        assert mgr.analysis_db is None

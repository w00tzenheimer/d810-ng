"""Exercise controller exit accounting with no IDA/native children."""
import json
import pytest
from tools.bench import dsl_per_test_profile as controller


@pytest.mark.parametrize("status,expected", [("passed", 0), ("skipped", 0), ("failed", 1), ("timeout", 1), ("profile_missing", 1), ("unknown", 1)])
def test_controller_exit_accounts_for_skips(tmp_path, monkeypatch, status, expected):
    concrete = type(tmp_path)
    class LocalPath(concrete):
        def __init__(self, *parts):
            value = concrete(*parts)
            if str(value).startswith("/work/"):
                value = tmp_path / str(value).lstrip("/")
            super().__init__(value)
        @classmethod
        def home(cls):
            return cls(tmp_path / "home")
    monkeypatch.setattr(controller, "Path", LocalPath)
    monkeypatch.setattr(controller, "_collection", lambda **kw: ({}, {"exit": 0}))
    monkeypatch.setattr(controller, "validate_collection_manifest", lambda *a, **kw: [{"nodeid": "one", "project": "test.json"}])
    monkeypatch.setattr(controller, "_execution_provenance", lambda *a: {})
    monkeypatch.setattr(controller, "_certificate_builder", lambda *a: None)
    monkeypatch.setattr(controller, "_project_manifest", lambda *a, **kw: {})
    monkeypatch.setattr(controller, "_shadow_child", lambda **kw: {})
    monkeypatch.setattr(controller, "assess_qualification", lambda *a, **kw: {"status": "not_applicable", "reason": "fixture"})
    monkeypatch.setattr(controller, "_profile_child", lambda **kw: {"status": status, "mode": "legacy-unqualified"})
    output = tmp_path / "result"
    actual = controller.main(["--output-dir", str(output)])
    assert actual == expected
    summary = json.loads((output / "summary.json").read_text())
    assert summary["profile_status_counts"] == {status: 1}
    assert summary["status"] == ("complete" if expected == 0 else "complete_with_failures")

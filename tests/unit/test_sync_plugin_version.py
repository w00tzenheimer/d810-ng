"""Tests for the ida-plugin.json version sync (ticket d81-zijs).

The manifest and ``d810.__version__`` had already drifted (0.6.6 vs 1.0.0b1)
before this tool existed, which is the argument for the ``--check`` gate.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "sync_plugin_version.py"


def _load_tool():
    """Import the tool by path -- ``tools/`` is not an installed package."""
    spec = importlib.util.spec_from_file_location("sync_plugin_version", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def tool():
    return _load_tool()


class TestPackageVersion:
    def test_parses_without_importing_d810(self, tool) -> None:
        """Importing d810 pulls idaapi, which only exists inside IDA."""
        import d810

        assert tool.package_version() == d810.__version__

    def test_reads_a_synthetic_init(self, tool, tmp_path, monkeypatch) -> None:
        init = tmp_path / "__init__.py"
        init.write_text('__version__ = "9.9.9rc1"\n', encoding="utf-8")
        monkeypatch.setattr(tool, "INIT", init)
        assert tool.package_version() == "9.9.9rc1"

    def test_missing_version_is_a_hard_error(self, tool, tmp_path, monkeypatch) -> None:
        init = tmp_path / "__init__.py"
        init.write_text("VERSION = 1\n", encoding="utf-8")
        monkeypatch.setattr(tool, "INIT", init)
        with pytest.raises(SystemExit):
            tool.package_version()


class TestSyncManifest:
    def test_rewrites_only_the_version_field(self, tool) -> None:
        original = json.dumps(
            {
                "IDAMetadataDescriptorVersion": 1,
                "plugin": {"name": "d810-ng", "version": "0.0.1", "idaVersions": ">=9.0"},
            },
            indent=4,
        )
        updated = json.loads(tool.sync_manifest(original, "1.2.3"))
        assert updated["plugin"]["version"] == "1.2.3"
        assert updated["plugin"]["name"] == "d810-ng"
        assert updated["plugin"]["idaVersions"] == ">=9.0"
        assert updated["IDAMetadataDescriptorVersion"] == 1

    def test_output_is_trailing_newline_terminated_json(self, tool) -> None:
        text = tool.sync_manifest('{"plugin": {"version": "0.0.1"}}', "1.2.3")
        assert text.endswith("\n")
        json.loads(text)


class TestCheckMode:
    def _write(self, tmp_path, version, manifest_version):
        init = tmp_path / "__init__.py"
        init.write_text(f'__version__ = "{version}"\n', encoding="utf-8")
        manifest = tmp_path / "ida-plugin.json"
        manifest.write_text(
            json.dumps({"plugin": {"name": "d810-ng", "version": manifest_version}}, indent=4)
            + "\n",
            encoding="utf-8",
        )
        return init, manifest

    def test_check_passes_when_in_sync(self, tool, tmp_path, monkeypatch) -> None:
        init, manifest = self._write(tmp_path, "1.0.0b1", "1.0.0b1")
        monkeypatch.setattr(tool, "INIT", init)
        monkeypatch.setattr(tool, "MANIFEST", manifest)
        assert tool.main(["--check"]) == 0

    def test_check_fails_on_drift_and_writes_nothing(
        self, tool, tmp_path, monkeypatch
    ) -> None:
        init, manifest = self._write(tmp_path, "1.0.0b1", "0.6.6")
        monkeypatch.setattr(tool, "INIT", init)
        monkeypatch.setattr(tool, "MANIFEST", manifest)
        before = manifest.read_text(encoding="utf-8")
        assert tool.main(["--check"]) == 1
        assert manifest.read_text(encoding="utf-8") == before

    def test_write_form_fixes_the_drift(self, tool, tmp_path, monkeypatch) -> None:
        init, manifest = self._write(tmp_path, "1.0.0b1", "0.6.6")
        monkeypatch.setattr(tool, "INIT", init)
        monkeypatch.setattr(tool, "MANIFEST", manifest)
        assert tool.main([]) == 0
        assert json.loads(manifest.read_text())["plugin"]["version"] == "1.0.0b1"
        assert tool.main(["--check"]) == 0


class TestRepositoryManifestIsInSync:
    """Backstop: the real manifest must match the real package version."""

    def test_shipped_manifest_matches_package_version(self, tool) -> None:
        import d810

        manifest = json.loads(
            (ROOT / "ida-plugin.json").read_text(encoding="utf-8")
        )
        assert manifest["plugin"]["version"] == d810.__version__

"""Tests for the ``python -m d810.core.diag`` CLI entry point."""
from __future__ import annotations

import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from d810.core.diag.__main__ import main
from tests.unit.core.diag.fixtures import create_sub_7ffd_scenario


@pytest.fixture()
def loaded_db_path(tmp_path: Path) -> Path:
    """Create a temporary SQLite DB pre-loaded with the sub_7FFD scenario."""
    db_path = tmp_path / "diag.sqlite3"
    conn = sqlite3.connect(str(db_path))
    create_sub_7ffd_scenario(conn)
    conn.close()
    return db_path


# ---------------------------------------------------------------------------
# Tests via main() with captured stdout (fast, in-process)
# ---------------------------------------------------------------------------


class TestChainCommand:
    def test_chain_basic(self, loaded_db_path: Path, capsys: pytest.CaptureFixture):
        rc = main(["chain", "--db", str(loaded_db_path), "131", "174", "176"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "blk[131]" in out
        assert "blk[174]" in out
        assert "blk[176]" in out

    def test_chain_shows_hop_ok(self, loaded_db_path: Path, capsys: pytest.CaptureFixture):
        rc = main(["chain", "--db", str(loaded_db_path), "131", "174"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "hop->174 OK" in out

    def test_chain_shows_broken_hop(
        self, loaded_db_path: Path, capsys: pytest.CaptureFixture
    ):
        rc = main(["chain", "--db", str(loaded_db_path), "206", "217"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "BROKEN" in out

    def test_chain_shows_instructions(
        self, loaded_db_path: Path, capsys: pytest.CaptureFixture
    ):
        rc = main(["chain", "--db", str(loaded_db_path), "131"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "131.0" in out
        assert "mov #0xACD0BD5" in out


class TestVarWritesCommand:
    def test_var_writes_return_slot(
        self, loaded_db_path: Path, capsys: pytest.CaptureFixture
    ):
        rc = main(["var-writes", "--db", str(loaded_db_path), "0x7F0"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "blk[175]" in out
        assert "blk[207]" in out
        assert "blk[217]" in out
        assert "stkoff=0x7F0" in out

    def test_var_writes_state_var(
        self, loaded_db_path: Path, capsys: pytest.CaptureFixture
    ):
        rc = main(["var-writes", "--db", str(loaded_db_path), "0x3C"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "blk[131]" in out
        assert "blk[32]" in out

    def test_var_writes_hex_parsing(
        self, loaded_db_path: Path, capsys: pytest.CaptureFixture
    ):
        """Ensure hex stkoff values are parsed correctly."""
        rc = main(["var-writes", "--db", str(loaded_db_path), "60"])
        assert rc == 0
        out = capsys.readouterr().out
        # 60 decimal = 0x3C
        assert "blk[131]" in out


class TestBlockCommand:
    def test_block_basic(self, loaded_db_path: Path, capsys: pytest.CaptureFixture):
        rc = main(["block", "--db", str(loaded_db_path), "206"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "blk[206]" in out
        assert "BLT_2WAY" in out
        assert "[207, 208]" in out

    def test_block_with_insns(
        self, loaded_db_path: Path, capsys: pytest.CaptureFixture
    ):
        rc = main(["block", "--db", str(loaded_db_path), "206", "--insns"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "instructions" in out

    def test_block_not_found(
        self, loaded_db_path: Path, capsys: pytest.CaptureFixture
    ):
        rc = main(["block", "--db", str(loaded_db_path), "9999"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "not found" in out

    def test_block_shows_meta(
        self, loaded_db_path: Path, capsys: pytest.CaptureFixture
    ):
        rc = main(["block", "--db", str(loaded_db_path), "206"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "valranges" in out


class TestReturnPathsCommand:
    def test_return_paths(
        self, loaded_db_path: Path, capsys: pytest.CaptureFixture
    ):
        rc = main(["return-paths", "--db", str(loaded_db_path)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "CONDITIONAL_RETURN" in out
        assert "blk[207]" in out

    def test_return_paths_flags_writes(
        self, loaded_db_path: Path, capsys: pytest.CaptureFixture
    ):
        rc = main(["return-paths", "--db", str(loaded_db_path)])
        assert rc == 0
        out = capsys.readouterr().out
        # blk[207] has return slot write -> flagged with *
        assert "[*] blk[207]" in out


class TestNoCommand:
    def test_no_command_returns_1(self, capsys: pytest.CaptureFixture):
        rc = main([])
        assert rc == 1


class TestSnapshotResolution:
    def test_explicit_snapshot_id(
        self, loaded_db_path: Path, capsys: pytest.CaptureFixture
    ):
        rc = main(["chain", "--db", str(loaded_db_path), "--snapshot", "1", "131"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "blk[131]" in out


# ---------------------------------------------------------------------------
# Subprocess test (validates ``python -m d810.core.diag`` entry point)
# ---------------------------------------------------------------------------


class TestSubprocess:
    def test_cli_chain_subprocess(self, loaded_db_path: Path):
        result = subprocess.run(
            [sys.executable, "-m", "d810.core.diag", "chain",
             "--db", str(loaded_db_path), "131", "174", "176"],
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(Path(__file__).resolve().parents[4] / "src")},
            timeout=10,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "blk[131]" in result.stdout

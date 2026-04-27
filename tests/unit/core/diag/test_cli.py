"""Tests for the ``python -m d810.core.diag`` CLI entry point."""
from __future__ import annotations

import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from d810.core.diag.__main__ import main
from d810.core.diag.snapshot import _dual
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

    def test_resolve_snapshot_by_maturity_and_phase(
        self, loaded_db_path: Path, capsys: pytest.CaptureFixture
    ):
        conn = sqlite3.connect(str(loaded_db_path))
        fh, fi = _dual(0x180012B60)
        conn.execute(
            "INSERT INTO snapshots VALUES "
            "(2, 'maturity_MMAT_GLBOPT1_post_d810', ?, ?, 'MMAT_GLBOPT1', 'post_d810', 0, 0.0)",
            (fh, fi),
        )
        conn.execute(
            "INSERT INTO rendered_programs VALUES (2, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "semantic_reference_like",
                "semantic",
                "local_boundary_selective",
                "state_family",
                "inline_single_level",
                "minimal",
                1,
                1,
            ),
        )
        conn.execute(
            "INSERT INTO rendered_program_nodes VALUES (2, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "semantic_reference_like",
                "STATE_GLBOPT1_POST",
                "state_family",
                "STATE_GLBOPT1_POST",
                7,
                7,
                None,
                1,
                1,
            ),
        )
        conn.execute(
            "INSERT INTO rendered_program_lines VALUES (2, ?, 1, 0, 0, 'label', NULL, ?)",
            ("semantic_reference_like", "STATE_GLBOPT1_POST:"),
        )
        conn.commit()
        conn.close()

        rc = main(
            [
                "program",
                "--db",
                str(loaded_db_path),
                "--maturity",
                "GLBOPT1",
                "--phase",
                "post_d810",
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "snapshot 2 [MMAT_GLBOPT1 / post_d810]" in out
        assert "STATE_GLBOPT1_POST:" in out

    def test_resolve_snapshot_by_phase_only(
        self, loaded_db_path: Path, capsys: pytest.CaptureFixture
    ):
        conn = sqlite3.connect(str(loaded_db_path))
        fh, fi = _dual(0x180012B60)
        conn.execute(
            "INSERT INTO snapshots VALUES "
            "(2, 'maturity_MMAT_GLBOPT1_post_d810', ?, ?, 'MMAT_GLBOPT1', 'post_d810', 0, 0.0)",
            (fh, fi),
        )
        conn.commit()
        conn.close()

        rc = main(["block", "--db", str(loaded_db_path), "--phase", "post_d810", "206"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "snapshot 2 [MMAT_GLBOPT1 / post_d810]" in out

    def test_resolve_snapshot_selector_missing_exits(
        self, loaded_db_path: Path, capsys: pytest.CaptureFixture
    ):
        with pytest.raises(SystemExit) as exc:
            main(
                [
                    "program",
                    "--db",
                    str(loaded_db_path),
                    "--maturity",
                    "GLBOPT1",
                    "--phase",
                    "post_d810",
                ]
            )
        assert exc.value.code == 1
        err = capsys.readouterr().err
        assert "no snapshot matches maturity=MMAT_GLBOPT1 phase=post_d810" in err


class TestRenderedProgramCommand:
    def test_program_text(self, loaded_db_path: Path, capsys: pytest.CaptureFixture):
        rc = main(["program", "--db", str(loaded_db_path)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "STATE_139F2922:" in out
        assert "goto STATE_16F7FF74;" in out

    def test_program_nodes(self, loaded_db_path: Path, capsys: pytest.CaptureFixture):
        rc = main(["program", "--db", str(loaded_db_path), "--nodes"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "STATE_139F2922" in out
        assert "state_family" in out
        assert "handler=blk[136]" in out

    def test_program_variants(self, loaded_db_path: Path, capsys: pytest.CaptureFixture):
        rc = main(["program-variants", "--db", str(loaded_db_path)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "semantic_reference_like" in out


class TestStateLocalCommand:
    def test_state_local(self, loaded_db_path: Path, capsys: pytest.CaptureFixture):
        rc = main(["state-local", "--db", str(loaded_db_path), "0x298372CC"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "STATE_298372CC:" in out
        assert "// entry blk[205] [range_backed]" in out
        assert "// blocks: blk[205], blk[207], blk[206], blk[217], blk[218]" in out
        assert "// shared-suffix: blk[217], blk[218]" in out
        assert "blk[205] -taken-> blk[207]" in out
        assert "blk[205] -fallthrough-> blk[206]" in out
        assert "blk[206] -shared_suffix-> blk[217]" in out
        assert "blk[217] -terminal-> blk[218]" in out


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

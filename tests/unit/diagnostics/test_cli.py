"""Tests for the ``python -m d810.diagnostics`` CLI entry point."""
from __future__ import annotations

import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from d810.diagnostics.__main__ import main
from d810.core.diag.snapshot import (
    _dual,
    snapshot_fact_conflicts,
    snapshot_fact_consumers,
    snapshot_fact_mappings,
    snapshot_fact_observations,
)
from d810.recon.facts import (
    FactConflict,
    FactConsumerRecord,
    FactMapping,
    FactObservation,
    FactStatus,
)
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
        assert "blk[131]@0x180014852" in out
        assert "blk[174]@synthetic" in out
        assert "blk[176]@synthetic" in out

    def test_chain_shows_hop_ok(self, loaded_db_path: Path, capsys: pytest.CaptureFixture):
        rc = main(["chain", "--db", str(loaded_db_path), "131", "174"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "hop->blk[174]@synthetic OK" in out

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
        assert "blk[206]@synthetic" in out
        assert "BLT_2WAY" in out
        assert "blk[207]@0x1800161C8" in out
        assert "blk[208]@unknown" in out

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
        assert "entry blk[131]@0x180014852" in out
        assert "local-cfg: blk[131]@0x180014852 -> blk[174]@synthetic" in out
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


class TestFactCommands:
    def _load_fact_rows(self, db_path: Path) -> None:
        conn = sqlite3.connect(str(db_path))
        snapshot_fact_observations(
            conn,
            1,
            0x180012B60,
            [
                FactObservation(
                    fact_id="induction:loop-a",
                    kind="InductionCarrierFact",
                    semantic_key="loop:a",
                    maturity="MMAT_LOCOPT",
                    phase="pre_d810",
                    confidence=0.9,
                    source_block=265,
                    source_ea=0x180015F08,
                )
            ],
        )
        snapshot_fact_mappings(
            conn,
            1,
            0x180012B60,
            [
                FactMapping(
                    source_fact_id="induction:loop-a",
                    source_maturity="MMAT_LOCOPT",
                    target_maturity="MMAT_GLBOPT1",
                    status=FactStatus.REMAPPED,
                    confidence=0.8,
                    target_block=184,
                    target_ea=0x180015F08,
                )
            ],
        )
        snapshot_fact_consumers(
            conn,
            1,
            0x180012B60,
            [
                FactConsumerRecord(
                    consumer="hodur.hcc",
                    strategy="HandlerChainComposer",
                    fact_id="induction:loop-a",
                    maturity="MMAT_GLBOPT1",
                    decision="protected",
                )
            ],
        )
        snapshot_fact_conflicts(
            conn,
            1,
            0x180012B60,
            [
                FactConflict(
                    conflict_id="conflict:a",
                    fact_id="induction:loop-a",
                    other_fact_id="induction:loop-b",
                    maturity="MMAT_GLBOPT1",
                    conflict_kind="overlap",
                    reason="same byte corridor",
                )
            ],
        )
        conn.close()

    def test_fact_observations_command(
        self, loaded_db_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        self._load_fact_rows(loaded_db_path)
        rc = main([
            "fact-observations",
            "--db",
            str(loaded_db_path),
            "--kind",
            "InductionCarrierFact",
        ])
        assert rc == 0
        out = capsys.readouterr().out
        assert "induction:loop-a" in out
        assert "loop:a" in out

    def test_fact_observations_all_snapshots(
        self, loaded_db_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        self._load_fact_rows(loaded_db_path)
        conn = sqlite3.connect(str(loaded_db_path))
        snapshot_fact_observations(
            conn,
            99,
            0x180012B60,
            [
                FactObservation(
                    fact_id="induction:loop-b",
                    kind="InductionCarrierFact",
                    semantic_key="loop:b",
                    maturity="MMAT_GLBOPT1",
                    phase="pre_d810",
                    confidence=0.7,
                    source_block=202,
                )
            ],
        )
        conn.close()

        rc = main([
            "fact-observations",
            "--db",
            str(loaded_db_path),
            "--kind",
            "InductionCarrierFact",
            "--all-snapshots",
        ])

        assert rc == 0
        out = capsys.readouterr().out
        assert "snapshot_id" in out
        assert "induction:loop-a" in out
        assert "induction:loop-b" in out

    def test_fact_mappings_command_json(
        self, loaded_db_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        self._load_fact_rows(loaded_db_path)
        rc = main([
            "fact-mappings",
            "--db",
            str(loaded_db_path),
            "--status",
            "REMAPPED",
            "--json",
        ])
        assert rc == 0
        out = capsys.readouterr().out
        assert '"source_fact_id": "induction:loop-a"' in out
        assert '"target_block": 184' in out

    def test_fact_consumers_and_conflicts_commands(
        self, loaded_db_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        self._load_fact_rows(loaded_db_path)
        rc = main([
            "fact-consumers",
            "--db",
            str(loaded_db_path),
            "--decision",
            "protected",
        ])
        assert rc == 0
        out = capsys.readouterr().out
        assert "hodur.hcc" in out

        rc = main([
            "fact-conflicts",
            "--db",
            str(loaded_db_path),
            "--conflict-kind",
            "overlap",
        ])
        assert rc == 0
        out = capsys.readouterr().out
        assert "same byte corridor" in out

    def test_fact_trace_command(
        self, loaded_db_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        self._load_fact_rows(loaded_db_path)

        rc = main([
            "fact-trace",
            "--db",
            str(loaded_db_path),
            "--semantic-key",
            "loop:a",
        ])

        assert rc == 0
        out = capsys.readouterr().out
        assert "observations:" in out
        assert "mappings:" in out
        assert "induction:loop-a" in out
        assert "REMAPPED" in out
        assert "blk[265]@0x180015F08" in out
        assert "blk[184]@0x180015F08" in out

    def test_fact_diff_command(
        self, loaded_db_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        self._load_fact_rows(loaded_db_path)

        rc = main([
            "fact-diff",
            "--db",
            str(loaded_db_path),
            "--from-maturity",
            "MMAT_LOCOPT",
            "--to-maturity",
            "MMAT_GLBOPT1",
            "--kind",
            "InductionCarrierFact",
        ])

        assert rc == 0
        out = capsys.readouterr().out
        assert "source_fact_id" in out
        assert "induction:loop-a" in out
        assert "REMAPPED" in out
        assert "blk[265]@0x180015F08" in out
        assert "blk[184]@0x180015F08" in out

    def test_fact_diff_is_scoped_by_function_identity(
        self, loaded_db_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        conn = sqlite3.connect(str(loaded_db_path))
        snapshot_fact_observations(
            conn,
            1,
            0x180012B60,
            [
                FactObservation(
                    fact_id="induction:shared-map",
                    kind="InductionCarrierFact",
                    semantic_key="loop:cross-map",
                    maturity="MMAT_LOCOPT",
                    phase="pre_d810",
                    confidence=0.9,
                    source_block=10,
                ),
                FactObservation(
                    fact_id="induction:shared-active",
                    kind="InductionCarrierFact",
                    semantic_key="loop:cross-active",
                    maturity="MMAT_LOCOPT",
                    phase="pre_d810",
                    confidence=0.9,
                    source_block=11,
                ),
            ],
        )
        snapshot_fact_mappings(
            conn,
            2,
            0x180099999,
            [
                FactMapping(
                    source_fact_id="induction:shared-map",
                    source_maturity="MMAT_LOCOPT",
                    target_maturity="MMAT_GLBOPT1",
                    status=FactStatus.REMAPPED,
                    confidence=0.8,
                    target_block=132,
                )
            ],
        )
        snapshot_fact_observations(
            conn,
            3,
            0x180099999,
            [
                FactObservation(
                    fact_id="induction:shared-active",
                    kind="InductionCarrierFact",
                    semantic_key="loop:cross-active",
                    maturity="MMAT_GLBOPT1",
                    phase="pre_d810",
                    confidence=0.9,
                    source_block=99,
                )
            ],
        )
        conn.close()

        rc = main([
            "fact-diff",
            "--db",
            str(loaded_db_path),
            "--from-maturity",
            "MMAT_LOCOPT",
            "--to-maturity",
            "MMAT_GLBOPT1",
            "--kind",
            "InductionCarrierFact",
            "--semantic-key",
            "loop:cross-map",
        ])
        assert rc == 0
        out = capsys.readouterr().out
        assert "induction:shared-map" in out
        assert "CARRIED_FORWARD" in out
        assert "REMAPPED" not in out
        assert "132" not in out

        rc = main([
            "fact-trace",
            "--db",
            str(loaded_db_path),
            "--kind",
            "InductionCarrierFact",
            "--semantic-key",
            "loop:cross-map",
        ])
        assert rc == 0
        out = capsys.readouterr().out
        assert "induction:shared-map" in out
        assert "REMAPPED" not in out
        assert "132" not in out

        rc = main([
            "fact-diff",
            "--db",
            str(loaded_db_path),
            "--from-maturity",
            "MMAT_LOCOPT",
            "--to-maturity",
            "MMAT_GLBOPT1",
            "--kind",
            "InductionCarrierFact",
            "--semantic-key",
            "loop:cross-active",
        ])
        assert rc == 0
        out = capsys.readouterr().out
        assert "induction:shared-active" in out
        assert "CARRIED_FORWARD" in out
        assert "ACTIVE" not in out


# ---------------------------------------------------------------------------
# Subprocess test (validates ``python -m d810.diagnostics`` entry point)
# ---------------------------------------------------------------------------


class TestSubprocess:
    def test_cli_chain_subprocess(self, loaded_db_path: Path):
        result = subprocess.run(
            [sys.executable, "-m", "d810.diagnostics", "chain",
             "--db", str(loaded_db_path), "131", "174", "176"],
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(Path(__file__).resolve().parents[3] / "src")},
            timeout=10,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "blk[131]" in result.stdout

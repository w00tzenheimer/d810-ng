from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from tools.hexrays_structuring_lab.__main__ import (
    LabError,
    build_summary,
    load_registry,
    main,
    render_case_command,
    render_validate_cfg_command,
)


def test_registry_loads_initial_cases() -> None:
    registry = load_registry()
    case_ids = {case["id"] for case in registry["cases"]}
    assert case_ids == {
        "single_pred_chain_merge",
        "multi_pred_boundary_barrier",
    }


def test_command_rendering_includes_docker_dump_command() -> None:
    case = load_registry()["cases"][0]
    command = render_case_command(case, output_subdir="lab_out")
    assert "run_system_tests_docker.sh dump" in command
    assert "-f hexrays_lab_single_pred_chain_merge" in command
    assert "-p default_instruction_only.json" in command
    assert "-o lab_out/single_pred_chain_merge.txt" in command
    assert "D810_CAPTURE_POST_MATURITY=GLBOPT1" in command


def test_validate_cfg_command_rendering_is_separate_from_dump() -> None:
    case = load_registry()["cases"][0]
    command = render_validate_cfg_command(case, output_subdir="cfg_out")
    assert "run_system_tests_docker.sh test" in command
    assert "test_structuring_lab_cfg_validation.py" in command
    assert "--hexrays-lab-case single_pred_chain_merge" in command
    assert "--hexrays-lab-function hexrays_lab_single_pred_chain_merge" in command
    assert (
        "--hexrays-lab-output-json "
        ".tmp/cfg_out/single_pred_chain_merge.json"
    ) in command
    assert "-o cfg_out/single_pred_chain_merge.txt" in command


def test_list_command_prints_cases(capsys) -> None:
    rc = main(["list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "single_pred_chain_merge" in out
    assert "multi_pred_boundary_barrier" in out
    assert "c_with_compiled_cfg_validation" in out


def test_show_command_prints_case_json(capsys) -> None:
    rc = main(["show", "single_pred_chain_merge"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["id"] == "single_pred_chain_merge"
    assert data["status"] == "observed"
    assert data["cfg_validation"]["status"] == "passed"
    assert (
        data["observation_artifact"]
        == "tools/hexrays_structuring_lab/observations/single_pred_chain_merge.json"
    )
    assert data["observation"]["from_block_count"] == 6
    assert data["observation"]["to_block_count"] == 3


def test_registry_does_not_point_at_tmp_artifacts() -> None:
    registry = load_registry()
    tmp_paths = [
        value for value in _json_strings(registry)
        if value.startswith(".tmp/") or "/.tmp/" in value
    ]
    assert tmp_paths == []


def test_summarize_reports_absorbed_block(tmp_path: Path) -> None:
    db = tmp_path / "diag.sqlite3"
    _create_merge_db(db)

    summary = build_summary(db, from_label="post_apply", to_label="post_d810")

    assert summary["from_block_count"] == 2
    assert summary["to_block_count"] == 1
    assert summary["vanished_count"] == 1
    assert summary["cfg_validation"]["status"] == "not_provided"
    assert summary["disposition_counts"] == {"absorbed": 1}
    vanished = summary["vanished"]
    assert vanished[0]["serial"] == 20
    assert vanished[0]["absorber"]["serial"] == 10


def test_summarize_cli_json(tmp_path: Path, capsys) -> None:
    db = tmp_path / "diag.sqlite3"
    _create_merge_db(db)

    rc = main([
        "summarize",
        "--db",
        str(db),
        "--from-label",
        "post_apply",
        "--to-label",
        "post_d810",
        "--format",
        "json",
    ])

    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["vanished_count"] == 1
    assert data["cfg_validation"]["status"] == "not_provided"
    assert data["cross_tab"] == {"has_content": {"absorbed": 1}}


def test_summarize_includes_passed_cfg_validation(tmp_path: Path) -> None:
    db = tmp_path / "diag.sqlite3"
    validation = tmp_path / "cfg_validation.json"
    _create_merge_db(db)
    validation.write_text(json.dumps({
        "status": "passed",
        "compiler_flags": ["-O0"],
        "binary_hash": "sha256:abc",
        "artifact_path": "validation/single_pred_chain_merge.json",
        "expected": {"block_count": ">= 3"},
        "observed": {"block_count": 4},
    }))

    summary = build_summary(
        db,
        from_label="post_apply",
        to_label="post_d810",
        cfg_validation_path=validation,
        require_cfg_validation=True,
    )

    assert summary["cfg_validation"]["status"] == "passed"
    assert summary["cfg_validation"]["binary_hash"] == "sha256:abc"
    assert summary["cfg_validation"]["observed"] == {"block_count": 4}


def test_required_cfg_validation_rejects_missing_result(tmp_path: Path) -> None:
    db = tmp_path / "diag.sqlite3"
    _create_merge_db(db)

    try:
        build_summary(
            db,
            from_label="post_apply",
            to_label="post_d810",
            require_cfg_validation=True,
        )
    except LabError as exc:
        assert "compiled-CFG validation is required" in str(exc)
    else:
        raise AssertionError("expected missing cfg validation to fail hard")


def test_required_cfg_validation_rejects_failed_result(tmp_path: Path) -> None:
    db = tmp_path / "diag.sqlite3"
    validation = tmp_path / "cfg_validation.json"
    _create_merge_db(db)
    validation.write_text(json.dumps({
        "status": "failed",
        "compiler_flags": ["-O0"],
        "binary_hash": "sha256:def",
        "expected": {"block_count": ">= 3"},
        "observed": {"block_count": 1},
    }))

    try:
        build_summary(
            db,
            from_label="post_apply",
            to_label="post_d810",
            cfg_validation_path=validation,
            require_cfg_validation=True,
        )
    except LabError as exc:
        assert "status='failed'" in str(exc)
    else:
        raise AssertionError("expected failed cfg validation to fail hard")


def _create_merge_db(path: Path) -> None:
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE snapshots (id INTEGER PRIMARY KEY, label TEXT)")
    conn.execute(
        "CREATE TABLE blocks ("
        "snapshot_id INTEGER, serial INTEGER, type_name TEXT, nsucc INTEGER, "
        "npred INTEGER, succs TEXT, preds TEXT, insn_count INTEGER, "
        "start_ea_hex TEXT, end_ea_hex TEXT)"
    )
    conn.execute(
        "CREATE TABLE instructions ("
        "snapshot_id INTEGER, block_serial INTEGER, insn_index INTEGER, "
        "ea_i64 INTEGER, ea_hex TEXT, opcode_name TEXT)"
    )
    conn.execute("INSERT INTO snapshots VALUES (1, 'post_apply')")
    conn.execute("INSERT INTO snapshots VALUES (2, 'post_d810')")
    conn.execute(
        "INSERT INTO blocks VALUES "
        "(1, 10, 'BLT_1WAY', 1, 0, '[20]', '[]', 1, '0x1000', '0x1004')"
    )
    conn.execute(
        "INSERT INTO blocks VALUES "
        "(1, 20, 'BLT_1WAY', 1, 1, '[30]', '[10]', 2, '0x1010', '0x1018')"
    )
    conn.execute(
        "INSERT INTO instructions VALUES "
        "(1, 10, 0, 4096, '0x1000', 'm_mov')"
    )
    conn.execute(
        "INSERT INTO instructions VALUES "
        "(1, 20, 0, 4112, '0x1010', 'm_add')"
    )
    conn.execute(
        "INSERT INTO instructions VALUES "
        "(1, 20, 1, 4116, '0x1014', 'm_goto')"
    )
    conn.execute(
        "INSERT INTO blocks VALUES "
        "(2, 10, 'BLT_1WAY', 0, 0, '[]', '[]', 3, '0x1000', '0x1018')"
    )
    conn.execute(
        "INSERT INTO instructions VALUES "
        "(2, 10, 0, 4096, '0x1000', 'm_mov')"
    )
    conn.execute(
        "INSERT INTO instructions VALUES "
        "(2, 10, 1, 4112, '0x1010', 'm_add')"
    )
    conn.execute(
        "INSERT INTO instructions VALUES "
        "(2, 10, 2, 4116, '0x1014', 'm_goto')"
    )
    conn.commit()
    conn.close()


def _json_strings(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        strings = []
        for item in value:
            strings.extend(_json_strings(item))
        return strings
    if isinstance(value, dict):
        strings = []
        for item in value.values():
            strings.extend(_json_strings(item))
        return strings
    return []

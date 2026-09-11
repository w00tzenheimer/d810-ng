"""Contracts for the reusable OLLVM mismatch-witness child entry point."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def load_runner():
    path = ROOT / "tools/bench/run_ollvm_mismatch_witness.py"
    assert path.exists(), f"{path} not implemented"
    spec = importlib.util.spec_from_file_location("run_ollvm_mismatch_witness", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _capture(runner, *, passed: int = 1, skipped: int = 0) -> dict:
    return {
        "passed": passed,
        "failed": 0,
        "skipped": skipped,
        "project": runner.PROJECT,
        "expected_project": runner.PROJECT,
        "records": [
            {
                "project": runner.PROJECT,
                "adapters": [
                    {
                        "canonical_fallback_enabled": False,
                        "uses_structural_matching": False,
                    }
                ],
            }
        ],
        "activation_calls": [],
        "accepted_enrolled": [],
    }


def _install_fake_child(
    runner,
    monkeypatch,
    *,
    capture: dict | None,
    exit_code: int = 0,
):
    observed = {}

    def fake_execute_child(**kwargs):
        observed.update(kwargs)
        run_dir = kwargs["run_dir"]
        native_dir = kwargs["native_dir"]
        env = kwargs["env"]
        run_dir.mkdir(parents=True, exist_ok=False)
        native_dir.mkdir(parents=True, exist_ok=False)
        Path(env["TMPDIR"]).mkdir(parents=True, exist_ok=False)
        process = {
            "command": kwargs["command"],
            "environment": {
                key: value for key, value in env.items() if key.startswith("D810_")
            },
            "paths": {
                "run_dir": str(run_dir),
                "native_dir": str(native_dir),
                "idalog": env["IDALOG"],
                "tmpdir": env["TMPDIR"],
            },
            "exit": exit_code,
            "process_seconds": 1.25,
        }
        runner._write_json(run_dir / "process.json", process)
        if capture is not None:
            output = Path(env["D810_CANONICAL_DAC_OUT"])
            runner._write_json(output, capture)
            runner._write_json(
                output.with_suffix(".witnesses.json"),
                [{"rule": "BnotXor_Rule_1"}],
            )
        return process

    monkeypatch.setattr(runner, "_execute_child", fake_execute_child)
    return observed


def test_runner_uses_exact_shadow_node_environment_and_paths(
    tmp_path, monkeypatch, capsys
):
    runner = load_runner()
    output_root = tmp_path / "work/.tmp"
    native_root = tmp_path / "work/runs"
    monkeypatch.setattr(runner, "OUTPUT_ROOT", output_root)
    monkeypatch.setattr(runner, "NATIVE_ROOT", native_root)
    monkeypatch.setenv("D810_RUN_ID", "unit-run")
    monkeypatch.setenv("D810_CANONICAL_MATCH_FALLBACK", "contamination")
    monkeypatch.setenv("D810_CANONICAL_DAC_ACTIVATION_PROOF", "contamination")
    monkeypatch.setattr(
        runner,
        "_execution_provenance",
        lambda root: {"git_revision": "a" * 40, "git_dirty": []},
    )
    observed = _install_fake_child(
        runner,
        monkeypatch,
        capture=_capture(runner),
    )

    result = runner.main(["--python", "/app/ida/.venv/bin/python"])

    assert result == 0
    assert observed["command"] == [
        "/app/ida/.venv/bin/python",
        "-u",
        "-m",
        "pytest",
        "-p",
        "no:cacheprovider",
        "-p",
        "tools.bench.canonical_dac_probe",
        "-q",
        "-s",
        "-o",
        "addopts=",
        runner.NODE_ID,
    ]
    assert observed["timeout"] == 900
    assert observed["run_dir"] == output_root / "mismatch-witness-r2/unit-run/ollvm"
    assert observed["native_dir"] == native_root / "unit-run/mismatch-native/ollvm"
    env = observed["env"]
    assert {
        "D810_CANONICAL_DAC_ORIGINAL_PROJECT": runner.PROJECT,
        "D810_CANONICAL_DAC_PROJECT": runner.PROJECT,
        "D810_CANONICAL_DAC_OUT": str(observed["run_dir"] / "shadow.json"),
        "D810_CANONICAL_DAC_AGGREGATE_ONLY": "1",
        "D810_LEGACY_DSL_PERMUTATIONS": "1",
        "D810_SHADOW_DSL_MATCHING": "1",
        "D810_CANONICAL_DAC_WITNESSES": "1",
    }.items() <= env.items()
    assert "D810_CANONICAL_MATCH_FALLBACK" not in env
    assert "D810_CANONICAL_DAC_ACTIVATION_PROOF" not in env
    assert env["IDALOG"] == str(observed["native_dir"] / "ida.log")
    assert env["TMPDIR"] == str(observed["native_dir"] / "tmp")
    assert observed["options"] == Path.home() / ".idapro/cfg/d810/options.json"
    receipt = json.loads((observed["run_dir"] / "receipt.json").read_text())
    assert receipt["status"] == "passed"
    assert receipt["test_status"] == "passed"
    assert receipt["witness_count"] == 1
    provenance = json.loads(
        (observed["run_dir"] / "source-provenance.json").read_text()
    )
    assert provenance["git_revision"] == "a" * 40
    assert len(provenance["witness_runner_sha256"]) == 64
    assert set(provenance["target_source_sha256"]) == {
        "samples/bins/libobfuscated.dll",
        "src/d810/backends/mba/hexrays_island.py",
        "src/d810/backends/mba/ida.py",
        "src/d810/backends/mba/native_z3.py",
        "src/d810/conf/default_unflattening_ollvm.json",
        "src/d810/hexrays/hooks/optinsn_adapter.py",
        "src/d810/mba/ac_matching.py",
        "src/d810/mba/canonical_pattern.py",
        "src/d810/mba/rules/bnot.py",
        "src/d810/mba/rules/catalogue.py",
        "src/d810/optimizers/microcode/instructions/pattern_matching/handler.py",
        "tests/system/e2e/test_libdeobfuscated_dsl.py",
    }
    assert all(
        len(digest) == 64
        for digest in provenance["target_source_sha256"].values()
    )
    printed = json.loads(capsys.readouterr().out)
    assert printed == receipt


def test_runner_selects_exact_reference_v4_node_project_and_slug(tmp_path, monkeypatch):
    runner = load_runner()
    monkeypatch.setattr(runner, "OUTPUT_ROOT", tmp_path / "outputs")
    monkeypatch.setattr(runner, "NATIVE_ROOT", tmp_path / "native")
    monkeypatch.setenv("D810_RUN_ID", "reference-run")
    monkeypatch.setattr(
        runner,
        "_execution_provenance",
        lambda root: {"git_revision": "c" * 40, "git_dirty": []},
    )
    target = runner.TARGETS["reference-v4"]
    observed = _install_fake_child(
        runner,
        monkeypatch,
        capture={
            **_capture(runner),
            "project": target.project,
            "expected_project": target.project,
            "records": [
                {
                    "project": target.project,
                    "adapters": [
                        {
                            "canonical_fallback_enabled": False,
                            "uses_structural_matching": False,
                        }
                    ],
                }
            ],
        },
    )

    result = runner.main(["--target", "reference-v4"])

    assert result == 0
    assert observed["command"][-1] == (
        "tests/system/e2e/test_libdeobfuscated_dsl.py::TestDacMasmFixtures::"
        "test_dac_masm_fixtures[sub_7FF856533A20]"
    )
    assert observed["env"]["D810_CANONICAL_DAC_PROJECT"] == (
        "eidolon_v4_const_simplify_solve.json"
    )
    assert observed["run_dir"] == tmp_path / "outputs/mismatch-witness-r2/reference-run/reference-v4"
    assert observed["native_dir"] == tmp_path / "native/reference-run/mismatch-native/reference-v4"
    provenance = json.loads(
        (observed["run_dir"] / "source-provenance.json").read_text()
    )
    assert set(provenance["target_source_sha256"]) == {
        "samples/bins/libobfuscated.dll",
        "src/d810/backends/mba/hexrays_island.py",
        "src/d810/backends/mba/ida.py",
        "src/d810/backends/mba/native_z3.py",
        "src/d810/conf/eidolon_v4_const_simplify_solve.json",
        "src/d810/hexrays/hooks/optinsn_adapter.py",
        "src/d810/mba/ac_matching.py",
        "src/d810/mba/canonical_pattern.py",
        "src/d810/mba/rules/catalogue.py",
        "src/d810/mba/rules/hodur.py",
        "src/d810/optimizers/microcode/instructions/pattern_matching/handler.py",
        "tests/system/e2e/test_libdeobfuscated_dsl.py",
    }


@pytest.mark.parametrize(
    ("case", "reason"),
    [
        ("missing-activation-calls", "activation_calls must be an empty list"),
        ("malformed-accepted-enrolled", "accepted_enrolled must be an empty list"),
        ("malformed-record", "shadow records must be JSON objects"),
        ("malformed-adapters", "shadow adapters must be a list"),
        ("implicit-adapter-flags", "canonical adapter flags must be explicitly false"),
    ],
)
def test_runner_fails_closed_on_missing_or_malformed_activation_evidence(
    tmp_path, monkeypatch, case, reason
):
    runner = load_runner()
    monkeypatch.setattr(runner, "OUTPUT_ROOT", tmp_path / "outputs")
    monkeypatch.setattr(runner, "NATIVE_ROOT", tmp_path / "native")
    monkeypatch.setenv("D810_RUN_ID", case)
    monkeypatch.setattr(
        runner,
        "_execution_provenance",
        lambda root: {"git_revision": "d" * 40, "git_dirty": []},
    )
    capture = _capture(runner)
    if case == "missing-activation-calls":
        capture.pop("activation_calls")
    elif case == "malformed-accepted-enrolled":
        capture["accepted_enrolled"] = None
    elif case == "malformed-record":
        capture["records"] = [None]
    elif case == "malformed-adapters":
        capture["records"][0]["adapters"] = None
    else:
        capture["records"][0]["adapters"] = [
            {"canonical_fallback_enabled": False}
        ]
    observed = _install_fake_child(runner, monkeypatch, capture=capture)

    result = runner.main([])

    assert result == 1
    receipt = json.loads((observed["run_dir"] / "receipt.json").read_text())
    assert receipt["status"] == "failed"
    assert receipt["reason"] == reason


@pytest.mark.parametrize(
    ("case", "capture_factory", "exit_code", "reason"),
    [
        ("child-failure", lambda runner: _capture(runner), 2, "child_exit_2"),
        (
            "skipped",
            lambda runner: _capture(runner, passed=0, skipped=1),
            0,
            "test_status_skipped",
        ),
        ("missing-capture", lambda runner: None, 0, "missing capture receipt"),
    ],
)
def test_runner_fails_closed_with_receipt(
    tmp_path,
    monkeypatch,
    case,
    capture_factory,
    exit_code,
    reason,
):
    runner = load_runner()
    monkeypatch.setattr(runner, "OUTPUT_ROOT", tmp_path / "outputs")
    monkeypatch.setattr(runner, "NATIVE_ROOT", tmp_path / "native")
    monkeypatch.setenv("D810_RUN_ID", case)
    monkeypatch.setattr(
        runner,
        "_execution_provenance",
        lambda root: {"git_revision": "b" * 40, "git_dirty": []},
    )
    observed = _install_fake_child(
        runner,
        monkeypatch,
        capture=capture_factory(runner),
        exit_code=exit_code,
    )

    result = runner.main([])

    assert result == 1
    receipt = json.loads((observed["run_dir"] / "receipt.json").read_text())
    assert receipt["status"] == "failed"
    assert receipt["reason"] == reason


def test_runner_refuses_existing_output_directory(tmp_path, monkeypatch):
    runner = load_runner()
    output_root = tmp_path / "outputs"
    run_dir = output_root / "custom-label/unit-run/ollvm"
    run_dir.mkdir(parents=True)
    monkeypatch.setattr(runner, "OUTPUT_ROOT", output_root)
    monkeypatch.setattr(runner, "NATIVE_ROOT", tmp_path / "native")
    monkeypatch.setenv("D810_RUN_ID", "unit-run")

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        runner.main(["--output-label", "custom-label"])

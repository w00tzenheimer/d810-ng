from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "tools" / "scripts" / "codemod_semantic_gap_ablation_config.py"
PLAN_SCRIPT = (
    REPO_ROOT / "tools" / "scripts" / "codemod_semantic_gap_ablation_plan.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location("codemod_semantic_gap", SCRIPT)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _sample_config() -> str:
    return """{
  "description": "sample",
  "ins_rules": [],
  "blk_rules": [
    {
      "name": "Unflattener",
      "is_activated": true,
      "config": {}
    },
    {
      "name": "EmulatedDispatcherUnflattener",
      "is_activated": false,
      "config": {}
    },
    {
      "name": "FixPredecessorOfConditionalJumpBlock",
      "is_activated": true,
      "config": {}
    }
  ]
}
"""


def test_ollvm_engine_only_preset_disables_legacy_and_sets_profile() -> None:
    mod = _load_module()

    out, report = mod.rewrite_config_text(
        _sample_config(),
        presets=("ollvm-engine-only",),
    )

    assert report.changed is True
    assert '"name": "Unflattener"' in out
    assert '"is_activated": false' in out
    assert '"name": "EmulatedDispatcherUnflattener"' in out
    assert '"profile": "state_dispatcher_map"' in out


def test_explicit_missing_rule_fails_without_allow_missing() -> None:
    mod = _load_module()

    try:
        mod.rewrite_config_text(_sample_config(), disable_rules=("MissingRule",))
    except ValueError as exc:
        assert "rule not found: MissingRule" in str(exc)
    else:
        raise AssertionError("missing rule should fail by default")


def test_apply_writes_generated_config(tmp_path: Path) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "out.json"
    input_path.write_text(_sample_config(), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--preset",
            "fixpred-off",
            "--apply",
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert output_path.exists()
    assert "wrote" in result.stdout
    assert '"name": "FixPredecessorOfConditionalJumpBlock"' in output_path.read_text(
        encoding="utf-8"
    )
    assert '"is_activated": false' in output_path.read_text(encoding="utf-8")


def test_dry_run_prints_diff_without_writing(tmp_path: Path) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "out.json"
    input_path.write_text(_sample_config(), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--preset",
            "fixpred-off",
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert "would write" in result.stdout
    assert "--- " in result.stdout
    assert "+++ " in result.stdout
    assert not output_path.exists()


def _write_plan_source_configs(root: Path) -> None:
    conf = root / "src" / "d810" / "conf"
    conf.mkdir(parents=True)
    (conf / "example_libobfuscated.json").write_text(
        _sample_config(),
        encoding="utf-8",
    )
    (conf / "default_unflattening_switch_case.json").write_text(
        """{
  "description": "tigress",
  "ins_rules": [],
  "blk_rules": [
    {
      "name": "UnflattenerSwitchCase",
      "is_activated": true,
      "config": {}
    }
  ]
}
""",
        encoding="utf-8",
    )


def test_plan_dry_run_generates_whole_ablation_artifact_set(tmp_path: Path) -> None:
    _write_plan_source_configs(tmp_path)

    result = subprocess.run(
        [
            sys.executable,
            str(PLAN_SCRIPT),
            "--root",
            str(tmp_path),
            "--unit",
            "ollvm-branch-ownership",
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert "would write" in result.stdout
    assert "ablation_ollvm_engine_only.json" in result.stdout
    assert "run_semantic_gap_ablation.sh" in result.stdout
    assert "gap_cards/ollvm_branch_ownership.md" in result.stdout
    assert not (
        tmp_path / ".tmp" / "semantic_gap_ablation" / "run_semantic_gap_ablation.sh"
    ).exists()


def test_plan_apply_writes_configs_runner_queries_manifest_and_gap_cards(
    tmp_path: Path,
) -> None:
    _write_plan_source_configs(tmp_path)

    result = subprocess.run(
        [
            sys.executable,
            str(PLAN_SCRIPT),
            "--root",
            str(tmp_path),
            "--unit",
            "ollvm-branch-ownership",
            "--apply",
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    conf = tmp_path / "src" / "d810" / "conf" / "ablation_ollvm_engine_only.json"
    runner = tmp_path / ".tmp" / "semantic_gap_ablation" / "run_semantic_gap_ablation.sh"
    queries = tmp_path / ".tmp" / "semantic_gap_ablation" / "witness_queries.sql"
    manifest = tmp_path / ".tmp" / "semantic_gap_ablation" / "manifest.json"
    gap_card = (
        tmp_path
        / ".tmp"
        / "semantic_gap_ablation"
        / "gap_cards"
        / "ollvm_branch_ownership.md"
    )

    assert conf.exists()
    assert '"profile": "state_dispatcher_map"' in conf.read_text(encoding="utf-8")
    assert runner.exists()
    assert runner.stat().st_mode & 0o111
    assert "test_function_ollvm_fla_bcf_sub" in runner.read_text(encoding="utf-8")
    assert "branch_ownership_proofs" in queries.read_text(encoding="utf-8")
    assert '"id": "ollvm-branch-ownership"' in manifest.read_text(encoding="utf-8")
    assert "Gap Card: OLLVM branch ownership semantic gap" in gap_card.read_text(
        encoding="utf-8"
    )

#!/usr/bin/env python3
"""Generate executable semantic-gap ablation artifacts.

Default mode is dry-run. Use ``--apply`` to write generated files.

This codemod materializes the retirement-rubric plan into reviewable artifacts:

- D810 project-config variants under ``src/d810/conf``;
- a shell runner with the legacy-on / engine-only / baseline dump commands;
- SQLite witness queries for the diagnostic DB;
- a machine-readable manifest;
- one gap-card template per ablation unit.

It intentionally does not execute IDA or Docker. The generated runner does that
after the file changes have been reviewed.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import codemod_semantic_gap_ablation_config as config_codemod


@dataclass(frozen=True)
class PlanUnit:
    unit_id: str
    title: str
    function: str
    source_project: str
    engine_project: str
    preset: str
    legacy_project: str
    current_project: str | None = None
    baseline_project: str = "default_instruction_only.json"
    notes: tuple[str, ...] = ()


PLAN_UNITS: dict[str, PlanUnit] = {
    "ollvm-branch-ownership": PlanUnit(
        unit_id="ollvm-branch-ownership",
        title="OLLVM branch ownership semantic gap",
        function="test_function_ollvm_fla_bcf_sub",
        source_project="example_libobfuscated.json",
        engine_project="ablation_ollvm_engine_only.json",
        preset="ollvm-engine-only",
        legacy_project="example_libobfuscated.json",
        current_project="default_unflattening_ollvm.json",
        notes=(
            "First output is a gap card, not a MopTracker patch.",
            "Look for unresolved branch ownership rows blocking terminal-payload retargeting.",
        ),
    ),
    "tigress-switch-transition-facts": PlanUnit(
        unit_id="tigress-switch-transition-facts",
        title="Tigress switch transition facts semantic gap",
        function="tigress_minmaxarray",
        source_project="default_unflattening_switch_case.json",
        engine_project="ablation_tigress_switch_engine_only.json",
        preset="tigress-switch-engine-only",
        legacy_project="default_unflattening_switch_case.json",
        notes=(
            "Planning variant until EmulatedDispatcherUnflattener accepts profile=tigress_switch.",
            "Gap target is switch_case_transition_facts without UnflattenerSwitchCase.",
        ),
    ),
    "fixpred-deletion": PlanUnit(
        unit_id="fixpred-deletion",
        title="FixPredecessor standalone-rule deletion check",
        function="test_function_ollvm_fla_bcf_sub",
        source_project="example_libobfuscated.json",
        engine_project="ablation_fixpred_off.json",
        preset="fixpred-off",
        legacy_project="example_libobfuscated.json",
        notes=(
            "If no semantic delta appears, disable/delete the standalone rule for that profile.",
            "If a delta appears, port only the missing cfg primitive.",
        ),
    ),
    "legacy-unflatteners-smoke": PlanUnit(
        unit_id="legacy-unflatteners-smoke",
        title="Broad legacy unflattener smoke ablation",
        function="test_function_ollvm_fla_bcf_sub",
        source_project="example_libobfuscated.json",
        engine_project="ablation_legacy_unflatteners_off.json",
        preset="legacy-unflatteners-off",
        legacy_project="example_libobfuscated.json",
        notes=(
            "Broad smoke pass; do not treat every delta as migration work.",
            "Use it to discover which narrower unit needs a focused gap card.",
        ),
    ),
}


WITNESS_QUERIES = """-- Semantic-gap ablation witness queries.
-- Usage:
--   sqlite3 "$DB" < witness_queries.sql

.headers on
.mode column

.print branch_ownership_proofs
SELECT proof_kind, trusted, COUNT(*) AS count
FROM branch_ownership_proofs
GROUP BY proof_kind, trusted
ORDER BY proof_kind, trusted;

.print state_transition_dispatch_resolutions
SELECT resolution_reason, COUNT(*) AS count
FROM state_transition_dispatch_resolutions
GROUP BY resolution_reason
ORDER BY resolution_reason;

.print state_dispatcher_rows
SELECT dispatcher_kind, resolution_reason, COUNT(*) AS count
FROM state_dispatcher_rows
GROUP BY dispatcher_kind, resolution_reason
ORDER BY dispatcher_kind, resolution_reason;

.print switch_case_transition_facts
SELECT transition_kind, proof_kind, COUNT(*) AS count
FROM switch_case_transition_facts
GROUP BY transition_kind, proof_kind
ORDER BY transition_kind, proof_kind;
"""


def _quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _safe_id(value: str) -> str:
    return value.replace("-", "_")


def _resolve(root: Path, value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    return path.resolve()


def _project_path(root: Path, project_name: str) -> Path:
    return root / "src" / "d810" / "conf" / project_name


def _render_config(root: Path, unit: PlanUnit) -> tuple[Path, str, tuple[str, ...]]:
    source = _project_path(root, unit.source_project)
    text = source.read_text(encoding="utf-8")
    out, report = config_codemod.rewrite_config_text(
        text,
        presets=(unit.preset,),
        allow_missing=True,
    )
    output = _project_path(root, unit.engine_project)
    return output, out, report.notes + report.warnings


def _dump_command(label: str, function: str, project: str) -> str:
    return (
        "D810_DIAG_SNAPSHOT=1 \"$D810CLI\" dump "
        "--worktree \"$WORKTREE\" "
        f"-f {_quote(function)} "
        f"-p {_quote(project)} "
        f"--label {_quote(label)}"
    )


def _no_project_command(label: str, function: str, project: str) -> str:
    return (
        "D810_DIAG_SNAPSHOT=1 \"$D810CLI\" dump "
        "--worktree \"$WORKTREE\" "
        f"-f {_quote(function)} "
        f"-p {_quote(project)} "
        f"--label {_quote(label)} "
        "--extra=--dump-no-project"
    )


def _render_runner(units: tuple[PlanUnit, ...], output_dir: Path) -> str:
    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        "WORKTREE=\"${WORKTREE:-unflattening-engine-extraction}\"",
        "D810CLI=\"${D810CLI:-./tools/d810cli.py}\"",
        f"ARTIFACT_DIR=\"${{ARTIFACT_DIR:-{output_dir.as_posix()}}}\"",
        "",
        "mkdir -p \"$ARTIFACT_DIR\"",
        "",
        "run_after_summary() {",
        "  local dump_path=\"$1\"",
        "  \"$D810CLI\" after --worktree \"$WORKTREE\" --dump \"$dump_path\" -n --stats",
        "}",
        "",
        "run_witness_queries() {",
        "  local db_path=\"$1\"",
        "  sqlite3 \"$db_path\" < \"$ARTIFACT_DIR/witness_queries.sql\"",
        "}",
        "",
        "# Each dump prints DUMP= and DB=. Capture those paths in the matching gap card.",
    ]

    for unit in units:
        sid = _safe_id(unit.unit_id)
        lines.extend(
            [
                "",
                f"echo '=== {unit.unit_id}: legacy-on ==='",
                _dump_command(
                    f"{sid}_legacy_on",
                    unit.function,
                    unit.legacy_project,
                ),
                f"echo '=== {unit.unit_id}: engine-only ==='",
                _dump_command(
                    f"{sid}_engine_only",
                    unit.function,
                    unit.engine_project,
                ),
            ]
        )
        if unit.current_project:
            lines.extend(
                [
                    f"echo '=== {unit.unit_id}: current-default ==='",
                    _dump_command(
                        f"{sid}_current_default",
                        unit.function,
                        unit.current_project,
                    ),
                ]
            )
        lines.extend(
            [
                f"echo '=== {unit.unit_id}: no-project baseline ==='",
                "# --extra replaces d810cli's default dump extras; this baseline is pseudocode-oriented.",
                _no_project_command(
                    f"{sid}_no_project",
                    unit.function,
                    unit.baseline_project,
                ),
            ]
        )

    lines.append("")
    return "\n".join(lines) + "\n"


def _render_gap_card(unit: PlanUnit) -> str:
    note_lines = "\n".join(f"- {note}" for note in unit.notes)
    if not note_lines:
        note_lines = "- None."
    return f"""# Gap Card: {unit.title}

Unit: `{unit.unit_id}`
Function: `{unit.function}`
Legacy project: `{unit.legacy_project}`
Engine-only project: `{unit.engine_project}`
Baseline project: `{unit.baseline_project}`

## Notes

{note_lines}

## Artifact Paths

- legacy-on DUMP:
- legacy-on DB:
- engine-only DUMP:
- engine-only DB:
- current-default DUMP:
- current-default DB:
- no-project DUMP:
- no-project DB:

## Observed Delta

- Source-level behavior changed:
- Runtime/oracle behavior changed:
- Dispatcher/state transition unresolved:
- Pseudocode recovery regression:
- Engine abstention blocker:
- Legacy live-mutation quirk:

## Witnesses

- Positive DB/proof witness:
- Negative witness / old bad trace:
- Rules fired delta:
- PatchPlan / GraphModification delta:

## Classification

Choose exactly one:

- No semantic gap
- Evidence gap
- Ownership/trust gap
- CFG primitive gap
- Materialization gap
- Scheduling/gating gap
- Unsafe legacy behavior

## Minimal Next Experiment

-

## Closure Condition

-
"""


def _render_manifest(units: tuple[PlanUnit, ...], output_dir: Path) -> str:
    payload: dict[str, Any] = {
        "artifact_dir": output_dir.as_posix(),
        "units": [
            {
                "id": unit.unit_id,
                "title": unit.title,
                "function": unit.function,
                "source_project": unit.source_project,
                "legacy_project": unit.legacy_project,
                "engine_project": unit.engine_project,
                "preset": unit.preset,
                "current_project": unit.current_project,
                "baseline_project": unit.baseline_project,
                "notes": list(unit.notes),
            }
            for unit in units
        ],
    }
    return json.dumps(payload, indent=2) + "\n"


def _render_readme(units: tuple[PlanUnit, ...]) -> str:
    unit_list = "\n".join(
        f"- `{unit.unit_id}`: `{unit.function}` via `{unit.engine_project}`"
        for unit in units
    )
    return f"""# Semantic-Gap Ablation Artifacts

Generated by `tools/scripts/codemod_semantic_gap_ablation_plan.py`.

Review generated configs before running the shell script. The runner executes
three or four dump modes per unit: legacy-on, engine-only, optional
current-default, and no-project baseline.

Units:

{unit_list}

Run:

```bash
WORKTREE=unflattening-engine-extraction .tmp/semantic_gap_ablation/run_semantic_gap_ablation.sh
```

For each printed `DB=...`, run:

```bash
sqlite3 "$DB" < .tmp/semantic_gap_ablation/witness_queries.sql
```

Fill the matching gap card under `.tmp/semantic_gap_ablation/gap_cards/`.
"""


def plan_files(root: Path, output_dir: Path, units: tuple[PlanUnit, ...]) -> dict[Path, str]:
    files: dict[Path, str] = {}
    config_notes: list[str] = []
    for unit in units:
        path, text, notes = _render_config(root, unit)
        files[path] = text
        config_notes.extend(f"{unit.unit_id}: {note}" for note in notes)

    files[output_dir / "run_semantic_gap_ablation.sh"] = _render_runner(
        units,
        output_dir,
    )
    files[output_dir / "witness_queries.sql"] = WITNESS_QUERIES
    files[output_dir / "manifest.json"] = _render_manifest(units, output_dir)
    files[output_dir / "README.md"] = _render_readme(units)
    if config_notes:
        files[output_dir / "config_rewrite_notes.txt"] = "\n".join(config_notes) + "\n"
    for unit in units:
        files[output_dir / "gap_cards" / f"{_safe_id(unit.unit_id)}.md"] = (
            _render_gap_card(unit)
        )
    return files


def _print_diff(path: Path, existing: str, generated: str) -> None:
    diff = difflib.unified_diff(
        existing.splitlines(),
        generated.splitlines(),
        fromfile=str(path),
        tofile=str(path),
        lineterm="",
    )
    for line in diff:
        print(line)


def _chmod_executable(path: Path) -> None:
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".", help="Repo/worktree root")
    parser.add_argument(
        "--output-dir",
        default=".tmp/semantic_gap_ablation",
        help="Artifact directory, relative to root unless absolute",
    )
    parser.add_argument(
        "--unit",
        action="append",
        choices=tuple(PLAN_UNITS),
        default=[],
        help="Generate only one unit; repeatable. Defaults to all units.",
    )
    parser.add_argument("--apply", action="store_true", help="Write generated files")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    output_dir = _resolve(root, args.output_dir)
    selected = tuple(PLAN_UNITS[name] for name in (args.unit or PLAN_UNITS.keys()))
    files = plan_files(root, output_dir, selected)

    changed = 0
    for path, generated in sorted(files.items()):
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
        if existing == generated:
            print(f"no changes for {path}")
            continue
        changed += 1
        if args.apply:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(generated, encoding="utf-8")
            if path.name.endswith(".sh"):
                _chmod_executable(path)
            print(f"wrote {path}")
        else:
            print(f"would write {path}")
            _print_diff(path, existing, generated)

    if changed == 0:
        print("no files needed rewriting")
    else:
        mode = "applied" if args.apply else "dry-run"
        print(f"{mode}: {changed} file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

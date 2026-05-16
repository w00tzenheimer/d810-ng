#!/usr/bin/env python3
"""Generate D810 project-config variants for semantic-gap ablation.

Default mode is dry-run. Use ``--apply`` to write the generated config.

The intended workflow mirrors other repo codemods:

    python tools/scripts/codemod_semantic_gap_ablation_config.py \
      --input src/d810/conf/example_libobfuscated.json \
      --preset ollvm-engine-only \
      --output src/d810/conf/ablation_ollvm_engine_only.json

Then re-run with ``--apply`` after reviewing the printed diff.
"""

from __future__ import annotations

import argparse
import copy
import difflib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


LEGACY_UNFLATTENER_RULES = (
    "FixPredecessorOfConditionalJumpBlock",
    "Unflattener",
    "UnflattenerSwitchCase",
    "UnflattenerTigressIndirect",
    "SingleIterationLoopUnflattener",
    "UnflattenerFakeJump",
    "BadWhileLoop",
)


@dataclass(frozen=True)
class RewriteReport:
    changed: bool
    notes: tuple[str, ...]
    warnings: tuple[str, ...]


def _rules(project: dict[str, Any]) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for key in ("ins_rules", "blk_rules"):
        section = project.get(key, [])
        if isinstance(section, list):
            rules.extend(rule for rule in section if isinstance(rule, dict))
    return rules


def _blk_rules(project: dict[str, Any]) -> list[dict[str, Any]]:
    section = project.setdefault("blk_rules", [])
    if not isinstance(section, list):
        raise TypeError("project config field 'blk_rules' must be a list")
    return section


def _matching_rules(project: dict[str, Any], name: str) -> list[dict[str, Any]]:
    return [rule for rule in _rules(project) if rule.get("name") == name]


def _set_rule_active(
    project: dict[str, Any],
    name: str,
    active: bool,
    *,
    allow_missing: bool,
) -> tuple[list[str], list[str]]:
    notes: list[str] = []
    warnings: list[str] = []
    matches = _matching_rules(project, name)
    if not matches:
        msg = f"rule not found: {name}"
        if allow_missing:
            warnings.append(msg)
            return notes, warnings
        raise ValueError(msg)
    for rule in matches:
        old = bool(rule.get("is_activated", False))
        rule["is_activated"] = active
        if old != active:
            notes.append(f"{name}: is_activated {old} -> {active}")
    return notes, warnings


def _ensure_blk_rule(
    project: dict[str, Any],
    name: str,
    *,
    active: bool,
    config: dict[str, Any] | None = None,
) -> list[str]:
    notes: list[str] = []
    matches = _matching_rules(project, name)
    if not matches:
        rule = {
            "name": name,
            "is_activated": active,
            "config": dict(config or {}),
        }
        _blk_rules(project).append(rule)
        return [f"{name}: added blk_rule active={active}"]
    for rule in matches:
        old = bool(rule.get("is_activated", False))
        rule["is_activated"] = active
        if old != active:
            notes.append(f"{name}: is_activated {old} -> {active}")
        if config:
            rule_config = rule.setdefault("config", {})
            if not isinstance(rule_config, dict):
                rule_config = {}
                rule["config"] = rule_config
            for key, value in config.items():
                old_value = rule_config.get(key)
                rule_config[key] = value
                if old_value != value:
                    notes.append(f"{name}: config.{key} {old_value!r} -> {value!r}")
    return notes


def _parse_value(raw: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def _set_nested(mapping: dict[str, Any], dotted_key: str, value: Any) -> None:
    parts = [part for part in dotted_key.split(".") if part]
    if not parts:
        raise ValueError("config key must not be empty")
    current = mapping
    for part in parts[:-1]:
        child = current.setdefault(part, {})
        if not isinstance(child, dict):
            raise ValueError(f"config key {dotted_key!r} crosses non-object {part!r}")
        current = child
    current[parts[-1]] = value


def _set_rule_config(
    project: dict[str, Any],
    name: str,
    assignment: str,
    *,
    allow_missing: bool,
) -> tuple[list[str], list[str]]:
    if "=" not in assignment:
        raise ValueError(f"expected KEY=VALUE assignment, got {assignment!r}")
    key, raw_value = assignment.split("=", 1)
    value = _parse_value(raw_value)
    notes: list[str] = []
    warnings: list[str] = []
    matches = _matching_rules(project, name)
    if not matches:
        msg = f"rule not found: {name}"
        if allow_missing:
            warnings.append(msg)
            return notes, warnings
        raise ValueError(msg)
    for rule in matches:
        rule_config = rule.setdefault("config", {})
        if not isinstance(rule_config, dict):
            rule_config = {}
            rule["config"] = rule_config
        before = copy.deepcopy(rule_config)
        _set_nested(rule_config, key, value)
        if before != rule_config:
            notes.append(f"{name}: config.{key} set to {value!r}")
    return notes, warnings


def _apply_preset(project: dict[str, Any], preset: str) -> tuple[list[str], list[str]]:
    notes: list[str] = []
    warnings: list[str] = []

    if preset == "ollvm-engine-only":
        n, w = _set_rule_active(
            project, "Unflattener", False, allow_missing=True
        )
        notes.extend(n)
        warnings.extend(w)
        notes.extend(
            _ensure_blk_rule(
                project,
                "EmulatedDispatcherUnflattener",
                active=True,
                config={"profile": "state_dispatcher_map"},
            )
        )
    elif preset == "tigress-switch-engine-only":
        n, w = _set_rule_active(
            project, "UnflattenerSwitchCase", False, allow_missing=True
        )
        notes.extend(n)
        warnings.extend(w)
        notes.extend(
            _ensure_blk_rule(
                project,
                "EmulatedDispatcherUnflattener",
                active=True,
                config={"profile": "tigress_switch"},
            )
        )
    elif preset == "fixpred-off":
        n, w = _set_rule_active(
            project,
            "FixPredecessorOfConditionalJumpBlock",
            False,
            allow_missing=True,
        )
        notes.extend(n)
        warnings.extend(w)
    elif preset == "legacy-unflatteners-off":
        for name in LEGACY_UNFLATTENER_RULES:
            n, w = _set_rule_active(project, name, False, allow_missing=True)
            notes.extend(n)
            warnings.extend(w)
    else:
        raise ValueError(f"unknown preset: {preset}")

    return notes, warnings


def rewrite_config_text(
    text: str,
    *,
    presets: tuple[str, ...] = (),
    disable_rules: tuple[str, ...] = (),
    enable_rules: tuple[str, ...] = (),
    set_rule_configs: tuple[tuple[str, str], ...] = (),
    allow_missing: bool = False,
) -> tuple[str, RewriteReport]:
    project = json.loads(text)
    if not isinstance(project, dict):
        raise ValueError("project config root must be a JSON object")

    notes: list[str] = []
    warnings: list[str] = []

    for preset in presets:
        n, w = _apply_preset(project, preset)
        notes.extend(n)
        warnings.extend(w)

    for name in disable_rules:
        n, w = _set_rule_active(
            project, name, False, allow_missing=allow_missing
        )
        notes.extend(n)
        warnings.extend(w)

    for name in enable_rules:
        n, w = _set_rule_active(project, name, True, allow_missing=allow_missing)
        notes.extend(n)
        warnings.extend(w)

    for name, assignment in set_rule_configs:
        n, w = _set_rule_config(
            project, name, assignment, allow_missing=allow_missing
        )
        notes.extend(n)
        warnings.extend(w)

    out = json.dumps(project, indent=2) + "\n"
    return out, RewriteReport(
        changed=(out != text),
        notes=tuple(notes),
        warnings=tuple(warnings),
    )


def _default_output_path(input_path: Path, presets: tuple[str, ...]) -> Path:
    suffix = "_".join(presets) if presets else "custom"
    suffix = suffix.replace("-", "_")
    return input_path.with_name(f"{input_path.stem}_ablation_{suffix}.json")


def _resolve(root: Path, value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    return path.resolve()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".", help="Repo/worktree root")
    parser.add_argument("--input", required=True, help="Input project config JSON")
    parser.add_argument("--output", help="Output project config JSON")
    parser.add_argument(
        "--preset",
        action="append",
        choices=(
            "ollvm-engine-only",
            "tigress-switch-engine-only",
            "fixpred-off",
            "legacy-unflatteners-off",
        ),
        default=[],
        help="Apply a named ablation preset",
    )
    parser.add_argument(
        "--disable-rule",
        action="append",
        default=[],
        help="Set a rule's is_activated flag to false",
    )
    parser.add_argument(
        "--enable-rule",
        action="append",
        default=[],
        help="Set a rule's is_activated flag to true",
    )
    parser.add_argument(
        "--set-rule-config",
        action="append",
        nargs=2,
        metavar=("RULE", "KEY=VALUE"),
        default=[],
        help="Set a rule config value; VALUE is parsed as JSON when possible",
    )
    parser.add_argument(
        "--allow-missing",
        action="store_true",
        help="Do not fail when explicit rule edits match no rule",
    )
    parser.add_argument("--apply", action="store_true", help="Write output")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    input_path = _resolve(root, args.input)
    presets = tuple(args.preset)
    output_path = (
        _resolve(root, args.output)
        if args.output
        else _default_output_path(input_path, presets)
    )

    src = input_path.read_text(encoding="utf-8")
    out, report = rewrite_config_text(
        src,
        presets=presets,
        disable_rules=tuple(args.disable_rule),
        enable_rules=tuple(args.enable_rule),
        set_rule_configs=tuple((a[0], a[1]) for a in args.set_rule_config),
        allow_missing=bool(args.allow_missing),
    )

    for warning in report.warnings:
        print(f"warning: {warning}")
    for note in report.notes:
        print(f"change: {note}")

    existing = output_path.read_text(encoding="utf-8") if output_path.exists() else ""
    if existing == out:
        print(f"no changes for {output_path}")
        return 0

    if args.apply:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(out, encoding="utf-8")
        print(f"wrote {output_path}")
    else:
        print(f"would write {output_path}")
        diff = difflib.unified_diff(
            existing.splitlines() if existing else src.splitlines(),
            out.splitlines(),
            fromfile=str(output_path if existing else input_path),
            tofile=str(output_path),
            lineterm="",
        )
        for line in diff:
            print(line)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Rewrite bundled config-v2 MBA rule selections to stable transform IDs."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping
from pathlib import Path

from d810.passes.mba_transform_options import mba_transform_id, mba_transform_stages


def _pipeline(payload: Mapping[str, object]) -> list[object]:
    additional = payload.get("additional_configuration", {})
    if not isinstance(additional, dict):
        return []
    pipeline = additional.get("pipeline_v2", [])
    return pipeline if isinstance(pipeline, list) else []


def _rewrite_payload(payload: dict[str, object], *, source: Path) -> bool:
    known_ids = frozenset(stage.stage_id for stage in mba_transform_stages())
    changed = False
    for entry in _pipeline(payload):
        if not isinstance(entry, dict):
            continue
        pass_id = entry.get("pass_id", entry.get("pass"))
        if pass_id != "mba-simplify" or "rules" not in entry:
            continue
        rules = entry["rules"]
        if not isinstance(rules, dict):
            raise ValueError(f"{source}: mba-simplify rules must be an object")
        if rules.get("include_groups") or rules.get("exclude_groups"):
            raise ValueError(f"{source}: MBA rule groups cannot be rewritten exactly")
        include = rules.get("include", [])
        exclude = frozenset(rules.get("exclude", []))
        if not isinstance(include, list) or not all(
            isinstance(name, str) for name in include
        ):
            raise ValueError(f"{source}: MBA rules.include must be a string list")
        selected_names = tuple(name for name in include if name not in exclude)
        transform_ids = tuple(mba_transform_id(name) for name in selected_names)
        unknown_ids = tuple(
            transform_id
            for transform_id in transform_ids
            if transform_id not in known_ids
        )
        if unknown_ids:
            raise ValueError(
                f"{source}: no registered MBA binding for {list(unknown_ids)}"
            )
        if len(set(transform_ids)) != len(transform_ids):
            raise ValueError(f"{source}: MBA transform conversion is not one-to-one")

        raw_rule_options = rules.get("options", {})
        if not isinstance(raw_rule_options, dict):
            raise ValueError(f"{source}: MBA rules.options must be an object")
        unknown_option_names = tuple(
            name for name in raw_rule_options if name not in include
        )
        if unknown_option_names:
            raise ValueError(
                f"{source}: options reference unknown rules {list(unknown_option_names)}"
            )
        transform_options = {
            mba_transform_id(name): options
            for name, options in raw_rule_options.items()
            if name in selected_names
        }
        options = entry.get("options", {})
        if not isinstance(options, dict):
            raise ValueError(f"{source}: MBA options must be an object")
        options["transforms"] = list(transform_ids)
        options["transform_options"] = transform_options
        entry["options"] = options
        del entry["rules"]
        changed = True
    return changed


def _candidate_files(root: Path) -> tuple[Path, ...]:
    if root.is_file():
        return (root,)
    return tuple(sorted(root.glob("*config_v2_canary.json")))


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    parser.add_argument("root", type=Path)
    args = parser.parse_args()

    changed_paths: list[Path] = []
    rewritten: dict[Path, str] = {}
    for path in _candidate_files(args.root):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if _rewrite_payload(payload, source=path):
            changed_paths.append(path)
            rewritten[path] = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"

    if args.check:
        for path in changed_paths:
            print(path)
        return 1 if changed_paths else 0
    for path, content in rewritten.items():
        path.write_text(content, encoding="utf-8")
    print(f"rewrote {len(rewritten)} bundled config-v2 files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

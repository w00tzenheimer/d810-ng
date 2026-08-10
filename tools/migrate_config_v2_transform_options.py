#!/usr/bin/env python3
"""Migrate inert legacy MBA transform options to config-v2 typed fields.

The config-v2 editor only accepts pass-declared controls.  Earlier canaries
persisted a ``dump_intermediate_microcode`` false/null value and a null
``maturities`` value for every MBA transform, although those values simply
asked the runtime to use its defaults.  This tool removes only those inert
entries.  Any setting without a corresponding typed editor field stops the
migration with its exact config path so it can be modelled deliberately.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

from d810.core import typing


class MigrationError(ValueError):
    """A legacy setting needs a typed ``PassEditorSpec`` field first."""


_TYPED_TRANSFORM_FIELDS = {
    "example-guessing": frozenset(
        {
            "min_nb_var",
            "max_nb_var",
            "min_nb_diff_opcodes",
            "max_nb_diff_opcodes",
        }
    ),
    "z-3-constant-optimization": frozenset(
        {
            "min_nb_opcode",
            "min_nb_constant",
        }
    ),
}


def _is_inert_legacy_field(name: str, value: object) -> bool:
    return (name == "maturities" and value is None) or (
        name == "dump_intermediate_microcode" and value in (None, False)
    )


def _migrate_transform_options(
    transform_options: object,
    *,
    config_path: str,
) -> tuple[dict[str, dict[str, object]], bool]:
    if not isinstance(transform_options, dict):
        raise MigrationError(f"{config_path} must be an object")
    migrated: dict[str, dict[str, object]] = {}
    changed = False
    for transform_id, raw_options in transform_options.items():
        if not isinstance(transform_id, str):
            raise MigrationError(f"{config_path} has a non-string transform ID")
        if not isinstance(raw_options, dict):
            raise MigrationError(f"{config_path}.{transform_id} must be an object")
        fields: dict[str, object] = {}
        for name, value in raw_options.items():
            if not isinstance(name, str):
                raise MigrationError(
                    f"{config_path}.{transform_id} has a non-string option name"
                )
            if _is_inert_legacy_field(name, value):
                changed = True
                continue
            if name not in _TYPED_TRANSFORM_FIELDS.get(transform_id, frozenset()):
                raise MigrationError(
                    f"{config_path}.{transform_id}.{name} has no typed editor field"
                )
            fields[name] = copy.deepcopy(value)
        if fields:
            migrated[transform_id] = fields
        elif raw_options:
            changed = True
    return migrated, changed


def migrate_document(document: dict[str, object]) -> bool:
    """Migrate every ``mba-simplify`` transform-options map in-place."""
    additional = document.get("additional_configuration")
    if not isinstance(additional, dict):
        raise MigrationError("additional_configuration must be an object")
    pipeline = additional.get("pipeline_v2")
    if not isinstance(pipeline, list):
        raise MigrationError("additional_configuration.pipeline_v2 must be a list")

    changed = False
    for index, entry in enumerate(pipeline):
        if not isinstance(entry, dict):
            raise MigrationError(f"additional_configuration.pipeline_v2[{index}] must be an object")
        if entry.get("pass_id") != "mba-simplify":
            continue
        options = entry.get("options", {})
        if not isinstance(options, dict):
            raise MigrationError(
                f"additional_configuration.pipeline_v2[{index}].options must be an object"
            )
        raw_transform_options = options.get("transform_options")
        if raw_transform_options is None:
            continue
        path = f"additional_configuration.pipeline_v2[{index}].options.transform_options"
        migrated, option_changed = _migrate_transform_options(
            raw_transform_options,
            config_path=path,
        )
        if option_changed:
            options["transform_options"] = migrated
            changed = True
    return changed


def _migrate_path(path: Path, *, write: bool) -> bool:
    try:
        document: typing.Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MigrationError(f"{path}: could not read JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise MigrationError(f"{path}: config-v2 document must be an object")
    changed = migrate_document(document)
    if changed and write:
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return changed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", metavar="CONFIG", nargs="+", type=Path)
    parser.add_argument(
        "--write",
        action="store_true",
        help="write migrated JSON in place; otherwise only report candidates",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    failed = False
    for path in args.paths:
        try:
            changed = _migrate_path(path, write=args.write)
        except MigrationError as exc:
            print(f"ERROR {exc}")
            failed = True
            continue
        state = "changed" if changed else "unchanged"
        print(f"{state} {path}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

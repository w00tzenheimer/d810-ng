#!/usr/bin/env python3
"""Analyze d810 verify-failure artifacts and suggest likely root causes.

Overview
--------
`analyze_verify_failures.py` is a triage helper for JSON artifacts emitted by
`d810.hexrays.cfg_utils.capture_failure_artifact()`. It condenses noisy verify
failures into:

1. A directory-level summary (entry EAs, phases, modification types, top errors)
2. Per-artifact structural signals (orphans, conditional blocks, capture depth)
3. Heuristic hypotheses to speed up root-cause analysis

The script is intentionally read-only: it never mutates artifacts.

Quick Start
-----------
Analyze latest artifacts from the default capture directory:

    python3 tools/analyze_verify_failures.py

Analyze a specific directory and include all files:

    python3 tools/analyze_verify_failures.py /path/to/verify_failures --latest 0

Analyze a single artifact:

    python3 tools/analyze_verify_failures.py /path/to/verify_fail_....json

Filter to one function entry EA:

    python3 tools/analyze_verify_failures.py --entry-ea 0x77c0

Emit machine-readable JSON:

    python3 tools/analyze_verify_failures.py --latest 25 --json

CLI Behavior
------------
- Positional `path` is optional:
  - file: analyze exactly that file
  - directory: analyze files matching `verify_fail_*.json`
  - omitted: use `~/.idapro/logs/d810_logs/verify_failures`
- `--latest N` applies only to directory mode:
  - default `20`
  - `0` means "all artifacts"
- `--entry-ea` accepts hex (`0x...`) or decimal
- Exit codes:
  - `0`: success
  - `1`: no matching/readable artifacts
  - `2`: invalid path/arguments

Artifact Contract (expected from capture_failure_artifact)
----------------------------------------------------------
Top-level required keys:
- `schema_version` (int)
- `timestamp_utc` (str)
- `context` (str)
- `error_type` (str)
- `error_message` (str)
- `mba` (dict with at least `entry_ea`, `maturity`, `qty`)
- `focus_blocks` (list)
- `captured_blocks` (list of block snapshots)
- `metadata` (dict)

Captured block entries are expected to be dicts and may include:
- `serial`, `type`, `nsucc`, `npred`, `succs`, `preds`, `nextb`, `prevb`, `tail`

The analyzer is tolerant of partial data. Contract mismatches are reported as
warnings in hypotheses instead of crashing.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from collections import Counter, defaultdict
from typing import Any

DEFAULT_ARTIFACT_DIR = pathlib.Path("~/.idapro/logs/d810_logs/verify_failures").expanduser()


def _load_artifact(path: pathlib.Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _discover_paths(path_arg: str | None, latest: int | None) -> list[pathlib.Path]:
    if path_arg is None:
        base = DEFAULT_ARTIFACT_DIR
    else:
        base = pathlib.Path(path_arg).expanduser()

    if base.is_file():
        return [base]

    if not base.exists() or not base.is_dir():
        raise FileNotFoundError(f"artifact path not found: {base}")

    paths = sorted(base.glob("verify_fail_*.json"))
    if latest is not None and latest > 0:
        paths = paths[-latest:]
    return paths


def _validate_capture_contract(payload: dict[str, Any]) -> list[str]:
    """Return contract warnings for a captured verify-failure payload.

    The checker validates only the schema that this analyzer *depends on*.
    It intentionally does not reject unknown fields.
    """
    warnings: list[str] = []
    required_types = {
        "schema_version": int,
        "timestamp_utc": str,
        "context": str,
        "error_type": str,
        "error_message": str,
        "mba": dict,
        "focus_blocks": list,
        "captured_blocks": list,
        "metadata": dict,
    }
    for key, expected_type in required_types.items():
        if key not in payload:
            warnings.append(f"missing required key '{key}'")
            continue
        if not isinstance(payload[key], expected_type):
            warnings.append(
                f"key '{key}' has type {type(payload[key]).__name__}, "
                f"expected {expected_type.__name__}"
            )

    mba = payload.get("mba", {})
    if isinstance(mba, dict):
        for key in ("entry_ea", "maturity", "qty"):
            if key not in mba:
                warnings.append(f"mba missing '{key}'")

    captured_blocks = payload.get("captured_blocks", [])
    if isinstance(captured_blocks, list):
        for index, blk in enumerate(captured_blocks):
            if not isinstance(blk, dict):
                warnings.append(f"captured_blocks[{index}] is not an object")
                continue
            if "serial" not in blk:
                warnings.append(f"captured_blocks[{index}] missing 'serial'")
    return warnings


def _entry_ea(payload: dict[str, Any]) -> int:
    mba = payload.get("mba", {})
    try:
        return int(mba.get("entry_ea", 0))
    except (TypeError, ValueError):
        return 0


def _find_modification(payload: dict[str, Any]) -> dict[str, Any] | None:
    md = payload.get("metadata", {})
    if isinstance(md.get("modification"), dict):
        return md["modification"]
    if isinstance(md.get("rolled_back_modification"), dict):
        return md["rolled_back_modification"]
    return None


def _find_phase(payload: dict[str, Any]) -> str | None:
    md = payload.get("metadata", {})
    phase = md.get("phase")
    return str(phase) if phase is not None else None


def _collect_structural_signals(payload: dict[str, Any]) -> dict[str, Any]:
    blocks = payload.get("captured_blocks", [])
    if not isinstance(blocks, list):
        blocks = []

    orphan_blocks: list[int] = []
    conditional_blocks: list[int] = []
    empty_blocks: list[int] = []

    for blk in blocks:
        if not isinstance(blk, dict):
            continue
        serial = blk.get("serial")
        if not isinstance(serial, int):
            continue

        npred = blk.get("npred")
        nsucc = blk.get("nsucc")
        btype = blk.get("type")

        if serial != 0 and npred == 0:
            orphan_blocks.append(serial)
        if nsucc == 2 or btype == 4:
            conditional_blocks.append(serial)
        if npred == 0 and nsucc == 0:
            empty_blocks.append(serial)

    return {
        "orphan_blocks": sorted(set(orphan_blocks)),
        "conditional_blocks": sorted(set(conditional_blocks)),
        "empty_blocks": sorted(set(empty_blocks)),
        "captured_block_count": len(blocks),
    }


def _infer_hypotheses(payload: dict[str, Any]) -> list[str]:
    context = str(payload.get("context", "")).lower()
    error_message = str(payload.get("error_message", "")).lower()
    phase = (_find_phase(payload) or "").lower()
    mod = _find_modification(payload) or {}
    mod_type = str(mod.get("mod_type", "")).upper()
    structural = _collect_structural_signals(payload)

    hypotheses: list[str] = []

    if "after rollback" in context or phase == "rollback_verify":
        hypotheses.append(
            "Rollback did not recover verify state; first failing modification is likely the primary corruption source."
        )

    if mod_type == "BLOCK_CREATE_WITH_REDIRECT":
        hypotheses.append(
            "create+redirect path failed; inspect copied instruction dependencies and helper-block edge wiring."
        )
        if "50860" in error_message or "unknown exception" in error_message:
            hypotheses.append(
                "Likely MMAT_CALLS dataflow inconsistency after helper-block insertion (common with missing producer closure)."
            )

    if mod_type == "BLOCK_GOTO_CHANGE":
        hypotheses.append(
            "Direct goto rewrite failed; inspect whether source/target shape assumes conditional predecessors or non-1way transitions."
        )

    if "after deferred modification" in context and not mod_type:
        hypotheses.append(
            "Deferred modification failed but artifact lacks explicit modification metadata; inspect recent_modifications chain."
        )

    if "optimizing unflattenerfakejump" in context or context.endswith("after rewriting"):
        hypotheses.append(
            "This may be a secondary verify failure after earlier corruption in the same pipeline."
        )

    if structural["orphan_blocks"]:
        hypotheses.append(
            f"Orphan blocks detected (npred=0): {structural['orphan_blocks'][:5]}."
        )

    if structural["empty_blocks"]:
        hypotheses.append(
            f"Empty/disconnected blocks captured: {structural['empty_blocks'][:5]}."
        )

    if (
        structural["captured_block_count"] <= 2
        and not payload.get("focus_blocks")
        and "unknown exception" in error_message
    ):
        hypotheses.append(
            "Low-context artifact (few captured blocks); rerun with incremental verify metadata to localize first bad rewrite."
        )

    if not hypotheses:
        hypotheses.append(
            "No specific heuristic matched. Inspect context, modification metadata, and captured block diffs."
        )

    contract_warnings = _validate_capture_contract(payload)
    if contract_warnings:
        hypotheses.append(
            "Artifact contract warnings: " + "; ".join(contract_warnings[:3])
        )

    return hypotheses


def _format_entry(payload: dict[str, Any], path: pathlib.Path) -> str:
    mba = payload.get("mba", {})
    mod = _find_modification(payload) or {}
    phase = _find_phase(payload) or "n/a"
    structural = _collect_structural_signals(payload)
    hypotheses = _infer_hypotheses(payload)

    lines: list[str] = []
    lines.append(f"Artifact: {path}")
    lines.append(
        f"  Time: {payload.get('timestamp_utc', 'n/a')}  Entry: {mba.get('entry_ea_hex', hex(_entry_ea(payload)))}"
    )
    lines.append(
        f"  Maturity: {mba.get('maturity', 'n/a')}  Blocks: {mba.get('qty', 'n/a')}  Phase: {phase}"
    )
    lines.append(f"  Context: {payload.get('context', 'n/a')}")
    lines.append(
        f"  Error: {payload.get('error_type', 'n/a')}: {payload.get('error_message', 'n/a')}"
    )

    if mod:
        lines.append(
            "  Modification: "
            f"{mod.get('mod_type', 'n/a')} blk={mod.get('block_serial', 'n/a')} "
            f"-> {mod.get('new_target', 'n/a')} ({mod.get('description', 'n/a')})"
        )

    lines.append(
        "  Structural signals: "
        f"captured={structural['captured_block_count']} "
        f"orphans={len(structural['orphan_blocks'])} "
        f"conditional={len(structural['conditional_blocks'])}"
    )
    contract_warnings = _validate_capture_contract(payload)
    if contract_warnings:
        lines.append("  Contract warnings:")
        for warning in contract_warnings:
            lines.append(f"    - {warning}")
    lines.append("  Hypotheses:")
    for item in hypotheses:
        lines.append(f"    - {item}")
    return "\n".join(lines)


def _aggregate(paths: list[pathlib.Path], payloads: list[dict[str, Any]]) -> str:
    by_entry: dict[int, int] = defaultdict(int)
    by_phase: Counter[str] = Counter()
    by_mod_type: Counter[str] = Counter()
    by_error: Counter[str] = Counter()

    for payload in payloads:
        by_entry[_entry_ea(payload)] += 1
        by_phase[str(_find_phase(payload) or "n/a")] += 1
        mod = _find_modification(payload) or {}
        by_mod_type[str(mod.get("mod_type", "n/a"))] += 1
        by_error[str(payload.get("error_message", "n/a"))] += 1

    lines = []
    lines.append(f"Analyzed {len(paths)} artifact(s)")
    lines.append("Summary:")
    lines.append(
        "  By entry_ea: "
        + ", ".join(f"{hex(ea)}={count}" for ea, count in sorted(by_entry.items()))
    )
    lines.append(
        "  By phase: "
        + ", ".join(f"{phase}={count}" for phase, count in by_phase.most_common())
    )
    lines.append(
        "  By mod_type: "
        + ", ".join(f"{mt}={count}" for mt, count in by_mod_type.most_common())
    )
    lines.append(
        "  Top errors: "
        + ", ".join(f"{err}={count}" for err, count in by_error.most_common(5))
    )
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Analyze d810 verify-failure artifacts and suggest likely root causes."
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help=(
            "Artifact file or directory containing verify_fail_*.json "
            f"(default: {DEFAULT_ARTIFACT_DIR})"
        ),
    )
    parser.add_argument(
        "--latest",
        type=int,
        default=20,
        help="When path is a directory, only analyze the latest N artifacts (default: 20). Use 0 for all.",
    )
    parser.add_argument(
        "--entry-ea",
        default=None,
        help="Filter by function entry EA (hex like 0x77c0 or decimal).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON summary.",
    )
    args = parser.parse_args(argv)

    latest = None if args.latest == 0 else args.latest
    try:
        paths = _discover_paths(args.path, latest)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if not paths:
        print("No verify_fail artifacts found.", file=sys.stderr)
        return 1

    payloads: list[dict[str, Any]] = []
    for path in paths:
        try:
            payloads.append(_load_artifact(path))
        except Exception as exc:  # pragma: no cover - best-effort CLI robustness
            print(f"Failed to read {path}: {exc}", file=sys.stderr)

    if not payloads:
        print("No readable artifacts.", file=sys.stderr)
        return 1

    if args.entry_ea is not None:
        try:
            wanted = int(args.entry_ea, 0)
        except ValueError:
            print(f"Invalid --entry-ea: {args.entry_ea}", file=sys.stderr)
            return 2
        filtered = [(p, d) for p, d in zip(paths, payloads) if _entry_ea(d) == wanted]
        if not filtered:
            print(f"No artifacts matched entry EA {hex(wanted)}", file=sys.stderr)
            return 1
        paths = [item[0] for item in filtered]
        payloads = [item[1] for item in filtered]

    if args.json:
        by_entry: Counter[int] = Counter(_entry_ea(d) for d in payloads)
        by_phase: Counter[str] = Counter(str(_find_phase(d) or "n/a") for d in payloads)
        by_mod_type: Counter[str] = Counter(
            str((_find_modification(d) or {}).get("mod_type", "n/a")) for d in payloads
        )
        data = {
            "count": len(paths),
            "summary": {
                "entries": {hex(k): v for k, v in sorted(by_entry.items())},
                "phases": dict(by_phase),
                "mod_types": dict(by_mod_type),
            },
            "artifacts": [],
        }
        for path, payload in zip(paths, payloads):
            data["artifacts"].append(
                {
                    "path": str(path),
                    "timestamp_utc": payload.get("timestamp_utc"),
                    "entry_ea": _entry_ea(payload),
                    "context": payload.get("context"),
                    "error_type": payload.get("error_type"),
                    "error_message": payload.get("error_message"),
                    "phase": _find_phase(payload),
                    "modification": _find_modification(payload),
                    "hypotheses": _infer_hypotheses(payload),
                    "structural_signals": _collect_structural_signals(payload),
                    "contract_warnings": _validate_capture_contract(payload),
                }
            )
        print(json.dumps(data, indent=2, sort_keys=True))
        return 0

    print(_aggregate(paths, payloads))
    for path, payload in zip(paths, payloads):
        print()
        print(_format_entry(payload, path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

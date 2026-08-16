#!/usr/bin/env python3
"""Verify the explicit SCCP/cache performance receipt.

This module is deliberately independent of IDA.  The benchmark produces the
receipt inside IDA; this command validates its shape, parity, work evidence,
and performance thresholds afterwards.  It is not imported by ordinary
runtime collection except by the explicit performance test module.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import sys

from d810.core.typing import Any


_HERE = Path(__file__).resolve().parent
_SCHEMA_PATH = _HERE / "sccp_perf_receipt.schema.json"
_EXPECTED_CAPACITIES = frozenset(
    (constant, ast) for constant in (1000, 4096, 8192) for ast in (20480, 40960, 81920)
)
_REQUIRED_RUN_FIELDS = frozenset(
    {
        "function_ea",
        "maturity",
        "overlay",
        "backend",
        "status",
        "program_fingerprint",
        "wall_seconds",
        "adapter_seconds",
        "solver_seconds",
        "cfg_events",
        "value_events",
        "constants_exposed",
        "edges_exposed",
        "fcp_patches",
        "cache_stats",
        "pseudocode_sha256",
        "cfg_sha256",
        "real_api_calls",
    }
)
_SCCP_COUNTERS = (
    "requests",
    "executions",
    "reuses",
    "fallbacks",
    "converged",
    "work_limit",
    "block_limit",
    "errors",
    "python_runs",
    "cython_runs",
    "cfg_events",
    "value_events",
    "adapter_seconds",
    "solver_seconds",
    "constants_exposed",
    "edges_exposed",
)


class ReceiptError(ValueError):
    """Raised for a malformed or failing performance receipt."""


def _schema_type(value: object, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return type(value) is int
    if expected == "number":
        return type(value) in (int, float) and not isinstance(value, bool)
    if expected == "null":
        return value is None
    if expected == "boolean":
        return type(value) is bool
    raise ReceiptError(f"unsupported schema type {expected!r}")


def _resolve_ref(schema: dict[str, Any], ref: str) -> dict[str, Any]:
    prefix = "#/$defs/"
    if not ref.startswith(prefix):
        raise ReceiptError(f"unsupported schema reference {ref!r}")
    try:
        return schema["$defs"][ref[len(prefix) :]]
    except KeyError as exc:
        raise ReceiptError(f"unknown schema reference {ref!r}") from exc


def _validate_schema_value(
    value: object,
    rule: dict[str, Any],
    schema: dict[str, Any],
    path: str,
) -> None:
    if "$ref" in rule:
        _validate_schema_value(value, _resolve_ref(schema, rule["$ref"]), schema, path)
        return

    if "const" in rule and value != rule["const"]:
        raise ReceiptError(f"{path} must equal {rule['const']!r}")
    if "enum" in rule and value not in rule["enum"]:
        raise ReceiptError(f"{path} must be one of {rule['enum']!r}")

    expected_type = rule.get("type")
    if expected_type is not None:
        expected_types = (
            expected_type if isinstance(expected_type, list) else [expected_type]
        )
        if not any(_schema_type(value, candidate) for candidate in expected_types):
            raise ReceiptError(f"{path} has invalid type")

    if isinstance(value, str):
        if "minLength" in rule and len(value) < rule["minLength"]:
            raise ReceiptError(f"{path} must not be empty")
        if "pattern" in rule:
            import re

            if re.fullmatch(rule["pattern"], value) is None:
                raise ReceiptError(f"{path} does not match the required pattern")

    if type(value) in (int, float) and not isinstance(value, bool):
        if not math.isfinite(float(value)):
            raise ReceiptError(f"{path} must be finite")
        if "minimum" in rule and value < rule["minimum"]:
            raise ReceiptError(f"{path} is below its minimum")

    if isinstance(value, list):
        if "minItems" in rule and len(value) < rule["minItems"]:
            raise ReceiptError(f"{path} has too few items")
        item_rule = rule.get("items")
        if item_rule is not None:
            for index, item in enumerate(value):
                _validate_schema_value(item, item_rule, schema, f"{path}[{index}]")

    if isinstance(value, dict):
        required = rule.get("required", ())
        for name in required:
            if name not in value:
                raise ReceiptError(f"{path} is missing required field {name!r}")
        properties = rule.get("properties", {})
        if rule.get("additionalProperties") is False:
            unknown = sorted(set(value) - set(properties))
            if unknown:
                raise ReceiptError(f"{path} has unknown fields {unknown!r}")
        for name, property_rule in properties.items():
            if name in value:
                _validate_schema_value(
                    value[name], property_rule, schema, f"{path}.{name}"
                )


def _load_and_validate_shape(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ReceiptError(f"receipt does not exist: {path}")
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReceiptError(f"could not read JSON receipt {path}: {exc}") from exc
    try:
        schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReceiptError(
            f"could not read receipt schema {_SCHEMA_PATH}: {exc}"
        ) from exc
    _validate_schema_value(receipt, schema, schema, "$")
    return receipt


def _rows_by_label(receipt: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = receipt["runs"]
    if len(rows) != 6:
        raise ReceiptError(f"runs must contain exactly six rows, got {len(rows)}")
    labels = [row["label"] for row in rows]
    if len(set(labels)) != len(labels):
        raise ReceiptError("runs labels must be unique")
    expected = {
        "solver_python",
        "solver_cython",
        "baseline",
        "candidate",
        "auto",
        "winner",
    }
    if set(labels) != expected:
        raise ReceiptError(f"runs must contain labels {sorted(expected)!r}")
    by_label = {row["label"]: row for row in rows}
    if {by_label[label]["kind"] for label in ("solver_python", "solver_cython")} != {
        "solver_replay"
    }:
        raise ReceiptError("solver rows must be solver_replay rows")
    if any(
        by_label[label]["kind"] != "full_decomp"
        for label in ("baseline", "candidate", "auto", "winner")
    ):
        raise ReceiptError("semantic rows must be full_decomp rows")
    return by_label


def _validate_common_row_fields(row: dict[str, Any], *, label: str) -> None:
    missing = sorted(_REQUIRED_RUN_FIELDS - set(row))
    if missing:
        raise ReceiptError(f"{label} is missing required run fields {missing!r}")
    if row["status"] != "converged":
        raise ReceiptError(f"{label} abstained with status={row['status']!r}")
    if row["backend"] == "python-fallback":
        raise ReceiptError(f"{label} used a Python fallback backend")
    if row["wall_seconds"] <= 0:
        raise ReceiptError(f"{label} must have one positive wall_seconds measurement")
    if row["real_api_calls"] <= 0:
        raise ReceiptError(f"{label} must retain real cache API calls")
    for field in ("pseudocode_sha256", "cfg_sha256", "program_fingerprint"):
        if not row[field]:
            raise ReceiptError(f"{label} must retain {field}")


def _parity_without_backend(row: dict[str, Any]) -> dict[str, Any]:
    projection = row["parity_projection"]
    return {
        key: projection[key]
        for key in (
            "status",
            "constants",
            "executable_edges",
            "reachable_blocks",
            "program_fingerprint",
            "cfg_events",
            "value_events",
            "peak_cfg_queue",
            "peak_value_queue",
        )
    }


def _cache_evictions(row: dict[str, Any]) -> int:
    return int(row["cache_stats"]["total_evictions"])


def _cache_memory_delta(row: dict[str, Any]) -> int:
    return int(row["cache_stats"]["memory_delta_bytes"])


def _verify_receipt(receipt: dict[str, Any]) -> None:
    rows = _rows_by_label(receipt)
    metadata = receipt["metadata"]
    function_ea = metadata["function_ea"]
    for label, row in rows.items():
        _validate_common_row_fields(row, label=label)
        if row["function_ea"] != function_ea:
            raise ReceiptError(f"{label} function_ea differs from metadata")

    for label in ("solver_python", "solver_cython"):
        row = rows[label]
        if row.get("warmup") != 3 or row.get("iterations") != 10:
            raise ReceiptError(
                f"{label} must record exactly warmup=3 and iterations=10"
            )
        if "median_seconds" not in row or "p95_seconds" not in row:
            raise ReceiptError(f"{label} must record median_seconds and p95_seconds")
        if row["median_seconds"] <= 0 or row["p95_seconds"] <= 0:
            raise ReceiptError(f"{label} timing samples must be positive")
    for label in ("baseline", "candidate", "auto", "winner"):
        row = rows[label]
        if "median_seconds" in row or "p95_seconds" in row:
            raise ReceiptError(f"{label} must not repeat solver measurements")

    if rows["solver_python"]["backend"] != "python":
        raise ReceiptError("solver_python must use the Python solver")
    if rows["solver_cython"]["backend"] != "cython":
        raise ReceiptError("solver_cython must use the compiled Cython solver")
    if _parity_without_backend(rows["solver_python"]) != _parity_without_backend(
        rows["solver_cython"]
    ):
        raise ReceiptError("Python and Cython solver parity projections differ")
    python_median = rows["solver_python"]["median_seconds"]
    cython_median = rows["solver_cython"]["median_seconds"]
    python_p95 = rows["solver_python"]["p95_seconds"]
    cython_p95 = rows["solver_cython"]["p95_seconds"]
    if python_median / cython_median < 2.0:
        raise ReceiptError(
            f"Cython solver median speedup is below 2x: {python_median / cython_median:.3f}x"
        )
    if python_p95 / cython_p95 < 2.0:
        raise ReceiptError(
            f"Cython solver p95 speedup is below 2x: {python_p95 / cython_p95:.3f}x"
        )

    hashes = {(row["pseudocode_sha256"], row["cfg_sha256"]) for row in rows.values()}
    cache_rows = receipt["cache_matrix"]
    if len(cache_rows) != 9:
        raise ReceiptError(
            f"cache_matrix must contain exactly nine rows, got {len(cache_rows)}"
        )
    capacities = {(row["constant_capacity"], row["ast_capacity"]) for row in cache_rows}
    if capacities != _EXPECTED_CAPACITIES:
        raise ReceiptError(
            "cache_matrix must contain each of the nine required capacity pairs exactly once"
        )
    for index, row in enumerate(cache_rows):
        _validate_common_row_fields(row, label=f"cache_matrix[{index}]")
        if row["function_ea"] != function_ea:
            raise ReceiptError(
                f"cache_matrix[{index}] function_ea differs from metadata"
            )
        if (
            row["kind"] != "cache_replay"
            or row["overlay"] != "replay"
            or row["backend"] != "cython"
        ):
            raise ReceiptError("cache_matrix rows must be replay rows")
        if row["real_api_calls"] != row["cache_stats"]["real_api_calls"]:
            raise ReceiptError("cache replay real API count must match cache stats")
        if row["real_api_calls"] <= 0 or row["workload_operations"] <= 0:
            raise ReceiptError("cache replay must exercise a non-empty real workload")
        for cache_name in ("MOP_CONSTANT_CACHE", "MOP_TO_AST_CACHE"):
            cache = row["cache_stats"][cache_name]
            if cache["real_api_calls"] <= 0 or cache["lookups"] <= 0:
                raise ReceiptError(
                    f"cache replay did not exercise {cache_name} lookups"
                )
        if (
            row["cache_stats"]["MOP_CONSTANT_CACHE"]["configured_max_size"]
            != row["constant_capacity"]
        ):
            raise ReceiptError("constant cache telemetry retained the wrong capacity")
        if (
            row["cache_stats"]["MOP_TO_AST_CACHE"]["configured_max_size"]
            != row["ast_capacity"]
        ):
            raise ReceiptError("MOP-to-AST cache telemetry retained the wrong capacity")
        hashes.add((row["pseudocode_sha256"], row["cfg_sha256"]))
    if len(hashes) != 1:
        raise ReceiptError(
            "pseudocode and live CFG hashes are not equal across captures"
        )

    summary = receipt["sccp_summary"]
    for field in _SCCP_COUNTERS:
        if field not in summary:
            raise ReceiptError(f"sccp_summary is missing {field}")
    if summary["work_limit"] or summary["block_limit"] or summary["errors"]:
        raise ReceiptError("SCCP summary contains abstained or error proof consumers")
    if summary["fallbacks"]:
        raise ReceiptError("SCCP summary contains fallback executions")
    if summary["python_runs"] <= 0 or summary["cython_runs"] <= 0:
        raise ReceiptError("SCCP summary must include Python and Cython runs")

    baseline = rows["baseline"]
    candidate = rows["candidate"]
    if candidate["backend"] != "cython" or candidate["overlay"] != "on":
        raise ReceiptError("candidate must be the Cython/on semantic run")
    if baseline["backend"] != "python" or baseline["overlay"] != "off":
        raise ReceiptError("baseline must be the Python/off semantic run")
    for label in ("auto", "winner"):
        if rows[label]["backend"] != "cython" or rows[label]["overlay"] != "auto":
            raise ReceiptError(f"{label} must be the Cython/auto semantic run")
    candidate_ratio = candidate["wall_seconds"] / baseline["wall_seconds"]
    if candidate_ratio > 1.10:
        raise ReceiptError(
            f"candidate is more than 10% slower than baseline: {candidate_ratio:.3f}x"
        )
    if candidate["wall_seconds"] > baseline["wall_seconds"]:
        raise ReceiptError(
            f"candidate full decomp is slower than baseline: {candidate_ratio:.3f}x"
        )
    for label in ("auto", "winner"):
        ratio = rows[label]["wall_seconds"] / baseline["wall_seconds"]
        if ratio > 1.10:
            raise ReceiptError(
                f"{label} paired decomp is more than 10% slower than baseline: {ratio:.3f}x"
            )

    if _cache_evictions(candidate) >= _cache_evictions(baseline):
        raise ReceiptError(
            "candidate cache evictions are not lower than baseline: "
            f"{_cache_evictions(candidate)} >= {_cache_evictions(baseline)}"
        )
    if _cache_memory_delta(candidate) >= _cache_memory_delta(baseline):
        raise ReceiptError(
            "candidate cache memory delta is not lower than baseline: "
            f"{_cache_memory_delta(candidate)} >= {_cache_memory_delta(baseline)}"
        )
    winner_pairs = [
        (row["constant_capacity"], row["ast_capacity"])
        for row in cache_rows
        if row["wall_seconds"] == min(item["wall_seconds"] for item in cache_rows)
    ]
    winner = rows["winner"]
    if (
        winner.get("constant_capacity"),
        winner.get("ast_capacity"),
    ) not in winner_pairs:
        raise ReceiptError("winner row does not use the measured fastest cache pair")
    if winner["constant_capacity"] == winner["ast_capacity"]:
        raise ReceiptError("winner row must retain both measured cache capacities")


def verify(path: Path) -> None:
    """Validate *path* and raise ``ValueError`` on any failed gate."""

    try:
        receipt = _load_and_validate_shape(Path(path))
        _verify_receipt(receipt)
    except ReceiptError:
        raise
    except (KeyError, TypeError, ZeroDivisionError) as exc:
        raise ReceiptError(f"receipt validation failed: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", type=Path)
    args = parser.parse_args(argv)
    try:
        verify(args.receipt)
    except ValueError as exc:
        print(f"SCCP performance gate FAILED: {exc}", file=sys.stderr)
        return 1
    print(f"SCCP performance gate PASSED: {args.receipt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

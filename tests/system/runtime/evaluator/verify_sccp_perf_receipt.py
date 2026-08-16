#!/usr/bin/env python3
"""Assemble and verify the isolated SCCP/cache performance receipt.

The performance gate is intentionally strict.  A receipt is assembled from
one JSON fragment per fresh IDA process and phase; it is never inferred from a
single long-lived pytest process.  This module has no IDA dependency so the
shape, provenance, merge, and adversarial tests can run on a developer host.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import statistics
import sys
import tempfile
from d810.core.typing import Any


_HERE = Path(__file__).resolve().parent
_SCHEMA_PATH = _HERE / "sccp_perf_receipt.schema.json"
PHASE_ORDER = (
    "capture",
    "solver_python",
    "solver_cython",
    "baseline",
    "candidate",
    "auto",
    "cache",
    "winner",
)
PHASE_INDEX = {phase: index for index, phase in enumerate(PHASE_ORDER)}
EXPECTED_RUN_LABELS = (
    "solver_python",
    "solver_cython",
    "baseline",
    "candidate",
    "auto",
    "winner",
)
EXPECTED_CAPACITIES = frozenset(
    (constant, ast) for constant in (1000, 4096, 8192) for ast in (20480, 40960, 81920)
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
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
_FULL_ONLY_FIELDS = frozenset(
    {
        "pseudocode_sha256",
        "live_pseudocode_sha256",
        "cfg_sha256",
        "live_cfg_sha256",
        "fcp_patches",
        "abstentions",
        "cache_stats",
        "rss_before_bytes",
        "rss_after_bytes",
        "rss_peak_bytes",
        "capacity",
        "constant_capacity",
        "ast_capacity",
    }
)
_SOLVER_FORBIDDEN_FIELDS = _FULL_ONLY_FIELDS | {
    "real_api_calls",
    "rebuilds",
    "evictions",
    "peak_weight",
    "memory_delta_bytes",
}


class ReceiptError(ValueError):
    """Raised when a receipt is malformed or fails a performance gate."""


class FixtureAttestationError(ReceiptError):
    """Raised when a fixture source changes while it is being copied."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_sha(value: object, field: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ReceiptError(f"{field} must be a lowercase SHA256")
    return value


def _require_nonempty(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReceiptError(f"{field} must be a non-empty string")
    return value


def _require_finite_number(
    value: object, field: str, *, positive: bool = False
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ReceiptError(f"{field} must be a finite number")
    result = float(value)
    if not math.isfinite(result) or (positive and result <= 0):
        requirement = "positive and finite" if positive else "finite"
        raise ReceiptError(f"{field} must be {requirement}")
    return result


def _require_nonnegative_integer(
    value: object, field: str, *, positive: bool = False
) -> int:
    if type(value) is not int or value < 0 or (positive and value <= 0):
        requirement = "positive" if positive else "non-negative"
        raise ReceiptError(f"{field} must be a {requirement} integer")
    return value


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def phase_fragment_path(receipt_dir: Path, run_id: str, phase: str) -> Path:
    """Return the only valid path for one ordered phase fragment."""

    if not isinstance(run_id, str) or RUN_ID_RE.fullmatch(run_id) is None:
        raise ValueError("run_id must contain only letters, digits, '.', '_' or '-'")
    if phase not in PHASE_INDEX:
        raise ValueError(f"unknown performance phase {phase!r}")
    return Path(receipt_dir) / f"{run_id}.{PHASE_INDEX[phase]:02d}.{phase}.json"


def write_phase_fragment(
    receipt_dir: Path,
    run_id: str,
    phase: str,
    payload: dict[str, Any],
    *,
    process_id: str | None = None,
    database_marker: str | None = None,
) -> Path:
    """Atomically write one fresh-process phase fragment.

    A second write for the same phase is rejected rather than silently
    replacing evidence from a previous process.
    """

    path = phase_fragment_path(receipt_dir, run_id, phase)
    if path.exists():
        raise ReceiptError(f"duplicate phase fragment already exists: {path.name}")
    if not isinstance(payload, dict):
        raise TypeError("phase fragment payload must be an object")
    envelope = {
        "run_id": run_id,
        "phase": phase,
        "phase_index": PHASE_INDEX[phase],
        "process_id": _require_nonempty(process_id or str(os.getpid()), "process_id"),
        "database_marker": _require_nonempty(
            database_marker or "unknown-database", "database_marker"
        ),
        "fresh_process": True,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "payload_sha256": _sha256_bytes(_canonical_json(payload)),
        "payload": payload,
    }
    _atomic_write_json(path, envelope)
    return path


def copy_fixture_with_attestation(
    source: Path,
    destination: Path,
    *,
    mutate_source: bool = False,
) -> dict[str, Any]:
    """Copy an IDB and attest that its source did not drift during the copy.

    ``mutate_source`` exists only for the local adversarial test; production
    callers leave it false.  The destination is written through a sibling
    temporary file and is never refreshed by later verification.
    """

    source = Path(source)
    destination = Path(destination)
    if not source.is_file():
        raise FixtureAttestationError(f"fixture source does not exist: {source}")
    source_sha_before = _sha256_file(source)
    source_size = source.stat().st_size
    copied_at = datetime.now(timezone.utc).isoformat()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.copying")
    temporary.unlink(missing_ok=True)
    try:
        shutil.copyfile(source, temporary)
        if mutate_source:
            source.write_bytes(source.read_bytes() + b"source-drift")
        source_sha_after = _sha256_file(source)
        if source_sha_after != source_sha_before:
            raise FixtureAttestationError(
                "source SHA256 changed during fixture copy: "
                f"{source_sha_before} -> {source_sha_after}"
            )
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    fixture_sha = _sha256_file(destination)
    if fixture_sha != source_sha_before:
        raise FixtureAttestationError(
            f"copied fixture SHA256 mismatch: {fixture_sha} != {source_sha_before}"
        )
    return {
        "source_path": str(source),
        "source_sha256_at_copy": source_sha_before,
        "fixture_path": str(destination),
        "fixture_sha256": fixture_sha,
        "fixture_size_bytes": int(destination.stat().st_size),
        "source_size_bytes": int(source_size),
        "fixture_copied_at_utc": copied_at,
    }


def _resolve_ref(schema: dict[str, Any], ref: str) -> dict[str, Any]:
    prefix = "#/$defs/"
    if not ref.startswith(prefix):
        raise ReceiptError(f"unsupported schema reference {ref!r}")
    try:
        return schema["$defs"][ref[len(prefix) :]]
    except KeyError as exc:
        raise ReceiptError(f"unknown schema reference {ref!r}") from exc


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
        return type(value) in (int, float)
    if expected == "boolean":
        return type(value) is bool
    if expected == "null":
        return value is None
    raise ReceiptError(f"unsupported schema type {expected!r}")


def _validate_schema_value(
    value: object, rule: dict[str, Any], schema: dict[str, Any], path: str
) -> None:
    if "$ref" in rule:
        _validate_schema_value(value, _resolve_ref(schema, rule["$ref"]), schema, path)
        return
    if "allOf" in rule:
        for candidate in rule["allOf"]:
            _validate_schema_value(value, candidate, schema, path)
        return
    if "oneOf" in rule:
        errors: list[str] = []
        matches = 0
        for candidate in rule["oneOf"]:
            try:
                _validate_schema_value(value, candidate, schema, path)
            except ReceiptError as exc:
                errors.append(str(exc))
            else:
                matches += 1
        if matches != 1:
            detail = "; ".join(errors) if errors else "multiple schema branches matched"
            raise ReceiptError(f"{path} failed oneOf: {detail}")
        return
    if "anyOf" in rule:
        for candidate in rule["anyOf"]:
            try:
                _validate_schema_value(value, candidate, schema, path)
            except ReceiptError:
                continue
            return
        raise ReceiptError(f"{path} failed anyOf")
    if "const" in rule and value != rule["const"]:
        raise ReceiptError(f"{path} must equal {rule['const']!r}")
    if "enum" in rule and value not in rule["enum"]:
        raise ReceiptError(f"{path} must be one of {rule['enum']!r}")
    expected = rule.get("type")
    if expected is not None:
        expected_types = expected if isinstance(expected, list) else [expected]
        if not any(_schema_type(value, candidate) for candidate in expected_types):
            raise ReceiptError(f"{path} has invalid type")
    if isinstance(value, str):
        if len(value) < rule.get("minLength", 0):
            raise ReceiptError(f"{path} must not be empty")
        pattern = rule.get("pattern")
        if pattern and re.fullmatch(pattern, value) is None:
            raise ReceiptError(f"{path} does not match the required pattern")
    if type(value) in (int, float):
        if not math.isfinite(float(value)):
            raise ReceiptError(f"{path} must be finite")
        if "minimum" in rule and value < rule["minimum"]:
            raise ReceiptError(f"{path} is below its minimum")
    if isinstance(value, list):
        if len(value) < rule.get("minItems", 0):
            raise ReceiptError(f"{path} has too few items")
        if "maxItems" in rule and len(value) > rule["maxItems"]:
            raise ReceiptError(f"{path} has too many items")
        if "items" in rule:
            for index, item in enumerate(value):
                _validate_schema_value(item, rule["items"], schema, f"{path}[{index}]")
    if isinstance(value, dict):
        for name in rule.get("required", ()):
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
        schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReceiptError(f"could not read receipt or schema: {exc}") from exc
    _validate_schema_value(receipt, schema, schema, "$")
    return receipt


def _load_fragment(path: Path, run_id: str, phase: str) -> dict[str, Any]:
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReceiptError(f"could not read phase fragment {path}: {exc}") from exc
    if not isinstance(envelope, dict):
        raise ReceiptError(f"phase fragment {path.name} is not an object")
    if envelope.get("run_id") != run_id or envelope.get("phase") != phase:
        raise ReceiptError(f"phase fragment {path.name} has mismatched run identity")
    if envelope.get("phase_index") != PHASE_INDEX[phase]:
        raise ReceiptError(f"phase fragment {path.name} is out-of-order")
    if envelope.get("fresh_process") is not True:
        raise ReceiptError(f"phase fragment {path.name} is not fresh-process evidence")
    _require_nonempty(envelope.get("process_id"), f"{path.name}.process_id")
    _require_nonempty(envelope.get("database_marker"), f"{path.name}.database_marker")
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise ReceiptError(f"phase fragment {path.name} is missing payload")
    expected = _require_sha(
        envelope.get("payload_sha256"), f"{path.name}.payload_sha256"
    )
    actual = _sha256_bytes(_canonical_json(payload))
    if expected != actual:
        raise ReceiptError(f"phase fragment {path.name} payload hash mismatch")
    return envelope


def merge_phase_fragments(
    receipt_dir: Path,
    run_id: str,
    output: Path | None = None,
) -> dict[str, Any]:
    """Assemble exactly one ordered fragment for every fresh-process phase."""

    receipt_dir = Path(receipt_dir)
    if not receipt_dir.is_dir():
        raise ReceiptError(f"phase receipt directory does not exist: {receipt_dir}")
    expected_paths = [
        phase_fragment_path(receipt_dir, run_id, phase) for phase in PHASE_ORDER
    ]
    expected_names = {path.name for path in expected_paths}
    json_files = sorted(receipt_dir.glob("*.json"), key=lambda path: path.name)
    unexpected = [path.name for path in json_files if path.name not in expected_names]
    if unexpected:
        raise ReceiptError(f"duplicate or out-of-order phase fragments: {unexpected!r}")
    missing = [path.name for path in expected_paths if not path.is_file()]
    if missing:
        raise ReceiptError(f"missing phase fragments: {missing!r}")
    envelopes = [
        _load_fragment(path, run_id, phase)
        for path, phase in zip(expected_paths, PHASE_ORDER, strict=True)
    ]
    process_ids = [envelope["process_id"] for envelope in envelopes]
    if len(set(process_ids)) != len(process_ids):
        raise ReceiptError("phase fragments reused a process identity")
    database_markers = [envelope["database_marker"] for envelope in envelopes]
    if len(set(database_markers)) != len(database_markers):
        raise ReceiptError("phase fragments reused a database identity")

    capture_payload = envelopes[0]["payload"]
    metadata = capture_payload.get("metadata")
    if not isinstance(metadata, dict):
        raise ReceiptError("capture phase is missing metadata")
    rows: list[dict[str, Any]] = []
    for envelope in envelopes[1:6]:
        row = envelope["payload"].get("row")
        if not isinstance(row, dict):
            raise ReceiptError(f"{envelope['phase']} phase is missing its row")
        rows.append(row)
    cache_payload = envelopes[6]["payload"]
    cache_matrix = cache_payload.get("cache_matrix")
    if not isinstance(cache_matrix, list):
        raise ReceiptError("cache phase is missing cache_matrix")
    winner_row = envelopes[7]["payload"].get("row")
    if not isinstance(winner_row, dict):
        raise ReceiptError("winner phase is missing its row")
    rows.append(winner_row)
    summary: dict[str, int | float] = {field: 0 for field in _SCCP_COUNTERS}
    for row in rows:
        row_summary = row.get("sccp_summary")
        if not isinstance(row_summary, dict):
            raise ReceiptError(
                f"{row.get('label', '<unknown>')} is missing sccp_summary"
            )
        for field in _SCCP_COUNTERS:
            value = row_summary.get(field)
            if type(value) not in (int, float) or not math.isfinite(float(value)):
                raise ReceiptError(
                    f"{row.get('label', '<unknown>')}.{field} is invalid"
                )
            summary[field] += value
    phase_fragments = [
        {
            "phase": envelope["phase"],
            "phase_index": envelope["phase_index"],
            "run_id": envelope["run_id"],
            "process_id": envelope["process_id"],
            "database_marker": envelope["database_marker"],
            "payload_sha256": envelope["payload_sha256"],
        }
        for envelope in envelopes
    ]
    receipt = {
        "schema_version": 2,
        "metadata": {**metadata, "run_id": run_id},
        "phase_order": list(PHASE_ORDER),
        "phase_fragments": phase_fragments,
        "runs": rows,
        "cache_matrix": cache_matrix,
        "sccp_summary": summary,
    }
    if output is not None:
        _atomic_write_json(Path(output), receipt)
    return receipt


def _validate_metadata(receipt: dict[str, Any]) -> dict[str, Any]:
    metadata = receipt["metadata"]
    source = _require_nonempty(metadata.get("source_path"), "metadata.source_path")
    fixture = _require_nonempty(metadata.get("fixture_path"), "metadata.fixture_path")
    if not Path(source).is_absolute() or not Path(fixture).is_absolute():
        raise ReceiptError(
            "metadata source_path and fixture_path must be exact absolute paths"
        )
    source_sha = _require_sha(
        metadata.get("source_sha256_at_copy"), "metadata.source_sha256_at_copy"
    )
    fixture_sha = _require_sha(
        metadata.get("fixture_sha256"), "metadata.fixture_sha256"
    )
    if source_sha != fixture_sha:
        raise ReceiptError("source-at-copy SHA256 does not match fixture SHA256")
    if metadata.get("binary_sha256") != fixture_sha:
        raise ReceiptError("binary_sha256 does not match attested fixture SHA256")
    size = _require_nonnegative_integer(
        metadata.get("fixture_size_bytes"), "metadata.fixture_size_bytes", positive=True
    )
    _require_nonempty(
        metadata.get("fixture_copied_at_utc"), "metadata.fixture_copied_at_utc"
    )
    try:
        datetime.fromisoformat(str(metadata["fixture_copied_at_utc"]))
    except ValueError as exc:
        raise ReceiptError(
            "metadata.fixture_copied_at_utc is not an ISO timestamp"
        ) from exc
    mode = metadata.get("gate_mode")
    if mode not in {"exact", "smoke", "unit"}:
        raise ReceiptError("metadata.gate_mode must be exact, smoke, or unit")
    if mode != "unit":
        path = Path(fixture)
        if not path.is_file():
            raise ReceiptError(f"attested fixture is not mounted: {fixture}")
        if path.stat().st_size != size or _sha256_file(path) != fixture_sha:
            raise ReceiptError("mounted fixture no longer matches the attested copy")
        expected = os.environ.get("D810_EXPECTED_FIXTURE_SHA256")
        if not expected:
            raise ReceiptError("D810_EXPECTED_FIXTURE_SHA256 is required")
        if expected != fixture_sha:
            raise ReceiptError("D810_EXPECTED_FIXTURE_SHA256 does not match fixture")
    if mode == "exact" and metadata.get("fixture_source") != source:
        raise ReceiptError("metadata fixture_source is not the exact source path")
    if metadata.get("capture_hooks_stopped") is not True:
        raise ReceiptError("capture was not recorded with D810 hooks stopped")
    for field in ("capture_lifecycle_events", "capture_optimizer_attempts"):
        if _require_nonnegative_integer(metadata.get(field), f"metadata.{field}") != 0:
            raise ReceiptError(f"capture emitted {field}")
    _require_nonnegative_integer(
        metadata.get("workload_operations"),
        "metadata.workload_operations",
        positive=True,
    )
    _require_sha(metadata.get("workload_fingerprint"), "metadata.workload_fingerprint")
    _require_sha(metadata.get("workload_hash"), "metadata.workload_hash")
    _require_sha(metadata.get("snapshot_fingerprint"), "metadata.snapshot_fingerprint")
    _require_sha(metadata.get("build_source_sha256"), "metadata.build_source_sha256")
    return metadata


def _validate_fragment_headers(
    receipt: dict[str, Any], metadata: dict[str, Any]
) -> None:
    if receipt["phase_order"] != list(PHASE_ORDER):
        raise ReceiptError("phase_order is missing, duplicated, or out-of-order")
    fragments = receipt["phase_fragments"]
    if len(fragments) != len(PHASE_ORDER):
        raise ReceiptError("phase_fragments must contain exactly one entry per phase")
    run_id = metadata["run_id"]
    process_ids: set[str] = set()
    db_markers: set[str] = set()
    for index, (fragment, phase) in enumerate(zip(fragments, PHASE_ORDER, strict=True)):
        if fragment["run_id"] != run_id or fragment["phase"] != phase:
            raise ReceiptError("phase fragment run identity or label mismatch")
        if fragment["phase_index"] != index:
            raise ReceiptError("phase fragment order mismatch")
        process_ids.add(fragment["process_id"])
        db_markers.add(fragment["database_marker"])
        _require_sha(
            fragment["payload_sha256"], f"phase_fragments[{index}].payload_sha256"
        )
    if len(process_ids) != len(PHASE_ORDER) or len(db_markers) != len(PHASE_ORDER):
        raise ReceiptError(
            "phase fragments are not independent fresh process/database evidence"
        )


def _validate_sccp_summary(summary: dict[str, Any], *, field_prefix: str) -> None:
    for field in _SCCP_COUNTERS:
        value = summary.get(field)
        if (
            type(value) not in (int, float)
            or not math.isfinite(float(value))
            or value < 0
        ):
            raise ReceiptError(
                f"{field_prefix}.{field} must be finite and non-negative"
            )


def _validate_parity(row: dict[str, Any], field_prefix: str) -> None:
    projection = row.get("parity_projection")
    if not isinstance(projection, dict):
        raise ReceiptError(f"{field_prefix} is missing parity_projection")
    parity_sha = _require_sha(row.get("parity_sha256"), f"{field_prefix}.parity_sha256")
    if parity_sha != _sha256_bytes(_canonical_json(projection)):
        raise ReceiptError(f"{field_prefix} parity hash is not bound to projection")
    for field in (
        "status",
        "constants",
        "executable_edges",
        "reachable_blocks",
        "program_fingerprint",
    ):
        if field not in projection:
            raise ReceiptError(f"{field_prefix}.parity_projection is missing {field}")


def _validate_solver_rows(
    rows: dict[str, dict[str, Any]], metadata: dict[str, Any]
) -> None:
    python = rows["solver_python"]
    cython = rows["solver_cython"]
    for label, row in (("solver_python", python), ("solver_cython", cython)):
        if (
            row["phase"] != label
            or row["label"] != label
            or row["kind"] != "solver_replay"
        ):
            raise ReceiptError(f"{label} phase/kind/label mismatch")
        if row["run_id"] != metadata["run_id"] or row["fresh_process"] is not True:
            raise ReceiptError(f"{label} does not identify its fresh run")
        if row["function_ea"] != metadata["function_ea"]:
            raise ReceiptError(f"{label} function_ea differs from metadata")
        if row["status"] != "converged":
            raise ReceiptError(f"{label} abstained with status={row['status']!r}")
        if row["backend"] not in {"python", "cython"}:
            raise ReceiptError(f"{label} has an invalid backend")
        if row["backend"] != ("python" if label.endswith("python") else "cython"):
            raise ReceiptError(f"{label} selected the wrong solver backend")
        forbidden = sorted(_SOLVER_FORBIDDEN_FIELDS.intersection(row))
        if forbidden:
            raise ReceiptError(
                f"{label} contains full-decomp/cache telemetry {forbidden!r}"
            )
        if (
            row["warmup"] != 3
            or row["iterations"] != 10
            or len(row["samples_seconds"]) != 10
        ):
            raise ReceiptError(
                f"{label} must record exactly 3 warmups and 10 measured samples"
            )
        samples = [
            _require_finite_number(value, f"{label}.samples_seconds")
            for value in row["samples_seconds"]
        ]
        if any(value <= 0 for value in samples):
            raise ReceiptError(f"{label} samples must be positive")
        median = _require_finite_number(
            row["median_seconds"], f"{label}.median_seconds", positive=True
        )
        p95 = _require_finite_number(
            row["p95_seconds"], f"{label}.p95_seconds", positive=True
        )
        expected_p95 = statistics.quantiles(samples, n=20, method="inclusive")[18]
        if not math.isclose(
            median, statistics.median(samples), rel_tol=1e-9, abs_tol=1e-12
        ):
            raise ReceiptError(f"{label}.median_seconds is not bound to samples")
        if not math.isclose(p95, expected_p95, rel_tol=1e-9, abs_tol=1e-12):
            raise ReceiptError(f"{label}.p95_seconds is not bound to samples")
        _require_finite_number(
            row["wall_seconds"], f"{label}.wall_seconds", positive=True
        )
        for field in (
            "program_fingerprint",
            "snapshot_fingerprint",
            "workload_fingerprint",
        ):
            _require_sha(row[field], f"{label}.{field}")
        _validate_parity(row, label)
        _validate_sccp_summary(
            row["sccp_summary"], field_prefix=f"{label}.sccp_summary"
        )
    parity_fields = (
        "status",
        "constants",
        "executable_edges",
        "reachable_blocks",
        "program_fingerprint",
    )
    for field in parity_fields:
        if python["parity_projection"][field] != cython["parity_projection"][field]:
            raise ReceiptError("Python and Cython solver parity projections differ")
    for field in (
        "program_fingerprint",
        "snapshot_fingerprint",
        "workload_fingerprint",
    ):
        if python[field] != cython[field]:
            raise ReceiptError(f"solver {field} differs across fresh phases")
    if python["median_seconds"] / cython["median_seconds"] < 2.0:
        raise ReceiptError("Cython solver median speedup is below 2x")
    if python["p95_seconds"] / cython["p95_seconds"] < 2.0:
        raise ReceiptError("Cython solver p95 speedup is below 2x")


def _validate_build_provenance(metadata: dict[str, Any], row: dict[str, Any]) -> None:
    provenance = row.get("compiled_provenance") or metadata.get("build_provenance")
    if not isinstance(provenance, dict):
        raise ReceiptError(f"{row['label']} is missing compiled build provenance")
    for name in ("c_sccp", "_fast_dataflow"):
        item = provenance.get(name)
        if not isinstance(item, dict):
            raise ReceiptError(f"{row['label']} is missing {name} build provenance")
        _require_nonempty(item.get("module_file"), f"{row['label']}.{name}.module_file")
        _require_sha(item.get("module_sha256"), f"{row['label']}.{name}.module_sha256")
        _require_nonempty(item.get("build_abi"), f"{row['label']}.{name}.build_abi")
        _require_nonempty(item.get("source_hash"), f"{row['label']}.{name}.source_hash")
        _require_nonnegative_integer(
            item.get("module_mtime_ns"),
            f"{row['label']}.{name}.module_mtime_ns",
            positive=True,
        )
        if item.get("callable") is not True:
            raise ReceiptError(f"{row['label']} {name} is not callable")
    if provenance.get("source_tree_sha256") != metadata["build_source_sha256"]:
        raise ReceiptError(
            f"{row['label']} build sources are not bound to the current source tree"
        )


def _cache_stats_memory(row: dict[str, Any]) -> tuple[int, int]:
    stats = row["cache_stats"]
    total_evictions = 0
    for name in ("MOP_CONSTANT_CACHE", "MOP_TO_AST_CACHE"):
        cache = stats[name]
        for field in ("lookups", "insertions", "capacity_evictions", "real_api_calls"):
            _require_nonnegative_integer(cache[field], f"{row['label']}.{name}.{field}")
        total_evictions += cache["capacity_evictions"]
        if cache["real_api_calls"] <= 0 or cache["lookups"] <= 0:
            raise ReceiptError(f"{row['label']} did not exercise {name}")
    if stats["total_evictions"] != total_evictions:
        raise ReceiptError(f"{row['label']} cache eviction total is inconsistent")
    if stats["real_api_calls"] != sum(
        stats[name]["real_api_calls"]
        for name in ("MOP_CONSTANT_CACHE", "MOP_TO_AST_CACHE")
    ):
        raise ReceiptError(f"{row['label']} cache API count is inconsistent")
    memory_delta = stats["memory_delta_bytes"]
    if type(memory_delta) is not int:
        raise ReceiptError(f"{row['label']} cache memory delta is not an integer")
    return total_evictions, memory_delta


def _validate_full_rows(
    rows: dict[str, dict[str, Any]], metadata: dict[str, Any]
) -> None:
    expected_modes = {
        "baseline": ("python", "off"),
        "candidate": ("cython", "on"),
        "auto": ("cython", "auto"),
        "winner": ("cython", "auto"),
    }
    hashes: set[tuple[str, str]] = set()
    for label, (backend, overlay) in expected_modes.items():
        row = rows[label]
        if (
            row["phase"] != label
            or row["kind"] != "full_decomp"
            or row["label"] != label
        ):
            raise ReceiptError(f"{label} phase/kind/label mismatch")
        if row["run_id"] != metadata["run_id"] or row["fresh_process"] is not True:
            raise ReceiptError(f"{label} does not identify its fresh process")
        if row["backend"] != backend or row["overlay"] != overlay:
            raise ReceiptError(f"{label} selected the wrong backend or overlay")
        if row["status"] != "converged" or row["abstentions"]:
            raise ReceiptError(f"{label} contains an abstained proof consumer")
        if row["function_ea"] != metadata["function_ea"]:
            raise ReceiptError(f"{label} function_ea differs from metadata")
        _require_finite_number(
            row["wall_seconds"], f"{label}.wall_seconds", positive=True
        )
        for field in ("adapter_seconds", "solver_seconds"):
            _require_finite_number(row[field], f"{label}.{field}", positive=True)
        summary = row["sccp_summary"]
        _validate_sccp_summary(summary, field_prefix=f"{label}.sccp_summary")
        for field in ("requests", "executions", "converged"):
            _require_nonnegative_integer(
                summary[field], f"{label}.sccp_summary.{field}", positive=True
            )
        if any(
            summary[field]
            for field in ("fallbacks", "work_limit", "block_limit", "errors")
        ):
            raise ReceiptError(
                f"{label} SCCP summary contains fallback/error/abstention"
            )
        _require_nonnegative_integer(row["fcp_patches"], f"{label}.fcp_patches")
        for field in ("rss_before_bytes", "rss_after_bytes", "rss_peak_bytes"):
            _require_nonnegative_integer(row[field], f"{label}.{field}")
        if row["rss_peak_bytes"] < max(row["rss_before_bytes"], row["rss_after_bytes"]):
            raise ReceiptError(f"{label} RSS peak is below before/after RSS")
        expected_delta = row["rss_after_bytes"] - row["rss_before_bytes"]
        if row["memory_delta_bytes"] != expected_delta:
            raise ReceiptError(f"{label} memory delta is inconsistent with RSS")
        for field in (
            "program_fingerprint",
            "pseudocode_sha256",
            "live_pseudocode_sha256",
            "cfg_sha256",
            "live_cfg_sha256",
        ):
            _require_sha(row[field], f"{label}.{field}")
        if (
            row["pseudocode_sha256"] != row["live_pseudocode_sha256"]
            or row["cfg_sha256"] != row["live_cfg_sha256"]
        ):
            raise ReceiptError(
                f"{label} copied rather than independently captured live hashes"
            )
        if row.get("evidence_origin") != {
            "pseudocode": "live_cfunc",
            "cfg": "live_flowchart",
            "program": "live_mba",
        }:
            raise ReceiptError(
                f"{label} does not identify independent live evidence origins"
            )
        hashes.add((row["live_pseudocode_sha256"], row["live_cfg_sha256"]))
        _validate_parity(row, label)
        if (
            row["parity_projection"].get("program_fingerprint")
            != row["program_fingerprint"]
        ):
            raise ReceiptError(
                f"{label} parity projection is not bound to its live program"
            )
        _cache_stats_memory(row)
        _validate_build_provenance(metadata, row)
    if len(hashes) != 1:
        raise ReceiptError(
            "pseudocode and live CFG hashes are not equal across full captures"
        )
    baseline = rows["baseline"]
    candidate = rows["candidate"]
    if (
        candidate["wall_seconds"] > baseline["wall_seconds"]
        or candidate["wall_seconds"] / baseline["wall_seconds"] > 1.10
    ):
        raise ReceiptError("candidate full decomp is slower than the baseline gate")
    for label in ("auto", "winner"):
        if rows[label]["wall_seconds"] / baseline["wall_seconds"] > 1.10:
            raise ReceiptError(
                f"{label} paired full decomp is more than 10% slower than baseline"
            )
    candidate_evictions, candidate_memory = _cache_stats_memory(candidate)
    baseline_evictions, baseline_memory = _cache_stats_memory(baseline)
    if candidate_evictions >= baseline_evictions:
        raise ReceiptError("candidate cache evictions are not lower than baseline")
    if candidate_memory >= baseline_memory:
        raise ReceiptError("candidate cache memory delta is not lower than baseline")


def _validate_cache_matrix(
    cache_rows: list[dict[str, Any]], metadata: dict[str, Any]
) -> None:
    if len(cache_rows) != 9:
        raise ReceiptError(
            f"cache_matrix must contain exactly nine rows, got {len(cache_rows)}"
        )
    capacities = {(row["constant_capacity"], row["ast_capacity"]) for row in cache_rows}
    if capacities != EXPECTED_CAPACITIES:
        raise ReceiptError("cache_matrix must contain each capacity pair exactly once")
    workload_hashes: set[str] = set()
    for index, row in enumerate(cache_rows):
        prefix = f"cache_matrix[{index}]"
        if (
            row["phase"] != "cache"
            or row["kind"] != "cache_replay"
            or row["overlay"] != "replay"
        ):
            raise ReceiptError(f"{prefix} is not a cache phase replay")
        if row["run_id"] != metadata["run_id"] or row["fresh_process"] is not True:
            raise ReceiptError(f"{prefix} lacks cache phase identity")
        if row["function_ea"] != metadata["function_ea"]:
            raise ReceiptError(f"{prefix} function_ea differs from metadata")
        if row["status"] != "converged" or row["backend"] not in {
            "python",
            "cython",
            "runtime",
        }:
            raise ReceiptError(f"{prefix} has an invalid backend/status")
        forbidden = {
            "parity_projection",
            "parity_sha256",
            "pseudocode_sha256",
            "cfg_sha256",
            "program_fingerprint",
        }.intersection(row)
        if forbidden:
            raise ReceiptError(
                f"{prefix} copied solver/full semantic evidence {sorted(forbidden)!r}"
            )
        workload = _require_sha(
            row["workload_fingerprint"], f"{prefix}.workload_fingerprint"
        )
        workload_hash = _require_sha(row["workload_hash"], f"{prefix}.workload_hash")
        workload_hashes.add(workload_hash)
        if (
            workload != metadata["workload_fingerprint"]
            or workload_hash != metadata["workload_hash"]
        ):
            raise ReceiptError(f"{prefix} workload fingerprint differs from capture")
        _require_nonnegative_integer(
            row["workload_operations"], f"{prefix}.workload_operations", positive=True
        )
        counts = row["operation_counts"]
        for name in (
            "l",
            "r",
            "d",
            "reconstructed_instruction_mops",
            "p_ast",
            "mop_utils",
        ):
            _require_nonnegative_integer(
                counts.get(name), f"{prefix}.operation_counts.{name}", positive=True
            )
        _require_finite_number(
            row["wall_seconds"], f"{prefix}.wall_seconds", positive=True
        )
        for field in ("rss_before_bytes", "rss_after_bytes", "rss_peak_bytes"):
            _require_nonnegative_integer(row[field], f"{prefix}.{field}")
        if row["rss_peak_bytes"] < max(row["rss_before_bytes"], row["rss_after_bytes"]):
            raise ReceiptError(f"{prefix} RSS peak is inconsistent")
        if (
            row["memory_delta_bytes"]
            != row["rss_after_bytes"] - row["rss_before_bytes"]
        ):
            raise ReceiptError(f"{prefix} memory delta is inconsistent")
        _require_nonnegative_integer(
            row["real_api_calls"], f"{prefix}.real_api_calls", positive=True
        )
        _require_nonnegative_integer(
            row["rebuilds"], f"{prefix}.rebuilds", positive=True
        )
        _require_nonnegative_integer(row["evictions"], f"{prefix}.evictions")
        _require_finite_number(
            row["peak_weight"], f"{prefix}.peak_weight", positive=True
        )
        if row["real_api_calls"] != row["cache_stats"]["real_api_calls"]:
            raise ReceiptError(f"{prefix} real API count is not bound to cache stats")
        _cache_stats_memory(row)
    if workload_hashes != {metadata["workload_hash"]}:
        raise ReceiptError("cache matrix workload hashes are inconsistent")


def _rows_by_label(receipt: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = receipt["runs"]
    if [row.get("label") for row in rows] != list(EXPECTED_RUN_LABELS):
        raise ReceiptError("runs must contain the six labels in phase order")
    if len({row.get("label") for row in rows}) != len(EXPECTED_RUN_LABELS):
        raise ReceiptError("runs labels must be unique")
    return {row["label"]: row for row in rows}


def _verify_receipt(receipt: dict[str, Any]) -> None:
    metadata = _validate_metadata(receipt)
    _validate_fragment_headers(receipt, metadata)
    rows = _rows_by_label(receipt)
    if metadata["run_id"] != receipt["phase_fragments"][0]["run_id"]:
        raise ReceiptError("receipt run_id does not match phase fragments")
    _validate_solver_rows(rows, metadata)
    _validate_full_rows(rows, metadata)
    cache_rows = receipt["cache_matrix"]
    _validate_cache_matrix(cache_rows, metadata)
    summary = receipt["sccp_summary"]
    _validate_sccp_summary(summary, field_prefix="sccp_summary")
    expected_summary: dict[str, int | float] = {field: 0 for field in _SCCP_COUNTERS}
    for row in rows.values():
        for field in _SCCP_COUNTERS:
            expected_summary[field] += row["sccp_summary"][field]
    if summary != expected_summary:
        raise ReceiptError("sccp_summary is not bound to the six row summaries")
    if any(
        summary[field] for field in ("fallbacks", "work_limit", "block_limit", "errors")
    ):
        raise ReceiptError(
            "sccp_summary contains abstained or fallback proof consumers"
        )
    winner = rows["winner"]
    fastest = min(
        cache_rows,
        key=lambda row: (
            row["wall_seconds"],
            row["constant_capacity"],
            row["ast_capacity"],
        ),
    )
    if winner.get("capacity") != {
        "constant": fastest["constant_capacity"],
        "ast": fastest["ast_capacity"],
    }:
        raise ReceiptError("winner row does not use the measured fastest cache pair")


def verify(path: Path) -> None:
    """Validate a merged receipt and raise :class:`ReceiptError` on failure."""

    try:
        receipt = _load_and_validate_shape(Path(path))
        _verify_receipt(receipt)
    except ReceiptError:
        raise
    except (KeyError, TypeError, ZeroDivisionError) as exc:
        raise ReceiptError(f"receipt validation failed: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", nargs="?", type=Path)
    parser.add_argument("--merge", action="store_true")
    parser.add_argument("--receipt-dir", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--prepare-fixture", nargs=2, metavar=("SOURCE", "DESTINATION"))
    args = parser.parse_args(argv)
    try:
        if args.prepare_fixture:
            attestation = copy_fixture_with_attestation(
                Path(args.prepare_fixture[0]), Path(args.prepare_fixture[1])
            )
            print(json.dumps(attestation, sort_keys=True))
            return 0
        if args.merge:
            if args.receipt_dir is None or not args.run_id or args.output is None:
                parser.error("--merge requires --receipt-dir, --run-id, and --output")
            merge_phase_fragments(args.receipt_dir, args.run_id, args.output)
            verify(args.output)
            print(f"SCCP performance gate PASSED: {args.output}")
            return 0
        if args.receipt is None:
            parser.error("a merged receipt path is required")
        verify(args.receipt)
    except (ReceiptError, OSError) as exc:
        print(f"SCCP performance gate FAILED: {exc}", file=sys.stderr)
        return 1
    print(f"SCCP performance gate PASSED: {args.receipt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

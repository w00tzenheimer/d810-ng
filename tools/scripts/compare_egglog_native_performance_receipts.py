#!/usr/bin/env python3
"""Validate and summarize two native Egglog performance receipt streams."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


_EXPECTED_STAGES = frozenset(
    {
        "root_eligibility",
        "ast_construction",
        "native_preflight",
        "egglog_extraction",
        "native_z3",
        "reconstruction",
    }
)


def _load_receipts(path: Path) -> tuple[dict[str, Any], ...]:
    rows = tuple(
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
    )
    if not rows or not all(isinstance(row, dict) for row in rows):
        raise ValueError(f"{path} must contain JSON object receipts")
    return rows


def _positive_int(value: object) -> bool:
    return type(value) is int and value > 0


def _corpus_receipt(rows: tuple[dict[str, Any], ...]) -> dict[str, Any]:
    matches = [row for row in rows if "candidate_count" in row]
    if len(matches) != 1:
        raise ValueError("expected exactly one corpus performance receipt")
    return matches[0]


def _validate_corpus_metadata(receipt: dict[str, Any]) -> None:
    required_strings = ("docker_image", "docker_image_id", "egglog_version")
    for field in required_strings:
        if type(receipt.get(field)) is not str or not receipt[field]:
            raise ValueError(f"corpus receipt must provide non-empty {field}")
    candidate_names = receipt.get("candidate_names")
    if not isinstance(candidate_names, list) or not candidate_names:
        raise ValueError("corpus receipt must provide non-empty candidate_names")
    if not all(type(name) is str and name for name in candidate_names):
        raise ValueError("candidate_names must contain non-empty strings")
    candidate_count = receipt.get("candidate_count")
    if not _positive_int(candidate_count) or candidate_count != len(candidate_names):
        raise ValueError("candidate_count must equal len(candidate_names)")
    timings = receipt.get("stage_timing_ms")
    if not isinstance(timings, dict) or set(timings) != _EXPECTED_STAGES:
        raise ValueError("corpus receipt must provide the expected stage set")
    for stage, timing in timings.items():
        if not isinstance(timing, dict) or not _positive_int(
            timing.get("sample_count")
        ):
            raise ValueError(f"{stage} must provide a positive stage sample count")


def _native_receipts(
    rows: tuple[dict[str, Any], ...],
) -> tuple[dict[str, Any], ...]:
    receipts = tuple(
        row
        for row in rows
        if type(row.get("corpus")) is str
        and isinstance(row.get("stage_sample_counts"), dict)
    )
    if not receipts:
        raise ValueError("receipt streams must provide native stage coverage")
    if len({receipt["corpus"] for receipt in receipts}) != len(receipts):
        raise ValueError("native corpus names must be unique")
    for receipt in receipts:
        execution_count = receipt.get("execution_count")
        if not _positive_int(execution_count):
            raise ValueError("native receipt must provide a positive execution_count")
        stage_counts = receipt["stage_sample_counts"]
        if set(stage_counts) != _EXPECTED_STAGES:
            raise ValueError("native receipt must provide the expected stage set")
        if any(not _positive_int(count) for count in stage_counts.values()):
            raise ValueError(
                "native receipt must provide a positive stage sample count"
            )
        if any(count != execution_count for count in stage_counts.values()):
            raise ValueError("native stage sample counts must equal execution_count")
        outcomes = receipt.get("outcomes")
        if not isinstance(outcomes, dict) or not outcomes:
            raise ValueError("native receipt must provide outcomes")
        valid_outcomes = all(
            type(name) is str and name and _positive_int(count)
            for name, count in outcomes.items()
        )
        if not valid_outcomes or sum(outcomes.values()) != execution_count:
            raise ValueError("native outcomes must sum to execution_count")
        source_names = receipt.get("source_names")
        if not isinstance(source_names, list) or len(source_names) != execution_count:
            raise ValueError("native source_names must match execution_count")
        if any(
            not isinstance(names, list)
            or not names
            or any(type(name) is not str or not name for name in names)
            for names in source_names
        ):
            raise ValueError("native source_names must be non-empty string lists")
    return tuple(sorted(receipts, key=lambda receipt: receipt["corpus"]))


def _native_projection(
    receipts: tuple[dict[str, Any], ...], key: str
) -> tuple[tuple[str, object], ...]:
    return tuple((receipt["corpus"], receipt[key]) for receipt in receipts)


def compare_receipts(
    python_rows: tuple[dict[str, Any], ...],
    cython_rows: tuple[dict[str, Any], ...],
) -> dict[str, object]:
    """Return an auditable comparison and fail closed on incomplete evidence."""

    python_corpus = _corpus_receipt(python_rows)
    cython_corpus = _corpus_receipt(cython_rows)
    _validate_corpus_metadata(python_corpus)
    _validate_corpus_metadata(cython_corpus)
    python_native = _native_receipts(python_rows)
    cython_native = _native_receipts(cython_rows)
    comparisons = {
        "image_match": python_corpus["docker_image"] == cython_corpus["docker_image"],
        "image_digest_match": python_corpus["docker_image_id"]
        == cython_corpus["docker_image_id"],
        "egglog_version_match": python_corpus["egglog_version"]
        == cython_corpus["egglog_version"],
        "candidate_count_match": python_corpus["candidate_count"]
        == cython_corpus["candidate_count"],
        "candidate_identities_match": python_corpus["candidate_names"]
        == cython_corpus["candidate_names"],
        "native_stage_coverage_match": _native_projection(
            python_native, "stage_sample_counts"
        )
        == _native_projection(cython_native, "stage_sample_counts"),
        "native_outcomes_match": _native_projection(python_native, "outcomes")
        == _native_projection(cython_native, "outcomes"),
        "native_source_identities_match": _native_projection(
            python_native, "source_names"
        )
        == _native_projection(cython_native, "source_names"),
    }
    if not all(comparisons.values()):
        mismatches = ", ".join(
            name for name, matched in comparisons.items() if not matched
        )
        raise ValueError(f"Egglog performance receipt mismatch: {mismatches}")
    return {
        "comparison": comparisons,
        "python": {
            "candidate_count": python_corpus["candidate_count"],
            "docker_image": python_corpus["docker_image"],
            "docker_image_id": python_corpus["docker_image_id"],
            "egglog_version": python_corpus["egglog_version"],
            "native_stage_coverage": _native_projection(
                python_native, "stage_sample_counts"
            ),
        },
        "cython": {
            "candidate_count": cython_corpus["candidate_count"],
            "docker_image": cython_corpus["docker_image"],
            "docker_image_id": cython_corpus["docker_image_id"],
            "egglog_version": cython_corpus["egglog_version"],
            "native_stage_coverage": _native_projection(
                cython_native, "stage_sample_counts"
            ),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", dest="python_path", type=Path, required=True)
    parser.add_argument("--cython", dest="cython_path", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = compare_receipts(
        _load_receipts(args.python_path), _load_receipts(args.cython_path)
    )
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()

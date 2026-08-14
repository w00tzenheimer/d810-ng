#!/usr/bin/env python3
"""Validate and summarize two native Egglog performance receipt streams."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _load_receipts(path: Path) -> tuple[dict[str, Any], ...]:
    rows = tuple(
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
    )
    if not rows or not all(isinstance(row, dict) for row in rows):
        raise ValueError(f"{path} must contain JSON object receipts")
    return rows


def _corpus_receipt(rows: tuple[dict[str, Any], ...]) -> dict[str, Any]:
    matches = [row for row in rows if "candidate_count" in row]
    if len(matches) != 1:
        raise ValueError("expected exactly one corpus performance receipt")
    return matches[0]


def _native_coverage(
    rows: tuple[dict[str, Any], ...],
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    coverage: list[tuple[str, tuple[str, ...]]] = []
    for row in rows:
        corpus = row.get("corpus")
        counts = row.get("stage_sample_counts")
        if type(corpus) is str and isinstance(counts, dict):
            coverage.append((corpus, tuple(sorted(counts))))
    return tuple(coverage)


def _validate_corpus_metadata(receipt: dict[str, Any]) -> None:
    required_strings = ("docker_image", "docker_image_id", "egglog_version")
    for field in required_strings:
        if type(receipt.get(field)) is not str or not receipt[field]:
            raise ValueError(f"corpus receipt must provide non-empty {field}")
    candidate_names = receipt.get("candidate_names")
    if not isinstance(candidate_names, list) or not candidate_names:
        raise ValueError("corpus receipt must provide non-empty candidate_names")


def compare_receipts(
    python_rows: tuple[dict[str, Any], ...],
    cython_rows: tuple[dict[str, Any], ...],
) -> dict[str, object]:
    """Return an auditable comparison and fail closed on environment drift."""

    python_corpus = _corpus_receipt(python_rows)
    cython_corpus = _corpus_receipt(cython_rows)
    _validate_corpus_metadata(python_corpus)
    _validate_corpus_metadata(cython_corpus)
    python_coverage = _native_coverage(python_rows)
    cython_coverage = _native_coverage(cython_rows)
    if not python_coverage or not cython_coverage:
        raise ValueError("receipt streams must provide native stage coverage")
    comparisons = {
        "image_match": python_corpus.get("docker_image")
        == cython_corpus.get("docker_image"),
        "image_digest_match": python_corpus.get("docker_image_id")
        == cython_corpus.get("docker_image_id"),
        "egglog_version_match": python_corpus.get("egglog_version")
        == cython_corpus.get("egglog_version"),
        "candidate_identities_match": python_corpus.get("candidate_names")
        == cython_corpus.get("candidate_names"),
        "native_stage_coverage_match": python_coverage == cython_coverage,
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
            "native_stage_coverage": python_coverage,
        },
        "cython": {
            "candidate_count": cython_corpus["candidate_count"],
            "docker_image": cython_corpus["docker_image"],
            "docker_image_id": cython_corpus["docker_image_id"],
            "egglog_version": cython_corpus["egglog_version"],
            "native_stage_coverage": cython_coverage,
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

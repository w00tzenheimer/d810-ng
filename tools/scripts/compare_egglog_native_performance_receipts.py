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
_EXPECTED_PROOF_MODES = frozenset({"legacy_native_ast", "shadow", "native_template"})


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


def _synthetic_stage_sample_counts(receipt: dict[str, Any]) -> dict[str, int]:
    """Validate and return the comparable synthetic stage sample-count profile."""

    attempts = receipt.get("stage_attempt_outcomes")
    if not isinstance(attempts, dict) or not attempts:
        raise ValueError("corpus receipt must provide stage_attempt_outcomes")
    if not all(
        type(outcome) is str and outcome and _positive_int(count)
        for outcome, count in attempts.items()
    ):
        raise ValueError("stage_attempt_outcomes must contain positive outcome counts")
    attempt_count = sum(attempts.values())

    timings = receipt.get("stage_timing_ms")
    if not isinstance(timings, dict) or set(timings) != _EXPECTED_STAGES:
        raise ValueError("corpus receipt must provide the expected stage set")
    counts: dict[str, int] = {}
    for stage, timing in timings.items():
        if not isinstance(timing, dict) or not _positive_int(
            timing.get("sample_count")
        ):
            raise ValueError(f"{stage} must provide a positive stage sample count")
        sample_count = timing["sample_count"]
        if sample_count != attempt_count:
            raise ValueError(
                "synthetic stage sample counts must equal stage_attempt_outcomes"
            )
        counts[stage] = sample_count
    return counts


def _validate_corpus_metadata(
    receipt: dict[str, Any], *, expected_cython_enabled: bool
) -> dict[str, int]:
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
    if receipt.get("cython_enabled") is not expected_cython_enabled:
        raise ValueError(
            f"corpus receipt cython_enabled must be {expected_cython_enabled}"
        )
    return _synthetic_stage_sample_counts(receipt)


def _split_receipt_stream(
    rows: tuple[dict[str, Any], ...],
) -> tuple[dict[str, Any], tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    """Classify every row so malformed or unrelated receipts cannot be ignored."""

    corpus = _corpus_receipt(rows)
    native: list[dict[str, Any]] = []
    real_corpus: list[dict[str, Any]] = []
    for row in rows:
        if row is corpus:
            continue
        if row.get("schema_version") == 2:
            real_corpus.append(row)
            continue
        if type(row.get("corpus")) is str and isinstance(
            row.get("stage_sample_counts"), dict
        ):
            native.append(row)
            continue
        raise ValueError("unrecognized receipt row")
    return corpus, tuple(native), tuple(real_corpus)


def _native_receipts(
    receipts: tuple[dict[str, Any], ...],
) -> tuple[dict[str, Any], ...]:
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


def _real_corpus_receipts(
    receipts: tuple[dict[str, Any], ...],
) -> tuple[dict[str, Any], ...]:
    """Validate full live-attempt receipts without pretending every attempt ran.

    A refusal can stop at root eligibility, so only that stage must cover every
    candidate.  Later stages are intentionally sparse and describe the actual
    partial pipeline, not a synthetic all-success path.
    """

    if not receipts:
        raise ValueError("receipt streams must provide real corpus attempts")
    identity_fields = ("corpus", "function", "project")
    identities: set[tuple[str, str, str]] = set()
    for receipt in receipts:
        if receipt.get("schema_version") != 2:
            raise ValueError("real corpus receipt must use schema_version 2")
        identity = tuple(receipt.get(field) for field in identity_fields)
        if not all(type(value) is str and value for value in identity):
            raise ValueError("real corpus receipt must provide stable identity")
        if identity in identities:
            raise ValueError("real corpus identities must be unique")
        identities.add(identity)

        execution_count = receipt.get("execution_count")
        if not _positive_int(execution_count):
            raise ValueError("real corpus receipt must provide execution_count")
        candidates = receipt.get("candidate_identities")
        if (
            not isinstance(candidates, list)
            or len(candidates) != execution_count
            or any(
                type(candidate) is not str or not candidate for candidate in candidates
            )
        ):
            raise ValueError(
                "real corpus candidate_identities must match execution_count"
            )
        if len(set(candidates)) != len(candidates):
            raise ValueError("real corpus candidate_identities must be unique")

        stage_counts = receipt.get("stage_sample_counts")
        if (
            not isinstance(stage_counts, dict)
            or not stage_counts
            or not set(stage_counts).issubset(_EXPECTED_STAGES)
            or "root_eligibility" not in stage_counts
            or any(not _positive_int(count) for count in stage_counts.values())
        ):
            raise ValueError("real corpus receipt must provide valid stage coverage")
        if stage_counts["root_eligibility"] != execution_count:
            raise ValueError("real root eligibility count must equal execution_count")
        if any(count > execution_count for count in stage_counts.values()):
            raise ValueError("real stage counts cannot exceed execution_count")

        outcomes = receipt.get("outcomes")
        if (
            not isinstance(outcomes, dict)
            or not outcomes
            or not all(
                type(name) is str and name and _positive_int(count)
                for name, count in outcomes.items()
            )
            or sum(outcomes.values()) != execution_count
        ):
            raise ValueError("real corpus outcomes must sum to execution_count")
        source_names = receipt.get("source_names")
        if not isinstance(source_names, list) or len(source_names) != execution_count:
            raise ValueError("real corpus source_names must match execution_count")
        if any(
            not isinstance(names, list)
            or any(type(name) is not str or not name for name in names)
            for names in source_names
        ):
            raise ValueError("real corpus source_names must be string lists")
        if sum(bool(names) for names in source_names) != outcomes.get("applied", 0):
            raise ValueError("real corpus applied sources must match outcomes")

        proof_modes = receipt.get("proof_mode_counts")
        if (
            not isinstance(proof_modes, dict)
            or not proof_modes
            or not set(proof_modes).issubset(_EXPECTED_PROOF_MODES)
            or not all(_positive_int(count) for count in proof_modes.values())
            or sum(proof_modes.values()) != execution_count
        ):
            raise ValueError("real corpus proof modes must match execution_count")
    return tuple(
        sorted(
            receipts,
            key=lambda receipt: tuple(receipt[field] for field in identity_fields),
        )
    )


def _real_corpus_projection(
    receipts: tuple[dict[str, Any], ...], key: str
) -> tuple[tuple[tuple[str, str, str], object], ...]:
    return tuple(
        (
            (receipt["corpus"], receipt["function"], receipt["project"]),
            receipt[key],
        )
        for receipt in receipts
    )


def compare_receipts(
    python_rows: tuple[dict[str, Any], ...],
    cython_rows: tuple[dict[str, Any], ...],
) -> dict[str, object]:
    """Return an auditable comparison and fail closed on incomplete evidence."""

    python_corpus, python_native_rows, python_real_rows = _split_receipt_stream(
        python_rows
    )
    cython_corpus, cython_native_rows, cython_real_rows = _split_receipt_stream(
        cython_rows
    )
    python_synthetic_counts = _validate_corpus_metadata(
        python_corpus, expected_cython_enabled=False
    )
    cython_synthetic_counts = _validate_corpus_metadata(
        cython_corpus, expected_cython_enabled=True
    )
    python_native = _native_receipts(python_native_rows)
    cython_native = _native_receipts(cython_native_rows)
    python_real = _real_corpus_receipts(python_real_rows)
    cython_real = _real_corpus_receipts(cython_real_rows)
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
        "cython_mode_match": (
            python_corpus["cython_enabled"] is False
            and cython_corpus["cython_enabled"] is True
        ),
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
        "real_corpus_attempts_match": _real_corpus_projection(
            python_real, "candidate_identities"
        )
        == _real_corpus_projection(cython_real, "candidate_identities"),
        "real_corpus_outcomes_match": _real_corpus_projection(python_real, "outcomes")
        == _real_corpus_projection(cython_real, "outcomes"),
        "real_corpus_source_identities_match": _real_corpus_projection(
            python_real, "source_names"
        )
        == _real_corpus_projection(cython_real, "source_names"),
        "real_corpus_stage_coverage_match": _real_corpus_projection(
            python_real, "stage_sample_counts"
        )
        == _real_corpus_projection(cython_real, "stage_sample_counts"),
        "real_corpus_proof_modes_match": _real_corpus_projection(
            python_real, "proof_mode_counts"
        )
        == _real_corpus_projection(cython_real, "proof_mode_counts"),
        "synthetic_stage_sample_counts_match": (
            python_synthetic_counts == cython_synthetic_counts
        ),
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
            "cython_enabled": python_corpus["cython_enabled"],
            "synthetic_stage_sample_counts": python_synthetic_counts,
            "native_stage_coverage": _native_projection(
                python_native, "stage_sample_counts"
            ),
            "real_corpus_stage_coverage": _real_corpus_projection(
                python_real, "stage_sample_counts"
            ),
        },
        "cython": {
            "candidate_count": cython_corpus["candidate_count"],
            "docker_image": cython_corpus["docker_image"],
            "docker_image_id": cython_corpus["docker_image_id"],
            "egglog_version": cython_corpus["egglog_version"],
            "cython_enabled": cython_corpus["cython_enabled"],
            "synthetic_stage_sample_counts": cython_synthetic_counts,
            "native_stage_coverage": _native_projection(
                cython_native, "stage_sample_counts"
            ),
            "real_corpus_stage_coverage": _real_corpus_projection(
                cython_real, "stage_sample_counts"
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

#!/usr/bin/env python3
"""Validate and summarize two native Egglog performance receipt streams."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from statistics import quantiles
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
_EXPECTED_PROOF_MODES = frozenset({"legacy", "shadow"})
_EXPECTED_OUTCOMES = frozenset(
    {
        "applied",
        "improved",
        "unchanged",
        "ineligible",
        "unavailable",
        "over_budget",
        "proof_failed",
        "reconstruction_failed",
        "error",
    }
)
_SUCCESS_OUTCOMES = frozenset({"applied", "improved"})
_PROVENANCE_REQUIRED_OUTCOMES = frozenset(
    {"applied", "improved", "proof_failed", "reconstruction_failed"}
)
_SHADOW_FALLBACK_REASONS = frozenset(
    {
        "template_unavailable",
        "shape_mismatch",
        "template_proof_failed",
        "shadow_divergence",
    }
)
_PERFORMANCE_CONTRACT = {
    "schema_version": 1,
    "baseline_kind": "native_pod_matcher",
    # Native view construction is shared Python work in both modes. This
    # contract therefore measures the numeric matcher slice directly and
    # publishes whole-native-preflight timing separately.
    # A reached preflight with zero comparisons is a shared feasibility no-op,
    # not matcher work.  Keep every such attempt in the semantic stream, but
    # evaluate the native matcher timing contract only on real structural
    # comparisons.  The paired real-IDB corpus supplies at least thirty such
    # pairs, spanning both successful matches and structural non-matches.
    "minimum_structural_matcher_pairs_per_mode": 30,
    "minimum_p50_matcher_reduction_fraction": 0.2,
    "minimum_p95_matcher_reduction_fraction": 0.1,
    "requires_exact_semantic_parity": True,
}
_MATCHER_BENCHMARK_CORPUS = "egglog-compiler-shapes"


def _load_receipts(path: Path) -> tuple[dict[str, Any], ...]:
    rows = tuple(
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
    )
    if not rows or not all(isinstance(row, dict) for row in rows):
        raise ValueError(f"{path} must contain JSON object receipts")
    return rows


def _positive_int(value: object) -> bool:
    return type(value) is int and value > 0


def _valid_cost(value: object) -> bool:
    return (
        isinstance(value, list)
        and len(value) == 2
        and all(type(item) is int and item >= 0 for item in value)
    )


def _valid_optional_elapsed(value: object) -> bool:
    return value is None or (type(value) is float and value >= 0)


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
        if row.get("schema_version") == 3:
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


def _validate_real_attempt(attempt: dict[str, Any]) -> None:
    """Reject impossible handler proof states before comparing two streams."""

    status = attempt["status"]
    refusal_reason = attempt["refusal_reason"]
    sources = attempt["source_names"]
    degree = attempt["degree"]
    input_cost = attempt["input_cost"]
    output_cost = attempt["output_cost"]
    mode = attempt["proof_mode"]
    template_source = attempt["template_source_name"]
    fallback_reason = attempt["template_fallback_reason"]
    template_verdict = attempt["template_proof_verdict"]
    legacy_verdict = attempt["legacy_proof_verdict"]
    template_elapsed_ms = attempt["template_proof_elapsed_ms"]
    legacy_elapsed_ms = attempt["legacy_proof_elapsed_ms"]
    matcher_backend = attempt["native_matcher_backend"]
    matcher_comparisons = attempt["native_matcher_comparisons"]
    matcher_lazy_swaps = attempt["native_matcher_lazy_swaps"]
    fixed_binding_count = attempt["native_fixed_binding_count"]
    matcher_elapsed_ms = attempt["native_matcher_elapsed_ms"]
    matcher_fields = (
        matcher_backend,
        matcher_comparisons,
        matcher_lazy_swaps,
        fixed_binding_count,
    )
    if all(value is None for value in matcher_fields):
        # Native preflight can refuse malformed widths, unsupported leaves, or
        # an island budget before it calls the structural matcher.
        pass
    else:
        if any(value is None for value in matcher_fields):
            raise ValueError("native matcher fields must be all present or all null")
        if matcher_backend not in {"python", "cython"}:
            raise ValueError("native matcher backend must be python or cython")
        if any(type(value) is not int or value < 0 for value in matcher_fields[1:]):
            raise ValueError("native matcher metrics must be non-negative integers")
        if matcher_comparisons > 256:
            raise ValueError("native matcher comparisons exceed fixed capacity")
        if matcher_lazy_swaps > matcher_comparisons:
            raise ValueError("native matcher lazy swaps cannot exceed comparisons")
    if not _valid_optional_elapsed(matcher_elapsed_ms):
        raise ValueError(
            "native matcher elapsed time must be a non-negative float or null"
        )

    if type(status) is not str or status not in _EXPECTED_OUTCOMES:
        raise ValueError("real corpus attempt has an unknown status")
    if status in _SUCCESS_OUTCOMES:
        if refusal_reason is not None:
            raise ValueError("successful real corpus attempt must not have a refusal")
    elif type(refusal_reason) is not str or not refusal_reason:
        raise ValueError("refused real corpus attempt requires a refusal reason")
    if not isinstance(sources, list) or any(
        type(name) is not str or not name for name in sources
    ):
        raise ValueError("real corpus attempt source_names must be string lists")
    if status in _PROVENANCE_REQUIRED_OUTCOMES and not sources:
        if status == "proof_failed":
            raise ValueError("real corpus proof failure must retain source provenance")
        raise ValueError("real corpus selected outcome must retain source provenance")

    if degree is None:
        if input_cost is not None or output_cost is not None:
            raise ValueError("null degree requires null costs")
    else:
        if type(degree) is not int or degree not in {1, 2}:
            raise ValueError("degree must be an integer in the supported range or null")
        if not _valid_cost(input_cost):
            raise ValueError(
                "input_cost must contain two non-negative integers or null"
            )
        if not _valid_cost(output_cost):
            raise ValueError(
                "output_cost must contain two non-negative integers or null"
            )
        if status in _SUCCESS_OUTCOMES and tuple(output_cost) >= tuple(input_cost):
            raise ValueError("applied real corpus attempt must strictly reduce cost")

    if template_source is not None and (
        type(template_source) is not str or not template_source
    ):
        raise ValueError("template source must be a non-empty string or null")
    if fallback_reason is not None and fallback_reason not in _SHADOW_FALLBACK_REASONS:
        raise ValueError("real corpus attempt has an unknown template fallback")
    if template_verdict is not None and type(template_verdict) is not bool:
        raise ValueError("real corpus template verdict must be boolean or null")
    if legacy_verdict is not None and type(legacy_verdict) is not bool:
        raise ValueError("real corpus legacy verdict must be boolean or null")
    if not _valid_optional_elapsed(template_elapsed_ms) or not _valid_optional_elapsed(
        legacy_elapsed_ms
    ):
        raise ValueError("real corpus proof timings must be non-negative floats")

    proof_fields = (
        template_source,
        fallback_reason,
        template_verdict,
        legacy_verdict,
        template_elapsed_ms,
        legacy_elapsed_ms,
    )
    if mode is None:
        if any(value is not None for value in proof_fields):
            raise ValueError("unreached proof must leave proof fields null")
        return
    if mode not in _EXPECTED_PROOF_MODES:
        raise ValueError("real corpus attempt has an unknown proof mode")
    if status not in _SUCCESS_OUTCOMES | {
        "proof_failed",
        "reconstruction_failed",
    }:
        raise ValueError("reached proof requires a proof-stage outcome")
    if degree is None or not sources:
        raise ValueError("reached proof requires a selected, costed rewrite")
    if legacy_verdict is None or legacy_elapsed_ms is None:
        raise ValueError("reached proof requires a legacy verdict and timing")

    if mode == "legacy":
        if any(
            value is not None
            for value in (
                template_source,
                fallback_reason,
                template_verdict,
                template_elapsed_ms,
            )
        ):
            raise ValueError("legacy proof must leave template fields null")
        if (
            status in _SUCCESS_OUTCOMES | {"reconstruction_failed"}
            and not legacy_verdict
        ):
            raise ValueError("successful legacy proof outcome requires a true verdict")
        if status == "proof_failed" and legacy_verdict:
            raise ValueError("legacy proof failure requires a false verdict")
        return

    if template_verdict is None:
        if template_elapsed_ms is not None:
            raise ValueError("unreached template proof must leave its timing null")
        if fallback_reason not in {"template_unavailable", "shape_mismatch"}:
            raise ValueError("unreached template proof requires an explained fallback")
    else:
        if template_source is None:
            raise ValueError("template proof verdict requires a template source")
        if template_elapsed_ms is None:
            raise ValueError("template proof verdict requires a template timing")
        if template_verdict != legacy_verdict:
            if fallback_reason != "shadow_divergence":
                raise ValueError(
                    "shadow verdict disagreement requires shadow_divergence"
                )
            if status != "proof_failed":
                raise ValueError("shadow divergence must be reported as proof_failed")
        elif fallback_reason == "shadow_divergence":
            raise ValueError("shadow_divergence requires disagreeing proof verdicts")
        elif fallback_reason == "template_proof_failed":
            if template_verdict or legacy_verdict:
                raise ValueError("template_proof_failed requires two false verdicts")
        elif fallback_reason is not None:
            raise ValueError("completed template proof has an inconsistent fallback")

    if status in _SUCCESS_OUTCOMES | {"reconstruction_failed"}:
        if not legacy_verdict or template_verdict is False:
            raise ValueError(
                "successful shadow proof outcome requires agreeing true verdicts"
            )
    if status == "proof_failed":
        if template_verdict == legacy_verdict is True:
            raise ValueError("proof_failed cannot retain two true shadow verdicts")
        if template_verdict is None and legacy_verdict:
            raise ValueError("proof_failed requires a false verdict or divergence")


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
        if receipt.get("schema_version") != 3:
            raise ValueError("real corpus receipt must use schema_version 3")
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

        attempt_rows = receipt.get("attempts")
        if not isinstance(attempt_rows, list) or len(attempt_rows) != execution_count:
            raise ValueError("real corpus attempts must match execution_count")
        if any(not isinstance(attempt, dict) for attempt in attempt_rows):
            raise ValueError("real corpus attempts must be objects")
        expected_attempt_keys = {
            "candidate_identity",
            "status",
            "refusal_reason",
            "source_names",
            "degree",
            "input_cost",
            "output_cost",
            "stage_timings_ms",
            "proof_mode",
            "template_source_name",
            "template_fallback_reason",
            "template_proof_verdict",
            "legacy_proof_verdict",
            "template_proof_elapsed_ms",
            "legacy_proof_elapsed_ms",
            "native_matcher_backend",
            "native_matcher_comparisons",
            "native_matcher_lazy_swaps",
            "native_fixed_binding_count",
            "native_matcher_elapsed_ms",
        }
        if any(set(attempt) != expected_attempt_keys for attempt in attempt_rows):
            raise ValueError("real corpus attempts have an invalid schema")
        if [attempt["candidate_identity"] for attempt in attempt_rows] != candidates:
            raise ValueError("real corpus attempts must preserve candidate identities")
        derived_stage_counts: dict[str, int] = {}
        derived_outcomes: dict[str, int] = {}
        derived_sources: list[list[str]] = []
        derived_proof_modes: dict[str, int] = {}
        for attempt in attempt_rows:
            _validate_real_attempt(attempt)
            status = attempt["status"]
            sources = attempt["source_names"]
            timings = attempt["stage_timings_ms"]
            mode = attempt["proof_mode"]
            if (
                not isinstance(timings, dict)
                or not timings
                or not set(timings).issubset(_EXPECTED_STAGES)
                or any(
                    type(value) is not float or value < 0 for value in timings.values()
                )
            ):
                raise ValueError("real corpus attempt timings must be known floats")
            derived_outcomes[status] = derived_outcomes.get(status, 0) + 1
            derived_sources.append(sources)
            for stage in timings:
                derived_stage_counts[stage] = derived_stage_counts.get(stage, 0) + 1
            if mode is not None:
                derived_proof_modes[mode] = derived_proof_modes.get(mode, 0) + 1

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
        if stage_counts != derived_stage_counts:
            raise ValueError("real stage counts must equal per-attempt coverage")

        outcomes = receipt.get("outcomes")
        if (
            not isinstance(outcomes, dict)
            or not outcomes
            or not all(
                type(name) is str and name and _positive_int(count)
                for name, count in outcomes.items()
            )
            or outcomes != derived_outcomes
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
        if source_names != derived_sources:
            raise ValueError("real corpus sources must equal per-attempt sources")

        proof_modes = receipt.get("proof_mode_counts")
        if (
            not isinstance(proof_modes, dict)
            or not set(proof_modes).issubset(_EXPECTED_PROOF_MODES)
            or not all(_positive_int(count) for count in proof_modes.values())
            or proof_modes != derived_proof_modes
            or receipt.get("proof_attempt_count") != sum(derived_proof_modes.values())
        ):
            raise ValueError("real corpus proof modes must equal actual proof attempts")
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


def _real_corpus_proof_projection(
    receipts: tuple[dict[str, Any], ...],
) -> tuple[tuple[tuple[str, str, str], tuple[tuple[object, ...], ...]], ...]:
    """Compare proof facts, not inherently variable per-stage timings."""

    fields = (
        "candidate_identity",
        "status",
        "refusal_reason",
        "source_names",
        "degree",
        "input_cost",
        "output_cost",
        "proof_mode",
        "template_source_name",
        "template_fallback_reason",
        "template_proof_verdict",
        "legacy_proof_verdict",
    )
    return tuple(
        (
            (receipt["corpus"], receipt["function"], receipt["project"]),
            tuple(
                tuple(
                    attempt[field] if field != "source_names" else tuple(attempt[field])
                    for field in fields
                )
                for attempt in receipt["attempts"]
            ),
        )
        for receipt in receipts
    )


def _real_corpus_proof_timings(
    receipts: tuple[dict[str, Any], ...],
) -> tuple[tuple[tuple[str, str, str], tuple[tuple[object, ...], ...]], ...]:
    """Publish every actual proof pair; timings are not parity comparisons."""

    fields = (
        "candidate_identity",
        "source_names",
        "proof_mode",
        "template_source_name",
        "template_fallback_reason",
        "template_proof_verdict",
        "legacy_proof_verdict",
        "template_proof_elapsed_ms",
        "legacy_proof_elapsed_ms",
    )
    return tuple(
        (
            (receipt["corpus"], receipt["function"], receipt["project"]),
            tuple(
                tuple(
                    attempt[field] if field != "source_names" else tuple(attempt[field])
                    for field in fields
                )
                for attempt in receipt["attempts"]
                if attempt["proof_mode"] is not None
            ),
        )
        for receipt in receipts
    )


def _real_corpus_matcher_projection(
    receipts: tuple[dict[str, Any], ...], *, include_backend: bool
) -> tuple[tuple[tuple[str, str, str], tuple[tuple[object, ...], ...]], ...]:
    """Publish candidate identity and fixed-binding counts, not binding maps."""

    fields = (
        "candidate_identity",
        "native_fixed_binding_count",
    )
    if include_backend:
        fields = (*fields, "native_matcher_backend")
    return tuple(
        (
            (receipt["corpus"], receipt["function"], receipt["project"]),
            tuple(
                tuple(attempt[field] for field in fields)
                for attempt in receipt["attempts"]
            ),
        )
        for receipt in receipts
    )


def _percentile(samples: tuple[float, ...], percentile: int) -> float:
    if len(samples) == 1:
        return samples[0]
    return quantiles(samples, n=100, method="inclusive")[percentile - 1]


def _real_corpus_matcher_timing_summary(
    receipts: tuple[dict[str, Any], ...], *, mode: str
) -> dict[str, object]:
    """Summarize actual structural matcher work without hiding no-op rows.

    All reached native-preflight attempts remain in the validated paired
    receipt stream.  This timing slice deliberately excludes the shared
    feasibility no-op rows (zero structural comparisons), because neither
    implementation ran a pattern matcher for them.
    """

    benchmark_receipts = tuple(
        receipt
        for receipt in receipts
        if receipt["corpus"] == _MATCHER_BENCHMARK_CORPUS
    )
    reached_count = sum(
        attempt["native_matcher_backend"] is not None
        for receipt in benchmark_receipts
        for attempt in receipt["attempts"]
    )
    samples = tuple(
        attempt["native_matcher_elapsed_ms"]
        for receipt in benchmark_receipts
        for attempt in receipt["attempts"]
        if attempt["native_matcher_comparisons"] not in {None, 0}
    )
    if (
        len(samples)
        < _PERFORMANCE_CONTRACT["minimum_structural_matcher_pairs_per_mode"]
    ):
        raise ValueError("real corpus must provide enough structural matcher pairs")
    if any(type(value) is not float or value < 0 for value in samples):
        raise ValueError("matched native matcher attempts require elapsed timings")
    return {
        "mode": mode,
        "reached_preflight_count": reached_count,
        "sample_count": len(samples),
        "p50_ms": _percentile(samples, 50),
        "p95_ms": _percentile(samples, 95),
        "max_ms": max(samples),
    }


def _real_corpus_uses_backend(
    receipts: tuple[dict[str, Any], ...], backend: str
) -> bool:
    """Require each reached native preflight to report the active backend."""

    return all(
        attempt["native_matcher_backend"] in {None, backend}
        for receipt in receipts
        for attempt in receipt["attempts"]
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
    python_matcher_timing = _real_corpus_matcher_timing_summary(
        python_real, mode="python"
    )
    cython_matcher_timing = _real_corpus_matcher_timing_summary(
        cython_real, mode="cython"
    )
    python_p50 = python_matcher_timing["p50_ms"]
    python_p95 = python_matcher_timing["p95_ms"]
    cython_p50 = cython_matcher_timing["p50_ms"]
    cython_p95 = cython_matcher_timing["p95_ms"]
    assert all(
        type(value) is float
        for value in (python_p50, python_p95, cython_p50, cython_p95)
    )
    matcher_timing_contract_met = (
        python_matcher_timing["sample_count"] == cython_matcher_timing["sample_count"]
        and python_p50 > 0.0
        and python_p95 > 0.0
        and (python_p50 - cython_p50) / python_p50
        >= _PERFORMANCE_CONTRACT["minimum_p50_matcher_reduction_fraction"]
        and (python_p95 - cython_p95) / python_p95
        >= _PERFORMANCE_CONTRACT["minimum_p95_matcher_reduction_fraction"]
    )
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
        "real_corpus_proof_paths_match": _real_corpus_proof_projection(python_real)
        == _real_corpus_proof_projection(cython_real),
        # Comparison and lazy-swap counts measure implementation work; a POD
        # speedup is allowed to change them. Candidate identity, fixed-binding
        # counts,
        # outcomes, provenance, and proof paths above remain exact parity
        # obligations.
        "real_corpus_matcher_binding_count_match": _real_corpus_matcher_projection(
            python_real, include_backend=False
        )
        == _real_corpus_matcher_projection(cython_real, include_backend=False),
        "real_corpus_matcher_backend_match": (
            _real_corpus_uses_backend(python_real, "python")
            and _real_corpus_uses_backend(cython_real, "cython")
            and _real_corpus_matcher_projection(python_real, include_backend=False)
            == _real_corpus_matcher_projection(cython_real, include_backend=False)
        ),
        "real_corpus_matcher_timing_contract_met": matcher_timing_contract_met,
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
        "performance_contract": _PERFORMANCE_CONTRACT,
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
            "real_corpus_proof_timings": _real_corpus_proof_timings(python_real),
            "real_corpus_matcher_metrics": _real_corpus_matcher_projection(
                python_real, include_backend=True
            ),
            "real_corpus_matcher_timing": python_matcher_timing,
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
            "real_corpus_proof_timings": _real_corpus_proof_timings(cython_real),
            "real_corpus_matcher_metrics": _real_corpus_matcher_projection(
                cython_real, include_backend=True
            ),
            "real_corpus_matcher_timing": cython_matcher_timing,
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

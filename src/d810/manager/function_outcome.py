"""Portable, function-oriented decompilation outcome summaries.

The INFO surface consumes structured receipts and outcome reports.  It never
parses component log messages, which remain diagnostic implementation detail.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass


_APPLICABLE_PHASES = frozenset(("selected", "applied"))
_MUTATION_EFFECT_KINDS = frozenset(
    (
        "mutation_receipt",
        "mba_mutation_receipt",
        "mba_instruction_edit",
        "mba_rule_edit",
        "ctree_edit",
        "native_patch_transaction",
        "idb_preparation_transaction",
    )
)


def _normalized_identifier(value: object) -> str:
    return str(value or "").strip().lower().replace(" ", "_").replace(":", "_")


def _normalized_blocker(reason_code: object) -> str | None:
    """Project a structured terminal reason into the small INFO vocabulary."""
    reason = _normalized_identifier(reason_code)
    if not reason or reason in {
        "no_modifications",
        "no_instruction_change",
        "no_rewrite",
        "not_applicable",
        "no_eligible_cfg_changes",
    }:
        return None
    if "recovery_disabled" in reason and "input_identity" in reason:
        return "input_identity_recovery_disabled"
    if reason in {
        "coordinator_owned_mutation_gateway_unavailable",
        "structural_mutation_gateway_unavailable",
    }:
        return "structural_mutation_gateway_unavailable"
    return None


@dataclass(frozen=True, slots=True)
class FunctionOutcomeSummary:
    """One immutable user-facing account of a completed decompilation."""

    function_ea: int
    function_name: str
    classification: str | None
    confidence: float | None
    evaluated: int
    applicable: int
    applied: int
    blocked_by: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.function_ea, bool) or not isinstance(self.function_ea, int):
            raise TypeError("function_ea must be an integer")
        if self.function_ea < 0:
            raise ValueError("function_ea must not be negative")
        name = str(self.function_name).strip() or f"sub_{self.function_ea:X}"
        object.__setattr__(self, "function_name", name)
        classification = (
            None
            if self.classification is None
            else str(self.classification).strip() or None
        )
        object.__setattr__(self, "classification", classification)
        if self.confidence is not None:
            confidence = float(self.confidence)
            if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
                raise ValueError("confidence must be between zero and one")
            object.__setattr__(self, "confidence", confidence)
        for field_name in ("evaluated", "applicable", "applied"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{field_name} must be an integer")
            if value < 0:
                raise ValueError(f"{field_name} must not be negative")
        blockers = tuple(
            dict.fromkeys(
                blocker
                for blocker in (
                    _normalized_identifier(item) for item in self.blocked_by
                )
                if blocker
            )
        )
        object.__setattr__(self, "blocked_by", blockers)


def _planner_counts(reports: Iterable[object]) -> tuple[int, int]:
    evaluated: set[str] = set()
    applicable: set[str] = set()
    for report in reports:
        if getattr(report, "consumer_name", "") != "hodur_planner":
            continue
        provenance = getattr(report, "provenance_dict", None)
        if callable(provenance):
            provenance = provenance()
        if not isinstance(provenance, Mapping):
            continue
        rows = provenance.get("rows", ())
        if not isinstance(rows, (list, tuple)):
            continue
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            strategy_name = str(row.get("strategy_name", "")).strip()
            if not strategy_name:
                continue
            evaluated.add(strategy_name)
            if str(row.get("phase", "")).lower() in _APPLICABLE_PHASES:
                applicable.add(strategy_name)
    return len(evaluated), len(applicable)


def _attempt_summary(attempts: Iterable[object]) -> tuple[int, tuple[str, ...]]:
    mutation_receipts: set[tuple[str, str]] = set()
    blockers: list[str] = []
    for attempt in attempts:
        blocker = _normalized_blocker(getattr(attempt, "reason_code", None))
        if blocker is not None:
            blockers.append(blocker)
        for effect in getattr(attempt, "effect_refs", ()):
            kind = str(getattr(effect, "kind", ""))
            ref_id = str(getattr(effect, "ref_id", ""))
            if kind in _MUTATION_EFFECT_KINDS and ref_id:
                mutation_receipts.add((kind, ref_id))
    return len(mutation_receipts), tuple(dict.fromkeys(blockers))


def build_function_outcome(
    *,
    function_ea: int,
    function_name: str,
    classification: str | None,
    confidence: float | None,
    reports: Iterable[object],
    attempts: Iterable[object],
    blocked_by: Iterable[str] = (),
) -> FunctionOutcomeSummary:
    """Aggregate the structured reports and receipt ledger for one session."""
    evaluated, applicable = _planner_counts(reports)
    applied, attempt_blockers = _attempt_summary(attempts)
    return FunctionOutcomeSummary(
        function_ea=function_ea,
        function_name=function_name,
        classification=classification,
        confidence=confidence,
        evaluated=evaluated,
        applicable=applicable,
        applied=applied,
        blocked_by=tuple(blocked_by) + attempt_blockers,
    )


def render_function_outcome(summary: FunctionOutcomeSummary) -> str:
    """Render the stable, single-line INFO contract for one function."""
    classification = summary.classification or "unclassified"
    if summary.classification is not None and summary.confidence is not None:
        classification += f" ({summary.confidence:.0%})"
    disposition = "changed" if summary.applied else "unchanged"
    parts = [
        f"[D810] {summary.function_name}: {classification} -> {disposition}",
        f"evaluated={summary.evaluated}",
        f"applicable={summary.applicable}",
        f"applied={summary.applied}",
    ]
    if summary.blocked_by:
        parts.append("blocked_by=" + ",".join(summary.blocked_by))
    return "; ".join(parts)


__all__ = [
    "FunctionOutcomeSummary",
    "build_function_outcome",
    "render_function_outcome",
]

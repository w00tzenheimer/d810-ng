"""Parse function-analysis prior configuration into portable prior models."""

from __future__ import annotations

from d810.analyses.control_flow.return_frontier_artifacts import (
    ReturnFrontierArtifactEdgeProof,
    ReturnFrontierArtifactPriors,
)
from d810.analyses.control_flow.terminal_tail_priors import (
    TerminalTailCascadeEgressPriors,
    TerminalTailContinuationBridgePrior,
    TerminalTailEntryFrontierPriors,
    TerminalTailEqualityFrontierPriors,
    TerminalTailRowTargetOverride,
)
from d810.core.typing import Any
from d810.passes.function_priors import FunctionAnalysisPriors


def _coerce_prior_constants(value: Any) -> tuple[object, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, int)):
        return (value,)
    try:
        return tuple(value)
    except TypeError:
        return (value,)


def _coerce_prior_int_tuple(value: Any) -> tuple[int, ...]:
    return tuple(int(item) for item in _coerce_prior_constants(value))


def load_return_frontier_edge_proofs(
    raw: Any,
) -> tuple[ReturnFrontierArtifactEdgeProof, ...]:
    if not isinstance(raw, (list, tuple)):
        return ()
    proofs: list[ReturnFrontierArtifactEdgeProof] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        try:
            proofs.append(
                ReturnFrontierArtifactEdgeProof(
                    source_block=int(item["source_block"]),
                    artifact_block=int(item["artifact_block"]),
                    old_target_block=int(item["old_target_block"]),
                    continuation_block=int(item["continuation_block"]),
                    proof_ids=tuple(
                        str(proof_id) for proof_id in item.get("proof_ids", ())
                    ),
                )
            )
        except (KeyError, TypeError, ValueError):
            continue
    return tuple(proofs)


def load_terminal_tail_cascade_priors(raw: Any) -> TerminalTailCascadeEgressPriors:
    if not isinstance(raw, dict):
        return TerminalTailCascadeEgressPriors()

    row_target_overrides = []
    for item in raw.get("row_target_overrides", ()) or ():
        if not isinstance(item, dict):
            continue
        try:
            row_target_overrides.append(
                TerminalTailRowTargetOverride(
                    byte_index=int(item["byte_index"]),
                    target_entry_byte_index=int(item["target_entry_byte_index"]),
                )
            )
        except (KeyError, TypeError, ValueError):
            continue

    continuation_bridges = []
    for item in raw.get("continuation_bridges", ()) or ():
        if not isinstance(item, dict):
            continue
        try:
            continuation_bridges.append(
                TerminalTailContinuationBridgePrior(
                    continuation_byte_index=int(item["continuation_byte_index"]),
                    source_byte_index=int(item["source_byte_index"]),
                    target_store_guard_byte_index=int(
                        item["target_store_guard_byte_index"]
                    ),
                    max_depth=int(item.get("max_depth", 8)),
                )
            )
        except (KeyError, TypeError, ValueError):
            continue

    equality_raw = raw.get("equality_frontier")
    equality = None
    if isinstance(equality_raw, dict):
        try:
            equality = TerminalTailEqualityFrontierPriors(
                return_frontier_byte_index=int(
                    equality_raw["return_frontier_byte_index"]
                ),
                row_byte_indices=_coerce_prior_int_tuple(
                    equality_raw.get("row_byte_indices", ())
                ),
                shared_store_guard_byte_indices=_coerce_prior_int_tuple(
                    equality_raw.get("shared_store_guard_byte_indices", ())
                ),
            )
        except (KeyError, TypeError, ValueError):
            equality = None

    entry_raw = raw.get("entry_frontier")
    entry = None
    if isinstance(entry_raw, dict):
        try:
            entry = TerminalTailEntryFrontierPriors(
                first_byte_index=int(entry_raw["first_byte_index"])
            )
        except (KeyError, TypeError, ValueError):
            entry = None

    return TerminalTailCascadeEgressPriors(
        byte_indices=_coerce_prior_int_tuple(raw.get("byte_indices", ())),
        split_byte_indices=_coerce_prior_int_tuple(raw.get("split_byte_indices", ())),
        row_target_overrides=tuple(row_target_overrides),
        continuation_bridges=tuple(continuation_bridges),
        equality_frontier=equality,
        entry_frontier=entry,
    )


def function_prior_keys(identifier: str | int) -> tuple[str, ...]:
    keys: set[str] = set()
    if isinstance(identifier, int):
        value = int(identifier)
        keys.add(str(value).lower())
        keys.add(f"0x{value:x}".lower())
        keys.add(f"sub_{value:x}".lower())
        return tuple(sorted(keys))

    raw = str(identifier).strip()
    if not raw:
        return tuple()
    keys.add(raw.lower())
    normalized = raw.lower()
    parse_target = normalized
    parse_base = 0
    if normalized.startswith("sub_"):
        parse_target = normalized[4:]
        parse_base = 16
    try:
        value = int(parse_target, parse_base)
    except ValueError:
        value = None
    if value is not None:
        keys.add(str(value).lower())
        keys.add(f"0x{value:x}".lower())
        keys.add(f"sub_{value:x}".lower())
    return tuple(sorted(keys))


def _lookup_priors(
    priors_by_key: dict[str, FunctionAnalysisPriors],
    function: str | int,
) -> FunctionAnalysisPriors:
    for key in function_prior_keys(function):
        priors = priors_by_key.get(key)
        if priors is not None:
            return priors
    return FunctionAnalysisPriors()


def _add_function_analysis_priors(
    priors_by_key: dict[str, FunctionAnalysisPriors],
    function: str | int,
    priors: FunctionAnalysisPriors,
) -> None:
    existing = _lookup_priors(priors_by_key, function)
    merged = existing.merge(priors)
    for key in function_prior_keys(function):
        priors_by_key[key] = merged


def load_function_analysis_priors_from_config(
    raw: Any,
) -> dict[str, FunctionAnalysisPriors]:
    priors_by_key: dict[str, FunctionAnalysisPriors] = {}
    if not isinstance(raw, dict):
        return priors_by_key
    for function, raw_priors in raw.items():
        if not isinstance(raw_priors, dict):
            continue
        return_frontier = raw_priors.get("return_frontier_artifacts", {})
        if not isinstance(return_frontier, dict):
            return_frontier = {}
        constants = return_frontier.get(
            "known_impossible_return_constants",
            raw_priors.get("known_impossible_return_constants", ()),
        )
        artifact_priors = (
            ReturnFrontierArtifactPriors
            .from_known_impossible_return_constants(
                _coerce_prior_constants(constants)
            )
        )
        artifact_priors = artifact_priors.with_impossible_return_artifact_edges(
            load_return_frontier_edge_proofs(
                return_frontier.get("impossible_return_artifact_edges", ())
            )
        )
        priors = FunctionAnalysisPriors(
            return_frontier_artifacts=artifact_priors,
            terminal_tail_cascade_egress=load_terminal_tail_cascade_priors(
                raw_priors.get("terminal_tail_cascade_egress", {})
            ),
        )
        if not priors.is_empty:
            _add_function_analysis_priors(priors_by_key, function, priors)
    return priors_by_key


__all__ = [
    "function_prior_keys",
    "load_function_analysis_priors_from_config",
    "load_return_frontier_edge_proofs",
    "load_terminal_tail_cascade_priors",
]

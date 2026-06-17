"""Pure discovery of residual raw-alias overrides from a LinearizedStateDag.

This is classification only — it walks the DAG, finds edges whose target_label
is still the raw hex form of a state value (residuals that survived primary
reconstruction), resolves them to real handler-entry blocks via the injected
callbacks, and returns a tuple of ``ResidualAliasOverride`` records. No
``modifications`` list is touched here — that is the cfg layer's job (see
``d810.transforms.residual_alias_emission``).

No IDA runtime calls, no ``ModificationBuilder`` invocations, no flow-graph
mutations. Follows the same pattern as
``d810.analyses.control_flow.missing_via_pred_discovery``: duck-typed access to DAG
edges/nodes keeps this module independent of heavy ``linearized_state_dag``
imports that pull in IDA transitively.
"""
from __future__ import annotations

from dataclasses import dataclass, replace

from d810.core.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from d810.analyses.control_flow.linearized_state_dag import StateDagEdge
    from d810.analyses.control_flow.reconstruction_candidate_builder import ReconstructionCandidate


@dataclass(frozen=True, slots=True)
class ResidualAliasOverride:
    """One residual raw-alias override resolved to a real handler entry.

    Pure data record — no CFG mutation. Consumed by
    ``d810.transforms.residual_alias_emission.emit_residual_alias_modifications`` to
    materialize primary-reconstruction-style modifications.
    """

    source_block: int
    target_entry: int
    target_state: int
    target_label: str
    normalized_edge: "StateDagEdge"
    candidate: "ReconstructionCandidate"


@dataclass(frozen=True, slots=True)
class ResidualAliasDiscoveryResult:
    """Aggregate of residual raw-alias overrides discovered on a DAG."""

    overrides: tuple[ResidualAliasOverride, ...]


def is_raw_state_label(label: str, state_value: int) -> bool:
    """Whether ``label`` is the raw hex form of ``state_value``.

    Raw labels look like ``0xdeadbeef``; canonical labels (synthesized by
    primary reconstruction) carry suffixes like ``_fallback``.
    """
    if label.endswith("_fallback"):
        return False
    try:
        return int(label, 16) == (state_value & 0xFFFFFFFF)
    except Exception:
        return False


def iter_residual_raw_alias_edges(
    dag,
    *,
    residual_dispatcher_preds: tuple[int, ...],
):
    """Yield ``(source_block, edge)`` for edges with raw-state target labels.

    Deduplicates by ``(source_block, target_state, ordered_path, target_entry)``.
    Source-block resolution follows the same two-step rule as the pre-split
    helper: prefer the tail of ``ordered_path`` if it sits on a residual
    dispatcher predecessor; otherwise fall back to the source anchor (again
    only if it's residual); else, when the residual-pred set is empty, admit
    tails that extend past the source anchor.
    """
    residual_set = {int(serial) for serial in residual_dispatcher_preds}
    seen: set[tuple[int, int, tuple[int, ...], int | None]] = set()
    for edge in getattr(dag, "edges", ()) or ():
        target_state = getattr(edge, "target_state", None)
        target_label = str(getattr(edge, "target_label", "") or "")
        if target_state is None or not is_raw_state_label(target_label, int(target_state)):
            continue
        ordered_path = tuple(int(serial) for serial in getattr(edge, "ordered_path", ()) or ())
        source_block = None
        if ordered_path and int(ordered_path[-1]) in residual_set:
            source_block = int(ordered_path[-1])
        else:
            source_anchor = getattr(edge, "source_anchor", None)
            anchor_block = getattr(source_anchor, "block_serial", None)
            if anchor_block is not None and int(anchor_block) in residual_set:
                source_block = int(anchor_block)
            elif not residual_set:
                # After region lowering, dispatcher predecessors may already be gone
                # even though a raw alias still survives on a post-source exit tail.
                # In that case, only admit tails that extend past the source anchor;
                # this keeps the late phase narrow while still catching shapes like
                # blk[15].fallthrough -> blk[16] -> 0x4C77464F.
                if ordered_path and anchor_block is not None and int(ordered_path[-1]) != int(anchor_block):
                    source_block = int(ordered_path[-1])
        if source_block is None:
            continue
        key = (
            int(source_block),
            int(target_state) & 0xFFFFFFFF,
            ordered_path,
            int(getattr(edge, "target_entry_anchor", -1))
            if getattr(edge, "target_entry_anchor", None) is not None
            else None,
        )
        if key in seen:
            continue
        seen.add(key)
        yield int(source_block), edge


def resolve_target_label_for_entry(
    dag,
    *,
    target_entry: int,
    fallback_label: str,
) -> str:
    """Return the canonical ``state_label`` for the DAG node anchored at ``target_entry``.

    Falls back to ``fallback_label`` when no node carries that entry anchor or
    when its label is empty.
    """
    for node in getattr(dag, "nodes", ()) or ():
        entry_anchor = getattr(node, "entry_anchor", None)
        if entry_anchor is None or int(entry_anchor) != int(target_entry):
            continue
        label = str(getattr(node, "state_label", "") or "")
        if label:
            return label
    return fallback_label


def discover_residual_alias_overrides(
    *,
    dag,
    flow_graph,
    dispatcher_region: set[int],
    dispatcher_serial: int,
    state_var_stkoff: int | None,
    constant_result,
    resolve_effective_target_entry,
    build_reconstruction_candidate,
    analysis_mba,
    dispatcher_lookup,
    dispatcher,
    residual_dispatcher_preds: tuple[int, ...],
    node_by_key,
    shared_suffix_blocks: set[int],
    condition_chain_blocks: set[int],
) -> ResidualAliasDiscoveryResult:
    """Discover residual raw-alias overrides on ``dag``.

    Pure classification — does not touch ``modifications``. The returned
    ``ResidualAliasDiscoveryResult`` is consumed by
    ``d810.transforms.residual_alias_emission.emit_residual_alias_modifications``.

    The callbacks (``resolve_effective_target_entry``,
    ``build_reconstruction_candidate``) are injected by the caller to keep
    this module decoupled from concrete wiring.
    """
    if state_var_stkoff is None or build_reconstruction_candidate is None:
        return ResidualAliasDiscoveryResult(overrides=())

    overrides: list[ResidualAliasOverride] = []
    seen_candidates: set[tuple[str, int, int, int | None, int | None, tuple[int, ...]]] = set()

    for source_block, edge in iter_residual_raw_alias_edges(
        dag,
        residual_dispatcher_preds=residual_dispatcher_preds,
    ):
        target_entry = getattr(edge, "target_entry_anchor", None)
        if (
            resolve_effective_target_entry is not None
            and analysis_mba is not None
        ):
            resolution = resolve_effective_target_entry(
                dag,
                edge,
                condition_chain_blocks=condition_chain_blocks,
                state_var_stkoff=int(state_var_stkoff),
                dispatcher_lookup=dispatcher_lookup,
                dispatcher=dispatcher,
                mba=analysis_mba,
            )
            resolved_target_entry = getattr(resolution, "target_entry", None)
            if resolved_target_entry is not None:
                target_entry = resolved_target_entry
        if target_entry is None:
            continue
        normalized_target = int(target_entry)
        original_target_entry = getattr(edge, "target_entry_anchor", None)
        if (
            normalized_target == int(source_block)
            or normalized_target in condition_chain_blocks
        ):
            continue
        if (
            original_target_entry is not None
            and int(original_target_entry) == normalized_target
            and not is_raw_state_label(
                str(getattr(edge, "target_label", "") or ""),
                int(getattr(edge, "target_state", 0)) & 0xFFFFFFFF,
            )
        ):
            continue

        normalized_edge = replace(
            edge,
            target_entry_anchor=normalized_target,
            target_label=resolve_target_label_for_entry(
                dag,
                target_entry=normalized_target,
                fallback_label=str(getattr(edge, "target_label", "") or ""),
            ),
        )
        candidate, _rejection = build_reconstruction_candidate(
            normalized_edge,
            flow_graph=flow_graph,
            node_by_key=node_by_key,
            state_var_stkoff=int(state_var_stkoff),
            constant_result=constant_result,
            shared_suffix_blocks=shared_suffix_blocks,
            dispatcher_region=dispatcher_region,
        )
        if candidate is None:
            continue
        candidate_key = (
            str(getattr(candidate, "emission_mode", "")),
            int(getattr(candidate, "horizon_block", -1)),
            int(getattr(candidate, "target_entry", -1)),
            (
                int(getattr(candidate, "first_shared_block"))
                if getattr(candidate, "first_shared_block", None) is not None
                else None
            ),
            (
                int(getattr(candidate, "via_pred"))
                if getattr(candidate, "via_pred", None) is not None
                else None
            ),
            tuple(int(serial) for serial in getattr(candidate.edge, "ordered_path", ()) or ()),
        )
        if candidate_key in seen_candidates:
            continue
        seen_candidates.add(candidate_key)
        overrides.append(
            ResidualAliasOverride(
                source_block=int(source_block),
                target_entry=normalized_target,
                target_state=int(getattr(edge, "target_state", 0)) & 0xFFFFFFFF,
                target_label=str(getattr(normalized_edge, "target_label", "") or ""),
                normalized_edge=normalized_edge,
                candidate=candidate,
            )
        )

    return ResidualAliasDiscoveryResult(overrides=tuple(overrides))


__all__ = [
    "ResidualAliasOverride",
    "ResidualAliasDiscoveryResult",
    "is_raw_state_label",
    "iter_residual_raw_alias_edges",
    "resolve_target_label_for_entry",
    "discover_residual_alias_overrides",
]

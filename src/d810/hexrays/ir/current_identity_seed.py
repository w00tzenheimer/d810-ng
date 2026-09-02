"""One complete current-CFG identity seed for portable CFF lowering.

This is a Hex-Rays identity-lifecycle adapter.  Optimizers consume the small
public API below, but the ``MbaBlockIdentityIndex`` type and its freshness
domain remain owned by the Hex-Rays IR layer.
"""

from __future__ import annotations

from collections.abc import Mapping

from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.ir.flowgraph import FlowGraph
from d810.transforms.cfg_transaction import LogicalBlockRef, NativeBlockRef
from d810.transforms.unflatten_authority.producer_api import (
    is_exact_logical_function_exit,
    is_unowned_structural_logical_stop,
    native_instruction_origins,
)


def current_materialized_lowering_identity(
    identity_index: object,
) -> MbaBlockIdentityIndex | None:
    """Return the sole admissible identity binding for materialized lowering.

    Resolver evidence may outlive an MBA binding.  In particular, merging
    recovery evidence deliberately clears ``ResolverSessionState.identity_index``
    so the next GENERATED MBA must recreate it.  A materialized route is not
    permitted to fall back to a serial, EA, or synthetic identity during that
    interval: it must defer until this exact catalogue is present.
    """

    return (
        identity_index
        if isinstance(identity_index, MbaBlockIdentityIndex)
        else None
    )


def resolver_identity_index_matches_flow_graph(
    identity_index: object,
    flow_graph: object,
    *,
    native_key: object,
) -> bool:
    """Accept a resolver index only when it is a complete current CFG binding."""

    if not isinstance(identity_index, MbaBlockIdentityIndex):
        return False
    if identity_index.native_key != native_key or type(flow_graph) is not FlowGraph:
        return False
    try:
        refs = identity_index.plan_refs_by_serial()
    except (TypeError, ValueError):
        return False
    expected = {int(serial) for serial in flow_graph.blocks}
    if set(refs) != expected:
        return False
    for serial in sorted(expected):
        block = flow_graph.blocks[serial]
        if int(block.serial) != serial:
            return False
        ref = refs[serial]
        if type(ref) is NativeBlockRef:
            try:
                origins = frozenset(native_instruction_origins(block))
            except (TypeError, ValueError):
                return False
            if (
                ref.identity.native_key != native_key
                or ref.identity.exact_instruction_eas != origins
            ):
                return False
        elif type(ref) is LogicalBlockRef:
            if not (
                is_exact_logical_function_exit(block, ref)
                or is_unowned_structural_logical_stop(block, ref)
            ):
                return False
        else:
            return False
    return True


def select_current_identity_index_for_flow_graph(
    identity_index: MbaBlockIdentityIndex,
    flow_graph: FlowGraph,
    *,
    native_key: object,
    generation: int,
    evidence_generation: int,
    maturity: int,
    session_id: str,
    imported_native_eas_by_serial: Mapping[int, frozenset[int]],
) -> MbaBlockIdentityIndex:
    """Rebuild a current CFG catalogue inside one live resolver binding."""

    if not isinstance(identity_index, MbaBlockIdentityIndex):
        raise TypeError("current identity seed requires a live resolver binding")

    if resolver_identity_index_matches_flow_graph(
        identity_index, flow_graph, native_key=native_key,
    ) and (
        identity_index.generation == int(generation)
        and identity_index.evidence_generation == int(evidence_generation)
        and identity_index.maturity == int(maturity)
        and identity_index.session_id == str(session_id)
    ):
        return identity_index
    return MbaBlockIdentityIndex.from_flow_graph(
        generation=int(generation),
        native_key=native_key,
        evidence_generation=int(evidence_generation),
        maturity=int(maturity),
        flow_graph=flow_graph,
        session_id=str(session_id),
        imported_native_eas_by_serial=imported_native_eas_by_serial,
    )


def refresh_current_identity_index_for_mba(
    identity_index: MbaBlockIdentityIndex,
    flow_graph: FlowGraph,
    *,
    native_key: object,
    evidence_generation: int,
    current_maturity: int,
    imported_native_eas_by_serial: Mapping[int, frozenset[int]],
) -> MbaBlockIdentityIndex:
    """Refresh a source catalogue for the MBA stage without minting a transaction.

    ``generation`` and ``session_id`` are lifetime authority inherited from the
    live resolver binding.  ``current_maturity`` is instead the provider stage
    of the MBA whose graph is being lowered, and therefore must never be
    borrowed from a prior catalogue.
    """

    if not isinstance(identity_index, MbaBlockIdentityIndex):
        raise TypeError("current identity seed requires a live resolver binding")
    return select_current_identity_index_for_flow_graph(
        identity_index,
        flow_graph,
        native_key=native_key,
        generation=int(identity_index.generation),
        evidence_generation=int(evidence_generation),
        maturity=int(current_maturity),
        session_id=str(identity_index.session_id),
        imported_native_eas_by_serial=imported_native_eas_by_serial,
    )

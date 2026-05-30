"""Env-gated equivalence probe for the ReconRoundDiscoveryContext rollout.

Runs a fresh rebuild of the DAG / indexes alongside the canonical
``ReconRoundDiscoveryContext`` and emits a single INFO log line per pass
comparing them. Dormant unless ``D810_RECON_ROUND_CTX_PROBE=1``.

The probe is strictly observational — it reads both sides and logs. It never
mutates the context or the rebuild. Use during Phase B strategy opt-in to
validate the canonical context matches the per-strategy setup recipes the
rollout is replacing.

Layer: ``d810.analyses.control_flow`` (read-only classification). No ``ModificationBuilder``
calls, no ``modifications`` lists.
"""
from __future__ import annotations

import os
from d810.core import logging
from d810.core.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from d810.analyses.control_flow.linearized_state_dag import LinearizedStateDag
    from d810.analyses.control_flow.reconstruction_discovery_indexes import (
        ReconstructionDiscoveryIndexes,
    )
    from d810.analyses.control_flow.round_discovery_context import ReconRoundDiscoveryContext


logger = logging.getLogger(
    "D810.recon.flow.round_discovery_context_probe", logging.DEBUG
)


__all__ = ("probe_enabled", "compare_round_context_to_rebuild")


def probe_enabled() -> bool:
    """Return ``True`` when ``D810_RECON_ROUND_CTX_PROBE=1`` is set."""
    return os.getenv("D810_RECON_ROUND_CTX_PROBE", "").strip() == "1"


def _edge_key(edge) -> tuple:
    src = getattr(getattr(edge, "source_anchor", None), "block_serial", None)
    arm = getattr(getattr(edge, "source_anchor", None), "branch_arm", None)
    tgt_entry = getattr(edge, "target_entry_anchor", None)
    tgt_state = getattr(edge, "target_state", None)
    path = tuple(int(s) for s in (getattr(edge, "ordered_path", ()) or ()))
    return (
        src,
        arm,
        tgt_entry,
        int(tgt_state) & 0xFFFFFFFF if tgt_state is not None else None,
        path,
    )


def compare_round_context_to_rebuild(
    ctx: ReconRoundDiscoveryContext,
    *,
    rebuild_dag: LinearizedStateDag,
    rebuild_corrected_dag: LinearizedStateDag,
    rebuild_indexes: ReconstructionDiscoveryIndexes,
) -> None:
    """Log structural equivalence between ``ctx`` and a fresh rebuild.

    Emits exactly one INFO line:
        ``ROUND CTX DAG EQUIV: match=yes``
    or
        ``ROUND CTX DAG EQUIV: match=no mismatches=[...]``

    Does NOT mutate either side.
    """
    mismatches: list[str] = []

    # 1. Edge set equivalence (by stable edge key)
    ctx_edges = {_edge_key(e) for e in getattr(ctx.dag, "edges", ())}
    rebuild_edges = {_edge_key(e) for e in getattr(rebuild_dag, "edges", ())}
    if ctx_edges != rebuild_edges:
        only_ctx = len(ctx_edges - rebuild_edges)
        only_rebuild = len(rebuild_edges - ctx_edges)
        mismatches.append(
            f"edges(ctx_only={only_ctx},rebuild_only={only_rebuild})"
        )

    # 2. bst_node_blocks equivalence
    ctx_bst = frozenset(int(s) for s in getattr(ctx.dag, "bst_node_blocks", ()))
    rebuild_bst = frozenset(
        int(s) for s in getattr(rebuild_dag, "bst_node_blocks", ())
    )
    if ctx_bst != rebuild_bst:
        mismatches.append(
            f"bst_node_blocks(ctx={len(ctx_bst)},rebuild={len(rebuild_bst)})"
        )

    # 3. dispatcher_entry_serial
    ctx_disp = int(getattr(ctx.dag, "dispatcher_entry_serial", -1))
    rebuild_disp = int(getattr(rebuild_dag, "dispatcher_entry_serial", -1))
    if ctx_disp != rebuild_disp:
        mismatches.append(
            f"dispatcher_entry_serial(ctx={ctx_disp},rebuild={rebuild_disp})"
        )

    # 4. structured_region_edge_pairs (from indexes bundle)
    ctx_pairs = set(getattr(ctx.indexes, "structured_region_edge_pairs", set()))
    rebuild_pairs = set(
        getattr(rebuild_indexes, "structured_region_edge_pairs", set())
    )
    if ctx_pairs != rebuild_pairs:
        mismatches.append(
            f"structured_region_edge_pairs(ctx={len(ctx_pairs)},rebuild={len(rebuild_pairs)})"
        )

    # 5. shared_suffix_blocks
    rebuild_shared = frozenset(
        int(s) for s in getattr(rebuild_indexes, "shared_suffix_blocks", ())
    )
    if ctx.shared_suffix_blocks != rebuild_shared:
        mismatches.append(
            f"shared_suffix_blocks(ctx={len(ctx.shared_suffix_blocks)},"
            f"rebuild={len(rebuild_shared)})"
        )

    # 6. node_by_key cardinality sanity (keys are opaque StateDagNodeKey instances)
    ctx_nk = len(ctx.node_by_key)
    rebuild_nk = len(getattr(rebuild_indexes, "node_by_key", {}))
    if ctx_nk != rebuild_nk:
        mismatches.append(
            f"node_by_key_count(ctx={ctx_nk},rebuild={rebuild_nk})"
        )

    # 7. corrected_dag edge equivalence
    ctx_corr_edges = {_edge_key(e) for e in getattr(ctx.corrected_dag, "edges", ())}
    rebuild_corr_edges = {
        _edge_key(e) for e in getattr(rebuild_corrected_dag, "edges", ())
    }
    if ctx_corr_edges != rebuild_corr_edges:
        only_ctx = len(ctx_corr_edges - rebuild_corr_edges)
        only_rebuild = len(rebuild_corr_edges - ctx_corr_edges)
        mismatches.append(
            f"corrected_edges(ctx_only={only_ctx},rebuild_only={only_rebuild})"
        )

    if mismatches:
        logger.info("ROUND CTX DAG EQUIV: match=no mismatches=%s", mismatches)
    else:
        logger.info("ROUND CTX DAG EQUIV: match=yes")

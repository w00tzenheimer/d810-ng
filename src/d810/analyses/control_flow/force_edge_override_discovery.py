"""Force-edge structured-region override plan discovery.

Pure classification producer for the structured-region force-edge override
block originally inlined in
``d810.optimizers.microcode.flow.flattening.hodur.strategies.reconstruction``
at lines 1176-1582.

For each ``(region, force_edge)`` pair the producer selects one of four
variant branches:

 * ``already_accepted`` — the force edge is already represented in the
   region's accepted-pair set; skip.
 * ``deferred`` — policy (see ``_should_defer_force_edge_materialization``)
   defers materialization to the bridge/postprocess pipeline.
 * ``no_candidates`` — no live override candidates; the emitter must first
   attempt a cached direct override, then fall back to the
   ``missing_via_pred`` retry path.
 * ``override_attempt`` — live override candidates exist; the emitter
   attempts a grouped shared-block reconstruction followed by the
   mixed-group / single-direct fallbacks.

The producer does **not** call ``ModificationBuilder``, does **not** touch
``flow_graph``, and does **not** read the cache. The emitter is responsible
for all mutation and replay.

Sub7ffd-specific constants are duplicated here (per the existing producer
pattern in ``d810.analyses.control_flow.missing_via_pred_discovery``). They must stay
in sync with the values in ``reconstruction.py``.
"""
from __future__ import annotations

from dataclasses import dataclass
from d810.core.typing import Mapping, Sequence


# Duplicated from reconstruction.py. Must stay in sync.
_SUB7FFD_DOWNSTREAM_REGION_NAME = "sub7ffd_downstream_chain_region"
_SUB7FFD_DOWNSTREAM_HEAD_FORCE_EDGE = (0x2E6C61F3, 0x652D7A98)


__all__ = [
    "ForceEdgeOverrideVariant",
    "ForceEdgeOverridePlan",
    "discover_force_edge_overrides",
    "_should_defer_force_edge_materialization",
    "_SUB7FFD_DOWNSTREAM_REGION_NAME",
    "_SUB7FFD_DOWNSTREAM_HEAD_FORCE_EDGE",
]


# Variant tag. String-valued rather than enum to keep the classification
# protocol printable for logging and to match the existing ``emission_mode``
# naming convention used across other producer/emitter pairs in this package.
ForceEdgeOverrideVariant = str


def _should_defer_force_edge_materialization(
    *,
    region_name: str,
    force_edge: tuple[int, int],
    override_candidates: Sequence[object],
) -> bool:
    """Policy gate for force-edge deferral to bridge/postprocess.

    Duplicated from ``reconstruction._should_defer_force_edge_materialization``
    verbatim. Later same-maturity reruns can still carry trusted region
    ownership even when the live graph no longer exposes a safe direct
    override candidate. For sub_7FFD's downstream head edge, forcing the
    cached direct redirect too early suppresses the bridge/post-bridge
    rescue sequence that currently yields the less-bad CFG shape, so keep
    this edge deferred.
    """
    return (
        region_name == _SUB7FFD_DOWNSTREAM_REGION_NAME
        and force_edge == _SUB7FFD_DOWNSTREAM_HEAD_FORCE_EDGE
        and not override_candidates
    )


@dataclass(frozen=True, slots=True)
class ForceEdgeOverridePlan:
    """Classification result for one ``(region, force_edge)`` pair.

    Fields are populated per ``variant``:

     * ``already_accepted``: no payload beyond the identifying pair.
     * ``deferred``: no payload beyond the identifying pair.
     * ``no_candidates``:
          * ``allow_corrected_missing_via_pred_retry`` — when ``True`` the
            emitter must attempt the ``missing_via_pred`` retry using the
            corrected-DAG matching edges even though no raw override
            candidates exist (sub_7FFD downstream head carve-out).
          * ``override_candidates`` is empty.
     * ``override_attempt``:
          * ``override_candidates`` — the non-empty list of raw override
            candidates for this force_edge.
          * ``shared_block`` — the shared-block serial the emitter should
            use for grouped reconstruction. ``None`` means no shared block
            (skip).
    """

    region_name: str
    force_edge: tuple[int, int]
    variant: ForceEdgeOverrideVariant
    override_candidates: tuple[object, ...]
    shared_block: int | None
    allow_corrected_missing_via_pred_retry: bool


def discover_force_edge_overrides(
    *,
    region_name: str,
    force_edge: tuple[int, int],
    structured_region_accepted_pairs: Mapping[str, set[tuple[int, int]]],
    structured_region_candidates_by_pair: Mapping[
        tuple[int, int], Sequence[object]
    ],
    corrected_region_edges_by_pair: Mapping[tuple[int, int], Sequence[object]],
) -> ForceEdgeOverridePlan:
    """Classify one ``(region, force_edge)`` pair into a variant-tagged plan.

    Mirrors the classification order of the original inline block:

      1. ``already_accepted`` skip (L1181-L1182).
      2. Log the status line (handled by the emitter to preserve byte-
         identical ordering).
      3. ``allow_corrected_missing_via_pred_retry`` gate (L1199-L1204).
      4. ``deferred`` skip (L1205-L1215).
      5. ``no_candidates`` branch (L1216+): cached replay + missing_via_pred
         retry; emitted by the emitter.
      6. ``override_attempt`` branch: shared_block path (L1337+).

    The producer performs classification only; the emitter owns the log
    messages and the cache read/write side effects.
    """
    override_candidates = tuple(
        structured_region_candidates_by_pair.get(force_edge, ())
    )

    if force_edge in structured_region_accepted_pairs.get(region_name, set()):
        return ForceEdgeOverridePlan(
            region_name=region_name,
            force_edge=force_edge,
            variant="already_accepted",
            override_candidates=override_candidates,
            shared_block=None,
            allow_corrected_missing_via_pred_retry=False,
        )

    allow_corrected_missing_via_pred_retry = (
        region_name == _SUB7FFD_DOWNSTREAM_REGION_NAME
        and force_edge == _SUB7FFD_DOWNSTREAM_HEAD_FORCE_EDGE
        and not override_candidates
        and bool(corrected_region_edges_by_pair.get(force_edge, ()))
    )

    if (
        _should_defer_force_edge_materialization(
            region_name=region_name,
            force_edge=force_edge,
            override_candidates=override_candidates,
        )
        and not allow_corrected_missing_via_pred_retry
    ):
        return ForceEdgeOverridePlan(
            region_name=region_name,
            force_edge=force_edge,
            variant="deferred",
            override_candidates=override_candidates,
            shared_block=None,
            allow_corrected_missing_via_pred_retry=False,
        )

    if not override_candidates:
        return ForceEdgeOverridePlan(
            region_name=region_name,
            force_edge=force_edge,
            variant="no_candidates",
            override_candidates=(),
            shared_block=None,
            allow_corrected_missing_via_pred_retry=(
                allow_corrected_missing_via_pred_retry
            ),
        )

    shared_block = override_candidates[0].first_shared_block
    if shared_block is None:
        return ForceEdgeOverridePlan(
            region_name=region_name,
            force_edge=force_edge,
            variant="override_attempt",
            override_candidates=override_candidates,
            shared_block=None,
            allow_corrected_missing_via_pred_retry=False,
        )

    return ForceEdgeOverridePlan(
        region_name=region_name,
        force_edge=force_edge,
        variant="override_attempt",
        override_candidates=override_candidates,
        shared_block=int(shared_block),
        allow_corrected_missing_via_pred_retry=False,
    )

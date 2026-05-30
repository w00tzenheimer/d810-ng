"""Missing-via-pred direct-override plan discovery.

Pure classification producer for the structured-region ``missing_via_pred``
retry path. Checks the rejected-metadata gate, collects raw and corrected
matching edges per ``force_edge``, and surfaces the ``DOWNSTREAM_HEAD_RESCUE``
special case as a typed plan input for the emitter.

No IDA runtime calls, no flow-graph mutations, no ``ModificationBuilder``
invocations. The emitter side (``d810.transforms.reconstruction_missing_via_pred_emission``)
consumes the plan produced here and runs the actual ``plan_direct_reconstruction_modifications``
+ ``plan_passthrough_reconstruction_modifications`` pair.
"""
from __future__ import annotations

from dataclasses import dataclass
from d810.core.typing import Mapping


# Duplicated here to keep this producer independent of the hodur strategy module.
# Must stay in sync with reconstruction._SUB7FFD_DOWNSTREAM_REGION_NAME and the
# associated force-edge / rescue constants.
_SUB7FFD_DOWNSTREAM_REGION_NAME = "sub7ffd_downstream_chain_region"
_SUB7FFD_DOWNSTREAM_HEAD_FORCE_EDGE = (0x2E6C61F3, 0x652D7A98)
_SUB7FFD_DOWNSTREAM_HEAD_RESCUE_SOURCE = 34
_SUB7FFD_DOWNSTREAM_HEAD_RESCUE_TARGET = 26


__all__ = [
    "MissingViaPredOverridePlan",
    "DownstreamHeadRescuePlan",
    "discover_missing_via_pred_direct_overrides",
    "_SUB7FFD_DOWNSTREAM_REGION_NAME",
    "_SUB7FFD_DOWNSTREAM_HEAD_FORCE_EDGE",
    "_SUB7FFD_DOWNSTREAM_HEAD_RESCUE_SOURCE",
    "_SUB7FFD_DOWNSTREAM_HEAD_RESCUE_TARGET",
]


@dataclass(frozen=True, slots=True)
class DownstreamHeadRescuePlan:
    """Sub7ffd downstream-head rescue bypass descriptor.

    Attached to a ``MissingViaPredOverridePlan`` when the corrected variant
    targets the sub_7FFD downstream head edge and the raw variant's target
    entries match the expected rescue target. The emitter applies this bypass
    inside the corrected ``_try_edge_set`` success path to keep the original
    helper semantics.
    """

    region_name: str
    force_edge: tuple[int, int]
    expected_source_block: int
    expected_target_entry: int
    rescue_source: int
    rescue_target: int
    raw_target_entries_requirement: tuple[int, ...]
    """raw_target_entries must equal this set (as a set) for the rescue to fire."""


@dataclass(frozen=True, slots=True)
class MissingViaPredOverridePlan:
    """Plan envelope for the missing-via-pred direct-override emission.

    ``variant_order`` preserves the original raw-then-corrected attempt order.
    ``raw_matching_edges`` and ``corrected_matching_edges`` are frozen tuples
    carrying the DAG edges the emitter will feed into
    ``plan_direct_reconstruction_modifications`` /
    ``plan_passthrough_reconstruction_modifications``.

    ``corrected_disabled_reason`` is set when the corrected variant should be
    short-circuited (sub_7FFD downstream head edge carve-out). In that case the
    emitter logs the original message and returns ``False`` instead of trying
    the corrected edge set.
    """

    force_edge: tuple[int, int]
    region_name: str
    variant_order: tuple[str, ...]
    raw_matching_edges: tuple[object, ...]
    corrected_matching_edges: tuple[object, ...]
    corrected_disabled_reason: str | None
    downstream_head_rescue: DownstreamHeadRescuePlan | None


def discover_missing_via_pred_direct_overrides(
    *,
    force_edge: tuple[int, int],
    region_name: str,
    structured_region_edges_by_pair: Mapping[tuple[int, int], list[object]],
    corrected_region_edges_by_pair: Mapping[tuple[int, int], list[object]],
    rejected_metadata: list[dict[str, int | str | None]],
) -> MissingViaPredOverridePlan | None:
    """Classify a force edge into a ``MissingViaPredOverridePlan``.

    Returns ``None`` when the force edge has no raw matching edges or the
    rejection reasons do not gate on ``missing_via_pred`` (mirroring the
    original ``_emit_missing_via_pred_direct_override`` early-return paths).
    """
    raw_matching_edges = tuple(structured_region_edges_by_pair.get(force_edge, ()))
    if not raw_matching_edges:
        return None

    raw_source_blocks = {
        int(getattr(getattr(edge, "source_anchor", None), "block_serial", -1))
        for edge in raw_matching_edges
    }
    raw_source_blocks.discard(-1)
    matching_rejections = [
        rejection
        for rejection in rejected_metadata
        if int(rejection.get("target_state") or -1) == int(force_edge[1])
        and int(rejection.get("source_block") or -1) in raw_source_blocks
    ]
    rejection_reasons = {
        str(rejection.get("rejection_reason") or "")
        for rejection in matching_rejections
    }
    if rejection_reasons != {"missing_via_pred"}:
        return None

    # Sub_7FFD downstream head edge carve-out: disable the corrected variant and
    # defer to bridge/postprocess. Preserves the original log message / bool
    # return semantics.
    corrected_disabled_reason: str | None = None
    if (
        region_name == _SUB7FFD_DOWNSTREAM_REGION_NAME
        and force_edge == _SUB7FFD_DOWNSTREAM_HEAD_FORCE_EDGE
    ):
        corrected_disabled_reason = (
            "corrected direct-source override disabled; leaving head edge to bridge/postprocess"
        )

    corrected_matching_edges = tuple(corrected_region_edges_by_pair.get(force_edge, ()))

    downstream_head_rescue: DownstreamHeadRescuePlan | None = None
    if (
        region_name == _SUB7FFD_DOWNSTREAM_REGION_NAME
        and force_edge == _SUB7FFD_DOWNSTREAM_HEAD_FORCE_EDGE
        and raw_matching_edges
    ):
        # The emitter only fires the rescue inside the corrected variant success
        # path (variant == "corrected", source_block==170, target_entry==34).
        # We still compute the target_entries requirement here so the emitter
        # can validate identically.
        downstream_head_rescue = DownstreamHeadRescuePlan(
            region_name=region_name,
            force_edge=force_edge,
            expected_source_block=170,
            expected_target_entry=_SUB7FFD_DOWNSTREAM_HEAD_RESCUE_SOURCE,
            rescue_source=_SUB7FFD_DOWNSTREAM_HEAD_RESCUE_SOURCE,
            rescue_target=_SUB7FFD_DOWNSTREAM_HEAD_RESCUE_TARGET,
            raw_target_entries_requirement=(_SUB7FFD_DOWNSTREAM_HEAD_RESCUE_TARGET,),
        )

    return MissingViaPredOverridePlan(
        force_edge=force_edge,
        region_name=region_name,
        variant_order=("raw", "corrected"),
        raw_matching_edges=raw_matching_edges,
        corrected_matching_edges=corrected_matching_edges,
        corrected_disabled_reason=corrected_disabled_reason,
        downstream_head_rescue=downstream_head_rescue,
    )

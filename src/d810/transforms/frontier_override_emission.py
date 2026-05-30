"""Emitter for structured-frontier override plans.

Takes ``FrontierOverridePlan`` records discovered by
``d810.analyses.control_flow.frontier_override_discovery.discover_frontier_overrides``
and applies them as CFG modifications via ``ModificationBuilder``.

The emitter enforces incremental claim collisions: each successfully emitted
plan updates ``claimed_sources``/``claimed_targets``, so later plans in the
iteration order can be filtered by earlier claims (mirroring the original
single-pass behavior).
"""
from __future__ import annotations

from d810.core.typing import TYPE_CHECKING, Iterable

from d810.core import logging
from d810.transforms.modification_builder import ModificationBuilder

if TYPE_CHECKING:
    from d810.analyses.control_flow.frontier_override_discovery import FrontierOverridePlan

logger = logging.getLogger(
    "D810.hodur.strategy.state_write_reconstruction",
    logging.DEBUG,
)

__all__ = ["emit_frontier_overrides"]


def emit_frontier_overrides(
    plans: "Iterable[FrontierOverridePlan]",
    *,
    builder: ModificationBuilder,
    modifications: list,
    owned_edges: set[tuple[int, int]],
    accepted_metadata: list[dict[str, int | str | None]],
    claimed_sources: set[int],
    claimed_targets: set[int],
) -> list[dict[str, object]]:
    """Apply frontier-override plans in order, updating claim state.

    Returns the list of emitted record dicts in emission order. Preserves the
    exact log messages and per-plan side effects of the original single-pass
    helper.
    """
    emitted_records: list[dict[str, object]] = []

    for plan in plans:
        exit_block = plan.exit_block
        target_entry = plan.target_entry

        if exit_block in claimed_sources or target_entry in claimed_targets:
            continue

        if plan.reaches_target:
            claimed_targets.add(target_entry)
            continue

        if plan.branch_arm is None:
            modification = builder.goto_redirect(
                source_block=exit_block,
                target_block=target_entry,
                old_target=plan.old_target,
            )
        else:
            modification = builder.edge_redirect(
                source_block=exit_block,
                target_block=target_entry,
                old_target=plan.old_target,
            )

        modifications.append(modification)
        claimed_sources.add(exit_block)
        claimed_targets.add(target_entry)
        owned_edges.add((exit_block, target_entry))
        accepted_metadata.append(plan.edge_metadata)
        emitted_records.append(
            {
                "source_block": exit_block,
                "target_entry": target_entry,
                "branch_arm": plan.branch_arm,
                "tag": plan.tag,
                "state_edge_pair": plan.state_edge_pair,
                "roles": tuple(sorted({membership["role"] for membership in plan.memberships})),
            }
        )
        logger.info(
            "RECON DAG: structured frontier override blk[%d]%s -> blk[%d] roles=%s state=%s",
            exit_block,
            f".arm{plan.branch_arm}" if plan.branch_arm is not None else "",
            target_entry,
            sorted({membership["role"] for membership in plan.memberships}),
            plan.state_pair_label,
        )

    return emitted_records

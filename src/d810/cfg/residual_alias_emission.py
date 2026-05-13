"""Emit ModificationBuilder records for discovered residual raw-alias overrides.

Consumes a read-only ``ResidualAliasDiscoveryResult`` from the recon layer and
appends primary-reconstruction-style modifications via
``execute_primary_reconstruction_modifications``. Mutates the caller's
``modifications`` / ``owned_blocks`` / ``owned_edges``.
"""
from __future__ import annotations

from d810.core.typing import TYPE_CHECKING

from d810.cfg.reconstruction_emission import execute_primary_reconstruction_modifications

if TYPE_CHECKING:
    from d810.recon.flow.residual_alias_discovery import ResidualAliasDiscoveryResult


__all__ = ["emit_residual_alias_modifications"]


def emit_residual_alias_modifications(
    *,
    discovery: "ResidualAliasDiscoveryResult",
    flow_graph,
    node_by_key,
    dispatcher_serial: int,
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
) -> int:
    """Execute the discovered residual-alias overrides via ModificationBuilder.

    Returns the number of redirect modifications appended (matches the count
    returned by the pre-split ``emit_residual_alias_overrides``).
    """
    overrides = tuple(getattr(discovery, "overrides", ()) or ())
    if not overrides:
        return 0

    raw_candidates: list[object] = [
        getattr(override, "candidate") for override in overrides
    ]
    if not raw_candidates:
        return 0

    pre_modification_count = len(modifications)
    execute_primary_reconstruction_modifications(
        raw_candidates=raw_candidates,
        flow_graph=flow_graph,
        node_by_key=node_by_key,
        dispatcher_serial=int(dispatcher_serial),
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
    )
    return len(modifications) - pre_modification_count

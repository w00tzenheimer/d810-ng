"""Recon-domain diagnostic capture facade.

Runtime recon code (recon runtime, fact collectors, microcode dump,
unflattener reconstruction reporting, etc.) calls into this module
instead of importing ``d810.core.diag.*`` directly.

This is the *capture-side* boundary: every entry point here writes a
diagnostic row, snapshot, or session-scoped record. Read-side queries
that drive runtime behaviour go through the explicitly-documented
behavior bridge in :mod:`d810.recon.flow.selected_alternate_edge_override`,
not through this module.

Phase 1 (this module): thin re-exports of the underlying
``d810.core.diag`` functions with ``record_*`` naming where it fits the
plan's observability shape. Phases 4 and 5 move the implementations;
the call sites stay on this facade.

See:
    docs/plans/2026-05-11-diag-observability-boundary.md
    docs/diag-observability-boundary.md
"""
from __future__ import annotations

# Session / connection handles. Runtime recon code asks for the
# function-scoped diag connection, then passes it to a record_* call.
# Post-Phase-5, the implementations move but the facade names remain
# stable on the recon side.
from d810.core.diag import (
    close_diag_session as close_capture_session,
    get_diag_db as get_diag_db,
    open_diag_session as open_capture_session,
)

# Recon-domain observation writers. Names align with the plan's
# record_* terminology. The neutral dataclasses (DagNode, DagEdge,
# Modification) and the helper `dag_node_diagnostic_state` are exposed
# under their original names because callers construct them by value
# before persistence; renaming them would obscure the schema mapping.
from d810.core.diag.snapshot import (
    DagEdge as DagEdge,
    DagNode as DagNode,
    Modification as Modification,
    dag_node_diagnostic_state as dag_node_diagnostic_state,
    snapshot_dag as record_dag,
    snapshot_dag_local_facts as record_dag_local_facts,
    snapshot_fact_conflicts as record_fact_conflict,
    snapshot_fact_consumers as record_fact_consumer,
    snapshot_fact_mappings as record_fact_mapping,
    snapshot_fact_observations as record_fact_observation,
    snapshot_modifications as record_modifications,
    snapshot_reachability as record_reachability,
    snapshot_rendered_program as record_rendered_program,
)

# Recon-domain code that needs the canonical ``snapshot_mba`` writer
# imports it through this facade. Live-MBA serialization
# (``mba_to_block_snapshots``) intentionally lives only in
# ``d810.hexrays.observability`` -- exposing it here would drag hexrays
# into every test that imports the recon facade and break the
# "unit-tests-no-hexrays" import-linter contract.
from d810.core.diag.snapshot import (
    snapshot_mba as record_mba_snapshot,
)

__all__ = [
    "DagEdge",
    "DagNode",
    "Modification",
    "close_capture_session",
    "dag_node_diagnostic_state",
    "get_diag_db",
    "open_capture_session",
    "record_dag",
    "record_dag_local_facts",
    "record_fact_conflict",
    "record_fact_consumer",
    "record_fact_mapping",
    "record_fact_observation",
    "record_mba_snapshot",
    "record_modifications",
    "record_reachability",
    "record_rendered_program",
]

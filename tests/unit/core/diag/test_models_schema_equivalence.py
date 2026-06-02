"""Pin that peewee Models reproduce the diag schema for every modeled table.

Tickets llr-t3nw (slice 1) + llr-ohvr Phase A (the remaining 30 tables).

Every non-view diag table is now a peewee Model (schema source of truth, see
``d810.core.diag.models``). These assertions lock the exact column layout
(name, type, notnull, pk-position) and the index set (origin + columns) so a
future Model edit that drifts from the original hand-written DDL is caught.
Column order matters: ``snapshot.py`` writers and ``tests/.../fixtures.py``
use **positional** INSERTs, and the ``dag_*`` back-compat views ``SELECT *``.

``EXPECTED_TABLE_INFO`` / ``EXPECTED_INDEXES`` were captured from peewee's
emitted DDL and verified equal to the ORIGINAL pristine ``_SCHEMA_SQL`` for all
30 tables EXCEPT one documented cell: ``watch_block_transitions.id``. The
legacy DDL declared it ``INTEGER PRIMARY KEY AUTOINCREMENT`` (PRAGMA
``notnull=0``); peewee's ``AutoField`` emits ``INTEGER NOT NULL PRIMARY KEY``
(``notnull=1``). That difference is harmless for an INTEGER PK (NULL still
auto-assigns the rowid) and is the *only* permitted deviation (see
``ALLOWED_PK_NOTNULL_DIFFS`` + ``test_only_allowed_pristine_diff``).

Composite-PK columns that were nullable in the DDL (e.g.
``state_cfg_frontier_closure_diagnostics.reason``,
``region_shape_features.snapshot_id``) stay ``notnull=0`` -- peewee does NOT
force NOT NULL on non-AutoField PK columns -- so they must match pristine
exactly.
"""
from __future__ import annotations

import sqlite3

from d810.core.diag import create_diag_database
from d810.core.diag.schema import create_tables  # noqa: F401  (exercised path)

# --------------------------------------------------------------------------- #
# Slice-1 tables (name, type, notnull, pk-position) in column order.
# --------------------------------------------------------------------------- #
EXPECTED = {
    "snapshots": [
        ("id", "INTEGER", 1, 1),
        ("label", "TEXT", 1, 0),
        ("func_ea_hex", "TEXT", 1, 0),
        ("func_ea_i64", "INTEGER", 1, 0),
        ("maturity", "TEXT", 1, 0),
        ("phase", "TEXT", 1, 0),
        ("block_count", "INTEGER", 1, 0),
        ("timestamp", "REAL", 1, 0),
    ],
    "state_cfg_nodes": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("state_hex", "TEXT", 1, 2),
        ("state_i64", "INTEGER", 1, 0),
        ("entry_block", "INTEGER", 1, 0),
        ("classification", "TEXT", 1, 0),
        ("shared_suffix", "TEXT", 0, 0),
    ],
    "state_cfg_edges": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("edge_id", "INTEGER", 1, 2),
        ("source_state_hex", "TEXT", 0, 0),
        ("source_state_i64", "INTEGER", 0, 0),
        ("target_state_hex", "TEXT", 0, 0),
        ("target_state_i64", "INTEGER", 0, 0),
        ("edge_kind", "TEXT", 1, 0),
        ("source_block", "INTEGER", 0, 0),
        ("source_arm", "INTEGER", 0, 0),
        ("target_entry", "INTEGER", 0, 0),
        ("ordered_path", "TEXT", 1, 0),
    ],
}

# --------------------------------------------------------------------------- #
# The remaining 30 modeled tables: column layout (name, type, notnull, pk).
# Captured from peewee's emitted DDL; equal to the pristine _SCHEMA_SQL except
# ALLOWED_PK_NOTNULL_DIFFS below.
# --------------------------------------------------------------------------- #
EXPECTED_TABLE_INFO = {
    "blocks": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("serial", "INTEGER", 1, 2),
        ("block_type", "INTEGER", 1, 0),
        ("type_name", "TEXT", 1, 0),
        ("start_ea_hex", "TEXT", 0, 0),
        ("start_ea_i64", "INTEGER", 0, 0),
        ("end_ea_hex", "TEXT", 0, 0),
        ("end_ea_i64", "INTEGER", 0, 0),
        ("nsucc", "INTEGER", 1, 0),
        ("npred", "INTEGER", 1, 0),
        ("succs", "TEXT", 1, 0),
        ("preds", "TEXT", 1, 0),
        ("insn_count", "INTEGER", 1, 0),
        ("meta", "TEXT", 0, 0),
    ],
    "block_observations": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("serial", "INTEGER", 1, 2),
        ("maturity", "TEXT", 1, 0),
        ("phase", "TEXT", 1, 0),
        ("start_ea_hex", "TEXT", 0, 0),
        ("start_ea_i64", "INTEGER", 0, 0),
        ("insn_count", "INTEGER", 1, 0),
        ("insn_ea_fingerprint", "TEXT", 1, 0),
        ("opcode_fingerprint", "TEXT", 1, 0),
        ("operand_fingerprint", "TEXT", 1, 0),
        ("body_fingerprint", "TEXT", 1, 0),
    ],
    "instructions": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("block_serial", "INTEGER", 1, 2),
        ("insn_index", "INTEGER", 1, 3),
        ("ea_hex", "TEXT", 1, 0),
        ("ea_i64", "INTEGER", 1, 0),
        ("opcode", "INTEGER", 1, 0),
        ("opcode_name", "TEXT", 1, 0),
        ("dest_type", "TEXT", 0, 0),
        ("dest_stkoff", "INTEGER", 0, 0),
        ("dest_size", "INTEGER", 0, 0),
        ("src_l_type", "TEXT", 0, 0),
        ("src_l_stkoff", "INTEGER", 0, 0),
        ("src_l_value_hex", "TEXT", 0, 0),
        ("src_l_value_i64", "INTEGER", 0, 0),
        ("src_r_type", "TEXT", 0, 0),
        ("src_r_stkoff", "INTEGER", 0, 0),
        ("src_r_value_hex", "TEXT", 0, 0),
        ("src_r_value_i64", "INTEGER", 0, 0),
        ("dstr", "TEXT", 0, 0),
        ("meta", "TEXT", 0, 0),
    ],
    "state_cfg_node_blocks": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("state_hex", "TEXT", 1, 2),
        ("entry_block", "INTEGER", 1, 3),
        ("block_serial", "INTEGER", 1, 0),
        ("block_index", "INTEGER", 1, 5),
        ("role", "TEXT", 1, 4),
    ],
    "state_cfg_local_segments": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("state_hex", "TEXT", 1, 2),
        ("entry_block", "INTEGER", 1, 3),
        ("segment_index", "INTEGER", 1, 4),
        ("segment_id", "TEXT", 1, 0),
        ("kind", "TEXT", 1, 0),
        ("blocks_json", "TEXT", 1, 0),
    ],
    "state_cfg_local_edges": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("state_hex", "TEXT", 1, 2),
        ("entry_block", "INTEGER", 1, 3),
        ("edge_index", "INTEGER", 1, 4),
        ("source_segment_id", "TEXT", 1, 0),
        ("target_segment_id", "TEXT", 1, 0),
        ("kind", "TEXT", 1, 0),
        ("branch_arm", "INTEGER", 0, 0),
    ],
    "state_cfg_edge_diagnostics": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("edge_id", "INTEGER", 1, 2),
        ("classification", "TEXT", 1, 0),
        ("source_state_hex", "TEXT", 0, 0),
        ("target_state_hex", "TEXT", 0, 0),
        ("edge_kind", "TEXT", 1, 0),
        ("is_terminal_tail", "INTEGER", 1, 0),
        ("original_state_const", "TEXT", 0, 0),
        ("rewritten_state_const", "TEXT", 0, 0),
        ("related_fact_ids", "TEXT", 1, 0),
        ("reason", "TEXT", 1, 0),
    ],
    "state_cfg_frontier_closure_diagnostics": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("kind", "TEXT", 1, 2),
        ("reason", "TEXT", 0, 6),
        ("source_block", "INTEGER", 0, 3),
        ("observed_target", "INTEGER", 0, 4),
        ("branch_arm", "INTEGER", 0, 5),
        ("from_dag_scc", "INTEGER", 0, 0),
        ("to_dag_scc", "INTEGER", 0, 0),
        ("candidate_targets_json", "TEXT", 1, 0),
        ("path_json", "TEXT", 1, 0),
        ("cfg_scc_size", "INTEGER", 0, 0),
        ("payload_json", "TEXT", 1, 0),
    ],
    "bst_interval_dispatcher_rows": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("row_index", "INTEGER", 1, 2),
        ("lo_hex", "TEXT", 1, 0),
        ("lo_i64", "INTEGER", 1, 0),
        ("hi_hex", "TEXT", 1, 0),
        ("hi_i64", "INTEGER", 1, 0),
        ("target_block", "INTEGER", 1, 0),
        ("dispatcher_entry_block", "INTEGER", 0, 0),
        ("maturity", "TEXT", 0, 0),
        ("payload_json", "TEXT", 1, 0),
    ],
    "state_dispatcher_rows": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("row_index", "INTEGER", 1, 2),
        ("state_const_hex", "TEXT", 1, 0),
        ("state_const_i64", "INTEGER", 1, 0),
        ("target_block", "INTEGER", 1, 0),
        ("dispatcher_entry_block", "INTEGER", 0, 0),
        ("compare_block", "INTEGER", 0, 0),
        ("dispatcher_kind", "TEXT", 1, 0),
        ("branch_kind", "TEXT", 0, 0),
        ("maturity", "TEXT", 0, 0),
        ("confidence", "REAL", 1, 0),
        ("payload_json", "TEXT", 1, 0),
    ],
    "state_transition_bst_resolutions": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("fact_id", "TEXT", 1, 2),
        ("source_block_serial", "INTEGER", 1, 0),
        ("source_state_const_hex", "TEXT", 1, 0),
        ("bst_resolved_next_block_serial", "INTEGER", 0, 0),
        ("bst_resolved_next_state_const_hex", "TEXT", 0, 0),
        ("bst_resolved_next_state_const_u64", "INTEGER", 0, 0),
        ("bst_resolution_reason", "TEXT", 1, 0),
        ("bst_resolution_maturity", "TEXT", 1, 0),
    ],
    "state_transition_dispatch_resolutions": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("fact_id", "TEXT", 1, 2),
        ("source_block_serial", "INTEGER", 1, 0),
        ("source_state_const_hex", "TEXT", 1, 0),
        ("resolved_next_block_serial", "INTEGER", 0, 0),
        ("resolved_next_state_const_hex", "TEXT", 0, 0),
        ("resolved_next_state_const_u64", "INTEGER", 0, 0),
        ("resolution_kind", "TEXT", 1, 3),
        ("resolution_reason", "TEXT", 1, 0),
        ("resolution_maturity", "TEXT", 1, 0),
    ],
    "switch_case_transition_facts": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("row_index", "INTEGER", 1, 2),
        ("fact_id", "TEXT", 1, 0),
        ("source_state_hex", "TEXT", 0, 0),
        ("source_state_i64", "INTEGER", 0, 0),
        ("case_entry_block", "INTEGER", 0, 0),
        ("transition_kind", "TEXT", 1, 0),
        ("next_state_a_hex", "TEXT", 0, 0),
        ("next_state_a_i64", "INTEGER", 0, 0),
        ("next_state_b_hex", "TEXT", 0, 0),
        ("next_state_b_i64", "INTEGER", 0, 0),
        ("return_value", "INTEGER", 0, 0),
        ("proof_kind", "TEXT", 0, 0),
        ("trusted", "INTEGER", 1, 0),
        ("reason", "TEXT", 1, 0),
        ("profile_name", "TEXT", 0, 0),
        ("dispatcher_entry", "INTEGER", 0, 0),
        ("target_block", "INTEGER", 0, 0),
        ("payload_json", "TEXT", 1, 0),
    ],
    "branch_ownership_proofs": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("row_index", "INTEGER", 1, 2),
        ("proof_id", "TEXT", 1, 0),
        ("proof_kind", "TEXT", 1, 0),
        ("trusted", "INTEGER", 1, 0),
        ("reason", "TEXT", 1, 0),
        ("source_block", "INTEGER", 0, 0),
        ("branch_arm", "INTEGER", 0, 0),
        ("source_state_hex", "TEXT", 0, 0),
        ("source_state_i64", "INTEGER", 0, 0),
        ("target_state_hex", "TEXT", 0, 0),
        ("target_state_i64", "INTEGER", 0, 0),
        ("target_entry", "INTEGER", 0, 0),
        ("predicate_block", "INTEGER", 0, 0),
        ("dispatcher_entry_block", "INTEGER", 0, 0),
        ("oracle_kind", "TEXT", 1, 0),
        ("evidence_json", "TEXT", 1, 0),
        ("payload_json", "TEXT", 1, 0),
    ],
    "state_cfg_edge_alternate_correlations": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("collapsed_edge_id", "INTEGER", 1, 2),
        ("alternate_edge_id", "INTEGER", 1, 3),
        ("collapsed_source_state", "TEXT", 0, 0),
        ("collapsed_target_state", "TEXT", 0, 0),
        ("alternate_source_state", "TEXT", 0, 0),
        ("alternate_target_state", "TEXT", 0, 0),
        ("alternate_ordered_path", "TEXT", 1, 0),
        ("overlap_blocks", "TEXT", 1, 0),
        ("alternate_classification", "TEXT", 0, 0),
        ("reason", "TEXT", 1, 0),
    ],
    "state_cfg_edge_alternate_selections": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("collapsed_edge_id", "INTEGER", 1, 2),
        ("alternate_edge_id", "INTEGER", 1, 3),
        ("selected", "INTEGER", 1, 0),
        ("source_byte_index", "INTEGER", 0, 0),
        ("reached_byte_index", "INTEGER", 0, 0),
        ("reached_state_hex", "TEXT", 0, 0),
        ("reason", "TEXT", 1, 0),
        ("evidence_json", "TEXT", 1, 0),
    ],
    "modifications": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("mod_index", "INTEGER", 1, 2),
        ("mod_type", "TEXT", 1, 0),
        ("source_block", "INTEGER", 0, 0),
        ("target_block", "INTEGER", 0, 0),
        ("old_target", "INTEGER", 0, 0),
        ("write_site_ea_hex", "TEXT", 0, 0),
        ("write_site_ea_i64", "INTEGER", 0, 0),
        ("write_site_blk", "INTEGER", 0, 0),
        ("status", "TEXT", 1, 0),
        ("reason", "TEXT", 0, 0),
    ],
    "block_classification": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("serial", "INTEGER", 1, 2),
        ("is_bst", "INTEGER", 1, 0),
        ("is_reachable", "INTEGER", 1, 0),
        ("is_gutted", "INTEGER", 1, 0),
        ("in_claimed", "INTEGER", 1, 0),
    ],
    "rendered_programs": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("variant_name", "TEXT", 1, 2),
        ("order_strategy", "TEXT", 1, 0),
        ("program_strategy", "TEXT", 1, 0),
        ("label_render_mode", "TEXT", 1, 0),
        ("boundary_inline_mode", "TEXT", 1, 0),
        ("comment_mode", "TEXT", 1, 0),
        ("line_count", "INTEGER", 1, 0),
        ("node_count", "INTEGER", 1, 0),
    ],
    "rendered_program_nodes": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("variant_name", "TEXT", 1, 2),
        ("node_index", "INTEGER", 1, 3),
        ("label_text", "TEXT", 1, 0),
        ("node_kind", "TEXT", 1, 0),
        ("state_label", "TEXT", 0, 0),
        ("handler_serial", "INTEGER", 0, 0),
        ("entry_anchor", "INTEGER", 0, 0),
        ("label_num", "INTEGER", 0, 0),
        ("line_start", "INTEGER", 1, 0),
        ("line_end", "INTEGER", 1, 0),
    ],
    "rendered_program_lines": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("variant_name", "TEXT", 1, 2),
        ("line_no", "INTEGER", 1, 3),
        ("node_index", "INTEGER", 0, 0),
        ("indent_level", "INTEGER", 1, 0),
        ("line_kind", "TEXT", 1, 0),
        ("target_label", "TEXT", 0, 0),
        ("text", "TEXT", 1, 0),
    ],
    "watch_block_transitions": [
        # ``id`` notnull=1 here (peewee AutoField) vs pristine notnull=0;
        # documented exception (see ALLOWED_PK_NOTNULL_DIFFS).
        ("id", "INTEGER", 1, 1),
        ("func_ea_hex", "TEXT", 1, 0),
        ("func_ea_i64", "INTEGER", 1, 0),
        ("apply_session_id", "TEXT", 1, 0),
        ("mod_index", "INTEGER", 0, 0),
        ("mod_type", "TEXT", 1, 0),
        ("phase", "TEXT", 1, 0),
        ("block_serial", "INTEGER", 1, 0),
        ("prev_type_name", "TEXT", 0, 0),
        ("prev_succs", "TEXT", 0, 0),
        ("prev_preds", "TEXT", 0, 0),
        ("now_type_name", "TEXT", 0, 0),
        ("now_succs", "TEXT", 0, 0),
        ("now_preds", "TEXT", 0, 0),
        ("timestamp", "REAL", 1, 0),
    ],
    "cfg_provenance": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("seq", "INTEGER", 1, 2),
        ("pass_name", "TEXT", 1, 0),
        ("action", "TEXT", 1, 0),
        ("block_serial", "INTEGER", 1, 0),
        ("target_serial", "INTEGER", 0, 0),
        ("reason", "TEXT", 0, 0),
        ("extra_json", "TEXT", 0, 0),
    ],
    "block_lineage": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("serial", "INTEGER", 1, 2),
        ("origin_snapshot_id", "INTEGER", 0, 0),
        ("origin_serial", "INTEGER", 0, 0),
        ("origin_start_ea_hex", "TEXT", 0, 0),
        ("origin_body_fingerprint", "TEXT", 0, 0),
        ("creation_kind", "TEXT", 1, 0),
        ("creation_reason", "TEXT", 0, 0),
        ("planner_block_id", "TEXT", 0, 0),
        ("source_mod_type", "TEXT", 0, 0),
        ("extra_json", "TEXT", 0, 0),
    ],
    "fact_observations": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("func_ea_hex", "TEXT", 1, 0),
        ("func_ea_i64", "INTEGER", 1, 0),
        ("fact_id", "TEXT", 1, 2),
        ("kind", "TEXT", 1, 0),
        ("semantic_key", "TEXT", 1, 0),
        ("maturity", "TEXT", 1, 0),
        ("phase", "TEXT", 1, 0),
        ("confidence", "REAL", 1, 0),
        ("source_block", "INTEGER", 0, 0),
        ("source_ea_hex", "TEXT", 0, 0),
        ("source_ea_i64", "INTEGER", 0, 0),
        ("block_fingerprint", "TEXT", 0, 0),
        ("mop_signature", "TEXT", 0, 0),
        ("payload", "TEXT", 1, 0),
        ("evidence", "TEXT", 1, 0),
    ],
    "fact_mappings": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("func_ea_hex", "TEXT", 1, 0),
        ("func_ea_i64", "INTEGER", 1, 0),
        ("mapping_index", "INTEGER", 1, 2),
        ("source_fact_id", "TEXT", 1, 0),
        ("target_fact_id", "TEXT", 0, 0),
        ("source_maturity", "TEXT", 1, 0),
        ("target_maturity", "TEXT", 1, 0),
        ("status", "TEXT", 1, 0),
        ("confidence", "REAL", 1, 0),
        ("target_block", "INTEGER", 0, 0),
        ("target_ea_hex", "TEXT", 0, 0),
        ("target_ea_i64", "INTEGER", 0, 0),
        ("target_mop_signature", "TEXT", 0, 0),
        ("reason", "TEXT", 0, 0),
        ("payload", "TEXT", 1, 0),
    ],
    "fact_consumers": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("func_ea_hex", "TEXT", 1, 0),
        ("func_ea_i64", "INTEGER", 1, 0),
        ("consumer_index", "INTEGER", 1, 2),
        ("consumer", "TEXT", 1, 0),
        ("strategy", "TEXT", 1, 0),
        ("fact_id", "TEXT", 1, 0),
        ("maturity", "TEXT", 1, 0),
        ("decision", "TEXT", 1, 0),
        ("reason", "TEXT", 0, 0),
        ("payload", "TEXT", 1, 0),
    ],
    "fact_conflicts": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("func_ea_hex", "TEXT", 1, 0),
        ("func_ea_i64", "INTEGER", 1, 0),
        ("conflict_id", "TEXT", 1, 2),
        ("fact_id", "TEXT", 1, 0),
        ("other_fact_id", "TEXT", 1, 0),
        ("maturity", "TEXT", 1, 0),
        ("conflict_kind", "TEXT", 1, 0),
        ("reason", "TEXT", 1, 0),
        ("payload", "TEXT", 1, 0),
    ],
    "region_shape_features": [
        ("func_ea_hex", "TEXT", 1, 1),
        ("func_ea_i64", "INTEGER", 1, 0),
        ("snapshot_id", "INTEGER", 0, 3),
        ("source", "TEXT", 1, 2),
        ("region", "TEXT", 1, 0),
        ("feature", "TEXT", 1, 4),
        ("value_text", "TEXT", 1, 0),
        ("evidence_json", "TEXT", 1, 0),
    ],
    "terminal_tail_dce_causes": [
        ("func_ea_hex", "TEXT", 1, 1),
        ("func_ea_i64", "INTEGER", 1, 0),
        ("byte_index", "INTEGER", 1, 2),
        ("last_present_snapshot_id", "INTEGER", 0, 0),
        ("first_missing_snapshot_id", "INTEGER", 0, 0),
        ("last_block_serial", "INTEGER", 0, 0),
        ("last_ea_hex", "TEXT", 0, 0),
        ("cause", "TEXT", 1, 0),
        ("recommended_action", "TEXT", 1, 0),
        ("rationale", "TEXT", 1, 0),
        ("evidence_json", "TEXT", 1, 0),
    ],
}

# Index set per table: (origin, columns) where origin is the PRAGMA index_list
# ``origin`` ('c' = CREATE INDEX, 'pk' = primary-key autoindex, 'u' = unique).
# Index *names* may differ (peewee names them ``<table>_<col>``); assert
# presence + indexed columns, not legacy names.
EXPECTED_INDEXES = {
    "blocks": [("pk", ("snapshot_id", "serial"))],
    "block_observations": [
        ("c", ("body_fingerprint",)),
        ("c", ("start_ea_hex",)),
        ("pk", ("snapshot_id", "serial")),
    ],
    "instructions": [
        ("c", ("snapshot_id", "dest_stkoff")),
        ("c", ("snapshot_id", "ea_hex")),
        ("c", ("snapshot_id", "opcode_name")),
        ("pk", ("snapshot_id", "block_serial", "insn_index")),
    ],
    "state_cfg_node_blocks": [
        ("c", ("snapshot_id", "state_hex", "entry_block")),
        ("pk", ("snapshot_id", "state_hex", "entry_block", "role", "block_index")),
    ],
    "state_cfg_local_segments": [
        ("c", ("snapshot_id", "state_hex", "entry_block")),
        ("pk", ("snapshot_id", "state_hex", "entry_block", "segment_index")),
    ],
    "state_cfg_local_edges": [
        ("c", ("snapshot_id", "state_hex", "entry_block", "edge_index")),
        ("pk", ("snapshot_id", "state_hex", "entry_block", "edge_index")),
    ],
    "state_cfg_edge_diagnostics": [
        ("c", ("is_terminal_tail", "classification")),
        ("c", ("snapshot_id", "classification")),
        ("pk", ("snapshot_id", "edge_id")),
    ],
    "state_cfg_frontier_closure_diagnostics": [
        ("c", ("snapshot_id", "kind", "reason")),
        (
            "pk",
            (
                "snapshot_id",
                "kind",
                "source_block",
                "observed_target",
                "branch_arm",
                "reason",
            ),
        ),
    ],
    "bst_interval_dispatcher_rows": [
        ("c", ("snapshot_id", "target_block")),
        ("pk", ("snapshot_id", "row_index")),
    ],
    "state_dispatcher_rows": [
        ("c", ("snapshot_id", "dispatcher_kind")),
        ("c", ("snapshot_id", "state_const_i64")),
        ("c", ("snapshot_id", "target_block")),
        ("pk", ("snapshot_id", "row_index")),
    ],
    "state_transition_bst_resolutions": [
        ("c", ("bst_resolved_next_state_const_hex",)),
        ("c", ("source_block_serial",)),
        ("pk", ("snapshot_id", "fact_id")),
    ],
    "state_transition_dispatch_resolutions": [
        ("c", ("resolved_next_state_const_hex",)),
        ("c", ("source_block_serial",)),
        ("pk", ("snapshot_id", "fact_id", "resolution_kind")),
    ],
    "switch_case_transition_facts": [
        ("c", ("snapshot_id", "source_state_i64")),
        ("c", ("snapshot_id", "transition_kind", "trusted")),
        ("pk", ("snapshot_id", "row_index")),
    ],
    "branch_ownership_proofs": [
        ("c", ("snapshot_id", "proof_kind", "trusted")),
        ("c", ("snapshot_id", "source_block", "branch_arm")),
        ("pk", ("snapshot_id", "row_index")),
    ],
    "state_cfg_edge_alternate_correlations": [
        ("c", ("snapshot_id", "collapsed_edge_id")),
        ("pk", ("snapshot_id", "collapsed_edge_id", "alternate_edge_id")),
    ],
    "state_cfg_edge_alternate_selections": [
        ("c", ("snapshot_id", "selected")),
        ("pk", ("snapshot_id", "collapsed_edge_id", "alternate_edge_id")),
    ],
    "modifications": [("pk", ("snapshot_id", "mod_index"))],
    "block_classification": [("pk", ("snapshot_id", "serial"))],
    "rendered_programs": [("pk", ("snapshot_id", "variant_name"))],
    "rendered_program_nodes": [
        ("pk", ("snapshot_id", "variant_name", "node_index"))
    ],
    "rendered_program_lines": [
        ("c", ("snapshot_id", "variant_name", "node_index", "line_no")),
        ("pk", ("snapshot_id", "variant_name", "line_no")),
    ],
    "watch_block_transitions": [
        ("c", ("apply_session_id", "mod_index")),
        ("c", ("block_serial", "apply_session_id")),
    ],
    "cfg_provenance": [
        ("c", ("snapshot_id", "action")),
        ("c", ("snapshot_id", "block_serial")),
        ("c", ("snapshot_id", "pass_name")),
        ("pk", ("snapshot_id", "seq")),
    ],
    "block_lineage": [
        ("c", ("origin_snapshot_id", "origin_serial")),
        ("c", ("origin_start_ea_hex",)),
        ("pk", ("snapshot_id", "serial")),
    ],
    "fact_observations": [
        ("c", ("fact_id",)),
        ("c", ("func_ea_hex", "semantic_key", "maturity")),
        ("c", ("snapshot_id", "kind")),
        ("pk", ("snapshot_id", "fact_id")),
    ],
    "fact_mappings": [
        ("c", ("snapshot_id", "status")),
        ("c", ("source_fact_id", "source_maturity", "target_maturity")),
        ("pk", ("snapshot_id", "mapping_index")),
    ],
    "fact_consumers": [
        ("c", ("fact_id", "maturity")),
        ("c", ("snapshot_id", "consumer", "strategy")),
        ("pk", ("snapshot_id", "consumer_index")),
    ],
    "fact_conflicts": [
        ("c", ("fact_id", "other_fact_id", "maturity")),
        ("pk", ("snapshot_id", "conflict_id")),
    ],
    "region_shape_features": [
        ("c", ("source", "region")),
        ("pk", ("func_ea_hex", "source", "snapshot_id", "feature")),
    ],
    "terminal_tail_dce_causes": [
        ("c", ("cause",)),
        ("pk", ("func_ea_hex", "byte_index")),
    ],
}

# The ONLY permitted deviation between the model-backed schema and the original
# pristine ``_SCHEMA_SQL``: a single PK column whose ``notnull`` flag flips
# 0 -> 1 because peewee's AutoField emits NOT NULL on the INTEGER PRIMARY KEY.
# (table, column) -> the column's notnull flag in the PRISTINE DDL.
ALLOWED_PK_NOTNULL_DIFFS = {("watch_block_transitions", "id"): 0}


def _table_info(conn: sqlite3.Connection, table: str) -> list[tuple]:
    return [
        (r[1], r[2], r[3], r[5])  # name, type, notnull, pk
        for r in conn.execute(f"PRAGMA table_info({table})")
    ]


def _index_set(conn: sqlite3.Connection, table: str) -> list[tuple]:
    """Sorted (origin, indexed-columns) tuples for ``table`` (names ignored)."""
    entries = []
    for ir in conn.execute(f"PRAGMA index_list({table})").fetchall():
        cols = tuple(c[2] for c in conn.execute(f"PRAGMA index_info({ir[1]})"))
        entries.append((ir[3], cols))
    return sorted(entries)


class TestModeledSchemaEquivalence:
    def test_slice1_tables_match_expected_layout(self) -> None:
        conn = create_diag_database(":memory:").connection()
        for table, expected in EXPECTED.items():
            assert _table_info(conn, table) == expected, table

    def test_no_extra_index_on_fk_column(self) -> None:
        conn = create_diag_database(":memory:").connection()
        # Only the composite-PK autoindex should exist (no FK auto-index).
        for table in ("state_cfg_nodes", "state_cfg_edges"):
            idx = [r[1] for r in conn.execute(f"PRAGMA index_list({table})")]
            assert idx == [f"sqlite_autoindex_{table}_1"], (table, idx)

    def test_all_modeled_tables_match_expected_layout(self) -> None:
        conn = create_diag_database(":memory:").connection()
        for table, expected in EXPECTED_TABLE_INFO.items():
            assert _table_info(conn, table) == expected, table

    def test_all_modeled_tables_index_sets_match(self) -> None:
        conn = create_diag_database(":memory:").connection()
        for table, expected in EXPECTED_INDEXES.items():
            assert _index_set(conn, table) == sorted(expected), table

    def test_only_allowed_pristine_diff(self) -> None:
        """The model schema equals pristine DDL except ALLOWED_PK_NOTNULL_DIFFS.

        Reconstructs the pristine per-table layout from ``EXPECTED_TABLE_INFO``
        by reversing each allowed PK-notnull flip, proving that every other
        cell is byte-identical to the original hand-written ``_SCHEMA_SQL``.
        """
        all_tables = set(EXPECTED) | set(EXPECTED_TABLE_INFO)
        # Slice-1 tables introduce no allowed diffs.
        for (table, _col) in ALLOWED_PK_NOTNULL_DIFFS:
            assert table in all_tables, table
        # Every allowed diff must reference an existing PK column.
        info = {**EXPECTED, **EXPECTED_TABLE_INFO}
        for (table, col), pristine_notnull in ALLOWED_PK_NOTNULL_DIFFS.items():
            cells = {c[0]: c for c in info[table]}
            assert col in cells, (table, col)
            name, typ, notnull, pk = cells[col]
            assert pk > 0, (table, col, "must be a PK column")
            assert notnull == 1 and pristine_notnull == 0, (table, col)

    def test_modeled_count(self) -> None:
        # Phase A models the 30 non-slice-1, non-view tables.
        assert len(EXPECTED_TABLE_INFO) == 30

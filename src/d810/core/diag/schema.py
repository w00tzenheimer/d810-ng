"""SQLite schema for MBA diagnostic snapshots."""
from __future__ import annotations

import sqlite3

_SCHEMA_SQL = """\
-- Layer 1: Universal MBA State

-- One row per snapshot checkpoint
CREATE TABLE IF NOT EXISTS snapshots (
    id              INTEGER PRIMARY KEY,
    label           TEXT NOT NULL,
    func_ea_hex     TEXT NOT NULL,
    func_ea_i64     INTEGER NOT NULL,
    maturity        TEXT NOT NULL,
    phase           TEXT NOT NULL DEFAULT 'unknown' CHECK(phase IN ('pre_d810', 'post_apply', 'post_gut_wire', 'post_pipeline', 'post_d810', 'unknown')),
    block_count     INTEGER NOT NULL,
    timestamp       REAL NOT NULL
);

-- One row per microcode block
CREATE TABLE IF NOT EXISTS blocks (
    snapshot_id     INTEGER NOT NULL REFERENCES snapshots(id),
    serial          INTEGER NOT NULL,
    block_type      INTEGER NOT NULL,
    type_name       TEXT NOT NULL,
    start_ea_hex    TEXT,
    start_ea_i64    INTEGER,
    end_ea_hex      TEXT,
    end_ea_i64      INTEGER,
    nsucc           INTEGER NOT NULL,
    npred           INTEGER NOT NULL,
    succs           TEXT NOT NULL,
    preds           TEXT NOT NULL,
    insn_count      INTEGER NOT NULL,
    meta            TEXT,
    PRIMARY KEY (snapshot_id, serial)
);

-- Derived block observation identity.  ``(snapshot_id, serial)`` is the only
-- exact identity; EA and fingerprints are correlation features for matching
-- blocks across maturities and detecting duplicated bodies.
CREATE TABLE IF NOT EXISTS block_observations (
    snapshot_id             INTEGER NOT NULL REFERENCES snapshots(id),
    serial                  INTEGER NOT NULL,
    maturity                TEXT NOT NULL,
    phase                   TEXT NOT NULL,
    start_ea_hex            TEXT,
    start_ea_i64            INTEGER,
    insn_count              INTEGER NOT NULL,
    insn_ea_fingerprint     TEXT NOT NULL,
    opcode_fingerprint      TEXT NOT NULL,
    operand_fingerprint     TEXT NOT NULL,
    body_fingerprint        TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, serial)
);

CREATE INDEX IF NOT EXISTS idx_block_observations_ea
    ON block_observations(start_ea_hex);
CREATE INDEX IF NOT EXISTS idx_block_observations_body_fp
    ON block_observations(body_fingerprint);

-- One row per microcode instruction
CREATE TABLE IF NOT EXISTS instructions (
    snapshot_id       INTEGER NOT NULL REFERENCES snapshots(id),
    block_serial      INTEGER NOT NULL,
    insn_index        INTEGER NOT NULL,
    ea_hex            TEXT NOT NULL,
    ea_i64            INTEGER NOT NULL,
    opcode            INTEGER NOT NULL,
    opcode_name       TEXT NOT NULL,
    dest_type         TEXT,
    dest_stkoff       INTEGER,
    dest_size         INTEGER,
    src_l_type        TEXT,
    src_l_stkoff      INTEGER,
    src_l_value_hex   TEXT,
    src_l_value_i64   INTEGER,
    src_r_type        TEXT,
    src_r_stkoff      INTEGER,
    src_r_value_hex   TEXT,
    src_r_value_i64   INTEGER,
    dstr              TEXT,
    meta              TEXT,
    PRIMARY KEY (snapshot_id, block_serial, insn_index)
);

-- Derived: which instructions write to a given stack variable
CREATE VIEW IF NOT EXISTS var_writes AS
SELECT i.*, b.succs, b.preds
FROM instructions i
JOIN blocks b ON i.snapshot_id = b.snapshot_id AND i.block_serial = b.serial
WHERE i.dest_type = 'mop_S';

-- Index for fast variable provenance queries
CREATE INDEX IF NOT EXISTS idx_insn_dest_stkoff
    ON instructions(snapshot_id, dest_stkoff);
CREATE INDEX IF NOT EXISTS idx_insn_opcode
    ON instructions(snapshot_id, opcode_name);
CREATE INDEX IF NOT EXISTS idx_insn_ea_hex
    ON instructions(snapshot_id, ea_hex);

-- Layer 2: Strategy Metadata

-- DAG nodes (one per handler state)
CREATE TABLE IF NOT EXISTS dag_nodes (
    snapshot_id     INTEGER NOT NULL REFERENCES snapshots(id),
    state_hex       TEXT NOT NULL,
    state_i64       INTEGER NOT NULL,
    entry_block     INTEGER NOT NULL,
    classification  TEXT NOT NULL,
    shared_suffix   TEXT,
    PRIMARY KEY (snapshot_id, state_hex)
);

-- DAG edges (one per transition)
CREATE TABLE IF NOT EXISTS dag_edges (
    snapshot_id           INTEGER NOT NULL REFERENCES snapshots(id),
    edge_id               INTEGER NOT NULL,
    source_state_hex      TEXT,
    source_state_i64      INTEGER,
    target_state_hex      TEXT,
    target_state_i64      INTEGER,
    edge_kind             TEXT NOT NULL CHECK(edge_kind IN (
        'TRANSITION',
        'CONDITIONAL_TRANSITION',
        'CONDITIONAL_RETURN',
        'EXIT_ROUTINE',
        'UNKNOWN'
    )),
    source_block          INTEGER,
    source_arm            INTEGER,
    target_entry          INTEGER,
    ordered_path          TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, edge_id)
);

-- Typed local facts for each DAG node. These mirror LinearizedStateDag node
-- internals so tools can reconstruct state-local CFG views without scraping
-- rendered text.
CREATE TABLE IF NOT EXISTS dag_node_blocks (
    snapshot_id     INTEGER NOT NULL REFERENCES snapshots(id),
    state_hex       TEXT NOT NULL,
    entry_block     INTEGER NOT NULL,
    block_serial    INTEGER NOT NULL,
    block_index     INTEGER NOT NULL,
    role            TEXT NOT NULL CHECK(role IN (
        'owned',
        'exclusive',
        'shared_suffix'
    )),
    PRIMARY KEY (snapshot_id, state_hex, entry_block, role, block_index)
);

CREATE TABLE IF NOT EXISTS dag_local_segments (
    snapshot_id     INTEGER NOT NULL REFERENCES snapshots(id),
    state_hex       TEXT NOT NULL,
    entry_block     INTEGER NOT NULL,
    segment_index   INTEGER NOT NULL,
    segment_id      TEXT NOT NULL,
    kind            TEXT NOT NULL,
    blocks_json     TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, state_hex, entry_block, segment_index)
);

CREATE TABLE IF NOT EXISTS dag_local_edges (
    snapshot_id        INTEGER NOT NULL REFERENCES snapshots(id),
    state_hex          TEXT NOT NULL,
    entry_block        INTEGER NOT NULL,
    edge_index         INTEGER NOT NULL,
    source_segment_id  TEXT NOT NULL,
    target_segment_id  TEXT NOT NULL,
    kind               TEXT NOT NULL,
    branch_arm         INTEGER,
    PRIMARY KEY (snapshot_id, state_hex, entry_block, edge_index)
);

CREATE INDEX IF NOT EXISTS idx_dag_node_blocks_state
    ON dag_node_blocks(snapshot_id, state_hex, entry_block);
CREATE INDEX IF NOT EXISTS idx_dag_local_segments_state
    ON dag_local_segments(snapshot_id, state_hex, entry_block);
CREATE INDEX IF NOT EXISTS idx_dag_local_edges_state
    ON dag_local_edges(snapshot_id, state_hex, entry_block, edge_index);

-- Edge classification diagnostics computed by correlating dag_edges
-- with StateWriteAnchor STATE_CONST_REWRITTEN mappings,
-- StateTransitionAnchorFact transit chains, and TerminalByteEmitterFact
-- destinations.  Observability-only: NO behavior of recon edge target
-- selection depends on these rows.  See
-- ``d810.diagnostics.edge_diagnostics`` for classification rules.
CREATE TABLE IF NOT EXISTS dag_edge_diagnostics (
    snapshot_id            INTEGER NOT NULL REFERENCES snapshots(id),
    edge_id                INTEGER NOT NULL,
    classification         TEXT NOT NULL CHECK(classification IN (
        'BENIGN',
        'LOCOPT_REWRITTEN_SOURCE',
        'TARGET_UNRESOLVED_AFTER_REWRITE',
        'COLLAPSED_TO_REWRITTEN_TARGET',
        'SPURIOUS_CONDITIONAL_ARM'
    )),
    source_state_hex       TEXT,
    target_state_hex       TEXT,
    edge_kind              TEXT NOT NULL,
    is_terminal_tail       INTEGER NOT NULL DEFAULT 0,
    original_state_const   TEXT,
    rewritten_state_const  TEXT,
    related_fact_ids       TEXT NOT NULL DEFAULT '[]',
    reason                 TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, edge_id)
);
CREATE INDEX IF NOT EXISTS idx_dag_edge_diagnostics_class
    ON dag_edge_diagnostics(snapshot_id, classification);
CREATE INDEX IF NOT EXISTS idx_dag_edge_diagnostics_terminal
    ON dag_edge_diagnostics(is_terminal_tail, classification);

-- DAG-frontier closure verifier output. Diagnostic-only: these rows explain
-- semantic-SCC leaks and unresolved repair candidates. No runtime behavior may
-- use them to authorize redirects.
CREATE TABLE IF NOT EXISTS dag_frontier_closure_diagnostics (
    snapshot_id             INTEGER NOT NULL REFERENCES snapshots(id),
    kind                    TEXT NOT NULL,
    reason                  TEXT,
    source_block            INTEGER,
    observed_target         INTEGER,
    branch_arm              INTEGER,
    from_dag_scc            INTEGER,
    to_dag_scc              INTEGER,
    candidate_targets_json  TEXT NOT NULL DEFAULT '[]',
    path_json               TEXT NOT NULL DEFAULT '[]',
    cfg_scc_size            INTEGER,
    payload_json            TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (
        snapshot_id,
        kind,
        source_block,
        observed_target,
        branch_arm,
        reason
    )
);
CREATE INDEX IF NOT EXISTS idx_dag_frontier_closure_diag_kind
    ON dag_frontier_closure_diagnostics(snapshot_id, kind, reason);

-- BST-resolved next-state enrichment for StateTransitionAnchorFact rows.
-- Computed by composing:
--   * an existing LOCOPT-pre StateTransitionAnchorFact (source_state_const)
--   * the GLBOPT1 BST interval dispatcher rows (single-hop value -> handler)
--   * the LOCOPT-pre StateWriteAnchorFact at the resolved handler block
-- Observability-only: NO recon edge target selection or HCC behavior
-- depends on these rows.  Single-hop only; no recursive walking.
CREATE TABLE IF NOT EXISTS bst_interval_dispatcher_rows (
    snapshot_id             INTEGER NOT NULL REFERENCES snapshots(id),
    row_index               INTEGER NOT NULL,
    lo_hex                  TEXT NOT NULL,
    lo_i64                  INTEGER NOT NULL,
    hi_hex                  TEXT NOT NULL,
    hi_i64                  INTEGER NOT NULL,
    target_block            INTEGER NOT NULL,
    dispatcher_entry_block  INTEGER,
    maturity                TEXT,
    payload_json            TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (snapshot_id, row_index)
);
CREATE INDEX IF NOT EXISTS idx_bst_interval_dispatcher_rows_target
    ON bst_interval_dispatcher_rows(snapshot_id, target_block);

CREATE TABLE IF NOT EXISTS state_dispatcher_rows (
    snapshot_id              INTEGER NOT NULL REFERENCES snapshots(id),
    row_index                INTEGER NOT NULL,
    state_const_hex          TEXT NOT NULL,
    state_const_i64          INTEGER NOT NULL,
    target_block             INTEGER NOT NULL,
    dispatcher_entry_block   INTEGER,
    compare_block            INTEGER,
    dispatcher_kind          TEXT NOT NULL,
    branch_kind              TEXT,
    maturity                 TEXT,
    confidence               REAL NOT NULL DEFAULT 1.0,
    payload_json             TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (snapshot_id, row_index)
);
CREATE INDEX IF NOT EXISTS idx_state_dispatcher_rows_state
    ON state_dispatcher_rows(snapshot_id, state_const_i64);
CREATE INDEX IF NOT EXISTS idx_state_dispatcher_rows_target
    ON state_dispatcher_rows(snapshot_id, target_block);
CREATE INDEX IF NOT EXISTS idx_state_dispatcher_rows_kind
    ON state_dispatcher_rows(snapshot_id, dispatcher_kind);

CREATE TABLE IF NOT EXISTS state_transition_bst_resolutions (
    snapshot_id                       INTEGER NOT NULL REFERENCES snapshots(id),
    fact_id                           TEXT NOT NULL,
    source_block_serial               INTEGER NOT NULL,
    source_state_const_hex            TEXT NOT NULL,
    bst_resolved_next_block_serial    INTEGER,
    bst_resolved_next_state_const_hex TEXT,
    bst_resolved_next_state_const_u64 INTEGER,
    bst_resolution_reason             TEXT NOT NULL,
    bst_resolution_maturity           TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, fact_id)
);
CREATE INDEX IF NOT EXISTS idx_state_transition_bst_resolutions_block
    ON state_transition_bst_resolutions(source_block_serial);
CREATE INDEX IF NOT EXISTS idx_state_transition_bst_resolutions_resolved
    ON state_transition_bst_resolutions(bst_resolved_next_state_const_hex);

CREATE TABLE IF NOT EXISTS state_transition_dispatch_resolutions (
    snapshot_id                         INTEGER NOT NULL REFERENCES snapshots(id),
    fact_id                             TEXT NOT NULL,
    source_block_serial                 INTEGER NOT NULL,
    source_state_const_hex              TEXT NOT NULL,
    resolved_next_block_serial          INTEGER,
    resolved_next_state_const_hex       TEXT,
    resolved_next_state_const_u64       INTEGER,
    resolution_kind                     TEXT NOT NULL,
    resolution_reason                   TEXT NOT NULL,
    resolution_maturity                 TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, fact_id, resolution_kind)
);
CREATE INDEX IF NOT EXISTS idx_state_transition_dispatch_resolutions_block
    ON state_transition_dispatch_resolutions(source_block_serial);
CREATE INDEX IF NOT EXISTS idx_state_transition_dispatch_resolutions_resolved
    ON state_transition_dispatch_resolutions(resolved_next_state_const_hex);

CREATE TABLE IF NOT EXISTS switch_case_transition_facts (
    snapshot_id          INTEGER NOT NULL REFERENCES snapshots(id),
    row_index            INTEGER NOT NULL,
    fact_id              TEXT NOT NULL,
    source_state_hex     TEXT,
    source_state_i64     INTEGER,
    case_entry_block     INTEGER,
    transition_kind      TEXT NOT NULL,
    next_state_a_hex     TEXT,
    next_state_a_i64     INTEGER,
    next_state_b_hex     TEXT,
    next_state_b_i64     INTEGER,
    return_value         INTEGER,
    proof_kind           TEXT,
    trusted              INTEGER NOT NULL DEFAULT 0,
    reason               TEXT NOT NULL,
    profile_name         TEXT,
    dispatcher_entry     INTEGER,
    target_block         INTEGER,
    payload_json         TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (snapshot_id, row_index)
);
CREATE INDEX IF NOT EXISTS idx_switch_case_transition_facts_source
    ON switch_case_transition_facts(snapshot_id, source_state_i64);
CREATE INDEX IF NOT EXISTS idx_switch_case_transition_facts_kind
    ON switch_case_transition_facts(snapshot_id, transition_kind, trusted);

CREATE TABLE IF NOT EXISTS branch_ownership_proofs (
    snapshot_id              INTEGER NOT NULL REFERENCES snapshots(id),
    row_index                INTEGER NOT NULL,
    proof_id                 TEXT NOT NULL,
    proof_kind               TEXT NOT NULL,
    trusted                  INTEGER NOT NULL DEFAULT 0,
    reason                   TEXT NOT NULL,
    source_block             INTEGER,
    branch_arm               INTEGER,
    source_state_hex         TEXT,
    source_state_i64         INTEGER,
    target_state_hex         TEXT,
    target_state_i64         INTEGER,
    target_entry             INTEGER,
    predicate_block          INTEGER,
    dispatcher_entry_block   INTEGER,
    oracle_kind              TEXT NOT NULL,
    evidence_json            TEXT NOT NULL DEFAULT '{}',
    payload_json             TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (snapshot_id, row_index)
);
CREATE INDEX IF NOT EXISTS idx_branch_ownership_proofs_kind
    ON branch_ownership_proofs(snapshot_id, proof_kind, trusted);
CREATE INDEX IF NOT EXISTS idx_branch_ownership_proofs_source
    ON branch_ownership_proofs(snapshot_id, source_block, branch_arm);

-- Correlations between a ``COLLAPSED_TO_REWRITTEN_TARGET`` recon edge
-- and an alternate already-persisted ``dag_edges`` row whose source
-- state is a RANGE_BACKED sibling whose owned/shared blocks overlap
-- the collapsed source's blocks.  The alternate edge IS the
-- traversing route that the collapsed exact edge is missing.
-- Observability-only: NO recon edge target selection or HCC behavior
-- depends on these rows.
CREATE TABLE IF NOT EXISTS dag_edge_alternate_correlations (
    snapshot_id              INTEGER NOT NULL REFERENCES snapshots(id),
    collapsed_edge_id        INTEGER NOT NULL,
    alternate_edge_id        INTEGER NOT NULL,
    collapsed_source_state   TEXT,
    collapsed_target_state   TEXT,
    alternate_source_state   TEXT,
    alternate_target_state   TEXT,
    alternate_ordered_path   TEXT NOT NULL,
    overlap_blocks           TEXT NOT NULL,
    alternate_classification TEXT,
    reason                   TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, collapsed_edge_id, alternate_edge_id)
);
CREATE INDEX IF NOT EXISTS idx_dag_edge_alt_corr_collapsed
    ON dag_edge_alternate_correlations(snapshot_id, collapsed_edge_id);

-- Per-alternate selection decisions: for each
-- ``dag_edge_alternate_correlations`` row, did the alternate edge
-- preserve terminal-tail byte progression (byte_index N -> N+k for
-- some k >= 1)?  Computed by bounded BFS (depth <= 2) from the
-- alternate's target state through ``dag_edges`` looking for a state
-- whose owned blocks contain a ``terminal_tail``
-- ``TerminalByteEmitterFact`` destination with a byte_index strictly
-- greater than the source's byte_index.  Observability-only.
CREATE TABLE IF NOT EXISTS dag_edge_alternate_selections (
    snapshot_id            INTEGER NOT NULL REFERENCES snapshots(id),
    collapsed_edge_id      INTEGER NOT NULL,
    alternate_edge_id      INTEGER NOT NULL,
    selected               INTEGER NOT NULL,  -- 0 / 1
    source_byte_index      INTEGER,
    reached_byte_index     INTEGER,
    reached_state_hex      TEXT,
    reason                 TEXT NOT NULL,
    evidence_json          TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (snapshot_id, collapsed_edge_id, alternate_edge_id)
);
CREATE INDEX IF NOT EXISTS idx_dag_edge_alt_sel_selected
    ON dag_edge_alternate_selections(snapshot_id, selected);

-- Reconstruction modifications (one per emitted mod)
CREATE TABLE IF NOT EXISTS modifications (
    snapshot_id         INTEGER NOT NULL REFERENCES snapshots(id),
    mod_index           INTEGER NOT NULL,
    mod_type            TEXT NOT NULL,
    source_block        INTEGER,
    target_block        INTEGER,
    old_target          INTEGER,
    write_site_ea_hex   TEXT,
    write_site_ea_i64   INTEGER,
    write_site_blk      INTEGER,
    status              TEXT NOT NULL,
    reason              TEXT,
    PRIMARY KEY (snapshot_id, mod_index)
);

-- Block classification (reachability, BST membership, gut status)
CREATE TABLE IF NOT EXISTS block_classification (
    snapshot_id   INTEGER NOT NULL REFERENCES snapshots(id),
    serial        INTEGER NOT NULL,
    is_bst        INTEGER NOT NULL DEFAULT 0,
    is_reachable  INTEGER NOT NULL DEFAULT 1,
    is_gutted     INTEGER NOT NULL DEFAULT 0,
    in_claimed    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (snapshot_id, serial)
);

-- Layer 3: Rendered linearized program IR

CREATE TABLE IF NOT EXISTS rendered_programs (
    snapshot_id          INTEGER NOT NULL REFERENCES snapshots(id),
    variant_name         TEXT NOT NULL,
    order_strategy       TEXT NOT NULL,
    program_strategy     TEXT NOT NULL,
    label_render_mode    TEXT NOT NULL,
    boundary_inline_mode TEXT NOT NULL,
    comment_mode         TEXT NOT NULL,
    line_count           INTEGER NOT NULL,
    node_count           INTEGER NOT NULL,
    PRIMARY KEY (snapshot_id, variant_name)
);

CREATE TABLE IF NOT EXISTS rendered_program_nodes (
    snapshot_id     INTEGER NOT NULL,
    variant_name    TEXT NOT NULL,
    node_index      INTEGER NOT NULL,
    label_text      TEXT NOT NULL,
    node_kind       TEXT NOT NULL,
    state_label     TEXT,
    handler_serial  INTEGER,
    entry_anchor    INTEGER,
    label_num       INTEGER,
    line_start      INTEGER NOT NULL,
    line_end        INTEGER NOT NULL,
    PRIMARY KEY (snapshot_id, variant_name, node_index),
    FOREIGN KEY (snapshot_id, variant_name)
        REFERENCES rendered_programs(snapshot_id, variant_name)
);

CREATE TABLE IF NOT EXISTS rendered_program_lines (
    snapshot_id     INTEGER NOT NULL,
    variant_name    TEXT NOT NULL,
    line_no         INTEGER NOT NULL,
    node_index      INTEGER,
    indent_level    INTEGER NOT NULL,
    line_kind       TEXT NOT NULL,
    target_label    TEXT,
    text            TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, variant_name, line_no),
    FOREIGN KEY (snapshot_id, variant_name)
        REFERENCES rendered_programs(snapshot_id, variant_name)
);

CREATE INDEX IF NOT EXISTS idx_rendered_program_lines_variant
    ON rendered_program_lines(snapshot_id, variant_name, node_index, line_no);

-- Per-mod watch-block transitions captured by DeferredGraphModifier.apply
-- when D810_DEFERRED_WATCH_BLOCKS is set. One row per observed transition
-- of a watched block's (type_name, succs, preds) triple during apply. Lets
-- diagnostic tooling answer "which mod mutated blk[X]?" with a single SQL
-- query instead of greping the text log.
CREATE TABLE IF NOT EXISTS watch_block_transitions (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    func_ea_hex         TEXT NOT NULL,
    func_ea_i64         INTEGER NOT NULL,
    apply_session_id    TEXT NOT NULL,
    mod_index           INTEGER,
    mod_type            TEXT NOT NULL,
    phase               TEXT NOT NULL,
    block_serial        INTEGER NOT NULL,
    prev_type_name      TEXT,
    prev_succs          TEXT,
    prev_preds          TEXT,
    now_type_name       TEXT,
    now_succs           TEXT,
    now_preds           TEXT,
    timestamp           REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_watch_block_transitions_session
    ON watch_block_transitions(apply_session_id, mod_index);
CREATE INDEX IF NOT EXISTS idx_watch_block_transitions_block
    ON watch_block_transitions(block_serial, apply_session_id);

-- CFG mutation provenance.  One row per CFG-mutating site call (block delete,
-- soft-kill, edge sever/redirect, block create, etc.).  Persisted under the
-- snapshot_id of the snapshot taken AFTER the mutation, so SQL queries can
-- correlate "block X gone in snapshot Y" with "pass P removed it".
CREATE TABLE IF NOT EXISTS cfg_provenance (
    snapshot_id     INTEGER NOT NULL REFERENCES snapshots(id),
    seq             INTEGER NOT NULL,
    pass_name       TEXT NOT NULL,
    action          TEXT NOT NULL,
    block_serial    INTEGER NOT NULL,
    target_serial   INTEGER,
    reason          TEXT,
    extra_json      TEXT,
    PRIMARY KEY (snapshot_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_provenance_block
    ON cfg_provenance(snapshot_id, block_serial);
CREATE INDEX IF NOT EXISTS idx_provenance_action
    ON cfg_provenance(snapshot_id, action);
CREATE INDEX IF NOT EXISTS idx_provenance_pass
    ON cfg_provenance(snapshot_id, pass_name);

-- Created-block lineage.  Observation rows say "what is blk[N] in this
-- snapshot"; lineage rows say "where did this created block come from".
CREATE TABLE IF NOT EXISTS block_lineage (
    snapshot_id                 INTEGER NOT NULL REFERENCES snapshots(id),
    serial                      INTEGER NOT NULL,
    origin_snapshot_id          INTEGER,
    origin_serial               INTEGER,
    origin_start_ea_hex         TEXT,
    origin_body_fingerprint     TEXT,
    creation_kind               TEXT NOT NULL,
    creation_reason             TEXT,
    planner_block_id            TEXT,
    source_mod_type             TEXT,
    extra_json                  TEXT,
    PRIMARY KEY (snapshot_id, serial)
);
CREATE INDEX IF NOT EXISTS idx_block_lineage_origin
    ON block_lineage(origin_snapshot_id, origin_serial);
CREATE INDEX IF NOT EXISTS idx_block_lineage_origin_ea
    ON block_lineage(origin_start_ea_hex);

-- Layer 4: Maturity fact lifecycle

CREATE TABLE IF NOT EXISTS fact_observations (
    snapshot_id         INTEGER NOT NULL REFERENCES snapshots(id),
    func_ea_hex         TEXT NOT NULL,
    func_ea_i64         INTEGER NOT NULL,
    fact_id             TEXT NOT NULL,
    kind                TEXT NOT NULL,
    semantic_key        TEXT NOT NULL,
    maturity            TEXT NOT NULL,
    phase               TEXT NOT NULL,
    confidence          REAL NOT NULL,
    source_block        INTEGER,
    source_ea_hex       TEXT,
    source_ea_i64       INTEGER,
    block_fingerprint   TEXT,
    mop_signature       TEXT,
    payload             TEXT NOT NULL,
    evidence            TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, fact_id)
);

CREATE INDEX IF NOT EXISTS idx_fact_observations_key
    ON fact_observations(func_ea_hex, semantic_key, maturity);
CREATE INDEX IF NOT EXISTS idx_fact_observations_kind
    ON fact_observations(snapshot_id, kind);
CREATE INDEX IF NOT EXISTS idx_fact_observations_fact_id
    ON fact_observations(fact_id);

CREATE TABLE IF NOT EXISTS fact_mappings (
    snapshot_id             INTEGER NOT NULL REFERENCES snapshots(id),
    func_ea_hex             TEXT NOT NULL,
    func_ea_i64             INTEGER NOT NULL,
    mapping_index           INTEGER NOT NULL,
    source_fact_id          TEXT NOT NULL,
    target_fact_id          TEXT,
    source_maturity         TEXT NOT NULL,
    target_maturity         TEXT NOT NULL,
    status                  TEXT NOT NULL,
    confidence              REAL NOT NULL,
    target_block            INTEGER,
    target_ea_hex           TEXT,
    target_ea_i64           INTEGER,
    target_mop_signature    TEXT,
    reason                  TEXT,
    payload                 TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, mapping_index)
);

CREATE INDEX IF NOT EXISTS idx_fact_mappings_source
    ON fact_mappings(source_fact_id, source_maturity, target_maturity);
CREATE INDEX IF NOT EXISTS idx_fact_mappings_status
    ON fact_mappings(snapshot_id, status);

CREATE TABLE IF NOT EXISTS fact_consumers (
    snapshot_id     INTEGER NOT NULL REFERENCES snapshots(id),
    func_ea_hex     TEXT NOT NULL,
    func_ea_i64     INTEGER NOT NULL,
    consumer_index  INTEGER NOT NULL,
    consumer        TEXT NOT NULL,
    strategy        TEXT NOT NULL,
    fact_id         TEXT NOT NULL,
    maturity        TEXT NOT NULL,
    decision        TEXT NOT NULL,
    reason          TEXT,
    payload         TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, consumer_index)
);

CREATE INDEX IF NOT EXISTS idx_fact_consumers_fact
    ON fact_consumers(fact_id, maturity);
CREATE INDEX IF NOT EXISTS idx_fact_consumers_consumer
    ON fact_consumers(snapshot_id, consumer, strategy);

CREATE TABLE IF NOT EXISTS fact_conflicts (
    snapshot_id     INTEGER NOT NULL REFERENCES snapshots(id),
    func_ea_hex     TEXT NOT NULL,
    func_ea_i64     INTEGER NOT NULL,
    conflict_id     TEXT NOT NULL,
    fact_id         TEXT NOT NULL,
    other_fact_id   TEXT NOT NULL,
    maturity        TEXT NOT NULL,
    conflict_kind   TEXT NOT NULL,
    reason          TEXT NOT NULL,
    payload         TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, conflict_id)
);

CREATE INDEX IF NOT EXISTS idx_fact_conflicts_fact
    ON fact_conflicts(fact_id, other_fact_id, maturity);

-- Region-shape features captured for REF and D810 snapshots.
-- Diagnostic-only; no behavior consumers. snapshot_id is NULL for REF rows.
CREATE TABLE IF NOT EXISTS region_shape_features (
    func_ea_hex   TEXT NOT NULL,
    func_ea_i64   INTEGER NOT NULL,
    snapshot_id   INTEGER,
    source        TEXT NOT NULL,
    region        TEXT NOT NULL,
    feature       TEXT NOT NULL,
    value_text    TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    PRIMARY KEY (func_ea_hex, source, snapshot_id, feature)
);

CREATE INDEX IF NOT EXISTS idx_region_shape_features_source
    ON region_shape_features(source, region);

-- Per-byte DCE cause classification for snap17 -> snap18 transitions.
CREATE TABLE IF NOT EXISTS terminal_tail_dce_causes (
    func_ea_hex                   TEXT NOT NULL,
    func_ea_i64                   INTEGER NOT NULL,
    byte_index                    INTEGER NOT NULL,
    last_present_snapshot_id      INTEGER,
    first_missing_snapshot_id     INTEGER,
    last_block_serial             INTEGER,
    last_ea_hex                   TEXT,
    cause                         TEXT NOT NULL,
    recommended_action            TEXT NOT NULL,
    rationale                     TEXT NOT NULL,
    evidence_json                 TEXT NOT NULL,
    PRIMARY KEY (func_ea_hex, byte_index)
);

CREATE INDEX IF NOT EXISTS idx_terminal_tail_dce_causes_cause
    ON terminal_tail_dce_causes(cause);
"""


def create_tables(conn: sqlite3.Connection) -> None:
    """Create all diagnostic snapshot tables, views, and indexes.

    Uses IF NOT EXISTS so this is safe to call multiple times (idempotent).
    """
    conn.executescript(_SCHEMA_SQL)

"""peewee Models = schema source of truth for the diag DB.

All non-view diag tables are modeled here (schema source of truth); only the
SQL **views** (``var_writes`` + the ``dag_*`` back-compat views) remain as raw
DDL in ``schema._SCHEMA_SQL``. peewee owns the diag connection (see
``core/diag/__init__``); query call-sites stay raw SQL on ``db.connection()``.

Modeling rules (must hold for every Model so positional INSERTs and the
``dag_*`` / legacy exit-path views keep working):

* Fields declared in **exact DDL column order**.
* ``CompositeKey(...)`` suppresses peewee's implicit ``id`` auto-PK for tables
  whose original DDL used a composite ``PRIMARY KEY (...)``; the CompositeKey
  argument order reproduces the DDL ``PRIMARY KEY`` column order (which can
  differ from the column-declaration order, e.g. ``state_cfg_node_blocks``).
* ``snapshot_id`` FKs use ``index=False`` (the hand-DDL has no FK index).
* ``Check("...")`` reproduces CHECK constraints; ``Meta.indexes`` reproduces
  every ``CREATE INDEX`` in the original DDL.

The equivalence with the original DDL is pinned by
``tests/unit/core/diag/test_models_schema_equivalence.py``.
"""
from __future__ import annotations

from d810._vendor.peewee import (
    AutoField,
    Check,
    CompositeKey,
    FloatField,
    ForeignKeyField,
    IntegerField,
    Model,
    SqliteDatabase,
    TextField,
)

# Deferred database: bound to the live diag connection at session-open time
# (core/diag/__init__ calls ``diag_db.init(path)`` / binds it). A deferred
# SqliteDatabase still carries the SQLite SQL dialect for DDL generation.
diag_db = SqliteDatabase(None)


class BaseModel(Model):
    class Meta:
        database = diag_db


def _snapshot_fk() -> ForeignKeyField:
    """``snapshot_id INTEGER NOT NULL REFERENCES snapshots(id)`` with no FK index."""
    return ForeignKeyField(
        Snapshot, field="id", column_name="snapshot_id", index=False, null=False
    )


# --------------------------------------------------------------------------- #
# Layer 1: Universal MBA State
# --------------------------------------------------------------------------- #


class Snapshot(BaseModel):
    # ``id INTEGER PRIMARY KEY`` -> peewee's implicit AutoField ``id`` (first column).
    label = TextField()
    func_ea_hex = TextField()
    func_ea_i64 = IntegerField()
    maturity = TextField()
    phase = TextField(
        default="unknown",
        constraints=[
            Check(
                "phase IN ('pre_d810','post_apply','post_gut_wire',"
                "'post_pipeline','post_d810','unknown')"
            )
        ],
    )
    block_count = IntegerField()
    timestamp = FloatField()

    class Meta:
        table_name = "snapshots"


class Block(BaseModel):
    snapshot = _snapshot_fk()
    serial = IntegerField()
    block_type = IntegerField()
    type_name = TextField()
    start_ea_hex = TextField(null=True)
    start_ea_i64 = IntegerField(null=True)
    end_ea_hex = TextField(null=True)
    end_ea_i64 = IntegerField(null=True)
    nsucc = IntegerField()
    npred = IntegerField()
    succs = TextField()
    preds = TextField()
    insn_count = IntegerField()
    meta = TextField(null=True)

    class Meta:
        table_name = "blocks"
        primary_key = CompositeKey("snapshot", "serial")


class BlockObservation(BaseModel):
    snapshot = _snapshot_fk()
    serial = IntegerField()
    maturity = TextField()
    phase = TextField()
    start_ea_hex = TextField(null=True)
    start_ea_i64 = IntegerField(null=True)
    insn_count = IntegerField()
    insn_ea_fingerprint = TextField()
    opcode_fingerprint = TextField()
    operand_fingerprint = TextField()
    body_fingerprint = TextField()

    class Meta:
        table_name = "block_observations"
        primary_key = CompositeKey("snapshot", "serial")
        indexes = (
            (("start_ea_hex",), False),
            (("body_fingerprint",), False),
        )


class Instruction(BaseModel):
    snapshot = _snapshot_fk()
    block_serial = IntegerField()
    insn_index = IntegerField()
    ea_hex = TextField()
    ea_i64 = IntegerField()
    opcode = IntegerField()
    opcode_name = TextField()
    dest_type = TextField(null=True)
    dest_stkoff = IntegerField(null=True)
    dest_size = IntegerField(null=True)
    src_l_type = TextField(null=True)
    src_l_stkoff = IntegerField(null=True)
    src_l_value_hex = TextField(null=True)
    src_l_value_i64 = IntegerField(null=True)
    src_r_type = TextField(null=True)
    src_r_stkoff = IntegerField(null=True)
    src_r_value_hex = TextField(null=True)
    src_r_value_i64 = IntegerField(null=True)
    dstr = TextField(null=True)
    meta = TextField(null=True)

    class Meta:
        table_name = "instructions"
        primary_key = CompositeKey("snapshot", "block_serial", "insn_index")
        indexes = (
            (("snapshot", "dest_stkoff"), False),
            (("snapshot", "opcode_name"), False),
            (("snapshot", "ea_hex"), False),
        )


# --------------------------------------------------------------------------- #
# Layer 2: Strategy Metadata
# (``state_cfg_nodes`` / ``state_cfg_edges`` are below)
# --------------------------------------------------------------------------- #


class StateCfgNode(BaseModel):
    snapshot = _snapshot_fk()
    state_hex = TextField()
    state_i64 = IntegerField()
    entry_block = IntegerField()
    classification = TextField()
    shared_suffix = TextField(null=True)

    class Meta:
        table_name = "state_cfg_nodes"
        primary_key = CompositeKey("snapshot", "state_hex")


class StateCfgEdge(BaseModel):
    snapshot = _snapshot_fk()
    edge_id = IntegerField()
    source_state_hex = TextField(null=True)
    source_state_i64 = IntegerField(null=True)
    target_state_hex = TextField(null=True)
    target_state_i64 = IntegerField(null=True)
    edge_kind = TextField(
        constraints=[
            Check(
                "edge_kind IN ('TRANSITION','CONDITIONAL_TRANSITION',"
                "'CONDITIONAL_RETURN','EXIT_ROUTINE','UNKNOWN')"
            )
        ]
    )
    source_block = IntegerField(null=True)
    source_arm = IntegerField(null=True)
    target_entry = IntegerField(null=True)
    ordered_path = TextField()

    class Meta:
        table_name = "state_cfg_edges"
        primary_key = CompositeKey("snapshot", "edge_id")


class StateCfgNodeBlock(BaseModel):
    # DDL column order: snapshot_id, state_hex, entry_block, block_serial,
    # block_index, role.  PK column order differs:
    # (snapshot_id, state_hex, entry_block, role, block_index).
    snapshot = _snapshot_fk()
    state_hex = TextField()
    entry_block = IntegerField()
    block_serial = IntegerField()
    block_index = IntegerField()
    role = TextField(
        constraints=[Check("role IN ('owned','exclusive','shared_suffix')")]
    )

    class Meta:
        table_name = "state_cfg_node_blocks"
        primary_key = CompositeKey(
            "snapshot", "state_hex", "entry_block", "role", "block_index"
        )
        indexes = ((("snapshot", "state_hex", "entry_block"), False),)


class StateCfgLocalSegment(BaseModel):
    snapshot = _snapshot_fk()
    state_hex = TextField()
    entry_block = IntegerField()
    segment_index = IntegerField()
    segment_id = TextField()
    kind = TextField()
    blocks_json = TextField()

    class Meta:
        table_name = "state_cfg_local_segments"
        primary_key = CompositeKey(
            "snapshot", "state_hex", "entry_block", "segment_index"
        )
        indexes = ((("snapshot", "state_hex", "entry_block"), False),)


class StateCfgLocalEdge(BaseModel):
    snapshot = _snapshot_fk()
    state_hex = TextField()
    entry_block = IntegerField()
    edge_index = IntegerField()
    source_segment_id = TextField()
    target_segment_id = TextField()
    kind = TextField()
    branch_arm = IntegerField(null=True)

    class Meta:
        table_name = "state_cfg_local_edges"
        primary_key = CompositeKey(
            "snapshot", "state_hex", "entry_block", "edge_index"
        )
        # Original DDL declares an index over the full PK column set.
        indexes = ((("snapshot", "state_hex", "entry_block", "edge_index"), False),)


class StateCfgEdgeDiagnostic(BaseModel):
    snapshot = _snapshot_fk()
    edge_id = IntegerField()
    classification = TextField(
        constraints=[
            Check(
                "classification IN ('BENIGN','LOCOPT_REWRITTEN_SOURCE',"
                "'TARGET_UNRESOLVED_AFTER_REWRITE',"
                "'COLLAPSED_TO_REWRITTEN_TARGET','SPURIOUS_CONDITIONAL_ARM')"
            )
        ]
    )
    source_state_hex = TextField(null=True)
    target_state_hex = TextField(null=True)
    edge_kind = TextField()
    is_terminal_tail = IntegerField(default=0)
    original_state_const = TextField(null=True)
    rewritten_state_const = TextField(null=True)
    related_fact_ids = TextField(default="[]")
    reason = TextField()

    class Meta:
        table_name = "state_cfg_edge_diagnostics"
        primary_key = CompositeKey("snapshot", "edge_id")
        indexes = (
            (("snapshot", "classification"), False),
            (("is_terminal_tail", "classification"), False),
        )


class StateCfgFrontierClosureDiagnostic(BaseModel):
    # DDL column order: snapshot_id, kind, reason, source_block,
    # observed_target, branch_arm, from_dag_scc, to_dag_scc,
    # candidate_targets_json, path_json, cfg_scc_size, payload_json.
    # PK column order differs:
    # (snapshot_id, kind, source_block, observed_target, branch_arm, reason).
    snapshot = _snapshot_fk()
    kind = TextField()
    reason = TextField(null=True)
    source_block = IntegerField(null=True)
    observed_target = IntegerField(null=True)
    branch_arm = IntegerField(null=True)
    from_dag_scc = IntegerField(null=True)
    to_dag_scc = IntegerField(null=True)
    candidate_targets_json = TextField(default="[]")
    path_json = TextField(default="[]")
    cfg_scc_size = IntegerField(null=True)
    payload_json = TextField(default="{}")

    class Meta:
        table_name = "state_cfg_frontier_closure_diagnostics"
        primary_key = CompositeKey(
            "snapshot",
            "kind",
            "source_block",
            "observed_target",
            "branch_arm",
            "reason",
        )
        indexes = ((("snapshot", "kind", "reason"), False),)


class ConditionChainIntervalDispatcherRow(BaseModel):
    snapshot = _snapshot_fk()
    row_index = IntegerField()
    lo_hex = TextField()
    lo_i64 = IntegerField()
    hi_hex = TextField()
    hi_i64 = IntegerField()
    target_block = IntegerField()
    dispatcher_entry_block = IntegerField(null=True)
    maturity = TextField(null=True)
    payload_json = TextField(default="{}")

    class Meta:
        table_name = "condition_chain_interval_dispatcher_rows"
        primary_key = CompositeKey("snapshot", "row_index")
        indexes = ((("snapshot", "target_block"), False),)


class StateDispatcherRow(BaseModel):
    snapshot = _snapshot_fk()
    row_index = IntegerField()
    state_const_hex = TextField()
    state_const_i64 = IntegerField()
    target_block = IntegerField()
    dispatcher_entry_block = IntegerField(null=True)
    compare_block = IntegerField(null=True)
    dispatcher_kind = TextField()
    branch_kind = TextField(null=True)
    maturity = TextField(null=True)
    confidence = FloatField(default=1.0)
    payload_json = TextField(default="{}")

    class Meta:
        table_name = "state_dispatcher_rows"
        primary_key = CompositeKey("snapshot", "row_index")
        indexes = (
            (("snapshot", "state_const_i64"), False),
            (("snapshot", "target_block"), False),
            (("snapshot", "dispatcher_kind"), False),
        )


class StateTransitionConditionChainResolution(BaseModel):
    snapshot = _snapshot_fk()
    fact_id = TextField()
    source_block_serial = IntegerField()
    source_state_const_hex = TextField()
    condition_chain_resolved_next_block_serial = IntegerField(null=True)
    condition_chain_resolved_next_state_const_hex = TextField(null=True)
    condition_chain_resolved_next_state_const_u64 = IntegerField(null=True)
    condition_chain_resolution_reason = TextField()
    condition_chain_resolution_maturity = TextField()

    class Meta:
        table_name = "state_transition_condition_chain_resolutions"
        primary_key = CompositeKey("snapshot", "fact_id")
        indexes = (
            (("source_block_serial",), False),
            (("condition_chain_resolved_next_state_const_hex",), False),
        )


class StateTransitionDispatchResolution(BaseModel):
    snapshot = _snapshot_fk()
    fact_id = TextField()
    source_block_serial = IntegerField()
    source_state_const_hex = TextField()
    resolved_next_block_serial = IntegerField(null=True)
    resolved_next_state_const_hex = TextField(null=True)
    resolved_next_state_const_u64 = IntegerField(null=True)
    resolution_kind = TextField()
    resolution_reason = TextField()
    resolution_maturity = TextField()

    class Meta:
        table_name = "state_transition_dispatch_resolutions"
        primary_key = CompositeKey("snapshot", "fact_id", "resolution_kind")
        indexes = (
            (("source_block_serial",), False),
            (("resolved_next_state_const_hex",), False),
        )


class SwitchCaseTransitionFact(BaseModel):
    snapshot = _snapshot_fk()
    row_index = IntegerField()
    fact_id = TextField()
    source_state_hex = TextField(null=True)
    source_state_i64 = IntegerField(null=True)
    case_entry_block = IntegerField(null=True)
    transition_kind = TextField()
    next_state_a_hex = TextField(null=True)
    next_state_a_i64 = IntegerField(null=True)
    next_state_b_hex = TextField(null=True)
    next_state_b_i64 = IntegerField(null=True)
    return_value = IntegerField(null=True)
    proof_kind = TextField(null=True)
    trusted = IntegerField(default=0)
    reason = TextField()
    profile_name = TextField(null=True)
    dispatcher_entry = IntegerField(null=True)
    target_block = IntegerField(null=True)
    payload_json = TextField(default="{}")

    class Meta:
        table_name = "switch_case_transition_facts"
        primary_key = CompositeKey("snapshot", "row_index")
        indexes = (
            (("snapshot", "source_state_i64"), False),
            (("snapshot", "transition_kind", "trusted"), False),
        )


class BranchOwnershipProof(BaseModel):
    snapshot = _snapshot_fk()
    row_index = IntegerField()
    proof_id = TextField()
    proof_kind = TextField()
    trusted = IntegerField(default=0)
    reason = TextField()
    source_block = IntegerField(null=True)
    branch_arm = IntegerField(null=True)
    source_state_hex = TextField(null=True)
    source_state_i64 = IntegerField(null=True)
    target_state_hex = TextField(null=True)
    target_state_i64 = IntegerField(null=True)
    target_entry = IntegerField(null=True)
    predicate_block = IntegerField(null=True)
    dispatcher_entry_block = IntegerField(null=True)
    oracle_kind = TextField()
    evidence_json = TextField(default="{}")
    payload_json = TextField(default="{}")

    class Meta:
        table_name = "branch_ownership_proofs"
        primary_key = CompositeKey("snapshot", "row_index")
        indexes = (
            (("snapshot", "proof_kind", "trusted"), False),
            (("snapshot", "source_block", "branch_arm"), False),
        )


class BranchWitnessDecision(BaseModel):
    snapshot = _snapshot_fk()
    row_index = IntegerField()
    state_hex = TextField(null=True)
    state_i64 = IntegerField(null=True)
    dispatcher_entry_block = IntegerField(null=True)
    compare_block = IntegerField(null=True)
    predicate = TextField(null=True)
    compare_const_hex = TextField(null=True)
    compare_const_i64 = IntegerField(null=True)
    selected_successor = IntegerField(null=True)
    rejected_successors_json = TextField(default="[]")
    target_block = IntegerField(null=True)
    proof_kind = TextField(null=True)
    outcome = TextField()
    reason = TextField(null=True)
    evidence = TextField(null=True)
    payload_json = TextField(default="{}")

    class Meta:
        table_name = "branch_witness_decisions"
        primary_key = CompositeKey("snapshot", "row_index")
        indexes = (
            (("snapshot", "state_i64"), False),
            (("snapshot", "outcome"), False),
            (("snapshot", "compare_block"), False),
        )


class ExitPathShortcutDecision(BaseModel):
    snapshot = _snapshot_fk()
    row_index = IntegerField()
    source_block = IntegerField(null=True)
    old_target = IntegerField(null=True)
    shortcut_target = IntegerField(null=True)
    witness_compare_blocks_json = TextField(default="[]")
    exit_path_blocks_json = TextField(default="[]")
    rejected_successors_json = TextField(default="[]")
    outcome = TextField()
    reason = TextField(null=True)
    live_definitions_json = TextField(default="[]")
    payload_json = TextField(default="{}")

    class Meta:
        table_name = "exit_path_shortcut_decisions"
        primary_key = CompositeKey("snapshot", "row_index")
        indexes = (
            (("snapshot", "source_block"), False),
            (("snapshot", "shortcut_target"), False),
            (("snapshot", "outcome"), False),
        )


class StateCfgEdgeAlternateCorrelation(BaseModel):
    snapshot = _snapshot_fk()
    collapsed_edge_id = IntegerField()
    alternate_edge_id = IntegerField()
    collapsed_source_state = TextField(null=True)
    collapsed_target_state = TextField(null=True)
    alternate_source_state = TextField(null=True)
    alternate_target_state = TextField(null=True)
    alternate_ordered_path = TextField()
    overlap_blocks = TextField()
    alternate_classification = TextField(null=True)
    reason = TextField()

    class Meta:
        table_name = "state_cfg_edge_alternate_correlations"
        primary_key = CompositeKey(
            "snapshot", "collapsed_edge_id", "alternate_edge_id"
        )
        indexes = ((("snapshot", "collapsed_edge_id"), False),)


class StateCfgEdgeAlternateSelection(BaseModel):
    snapshot = _snapshot_fk()
    collapsed_edge_id = IntegerField()
    alternate_edge_id = IntegerField()
    selected = IntegerField()
    source_byte_index = IntegerField(null=True)
    reached_byte_index = IntegerField(null=True)
    reached_state_hex = TextField(null=True)
    reason = TextField()
    evidence_json = TextField(default="{}")

    class Meta:
        table_name = "state_cfg_edge_alternate_selections"
        primary_key = CompositeKey(
            "snapshot", "collapsed_edge_id", "alternate_edge_id"
        )
        indexes = ((("snapshot", "selected"), False),)


class Modification(BaseModel):
    snapshot = _snapshot_fk()
    mod_index = IntegerField()
    mod_type = TextField()
    source_block = IntegerField(null=True)
    source_block_label = TextField(null=True)
    source_block_ea_hex = TextField(null=True)
    source_block_ea_i64 = IntegerField(null=True)
    target_block = IntegerField(null=True)
    target_block_label = TextField(null=True)
    target_block_ea_hex = TextField(null=True)
    target_block_ea_i64 = IntegerField(null=True)
    old_target = IntegerField(null=True)
    old_target_label = TextField(null=True)
    old_target_ea_hex = TextField(null=True)
    old_target_ea_i64 = IntegerField(null=True)
    write_site_ea_hex = TextField(null=True)
    write_site_ea_i64 = IntegerField(null=True)
    write_site_blk = IntegerField(null=True)
    status = TextField()
    reason = TextField(null=True)

    class Meta:
        table_name = "modifications"
        primary_key = CompositeKey("snapshot", "mod_index")


class BlockClassification(BaseModel):
    snapshot = _snapshot_fk()
    serial = IntegerField()
    is_condition_chain = IntegerField(default=0)
    is_reachable = IntegerField(default=1)
    is_gutted = IntegerField(default=0)
    in_claimed = IntegerField(default=0)

    class Meta:
        table_name = "block_classification"
        primary_key = CompositeKey("snapshot", "serial")


# --------------------------------------------------------------------------- #
# Layer 3: Rendered linearized program IR
# --------------------------------------------------------------------------- #


class RenderedProgram(BaseModel):
    snapshot = _snapshot_fk()
    variant_name = TextField()
    order_strategy = TextField()
    program_strategy = TextField()
    label_render_mode = TextField()
    boundary_inline_mode = TextField()
    comment_mode = TextField()
    line_count = IntegerField()
    node_count = IntegerField()

    class Meta:
        table_name = "rendered_programs"
        primary_key = CompositeKey("snapshot", "variant_name")


class RenderedProgramNode(BaseModel):
    # ``snapshot_id`` here is a plain INTEGER NOT NULL (no standalone FK to
    # snapshots); the composite FK targets rendered_programs.  Modeled as a
    # plain IntegerField to match the DDL (no FK index, no snapshots ref).
    snapshot_id = IntegerField()
    variant_name = TextField()
    node_index = IntegerField()
    label_text = TextField()
    node_kind = TextField()
    state_label = TextField(null=True)
    handler_serial = IntegerField(null=True)
    entry_anchor = IntegerField(null=True)
    label_num = IntegerField(null=True)
    line_start = IntegerField()
    line_end = IntegerField()

    class Meta:
        table_name = "rendered_program_nodes"
        primary_key = CompositeKey("snapshot_id", "variant_name", "node_index")


class RenderedProgramLine(BaseModel):
    snapshot_id = IntegerField()
    variant_name = TextField()
    line_no = IntegerField()
    node_index = IntegerField(null=True)
    indent_level = IntegerField()
    line_kind = TextField()
    target_label = TextField(null=True)
    text = TextField()

    class Meta:
        table_name = "rendered_program_lines"
        primary_key = CompositeKey("snapshot_id", "variant_name", "line_no")
        indexes = (
            (("snapshot_id", "variant_name", "node_index", "line_no"), False),
        )


class WatchBlockTransition(BaseModel):
    # ``id INTEGER PRIMARY KEY AUTOINCREMENT`` -> peewee AutoField ``id``.
    # peewee emits ``INTEGER NOT NULL PRIMARY KEY`` (notnull=1) vs the legacy
    # ``INTEGER PRIMARY KEY AUTOINCREMENT`` (notnull=0); harmless for an
    # INTEGER PK (the equivalence test allows the PK notnull diff).
    id = AutoField()
    func_ea_hex = TextField()
    func_ea_i64 = IntegerField()
    apply_session_id = TextField()
    mod_index = IntegerField(null=True)
    mod_type = TextField()
    phase = TextField()
    block_serial = IntegerField()
    prev_type_name = TextField(null=True)
    prev_succs = TextField(null=True)
    prev_preds = TextField(null=True)
    now_type_name = TextField(null=True)
    now_succs = TextField(null=True)
    now_preds = TextField(null=True)
    timestamp = FloatField()

    class Meta:
        table_name = "watch_block_transitions"
        indexes = (
            (("apply_session_id", "mod_index"), False),
            (("block_serial", "apply_session_id"), False),
        )


class CfgProvenance(BaseModel):
    snapshot = _snapshot_fk()
    seq = IntegerField()
    pass_name = TextField()
    action = TextField()
    block_serial = IntegerField()
    block_label = TextField(null=True)
    block_ea_hex = TextField(null=True)
    block_ea_i64 = IntegerField(null=True)
    target_serial = IntegerField(null=True)
    target_label = TextField(null=True)
    target_ea_hex = TextField(null=True)
    target_ea_i64 = IntegerField(null=True)
    reason = TextField(null=True)
    extra_json = TextField(null=True)

    class Meta:
        table_name = "cfg_provenance"
        primary_key = CompositeKey("snapshot", "seq")
        indexes = (
            (("snapshot", "block_serial"), False),
            (("snapshot", "action"), False),
            (("snapshot", "pass_name"), False),
        )


class BlockLineage(BaseModel):
    snapshot = _snapshot_fk()
    serial = IntegerField()
    origin_snapshot_id = IntegerField(null=True)
    origin_serial = IntegerField(null=True)
    origin_start_ea_hex = TextField(null=True)
    origin_body_fingerprint = TextField(null=True)
    creation_kind = TextField()
    creation_reason = TextField(null=True)
    planner_block_id = TextField(null=True)
    source_mod_type = TextField(null=True)
    extra_json = TextField(null=True)

    class Meta:
        table_name = "block_lineage"
        primary_key = CompositeKey("snapshot", "serial")
        indexes = (
            (("origin_snapshot_id", "origin_serial"), False),
            (("origin_start_ea_hex",), False),
        )


# --------------------------------------------------------------------------- #
# Layer 4: Maturity fact lifecycle
# --------------------------------------------------------------------------- #


class FactObservation(BaseModel):
    snapshot = _snapshot_fk()
    func_ea_hex = TextField()
    func_ea_i64 = IntegerField()
    fact_id = TextField()
    kind = TextField()
    semantic_key = TextField()
    maturity = TextField()
    phase = TextField()
    confidence = FloatField()
    source_block = IntegerField(null=True)
    source_ea_hex = TextField(null=True)
    source_ea_i64 = IntegerField(null=True)
    block_fingerprint = TextField(null=True)
    mop_signature = TextField(null=True)
    payload = TextField()
    evidence = TextField()

    class Meta:
        table_name = "fact_observations"
        primary_key = CompositeKey("snapshot", "fact_id")
        indexes = (
            (("func_ea_hex", "semantic_key", "maturity"), False),
            (("snapshot", "kind"), False),
            (("fact_id",), False),
        )


class FactMapping(BaseModel):
    snapshot = _snapshot_fk()
    func_ea_hex = TextField()
    func_ea_i64 = IntegerField()
    mapping_index = IntegerField()
    source_fact_id = TextField()
    target_fact_id = TextField(null=True)
    source_maturity = TextField()
    target_maturity = TextField()
    status = TextField()
    confidence = FloatField()
    target_block = IntegerField(null=True)
    target_ea_hex = TextField(null=True)
    target_ea_i64 = IntegerField(null=True)
    target_mop_signature = TextField(null=True)
    reason = TextField(null=True)
    payload = TextField()

    class Meta:
        table_name = "fact_mappings"
        primary_key = CompositeKey("snapshot", "mapping_index")
        indexes = (
            (("source_fact_id", "source_maturity", "target_maturity"), False),
            (("snapshot", "status"), False),
        )


class FactConsumer(BaseModel):
    snapshot = _snapshot_fk()
    func_ea_hex = TextField()
    func_ea_i64 = IntegerField()
    consumer_index = IntegerField()
    consumer = TextField()
    strategy = TextField()
    fact_id = TextField()
    maturity = TextField()
    decision = TextField()
    reason = TextField(null=True)
    payload = TextField()

    class Meta:
        table_name = "fact_consumers"
        primary_key = CompositeKey("snapshot", "consumer_index")
        indexes = (
            (("fact_id", "maturity"), False),
            (("snapshot", "consumer", "strategy"), False),
        )


class FactConflict(BaseModel):
    snapshot = _snapshot_fk()
    func_ea_hex = TextField()
    func_ea_i64 = IntegerField()
    conflict_id = TextField()
    fact_id = TextField()
    other_fact_id = TextField()
    maturity = TextField()
    conflict_kind = TextField()
    reason = TextField()
    payload = TextField()

    class Meta:
        table_name = "fact_conflicts"
        primary_key = CompositeKey("snapshot", "conflict_id")
        indexes = ((("fact_id", "other_fact_id", "maturity"), False),)


class RegionShapeFeature(BaseModel):
    # DDL column order: func_ea_hex, func_ea_i64, snapshot_id, source, region,
    # feature, value_text, evidence_json.  PK column order differs:
    # (func_ea_hex, source, snapshot_id, feature).  ``snapshot_id`` is a plain
    # nullable INTEGER (NULL for REF rows), NOT a FK to snapshots.
    func_ea_hex = TextField()
    func_ea_i64 = IntegerField()
    snapshot_id = IntegerField(null=True)
    source = TextField()
    region = TextField()
    feature = TextField()
    value_text = TextField()
    evidence_json = TextField()

    class Meta:
        table_name = "region_shape_features"
        primary_key = CompositeKey(
            "func_ea_hex", "source", "snapshot_id", "feature"
        )
        indexes = ((("source", "region"), False),)


class TerminalTailDceCause(BaseModel):
    func_ea_hex = TextField()
    func_ea_i64 = IntegerField()
    byte_index = IntegerField()
    last_present_snapshot_id = IntegerField(null=True)
    first_missing_snapshot_id = IntegerField(null=True)
    last_block_serial = IntegerField(null=True)
    last_ea_hex = TextField(null=True)
    cause = TextField()
    recommended_action = TextField()
    rationale = TextField()
    evidence_json = TextField()

    class Meta:
        table_name = "terminal_tail_dce_causes"
        primary_key = CompositeKey("func_ea_hex", "byte_index")
        indexes = ((("cause",), False),)


# All modeled tables. Order: Snapshot first (FK target); every other table's
# ``snapshot_id`` FK points only at Snapshot, so the remaining order is free.
MODELS = (
    Snapshot,
    # Layer 1
    Block,
    BlockObservation,
    Instruction,
    # Layer 2
    StateCfgNode,
    StateCfgEdge,
    StateCfgNodeBlock,
    StateCfgLocalSegment,
    StateCfgLocalEdge,
    StateCfgEdgeDiagnostic,
    StateCfgFrontierClosureDiagnostic,
    ConditionChainIntervalDispatcherRow,
    StateDispatcherRow,
    StateTransitionConditionChainResolution,
    StateTransitionDispatchResolution,
    SwitchCaseTransitionFact,
    BranchOwnershipProof,
    BranchWitnessDecision,
    ExitPathShortcutDecision,
    StateCfgEdgeAlternateCorrelation,
    StateCfgEdgeAlternateSelection,
    Modification,
    BlockClassification,
    # Layer 3
    RenderedProgram,
    RenderedProgramNode,
    RenderedProgramLine,
    WatchBlockTransition,
    CfgProvenance,
    BlockLineage,
    # Layer 4
    FactObservation,
    FactMapping,
    FactConsumer,
    FactConflict,
    RegionShapeFeature,
    TerminalTailDceCause,
)

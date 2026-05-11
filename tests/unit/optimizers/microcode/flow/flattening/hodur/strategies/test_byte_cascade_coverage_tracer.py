"""Tests for the HCC byte-cascade coverage tracer (read-only diagnostic)."""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from d810.core.typing import Any

from d810.cfg.graph_modification import (
    ConvertToGoto,
    DuplicateBlock,
    EdgeRedirectViaPredSplit,
    InsertBlock,
    RedirectBranch,
    RedirectGoto,
)
from d810.cfg.flowgraph import InsnSnapshot
from d810.optimizers.microcode.flow.flattening.hodur.byte_cascade_coverage_tracer import (
    ByteCascadeCoverageTracer,
    ByteCascadeStage,
    ByteEvidence,
    ByteRecord,
    ENV_GATE,
    ROW_LOG_PREFIX,
    TABLE_LOG_PREFIX,
    _canonical_mod_sig,
    _classify_preservation,
    _seed_records_from_fact_view,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _FakeObs:
    kind: str
    payload: dict[str, Any]
    fact_id: str = "fact"
    confidence: float = 0.8
    source_ea_hex: str | None = None
    source_ea_i64: int | None = None
    source_ea: int | None = None


@dataclass
class _FakeFactView:
    active_observations: tuple[_FakeObs, ...]


@dataclass(frozen=True)
class _FakeStateDagNode:
    entry_anchor: int
    owned_blocks: tuple[int, ...] = ()
    key: str = ""


@dataclass
class _FakeDag:
    nodes: tuple[_FakeStateDagNode, ...]


@dataclass(frozen=True)
class _FakeSourceAnchor:
    block_serial: int | None = None


@dataclass(frozen=True)
class _FakeEdge:
    source_anchor: _FakeSourceAnchor | None = None
    ordered_path: tuple[int, ...] = ()


@dataclass
class _FakeMba:
    entry_ea: int = 0x180012340


@dataclass
class _FakeSnapshot:
    diagnostic_fact_view: _FakeFactView | None = None
    mba: _FakeMba | None = None


class _RecordingLogger:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def info(self, fmt: str, *args: Any) -> None:
        try:
            line = fmt % args if args else fmt
        except TypeError:
            line = fmt + " | " + " ".join(str(a) for a in args)
        self.lines.append(line)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _byte_fact(
    byte_index: int,
    block_serial: int,
    *,
    block_ea: int,
    source_ea: int,
    role: str = "memory_store",
    destination: str = "[ds.2:((%var_190+#{idx}.8)+%var_188.8)]",
) -> _FakeObs:
    payload_source_ea = source_ea
    return _FakeObs(
        kind="TerminalByteEmitterFact",
        payload={
            "byte_index": byte_index,
            "destination_block": block_serial,
            "block_ea": block_ea,
            "source_ea": payload_source_ea,
            "opcode": "m_stx",
            "emitter_role": role,
            "corridor_role": "terminal_tail",
            "destination_buffer_expression": destination.format(idx=byte_index),
            "source_byte_expression": f"xdu([ds.2:%var_190.8+#{byte_index}.8].1)",
            "return_edge": None,
            "continuation_edge": None,
            "successor_blocks": (),
        },
        fact_id=f"fact_byte_{byte_index}",
        confidence=0.82,
        source_ea=source_ea,
    )


def _snapshot(*facts: _FakeObs) -> _FakeSnapshot:
    return _FakeSnapshot(
        diagnostic_fact_view=_FakeFactView(active_observations=tuple(facts)),
        mba=_FakeMba(),
    )


def _enable_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_GATE, "1")


# ---------------------------------------------------------------------------
# Construction / env gate
# ---------------------------------------------------------------------------


def test_returns_none_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_GATE, raising=False)
    snap = _snapshot(_byte_fact(2, 56, block_ea=0x180014C00, source_ea=0x180014C10))
    assert ByteCascadeCoverageTracer.from_snapshot(snap) is None


def test_returns_none_when_no_terminal_byte_facts(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_gate(monkeypatch)
    snap = _snapshot()
    assert ByteCascadeCoverageTracer.from_snapshot(snap) is None


def test_returns_none_when_fact_view_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_gate(monkeypatch)
    snap = _FakeSnapshot(diagnostic_fact_view=None, mba=_FakeMba())
    assert ByteCascadeCoverageTracer.from_snapshot(snap) is None


def test_seeds_one_record_per_byte_index(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_gate(monkeypatch)
    snap = _snapshot(
        _byte_fact(2, 56, block_ea=0x180014C00, source_ea=0x180014C10),
        _byte_fact(3, 163, block_ea=0x180014D00, source_ea=0x180014D10),
        _byte_fact(6, 217, block_ea=0x180014E00, source_ea=0x180014E10),
    )
    tracer = ByteCascadeCoverageTracer.from_snapshot(snap)
    assert tracer is not None
    assert sorted(tracer.records) == [2, 3, 6]
    rec = tracer.records[2]
    assert rec.block_ea_hex == "0x0000000180014C00"
    assert rec.primary_evidence is not None
    assert rec.primary_evidence.source_ea_hex == "0x0000000180014C10"
    assert len(rec.evidence) == 1


def test_seeds_source_ea_from_observation_attribute_when_payload_lacks_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_gate(monkeypatch)
    obs = _byte_fact(2, 56, block_ea=0x180014C00, source_ea=0x180014C10)
    payload_without_source_ea = dict(obs.payload)
    payload_without_source_ea.pop("source_ea")
    snap = _snapshot(
        _FakeObs(
            kind=obs.kind,
            payload=payload_without_source_ea,
            fact_id=obs.fact_id,
            confidence=obs.confidence,
            source_ea=obs.source_ea,
        )
    )

    tracer = ByteCascadeCoverageTracer.from_snapshot(snap)

    assert tracer is not None
    rec = tracer.records[2]
    assert rec.source_ea_hex_set == {"0x0000000180014C10"}
    assert "source_eas=0x0000000180014C10" in rec.render_row_log()


def test_seeds_multiple_evidence_records_for_same_byte(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_gate(monkeypatch)
    # Same byte_index=3, two different m_stx facts (counter store + byte store).
    snap = _snapshot(
        _byte_fact(3, 163, block_ea=0x180014D00, source_ea=0x180014D10,
                   destination="%var_178.8"),  # counter, no var_190
        _byte_fact(3, 163, block_ea=0x180014D00, source_ea=0x180014D20),  # real byte_emit
    )
    tracer = ByteCascadeCoverageTracer.from_snapshot(snap)
    assert tracer is not None
    rec = tracer.records[3]
    assert len(rec.evidence) == 2
    # The byte-cascade fact (with %var_190 in source_expression) sorts first.
    assert rec.primary_evidence is not None
    assert "%var_190" in rec.primary_evidence.source_expression
    assert rec.source_ea_hex_set == {"0x0000000180014D10", "0x0000000180014D20"}


def test_infers_byte_index_from_source_expression_when_payload_missing_it() -> None:
    # _seed_records_from_fact_view is the inference unit; test it directly so we
    # don't depend on env gating.
    fv = _FakeFactView(
        active_observations=(
            _FakeObs(
                kind="TerminalByteEmitterFact",
                payload={
                    "destination_block": 72,
                    "block_ea": 0x180014F00,
                    "source_ea": 0x180014F10,
                    "opcode": "m_stx",
                    "emitter_role": "memory_store",
                    "corridor_role": "terminal_tail",
                    "destination_buffer_expression": "[ds.2:.+%var_188.8]",
                    "source_byte_expression": "xdu([ds.2:%var_190.8+#4.8].1)",
                },
            ),
        )
    )
    records = _seed_records_from_fact_view(fv)
    assert list(records) == [4]
    assert records[4].byte_index == 4
    assert records[4].primary_evidence is not None
    assert records[4].primary_evidence.byte_index == 4


def test_seeds_source_ea_from_observation_fields_when_payload_missing_it() -> None:
    fv = _FakeFactView(
        active_observations=(
            _FakeObs(
                kind="TerminalByteEmitterFact",
                payload={
                    "byte_index": 3,
                    "destination_block": 163,
                    "block_ea": 0x180014D00,
                    "opcode": "m_stx",
                    "emitter_role": "memory_store",
                    "corridor_role": "terminal_tail",
                    "destination_buffer_expression": "[ds.2:.+%var_188.8]",
                    "source_byte_expression": "xdu([ds.2:%var_190.8+#3.8].1)",
                },
                source_ea_hex="0x0000000180014d10",
            ),
            _FakeObs(
                kind="TerminalByteEmitterFact",
                payload={
                    "byte_index": 4,
                    "destination_block": 164,
                    "block_ea": 0x180014E00,
                    "opcode": "m_stx",
                    "emitter_role": "memory_store",
                    "corridor_role": "terminal_tail",
                    "destination_buffer_expression": "[ds.2:.+%var_188.8]",
                    "source_byte_expression": "xdu([ds.2:%var_190.8+#4.8].1)",
                },
                source_ea_i64=0x180014E10,
            ),
        )
    )

    records = _seed_records_from_fact_view(fv)

    assert records[3].source_ea_hex_set == {"0x0000000180014D10"}
    assert records[4].source_ea_hex_set == {"0x0000000180014E10"}


def test_skips_non_terminal_tail_corridor_role() -> None:
    fv = _FakeFactView(
        active_observations=(
            _FakeObs(
                kind="TerminalByteEmitterFact",
                payload={
                    "byte_index": 3,
                    "destination_block": 999,
                    "block_ea": 0x18001A000,
                    "source_ea": 0x18001A010,
                    "corridor_role": "intermediate",
                    "emitter_role": "memory_store",
                    "source_byte_expression": "x",
                    "destination_buffer_expression": "x",
                },
            ),
        )
    )
    assert _seed_records_from_fact_view(fv) == {}


# ---------------------------------------------------------------------------
# DAG / region seeding
# ---------------------------------------------------------------------------


def test_seed_dag_marks_in_dag_when_block_is_entry_anchor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_gate(monkeypatch)
    snap = _snapshot(_byte_fact(3, 163, block_ea=0x180014D00, source_ea=0x180014D10))
    tracer = ByteCascadeCoverageTracer.from_snapshot(snap)
    assert tracer is not None
    dag = _FakeDag(nodes=(_FakeStateDagNode(entry_anchor=163, key="STATE_72AFE1BC"),))
    tracer.seed_dag(dag)
    rec = tracer.records[3]
    assert rec.in_dag is True
    assert 163 in rec.entry_anchors
    assert "STATE_72AFE1BC" in rec.dag_node_keys


def test_seed_dag_marks_in_dag_when_block_is_in_owned_blocks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_gate(monkeypatch)
    snap = _snapshot(_byte_fact(4, 72, block_ea=0x180014F00, source_ea=0x180014F10))
    tracer = ByteCascadeCoverageTracer.from_snapshot(snap)
    assert tracer is not None
    dag = _FakeDag(
        nodes=(_FakeStateDagNode(entry_anchor=70, owned_blocks=(70, 71, 72), key="STATE_X"),)
    )
    tracer.seed_dag(dag)
    assert tracer.records[4].in_dag is True
    assert 70 in tracer.records[4].entry_anchors


def test_seed_corrected_dag_uses_separate_attribute(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_gate(monkeypatch)
    snap = _snapshot(_byte_fact(2, 56, block_ea=0x180014C00, source_ea=0x180014C10))
    tracer = ByteCascadeCoverageTracer.from_snapshot(snap)
    assert tracer is not None
    tracer.seed_dag(_FakeDag(nodes=(_FakeStateDagNode(entry_anchor=56, key="A"),)))
    tracer.seed_corrected_dag(
        _FakeDag(nodes=(_FakeStateDagNode(entry_anchor=99, key="B"),))
    )
    assert tracer.records[2].in_dag is True
    assert tracer.records[2].in_corrected_dag is False


def test_seed_raw_region_table_records_membership(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_gate(monkeypatch)
    snap = _snapshot(_byte_fact(5, 101, block_ea=0x180014E00, source_ea=0x180014E10))
    tracer = ByteCascadeCoverageTracer.from_snapshot(snap)
    assert tracer is not None

    @dataclass(frozen=True)
    class _Row:
        handler_serials: tuple[int, ...]

    tracer.seed_raw_region_table((_Row(handler_serials=(101, 102)),))
    assert tracer.records[5].in_region_table is True


# ---------------------------------------------------------------------------
# Candidate recording
# ---------------------------------------------------------------------------


def test_record_candidate_marks_raw_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_gate(monkeypatch)
    snap = _snapshot(_byte_fact(3, 163, block_ea=0x180014D00, source_ea=0x180014D10))
    tracer = ByteCascadeCoverageTracer.from_snapshot(snap)
    assert tracer is not None
    edge = _FakeEdge(source_anchor=_FakeSourceAnchor(block_serial=163))
    tracer.record_candidate_build(edge, candidate=object(), rejection=None)
    assert tracer.records[3].raw_candidate is True


def test_record_candidate_stores_rejection_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_gate(monkeypatch)
    snap = _snapshot(_byte_fact(6, 217, block_ea=0x180014F00, source_ea=0x180014F10))
    tracer = ByteCascadeCoverageTracer.from_snapshot(snap)
    assert tracer is not None
    edge = _FakeEdge(source_anchor=_FakeSourceAnchor(block_serial=217))
    tracer.record_candidate_build(
        edge,
        candidate=None,
        rejection={"rejection_reason": "dispatcher_region_block"},
    )
    rec = tracer.records[6]
    assert rec.raw_candidate is False
    assert rec.candidate_rejection == "dispatcher_region_block"


# ---------------------------------------------------------------------------
# Preservation predicate
# ---------------------------------------------------------------------------


def _record(byte_index: int, serial: int, source_ea: int) -> ByteRecord:
    """Build a single-evidence ByteRecord for direct preservation tests."""
    return ByteRecord(
        byte_index=byte_index,
        evidence=[
            ByteEvidence(
                byte_index=byte_index,
                block_serial=serial,
                block_ea_hex=f"0x{serial:016X}",
                source_ea_hex=f"0x{source_ea:016X}",
                destination="",
                source_expression="",
                fact_id="",
                confidence=0.0,
            )
        ],
    )


def _insn(opcode: int, ea: int) -> InsnSnapshot:
    return InsnSnapshot(opcode=opcode, ea=ea, operands=())


def test_preservation_insertblock_evidence_matches_by_ea() -> None:
    rec = _record(3, 163, 0x18001ABCD)
    mod = InsertBlock(
        pred_serial=10,
        succ_serial=20,
        instructions=(_insn(0x11, 0x18001ABCD), _insn(0x12, 0x18001ABCE)),
    )
    preserved, mechanism = _classify_preservation(rec, [mod])
    assert preserved is True
    assert mechanism == "insertblock_evidence"


def test_preservation_redirect_target_when_block_is_new_target() -> None:
    rec = _record(4, 72, 0x18001BEEF)
    mod = RedirectGoto(from_serial=5, old_target=99, new_target=72)
    preserved, mechanism = _classify_preservation(rec, [mod])
    assert preserved is True
    assert mechanism == "redirect_target"


def test_preservation_unmaterialized_when_no_mod_touches_block() -> None:
    rec = _record(5, 101, 0x18001CAFE)
    mod = RedirectGoto(from_serial=200, old_target=300, new_target=400)
    preserved, mechanism = _classify_preservation(rec, [mod])
    # Block isn't touched by any mod, so it remains in the CFG. But that is
    # NOT semantic preservation -- HCC just didn't claim it, and IDA's later
    # optimize_global may still DCE it.
    assert preserved is True
    assert mechanism == "unmaterialized_original_block"


def test_preservation_redirected_away() -> None:
    rec = _record(2, 56, 0x18001DEAD)
    mod = RedirectGoto(from_serial=56, old_target=80, new_target=200)
    preserved, mechanism = _classify_preservation(rec, [mod])
    assert preserved is False
    assert mechanism == "redirected_away"


def test_preservation_insertblock_evidence_outranks_redirect_away() -> None:
    """If evidence got composed into an InsertBlock body, the byte is preserved
    even if the original block is being redirected away."""
    rec = _record(3, 163, 0x18001ABCD)
    mods = [
        RedirectGoto(from_serial=163, old_target=200, new_target=300),
        InsertBlock(
            pred_serial=10,
            succ_serial=20,
            instructions=(_insn(0x11, 0x18001ABCD),),
        ),
    ]
    preserved, mechanism = _classify_preservation(rec, mods)
    assert preserved is True
    assert mechanism == "insertblock_evidence"


def test_preservation_matches_any_evidence_anchor() -> None:
    """Multi-evidence: byte is preserved if ANY anchor's EA appears in an
    InsertBlock body."""
    rec = ByteRecord(
        byte_index=3,
        evidence=[
            ByteEvidence(
                byte_index=3, block_serial=163, block_ea_hex="0x163",
                source_ea_hex="0x000000018001AAAA",
                destination="counter", source_expression="",
                fact_id="counter", confidence=0.5,
            ),
            ByteEvidence(
                byte_index=3, block_serial=163, block_ea_hex="0x163",
                source_ea_hex="0x000000018001BBBB",
                destination="buffer",
                source_expression="xdu(%var_190.8+#3.8)",
                fact_id="byte", confidence=0.8,
            ),
        ],
    )
    # InsertBlock contains only the second anchor's EA.
    mod = InsertBlock(
        pred_serial=10,
        succ_serial=20,
        instructions=(_insn(0x11, 0x18001BBBB),),
    )
    preserved, mechanism = _classify_preservation(rec, [mod])
    assert preserved is True
    assert mechanism == "insertblock_evidence"


# ---------------------------------------------------------------------------
# Canonical mod signatures
# ---------------------------------------------------------------------------


def test_canonical_mod_sig_redirect_goto() -> None:
    sig = _canonical_mod_sig(RedirectGoto(from_serial=1, old_target=2, new_target=3))
    assert (sig.kind, sig.src, sig.old, sig.new) == ("redirect_goto", 1, 2, 3)


def test_canonical_mod_sig_redirect_branch() -> None:
    sig = _canonical_mod_sig(RedirectBranch(from_serial=4, old_target=5, new_target=6))
    assert (sig.kind, sig.src, sig.old, sig.new) == ("redirect_branch", 4, 5, 6)


def test_canonical_mod_sig_convert_to_goto() -> None:
    sig = _canonical_mod_sig(ConvertToGoto(block_serial=7, goto_target=8))
    assert (sig.kind, sig.src, sig.new) == ("convert_to_goto", 7, 8)


def test_canonical_mod_sig_edge_redirect_via_pred_split() -> None:
    sig = _canonical_mod_sig(
        EdgeRedirectViaPredSplit(src_block=10, old_target=11, new_target=12, via_pred=13)
    )
    assert sig.kind == "edge_redirect_via_pred_split"
    assert "via_pred=13" in sig.fingerprint


def test_canonical_mod_sig_insert_block_fingerprints_eas() -> None:
    sig = _canonical_mod_sig(
        InsertBlock(
            pred_serial=20,
            succ_serial=30,
            instructions=(_insn(0x11, 0x1000), _insn(0x12, 0x1004)),
        )
    )
    assert sig.kind == "insert_block"
    assert "0x0000000000001000" in sig.fingerprint
    assert "0x0000000000001004" in sig.fingerprint


def test_canonical_mod_sig_duplicate_block() -> None:
    sig = _canonical_mod_sig(
        DuplicateBlock(source_block=40, target_block=None, pred_serial=41, patch_kind="kx")
    )
    assert sig.kind == "duplicate_block"
    assert sig.src == 40
    assert sig.fingerprint == "kx"


# ---------------------------------------------------------------------------
# Stage transitions and final status
# ---------------------------------------------------------------------------


def test_record_stage_modifications_marks_redirected_away_on_first_drop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_gate(monkeypatch)
    snap = _snapshot(_byte_fact(2, 56, block_ea=0x180014C00, source_ea=0x180014C10))
    tracer = ByteCascadeCoverageTracer.from_snapshot(snap)
    assert tracer is not None
    # Seed DAG presence so the byte isn't "no_dag_evidence".
    tracer.seed_dag(_FakeDag(nodes=(_FakeStateDagNode(entry_anchor=56, key="A"),)))

    unmaterialized_mods: list = []
    dropped_mods = [RedirectGoto(from_serial=56, old_target=80, new_target=200)]

    tracer.record_stage_modifications(
        ByteCascadeStage.PRIMARY_EXECUTION, unmaterialized_mods,
    )
    tracer.record_stage_modifications(ByteCascadeStage.POSTPROCESS, dropped_mods)
    tracer.record_stage_modifications(ByteCascadeStage.FINAL, dropped_mods)
    tracer.record_finalize(dropped_mods)

    rec = tracer.records[2]
    assert rec.first_dropped_stage == ByteCascadeStage.POSTPROCESS.value
    assert rec.final_status == "redirected_away"


def test_record_stage_modifications_marks_accepted_via_insertblock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_gate(monkeypatch)
    snap = _snapshot(_byte_fact(3, 163, block_ea=0x180014D00, source_ea=0x180014D10))
    tracer = ByteCascadeCoverageTracer.from_snapshot(snap)
    assert tracer is not None

    insertblock_mods = [
        InsertBlock(
            pred_serial=10,
            succ_serial=20,
            instructions=(_insn(0x11, 0x180014D10),),
        )
    ]
    tracer.record_stage_modifications(
        ByteCascadeStage.PRIMARY_EXECUTION, insertblock_mods
    )
    tracer.record_finalize(insertblock_mods)

    rec = tracer.records[3]
    assert rec.accepted_stage == ByteCascadeStage.PRIMARY_EXECUTION.value
    assert rec.emitted_mod_kind == "InsertBlock"
    assert rec.preserved_in_insertblock is True
    assert rec.final_status == "preserved_insertblock"


def test_final_status_region_detection_gap_when_in_dag_but_not_in_region(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The signature outcome for sub_7FFD bytes 2-6: HCC saw the state in its
    DAG but never picked the block up as part of any raw region or InsertBlock
    body."""
    _enable_gate(monkeypatch)
    snap = _snapshot(_byte_fact(4, 72, block_ea=0x180014F00, source_ea=0x180014F10))
    tracer = ByteCascadeCoverageTracer.from_snapshot(snap)
    assert tracer is not None
    # Byte IS in the DAG.
    tracer.seed_dag(_FakeDag(nodes=(_FakeStateDagNode(entry_anchor=72, key="S"),)))
    tracer.seed_corrected_dag(
        _FakeDag(nodes=(_FakeStateDagNode(entry_anchor=72, key="S"),))
    )
    # But the raw region table has NO entry for the byte's block.
    tracer.seed_raw_region_table(())
    # And no mod touches the block.
    tracer.record_stage_modifications(ByteCascadeStage.PRIMARY_EXECUTION, [])
    tracer.record_finalize([])

    rec = tracer.records[4]
    assert rec.in_dag is True
    assert rec.in_region_table is False
    assert rec.preserved_in_insertblock is False
    assert rec.final_status == "region_detection_gap"


def test_final_status_unmaterialized_when_in_region_but_no_mod_lands_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_gate(monkeypatch)
    snap = _snapshot(_byte_fact(5, 101, block_ea=0x180014E00, source_ea=0x180014E10))
    tracer = ByteCascadeCoverageTracer.from_snapshot(snap)
    assert tracer is not None
    tracer.seed_dag(_FakeDag(nodes=(_FakeStateDagNode(entry_anchor=101, key="S"),)))

    @dataclass(frozen=True)
    class _Row:
        handler_serials: tuple[int, ...]

    # Block IS in a raw region.
    tracer.seed_raw_region_table((_Row(handler_serials=(101,)),))
    # But nothing materialised it.
    tracer.record_stage_modifications(ByteCascadeStage.PRIMARY_EXECUTION, [])
    tracer.record_finalize([])

    rec = tracer.records[5]
    assert rec.in_region_table is True
    assert rec.final_status == "unmaterialized_original_block"


def test_final_status_no_dag_evidence_when_byte_absent_from_dag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_gate(monkeypatch)
    snap = _snapshot(_byte_fact(6, 217, block_ea=0x180014F00, source_ea=0x180014F10))
    tracer = ByteCascadeCoverageTracer.from_snapshot(snap)
    assert tracer is not None
    # NO seed_dag / seed_corrected_dag calls.
    tracer.record_stage_modifications(ByteCascadeStage.FINAL, [])
    tracer.record_finalize([])

    rec = tracer.records[6]
    assert rec.in_dag is False
    assert rec.final_status == "no_dag_evidence"


def test_final_status_preserved_redirect_when_block_is_redirect_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_gate(monkeypatch)
    snap = _snapshot(_byte_fact(1, 50, block_ea=0x180014B00, source_ea=0x180014B10))
    tracer = ByteCascadeCoverageTracer.from_snapshot(snap)
    assert tracer is not None
    tracer.seed_dag(_FakeDag(nodes=(_FakeStateDagNode(entry_anchor=50, key="S"),)))
    mods = [RedirectGoto(from_serial=99, old_target=98, new_target=50)]
    tracer.record_stage_modifications(ByteCascadeStage.PRIMARY_EXECUTION, mods)
    tracer.record_finalize(mods)

    rec = tracer.records[1]
    assert rec.final_status == "preserved_redirect"
    assert rec.emitted_mod_kind == "RedirectGoto"


def test_record_finalize_emits_grep_rows_and_table(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_gate(monkeypatch)
    snap = _snapshot(
        _byte_fact(2, 56, block_ea=0x180014C00, source_ea=0x180014C10),
        _byte_fact(3, 163, block_ea=0x180014D00, source_ea=0x180014D10),
    )
    logger = _RecordingLogger()
    tracer = ByteCascadeCoverageTracer.from_snapshot(snap, logger=logger)
    assert tracer is not None
    insertblock_mods = [
        InsertBlock(
            pred_serial=10,
            succ_serial=20,
            instructions=(_insn(0x11, 0x180014C10),),
        )
    ]
    tracer.record_stage_modifications(ByteCascadeStage.FINAL, insertblock_mods)
    tracer.record_finalize(insertblock_mods)
    tracer.emit_log()

    grep_rows = [line for line in logger.lines if line.startswith(ROW_LOG_PREFIX)]
    assert len(grep_rows) == 2
    assert any("byte=2" in line for line in grep_rows)
    assert any("byte=3" in line for line in grep_rows)
    # n_evidence field appears in the row log per the new schema.
    assert any("n_evidence=1" in line for line in grep_rows)
    # source_eas field exposes the byte's m_stx EAs so the d810.diagnostics
    # layer can cross-reference snap17 -> snap18 survival per EA.
    assert any("source_eas=0x0000000180014C10" in line for line in grep_rows)
    table_lines = [line for line in logger.lines if TABLE_LOG_PREFIX in line]
    assert table_lines
    rendered = tracer.render_markdown_table()
    assert "| byte | block_ea |" in rendered
    assert "n_evidence" in rendered
    assert "final_status" in rendered


def test_hook_methods_are_noops_when_records_empty() -> None:
    tracer = ByteCascadeCoverageTracer(records={}, logger=None, func_ea_hex="")
    # Should not raise.
    tracer.seed_dag(_FakeDag(nodes=()))
    tracer.seed_corrected_dag(_FakeDag(nodes=()))
    tracer.seed_raw_region_table(())
    tracer.record_candidate_build(_FakeEdge(), candidate=None, rejection=None)
    tracer.record_stage_modifications(ByteCascadeStage.FINAL, [])
    tracer.record_finalize([])
    tracer.emit_log()
    assert tracer.render_markdown_table().startswith("### HCC byte-cascade coverage")

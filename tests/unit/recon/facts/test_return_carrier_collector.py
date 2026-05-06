"""Tests for ReturnCarrierFactCollector."""
from __future__ import annotations

from types import SimpleNamespace

from d810.core.diag.snapshot import BlockSnapshot, InstructionSnapshot
from d810.recon.facts.collectors import ReturnCarrierFactCollector
from d810.recon.facts.collectors.induction_carrier import _MATURITY_VALUES


def _insn(
    *,
    index: int = 0,
    opcode_name: str = "m_mov",
    dest_type: str | None = "mop_S",
    dest_stkoff: int | None = 0x7F0,
    dest_size: int | None = 8,
    src_l_type: str | None = "mop_S",
    src_l_stkoff: int | None = 0x680,
    src_l_value: int | None = None,
    src_r_type: str | None = None,
    src_r_stkoff: int | None = None,
    src_r_value: int | None = None,
    dstr: str = "mov %var_178.8, %var_8.8",
) -> InstructionSnapshot:
    return InstructionSnapshot(
        index=index,
        ea=0x180010000 + index,
        opcode=0,
        opcode_name=opcode_name,
        dest_type=dest_type,
        dest_stkoff=dest_stkoff,
        dest_size=dest_size,
        src_l_type=src_l_type,
        src_l_stkoff=src_l_stkoff,
        src_l_value=src_l_value,
        src_r_type=src_r_type,
        src_r_stkoff=src_r_stkoff,
        src_r_value=src_r_value,
        dstr=dstr,
    )


def _target(*instructions: InstructionSnapshot) -> SimpleNamespace:
    return SimpleNamespace(
        blocks={
            10: BlockSnapshot(
                serial=10,
                block_type=1,
                type_name="BLT_1WAY",
                nsucc=1,
                npred=1,
                succs=[11],
                preds=[9],
                instructions=list(instructions),
            )
        }
    )


def test_collects_return_slot_identity_carrier() -> None:
    collector = ReturnCarrierFactCollector()

    facts = collector.collect(
        _target(
            _insn(),
            _insn(
                index=1,
                dest_type="mop_r",
                dest_stkoff=None,
                dest_size=8,
                src_l_type="mop_S",
                src_l_stkoff=0x7F0,
                dstr="mov %var_8.8, rax.8",
            ),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.kind == "ReturnCarrierFact"
    assert fact.semantic_key == (
        "return_carrier:slot=0x7f0:class=stack_identity_carrier:source=mop_S:0x680"
    )
    assert fact.maturity == "MMAT_LOCOPT"
    assert fact.source_block == 10
    assert fact.source_ea == 0x180010000
    assert fact.mop_signature == "return_slot:mop_S:0x7f0:8"
    assert fact.payload["return_slot_stkoff"] == 0x7F0
    assert fact.payload["source_signature"] == "mop_S:0x680"
    assert fact.payload["carrier_class"] == "stack_identity_carrier"
    assert fact.evidence == ("mov %var_178.8, %var_8.8",)


def test_collects_state_guard_artifact_candidate() -> None:
    collector = ReturnCarrierFactCollector()

    facts = collector.collect(
        _target(
            _insn(
                opcode_name="m_xdu",
                src_l_stkoff=0x3C,
                dstr="xdu %var_7BC.4, %var_8.8",
            ),
            _insn(
                index=1,
                dest_type="mop_r",
                dest_stkoff=None,
                src_l_stkoff=0x7F0,
                dstr="mov %var_8.8, rax.8",
            ),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_GLBOPT1"],
        phase="post_d810",
    )

    assert len(facts) == 1
    assert facts[0].semantic_key == (
        "return_carrier:slot=0x7f0:class=state_guard_artifact_candidate:"
        "source=mop_S:0x3c"
    )
    assert facts[0].payload["source_signature"] == "mop_S:0x3c"
    assert facts[0].payload["opcode"] == "m_xdu"


def test_collects_constant_or_offset_return() -> None:
    collector = ReturnCarrierFactCollector()

    facts = collector.collect(
        _target(
            _insn(
                opcode_name="m_add",
                src_l_type="mop_n",
                src_l_stkoff=None,
                src_l_value=0xD0,
                src_r_type="mop_S",
                src_r_stkoff=0x20,
                dstr="add %arg_20.8, #0xD0.8, %var_8.8",
            ),
            _insn(
                index=1,
                dest_type="mop_r",
                dest_stkoff=None,
                src_l_stkoff=0x7F0,
                dstr="mov %var_8.8, rax.8",
            ),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_CALLS"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    assert facts[0].semantic_key == (
        "return_carrier:slot=0x7f0:class=constant_or_offset_return:source=const:0xd0"
    )
    assert facts[0].payload["source_signature"] == "const:0xd0"


def test_classifies_non_mov_stack_arithmetic_as_computed_return() -> None:
    collector = ReturnCarrierFactCollector()

    facts = collector.collect(
        _target(
            _insn(
                opcode_name="m_add",
                src_l_type="mop_S",
                src_l_stkoff=0x680,
                src_r_type="mop_S",
                src_r_stkoff=0x688,
                dstr="add %var_178.8, %var_170.8, %var_8.8",
            ),
            _insn(
                index=1,
                dest_type="mop_r",
                dest_stkoff=None,
                src_l_stkoff=0x7F0,
                dstr="mov %var_8.8, rax.8",
            ),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_CALLS"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    assert facts[0].semantic_key == (
        "return_carrier:slot=0x7f0:class=computed_return:source=mop_S:0x680"
    )
    assert facts[0].payload["carrier_class"] == "computed_return"


def test_ignores_return_slot_writes_without_return_register_read() -> None:
    collector = ReturnCarrierFactCollector()

    facts = collector.collect(
        _target(_insn()),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    assert facts == ()


def test_ignores_non_return_slot_write() -> None:
    collector = ReturnCarrierFactCollector()

    facts = collector.collect(
        _target(
            _insn(dest_stkoff=0x680, dstr="mov %var_178.8, %var_178.8"),
            _insn(
                index=1,
                dest_type="mop_r",
                dest_stkoff=None,
                src_l_stkoff=0x7F0,
                dstr="mov %var_8.8, rax.8",
            ),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    assert facts == ()


def test_records_upstream_mba_for_stack_identity_carrier() -> None:
    """Backward-trace the canonical OLLVM ``mov %var_K -> %var_8``
    trampoline: the collector should record the upstream instruction
    that defined ``%var_K`` (the return-carrier MBA materialization
    site) so later GLBOPT1 consumers can recognise the site even after
    IDA's CALLS phase folds the chain into a sub-instruction operand
    tree.
    """
    collector = ReturnCarrierFactCollector()

    # Upstream MBA producer at insn 0:
    #   add (9*(%var_40 & %var_228)), (0x15*(~%var_228 & ((%var_660+%var_650) ^ %var_658))), %var_7C8
    upstream_dstr = (
        "add (9.8*(%var_40.8 & %var_228.8)), "
        "(0x15.8*(bnot(%var_228.8) & ((%var_660.8+%var_650.8) ^ %var_658.8))), "
        "%var_7C8.8"
    )
    upstream = _insn(
        index=0,
        opcode_name="m_add",
        dest_type="mop_S",
        dest_stkoff=0x7C8,
        dest_size=8,
        src_l_type="mop_d",
        src_l_stkoff=None,
        src_r_type="mop_d",
        src_r_stkoff=None,
        dstr=upstream_dstr,
    )
    # Identity carrier mov %var_7C8 -> %var_8 at insn 1.
    carrier = _insn(
        index=1,
        opcode_name="m_mov",
        dest_type="mop_S",
        dest_stkoff=0x8,
        dest_size=8,
        src_l_type="mop_S",
        src_l_stkoff=0x7C8,
        dstr="mov %var_7C8.8, %var_8.8",
    )
    # Return-register trampoline so ``_return_slot_offsets`` resolves
    # the slot to 0x8.
    rax_trampoline = _insn(
        index=2,
        opcode_name="m_mov",
        dest_type="mop_r",
        dest_stkoff=None,
        src_l_type="mop_S",
        src_l_stkoff=0x8,
        dstr="mov %var_8.8, rax.8",
    )

    facts = collector.collect(
        _target(upstream, carrier, rax_trampoline),
        func_ea=0x180012cf0,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.kind == "ReturnCarrierFact"
    assert fact.payload["carrier_class"] == "stack_identity_carrier"
    # The carrier's source stkvar (var_7C8 at stkoff 0x7C8) must have
    # been recorded as the upstream destination.
    assert fact.payload["carrier_dst_stkoff"] == 0x7C8
    assert fact.payload["upstream_writer_ea"] == 0x180010000  # _insn ea pattern
    assert fact.payload["upstream_writer_block_serial"] == 10
    assert fact.payload["upstream_writer_insn_index"] == 0
    assert fact.payload["upstream_writer_opcode"] == "m_add"
    assert fact.payload["upstream_writer_dest_stkoff"] == 0x7C8
    assert fact.payload["upstream_writer_dstr"] == upstream_dstr
    # The set of ``%var_NNN`` references the upstream MBA reads must
    # surface so a later guard can intersect with handler-block
    # constant writes.
    refs = set(fact.payload["upstream_writer_var_refs"])
    assert {"40", "228", "650", "658", "660", "7c8"}.issubset(refs)
    # Both dstrs end up in the evidence tuple.
    assert fact.evidence == ("mov %var_7C8.8, %var_8.8", upstream_dstr)


def test_does_not_record_upstream_when_no_writer_present() -> None:
    """If the ``%var_K`` source has no upstream definition in the
    snapshot (e.g. it's an arg slot or comes from an earlier untracked
    block), the upstream payload fields must stay absent rather than
    populated with ``None``."""
    collector = ReturnCarrierFactCollector()

    carrier = _insn(
        index=0,
        opcode_name="m_mov",
        dest_type="mop_S",
        dest_stkoff=0x8,
        dest_size=8,
        src_l_type="mop_S",
        src_l_stkoff=0x7C8,
        dstr="mov %var_7C8.8, %var_8.8",
    )
    rax_trampoline = _insn(
        index=1,
        opcode_name="m_mov",
        dest_type="mop_r",
        dest_stkoff=None,
        src_l_type="mop_S",
        src_l_stkoff=0x8,
        dstr="mov %var_8.8, rax.8",
    )

    facts = collector.collect(
        _target(carrier, rax_trampoline),
        func_ea=0x180012cf0,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.payload["carrier_class"] == "stack_identity_carrier"
    assert "upstream_writer_ea" not in fact.payload
    assert "upstream_writer_var_refs" not in fact.payload


def _multi_block_target(blocks: dict[int, list[InstructionSnapshot]]) -> SimpleNamespace:
    """Build a snapshot with multiple blocks.  Each entry in ``blocks``
    maps a block serial to its ordered instructions list."""
    block_snapshots = {}
    sorted_serials = sorted(blocks.keys())
    for idx, serial in enumerate(sorted_serials):
        succs = (
            [sorted_serials[idx + 1]] if idx + 1 < len(sorted_serials) else []
        )
        preds = [sorted_serials[idx - 1]] if idx > 0 else []
        block_snapshots[serial] = BlockSnapshot(
            serial=serial,
            block_type=1,
            type_name="BLT_1WAY",
            nsucc=len(succs),
            npred=len(preds),
            succs=succs,
            preds=preds,
            instructions=list(blocks[serial]),
        )
    return SimpleNamespace(blocks=block_snapshots)


def test_upstream_writer_walk_picks_canonical_producer_not_function_wide_last() -> None:
    """Regression for the iteration-order scoping fix.

    Function has THREE writers to the carrier slot ``%var_7C8`` (stkoff
    0x7C8).  The carrier-mov is in the middle block.  A *later* block
    overrides ``%var_7C8`` with an unrelated MBA.  The collector must
    pick the writer that *precedes* the carrier-mov, not the
    function-wide last writer.

    Pre-fix the collector returned the late writer's payload (mirroring
    the sub_7FFD ``upstream_writer_block_serial=254`` regression seen
    on the live binary).  Post-fix the collector returns the canonical
    writer in the predecessor block.
    """
    canonical_dstr = (
        "add (9.8*(%var_40.8 & %var_228.8)), "
        "(0x15.8*(bnot(%var_228.8) & ((%var_660.8+%var_650.8) ^ %var_658.8))), "
        "%var_7C8.8"
    )
    late_unrelated_dstr = (
        "add ((((4.8*(xdu.8(%var_1C8.1) | -0x80.8)))+#0xFE.8), %var_7C8.8"
    )

    canonical_writer = _insn(
        index=0,
        opcode_name="m_add",
        dest_type="mop_S",
        dest_stkoff=0x7C8,
        dest_size=8,
        src_l_type="mop_d",
        src_l_stkoff=None,
        src_r_type="mop_d",
        src_r_stkoff=None,
        dstr=canonical_dstr,
    )
    carrier_mov = _insn(
        index=0,
        opcode_name="m_mov",
        dest_type="mop_S",
        dest_stkoff=0x8,
        dest_size=8,
        src_l_type="mop_S",
        src_l_stkoff=0x7C8,
        dstr="mov %var_7C8.8, %var_8.8",
    )
    rax_trampoline = _insn(
        index=1,
        opcode_name="m_mov",
        dest_type="mop_r",
        dest_stkoff=None,
        src_l_type="mop_S",
        src_l_stkoff=0x8,
        dstr="mov %var_8.8, rax.8",
    )
    late_writer = _insn(
        index=0,
        opcode_name="m_add",
        dest_type="mop_S",
        dest_stkoff=0x7C8,
        dest_size=8,
        src_l_type="mop_d",
        src_l_stkoff=None,
        src_r_type="mop_d",
        src_r_stkoff=None,
        dstr=late_unrelated_dstr,
    )

    target = _multi_block_target({
        140: [canonical_writer],          # the canonical OLLVM MBA
        141: [carrier_mov, rax_trampoline],  # the trampoline mov
        254: [late_writer],               # function-wide LAST writer; not the reaching def
    })

    collector = ReturnCarrierFactCollector()
    facts = collector.collect(
        target,
        func_ea=0x180012cf0,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    fact = facts[0]
    # The canonical writer's identity must be recorded -- not the late
    # function-wide writer.
    assert fact.payload["upstream_writer_block_serial"] == 140
    assert fact.payload["upstream_writer_dstr"] == canonical_dstr
    refs = set(fact.payload["upstream_writer_var_refs"])
    # Canonical OLLVM source vars must be present.
    assert {"40", "228", "650", "658", "660"}.issubset(refs)
    # The unrelated late writer's only operand var (var_1C8) must NOT
    # appear -- proving we picked the canonical producer, not the late
    # function-wide last writer.
    assert "1c8" not in refs

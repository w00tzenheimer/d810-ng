"""Tests for ReturnSlotFactCollector."""
from __future__ import annotations

import json
from types import SimpleNamespace

from d810.core.diag.snapshot import BlockSnapshot, InstructionSnapshot
from d810.ir.flowgraph import (
    BlockSnapshot as CfgBlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.analyses.value_flow.return_carrier import ReturnSlotFactCollector
from d810.analyses.value_flow.induction_carrier import _MATURITY_VALUES

from tests.system.runtime.recon.facts._diag_meta_builder import flat_meta

_OPCODE_ALIASES = {
    "m_mov": "move",
    "m_add": "add",
    "m_sub": "sub",
}

_OPERAND_TYPE_ALIASES = {
    "mop_S": "S",
    "mop_n": "c",
    "mop_r": "r",
    "mop_d": "t",
}


def _opcode_name(value: str) -> str:
    return _OPCODE_ALIASES.get(value, value)


def _operand_type(value: str | None) -> str | None:
    if value is None:
        return None
    return _OPERAND_TYPE_ALIASES.get(value, value)


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
    dest_reg: int | None = None,
    src_l_reg: int | None = None,
    src_r_reg: int | None = None,
    dstr: str = "mov %var_178.8, %var_8.8",
    source_stkoffs: tuple[int, ...] = (),
) -> InstructionSnapshot:
    insn = InstructionSnapshot(
        index=index,
        ea=0x180010000 + index,
        opcode=0,
        opcode_name=opcode_name,
        dest_type=_operand_type(dest_type),
        dest_stkoff=dest_stkoff,
        dest_size=dest_size,
        src_l_type=_operand_type(src_l_type),
        src_l_stkoff=src_l_stkoff,
        src_l_value=src_l_value,
        src_r_type=_operand_type(src_r_type),
        src_r_stkoff=src_r_stkoff,
        src_r_value=src_r_value,
        dstr=dstr,
        meta=flat_meta(
            opcode_name=opcode_name,
            ea=0x180010000 + index,
            dstr=dstr,
            dest_type=dest_type,
            dest_stkoff=dest_stkoff,
            dest_size=dest_size,
            dest_register=dest_reg,
            src_l_type=src_l_type,
            src_l_stkoff=src_l_stkoff,
            src_l_value=src_l_value,
            src_l_register=src_l_reg,
            src_l_size=dest_size,
            src_r_type=src_r_type,
            src_r_stkoff=src_r_stkoff,
            src_r_value=src_r_value,
            src_r_register=src_r_reg,
        ),
    )
    insn.source_stkoffs = tuple(int(offset) for offset in source_stkoffs)
    if dest_reg is not None:
        insn.dest_reg = int(dest_reg)
    if src_l_reg is not None:
        insn.src_l_reg = int(src_l_reg)
    if src_r_reg is not None:
        insn.src_r_reg = int(src_r_reg)
    return insn


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


def _cfg_stack(stkoff: int, *, size: int = 8) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.STACK, stkoff=stkoff, size=size)


def _cfg_reg(reg: int, *, size: int = 8) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.REGISTER, reg=reg, size=size)


def _cfg_insn(
    *,
    index: int,
    kind: InsnKind,
    l: MopSnapshot | None = None,
    r: MopSnapshot | None = None,
    d: MopSnapshot | None = None,
    display_text: str = "",
) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=-1,
        raw_opcode=0x1000 + index,
        ea=0x180010000 + index,
        operands=tuple(op for op in (l, r, d) if op is not None),
        operand_slots=tuple(
            (slot, op)
            for slot, op in (("l", l), ("r", r), ("d", d))
            if op is not None
        ),
        display_text=display_text,
        l=l,
        r=r,
        d=d,
        kind=kind,
    )


def _cfg_target(*instructions: InsnSnapshot) -> FlowGraph:
    block = CfgBlockSnapshot(
        serial=10,
        block_type=1,
        succs=(11,),
        preds=(9,),
        flags=0,
        start_ea=0x180014000,
        insn_snapshots=tuple(instructions),
    )
    return FlowGraph(blocks={10: block}, entry_serial=10, func_ea=0x401000)


def test_collects_return_slot_identity_carrier() -> None:
    collector = ReturnSlotFactCollector()

    facts = collector.collect(
        _target(
            _insn(),
            _insn(
                index=1,
                dest_type="mop_r",
                dest_stkoff=None,
                dest_size=8,
                dest_reg=0,
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
        "return_carrier:slot=0x7f0:class=stack_identity_carrier:source=S:0x680"
    )
    assert fact.maturity == "MMAT_LOCOPT"
    assert fact.source_block == 10
    assert fact.source_ea == 0x180010000
    assert fact.mop_signature == "return_slot:mop_S:0x7f0:8"
    assert fact.payload["return_slot_stkoff"] == 0x7F0
    assert fact.payload["source_signature"] == "S:0x680"
    assert fact.payload["carrier_class"] == "stack_identity_carrier"
    assert fact.evidence == ("mov %var_178.8, %var_8.8",)


def test_collects_return_slot_identity_carrier_from_canonical_flowgraph() -> None:
    collector = ReturnSlotFactCollector()

    facts = collector.collect(
        _cfg_target(
            _cfg_insn(
                index=0,
                kind=InsnKind.MOV,
                l=_cfg_stack(0x680),
                d=_cfg_stack(0x7F0),
                display_text="mov %var_178.8, %var_8.8",
            ),
            _cfg_insn(
                index=1,
                kind=InsnKind.MOV,
                l=_cfg_stack(0x7F0),
                d=_cfg_reg(0),
                display_text="mov %var_8.8, rax.8",
            ),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    assert facts[0].semantic_key == (
        "return_carrier:slot=0x7f0:class=stack_identity_carrier:source=S:0x680"
    )
    assert facts[0].payload["source_signature"] == "S:0x680"


def test_collects_protected_non_carrier_return_writer_candidate() -> None:
    collector = ReturnSlotFactCollector()

    facts = collector.collect(
        _cfg_target(
            _cfg_insn(
                index=0,
                kind=InsnKind.XDU,
                l=_cfg_stack(0x3C, size=4),
                d=_cfg_stack(0x7F0),
                display_text="xdu %var_7BC.4, %var_8.8",
            ),
            _cfg_insn(
                index=1,
                kind=InsnKind.MOV,
                l=_cfg_stack(0x7F0),
                d=_cfg_reg(0),
                display_text="mov %var_8.8, rax.8",
            ),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_GLBOPT1"],
        phase="post_d810",
    )

    assert len(facts) == 1
    assert facts[0].semantic_key == (
        "return_carrier:slot=0x7f0:class=protected_non_carrier_return_writer_candidate:"
        "source=S:0x3c"
    )
    assert facts[0].payload["source_signature"] == "S:0x3c"
    assert facts[0].payload["opcode"] == "zext"


def test_collects_constant_or_offset_return() -> None:
    collector = ReturnSlotFactCollector()

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
                dest_reg=0,
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
    collector = ReturnSlotFactCollector()

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
                dest_reg=0,
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
        "return_carrier:slot=0x7f0:class=computed_return:source=S:0x680"
    )
    assert facts[0].payload["carrier_class"] == "computed_return"


def test_ignores_return_slot_writes_without_return_register_read() -> None:
    collector = ReturnSlotFactCollector()

    facts = collector.collect(
        _target(_insn()),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    assert facts == ()


def test_ignores_rendered_rax_text_without_lifted_register_identity() -> None:
    collector = ReturnSlotFactCollector()

    facts = collector.collect(
        _target(
            _insn(),
            _insn(
                index=1,
                dest_type="mop_r",
                dest_stkoff=None,
                src_l_type="mop_S",
                src_l_stkoff=0x7F0,
                dstr="mov %var_8.8, rax.8",
            ),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    assert facts == ()


def test_ignores_non_return_slot_write() -> None:
    collector = ReturnSlotFactCollector()

    facts = collector.collect(
        _target(
            _insn(dest_stkoff=0x680, dstr="mov %var_178.8, %var_178.8"),
            _insn(
                index=1,
                dest_type="mop_r",
                dest_stkoff=None,
                dest_reg=0,
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
    collector = ReturnSlotFactCollector()

    # Upstream MBA producer at insn 0:
    #   add (9*(%var_40 & %var_228)), (0x15*(~%var_228 & ((%var_660+%var_650) ^ %var_658))), %var_7C8
    upstream_dstr = "add opaque-return-carrier-mba, %var_7C8.8"
    upstream_source_stkoffs = (0x40, 0x228, 0x650, 0x658, 0x660)
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
        source_stkoffs=upstream_source_stkoffs,
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
        dest_reg=0,
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
    assert fact.payload["carrier_dst_storage_key"] == "S1992"
    assert fact.payload["carrier_dst_storage_identity"] == {
        "kind": "stack",
        "prefix": "S",
        "offset": 0x7C8,
        "key": "S1992",
    }
    assert fact.payload["upstream_writer_ea"] == 0x180010000  # _insn ea pattern
    assert fact.payload["upstream_writer_block_serial"] == 10
    assert fact.payload["upstream_writer_insn_index"] == 0
    assert fact.payload["upstream_writer_opcode"] == "add"
    assert fact.payload["upstream_writer_dest_stkoff"] == 0x7C8
    assert fact.payload["upstream_writer_dest_storage_key"] == "S1992"
    assert fact.payload["upstream_writer_dstr"] == upstream_dstr
    # ``upstream_writer_source_storage_keys`` recovery from nested ``mop_d``
    # sub-operands was a capability of the deleted meta-less flat ``source_stkoffs``
    # attribute; the canonical projection keeps nested sub-expressions out of
    # ``Instruction.inputs`` (llr-3b41 S11), so for a nested-operand writer the
    # set is empty.  The upstream writer identity/opcode/dest above is the fact
    # this test guards.
    assert set(fact.payload["upstream_writer_source_storage_keys"]) == set()
    assert "upstream_writer_var_refs" not in fact.payload
    # Both dstrs end up in the evidence tuple.
    assert fact.evidence == ("mov %var_7C8.8, %var_8.8", upstream_dstr)


def test_does_not_record_upstream_when_no_writer_present() -> None:
    """If the ``%var_K`` source has no upstream definition in the
    snapshot (e.g. it's an arg slot or comes from an earlier untracked
    block), the upstream payload fields must stay absent rather than
    populated with ``None``."""
    collector = ReturnSlotFactCollector()

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
        dest_reg=0,
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
    assert "upstream_writer_source_storage_keys" not in fact.payload


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
        source_stkoffs=(0x40, 0x228, 0x650, 0x658, 0x660),
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
        dest_reg=0,
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
        source_stkoffs=(0x1C8,),
    )

    target = _multi_block_target({
        140: [canonical_writer],          # the canonical OLLVM MBA
        141: [carrier_mov, rax_trampoline],  # the trampoline mov
        254: [late_writer],               # function-wide LAST writer; not the reaching def
    })

    collector = ReturnSlotFactCollector()
    facts = collector.collect(
        target,
        func_ea=0x180012cf0,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    fact = facts[0]
    # The canonical writer's identity must be recorded -- not the late
    # function-wide writer.  This is the iteration-order scoping regression:
    # the collector picks the writer that PRECEDES the carrier-mov, not the
    # function-wide last writer (block 254).
    assert fact.payload["upstream_writer_block_serial"] == 140
    assert fact.payload["upstream_writer_dstr"] == canonical_dstr
    # NB: ``upstream_writer_source_storage_keys`` recovery from nested ``mop_d``
    # sub-operands was a capability of the deleted meta-less flat ``source_stkoffs``
    # attribute; the canonical projection keeps nested sub-expressions out of
    # ``Instruction.inputs`` (llr-3b41 S11), so this assertion is dropped -- the
    # block-serial scoping above is the regression this test guards.


# ---------------------------------------------------------------------------
# llr-3b41 (missed 9th collector): per-collector port onto canonical Instruction.
#
# The collector's own dual-currency iterator
# (:func:`~d810.analyses.value_flow.return_carrier._iter_return_carrier_insns`)
# routes the two meta-rich currencies -- a portable ``FlowGraph`` block
# (covered above by ``_cfg_target``) AND a diag row carrying a parseable ``meta``
# operand tree -- through the SAME canonical projection, while meta-less rows
# (every ``_target`` test above) stay on the byte-identical legacy flat path.
# The tests below pin the previously-uncovered operand-tree diag-row source and
# the meta-less zero-observation contract.
# ---------------------------------------------------------------------------


def _meta_stack(stkoff: int, *, size: int = 8) -> dict:
    return {
        "type": "mop_S",
        "type_num": 5,
        "size": size,
        "dstr": f"%var_{stkoff:x}.{size}",
        "stkoff": stkoff,
    }


def _meta_reg(reg: int, *, size: int = 8) -> dict:
    return {
        "type": "mop_r",
        "type_num": 1,
        "size": size,
        "dstr": "rax.8",
        "register": reg,
    }


def _meta_insn(
    *,
    index: int,
    ea: int,
    opcode_name: str,
    l: dict | None = None,
    r: dict | None = None,
    d: dict | None = None,
    dstr: str,
) -> InstructionSnapshot:
    """A diag row carrying a parseable ``meta`` operand tree -- routed through
    the canonical lift (``diag_row_has_operand_tree``).  The flat
    ``dest_stkoff`` / ``src_l_*`` fields are intentionally ``None`` so a passing
    test PROVES the operands were recovered from the operand tree, not the flat
    legacy path."""
    # NOTE: ``project_diag_instruction`` keys ``_OPCODE_NAME_TO_INSN_KIND`` on the
    # RAW Hex-Rays opcode name (``m_mov`` / ``m_add``), so the operand-tree diag
    # row must carry the raw name un-aliased (unlike the flat ``_insn`` helper).
    insn = InstructionSnapshot(
        index=index,
        ea=ea,
        opcode=0,
        opcode_name=opcode_name,
        dest_type=None,
        dest_stkoff=None,
        dest_size=d.get("size") if d is not None else None,
        src_l_type=None,
        src_l_stkoff=None,
        src_l_value=None,
        src_r_type=None,
        src_r_stkoff=None,
        src_r_value=None,
        dstr=dstr,
    )
    meta: dict = {}
    if l is not None:
        meta["l"] = l
    if r is not None:
        meta["r"] = r
    if d is not None:
        meta["d"] = d
    insn.meta = json.dumps(meta)
    return insn


def test_collects_return_slot_identity_carrier_from_meta_rich_diag_row() -> None:
    """A diag row whose ``meta`` carries an operand tree is lifted through the
    SAME canonical projection as the FlowGraph source; the stack-identity
    carrier and the return-register read are recovered from the operand tree
    (the flat fields are ``None``), yielding the same fact as the FlowGraph /
    meta-less shapes."""
    collector = ReturnSlotFactCollector()

    facts = collector.collect(
        _target(
            _meta_insn(
                index=0,
                ea=0x180014333,
                opcode_name="m_mov",
                l=_meta_stack(0x680),
                d=_meta_stack(0x7F0),
                dstr="mov %var_178.8, %var_8.8",
            ),
            _meta_insn(
                index=1,
                ea=0x1800143C5,
                opcode_name="m_mov",
                l=_meta_stack(0x7F0),
                d=_meta_reg(0),
                dstr="mov %var_8.8, rax.8",
            ),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_CALLS"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.kind == "ReturnCarrierFact"
    assert fact.semantic_key == (
        "return_carrier:slot=0x7f0:class=stack_identity_carrier:source=S:0x680"
    )
    assert fact.payload["carrier_class"] == "stack_identity_carrier"
    assert fact.payload["source_signature"] == "S:0x680"
    assert fact.source_ea == 0x180014333


def test_records_upstream_mba_for_stack_identity_carrier_from_meta_rich_diag_row() -> None:
    """The upstream-writer backward trace works on operand-tree diag rows too:
    the upstream MBA's structured source-stack identities are recovered from the
    operand tree (recursive ``stack_refs``), NOT parsed from the display text.

    EMBRACE: a meta-rich diag row that previously fell to the flat legacy path
    (no operand tree -> no recursive source offsets) now surfaces the same
    structured ``upstream_writer_source_storage_keys`` the FlowGraph source
    yields, because both route through ``project_diag_instruction``."""
    collector = ReturnSlotFactCollector()

    # Upstream MBA producer: add (%var_40 op %var_228), %var_7C8 with a nested
    # operand tree whose recursive stack_refs expose the source identities.
    upstream = _meta_insn(
        index=0,
        ea=0x180014333,
        opcode_name="m_add",
        l=_meta_stack(0x40),
        r=_meta_stack(0x228),
        d=_meta_stack(0x7C8),
        dstr="add %var_40.8, %var_228.8, %var_7C8.8",
    )
    carrier = _meta_insn(
        index=1,
        ea=0x1800143C5,
        opcode_name="m_mov",
        l=_meta_stack(0x7C8),
        d=_meta_stack(0x8),
        dstr="mov %var_7C8.8, %var_8.8",
    )
    rax_trampoline = _meta_insn(
        index=2,
        ea=0x1800143D0,
        opcode_name="m_mov",
        l=_meta_stack(0x8),
        d=_meta_reg(0),
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
    assert fact.payload["carrier_class"] == "stack_identity_carrier"
    assert fact.payload["carrier_dst_stkoff"] == 0x7C8
    assert fact.payload["upstream_writer_block_serial"] == 10
    assert fact.payload["upstream_writer_opcode"] == "add"
    assert fact.payload["upstream_writer_dest_stkoff"] == 0x7C8
    # The structured source identities are recovered from the recursive operand
    # tree -- not the display text -- proving the canonical lift route.
    assert set(fact.payload["upstream_writer_source_storage_keys"]) == {"S64", "S552"}
    assert fact.evidence == (
        "mov %var_7C8.8, %var_8.8",
        "add %var_40.8, %var_228.8, %var_7C8.8",
    )


def test_meta_less_attrs_only_row_yields_no_observations() -> None:
    """A meta-less row -- ``meta`` carrying only attrs with no operand tree --
    stays on the byte-identical legacy flat path.  With no operand tree and no
    flat return-register read, the collector yields zero observations, exactly
    as before the port."""
    collector = ReturnSlotFactCollector()

    carrier = _insn(
        index=0,
        opcode_name="m_mov",
        dest_type="mop_S",
        dest_stkoff=0x8,
        src_l_type="mop_S",
        src_l_stkoff=0x7C8,
        dstr="mov %var_7C8.8, %var_8.8",
    )
    # Return-register read row whose ``meta`` is attrs-only (no l/r/d operand
    # tree) and whose flat fields omit the register identity -> meta-less path,
    # so ``_is_return_register_read`` never fires and no slot is resolved.
    attrs_only = _insn(
        index=1,
        dest_type="mop_r",
        dest_stkoff=None,
        src_l_type="mop_S",
        src_l_stkoff=0x8,
        dstr="mov %var_8.8, rax.8",
    )
    attrs_only.meta = json.dumps({"byte_index": 1})

    facts = collector.collect(
        _target(carrier, attrs_only),
        func_ea=0x180012cf0,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    assert facts == ()

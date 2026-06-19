from __future__ import annotations

from dataclasses import replace

import d810.backends.llvm.emitter as llvm_emitter
from d810.backends.llvm import (
    LlvmIdentityManifestMemory,
    LlvmIdentityParityStatus,
    check_identity_manifest,
    check_identity_roundtrip,
    emit_flowgraph_to_llvm,
)
from d810.backends.llvm.identity_lowering import build_identity_manifest
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.ir.instructions import (
    Instruction,
    InstructionEffect,
    InstructionEffectKind,
    InstructionMemoryAccess,
    InstructionMemoryAccessKind,
)
from d810.ir.semantics import CallKind, PredicateKind
from d810.ir.varnode import Space, Varnode


def _reg(register_id: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.REGISTER, reg=register_id, size=size)


def _stk(offset: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.STACK, stkoff=offset, size=size)


def _num(value: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.NUMBER, value=value, size=size)


def _block_ref(serial: int) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.BLOCK, block_ref=serial)


def _case_list(cases: tuple[tuple[tuple[int, ...], int], ...]) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.CASE_LIST, switch_cases=cases)


def _mov(src: MopSnapshot, dst: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(opcode=0x04, ea=0x1000, operands=(), kind=InsnKind.MOV, l=src, d=dst)


def _add(lhs: MopSnapshot, rhs: MopSnapshot, dst: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=0x12,
        ea=0x1004,
        operands=(),
        kind=InsnKind.ADD,
        l=lhs,
        r=rhs,
        d=dst,
    )


def _ret(value: MopSnapshot | None = None) -> InsnSnapshot:
    return InsnSnapshot(opcode=0x42, ea=0x1010, operands=(), kind=InsnKind.RET, l=value)


def _jcc(predicate: PredicateKind, lhs: MopSnapshot, rhs: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=0x2C,
        ea=0x2000,
        operands=(),
        kind=InsnKind.EQUALITY_JUMP,
        branch_predicate=predicate,
        l=lhs,
        r=rhs,
        d=_block_ref(1),
    )


def _jtbl(
    selector: MopSnapshot | None,
    cases: tuple[tuple[tuple[int, ...], int], ...],
) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=0x35,
        ea=0x2030,
        operands=(),
        kind=InsnKind.TABLE_JUMP,
        l=selector,
        r=_case_list(cases),
    )


def _call(
    call_kind: CallKind,
    target: MopSnapshot | None,
    dst: MopSnapshot | None = None,
    *,
    arg: MopSnapshot | None = None,
) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=0x41,
        ea=0x3000,
        operands=(),
        kind=InsnKind.CALL,
        call_kind=call_kind,
        l=target,
        r=arg,
        d=dst,
    )


def _block(serial: int, succs: tuple[int, ...], insns: tuple[InsnSnapshot, ...]) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=0,
        succs=succs,
        preds=(),
        flags=0,
        start_ea=0x1000 + serial,
        insn_snapshots=insns,
    )


def _graph(*blocks: BlockSnapshot, entry: int = 0) -> FlowGraph:
    return FlowGraph(
        blocks={blk.serial: blk for blk in blocks},
        entry_serial=entry,
        func_ea=0x180000000,
        metadata={},
    )


def test_identity_roundtrip_passes_for_simple_arithmetic_return():
    flow = _graph(
        _block(
            0,
            (),
            (
                _mov(_num(7), _stk(0x10)),
                _add(_stk(0x10), _num(5), _reg(0)),
                _ret(_reg(0)),
            ),
        )
    )

    lift = emit_flowgraph_to_llvm(flow, function_name="identity_arith")
    parity = check_identity_roundtrip(flow, function_name="identity_arith", lift_result=lift)

    assert lift.supported
    assert lift.identity_manifest is not None
    assert parity.status is LlvmIdentityParityStatus.PASSED
    assert parity.block_count == 1
    assert parity.instruction_count == 3


def test_identity_roundtrip_uses_sanitized_function_name_for_parity():
    flow = _graph(_block(0, (), (_mov(_num(7), _reg(0)), _ret(_reg(0)))))

    lift = emit_flowgraph_to_llvm(flow, function_name="../escape")
    parity = check_identity_roundtrip(flow, function_name="../escape", lift_result=lift)

    assert lift.supported
    assert lift.identity_manifest is not None
    assert lift.identity_manifest.function_name == ".._escape"
    assert parity.status is LlvmIdentityParityStatus.PASSED


def test_identity_manifest_preserves_conditional_operand_multiplicity():
    flow = _graph(
        _block(0, (1, 2), (_jcc(PredicateKind.EQ, _reg(0), _reg(0)),)),
        _block(1, (), (_ret(),)),
        _block(2, (), (_ret(),)),
    )

    lift = emit_flowgraph_to_llvm(flow, function_name="identity_branch")
    parity = check_identity_roundtrip(flow, function_name="identity_branch", lift_result=lift)

    assert lift.supported
    assert parity.passed
    branch = lift.identity_manifest.blocks[0].instructions[0]
    assert branch.operation == "conditional_branch"
    assert len(branch.inputs) == 2
    assert branch.inputs[0] == branch.inputs[1]


def test_identity_roundtrip_preserves_table_branch_payload():
    cases = (((0,), 1), ((1, 2), 2), ((), 3))
    flow = _graph(
        _block(0, (1, 2, 3), (_jtbl(_stk(0x10), cases),)),
        _block(1, (), (_ret(_num(11)),)),
        _block(2, (), (_ret(_num(22)),)),
        _block(3, (), (_ret(_num(33)),)),
    )

    lift = emit_flowgraph_to_llvm(flow, function_name="identity_switch")
    parity = check_identity_roundtrip(flow, function_name="identity_switch", lift_result=lift)

    assert lift.supported
    assert parity.passed
    switch = lift.identity_manifest.blocks[0].instructions[0]
    assert switch.control is not None
    assert tuple((case.values, case.target) for case in switch.control.switch_cases) == cases


def test_identity_roundtrip_preserves_opaque_call_payload_and_effect():
    flow = _graph(
        _block(
            0,
            (),
            (_call(CallKind.INDIRECT, _reg(5, size=8), _reg(0), arg=_reg(5, size=8)), _ret()),
        )
    )

    lift = emit_flowgraph_to_llvm(flow, function_name="identity_call")
    parity = check_identity_roundtrip(flow, function_name="identity_call", lift_result=lift)

    assert lift.supported
    assert parity.passed
    call = lift.identity_manifest.blocks[0].instructions[0]
    assert call.operation == "indirect"
    assert len(call.inputs) == 2
    assert call.effects[0].kind == "call"
    assert call.control is not None
    assert call.control.call_kind == "indirect"
    assert call.control.call_target == call.inputs[0]


def test_identity_manifest_records_direct_cell_load_store_contract(monkeypatch):
    target = Varnode(Space.STACK, 0x10, 4)
    value = Varnode(Space.REGISTER, 0, 4)
    result_vn = Varnode(Space.REGISTER, 1, 4)
    store = Instruction(
        operation=ValueOpKind.STORE,
        inputs=(value, target),
        effects=(InstructionEffect(InstructionEffectKind.STORE, target=target, value=value),),
        memory=InstructionMemoryAccess(
            kind=InstructionMemoryAccessKind.DIRECT_CELL,
            target=target,
            value=value,
            width=4,
        ),
    )
    load = Instruction(
        operation=ValueOpKind.LOAD,
        inputs=(target,),
        result=result_vn,
        memory=InstructionMemoryAccess(
            kind=InstructionMemoryAccessKind.DIRECT_CELL,
            target=target,
            width=4,
        ),
    )
    flow = _graph(_block(0, (), (_ret(_reg(0)),)))
    monkeypatch.setattr(llvm_emitter, "_collect_instructions", lambda _flow: {0: (store, load)})

    lift = emit_flowgraph_to_llvm(flow, function_name="identity_memory")

    assert lift.supported
    assert lift.identity_manifest is not None
    store_manifest = lift.identity_manifest.blocks[0].instructions[0]
    load_manifest = lift.identity_manifest.blocks[0].instructions[1]
    assert isinstance(store_manifest.memory, LlvmIdentityManifestMemory)
    assert store_manifest.memory.kind == "direct_cell"
    assert store_manifest.effects[0].target == store_manifest.memory.target
    assert store_manifest.effects[0].value == store_manifest.memory.value
    assert isinstance(load_manifest.memory, LlvmIdentityManifestMemory)
    assert load_manifest.memory.kind == "direct_cell"
    assert load_manifest.result is not None


def test_identity_roundtrip_is_unsupported_when_lift_is_unsupported():
    flow = _graph(_block(0, (), (_add(_reg(0), _reg(1, size=8), _reg(2)), _ret(_reg(2)))))

    lift = emit_flowgraph_to_llvm(flow, function_name="identity_unsupported")
    parity = check_identity_roundtrip(flow, function_name="identity_unsupported", lift_result=lift)

    assert not lift.supported
    assert lift.identity_manifest is None
    assert parity.status is LlvmIdentityParityStatus.UNSUPPORTED
    assert "unsupported" in (parity.reason or "")


def test_identity_manifest_corruption_fails_with_specific_mismatch():
    flow = _graph(_block(0, (), (_mov(_num(7), _reg(0)), _ret(_reg(0)))))
    lift = emit_flowgraph_to_llvm(flow, function_name="identity_corrupt")
    assert lift.identity_manifest is not None
    block = lift.identity_manifest.blocks[0]
    bad_instruction = replace(block.instructions[0], operation="sub")
    bad_block = replace(block, instructions=(bad_instruction, *block.instructions[1:]))
    bad_manifest = replace(lift.identity_manifest, blocks=(bad_block,))

    parity = check_identity_manifest(flow, bad_manifest, function_name="identity_corrupt")

    assert parity.status is LlvmIdentityParityStatus.FAILED
    assert parity.mismatches
    assert parity.mismatches[0].kind == "operation"
    assert parity.mismatches[0].path == "blocks[0].instructions[0].operation"


def test_build_identity_manifest_uses_emitter_instruction_map_not_source_snapshots():
    target = Varnode(Space.STACK, 0x20, 4)
    value = Varnode(Space.REGISTER, 3, 4)
    store = Instruction(
        operation=ValueOpKind.STORE,
        inputs=(value, target),
        effects=(InstructionEffect(InstructionEffectKind.STORE, target=target, value=value),),
        memory=InstructionMemoryAccess(
            kind=InstructionMemoryAccessKind.DIRECT_CELL,
            target=target,
            value=value,
            width=4,
        ),
    )
    flow = _graph(_block(0, (), ()))

    manifest = build_identity_manifest(
        flow,
        {0: (store,)},
        (target, value),
        function_name="manual_manifest",
    )

    assert manifest.function_name == "manual_manifest"
    assert manifest.instruction_count == 1
    assert manifest.blocks[0].instructions[0].operation == "store"
    assert manifest.blocks[0].instructions[0].memory is not None

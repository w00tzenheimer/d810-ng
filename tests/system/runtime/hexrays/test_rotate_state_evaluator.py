"""Native MASM rotate helpers replay through the portable concrete evaluator."""

from __future__ import annotations

import pytest

import ida_hexrays
import idaapi
import idc

from d810.analyses.value_flow.state_write import (
    forward_eval_instruction,
    resolve_varnode_from_maps,
)
from d810.hexrays.mutation.ir_translator import capture_insn_snapshot
from d810.ir.expressions import ValueOpKind
from d810.ir.insn_projection import project_instruction_sequence
from d810.ir.varnode import Space
from tests.system.runtime.conftest import gen_microcode_at_maturity


def _native_rotate_sequence(function_name: str):
    function_ea = int(idc.get_name_ea_simple(function_name))
    assert function_ea != int(idaapi.BADADDR), function_name
    for maturity in (
        ida_hexrays.MMAT_PREOPTIMIZED,
        ida_hexrays.MMAT_LOCOPT,
        ida_hexrays.MMAT_CALLS,
        ida_hexrays.MMAT_GLBOPT1,
    ):
        mba = gen_microcode_at_maturity(function_ea, maturity)
        if mba is None:
            continue
        for serial in range(mba.qty):
            block = mba.get_mblock(serial)
            instruction = None if block is None else block.head
            while instruction is not None:
                snapshot = capture_insn_snapshot(instruction)
                sequence = project_instruction_sequence(snapshot)
                if any(
                    item.operation in {ValueOpKind.ROL, ValueOpKind.ROR}
                    for item in sequence
                ):
                    return sequence
                instruction = instruction.next
    pytest.fail(f"no rotate helper was lifted for {function_name}")


class TestNativeRotateStateEvaluator:
    binary_name = "rotate_state_evaluator.dll"

    @pytest.mark.parametrize(
        ("function_name", "operation", "value", "count", "expected"),
        (
            ("state_rotate_rol4", ValueOpKind.ROL, 0x12345678, 13, 0x8ACF0246),
            (
                "state_rotate_ror8",
                ValueOpKind.ROR,
                0x0123456789ABCDEF,
                17,
                0xE6F78091A2B3C4D5,
            ),
        ),
    )
    def test_native_rotate_fixture_replays_without_z3(
        self,
        libobfuscated_setup,
        function_name,
        operation,
        value,
        count,
        expected,
    ):
        sequence = _native_rotate_sequence(function_name)
        rotate = next(item for item in sequence if item.operation is operation)
        assert rotate.inputs[0].space is Space.REGISTER
        reg_map = {int(rotate.inputs[0].offset): value}
        if rotate.inputs[1].space in {Space.REGISTER, Space.TEMP}:
            reg_map[int(rotate.inputs[1].offset)] = count
        stk_map: dict[int, int] = {}

        for instruction in sequence:
            forward_eval_instruction(instruction, stk_map, reg_map, 0)

        result = resolve_varnode_from_maps(sequence[-1].result, stk_map, reg_map)
        assert result == expected, (
            tuple(item.operation for item in sequence),
            sequence,
            reg_map,
        )

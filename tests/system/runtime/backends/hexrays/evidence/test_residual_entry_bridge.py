"""Runtime checks for the live residual-entry bridge recognizer."""
from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.backends.hexrays.evidence.residual_entry_bridge import (
    predicate_arm_reaches_ea,
    recognize_conditional_handler_bridges,
    recognize_residual_entry_bridge,
)


STATE_REGISTER = 7


class _Block:
    def __init__(self, instructions, successors):
        self._successors = tuple(successors)
        self.start = instructions[0].ea if instructions else 0
        self.head = instructions[0] if instructions else None
        self.tail = instructions[-1] if instructions else None
        for current, following in zip(instructions, instructions[1:]):
            current.next = following
        if instructions:
            instructions[-1].next = None

    def nsucc(self):
        return len(self._successors)

    def succ(self, index):
        return self._successors[index]


def _reg(number):
    return SimpleNamespace(t=ida_hexrays.mop_r, r=number, size=4)


def _stack(offset, size=4):
    return SimpleNamespace(t=ida_hexrays.mop_S, s=SimpleNamespace(off=offset), size=size)


def _number(value):
    return SimpleNamespace(t=ida_hexrays.mop_n, nnn=SimpleNamespace(value=value))


def _derived(size=4):
    return SimpleNamespace(t=ida_hexrays.mop_d, size=size)


def _insn(opcode, ea, *, l=None, r=None, d=None):
    return SimpleNamespace(opcode=opcode, ea=ea, l=l, r=r, d=d, next=None)


def _mba(blocks):
    return SimpleNamespace(qty=len(blocks), get_mblock=lambda serial: blocks.get(int(serial)))


def _bridge_mba(*, predicate=None, store_destination=None):
    predicate = predicate if predicate is not None else _stack(0x20)
    store_destination = store_destination if store_destination is not None else _stack(0x80)
    return _mba(
        {
            0: _Block(
                [
                    _insn(ida_hexrays.m_mov, 0x0F0, l=_number(0x20), d=_reg(8)),
                    _insn(ida_hexrays.m_mov, 0x0F4, l=_number(0x10), d=_reg(STATE_REGISTER)),
                    _insn(
                        ida_hexrays.m_jnz,
                        0x100,
                        l=predicate,
                        r=_number(0),
                        d=SimpleNamespace(b=2),
                    )
                ],
                [1, 2],
            ),
            1: _Block([_insn(ida_hexrays.m_mov, 0x110, l=_reg(8), d=_reg(STATE_REGISTER))], [2]),
            2: _Block([_insn(ida_hexrays.m_mov, 0x120, l=_reg(STATE_REGISTER), d=store_destination)], []),
        }
    )


def test_recognizes_default_plus_one_arm_overwrite_into_merged_state_store():
    result = recognize_residual_entry_bridge(_bridge_mba())

    assert result is not None
    assert result.predicate_ea == 0x100
    assert result.condition_code == 5
    assert result.stack_cell_identity == (0x80, 4)
    assert result.taken_state_constant == 0x10
    assert result.fallthrough_state_constant == 0x20
    assert result.source_store_ea == 0x120


def test_abstains_when_predicate_is_not_a_direct_frame_operand():
    assert recognize_residual_entry_bridge(_bridge_mba(predicate=_reg(3))) is None


def test_abstains_when_merge_store_is_not_a_direct_stack_cell():
    assert recognize_residual_entry_bridge(_bridge_mba(store_destination=_reg(4))) is None


def _handler_bridge_mba(
    *,
    opcode=ida_hexrays.m_jnz,
    compared=None,
    predicate=None,
    include_inherited_state_write=True,
    include_predicate_setup=True,
):
    compared = compared if compared is not None else _number(0)
    predicate = predicate if predicate is not None else _reg(44)
    source_instructions = []
    if include_inherited_state_write:
        source_instructions.append(
            _insn(
                ida_hexrays.m_mov,
                0x200,
                l=_number(0xA5A94B86),
                d=_reg(STATE_REGISTER),
            )
        )
    if include_predicate_setup:
        source_instructions.append(
            _insn(
                ida_hexrays.m_mov,
                0x208,
                l=_number(1),
                d=_reg(44),
            )
        )
    source_instructions.append(
        _insn(
            opcode,
            0x210,
            l=predicate,
            r=compared,
            d=SimpleNamespace(b=2),
        )
    )
    return _mba(
        {
            0: _Block(
                source_instructions,
                [1, 2],
            ),
            1: _Block([], []),
            2: _Block(
                [
                    _insn(
                        ida_hexrays.m_mov,
                        0x220,
                        l=_number(0x304E8694),
                        d=_reg(STATE_REGISTER),
                    )
                ],
                [],
            ),
        }
    )


def test_recognizes_register_nonzero_handler_arms_and_inherited_state():
    (result,) = recognize_conditional_handler_bridges(
        _handler_bridge_mba(),
        state_register=STATE_REGISTER,
        state_targets={0xA5A94B86: 0x3000, 0x304E8694: 0x4000},
    )

    assert result.source_block_ea == 0x200
    assert result.predicate_ea == 0x210
    assert result.predicate_register == 44
    assert result.predicate_size == 4
    assert result.predicate_predecessor_ea == 0x208
    assert result.true_state == 0x304E8694
    assert result.true_target_ea == 0x4000
    assert result.false_state == 0xA5A94B86
    assert result.false_target_ea == 0x3000


def test_normalizes_jz_handler_arms_to_register_nonzero_polarity():
    (result,) = recognize_conditional_handler_bridges(
        _handler_bridge_mba(opcode=ida_hexrays.m_jz),
        state_register=STATE_REGISTER,
        state_targets={0xA5A94B86: 0x3000, 0x304E8694: 0x4000},
    )

    assert result.true_target_ea == 0x3000
    assert result.false_target_ea == 0x4000


def test_recognizes_register_comparison_handler_arms():
    (result,) = recognize_conditional_handler_bridges(
        _handler_bridge_mba(compared=_reg(45)),
        state_register=STATE_REGISTER,
        state_targets={0xA5A94B86: 0x3000, 0x304E8694: 0x4000},
    )

    assert result.predicate_register == 44
    assert result.predicate_compare_register == 45
    assert result.true_target_ea == 0x4000
    assert result.false_target_ea == 0x3000


def test_recognizes_register_constant_comparison_handler_arms():
    (result,) = recognize_conditional_handler_bridges(
        _handler_bridge_mba(compared=_number(0x62)),
        state_register=STATE_REGISTER,
        state_targets={0xA5A94B86: 0x3000, 0x304E8694: 0x4000},
    )

    assert result.predicate_register == 44
    assert result.predicate_compare_constant == 0x62
    assert result.true_target_ea == 0x4000
    assert result.false_target_ea == 0x3000


def test_uses_pre_dce_arm_states_for_live_predicate_after_calls_fold():
    mba = _handler_bridge_mba(
        compared=_derived(),
        predicate=_derived(),
        include_inherited_state_write=False,
        include_predicate_setup=False,
    )
    mba.get_mblock(2).head = None
    mba.get_mblock(2).tail = None

    (result,) = recognize_conditional_handler_bridges(
        mba,
        state_register=STATE_REGISTER,
        state_targets={0xA5A94B86: 0x3000, 0x304E8694: 0x4000},
        arm_states_by_predicate_ea={
            0x210: (0x304E8694, 0xA5A94B86),
        },
    )

    assert result.predicate_register is None
    assert result.predicate_compare_register is None
    assert result.predicate_compare_constant is None
    assert result.predicate_predecessor_ea is None
    assert result.true_state == 0x304E8694
    assert result.true_target_ea == 0x4000
    assert result.false_state == 0xA5A94B86
    assert result.false_target_ea == 0x3000


def test_recognizes_folded_inherited_state_from_route_evidence():
    (result,) = recognize_conditional_handler_bridges(
        _handler_bridge_mba(
            compared=_number(0x62),
            include_inherited_state_write=False,
        ),
        state_register=STATE_REGISTER,
        state_targets={0xA5A94B86: 0x3000, 0x304E8694: 0x4000},
        inherited_states_by_predicate_ea={0x210: 0xA5A94B86},
    )

    assert result.predicate_ea == 0x210
    assert result.predicate_compare_constant == 0x62
    assert result.false_state == 0xA5A94B86


def test_exact_route_state_outranks_stale_merged_local_write():
    (result,) = recognize_conditional_handler_bridges(
        _handler_bridge_mba(compared=_number(0x62)),
        state_register=STATE_REGISTER,
        state_targets={0x742F372A: 0x3000, 0x304E8694: 0x4000},
        inherited_states_by_predicate_ea={0x210: 0x742F372A},
    )

    assert result.predicate_ea == 0x210
    assert result.true_state == 0x304E8694
    assert result.false_state == 0x742F372A


def test_recognizes_live_nested_predicate_without_reconstruction_identity():
    nested_predicate = SimpleNamespace(t=ida_hexrays.mop_d, size=4)
    (result,) = recognize_conditional_handler_bridges(
        _handler_bridge_mba(
            compared=_number(0x62),
            predicate=nested_predicate,
            include_inherited_state_write=False,
        ),
        state_register=STATE_REGISTER,
        state_targets={0xA5A94B86: 0x3000, 0x304E8694: 0x4000},
        inherited_states_by_predicate_ea={0x210: 0xA5A94B86},
    )

    assert result.predicate_register is None
    assert result.predicate_compare_constant == 0x62
    assert result.true_is_taken is True


def test_predicate_arm_reaches_route_ea_through_bounded_microcode_path():
    mba = _handler_bridge_mba(compared=_reg(45))

    assert predicate_arm_reaches_ea(
        mba,
        predicate_ea=0x210,
        route_ea=0x220,
    )
    assert not predicate_arm_reaches_ea(
        mba,
        predicate_ea=0x210,
        route_ea=0x999,
    )


def test_conditional_handler_bridge_abstains_without_both_state_targets():
    assert recognize_conditional_handler_bridges(
        _handler_bridge_mba(),
        state_register=STATE_REGISTER,
        state_targets={0xA5A94B86: 0x3000},
    ) == ()

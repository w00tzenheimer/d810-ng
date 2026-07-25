"""Runtime checks for the live residual-entry bridge recognizer."""

from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.backends.hexrays.evidence.residual_entry_bridge import (
    predicate_arm_reaches_ea,
    recognize_conditional_handler_bridges,
    recognize_preoptimized_residual_entry_bridge,
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
    return SimpleNamespace(
        t=ida_hexrays.mop_S, s=SimpleNamespace(off=offset), size=size
    )


def _number(value):
    return SimpleNamespace(t=ida_hexrays.mop_n, nnn=SimpleNamespace(value=value))


def _derived(size=4):
    return SimpleNamespace(t=ida_hexrays.mop_d, size=size)


def _nested(opcode, *, left, size=1):
    return SimpleNamespace(
        t=ida_hexrays.mop_d,
        d=_insn(opcode, 0, left=left),
        size=size,
    )


def _insn(opcode, ea, *, left=None, r=None, d=None):
    return SimpleNamespace(opcode=opcode, ea=ea, l=left, r=r, d=d, next=None)


def _mba(blocks):
    return SimpleNamespace(
        qty=len(blocks),
        get_mblock=lambda serial: blocks.get(int(serial)),
        stkoff_vd2ida=lambda off: int(off) - 0x40,
    )


def _block_instructions(block):
    current = block.head
    result = []
    while current is not None:
        result.append(current)
        if current is block.tail:
            break
        current = current.next
    return tuple(result)


def _bridge_mba(*, predicate=None, store_destination=None):
    predicate = predicate if predicate is not None else _stack(0x20)
    store_destination = (
        store_destination if store_destination is not None else _stack(0x80)
    )
    return _mba(
        {
            0: _Block(
                [
                    _insn(ida_hexrays.m_mov, 0x0F0, left=_number(0x20), d=_reg(8)),
                    _insn(
                        ida_hexrays.m_mov,
                        0x0F4,
                        left=_number(0x10),
                        d=_reg(STATE_REGISTER),
                    ),
                    _insn(
                        ida_hexrays.m_jnz,
                        0x100,
                        left=predicate,
                        r=_number(0),
                        d=SimpleNamespace(b=2),
                    ),
                ],
                [1, 2],
            ),
            1: _Block(
                [_insn(ida_hexrays.m_mov, 0x110, left=_reg(8), d=_reg(STATE_REGISTER))],
                [2],
            ),
            2: _Block(
                [
                    _insn(
                        ida_hexrays.m_mov,
                        0x120,
                        left=_reg(STATE_REGISTER),
                        d=store_destination,
                    )
                ],
                [],
            ),
        }
    )


def test_recognizes_default_plus_one_arm_overwrite_into_merged_state_store():
    result = recognize_residual_entry_bridge(_bridge_mba())

    assert result is not None
    assert result.predicate_ea == 0x100
    assert result.conditional_tail_ea == 0x100
    assert result.condition_code == 5
    assert result.stack_cell_identity == (0x80, 4)
    assert result.taken_state_constant == 0x10
    assert result.fallthrough_state_constant == 0x20
    assert result.source_store_ea == 0x120
    assert result.canonical_predicate_stack_identity == (-0x20, 4)


def test_abstains_when_predicate_is_not_a_direct_frame_operand():
    assert recognize_residual_entry_bridge(_bridge_mba(predicate=_reg(3))) is None


def test_abstains_when_merge_store_is_not_a_direct_stack_cell():
    assert (
        recognize_residual_entry_bridge(_bridge_mba(store_destination=_reg(4))) is None
    )


def _preoptimized_bridge_mba(
    *,
    condition_register=99,
    branch_register=99,
    native_ea_target=False,
):
    branch_target = (
        SimpleNamespace(
            t=ida_hexrays.mop_v,
            g=0x120,
            b=None,
        )
        if native_ea_target
        else SimpleNamespace(t=ida_hexrays.mop_b, b=2)
    )
    return _mba(
        {
            0: _Block(
                [
                    _insn(
                        ida_hexrays.m_setz,
                        0x100,
                        left=_stack(0x20),
                        r=_number(0),
                        d=_reg(condition_register),
                    ),
                    _insn(
                        ida_hexrays.m_mov,
                        0x104,
                        left=_number(0x20),
                        d=_reg(8),
                    ),
                    _insn(
                        ida_hexrays.m_mov,
                        0x108,
                        left=_number(0x10),
                        d=_reg(STATE_REGISTER),
                    ),
                    _insn(
                        ida_hexrays.m_jcnd,
                        0x10C,
                        left=_nested(
                            ida_hexrays.m_lnot,
                            left=_reg(branch_register),
                        ),
                        d=branch_target,
                    ),
                ],
                [],
            ),
            1: _Block(
                [
                    _insn(
                        ida_hexrays.m_mov,
                        0x110,
                        left=_reg(8),
                        d=_reg(STATE_REGISTER),
                    )
                ],
                [],
            ),
            2: _Block(
                [
                    _insn(
                        ida_hexrays.m_mov,
                        0x120,
                        left=_reg(STATE_REGISTER),
                        d=_stack(0x80),
                    )
                ],
                [],
            ),
        }
    )


def test_recognizes_preoptimized_setz_lnot_cmov_lowering_without_cfg_edges():
    result = recognize_preoptimized_residual_entry_bridge(_preoptimized_bridge_mba())

    assert result is not None
    assert result.predicate_ea == 0x100
    assert result.conditional_tail_ea == 0x10C
    assert result.condition_code == 5
    assert result.predicate_stack_identity == (0x20, 4)
    assert result.stack_cell_identity == (0x80, 4)
    assert result.taken_state_constant == 0x10
    assert result.fallthrough_state_constant == 0x20
    assert result.source_store_ea == 0x120
    assert result.canonical_stack_cell_identity == (0x40, 4)
    assert result.canonical_predicate_stack_identity == (-0x20, 4)
    assert result.predicate_block_ea == 0x100
    assert result.taken_arm_entry_ea == 0x120
    assert result.fallthrough_arm_entry_ea == 0x110


def test_preoptimized_recognizer_abstains_on_unrelated_condition_flag():
    assert (
        recognize_preoptimized_residual_entry_bridge(
            _preoptimized_bridge_mba(branch_register=100)
        )
        is None
    )


def test_preoptimized_recognizer_resolves_native_ea_branch_target():
    result = recognize_preoptimized_residual_entry_bridge(
        _preoptimized_bridge_mba(native_ea_target=True)
    )

    assert result is not None
    assert result.source_store_ea == 0x120


def test_preoptimized_recognizer_applies_register_moves_before_state_store():
    mba = _mba(
        {
            0: _Block(
                [
                    _insn(
                        ida_hexrays.m_setz,
                        0x100,
                        left=_stack(0x20),
                        r=_number(0),
                        d=_reg(99),
                    ),
                    _insn(
                        ida_hexrays.m_mov,
                        0x104,
                        left=_number(0x10),
                        d=_reg(STATE_REGISTER),
                    ),
                    _insn(
                        ida_hexrays.m_jcnd,
                        0x108,
                        left=_nested(ida_hexrays.m_lnot, left=_reg(99)),
                        d=SimpleNamespace(t=ida_hexrays.mop_b, b=2),
                    ),
                ],
                [],
            ),
            1: _Block(
                [
                    _insn(
                        ida_hexrays.m_mov,
                        0x110,
                        left=_number(0x30),
                        d=_reg(9),
                    ),
                    _insn(
                        ida_hexrays.m_mov,
                        0x114,
                        left=_reg(9),
                        d=_reg(STATE_REGISTER),
                    ),
                    _insn(
                        ida_hexrays.m_mov,
                        0x120,
                        left=_reg(STATE_REGISTER),
                        d=_stack(0x80),
                    ),
                ],
                [],
            ),
            2: _Block(
                [
                    _insn(
                        ida_hexrays.m_mov,
                        0x120,
                        left=_reg(STATE_REGISTER),
                        d=_stack(0x80),
                    )
                ],
                [],
            ),
        }
    )

    result = recognize_preoptimized_residual_entry_bridge(mba)

    assert result is not None
    assert result.taken_state_constant == 0x10
    assert result.fallthrough_state_constant == 0x30


def test_preoptimized_recognizer_abstains_when_flag_is_overwritten_before_branch():
    mba = _preoptimized_bridge_mba()
    source = mba.get_mblock(0)
    instructions = list(_block_instructions(source))
    instructions.insert(
        -1,
        _insn(
            ida_hexrays.m_mov,
            0x10A,
            left=_number(1),
            d=_reg(99),
        ),
    )
    mba = _mba(
        {
            0: _Block(instructions, []),
            1: mba.get_mblock(1),
            2: mba.get_mblock(2),
        }
    )

    assert recognize_preoptimized_residual_entry_bridge(mba) is None


def test_preoptimized_recognizer_abstains_on_mid_block_native_ea_target():
    mba = _preoptimized_bridge_mba(native_ea_target=True)
    target = mba.get_mblock(2)
    target_instructions = [
        _insn(
            ida_hexrays.m_mov,
            0x118,
            left=_number(0),
            d=_reg(55),
        ),
        *_block_instructions(target),
    ]
    mba = _mba(
        {
            0: mba.get_mblock(0),
            1: mba.get_mblock(1),
            2: _Block(target_instructions, []),
        }
    )

    assert recognize_preoptimized_residual_entry_bridge(mba) is None


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
                left=_number(0xA5A94B86),
                d=_reg(STATE_REGISTER),
            )
        )
    if include_predicate_setup:
        source_instructions.append(
            _insn(
                ida_hexrays.m_mov,
                0x208,
                left=_number(1),
                d=_reg(44),
            )
        )
    source_instructions.append(
        _insn(
            opcode,
            0x210,
            left=predicate,
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
                        left=_number(0x304E8694),
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


def test_recognizes_ordered_handler_predicate_with_taken_state_preserved():
    (result,) = recognize_conditional_handler_bridges(
        _handler_bridge_mba(
            opcode=ida_hexrays.m_jg,
            compared=_number(6),
        ),
        state_register=STATE_REGISTER,
        state_targets={0xA5A94B86: 0x3000, 0x304E8694: 0x4000},
    )

    assert result.condition_code == 15
    assert result.predicate_compare_constant == 6
    assert result.true_is_taken is True
    assert result.true_state == 0x304E8694
    assert result.true_target_ea == 0x4000
    assert result.false_state == 0xA5A94B86
    assert result.false_target_ea == 0x3000


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


def test_recognizes_import_owned_opaque_jcnd_with_exact_state_arms():
    opaque_condition = _derived(size=1)
    empty_right = SimpleNamespace(t=ida_hexrays.mop_z, size=0)
    mba = _handler_bridge_mba(
        opcode=ida_hexrays.m_jcnd,
        compared=empty_right,
        predicate=opaque_condition,
        include_predicate_setup=False,
    )
    source_instructions = list(_block_instructions(mba.get_mblock(0)))
    source_instructions.insert(
        -1,
        _insn(
            ida_hexrays.m_mov,
            0x208,
            left=_number(0x304E8694),
            d=_reg(44),
        ),
    )
    mba = _mba(
        {
            0: _Block(source_instructions, [1, 2]),
            1: mba.get_mblock(1),
            2: _Block(
                [
                    _insn(
                        ida_hexrays.m_mov,
                        0x220,
                        left=_reg(44),
                        d=_reg(STATE_REGISTER),
                    )
                ],
                [],
            ),
        }
    )
    state_targets = {0xA5A94B86: 0x3000, 0x304E8694: 0x4000}

    assert (
        recognize_conditional_handler_bridges(
            mba,
            state_register=STATE_REGISTER,
            state_targets=state_targets,
        )
        == ()
    )

    (result,) = recognize_conditional_handler_bridges(
        mba,
        state_register=STATE_REGISTER,
        state_targets=state_targets,
        preserve_live_predicate_eas=frozenset({0x210}),
    )

    assert result.predicate_ea == 0x210
    assert result.condition_code == 5
    assert result.predicate_register is None
    assert result.predicate_compare_constant is None
    assert result.true_is_taken is True
    assert result.true_state == 0x304E8694
    assert result.false_state == 0xA5A94B86


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
    assert (
        recognize_conditional_handler_bridges(
            _handler_bridge_mba(),
            state_register=STATE_REGISTER,
            state_targets={0xA5A94B86: 0x3000},
        )
        == ()
    )

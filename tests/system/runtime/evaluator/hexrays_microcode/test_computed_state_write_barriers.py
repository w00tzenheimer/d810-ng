"""Reaching-definition barriers in the live computed-state-write adapter."""

from types import SimpleNamespace

import ida_hexrays

from tests.system.runtime.evaluator.hexrays_microcode.test_resolve_state_write_value_set import (
    _A,
    _STATE_OFF,
    _block,
    _insn,
    _mba,
    _mop_n,
    _mop_S,
)


def test_partitioned_register_fold_does_not_walk_through_a_clobber():
    from d810.evaluator.hexrays_microcode.dynamic_state_write_backend import (
        resolve_computed_state_write,
    )

    def reg(index):
        return SimpleNamespace(t=ida_hexrays.mop_r, r=index, size=4)

    for kill in (
        _insn(ida_hexrays.m_call),
        _insn(ida_hexrays.m_mov, l=reg(20), d=reg(16)),
        _insn(ida_hexrays.m_xor, l=reg(16), r=reg(20), d=reg(16)),
    ):
        mba = _mba(
            {
                0: _block(_insn(ida_hexrays.m_mov, l=_mop_n(_A), d=reg(16))),
                1: _block(kill, predset=(0,)),
                2: _block(
                    _insn(ida_hexrays.m_mov, l=reg(16), d=_mop_S(_STATE_OFF)),
                    predset=(1,),
                ),
            }
        )
        result = resolve_computed_state_write(
            mba=mba, block_serial=2, state_var_stkoff=_STATE_OFF
        )
        assert not result.resolved
        assert not result.values


def test_partitioned_register_fold_rejects_a_changed_writer_block_operand():
    from d810.evaluator.hexrays_microcode.dynamic_state_write_backend import (
        resolve_computed_state_write,
    )

    def reg(index):
        return SimpleNamespace(t=ida_hexrays.mop_r, r=index, size=4)

    mba = _mba(
        {
            0: _block(_insn(ida_hexrays.m_mov, l=_mop_n(_A), d=reg(16))),
            1: _block(
                _insn(ida_hexrays.m_xor, l=reg(16), r=reg(20), d=reg(16)),
                _insn(ida_hexrays.m_mov, l=reg(16), d=_mop_S(_STATE_OFF)),
                predset=(0,),
            ),
        }
    )
    result = resolve_computed_state_write(
        mba=mba, block_serial=1, state_var_stkoff=_STATE_OFF
    )
    assert not result.resolved
    assert not result.values


def test_partitioned_register_fold_rejects_narrow_operands():
    from d810.evaluator.hexrays_microcode.dynamic_state_write_backend import (
        resolve_computed_state_write,
    )

    def reg(size):
        return SimpleNamespace(t=ida_hexrays.mop_r, r=16, size=size)

    mba = _mba(
        {
            0: _block(_insn(ida_hexrays.m_mov, l=_mop_n(0x12345678), d=reg(4))),
            1: _block(
                _insn(ida_hexrays.m_mov, l=reg(1), d=_mop_S(_STATE_OFF)), predset=(0,)
            ),
        }
    )
    result = resolve_computed_state_write(
        mba=mba, block_serial=1, state_var_stkoff=_STATE_OFF
    )
    assert not result.resolved


def test_partitioned_register_fold_rejects_unmodeled_intermediate_width():
    from d810.evaluator.hexrays_microcode.dynamic_state_write_backend import (
        resolve_computed_state_write,
    )

    reg = SimpleNamespace(t=ida_hexrays.mop_r, r=16, size=4)
    add = _insn(ida_hexrays.m_add, l=reg, r=_mop_n(1))
    expression = SimpleNamespace(t=ida_hexrays.mop_d, d=add, size=4)
    mba = _mba(
        {
            0: _block(_insn(ida_hexrays.m_mov, l=_mop_n(0xFFFFFFFF), d=reg)),
            1: _block(
                _insn(
                    ida_hexrays.m_shr, l=expression, r=_mop_n(1), d=_mop_S(_STATE_OFF)
                ),
                predset=(0,),
            ),
        }
    )
    result = resolve_computed_state_write(
        mba=mba, block_serial=1, state_var_stkoff=_STATE_OFF
    )
    # The real 32-bit expression is zero, not the 64-bit fold's 0x80000000.
    assert not result.resolved

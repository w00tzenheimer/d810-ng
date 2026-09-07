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


def test_partitioned_fold_does_not_reuse_storage_after_addressed_stores():
    from d810.evaluator.hexrays_microcode.dynamic_state_write_backend import (
        resolve_computed_state_write,
    )

    for prefix, unknown_address in ((False, False), (True, False), (False, True)):
        reg = SimpleNamespace(t=ida_hexrays.mop_r, r=16, size=4)
        address = SimpleNamespace(t=ida_hexrays.mop_a, a=_mop_S(0x80), size=8)
        if unknown_address:
            address = SimpleNamespace(t=ida_hexrays.mop_r, r=24, size=8)
        store = _insn(ida_hexrays.m_stx, l=_mop_n(0x200), r=_mop_n(0, 2), d=address)
        seed = [
            _insn(ida_hexrays.m_mov, l=_mop_n(0x100), d=_mop_S(0x80)),
            _insn(ida_hexrays.m_mov, l=_mop_n(1), d=reg),
        ]
        writer = _insn(ida_hexrays.m_xor, l=_mop_S(0x80), r=reg, d=_mop_S(_STATE_OFF))
        mba = _mba(
            {
                0: _block(*seed, *([] if prefix else [store])),
                1: _block(*([store] if prefix else []), writer, predset=(0,)),
            }
        )
        result = resolve_computed_state_write(
            mba=mba, block_serial=1, state_var_stkoff=_STATE_OFF
        )
        assert not result.resolved, (prefix, unknown_address, result)


def test_partitioned_fold_normalizes_mapped_lvar_storage_aliases():
    from d810.evaluator.hexrays_microcode.dynamic_state_write_backend import (
        resolve_computed_state_write,
    )

    reg = SimpleNamespace(t=ida_hexrays.mop_r, r=16, size=4)
    lvar = SimpleNamespace(t=ida_hexrays.mop_l, l=SimpleNamespace(idx=0), size=4)
    mba = _mba(
        {
            0: _block(
                _insn(ida_hexrays.m_mov, l=_mop_n(0x100), d=_mop_S(0x80)),
                _insn(ida_hexrays.m_mov, l=_mop_n(1), d=reg),
                _insn(ida_hexrays.m_mov, l=_mop_n(0x200), d=lvar),
            ),
            1: _block(
                _insn(ida_hexrays.m_xor, l=_mop_S(0x80), r=reg, d=_mop_S(_STATE_OFF)),
                predset=(0,),
            ),
        }
    )
    mba.maturity = ida_hexrays.MMAT_LVARS
    mba.vars = [
        SimpleNamespace(
            location=SimpleNamespace(is_stkoff=lambda: True, stkoff=lambda: 0x80)
        )
    ]
    result = resolve_computed_state_write(
        mba=mba, block_serial=1, state_var_stkoff=_STATE_OFF
    )
    assert not result.resolved or result.values == frozenset({0x201})


def test_partitioned_lvar_fold_rejects_unmapped_register_clobbers():
    from d810.evaluator.hexrays_microcode.dynamic_state_write_backend import (
        resolve_computed_state_write,
    )

    local = SimpleNamespace(t=ida_hexrays.mop_l, l=SimpleNamespace(idx=0), size=4)
    for kill in (
        _insn(ida_hexrays.m_call),
        _insn(
            ida_hexrays.m_mov,
            l=_mop_n(0x200),
            d=SimpleNamespace(t=ida_hexrays.mop_r, r=16, size=4),
        ),
    ):
        mba = _mba(
            {
                0: _block(_insn(ida_hexrays.m_mov, l=_mop_n(0x100), d=local), kill),
                1: _block(
                    _insn(
                        ida_hexrays.m_xor, l=local, r=_mop_n(1), d=_mop_S(_STATE_OFF)
                    ),
                    predset=(0,),
                ),
            }
        )
        result = resolve_computed_state_write(
            mba=mba, block_serial=1, state_var_stkoff=_STATE_OFF
        )
        assert not result.resolved


def test_lvar_mapping_checks_sdk_preconditions_before_union_access():
    from d810.evaluator.hexrays_microcode.dynamic_state_write_backend import (
        _computed_operand_lvar_stkoff,
    )

    invalid_accesses = []
    location = SimpleNamespace(
        is_stkoff=lambda: False, stkoff=lambda: invalid_accesses.append("stkoff") or 80
    )
    mba = SimpleNamespace(
        maturity=ida_hexrays.MMAT_LVARS, vars=[SimpleNamespace(location=location)]
    )
    assert _computed_operand_lvar_stkoff(mba, 0) is None
    assert not invalid_accesses

    class EarlyMba:
        maturity = ida_hexrays.MMAT_GLBOPT1

        @property
        def vars(self):
            invalid_accesses.append("vars")
            return []

    assert _computed_operand_lvar_stkoff(EarlyMba(), 0) is None
    assert not invalid_accesses


def test_unknown_call_invalidates_computed_stack_operands():
    from d810.evaluator.hexrays_microcode.dynamic_state_write_backend import (
        resolve_computed_state_write,
    )

    mba = _mba(
        {
            0: _block(
                _insn(ida_hexrays.m_mov, l=_mop_n(0x100), d=_mop_S(0x80)),
                _insn(ida_hexrays.m_mov, l=_mop_n(1), d=_mop_S(0x90)),
                _insn(ida_hexrays.m_call),
            ),
            1: _block(
                _insn(
                    ida_hexrays.m_xor,
                    l=_mop_S(0x80),
                    r=_mop_S(0x90),
                    d=_mop_S(_STATE_OFF),
                ),
                predset=(0,),
            ),
        }
    )
    result = resolve_computed_state_write(
        mba=mba, block_serial=1, state_var_stkoff=_STATE_OFF
    )
    assert not result.resolved

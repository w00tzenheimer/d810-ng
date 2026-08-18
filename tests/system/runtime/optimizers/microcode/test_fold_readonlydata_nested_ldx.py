from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.optimizers.microcode.instructions.peephole.fold_readonlydata import (
    FoldReadonlyDataRule,
)


class _Mop:
    def __init__(self, mop_type: int, size: int = 0, **attrs) -> None:
        self.t = mop_type
        self.size = size
        for name, value in attrs.items():
            setattr(self, name, value)

    def __bool__(self) -> bool:
        return self.t != ida_hexrays.mop_z

    def make_number(self, value: int, size: int, *_args) -> None:
        self.t = ida_hexrays.mop_n
        self.size = size
        self.nnn = SimpleNamespace(value=value)


def test_destinationless_nested_ldx_folds_owning_operand_to_immediate() -> None:
    """A value-only table lookup must replace its owning mop, not emit an ldc."""
    table_ea = 0x1800296A0
    offset = 0x6E
    expected_value = 0x7B

    symbol = _Mop(
        ida_hexrays.mop_S,
        8,
        s=SimpleNamespace(start_ea=table_ea),
    )
    address = _Mop(ida_hexrays.mop_a, 8, a=symbol)
    displacement = _Mop(
        ida_hexrays.mop_n,
        8,
        nnn=SimpleNamespace(value=offset),
    )
    add = SimpleNamespace(
        opcode=ida_hexrays.m_add,
        l=address,
        r=displacement,
    )
    load = SimpleNamespace(
        opcode=ida_hexrays.m_ldx,
        l=_Mop(ida_hexrays.mop_r, 2),
        r=_Mop(ida_hexrays.mop_d, 8, d=add),
        d=_Mop(ida_hexrays.mop_z, 1),
    )
    owner = _Mop(ida_hexrays.mop_d, 1, d=load)

    decisions: list[tuple[int, int, str]] = []
    rule = object.__new__(FoldReadonlyDataRule)

    def decide(ea: int, size: int, *, site: str):
        decisions.append((ea, size, site))
        return SimpleNamespace(can_inline_read=True, value=expected_value)

    rule._decision_for = decide

    changed = rule._fold_readonly_inplace(owner)

    assert changed is True
    assert decisions == [(table_ea + offset, 1, "expr-ldx")]
    assert owner.t == ida_hexrays.mop_n
    assert owner.size == 1
    assert owner.nnn.value == expected_value

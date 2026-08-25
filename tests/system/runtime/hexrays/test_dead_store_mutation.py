"""Apply-time safety checks for guarded dead-store removal."""

from __future__ import annotations

from types import SimpleNamespace

import pytest


ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier  # noqa: E402


class _Instruction:
    ea = 0x401010
    opcode = ida_hexrays.m_mov
    next = None

    def __init__(self, *, effectful: bool) -> None:
        self.d = SimpleNamespace(
            t=ida_hexrays.mop_r,
            r=7,
            size=8,
        )
        self.effectful = effectful

    def has_side_effects(self, include_ldx_and_divs: bool) -> bool:
        assert include_ldx_and_divs is False
        return self.effectful


class _Block:
    serial = 3
    start = 0x401000

    def __init__(self, instruction: _Instruction) -> None:
        self.head = instruction
        self.removed = []
        self.lists_dirtied = False

    def remove_from_block(self, instruction: _Instruction) -> None:
        self.removed.append(instruction)

    def mark_lists_dirty(self) -> None:
        self.lists_dirtied = True


def test_guarded_remove_rejects_effectful_instruction_after_planning() -> None:
    instruction = _Instruction(effectful=True)
    block = _Block(instruction)
    mba = SimpleNamespace(chains_dirtied=False)
    mba.mark_chains_dirty = lambda: setattr(mba, "chains_dirtied", True)
    modifier = DeferredGraphModifier(mba)

    changed = modifier._apply_guarded_insn_remove(
        block,
        block_start_ea=0x401000,
        insn_ea=0x401010,
        ordinal=0,
        opcode=ida_hexrays.m_mov,
        destination_kind="register",
        destination_id=7,
        destination_size=8,
    )

    assert changed is False
    assert block.removed == []
    assert block.lists_dirtied is False
    assert mba.chains_dirtied is False


def test_coalesce_keeps_distinct_guarded_removals_in_one_block() -> None:
    modifier = DeferredGraphModifier(SimpleNamespace())
    for ordinal, ea, destination_id in (
        (5, 0x401050, 11),
        (3, 0x401030, 12),
    ):
        modifier.queue_guarded_insn_remove(
            block_serial=3,
            block_start_ea=0x401000,
            insn_ea=ea,
            ordinal=ordinal,
            opcode=ida_hexrays.m_mov,
            destination_kind="register",
            destination_id=destination_id,
            destination_size=8,
        )

    removed = modifier.coalesce()

    assert removed == 0
    assert len(modifier.modifications) == 2

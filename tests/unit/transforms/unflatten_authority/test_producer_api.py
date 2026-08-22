from __future__ import annotations

import pytest
from types import SimpleNamespace

from d810.ir.flowgraph import BlockKind, BlockSnapshot, InsnKind, InsnSnapshot, MopSnapshot
from d810.ir.semantics import ControlTransferKind
from d810.transforms.unflatten_authority.model import EffectSiteKind, TerminalKind
from d810.transforms.unflatten_authority import producer_api as producer_module
from d810.transforms.unflatten_authority.model import (
    InventoryInstructionObservation,
    resolve_inventory_block_sites,
)
from d810.transforms.unflatten_authority.producer_api import (
    classify_block_effects_and_terminals,
)


def _block(*instructions: InsnSnapshot, kind: BlockKind = BlockKind.UNKNOWN, succs: tuple[int, ...] = ()) -> BlockSnapshot:
    return BlockSnapshot(1, 0, succs, (), 0, 0x1000, instructions, kind=kind)


@pytest.mark.parametrize(
    ("insn_kind", "effect_kind", "terminal_kind"),
    [
        (InsnKind.STORE, EffectSiteKind.STORE, None),
        (InsnKind.TRAP, EffectSiteKind.TRAP, TerminalKind.TRAP),
        (InsnKind.RET, EffectSiteKind.RETURN, TerminalKind.RETURN),
        (InsnKind.CALL, EffectSiteKind.CALL, TerminalKind.NORETURN_CALL),
    ],
)
def test_classifier_emits_exact_effect_and_terminal_rows(
    insn_kind: InsnKind, effect_kind: EffectSiteKind, terminal_kind: TerminalKind | None,
) -> None:
    insn = InsnSnapshot(0x42, 0x1000, (), kind=insn_kind, l=MopSnapshot(size=2), r=MopSnapshot(size=4))
    effects, terminals = classify_block_effects_and_terminals(_block(insn), owner_ref=None, owner_anchor_ea=0x1000)
    assert len(effects) == 1
    assert effects[0].effect_kind is effect_kind
    assert effects[0].opcode == 0x42
    assert effects[0].width == 4
    if terminal_kind is None:
        assert terminals == ()
    else:
        assert terminals[0].terminal_kind is terminal_kind


def test_classifier_emits_call_terminal_and_synthesized_stop() -> None:
    call = InsnSnapshot(0x42, 0x1000, (), kind=InsnKind.CALL)
    effects, terminals = classify_block_effects_and_terminals(
        _block(call, kind=BlockKind.STOP), owner_ref=None, owner_anchor_ea=0x1000,
    )
    assert effects[0].effect_kind is EffectSiteKind.CALL
    assert {item.terminal_kind for item in terminals} == {TerminalKind.NORETURN_CALL}

    effects, terminals = classify_block_effects_and_terminals(
        _block(kind=BlockKind.STOP), owner_ref=None, owner_anchor_ea=0x1000,
    )
    assert effects == ()
    assert terminals[0].terminal_kind is TerminalKind.STOP
    assert terminals[0].instruction_ordinal is None


def test_inventory_adapter_retains_generated_candidate_control_transfer_without_ea() -> None:
    generated = BlockSnapshot(
        7, 0, (8,), (), 0, 0xFFFFFFFFFFFFFFFF,
        (InsnSnapshot(
            0x42, 0xFFFFFFFFFFFFFFFF, (), kind=InsnKind.GOTO,
            control_transfer_kind=ControlTransferKind.GOTO,
        ),),
        kind=BlockKind.UNKNOWN,
    )
    observed = producer_module.observe_inventory_block(
        generated, owner_ref=None, owner_anchor_ea=None,
    )
    assert observed.successor_serials == (8,)
    assert observed.transfer_ea is None
    assert observed.instruction_observations[0].instruction_ea is None
    assert observed.instruction_observations[0].control_transfer_kind is ControlTransferKind.GOTO


def test_classifier_uses_return_transfer_and_rejects_overlap_or_missing_ea() -> None:
    with pytest.raises(TypeError):
        classify_block_effects_and_terminals(
            _block(SimpleNamespace(kind=InsnKind.STORE, native_ea=0x1000, ea=0x1000, opcode=1)),
            owner_ref=None, owner_anchor_ea=0x1000,
        )
    effects, terminals = classify_block_effects_and_terminals(
        _block(InsnSnapshot(0x42, 0xFFFFFFFFFFFFFFFF, (), kind=InsnKind.NOP)),
        owner_ref=None, owner_anchor_ea=0x1000,
    )
    assert effects == () and terminals == ()
    returned = InsnSnapshot(0x42, 0x1000, (), control_transfer_kind=ControlTransferKind.RETURN)
    effects, terminals = classify_block_effects_and_terminals(_block(returned), owner_ref=None, owner_anchor_ea=0x1000)
    assert effects[0].effect_kind is EffectSiteKind.RETURN
    assert terminals[0].terminal_kind is TerminalKind.RETURN

    with pytest.raises(ValueError, match="overlap"):
        classify_block_effects_and_terminals(
            _block(InsnSnapshot(0x42, 0x1000, (), kind=InsnKind.STORE, is_call=True)),
            owner_ref=None, owner_anchor_ea=0x1000,
        )
    with pytest.raises(ValueError, match="native"):
        classify_block_effects_and_terminals(
            _block(InsnSnapshot(0x42, 0xFFFFFFFFFFFFFFFF, (), kind=InsnKind.STORE)),
            owner_ref=None, owner_anchor_ea=0x1000,
        )

    with pytest.raises(ValueError, match="duplicate"):
        classify_block_effects_and_terminals(
            _block(
                InsnSnapshot(0x42, 0x1000, (), kind=InsnKind.STORE),
                InsnSnapshot(0x43, 0x1000, (), kind=InsnKind.STORE),
            ),
            owner_ref=None, owner_anchor_ea=0x1000,
        )


def test_classifier_revalidates_corrupted_empty_block_scalars() -> None:
    block = _block()
    object.__setattr__(block, "serial", -1)
    with pytest.raises(ValueError):
        classify_block_effects_and_terminals(block, owner_ref=None, owner_anchor_ea=0x1000)


def test_producer_classifier_delegates_to_one_neutral_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[object, ...]] = []
    original = producer_module.resolve_inventory_block_sites

    def spy(**kwargs: object) -> object:
        calls.append(tuple(kwargs["instruction_observations"]))
        return original(**kwargs)

    monkeypatch.setattr(producer_module, "resolve_inventory_block_sites", spy)
    block = _block(InsnSnapshot(0x42, 0x1000, (), kind=InsnKind.STORE))
    effects, terminals = classify_block_effects_and_terminals(
        block, owner_ref=None, owner_anchor_ea=0x1000,
    )
    assert len(calls) == 1
    rows = calls[0]
    assert all(type(row) is InventoryInstructionObservation for row in rows)
    expected = resolve_inventory_block_sites(
        serial=block.serial, owner_ref=None, owner_anchor_ea=0x1000,
        block_kind=block.kind, successor_serials=block.succs,
        instruction_observations=rows,
    )
    assert (effects, terminals) == expected


def test_classifier_rejects_non_tail_control_transfer() -> None:
    block = _block(
        InsnSnapshot(0x42, 0x1000, (), kind=InsnKind.GOTO),
        InsnSnapshot(0x43, 0x1004, (), kind=InsnKind.NOP),
        succs=(2,),
    )
    with pytest.raises(ValueError, match="tail"):
        classify_block_effects_and_terminals(block, owner_ref=None, owner_anchor_ea=0x1000)


@pytest.mark.parametrize("kind", (InsnKind.RET, InsnKind.GOTO))
def test_classifier_rejects_post_init_erased_raw_transfer_marker(kind: InsnKind) -> None:
    instruction = InsnSnapshot(0x42, 0x1000, (), kind=kind)
    object.__setattr__(instruction, "control_transfer_kind", None)
    with pytest.raises(ValueError, match="requires control transfer"):
        classify_block_effects_and_terminals(
            _block(instruction, succs=(2,) if kind is InsnKind.GOTO else ()),
            owner_ref=None,
            owner_anchor_ea=0x1000,
        )


@pytest.mark.parametrize("kind", (InsnKind.NOP, InsnKind.STORE, InsnKind.CALL))
def test_classifier_rejects_foreign_transfer_marker(kind: InsnKind) -> None:
    instruction = InsnSnapshot(
        0x42, 0x1000, (), kind=kind, control_transfer_kind=ControlTransferKind.GOTO,
    )
    with pytest.raises(ValueError, match="must not carry control transfer"):
        classify_block_effects_and_terminals(
            _block(instruction), owner_ref=None, owner_anchor_ea=0x1000,
        )


@pytest.mark.parametrize("transfer", (ControlTransferKind.GOTO, ControlTransferKind.RETURN))
def test_classifier_accepts_unknown_kind_recovered_transfer(transfer: ControlTransferKind) -> None:
    instruction = InsnSnapshot(0x42, 0x1000, (), control_transfer_kind=transfer)
    classify_block_effects_and_terminals(
        _block(instruction), owner_ref=None, owner_anchor_ea=0x1000,
    )

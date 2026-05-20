from __future__ import annotations

from types import SimpleNamespace

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.cfg.dispatcher_residue_cleanup_planning import (
    DispatcherResidueCleanupPlan,
    DispatcherResidueTwoWayConversion,
    UnreachableRegionBlockPlan,
    UnreachableRegionCleanupPlan,
    UnreachableRegionForwardRedirect,
)
from d810.hexrays.mutation import dispatcher_residue_cleanup as cleanup


class _Insn:
    def __init__(self, ea: int) -> None:
        self.ea = int(ea)
        self.next: _Insn | None = None


def _insn_chain(*eas: int) -> tuple[_Insn | None, _Insn | None]:
    insns = [_Insn(ea) for ea in eas]
    for left, right in zip(insns, insns[1:]):
        left.next = right
    if not insns:
        return None, None
    return insns[0], insns[-1]


class _Block:
    def __init__(
        self,
        serial: int,
        *,
        succs: tuple[int, ...] = (),
        preds: tuple[int, ...] = (),
        insn_eas: tuple[int, ...] = (),
    ) -> None:
        self.serial = int(serial)
        self.succs = list(succs)
        self.preds = list(preds)
        self.head, self.tail = _insn_chain(*insn_eas)
        self.nopped: list[int] = []

    def nsucc(self) -> int:
        return len(self.succs)

    def succ(self, index: int) -> int:
        return self.succs[index]

    def npred(self) -> int:
        return len(self.preds)

    def pred(self, index: int) -> int:
        return self.preds[index]


class _Mba:
    def __init__(self, blocks: tuple[_Block, ...]) -> None:
        self.blocks = {block.serial: block for block in blocks}

    def get_mblock(self, serial: int) -> _Block | None:
        return self.blocks.get(int(serial))


class _FakeDeferredGraphModifier:
    instances: list["_FakeDeferredGraphModifier"] = []

    def __init__(self, mba: _Mba) -> None:
        self.mba = mba
        self.modifications: list[tuple[str, int, int]] = []
        self.apply_kwargs: dict | None = None
        self.__class__.instances.append(self)

    def queue_remove_edge(
        self,
        from_serial: int,
        to_serial: int,
        description: str = "",
    ) -> None:
        self.modifications.append(("remove", int(from_serial), int(to_serial)))

    def queue_convert_to_goto(
        self,
        block_serial: int,
        goto_target: int,
        description: str = "",
    ) -> None:
        self.modifications.append(("convert", int(block_serial), int(goto_target)))

    def queue_goto_change(
        self,
        block_serial: int,
        new_target: int,
        description: str = "",
        **_kwargs,
    ) -> None:
        self.modifications.append(("goto", int(block_serial), int(new_target)))

    def queue_insn_nop(
        self,
        block_serial: int,
        insn_ea: int,
        description: str = "",
    ) -> None:
        self.modifications.append(("nop", int(block_serial), int(insn_ea)))

    def apply(self, **kwargs) -> int:
        self.apply_kwargs = dict(kwargs)
        applied = 0
        for op, source, target in self.modifications:
            block = self.mba.get_mblock(source)
            if block is None:
                continue
            if op == "remove":
                if target in block.succs:
                    block.succs.remove(target)
                target_block = self.mba.get_mblock(target)
                if target_block is not None and source in target_block.preds:
                    target_block.preds.remove(source)
                applied += 1
            elif op == "convert":
                for old_target in tuple(block.succs):
                    old_block = self.mba.get_mblock(old_target)
                    if old_block is not None and source in old_block.preds:
                        old_block.preds.remove(source)
                block.succs = [target]
                target_block = self.mba.get_mblock(target)
                if target_block is not None and source not in target_block.preds:
                    target_block.preds.append(source)
                applied += 1
            elif op == "goto":
                old_targets = tuple(block.succs)
                block.succs = [target]
                for old_target in old_targets:
                    old_block = self.mba.get_mblock(old_target)
                    if old_block is not None and source in old_block.preds:
                        old_block.preds.remove(source)
                target_block = self.mba.get_mblock(target)
                if target_block is not None and source not in target_block.preds:
                    target_block.preds.append(source)
                applied += 1
            elif op == "nop":
                block.nopped.append(target)
                applied += 1
        return applied


@pytest.fixture(autouse=True)
def _use_fake_deferred_modifier(monkeypatch):
    _FakeDeferredGraphModifier.instances = []
    monkeypatch.setattr(
        cleanup,
        "DeferredGraphModifier",
        _FakeDeferredGraphModifier,
    )


def _logger() -> SimpleNamespace:
    return SimpleNamespace(
        info=lambda *args, **kwargs: None,
        warning=lambda *args, **kwargs: None,
    )


def test_dispatcher_residue_cleanup_queues_deferred_edge_and_branch_edits() -> None:
    mba = _Mba(
        (
            _Block(2, succs=(30, 31), preds=(10, 11)),
            _Block(10, succs=(2,), preds=()),
            _Block(11, succs=(2, 20), preds=()),
            _Block(20, preds=(11,)),
            _Block(30, preds=(2,)),
            _Block(31, preds=(2,)),
        )
    )
    plan = DispatcherResidueCleanupPlan(
        dispatcher_serial=2,
        one_way_edge_severs=(10,),
        two_way_conversions=(
            DispatcherResidueTwoWayConversion(
                block_serial=11,
                keep_successor=20,
                old_successors=(2, 20),
            ),
        ),
        dispatcher_outgoing_successors=(30, 31),
    )

    result = cleanup.apply_dispatcher_residue_cleanup_plan(
        mba,  # type: ignore[arg-type]
        plan,
        logger=_logger(),
    )

    assert result.severed_1way == 1
    assert result.converted_2way == 1
    assert result.dispatcher_outgoing_severed == 2
    assert len(_FakeDeferredGraphModifier.instances) == 2
    assert _FakeDeferredGraphModifier.instances[0].modifications == [
        ("remove", 10, 2),
        ("convert", 11, 20),
    ]
    assert _FakeDeferredGraphModifier.instances[1].modifications == [
        ("remove", 2, 30),
        ("remove", 2, 31),
    ]
    assert _FakeDeferredGraphModifier.instances[0].apply_kwargs == {
        "run_optimize_local": False,
        "run_deep_cleaning": False,
        "verify_each_mod": False,
        "rollback_on_verify_failure": False,
        "defer_post_apply_maintenance": True,
    }


def test_unreachable_region_cleanup_queues_deferred_nops_conversions_and_redirects() -> None:
    mba = _Mba(
        (
            _Block(5, succs=(8, 9), preds=(), insn_eas=(0x1000, 0x1004, 0x1008)),
            _Block(6, succs=(5,), preds=(), insn_eas=(0x2000, 0x2004)),
            _Block(8, preds=(5,)),
            _Block(9, preds=(5,)),
            _Block(99, preds=()),
        )
    )
    plan = UnreachableRegionCleanupPlan(
        stop_serial=99,
        cleanup_candidates=frozenset((5, 6)),
        blocks=(
            UnreachableRegionBlockPlan(block_serial=5, successors=(8, 9)),
            UnreachableRegionBlockPlan(block_serial=6, successors=(5,)),
        ),
        forward_redirects=(
            UnreachableRegionForwardRedirect(
                block_serial=6,
                old_target=5,
                new_target=99,
            ),
        ),
    )

    result = cleanup.apply_unreachable_region_cleanup_plan(
        mba,  # type: ignore[arg-type]
        plan,
        logger=_logger(),
    )

    assert result.gutted == 2
    assert result.redirected == 1
    assert len(_FakeDeferredGraphModifier.instances) == 2
    assert _FakeDeferredGraphModifier.instances[0].modifications == [
        ("nop", 5, 0x1000),
        ("nop", 5, 0x1004),
        ("convert", 5, 8),
        ("nop", 6, 0x2000),
    ]
    assert _FakeDeferredGraphModifier.instances[1].modifications == [
        ("goto", 6, 99),
    ]
    assert mba.blocks[5].nopped == [0x1000, 0x1004]
    assert mba.blocks[6].nopped == [0x2000]
    assert mba.blocks[5].succs == [8]
    assert mba.blocks[6].succs == [99]


def test_unreachable_region_cleanup_rejects_unsupported_multi_successor_blocks() -> None:
    mba = _Mba(
        (
            _Block(5, succs=(8, 9, 10), preds=(), insn_eas=(0x1000, 0x1004)),
            _Block(8, preds=(5,)),
            _Block(9, preds=(5,)),
            _Block(10, preds=(5,)),
        )
    )
    plan = UnreachableRegionCleanupPlan(
        stop_serial=99,
        cleanup_candidates=frozenset((5,)),
        blocks=(
            UnreachableRegionBlockPlan(block_serial=5, successors=(8, 9, 10)),
        ),
        forward_redirects=(),
    )

    result = cleanup.apply_unreachable_region_cleanup_plan(
        mba,  # type: ignore[arg-type]
        plan,
        logger=_logger(),
    )

    assert result.gutted == 0
    assert result.redirected == 0
    assert len(_FakeDeferredGraphModifier.instances) == 1
    assert _FakeDeferredGraphModifier.instances[0].modifications == []
    assert mba.blocks[5].nopped == []
    assert mba.blocks[5].succs == [8, 9, 10]


def test_unreachable_region_cleanup_rejects_redirect_source_outside_cleanup_set() -> None:
    mba = _Mba(
        (
            _Block(5, succs=(8, 9), preds=(6,), insn_eas=(0x1000, 0x1004)),
            _Block(6, succs=(5,), preds=()),
            _Block(8, preds=(5,)),
            _Block(9, preds=(5,)),
            _Block(99, preds=()),
        )
    )
    plan = UnreachableRegionCleanupPlan(
        stop_serial=99,
        cleanup_candidates=frozenset((5,)),
        blocks=(
            UnreachableRegionBlockPlan(block_serial=5, successors=(8, 9)),
        ),
        forward_redirects=(
            UnreachableRegionForwardRedirect(
                block_serial=6,
                old_target=5,
                new_target=99,
            ),
        ),
    )

    result = cleanup.apply_unreachable_region_cleanup_plan(
        mba,  # type: ignore[arg-type]
        plan,
        logger=_logger(),
    )

    assert result.gutted == 1
    assert result.redirected == 0
    assert len(_FakeDeferredGraphModifier.instances) == 2
    assert _FakeDeferredGraphModifier.instances[0].modifications == [
        ("nop", 5, 0x1000),
        ("convert", 5, 8),
    ]
    assert _FakeDeferredGraphModifier.instances[1].modifications == []
    assert mba.blocks[6].succs == [5]


def test_unreachable_region_cleanup_applies_redirect_only_dead_zone_shells() -> None:
    mba = _Mba(
        (
            _Block(5, succs=(6,), preds=()),
            _Block(6, succs=(99,), preds=(5,)),
            _Block(99, preds=(6,)),
        )
    )
    plan = UnreachableRegionCleanupPlan(
        stop_serial=99,
        cleanup_candidates=frozenset((5, 6)),
        blocks=(
            UnreachableRegionBlockPlan(block_serial=5, successors=(6,)),
            UnreachableRegionBlockPlan(block_serial=6, successors=(99,)),
        ),
        forward_redirects=(
            UnreachableRegionForwardRedirect(
                block_serial=5,
                old_target=6,
                new_target=99,
            ),
        ),
    )

    result = cleanup.apply_unreachable_region_cleanup_plan(
        mba,  # type: ignore[arg-type]
        plan,
        logger=_logger(),
    )

    assert result.gutted == 2
    assert result.redirected == 1
    assert len(_FakeDeferredGraphModifier.instances) == 2
    assert _FakeDeferredGraphModifier.instances[0].modifications == []
    assert _FakeDeferredGraphModifier.instances[1].modifications == [
        ("goto", 5, 99),
    ]
    assert mba.blocks[5].succs == [99]

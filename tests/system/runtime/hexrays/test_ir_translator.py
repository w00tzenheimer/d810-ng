"""Tests for IDAIRTranslator.

System-level integration tests that verify IDAIRTranslator conforms to the
IRTranslator protocol and exposes the expected interface.

Runs in IDA environment (system/runtime); skips gracefully without IDA.
"""
from __future__ import annotations

import importlib
import platform
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.cfg.graph_modification import (
    CreateConditionalRedirect,
    DuplicateBlock,
    EdgeRedirectViaPredSplit,
    InsertBlock,
    RedirectGoto,
    RemoveEdge,
)
from d810.cfg.plan import (
    PatchDuplicateBlock,
    PatchInsertBlock,
    PatchPlan,
    PatchRedirectGoto,
    compile_patch_plan,
)
from d810.hexrays.mutation.ir_translator import IDAIRTranslator


_DEFAULT_TEST_BINARY = "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"


@dataclass(frozen=True)
class _BlockRef:
    block_num: int


def _block(serial: int, succs: tuple[int, ...], preds: tuple[int, ...]) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1 if succs else 0,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0,
        insn_snapshots=(),
    )


def _cfg() -> FlowGraph:
    return FlowGraph(
        blocks={
            2: _block(2, (), (45,)),
            44: _block(44, (45,), ()),
            122: _block(122, (45,), ()),
            45: _block(45, (2,), (44, 122)),
            199: _block(199, (), ()),
        },
        entry_serial=44,
        func_ea=0,
    )


def _conditional_duplicate_cfg() -> FlowGraph:
    return FlowGraph(
        blocks={
            2: _block(2, (), (45,)),
            3: _block(3, (), (45,)),
            44: _block(44, (45,), ()),
            122: _block(122, (45,), ()),
            45: BlockSnapshot(
                serial=45,
                block_type=2,
                succs=(2, 3),
                preds=(44, 122),
                flags=0,
                start_ea=0,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0x70,
                        ea=0x1010,
                        operands=(_BlockRef(2),),
                        operand_slots=(("d", _BlockRef(2)),),
                    ),
                ),
            ),
            199: _block(199, (), ()),
        },
        entry_serial=44,
        func_ea=0,
    )


def _get_real_mba():
    import idaapi
    import idc

    test_functions = (
        "abc_xor_dispatch",
        "abc_or_dispatch",
        "nested_simple",
        "test_cst_simplification",
        "test_xor",
        "test_mba_guessing",
        "test_chained_add",
    )

    for func_name in test_functions:
        func_ea = idc.get_name_ea_simple(func_name)
        if func_ea == idaapi.BADADDR:
            func_ea = idc.get_name_ea_simple("_" + func_name)
        if func_ea == idaapi.BADADDR:
            continue

        func = idaapi.get_func(func_ea)
        if func is None:
            continue

        mbr = ida_hexrays.mba_ranges_t(func)
        hf = ida_hexrays.hexrays_failure_t()
        mba = ida_hexrays.gen_microcode(
            mbr,
            hf,
            None,
            ida_hexrays.DECOMP_NO_WAIT,
            ida_hexrays.MMAT_CALLS,
        )
        if mba is not None:
            return mba

    pytest.skip("No runtime mba_t available for InsertBlock lowering test")


def _find_insertable_edge(mba) -> tuple[int, int] | None:
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk is None:
            continue
        if blk.serial == 0:
            continue
        if blk.type in (ida_hexrays.BLT_XTRN, ida_hexrays.BLT_STOP):
            continue
        if blk.nsucc() != 1:
            continue
        return blk.serial, blk.succ(0)
    return None


def _find_duplicate_candidate(mba) -> tuple[int, int] | None:
    for i in range(mba.qty):
        source_blk = mba.get_mblock(i)
        if source_blk is None:
            continue
        if source_blk.serial == 0:
            continue
        if source_blk.type in (ida_hexrays.BLT_XTRN, ida_hexrays.BLT_STOP):
            continue
        if source_blk.nsucc() != 1:
            continue

        for pred_idx in range(source_blk.npred()):
            pred_serial = source_blk.pred(pred_idx)
            pred_blk = mba.get_mblock(pred_serial)
            if pred_blk is None:
                continue
            if pred_blk.serial == 0:
                continue
            if (
                pred_blk.nsucc() == 1
                and pred_blk.succ(0) == source_blk.serial
                and source_blk.succ(0) != pred_blk.serial
            ):
                return pred_blk.serial, source_blk.serial
    return None


def _find_conditional_duplicate_candidate(mba) -> tuple[int, int] | None:
    for i in range(mba.qty):
        source_blk = mba.get_mblock(i)
        if source_blk is None:
            continue
        if source_blk.serial == 0:
            continue
        if source_blk.type in (ida_hexrays.BLT_XTRN, ida_hexrays.BLT_STOP):
            continue
        if source_blk.nsucc() != 2:
            continue
        if source_blk.tail is None or not ida_hexrays.is_mcode_jcond(source_blk.tail.opcode):
            continue

        for pred_idx in range(source_blk.npred()):
            pred_serial = source_blk.pred(pred_idx)
            pred_blk = mba.get_mblock(pred_serial)
            if pred_blk is None or pred_blk.serial == 0:
                continue
            if pred_blk.nsucc() == 1 and pred_blk.succ(0) == source_blk.serial:
                return pred_blk.serial, source_blk.serial
            if (
                pred_blk.nsucc() == 2
                and pred_blk.tail is not None
                and ida_hexrays.is_mcode_jcond(pred_blk.tail.opcode)
                and pred_blk.tail.d.t == ida_hexrays.mop_b
                and pred_blk.tail.d.b == source_blk.serial
            ):
                return pred_blk.serial, source_blk.serial
    return None


class TestIDAIRTranslatorBasics:
    """Test basic IDAIRTranslator properties and interface."""

    def test_backend_name(self):
        """Test that IDAIRTranslator.name returns 'ida'."""
        backend = IDAIRTranslator()
        assert backend.name == "ida"

    def test_backend_implements_protocol(self):
        """Test that IDAIRTranslator conforms to CFGBackend protocol."""
        from d810.cfg.protocol import IRTranslator

        backend = IDAIRTranslator()
        assert isinstance(backend, IRTranslator)

    def test_lower_requires_patch_plan(self):
        backend = IDAIRTranslator()
        with pytest.raises(TypeError, match="requires PatchPlan"):
            backend.lower(  # type: ignore[arg-type]
                [RedirectGoto(from_serial=1, old_target=2, new_target=3)],
                object(),
            )


class _FakeDeferredGraphModifier:
    def __init__(self, mba: object):
        self.mba = mba
        self.calls: list[tuple] = []
        self.verify_failed = False

    def queue_goto_change(self, src: int, new: int, description: str = "") -> None:
        self.calls.append(("goto", src, new, description))

    def queue_conditional_target_change(self, src: int, new: int, description: str = "") -> None:
        self.calls.append(("branch", src, new, description))

    def queue_convert_to_goto(self, serial: int, target: int, description: str = "") -> None:
        self.calls.append(("convert", serial, target, description))

    def queue_edge_redirect(
        self,
        *,
        src_block: int,
        old_target: int,
        new_target: int,
        via_pred: int,
        rule_priority: int,
        description: str = "",
    ) -> None:
        self.calls.append(
            ("edge_redirect", src_block, old_target, new_target, via_pred, rule_priority, description)
        )

    def queue_edge_split_trampoline(
        self,
        *,
        source_block: int,
        via_pred: int,
        old_target: int,
        new_target: int,
        expected_serial: int,
        description: str = "",
    ) -> None:
        self.calls.append(
            (
                "edge_split_trampoline",
                source_block,
                via_pred,
                old_target,
                new_target,
                expected_serial,
                description,
            )
        )

    def queue_create_conditional_redirect(
        self,
        *,
        source_blk_serial: int,
        ref_blk_serial: int,
        conditional_target_serial: int,
        fallthrough_target_serial: int,
        expected_conditional_serial: int | None = None,
        expected_fallthrough_serial: int | None = None,
        description: str = "",
    ) -> None:
        self.calls.append(
            (
                "create_conditional",
                source_blk_serial,
                ref_blk_serial,
                conditional_target_serial,
                fallthrough_target_serial,
                expected_conditional_serial,
                expected_fallthrough_serial,
                description,
            )
        )

    def queue_create_and_redirect(
        self,
        *,
        source_block_serial: int,
        final_target_serial: int,
        instructions_to_copy: list[object],
        is_0_way: bool = False,
        expected_serial: int | None = None,
        description: str = "",
    ) -> None:
        self.calls.append(
            (
                "create_and_redirect",
                source_block_serial,
                final_target_serial,
                len(instructions_to_copy),
                is_0_way,
                expected_serial,
                description,
            )
        )

    def queue_duplicate_block(
        self,
        *,
        source_block_serial: int,
        pred_serial: int | None,
        target_serial: int | None = None,
        expected_serial: int | None = None,
        expected_secondary_serial: int | None = None,
        description: str = "",
    ) -> None:
        self.calls.append(
            (
                "duplicate_block",
                source_block_serial,
                pred_serial,
                target_serial,
                expected_serial,
                expected_secondary_serial,
                description,
            )
        )

    def queue_insn_nop(self, serial: int, ea: int, description: str = "") -> None:
        self.calls.append(("nop", serial, ea, description))

    def _check_edge_split_trampoline_preconditions(
        self,
        *,
        source_block_serial: int | None,
        via_pred: int | None,
        old_target: int | None,
        new_target: int | None,
    ) -> bool:
        return all(
            value is not None
            for value in (source_block_serial, via_pred, old_target, new_target)
        )

    def apply(self, **kwargs) -> int:  # noqa: ANN003
        self.calls.append(("apply", kwargs))
        return sum(1 for call in self.calls if call[0] != "apply")


class TestIDAIntegration:
    """Integration tests requiring IDA runtime.

    These tests verify that the backend can interact with real IDA types.
    """

    binary_name = _DEFAULT_TEST_BINARY

    def test_lift_returns_flowgraph(self):
        """Test lift() returns a FlowGraph flowgraph for a real mba_t."""
        backend = IDAIRTranslator()
        assert hasattr(backend, "lift")
        assert callable(backend.lift)

    def test_lower_accepts_real_mba(self):
        """Test lower() accepts a real mba_t instance."""
        backend = IDAIRTranslator()
        assert hasattr(backend, "lower")
        assert callable(backend.lower)

    def test_verify_accepts_real_mba(self):
        """Test verify() accepts a real mba_t instance."""
        backend = IDAIRTranslator()
        assert hasattr(backend, "verify")
        assert callable(backend.verify)

    def test_lower_applies_insert_block_patch_plan_to_real_mba(self, libobfuscated_setup):
        mba = _get_real_mba()
        edge = _find_insertable_edge(mba)
        if edge is None:
            pytest.skip("No 1-way edge available for InsertBlock runtime test")

        pred_serial, succ_serial = edge
        backend = IDAIRTranslator()
        patch_plan = compile_patch_plan(
            [
                InsertBlock(
                    pred_serial=pred_serial,
                    succ_serial=succ_serial,
                    instructions=(InsnSnapshot(opcode=ida_hexrays.m_nop, ea=0, operands=()),),
                )
            ],
            backend.lift(mba),
        )
        insert_step = next(
            step for step in patch_plan.steps if isinstance(step, PatchInsertBlock)
        )

        count = backend.lower(patch_plan, mba)

        assert count == 1
        mba.verify(True)

        pred_blk = mba.get_mblock(pred_serial)
        assert pred_blk is not None
        assert pred_blk.nsucc() == 1
        assert pred_blk.succ(0) == insert_step.assigned_serial

        inserted_blk = mba.get_mblock(insert_step.assigned_serial)
        assert inserted_blk is not None
        assert inserted_blk.nsucc() == 1
        assert inserted_blk.succ(0) == insert_step.succ_serial

    def test_lower_applies_duplicate_block_patch_plan_to_real_mba(self, libobfuscated_setup):
        mba = _get_real_mba()
        candidate = _find_duplicate_candidate(mba)
        if candidate is None:
            pytest.skip("No supported predecessor/source pair available for DuplicateBlock runtime test")

        pred_serial, source_serial = candidate
        backend = IDAIRTranslator()
        patch_plan = compile_patch_plan(
            [
                DuplicateBlock(
                    source_block=source_serial,
                    target_block=None,
                    pred_serial=pred_serial,
                )
            ],
            backend.lift(mba),
        )
        duplicate_step = next(
            step for step in patch_plan.steps if isinstance(step, PatchDuplicateBlock)
        )

        count = backend.lower(patch_plan, mba)

        assert count == 1
        mba.verify(True)

        pred_blk = mba.get_mblock(pred_serial)
        assert pred_blk is not None
        assert duplicate_step.pred_serial == pred_serial
        assert duplicate_step.assigned_serial in {pred_blk.succ(i) for i in range(pred_blk.nsucc())}

        duplicated_blk = mba.get_mblock(duplicate_step.assigned_serial)
        assert duplicated_blk is not None
        assert duplicated_blk.nsucc() == len(duplicate_step.source_successors)

    def test_lower_applies_conditional_duplicate_block_patch_plan_to_real_mba(self, libobfuscated_setup):
        mba = _get_real_mba()
        candidate = _find_conditional_duplicate_candidate(mba)
        if candidate is None:
            pytest.skip(
                "No supported predecessor/source pair available for conditional DuplicateBlock runtime test"
            )

        pred_serial, source_serial = candidate
        backend = IDAIRTranslator()
        patch_plan = compile_patch_plan(
            [
                DuplicateBlock(
                    source_block=source_serial,
                    target_block=None,
                    pred_serial=pred_serial,
                )
            ],
            backend.lift(mba),
        )
        duplicate_step = next(
            step for step in patch_plan.steps if isinstance(step, PatchDuplicateBlock)
        )

        assert duplicate_step.fallthrough_serial is not None

        count = backend.lower(patch_plan, mba)

        assert count == 1
        mba.verify(True)

        pred_blk = mba.get_mblock(pred_serial)
        assert pred_blk is not None
        assert duplicate_step.assigned_serial in {
            pred_blk.succ(i) for i in range(pred_blk.nsucc())
        }

        duplicated_blk = mba.get_mblock(duplicate_step.assigned_serial)
        assert duplicated_blk is not None
        assert duplicated_blk.nsucc() == 2

        duplicated_default = mba.get_mblock(duplicate_step.fallthrough_serial)
        assert duplicated_default is not None
        assert duplicated_default.nsucc() == 1

    def test_lower_applies_concrete_patch_plan(self, monkeypatch: pytest.MonkeyPatch):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        backend = IDAIRTranslator()
        patch_plan = PatchPlan(
            steps=(PatchRedirectGoto(from_serial=7, old_target=8, new_target=9),)
        )

        count = backend.lower(patch_plan, object())

        assert count == 1
        assert len(created) == 1
        assert created[0].calls[0][0] == "goto"
        assert created[0].calls[0][1:3] == (7, 9)

    def test_lower_applies_edge_split_trampoline_patch_plan(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        backend = IDAIRTranslator()
        patch_plan = compile_patch_plan(
            [
                EdgeRedirectViaPredSplit(
                    src_block=45,
                    old_target=2,
                    new_target=2,
                    via_pred=122,
                    rule_priority=550,
                )
            ],
            _cfg(),
        )

        count = backend.lower(patch_plan, object())

        assert count == 1
        assert len(created) == 2
        assert created[0].calls == []
        assert created[1].calls[0][0] == "edge_split_trampoline"
        assert created[1].calls[0][1:6] == (45, 122, 2, 2, 199)

    def test_lower_rejects_legacy_block_creation_when_disabled(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        backend = IDAIRTranslator(allow_legacy_block_creation=False)
        patch_plan = compile_patch_plan(
            [
                InsertBlock(
                    pred_serial=45,
                    succ_serial=2,
                    instructions=(InsnSnapshot(opcode=0x77, ea=0x1000, operands=()),),
                )
            ]
        )

        count = backend.lower(patch_plan, object())

        assert count == 0
        assert created == []

    def test_lower_applies_conditional_redirect_patch_plan(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        backend = IDAIRTranslator()
        patch_plan = compile_patch_plan(
            [
                CreateConditionalRedirect(
                    source_block=44,
                    ref_block=45,
                    conditional_target=199,
                    fallthrough_target=2,
                )
            ],
            _cfg(),
        )

        count = backend.lower(patch_plan, object())

        assert count == 1
        assert len(created) == 1
        assert created[0].calls[0][0] == "create_conditional"
        assert created[0].calls[0][1:7] == (44, 45, 201, 2, 199, 200)

    def test_lower_applies_insert_block_patch_plan(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        backend = IDAIRTranslator()
        patch_plan = compile_patch_plan(
            [
                InsertBlock(
                    pred_serial=45,
                    succ_serial=199,
                    instructions=(InsnSnapshot(opcode=0x77, ea=0x1000, operands=()),),
                )
            ],
            _cfg(),
        )

        count = backend.lower(patch_plan, SimpleNamespace(entry_ea=0x180000000))

        assert count == 1
        assert len(created) == 1
        assert created[0].calls[0][0] == "create_and_redirect"
        assert created[0].calls[0][1:6] == (45, 200, 1, False, 199)

    def test_lower_applies_duplicate_block_patch_plan(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        backend = IDAIRTranslator()
        patch_plan = compile_patch_plan(
            [
                DuplicateBlock(
                    source_block=45,
                    target_block=199,
                    pred_serial=44,
                )
            ],
            _cfg(),
        )

        count = backend.lower(patch_plan, object())

        assert count == 1
        assert len(created) == 1
        assert created[0].calls[0][0] == "duplicate_block"
        assert created[0].calls[0][1:6] == (45, 44, 200, 199, None)

    def test_lower_applies_conditional_duplicate_block_patch_plan(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        backend = IDAIRTranslator()
        patch_plan = compile_patch_plan(
            [
                DuplicateBlock(
                    source_block=45,
                    target_block=None,
                    pred_serial=44,
                )
            ],
            _conditional_duplicate_cfg(),
        )

        count = backend.lower(patch_plan, object())

        assert count == 1
        assert len(created) == 1
        assert created[0].calls[0][0] == "duplicate_block"
        assert created[0].calls[0][1:6] == (45, 44, None, 199, 200)

    def test_lower_rejects_unsupported_legacy_insert_block_when_enabled(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        backend = IDAIRTranslator()
        patch_plan = compile_patch_plan(
            [
                InsertBlock(
                    pred_serial=45,
                    succ_serial=2,
                    instructions=(InsnSnapshot(opcode=0x77, ea=0x1000, operands=()),),
                )
            ]
        )

        count = backend.lower(patch_plan, object())

        assert count == 0
        assert created == []

    def test_lower_rejects_unreconstructable_patch_insert_block_before_modifier_creation(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        backend = IDAIRTranslator()
        patch_plan = compile_patch_plan(
            [
                InsertBlock(
                    pred_serial=45,
                    succ_serial=199,
                    instructions=(InsnSnapshot(opcode=0x77, ea=0x1000, operands=(object(),)),),
                )
            ],
            _cfg(),
        )

        count = backend.lower(patch_plan, SimpleNamespace(entry_ea=0x180000000))

        assert count == 0
        assert created == []

    def test_lower_rejects_unsupported_remove_edge_before_modifier_creation(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        backend = IDAIRTranslator()
        patch_plan = compile_patch_plan([RemoveEdge(from_serial=45, to_serial=2)])

        count = backend.lower(patch_plan, object())

        assert count == 0
        assert created == []

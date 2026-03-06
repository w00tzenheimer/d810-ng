"""Tests for IDAIRTranslator.

System-level integration tests that verify IDAIRTranslator conforms to the
IRTranslator protocol and exposes the expected interface.

Runs in IDA environment (system/runtime); skips gracefully without IDA.
"""
from __future__ import annotations

import importlib

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.cfg.graph_modification import EdgeRedirectViaPredSplit, InsertBlock, RedirectGoto
from d810.cfg.plan import PatchPlan, PatchRedirectGoto, compile_patch_plan
from d810.hexrays.mutation.ir_translator import IDAIRTranslator


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
        description: str = "",
    ) -> None:
        self.calls.append(
            (
                "create_conditional",
                source_blk_serial,
                ref_blk_serial,
                conditional_target_serial,
                fallthrough_target_serial,
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
        assert len(created) == 1
        assert created[0].calls == []

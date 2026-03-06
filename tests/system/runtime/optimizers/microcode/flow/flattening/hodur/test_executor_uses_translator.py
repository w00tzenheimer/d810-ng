"""Runtime tests for Hodur executor translation path."""
import sys
import types

import pytest

# Minimal stub so modules importing ida_hexrays remain importable in unit tests.
if "ida_hexrays" not in sys.modules:
    ida_hexrays_stub = types.ModuleType("ida_hexrays")
    ida_hexrays_stub.mop_z = 0
    sys.modules["ida_hexrays"] = ida_hexrays_stub

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.cfg.graph_modification import (
    DuplicateBlock,
    EdgeRedirectViaPredSplit,
    NopInstructions,
    RedirectGoto,
)
from d810.cfg.plan import PatchPlan
from d810.optimizers.microcode.flow.flattening.hodur import executor as _executor_mod
from d810.optimizers.microcode.flow.flattening.hodur.executor import TransactionalExecutor
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    BenefitMetrics,
    FAMILY_DIRECT,
    OwnershipScope,
    PlanFragment,
)


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


def _base_fragment() -> dict:
    return {
        "strategy_name": "test_strategy",
        "family": FAMILY_DIRECT,
        "ownership": OwnershipScope(
            blocks=frozenset(),
            edges=frozenset(),
            transitions=frozenset(),
        ),
        "prerequisites": [],
        "expected_benefit": BenefitMetrics(
            handlers_resolved=0,
            transitions_resolved=0,
            blocks_freed=0,
            conflict_density=0.0,
        ),
        "risk_score": 0.1,
        "metadata": {},
    }


class _FakeTranslator:
    def __init__(self, pre_cfg: FlowGraph, post_cfg: FlowGraph | None = None):
        self.pre_cfg = pre_cfg
        self.post_cfg = post_cfg if post_cfg is not None else pre_cfg
        self.lift_calls = 0
        self.lower_calls: list[PatchPlan] = []

    def lift(self, mba: object) -> FlowGraph:  # noqa: ARG002
        self.lift_calls += 1
        return self.pre_cfg if self.lift_calls == 1 else self.post_cfg

    def lower(self, patch_plan: PatchPlan, mba: object) -> int:  # noqa: ARG002
        self.lower_calls.append(patch_plan)
        return len(patch_plan.as_graph_modifications())


def test_executor_uses_fragment_modifications(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        _executor_mod, "should_apply_cfg_modifications",
        lambda *args, **kwargs: True,
    )

    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), ()),
            1: _block(1, (2,), (0,)),
            2: _block(2, (), (1,)),
        },
        entry_serial=0,
        func_ea=0,
    )
    translator = _FakeTranslator(pre_cfg=cfg)

    fragment = PlanFragment(
        modifications=[
            RedirectGoto(from_serial=0, old_target=1, new_target=1),
            RedirectGoto(from_serial=1, old_target=2, new_target=2),
            RedirectGoto(from_serial=0, old_target=1, new_target=2),
        ],
        **_base_fragment(),
    )

    executor = TransactionalExecutor(mba=object(), translator=translator)
    result = executor.execute_stage(fragment, total_handlers=1)

    assert result.success
    assert result.edits_applied == 3
    assert translator.lift_calls == 2
    assert len(translator.lower_calls) == 1
    assert isinstance(translator.lower_calls[0], PatchPlan)
    assert translator.lower_calls[0].as_graph_modifications() == fragment.modifications
    assert not translator.lower_calls[0].contains_block_creation


def test_executor_preflight_uses_backend_order(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        _executor_mod, "should_apply_cfg_modifications",
        lambda *args, **kwargs: True,
    )

    cfg = FlowGraph(
        blocks={
            44: _block(44, (99, 45), ()),
            122: _block(122, (45,), ()),
            45: _block(45, (2,), (44, 122)),
            2: _block(2, (99,), (45,)),
            99: _block(99, (), (2, 127, 180)),
            127: _block(127, (99,), ()),
            180: _block(180, (99,), ()),
        },
        entry_serial=44,
        func_ea=0,
    )
    translator = _FakeTranslator(pre_cfg=cfg)

    fragment = PlanFragment(
        modifications=[
            RedirectGoto(from_serial=45, old_target=2, new_target=127),
            EdgeRedirectViaPredSplit(
                src_block=45,
                old_target=2,
                new_target=180,
                via_pred=122,
                rule_priority=550,
            ),
        ],
        **_base_fragment(),
    )

    executor = TransactionalExecutor(mba=object(), translator=translator)
    result = executor.execute_stage(fragment, total_handlers=1)

    assert result.success
    assert len(translator.lower_calls) == 1
    assert translator.lower_calls[0].as_graph_modifications() == fragment.modifications
    assert translator.lower_calls[0].contains_block_creation
    assert not translator.lower_calls[0].legacy_block_operations


def test_executor_rejects_legacy_block_creation_when_policy_disabled(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        _executor_mod, "should_apply_cfg_modifications",
        lambda *args, **kwargs: True,
    )

    cfg = FlowGraph(
        blocks={
            44: _block(44, (99, 45), ()),
            122: _block(122, (45,), ()),
            45: _block(45, (2,), (44, 122)),
            2: _block(2, (99,), (45,)),
            99: _block(99, (), (2, 127, 180)),
            127: _block(127, (99,), ()),
            180: _block(180, (99,), ()),
        },
        entry_serial=44,
        func_ea=0,
    )
    translator = _FakeTranslator(pre_cfg=cfg)

    fragment = PlanFragment(
        modifications=[
            DuplicateBlock(
                source_block=45,
                target_block=2,
                pred_serial=44,
            ),
        ],
        **{**_base_fragment(), "metadata": {"handler_entry_serials": {180}, "dispatcher_serial": 44}},
    )

    executor = TransactionalExecutor(
        mba=object(),
        translator=translator,
        allow_legacy_block_creation=False,
    )
    result = executor.execute_stage(fragment, total_handlers=1)

    assert not result.success
    assert result.error == "block-creating edits disabled by policy"
    assert not translator.lower_calls


def test_cycle_filter_preserves_non_redirect_modifications():
    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), ()),
            1: _block(1, (2,), (0,)),
            2: _block(2, (3,), (1,)),
            3: _block(3, (), (2,)),
        },
        entry_serial=0,
        func_ea=0,
    )

    fragment = PlanFragment(
        modifications=[],
        **_base_fragment(),
    )
    executor = TransactionalExecutor(mba=object(), translator=_FakeTranslator(pre_cfg=cfg))

    cycle_mod = EdgeRedirectViaPredSplit(
        src_block=2,
        old_target=3,
        new_target=1,
        via_pred=1,
        rule_priority=550,
    )
    nop_mod = NopInstructions(block_serial=2, insn_eas=(0x1234,))

    filtered = executor._filter_cycle_modifications(
        fragment=fragment,
        pre_adj=cfg.as_adjacency_dict(),
        terminal_exits={3},
        handler_entries={1},
        dispatcher=0,
        original_modifications=[nop_mod, cycle_mod],
    )

    assert filtered == [nop_mod]

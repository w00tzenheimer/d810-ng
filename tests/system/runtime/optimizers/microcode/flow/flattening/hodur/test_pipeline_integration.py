"""Planner/executor integration tests for pre-lifted FlowGraph snapshots."""
from __future__ import annotations

import sys
import types

if "ida_hexrays" not in sys.modules:
    ida_hexrays_stub = types.ModuleType("ida_hexrays")
    ida_hexrays_stub.mop_z = 0
    sys.modules["ida_hexrays"] = ida_hexrays_stub

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.cfg.graph_modification import RedirectGoto
from d810.cfg.plan import PatchPlan
from d810.optimizers.microcode.flow.flattening.hodur import executor as _executor_mod
from d810.optimizers.microcode.flow.flattening.hodur.executor import (
    TransactionalExecutor,
)
from d810.optimizers.microcode.flow.flattening.hodur.planner import (
    PipelinePolicy,
    UnflatteningPlanner,
)
from d810.optimizers.microcode.flow.flattening.hodur.provenance import (
    PlannerInputs,
)
from d810.optimizers.microcode.flow.flattening.hodur.snapshot import AnalysisSnapshot
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


def _cfg(
    block1_succ: int,
    block2_succ: int,
) -> FlowGraph:
    return FlowGraph(
        blocks={
            0: _block(0, (1, 2), ()),
            1: _block(1, (block1_succ,), (0,)),
            2: _block(2, (block2_succ,), (0,)),
            3: _block(3, (4,), (1, 2)),
            4: _block(4, (), (3,)),
        },
        entry_serial=0,
        func_ea=0x401000,
    )


def _fragment_base(name: str, *, prerequisites: list[str] | None = None) -> dict:
    return {
        "strategy_name": name,
        "family": FAMILY_DIRECT,
        "ownership": OwnershipScope(
            blocks=frozenset(),
            edges=frozenset(),
            transitions=frozenset(),
        ),
        "prerequisites": prerequisites or [],
        "expected_benefit": BenefitMetrics(
            handlers_resolved=1,
            transitions_resolved=0,
            blocks_freed=0,
            conflict_density=0.0,
        ),
        "risk_score": 0.1,
        "metadata": {
            "handler_entry_serials": {1, 2},
            "dispatcher_serial": 0,
            "terminal_exit_blocks": {4},
            "exit_blocks": {4},
        },
    }


class _SnapshotPlanningStrategy:
    def __init__(
        self,
        *,
        name: str,
        from_serial: int,
        new_target: int,
        prerequisites: list[str] | None = None,
    ) -> None:
        self.name = name
        self.family = FAMILY_DIRECT
        self._from_serial = from_serial
        self._new_target = new_target
        self._prerequisites = prerequisites or []
        self.snapshot_ids: list[int] = []
        self.snapshot_adjs: list[dict[int, list[int]]] = []

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        return snapshot.flow_graph is not None

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        assert snapshot.flow_graph is not None
        self.snapshot_ids.append(id(snapshot.flow_graph))
        self.snapshot_adjs.append(snapshot.flow_graph.as_adjacency_dict())
        block = snapshot.flow_graph.get_block(self._from_serial)
        assert block is not None
        return PlanFragment(
            modifications=[
                RedirectGoto(
                    from_serial=self._from_serial,
                    old_target=block.succs[0],
                    new_target=self._new_target,
                )
            ],
            **_fragment_base(self.name, prerequisites=self._prerequisites),
        )


class _SequenceTranslator:
    def __init__(self, lifts: list[FlowGraph]):
        self._lifts = list(lifts)
        self.lower_calls: list[PatchPlan] = []

    def lift(self, mba: object) -> FlowGraph:  # noqa: ARG002
        assert self._lifts, "unexpected extra lift() call"
        return self._lifts.pop(0)

    def lower(self, patch_plan: PatchPlan, mba: object, **kwargs) -> int:  # noqa: ARG002
        self.lower_calls.append(patch_plan)
        return len(patch_plan.as_graph_modifications())


def test_fragments_planned_from_same_snapshot_execute_stably(monkeypatch):
    monkeypatch.setattr(
        _executor_mod,
        "should_apply_cfg_modifications",
        lambda *args, **kwargs: True,
    )

    pre_cfg = _cfg(4, 4)
    mid_cfg = _cfg(3, 4)
    post_cfg = _cfg(3, 3)
    snapshot = AnalysisSnapshot(mba=object(), flow_graph=pre_cfg)

    first = _SnapshotPlanningStrategy(name="first", from_serial=1, new_target=3)
    second = _SnapshotPlanningStrategy(
        name="second",
        from_serial=2,
        new_target=3,
        prerequisites=["first"],
    )

    fragments = [first.plan(snapshot), second.plan(snapshot)]
    assert all(fragment is not None for fragment in fragments)
    planned_fragments = [fragment for fragment in fragments if fragment is not None]

    assert first.snapshot_ids == [id(pre_cfg)]
    assert second.snapshot_ids == [id(pre_cfg)]
    assert first.snapshot_adjs == [pre_cfg.as_adjacency_dict()]
    assert second.snapshot_adjs == [pre_cfg.as_adjacency_dict()]

    planner = UnflatteningPlanner(PipelinePolicy())
    pipeline, _provenance = planner.compose_pipeline(planned_fragments, inputs=PlannerInputs(total_handlers=2))
    assert [fragment.strategy_name for fragment in pipeline] == ["first", "second"]

    translator = _SequenceTranslator([pre_cfg, mid_cfg, mid_cfg, post_cfg])
    executor = TransactionalExecutor(mba=object(), translator=translator)
    results = executor.execute_pipeline(pipeline, total_handlers=2)

    assert [result.success for result in results] == [True, True]
    assert [result.edits_applied for result in results] == [1, 1]
    assert [result.rollback_needed for result in results] == [False, False]
    assert [plan.as_graph_modifications() for plan in translator.lower_calls] == [
        planned_fragments[0].modifications,
        planned_fragments[1].modifications,
    ]
    assert snapshot.flow_graph is pre_cfg
    assert snapshot.flow_graph.as_adjacency_dict() == pre_cfg.as_adjacency_dict()

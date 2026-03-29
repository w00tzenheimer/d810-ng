from __future__ import annotations

import d810.cfg.entry_island_rescue_planning as rescue_mod
from d810.cfg.entry_island_rescue import EntryIslandRescueOption
from d810.cfg.entry_island_rescue_planning import (
    EntryIslandRescuePlanningSeed,
    plan_entry_island_rescues,
    score_entry_island_rescue_option,
    select_entry_island_rescue,
)


class _DummyBuilder:
    @staticmethod
    def goto_redirect(*, source_block: int, target_block: int, old_target: int):
        return ("goto", int(source_block), int(target_block), int(old_target))

    @staticmethod
    def edge_redirect(*, source_block: int, target_block: int, old_target: int, via_pred: int):
        return ("edge", int(source_block), int(target_block), int(old_target), int(via_pred))


class _DummyBlock:
    def __init__(self, preds: tuple[int, ...], succs: tuple[int, ...]):
        self.preds = preds
        self.succs = succs
        self.npred = len(preds)
        self.nsucc = len(succs)


class _DummyFlowGraph:
    def __init__(self, mapping: dict[int, tuple[tuple[int, ...], tuple[int, ...]]]):
        self._mapping = {
            int(k): _DummyBlock(tuple(int(v) for v in preds), tuple(int(v) for v in succs))
            for k, (preds, succs) in mapping.items()
        }
        self.entry_serial = 1

    def get_block(self, serial: int):
        return self._mapping.get(int(serial))


class _RawSeed:
    def __init__(self, source_block: int | None, lifted_entry: int):
        self.source_block = source_block
        self.lifted_entry = lifted_entry


class TestScoreEntryIslandRescueOption:
    def test_rejects_when_lifted_entry_not_reachable(self, monkeypatch) -> None:
        monkeypatch.setattr(
            rescue_mod,
            "compile_patch_plan",
            lambda modifications, flow_graph: ("plan", tuple(modifications)),
        )
        monkeypatch.setattr(
            rescue_mod,
            "project_post_state",
            lambda flow_graph, patch_plan: object(),
        )

        scored = score_entry_island_rescue_option(
            EntryIslandRescueOption(40, 90, 6),
            base_flow_graph=object(),
            builder=_DummyBuilder(),
            modifications=[],
            baseline_reachable_count=2,
            baseline_reachable_blocks={6, 40},
            compute_reachable_blocks=lambda flow_graph: {6, 40},
        )

        assert scored is None


class TestSelectEntryIslandRescue:
    def test_selects_best_scoring_option(self, monkeypatch) -> None:
        flow_graph = _DummyFlowGraph({
            40: ((12,), (6,)),
            50: ((13,), (6,)),
        })

        monkeypatch.setattr(
            rescue_mod,
            "compile_patch_plan",
            lambda modifications, flow_graph: tuple(modifications),
        )

        def _project_post_state(flow_graph, patch_plan):
            last_mod = patch_plan[-1]
            if last_mod[1] == 40:
                return "fg-40"
            return "fg-50"

        monkeypatch.setattr(rescue_mod, "project_post_state", _project_post_state)

        selection = select_entry_island_rescue(
            seeds=(
                EntryIslandRescuePlanningSeed(source_block=40, lifted_entry=90),
                EntryIslandRescuePlanningSeed(source_block=50, lifted_entry=91),
            ),
            current_projected_flow_graph=flow_graph,
            base_flow_graph=flow_graph,
            builder=_DummyBuilder(),
            modifications=[],
            reachable_blocks={6, 12, 13},
            dispatcher_region={6},
            claimed_sources=set(),
            compute_reachable_blocks=lambda projected: (
                {6, 12, 13, 40, 90}
                if projected == "fg-40"
                else {6, 12, 13, 50, 91, 92}
            ),
        )

        assert selection.accepted is True
        assert selection.option == EntryIslandRescueOption(
            source_block=50,
            lifted_entry=91,
            old_target=6,
        )
        assert selection.modification == ("goto", 50, 91, 6)
        assert selection.projected_flow_graph == "fg-50"

    def test_returns_rejected_when_no_option_survives(self, monkeypatch) -> None:
        flow_graph = _DummyFlowGraph({
            40: ((12,), (6,)),
        })

        monkeypatch.setattr(
            rescue_mod,
            "compile_patch_plan",
            lambda modifications, flow_graph: tuple(modifications),
        )
        monkeypatch.setattr(
            rescue_mod,
            "project_post_state",
            lambda flow_graph, patch_plan: object(),
        )

        selection = select_entry_island_rescue(
            seeds=(EntryIslandRescuePlanningSeed(source_block=40, lifted_entry=90),),
            current_projected_flow_graph=flow_graph,
            base_flow_graph=flow_graph,
            builder=_DummyBuilder(),
            modifications=[],
            reachable_blocks={6, 12},
            dispatcher_region={6},
            claimed_sources=set(),
            compute_reachable_blocks=lambda flow_graph: {6, 12},
        )

        assert selection.accepted is False
        assert selection.option is None


class TestPlanEntryIslandRescues:
    def test_runs_until_selection_rejected(self, monkeypatch) -> None:
        flow_graph = _DummyFlowGraph({
            40: ((12,), (6,)),
        })
        modifications = []
        call_count = {"value": 0}

        monkeypatch.setattr(
            rescue_mod,
            "compile_patch_plan",
            lambda modifications, flow_graph: tuple(modifications),
        )
        monkeypatch.setattr(
            rescue_mod,
            "project_post_state",
            lambda flow_graph, patch_plan: flow_graph,
        )

        def collect_seeds(*args, **kwargs):
            call_count["value"] += 1
            if call_count["value"] == 1:
                return (_RawSeed(40, 90),)
            return (_RawSeed(None, 90),)

        run = plan_entry_island_rescues(
            dag=object(),
            base_flow_graph=flow_graph,
            projected_flow_graph=flow_graph,
            builder=_DummyBuilder(),
            modifications=modifications,
            dispatcher_region={6},
            collect_seeds=collect_seeds,
            compute_reachable_blocks=lambda projected: {6, 12, 40, 90},
        )

        assert run.emitted_count == 1
        assert len(run.iterations) == 2
        assert run.iterations[0].selection.accepted is True
        assert run.iterations[1].selection.accepted is False
        assert modifications == [("goto", 40, 90, 6)]

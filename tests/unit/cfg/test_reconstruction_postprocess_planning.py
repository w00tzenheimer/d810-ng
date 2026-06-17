from __future__ import annotations

from types import SimpleNamespace

import d810.transforms.reconstruction_postprocess_planning as planner
from d810.transforms.graph_modification import RedirectBranch, RedirectGoto


class _Builder:
    @staticmethod
    def goto_redirect(*, source_block: int, target_block: int, old_target: int):
        return RedirectGoto(
            from_serial=source_block,
            old_target=old_target,
            new_target=target_block,
        )

    @staticmethod
    def edge_redirect(*, source_block: int, target_block: int, old_target: int):
        return RedirectBranch(
            from_serial=source_block,
            old_target=old_target,
            new_target=target_block,
        )


def _graph(spec):
    blocks = {
        int(serial): SimpleNamespace(
            nsucc=len(tuple(succs)),
            succs=tuple(int(succ) for succ in succs),
            preds=(),
        )
        for serial, succs in spec.items()
    }
    return SimpleNamespace(blocks=blocks, get_block=blocks.get)


def _return_edge(source_block: int, ordered_path: tuple[int, ...]):
    return SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_RETURN"),
        source_anchor=SimpleNamespace(block_serial=source_block, branch_arm=None),
        source_key=("state", source_block),
        ordered_path=ordered_path,
    )


class _IntervalDispatcher:
    def __init__(self, mapping):
        self._mapping = dict(mapping)

    def lookup(self, state_value: int):
        return self._mapping.get(int(state_value) & 0xFFFFFFFF)


class _ExactDispatcherMap:
    def __init__(self, mapping):
        self._mapping = dict(mapping)

    def resolve_target(self, state_value: int):
        return self._mapping.get(int(state_value) & 0xFFFFFFFF)


def test_return_anchor_priority_is_default_even_when_spine_claims_source(
    monkeypatch,
) -> None:
    monkeypatch.setenv("D810_S1A_RETURN_PRIORITY", "0")
    graph = _graph({10: (6,)})
    spine_mod = RedirectGoto(from_serial=10, old_target=6, new_target=99)
    dag = SimpleNamespace(
        pre_header_serial=None,
        initial_state=None,
        edges=(_return_edge(10, (10, 20, 206)),),
    )

    monkeypatch.setattr(
        planner,
        "plan_reconstruction_preheader_bridge",
        lambda **kwargs: planner.ReconstructionPreheaderBridgeResult(
            modification=None,
            resolved_target=None,
        ),
    )
    monkeypatch.setattr(
        planner,
        "plan_reconstruction_bridge_modifications",
        lambda **kwargs: planner.ReconstructionBridgePlanResult(
            modifications=(),
            log_entries=(),
            claimed_sources=frozenset(kwargs["claimed_sources"]),
            claimed_targets=frozenset(kwargs["claimed_targets"]),
        ),
    )
    monkeypatch.setattr(
        planner,
        "plan_reconstruction_feeder_modifications",
        lambda **kwargs: planner.ReconstructionFeederPlanResult(
            modifications=(),
            log_entries=(),
            claimed_sources=frozenset(kwargs["claimed_sources"]),
            claimed_targets=frozenset(kwargs["claimed_targets"]),
        ),
    )
    monkeypatch.setattr(
        planner,
        "plan_fixpoint_feeder_modifications",
        lambda **kwargs: planner.ReconstructionFixpointFeederPlanResult(
            modifications=(),
            log_entries=(),
            claimed_sources=frozenset(kwargs["claimed_sources"]),
        ),
    )

    result = planner.plan_reconstruction_postprocess_modifications(
        dag=dag,
        flow_graph=graph,
        projected_flow_graph=graph,
        builder=_Builder(),
        dispatcher_serial=6,
        condition_chain_blocks={6},
        dispatcher=None,
        modifications=[spine_mod],
        owned_blocks={10},
        rejected_metadata=[],
        constant_result=None,
        state_var_stkoff=None,
        artifact_return_blocks=set(),
        common_return_corridor={20, 206},
        node_by_key={},
    )

    assert result.return_plan.modifications == (
        RedirectGoto(from_serial=10, old_target=6, new_target=20),
    )
    assert result.return_plan.skipped_entries == ()


def test_fixpoint_feeder_prefers_exact_dispatcher_rows_over_interval_default() -> None:
    graph = _graph({1: (2,), 2: (4,), 20: (22,), 116: (118,)})
    constant_result = SimpleNamespace(out_stk_maps={1: {0x364: 0x6F2791FF}})

    result = planner.plan_fixpoint_feeder_modifications(
        flow_graph=graph,
        builder=_Builder(),
        dispatcher_serial=2,
        condition_chain_blocks={2},
        claimed_sources=set(),
        constant_result=constant_result,
        state_var_stkoff=0x364,
        dispatcher=_IntervalDispatcher({0x6F2791FF: 20}),
        exact_dispatcher_map=_ExactDispatcherMap({0x6F2791FF: 116}),
    )

    assert result.modifications == (
        RedirectGoto(from_serial=1, old_target=2, new_target=116),
    )
    assert result.log_entries[0].target_block == 116

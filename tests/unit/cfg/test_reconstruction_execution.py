from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import d810.cfg.reconstruction_execution as exec_mod
from d810.cfg.reconstruction_execution import (
    execute_primary_reconstruction_modifications,
    execute_shared_group_reconstruction,
)


def _candidate(
    *,
    emission_mode: str,
    horizon_block: int,
    target_entry: int,
    via_pred: int | None = None,
    first_shared_block: int | None = None,
    ordered_path: tuple[int, ...] = (),
    branch_arm: int | None = None,
    state_const: int = 0x11111111,
):
    source_key = _SourceKey(state_const=state_const)
    source_anchor = SimpleNamespace(branch_arm=branch_arm)
    edge_kind = SimpleNamespace(name="CONDITIONAL_TRANSITION" if emission_mode == "conditional_arm" else "TRANSITION")
    edge = SimpleNamespace(
        ordered_path=ordered_path,
        source_key=source_key,
        source_anchor=source_anchor,
        kind=edge_kind,
    )
    site = SimpleNamespace(state_value=state_const)
    return SimpleNamespace(
        emission_mode=emission_mode,
        horizon_block=horizon_block,
        target_entry=target_entry,
        via_pred=via_pred,
        first_shared_block=first_shared_block,
        edge=edge,
        site=site,
    )


@dataclass(frozen=True)
class _SourceKey:
    state_const: int


class TestExecuteSharedGroupReconstruction:
    def test_returns_empty_when_no_via_pred_candidates(self) -> None:
        result = execute_shared_group_reconstruction(
            shared_block=20,
            candidates=[_candidate(emission_mode="pred_split", horizon_block=20, target_entry=40)],
            flow_graph=object(),
            modifications=[],
            owned_blocks=set(),
            owned_edges=set(),
        )

        assert result.accepted_candidates == ()
        assert result.rejected_candidates == ()
        assert result.rejection_reason is None

    def test_applies_shared_group_plan_and_tracks_edges(self, monkeypatch) -> None:
        monkeypatch.setattr(
            exec_mod,
            "plan_shared_group_reconstruction_modifications",
            lambda **kwargs: SimpleNamespace(
                accepted=True,
                rejection_reason=None,
                ordered_via_preds=(8, 9),
                per_pred_targets=((8, 24), (9, 30)),
                modifications=[("dup", 20)],
            ),
        )
        modifications: list[object] = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()

        result = execute_shared_group_reconstruction(
            shared_block=20,
            candidates=[
                _candidate(
                    emission_mode="pred_split",
                    horizon_block=20,
                    target_entry=24,
                    via_pred=8,
                    first_shared_block=20,
                    ordered_path=(20, 21),
                ),
                _candidate(
                    emission_mode="pred_split",
                    horizon_block=20,
                    target_entry=30,
                    via_pred=9,
                    first_shared_block=20,
                    ordered_path=(20, 21),
                ),
            ],
            flow_graph=object(),
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
        )

        assert modifications == [("dup", 20)]
        assert owned_blocks == {20}
        assert owned_edges == {(20, 24), (20, 30)}
        assert [candidate.via_pred for candidate in result.accepted_candidates] == [8, 9]


class TestExecutePrimaryReconstructionModifications:
    def test_direct_conflict_rejects_all_conflicting_candidates(self) -> None:
        cand_a = _candidate(
            emission_mode="direct",
            horizon_block=14,
            target_entry=24,
            ordered_path=(14, 16),
        )
        cand_b = _candidate(
            emission_mode="direct",
            horizon_block=14,
            target_entry=30,
            ordered_path=(14, 18),
        )

        result = execute_primary_reconstruction_modifications(
            raw_candidates=[cand_a, cand_b],
            flow_graph=object(),
            node_by_key={},
            dispatcher_serial=6,
            modifications=[],
            owned_blocks=set(),
            owned_edges=set(),
        )

        assert result.direct_results[0].accepted_candidate is None
        assert result.direct_results[0].rejection_reason == "direct_conflict"
        assert result.direct_results[0].rejected_candidates == (cand_a, cand_b)

    def test_conditional_candidate_emits_redirect_and_passthrough(self, monkeypatch) -> None:
        monkeypatch.setattr(
            exec_mod,
            "plan_conditional_arm_reconstruction_modifications",
            lambda **kwargs: SimpleNamespace(modifications=[("cond", kwargs["horizon_block"], kwargs["target_entry"])]),
        )
        monkeypatch.setattr(
            exec_mod,
            "plan_passthrough_reconstruction_modifications",
            lambda **kwargs: SimpleNamespace(modifications=[("pt", kwargs["horizon_block"])]),
        )
        candidate = _candidate(
            emission_mode="conditional_arm",
            horizon_block=12,
            target_entry=40,
            ordered_path=(12, 14),
            branch_arm=1,
            state_const=0x22222222,
        )
        node_by_key = {candidate.edge.source_key: SimpleNamespace(entry_anchor=18)}
        modifications: list[object] = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()

        result = execute_primary_reconstruction_modifications(
            raw_candidates=[candidate],
            flow_graph=object(),
            node_by_key=node_by_key,
            dispatcher_serial=6,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
        )

        assert modifications == [("cond", 12, 40), ("pt", 12)]
        assert owned_blocks == {12}
        assert owned_edges == {(12, 40)}
        assert result.conditional_results[0].redirect_count == 1
        assert result.conditional_results[0].passthrough_count == 1

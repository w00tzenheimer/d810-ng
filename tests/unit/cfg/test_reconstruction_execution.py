from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import d810.cfg.reconstruction_execution as exec_mod
from d810.cfg.graph_modification import (
    CreateConditionalRedirect,
    DuplicateBlock,
    DuplicateAndRedirect,
    EdgeRedirectViaPredSplit,
    RedirectBranch,
    RedirectGoto,
    ZeroStateWrite,
)
from d810.cfg.reconstruction_execution import (
    apply_shared_group_reachability_fallback,
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
    target_state: int | None = None,
    site_block_serial: int | None = None,
    site_insn_ea: int | None = None,
    source_anchor_block: int | None = None,
    conditional_group_policy: str = "auto",
):
    source_key = _SourceKey(state_const=state_const)
    source_anchor = SimpleNamespace(
        branch_arm=branch_arm,
        block_serial=(
            horizon_block if source_anchor_block is None else source_anchor_block
        ),
    )
    edge_kind = SimpleNamespace(name="CONDITIONAL_TRANSITION" if emission_mode == "conditional_arm" else "TRANSITION")
    edge = SimpleNamespace(
        ordered_path=ordered_path,
        source_key=source_key,
        source_anchor=source_anchor,
        kind=edge_kind,
        target_state=(state_const if target_state is None else target_state),
    )
    site = SimpleNamespace(
        state_value=(state_const if target_state is None else target_state),
        block_serial=(
            horizon_block if site_block_serial is None else site_block_serial
        ),
        insn_ea=(0 if site_insn_ea is None else site_insn_ea),
    )
    return SimpleNamespace(
        emission_mode=emission_mode,
        horizon_block=horizon_block,
        target_entry=target_entry,
        via_pred=via_pred,
        first_shared_block=first_shared_block,
        edge=edge,
        site=site,
        conditional_group_policy=conditional_group_policy,
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
                emission_mode="duplicate_and_redirect",
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
        assert result.emission_mode == "duplicate_and_redirect"


    def test_force_clone_is_forwarded_to_shared_group_planner(self, monkeypatch) -> None:
        seen_force_clone: list[bool] = []

        def _plan(**kwargs):
            seen_force_clone.append(bool(kwargs["force_clone"]))
            return SimpleNamespace(
                accepted=True,
                rejection_reason=None,
                ordered_via_preds=(8,),
                per_pred_targets=((9, 2), (8, 24)),
                emission_mode="duplicate_and_redirect",
                modifications=[("dup", 20)],
            )

        monkeypatch.setattr(exec_mod, "plan_shared_group_reconstruction_modifications", _plan)

        execute_shared_group_reconstruction(
            shared_block=20,
            candidates=[
                _candidate(
                    emission_mode="pred_split",
                    horizon_block=20,
                    target_entry=24,
                    via_pred=8,
                    first_shared_block=20,
                    ordered_path=(8, 20),
                ),
            ],
            flow_graph=object(),
            modifications=[],
            owned_blocks=set(),
            owned_edges=set(),
            force_clone=True,
        )

        assert seen_force_clone == [True]

    def test_preserves_all_semantic_owners_for_accepted_shared_group_targets(
        self, monkeypatch
    ) -> None:
        monkeypatch.setattr(
            exec_mod,
            "plan_shared_group_reconstruction_modifications",
            lambda **kwargs: SimpleNamespace(
                accepted=True,
                rejection_reason=None,
                ordered_via_preds=(8, 9),
                per_pred_targets=((8, 24), (9, 30)),
                emission_mode="duplicate_and_redirect",
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
                    ordered_path=(8, 20),
                    state_const=0x57BE6FD0,
                ),
                _candidate(
                    emission_mode="pred_split",
                    horizon_block=20,
                    target_entry=24,
                    via_pred=8,
                    first_shared_block=20,
                    ordered_path=(8, 20),
                    state_const=0x03E42B03,
                ),
                _candidate(
                    emission_mode="pred_split",
                    horizon_block=20,
                    target_entry=30,
                    via_pred=9,
                    first_shared_block=20,
                    ordered_path=(9, 20),
                    state_const=0x610BB4D9,
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
        assert result.emission_mode == "duplicate_and_redirect"
        assert [
            (candidate.via_pred, candidate.target_entry, candidate.edge.source_key.state_const)
            for candidate in result.accepted_candidates
        ] == [
            (8, 24, 0x57BE6FD0),
            (8, 24, 0x03E42B03),
            (9, 30, 0x610BB4D9),
        ]


class TestExecutePrimaryReconstructionModifications:
    def test_falls_back_to_force_clone_when_per_pred_redirect_loses_handlers(self, monkeypatch) -> None:
        call_force_clone: list[bool] = []

        def _plan_shared(**kwargs):
            call_force_clone.append(bool(kwargs["force_clone"]))
            if kwargs["force_clone"]:
                return SimpleNamespace(
                    accepted=True,
                    rejection_reason=None,
                    ordered_via_preds=(8, 9),
                    per_pred_targets=((8, 24), (9, 30)),
                    emission_mode="duplicate_and_redirect",
                    modifications=[
                        DuplicateAndRedirect(
                            source_serial=kwargs["shared_block"],
                            per_pred_targets=((8, 24), (9, 30)),
                        )
                    ],
                )
            return SimpleNamespace(
                accepted=True,
                rejection_reason=None,
                ordered_via_preds=(8, 9),
                per_pred_targets=((8, 24), (9, 30)),
                emission_mode="per_pred_redirect",
                modifications=[
                    RedirectGoto(from_serial=8, old_target=20, new_target=24),
                    RedirectGoto(from_serial=9, old_target=20, new_target=30),
                    RedirectGoto(from_serial=kwargs["shared_block"], old_target=24, new_target=24),
                ],
            )

        monkeypatch.setattr(exec_mod, "plan_shared_group_reconstruction_modifications", _plan_shared)
        monkeypatch.setattr(
            exec_mod,
            "_project_primary_reconstruction_flow_graph",
            lambda base_flow_graph, modifications: SimpleNamespace(entry_serial=0),
        )

        modifications: list[object] = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        shared_a = _candidate(
            emission_mode="pred_split",
            horizon_block=20,
            target_entry=24,
            via_pred=8,
            first_shared_block=20,
            ordered_path=(8, 20),
        )
        shared_b = _candidate(
            emission_mode="pred_split",
            horizon_block=20,
            target_entry=30,
            via_pred=9,
            first_shared_block=20,
            ordered_path=(9, 20),
        )
        initial_result = execute_shared_group_reconstruction(
            shared_block=20,
            candidates=[shared_a, shared_b],
            flow_graph=object(),
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            allow_divergent_per_pred_redirect=True,
        )

        result = apply_shared_group_reachability_fallback(
            shared_group_results=(initial_result,),
            shared_groups={20: [shared_a, shared_b]},
            flow_graph=object(),
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            handler_entries=(24, 30),
            compute_reachable_blocks=lambda flow_graph, start_serial=None: {0, 24},
        )

        assert call_force_clone == [False, True]
        assert modifications == [
            DuplicateAndRedirect(
                source_serial=20,
                per_pred_targets=((8, 24), (9, 30)),
            )
        ]
        assert result[0].emission_mode == "duplicate_and_redirect"

    def test_selective_shared_group_fallback_keeps_safe_per_pred_groups(self, monkeypatch) -> None:
        call_force_clone: list[tuple[int, bool]] = []

        def _plan_shared(**kwargs):
            shared_block = int(kwargs["shared_block"])
            force_clone = bool(kwargs["force_clone"])
            call_force_clone.append((shared_block, force_clone))
            if force_clone:
                if shared_block == 20:
                    return SimpleNamespace(
                        accepted=True,
                        rejection_reason=None,
                        ordered_via_preds=(8, 9),
                        per_pred_targets=((8, 24), (9, 30)),
                        emission_mode="duplicate_and_redirect",
                        modifications=[
                            DuplicateAndRedirect(
                                source_serial=20,
                                per_pred_targets=((8, 24), (9, 30)),
                            )
                        ],
                    )
                return SimpleNamespace(
                    accepted=True,
                    rejection_reason=None,
                    ordered_via_preds=(18, 19),
                    per_pred_targets=((18, 44), (19, 50)),
                    emission_mode="duplicate_and_redirect",
                    modifications=[
                        DuplicateAndRedirect(
                            source_serial=40,
                            per_pred_targets=((18, 44), (19, 50)),
                        )
                    ],
                )
            if shared_block == 20:
                return SimpleNamespace(
                    accepted=True,
                    rejection_reason=None,
                    ordered_via_preds=(8, 9),
                    per_pred_targets=((8, 24), (9, 30)),
                    emission_mode="per_pred_redirect",
                    modifications=[
                        RedirectGoto(from_serial=8, old_target=20, new_target=24),
                        RedirectGoto(from_serial=9, old_target=20, new_target=30),
                        RedirectGoto(from_serial=20, old_target=24, new_target=24),
                    ],
                )
            return SimpleNamespace(
                accepted=True,
                rejection_reason=None,
                ordered_via_preds=(18, 19),
                per_pred_targets=((18, 44), (19, 50)),
                emission_mode="per_pred_redirect",
                modifications=[
                    RedirectGoto(from_serial=18, old_target=40, new_target=44),
                    RedirectGoto(from_serial=19, old_target=40, new_target=50),
                    RedirectGoto(from_serial=40, old_target=44, new_target=44),
                ],
            )

        monkeypatch.setattr(exec_mod, "plan_shared_group_reconstruction_modifications", _plan_shared)
        monkeypatch.setattr(
            exec_mod,
            "_project_primary_reconstruction_flow_graph",
            lambda base_flow_graph, modifications: SimpleNamespace(
                entry_serial=0,
                modifications=tuple(modifications),
            ),
        )

        def _reachable(projected_flow_graph, start_serial=None):
            del start_serial
            source_serials = {
                int(getattr(modification, "from_serial", -1))
                for modification in getattr(projected_flow_graph, "modifications", ())
                if hasattr(modification, "from_serial")
            }
            if 18 in source_serials or 19 in source_serials or 40 in source_serials:
                return {0, 24, 30, 44}
            return {0, 24, 30, 44, 50}

        modifications: list[object] = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        shared_a0 = _candidate(
            emission_mode="pred_split",
            horizon_block=20,
            target_entry=24,
            via_pred=8,
            first_shared_block=20,
            ordered_path=(8, 20),
        )
        shared_a1 = _candidate(
            emission_mode="pred_split",
            horizon_block=20,
            target_entry=30,
            via_pred=9,
            first_shared_block=20,
            ordered_path=(9, 20),
        )
        shared_b0 = _candidate(
            emission_mode="pred_split",
            horizon_block=40,
            target_entry=44,
            via_pred=18,
            first_shared_block=40,
            ordered_path=(18, 40),
        )
        shared_b1 = _candidate(
            emission_mode="pred_split",
            horizon_block=40,
            target_entry=50,
            via_pred=19,
            first_shared_block=40,
            ordered_path=(19, 40),
        )

        initial_result_a = execute_shared_group_reconstruction(
            shared_block=20,
            candidates=[shared_a0, shared_a1],
            flow_graph=object(),
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            allow_divergent_per_pred_redirect=True,
        )
        initial_result_b = execute_shared_group_reconstruction(
            shared_block=40,
            candidates=[shared_b0, shared_b1],
            flow_graph=object(),
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            allow_divergent_per_pred_redirect=True,
        )

        result = apply_shared_group_reachability_fallback(
            shared_group_results=(initial_result_a, initial_result_b),
            shared_groups={20: [shared_a0, shared_a1], 40: [shared_b0, shared_b1]},
            flow_graph=object(),
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            handler_entries=(24, 30, 44, 50),
            compute_reachable_blocks=_reachable,
        )

        assert call_force_clone == [(20, False), (40, False), (40, True)]
        assert result[0].emission_mode == "per_pred_redirect"
        assert result[1].emission_mode == "duplicate_and_redirect"
        assert modifications == [
            RedirectGoto(from_serial=8, old_target=20, new_target=24),
            RedirectGoto(from_serial=9, old_target=20, new_target=30),
            RedirectGoto(from_serial=20, old_target=24, new_target=24),
            DuplicateAndRedirect(
                source_serial=40,
                per_pred_targets=((18, 44), (19, 50)),
            ),
        ]

    def test_late_fallback_can_force_semantic_clone_without_trial(self, monkeypatch) -> None:
        call_force_clone: list[tuple[int, bool]] = []

        def _plan_shared(**kwargs):
            shared_block = int(kwargs["shared_block"])
            force_clone = bool(kwargs["force_clone"])
            call_force_clone.append((shared_block, force_clone))
            if force_clone:
                return SimpleNamespace(
                    accepted=True,
                    rejection_reason=None,
                    ordered_via_preds=(8, 9),
                    per_pred_targets=((8, 24), (9, 30)),
                    emission_mode="duplicate_and_redirect",
                    modifications=[
                        DuplicateAndRedirect(
                            source_serial=shared_block,
                            per_pred_targets=((8, 24), (9, 30)),
                        )
                    ],
                )
            return SimpleNamespace(
                accepted=True,
                rejection_reason=None,
                ordered_via_preds=(8, 9),
                per_pred_targets=((8, 24), (9, 30)),
                emission_mode="per_pred_redirect",
                modifications=[
                    RedirectGoto(from_serial=8, old_target=20, new_target=24),
                    RedirectGoto(from_serial=9, old_target=20, new_target=30),
                    RedirectGoto(from_serial=20, old_target=24, new_target=24),
                ],
            )

        monkeypatch.setattr(exec_mod, "plan_shared_group_reconstruction_modifications", _plan_shared)
        monkeypatch.setattr(
            exec_mod,
            "_project_primary_reconstruction_flow_graph",
            lambda base_flow_graph, modifications: SimpleNamespace(entry_serial=0),
        )

        modifications: list[object] = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        shared_a = _candidate(
            emission_mode="pred_split",
            horizon_block=20,
            target_entry=24,
            via_pred=8,
            first_shared_block=20,
            ordered_path=(8, 20),
        )
        shared_b = _candidate(
            emission_mode="pred_split",
            horizon_block=20,
            target_entry=30,
            via_pred=9,
            first_shared_block=20,
            ordered_path=(9, 20),
        )
        initial_result = execute_shared_group_reconstruction(
            shared_block=20,
            candidates=[shared_a, shared_b],
            flow_graph=object(),
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            allow_divergent_per_pred_redirect=True,
        )

        result = apply_shared_group_reachability_fallback(
            shared_group_results=(initial_result,),
            shared_groups={20: [shared_a, shared_b]},
            flow_graph=object(),
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            handler_entries=(24, 30),
            compute_reachable_blocks=lambda flow_graph, start_serial=None: {0, 24, 30},
            force_clone_shared_blocks={20},
        )

        assert call_force_clone == [(20, False), (20, True)]
        assert result[0].emission_mode == "duplicate_and_redirect"
        assert modifications == [
            DuplicateAndRedirect(
                source_serial=20,
                per_pred_targets=((8, 24), (9, 30)),
            )
        ]

    def test_late_fallback_can_force_keep_per_pred_redirect_for_experiment(self, monkeypatch) -> None:
        monkeypatch.setattr(
            exec_mod,
            "_project_primary_reconstruction_flow_graph",
            lambda base_flow_graph, modifications: SimpleNamespace(entry_serial=0),
        )

        modifications: list[object] = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        shared_a = _candidate(
            emission_mode="pred_split",
            horizon_block=20,
            target_entry=24,
            via_pred=8,
            first_shared_block=20,
            ordered_path=(8, 20),
        )
        shared_b = _candidate(
            emission_mode="pred_split",
            horizon_block=20,
            target_entry=30,
            via_pred=9,
            first_shared_block=20,
            ordered_path=(9, 20),
        )
        initial_result = exec_mod.SharedGroupExecutionResult(
            shared_block=20,
            accepted_candidates=(shared_a, shared_b),
            rejected_candidates=(),
            rejection_reason=None,
            emission_mode="per_pred_redirect",
            modifications=(
                RedirectGoto(from_serial=8, old_target=20, new_target=24),
                RedirectGoto(from_serial=9, old_target=20, new_target=30),
            ),
            per_pred_targets=((8, 24), (9, 30)),
        )

        result = apply_shared_group_reachability_fallback(
            shared_group_results=(initial_result,),
            shared_groups={20: [shared_a, shared_b]},
            flow_graph=object(),
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            handler_entries=(24, 30),
            compute_reachable_blocks=lambda flow_graph, start_serial=None: {0},
            force_keep_per_pred_shared_blocks={20},
        )

        assert result[0].emission_mode == "per_pred_redirect"
        assert modifications == [
            RedirectGoto(from_serial=8, old_target=20, new_target=24),
            RedirectGoto(from_serial=9, old_target=20, new_target=30),
        ]

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

    def test_paired_conditional_candidates_rewrite_horizon_conditional(self) -> None:
        flow_blocks = {
            8: SimpleNamespace(serial=8, preds=(), succs=(12,), npred=0, nsucc=1),
            12: SimpleNamespace(serial=12, preds=(8,), succs=(14, 16), npred=1, nsucc=2),
        }
        flow_graph = SimpleNamespace(get_block=lambda serial: flow_blocks.get(int(serial)))

        fallthrough_candidate = _candidate(
            emission_mode="conditional_arm",
            horizon_block=12,
            target_entry=14,
            ordered_path=(12, 14),
            branch_arm=0,
            state_const=0x22222222,
        )
        conditional_candidate = _candidate(
            emission_mode="conditional_arm",
            horizon_block=12,
            target_entry=44,
            ordered_path=(12, 16),
            branch_arm=1,
            state_const=0x22222222,
        )

        modifications: list[object] = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        result = execute_primary_reconstruction_modifications(
            raw_candidates=[fallthrough_candidate, conditional_candidate],
            flow_graph=flow_graph,
            node_by_key={},
            dispatcher_serial=6,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
        )

        assert modifications == [
            RedirectBranch(from_serial=12, old_target=16, new_target=44),
        ]
        assert owned_blocks == {12}
        assert owned_edges == {(12, 14), (12, 44)}
        assert {entry.candidate.target_entry for entry in result.conditional_results} == {
            14,
            44,
        }
        assert all(entry.redirect_count == 1 for entry in result.conditional_results)
        assert all(entry.passthrough_count == 0 for entry in result.conditional_results)

    def test_paired_conditional_grouping_does_not_mix_source_states(self) -> None:
        flow_blocks = {
            8: SimpleNamespace(serial=8, preds=(), succs=(12,), npred=0, nsucc=1),
            12: SimpleNamespace(serial=12, preds=(8,), succs=(14, 16), npred=1, nsucc=2),
        }
        flow_graph = SimpleNamespace(get_block=lambda serial: flow_blocks.get(int(serial)))

        arm0 = _candidate(
            emission_mode="conditional_arm",
            horizon_block=12,
            target_entry=14,
            ordered_path=(12, 14),
            branch_arm=0,
            state_const=0x11111111,
        )
        arm1 = _candidate(
            emission_mode="conditional_arm",
            horizon_block=12,
            target_entry=44,
            ordered_path=(12, 16),
            branch_arm=1,
            state_const=0x22222222,
        )

        groups, leftovers = exec_mod._collect_paired_conditional_arm_groups(
            candidates=[arm0, arm1],
            flow_graph=flow_graph,
        )

        assert groups == ()
        assert leftovers == (arm0, arm1)

    def test_paired_conditional_candidates_create_conditional_redirect_when_fallthrough_moves(self) -> None:
        flow_blocks = {
            8: SimpleNamespace(serial=8, preds=(), succs=(12,), npred=0, nsucc=1),
            12: SimpleNamespace(serial=12, preds=(8,), succs=(14, 16), npred=1, nsucc=2),
        }
        flow_graph = SimpleNamespace(get_block=lambda serial: flow_blocks.get(int(serial)))

        fallthrough_candidate = _candidate(
            emission_mode="conditional_arm",
            horizon_block=12,
            target_entry=40,
            ordered_path=(12, 14),
            branch_arm=0,
            state_const=0x22222222,
        )
        conditional_candidate = _candidate(
            emission_mode="conditional_arm",
            horizon_block=12,
            target_entry=44,
            ordered_path=(12, 16),
            branch_arm=1,
            state_const=0x22222222,
        )

        modifications: list[object] = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        result = execute_primary_reconstruction_modifications(
            raw_candidates=[fallthrough_candidate, conditional_candidate],
            flow_graph=flow_graph,
            node_by_key={},
            dispatcher_serial=6,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
        )

        assert modifications == [
            CreateConditionalRedirect(
                source_block=8,
                ref_block=12,
                conditional_target=44,
                fallthrough_target=40,
            )
        ]
        assert owned_blocks == {8}
        assert owned_edges == {(8, 40), (8, 44)}
        assert {entry.candidate.target_entry for entry in result.conditional_results} == {
            40,
            44,
        }
        assert all(entry.redirect_count == 1 for entry in result.conditional_results)
        assert all(entry.passthrough_count == 0 for entry in result.conditional_results)

    def test_paired_conditional_candidates_duplicate_branch_head_when_fallthrough_moves(self) -> None:
        flow_blocks = {
            13: SimpleNamespace(serial=13, preds=(), succs=(14, 15), npred=0, nsucc=2),
            15: SimpleNamespace(serial=15, preds=(13,), succs=(16, 17), npred=1, nsucc=2),
        }
        flow_graph = SimpleNamespace(get_block=lambda serial: flow_blocks.get(int(serial)))

        fallthrough_candidate = _candidate(
            emission_mode="conditional_arm",
            horizon_block=15,
            target_entry=14,
            ordered_path=(15, 16),
            branch_arm=0,
            state_const=0x6107F8EC,
        )
        conditional_candidate = _candidate(
            emission_mode="conditional_arm",
            horizon_block=15,
            target_entry=193,
            ordered_path=(15, 17),
            branch_arm=1,
            state_const=0x6107F8EC,
        )

        modifications: list[object] = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        result = execute_primary_reconstruction_modifications(
            raw_candidates=[fallthrough_candidate, conditional_candidate],
            flow_graph=flow_graph,
            node_by_key={},
            dispatcher_serial=6,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
        )

        assert modifications == [
            DuplicateBlock(
                source_block=15,
                target_block=None,
                pred_serial=13,
                patch_kind="reconstruction_paired_conditional",
                conditional_target=193,
                fallthrough_target=14,
            )
        ]
        assert owned_blocks == {13, 15}
        assert owned_edges == {(13, 14), (13, 193)}
        assert {entry.candidate.target_entry for entry in result.conditional_results} == {
            14,
            193,
        }
        assert all(entry.redirect_count == 1 for entry in result.conditional_results)
        assert all(entry.passthrough_count == 0 for entry in result.conditional_results)

    def test_paired_conditional_candidates_force_horizon_rewrite_for_region_owned_group(self) -> None:
        flow_blocks = {
            13: SimpleNamespace(serial=13, preds=(), succs=(14, 15), npred=0, nsucc=2),
            15: SimpleNamespace(serial=15, preds=(13,), succs=(16, 17), npred=1, nsucc=2),
        }
        flow_graph = SimpleNamespace(get_block=lambda serial: flow_blocks.get(int(serial)))

        fallthrough_candidate = _candidate(
            emission_mode="conditional_arm",
            horizon_block=15,
            target_entry=66,
            ordered_path=(158, 15, 16),
            branch_arm=0,
            state_const=0x6107F8EC,
            source_anchor_block=158,
            conditional_group_policy="rewrite_horizon",
        )
        conditional_candidate = _candidate(
            emission_mode="conditional_arm",
            horizon_block=15,
            target_entry=202,
            ordered_path=(158, 15, 17),
            branch_arm=1,
            state_const=0x6107F8EC,
            source_anchor_block=158,
            conditional_group_policy="rewrite_horizon",
        )

        modifications: list[object] = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        result = execute_primary_reconstruction_modifications(
            raw_candidates=[fallthrough_candidate, conditional_candidate],
            flow_graph=flow_graph,
            node_by_key={},
            dispatcher_serial=6,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
        )

        assert modifications == [
            RedirectBranch(from_serial=15, old_target=16, new_target=66),
            RedirectBranch(from_serial=15, old_target=17, new_target=202),
        ]
        assert owned_blocks == {15}
        assert owned_edges == {(15, 66), (15, 202)}
        assert {entry.candidate.target_entry for entry in result.conditional_results} == {
            66,
            202,
        }
        assert all(entry.redirect_count == 1 for entry in result.conditional_results)
        assert all(entry.passthrough_count == 0 for entry in result.conditional_results)

    def test_paired_conditional_candidates_force_horizon_rewrite_uses_ordered_path_over_branch_arm_index(self) -> None:
        flow_blocks = {
            13: SimpleNamespace(serial=13, preds=(), succs=(14, 15), npred=0, nsucc=2),
            15: SimpleNamespace(serial=15, preds=(13,), succs=(16, 17), npred=1, nsucc=2),
        }
        flow_graph = SimpleNamespace(get_block=lambda serial: flow_blocks.get(int(serial)))

        fallthrough_candidate = _candidate(
            emission_mode="conditional_arm",
            horizon_block=15,
            target_entry=66,
            ordered_path=(158, 15, 16),
            branch_arm=1,
            state_const=0x6107F8EC,
            source_anchor_block=158,
            conditional_group_policy="rewrite_horizon",
        )
        conditional_candidate = _candidate(
            emission_mode="conditional_arm",
            horizon_block=15,
            target_entry=202,
            ordered_path=(158, 15, 17),
            branch_arm=0,
            state_const=0x6107F8EC,
            source_anchor_block=158,
            conditional_group_policy="rewrite_horizon",
        )

        modifications: list[object] = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        result = execute_primary_reconstruction_modifications(
            raw_candidates=[fallthrough_candidate, conditional_candidate],
            flow_graph=flow_graph,
            node_by_key={},
            dispatcher_serial=6,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
        )

        assert modifications == [
            RedirectBranch(from_serial=15, old_target=17, new_target=202),
            RedirectBranch(from_serial=15, old_target=16, new_target=66),
        ]
        assert owned_blocks == {15}
        assert owned_edges == {(15, 66), (15, 202)}
        assert {entry.candidate.target_entry for entry in result.conditional_results} == {
            66,
            202,
        }

    def test_direct_candidate_appends_zero_state_write_for_matching_site(self, monkeypatch) -> None:
        monkeypatch.setattr(
            exec_mod,
            "plan_direct_reconstruction_modifications",
            lambda **kwargs: SimpleNamespace(
                accepted=True,
                modifications=[RedirectGoto(from_serial=14, old_target=2, new_target=40)],
            ),
        )

        candidate = _candidate(
            emission_mode="direct",
            horizon_block=14,
            target_entry=40,
            ordered_path=(14, 20),
            target_state=0x4C77464F,
            site_insn_ea=0x180001234,
        )

        modifications: list[object] = []
        result = execute_primary_reconstruction_modifications(
            raw_candidates=[candidate],
            flow_graph=object(),
            node_by_key={},
            dispatcher_serial=6,
            modifications=modifications,
            owned_blocks=set(),
            owned_edges=set(),
        )

        assert result.direct_results[0].accepted_candidate is candidate
        assert modifications == [
            RedirectGoto(from_serial=14, old_target=2, new_target=40),
            ZeroStateWrite(block_serial=14, insn_ea=0x180001234),
        ]

    def test_direct_candidate_appends_deep_path_zero_state_write_for_matching_site(self, monkeypatch) -> None:
        monkeypatch.setattr(
            exec_mod,
            "plan_direct_reconstruction_modifications",
            lambda **kwargs: SimpleNamespace(
                accepted=True,
                modifications=[RedirectGoto(from_serial=14, old_target=2, new_target=40)],
            ),
        )

        candidate = _candidate(
            emission_mode="direct",
            horizon_block=14,
            target_entry=40,
            ordered_path=(14, 16),
            target_state=0x4C77464F,
            site_block_serial=16,
            site_insn_ea=0x180001236,
        )

        modifications: list[object] = []
        result = execute_primary_reconstruction_modifications(
            raw_candidates=[candidate],
            flow_graph=object(),
            node_by_key={},
            dispatcher_serial=6,
            modifications=modifications,
            owned_blocks=set(),
            owned_edges=set(),
        )

        assert result.direct_results[0].accepted_candidate is candidate
        assert modifications == [
            RedirectGoto(from_serial=14, old_target=2, new_target=40),
            ZeroStateWrite(block_serial=16, insn_ea=0x180001236),
        ]

    def test_direct_candidate_appends_zero_state_write_for_observed_alias_target_state(
        self, monkeypatch
    ) -> None:
        monkeypatch.setattr(
            exec_mod,
            "plan_direct_reconstruction_modifications",
            lambda **kwargs: SimpleNamespace(
                accepted=True,
                modifications=[RedirectGoto(from_serial=14, old_target=2, new_target=66)],
            ),
        )

        candidate = _candidate(
            emission_mode="direct",
            horizon_block=14,
            target_entry=66,
            ordered_path=(14, 16),
            target_state=0x474EEEBB,
            site_block_serial=16,
            site_insn_ea=0x180001238,
        )
        candidate.edge.observed_target_state = 0x4C77464F
        candidate.site.state_value = 0x4C77464F

        modifications: list[object] = []
        result = execute_primary_reconstruction_modifications(
            raw_candidates=[candidate],
            flow_graph=object(),
            node_by_key={},
            dispatcher_serial=6,
            modifications=modifications,
            owned_blocks=set(),
            owned_edges=set(),
        )

        assert result.direct_results[0].accepted_candidate is candidate
        assert modifications == [
            RedirectGoto(from_serial=14, old_target=2, new_target=66),
            ZeroStateWrite(block_serial=16, insn_ea=0x180001238),
        ]

    def test_paired_conditional_candidates_append_branch_arm_zero_state_writes(self) -> None:
        flow_blocks = {
            13: SimpleNamespace(serial=13, preds=(), succs=(14, 15), npred=0, nsucc=2),
            15: SimpleNamespace(serial=15, preds=(13,), succs=(16, 17), npred=1, nsucc=2),
        }
        flow_graph = SimpleNamespace(get_block=lambda serial: flow_blocks.get(int(serial)))

        fallthrough_candidate = _candidate(
            emission_mode="conditional_arm",
            horizon_block=15,
            target_entry=66,
            ordered_path=(158, 15, 16),
            branch_arm=0,
            state_const=0x6107F8EC,
            target_state=0x4C77464F,
            source_anchor_block=158,
            conditional_group_policy="rewrite_horizon",
            site_block_serial=16,
            site_insn_ea=0x180012EE2,
        )
        conditional_candidate = _candidate(
            emission_mode="conditional_arm",
            horizon_block=15,
            target_entry=202,
            ordered_path=(158, 15, 17),
            branch_arm=1,
            state_const=0x6107F8EC,
            target_state=0x296F2452,
            source_anchor_block=158,
            conditional_group_policy="rewrite_horizon",
            site_block_serial=17,
            site_insn_ea=0x180012EEC,
        )

        modifications: list[object] = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        result = execute_primary_reconstruction_modifications(
            raw_candidates=[fallthrough_candidate, conditional_candidate],
            flow_graph=flow_graph,
            node_by_key={},
            dispatcher_serial=6,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
        )

        assert modifications == [
            RedirectBranch(from_serial=15, old_target=16, new_target=66),
            RedirectBranch(from_serial=15, old_target=17, new_target=202),
            ZeroStateWrite(block_serial=16, insn_ea=0x180012EE2),
            ZeroStateWrite(block_serial=17, insn_ea=0x180012EEC),
        ]
        assert owned_blocks == {15}
        assert owned_edges == {(15, 66), (15, 202)}
        assert {entry.candidate.target_entry for entry in result.conditional_results} == {
            66,
            202,
        }

    def test_emits_deferred_sub7ffd_poll_corridor_bundle(self, monkeypatch) -> None:
        monkeypatch.setattr(
            exec_mod,
            "plan_shared_group_reconstruction_modifications",
            lambda **kwargs: SimpleNamespace(
                accepted=True,
                rejection_reason=None,
                ordered_via_preds=(44, 122),
                per_pred_targets=((44, 126), (122, 180)),
                emission_mode="deferred_corridor_clone",
                modifications=[],
            ),
        )

        flow_graph = SimpleNamespace(
            get_block=lambda serial: (
                SimpleNamespace(preds=(44, 122), succs=(2,), npred=2, nsucc=1)
                if int(serial) == 45
                else None
            )
        )
        modifications: list[object] = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        shared_a = _candidate(
            emission_mode="pred_split",
            horizon_block=20,
            target_entry=126,
            via_pred=44,
            first_shared_block=45,
            ordered_path=(44, 45),
        )
        shared_b = _candidate(
            emission_mode="pred_split",
            horizon_block=69,
            target_entry=180,
            via_pred=122,
            first_shared_block=45,
            ordered_path=(20, 69, 122, 45),
            state_const=exec_mod._SUB7FFD_POLL_TARGET_STATE,
        )

        result = execute_primary_reconstruction_modifications(
            raw_candidates=[shared_a, shared_b],
            flow_graph=flow_graph,
            node_by_key={},
            dispatcher_serial=6,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
        )

        assert result.shared_group_results[0].emission_mode == "deferred_corridor_clone"
        assert modifications == [
            RedirectGoto(from_serial=45, old_target=2, new_target=126),
            EdgeRedirectViaPredSplit(
                src_block=122,
                old_target=45,
                new_target=180,
                via_pred=69,
                clone_until=45,
            ),
        ]
        assert 122 in owned_blocks
        assert 45 in owned_blocks
        assert (122, 180) in owned_edges
        assert (45, 126) in owned_edges

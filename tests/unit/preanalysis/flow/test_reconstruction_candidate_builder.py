from __future__ import annotations

import d810.analyses.control_flow.reconstruction_candidate_builder as builder_module

from d810.transforms.reconstruction_planning import (
    ReconstructionEmissionMode,
    ReconstructionPlanningDecision,
)
from d810.analyses.control_flow.linearized_state_dag import (
    RedirectSourceKind,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNodeKey,
    StateRedirectAnchor,
)
from d810.analyses.control_flow.reconstruction_candidate_builder import (
    build_reconstruction_candidate,
)
from d810.analyses.control_flow.reconstruction_discovery import ReconstructionCandidateSeed
from d810.analyses.control_flow.state_machine_analysis import (
    SnapshotConstantFixpointResult,
    StateWriteSite,
)


def _make_edge(*, kind: SemanticEdgeKind = SemanticEdgeKind.TRANSITION) -> StateDagEdge:
    source_key = StateDagNodeKey(handler_serial=10, state_const=0x11111111)
    target_key = StateDagNodeKey(handler_serial=20, state_const=0x22222222)
    return StateDagEdge(
        kind=kind,
        source_key=source_key,
        target_key=target_key,
        target_state=0x22222222,
        target_entry_anchor=24,
        target_label="target",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.UNCONDITIONAL,
            block_serial=14,
            branch_arm=None,
        ),
        ordered_path=(14, 16, 18),
    )


def _constant_result() -> SnapshotConstantFixpointResult:
    return SnapshotConstantFixpointResult(
        in_stk_maps={},
        in_reg_maps={},
        out_stk_maps={},
        out_reg_maps={},
        iterations=1,
    )


def _state_write_site() -> StateWriteSite:
    return StateWriteSite(
        block_serial=14,
        state_value=0x22222222,
        insn_ea=0x180001000,
        insn_index=0,
    )


class TestBuildReconstructionCandidate:
    def test_rejects_unsupported_edge_kind(self):
        candidate, rejection = build_reconstruction_candidate(
            _make_edge(kind=SemanticEdgeKind.UNKNOWN),
            flow_graph=object(),
            node_by_key={},
            state_var_stkoff=0x10,
            constant_result=_constant_result(),
            shared_suffix_blocks=set(),
            dispatcher_region=set(),
        )

        assert candidate is None
        assert rejection is not None
        assert rejection["rejection_reason"] == "unsupported_edge_kind"

    def test_returns_seed_rejection_metadata(self, monkeypatch):
        monkeypatch.setattr(
            builder_module,
            "discover_reconstruction_candidate_seed",
            lambda *args, **kwargs: (None, "missing_path_horizon"),
        )

        candidate, rejection = build_reconstruction_candidate(
            _make_edge(),
            flow_graph=object(),
            node_by_key={},
            state_var_stkoff=0x10,
            constant_result=_constant_result(),
            shared_suffix_blocks=set(),
            dispatcher_region=set(),
        )

        assert candidate is None
        assert rejection is not None
        assert rejection["rejection_reason"] == "missing_path_horizon"

    def test_builds_direct_candidate_from_planning_decision(self, monkeypatch):
        monkeypatch.setattr(
            builder_module,
            "discover_reconstruction_candidate_seed",
            lambda *args, **kwargs: (
                ReconstructionCandidateSeed(
                    horizon_block=14,
                    site=_state_write_site(),
                    target_entry=24,
                ),
                None,
            ),
        )
        monkeypatch.setattr(
            builder_module,
            "plan_reconstruction_candidate",
            lambda *args, **kwargs: ReconstructionPlanningDecision(
                accepted=True,
                target_entry=24,
                emission_mode=ReconstructionEmissionMode.DIRECT,
                first_shared_block=None,
                via_pred=None,
            ),
        )

        candidate, rejection = build_reconstruction_candidate(
            _make_edge(),
            flow_graph=object(),
            node_by_key={},
            state_var_stkoff=0x10,
            constant_result=_constant_result(),
            shared_suffix_blocks={30},
            dispatcher_region={6},
        )

        assert rejection is None
        assert candidate is not None
        assert candidate.horizon_block == 14
        assert candidate.target_entry == 24
        assert candidate.emission_mode == "direct"
        assert candidate.first_shared_block is None
        assert candidate.via_pred is None

    def test_builds_pred_split_candidate_from_planning_decision(self, monkeypatch):
        monkeypatch.setattr(
            builder_module,
            "discover_reconstruction_candidate_seed",
            lambda *args, **kwargs: (
                ReconstructionCandidateSeed(
                    horizon_block=16,
                    site=_state_write_site(),
                    target_entry=24,
                ),
                None,
            ),
        )
        monkeypatch.setattr(
            builder_module,
            "plan_reconstruction_candidate",
            lambda *args, **kwargs: ReconstructionPlanningDecision(
                accepted=True,
                target_entry=24,
                emission_mode=ReconstructionEmissionMode.PRED_SPLIT,
                first_shared_block=16,
                via_pred=12,
            ),
        )

        candidate, rejection = build_reconstruction_candidate(
            _make_edge(),
            flow_graph=object(),
            node_by_key={},
            state_var_stkoff=0x10,
            constant_result=_constant_result(),
            shared_suffix_blocks=set(),
            dispatcher_region={6},
        )

        assert rejection is None
        assert candidate is not None
        assert candidate.horizon_block == 16
        assert candidate.first_shared_block == 16
        assert candidate.via_pred == 12
        assert candidate.emission_mode == "pred_split"

from __future__ import annotations

import d810.cfg.terminal_family_split as split_mod
from d810.cfg.graph_modification import (
    DirectTerminalLoweringGroup,
    DirectTerminalLoweringKind,
)
from d810.cfg.terminal_family_split import (
    TerminalFamilySplitCandidate,
    build_terminal_family_direct_const_lowering_modification,
    build_terminal_family_split_candidates,
    build_terminal_family_split_modification,
    build_terminal_family_split_proposals,
    plan_terminal_family_splits,
    select_terminal_family_split,
)


class _DummyBlock:
    def __init__(self, succs: tuple[int, ...]):
        self.succs = succs
        self.nsucc = len(succs)


class _DummyFlowGraph:
    def __init__(self, mapping: dict[int, tuple[int, ...]]):
        self._mapping = {
            int(k): _DummyBlock(tuple(int(v) for v in succs))
            for k, succs in mapping.items()
        }
        self.entry_serial = min(self._mapping) if self._mapping else None

    def get_block(self, serial: int):
        return self._mapping.get(int(serial))


class _DummyBuilder:
    def private_terminal_suffix(
        self,
        *,
        anchor_serial: int,
        shared_entry_serial: int,
        return_block_serial: int,
        suffix_serials: tuple[int, ...],
        reason: str,
    ):
        return (
            "pts",
            int(anchor_serial),
            int(shared_entry_serial),
            int(return_block_serial),
            tuple(int(s) for s in suffix_serials),
            reason,
        )

    def private_terminal_suffix_group(
        self,
        *,
        anchors: tuple[int, ...],
        shared_entry_serial: int,
        return_block_serial: int,
        suffix_serials: tuple[int, ...],
        reason: str,
    ):
        return (
            "ptsg",
            tuple(int(a) for a in anchors),
            int(shared_entry_serial),
            int(return_block_serial),
            tuple(int(s) for s in suffix_serials),
            reason,
        )

    def direct_terminal_lowering(
        self,
        *,
        sites,
        shared_entry_serial: int,
        return_block_serial: int,
        suffix_serials: tuple[int, ...],
        reason: str,
    ):
        return DirectTerminalLoweringGroup(
            sites=tuple(sites),
            shared_entry_serial=int(shared_entry_serial),
            return_block_serial=int(return_block_serial),
            suffix_serials=tuple(int(s) for s in suffix_serials),
            reason=reason,
        )


class _RawCandidate:
    def __init__(
        self,
        *,
        source_block: int,
        branch_arm: int | None,
        family_entry: int,
        path: tuple[int, ...],
        value_family_signature: tuple[object, ...],
        lineage_eas: tuple[int, ...],
    ):
        self.source_block = source_block
        self.branch_arm = branch_arm
        self.family_entry = family_entry
        self.path = path
        self.value_family_signature = value_family_signature
        self.lineage_eas = lineage_eas


class _Collection:
    def __init__(self, candidates):
        self.candidates = tuple(candidates)


class _Report:
    def __init__(self, candidates):
        self.collection = _Collection(candidates)
        self.seed_reports = ()
        self.candidate_reports = ()


class TestBuildTerminalFamilySplitProposals:
    def test_selects_non_primary_bucket_anchor_for_shared_suffix(self):
        candidates = (
            TerminalFamilySplitCandidate(
                source_block=10,
                branch_arm=None,
                family_entry=20,
                path=(20, 30, 40),
                value_family_signature=("keep",),
                lineage_eas=(0x1000,),
            ),
            TerminalFamilySplitCandidate(
                source_block=11,
                branch_arm=None,
                family_entry=21,
                path=(21, 30, 40),
                value_family_signature=("split",),
                lineage_eas=(0x2000,),
            ),
            TerminalFamilySplitCandidate(
                source_block=12,
                branch_arm=None,
                family_entry=22,
                path=(22, 30, 40),
                value_family_signature=("keep",),
                lineage_eas=(0x3000,),
            ),
        )
        flow_graph = _DummyFlowGraph({
            20: (30,),
            21: (30,),
            22: (30,),
            30: (40,),
            40: (),
        })

        proposals = build_terminal_family_split_proposals(
            candidates,
            projected_flow_graph=flow_graph,
        )

        assert proposals == (
            build_expected := proposals[0],
        )
        assert build_expected.suffix_serials == (30, 40)
        assert build_expected.selected_candidate_indexes == (1,)
        assert build_expected.selected_anchors == (21,)
        assert build_expected.primary_signature == ("keep",)

    def test_skips_already_direct_lowered_anchors(self):
        candidates = (
            TerminalFamilySplitCandidate(
                source_block=10,
                branch_arm=None,
                family_entry=20,
                path=(20, 30, 40),
                value_family_signature=("keep",),
                lineage_eas=(0x1000,),
            ),
            TerminalFamilySplitCandidate(
                source_block=11,
                branch_arm=None,
                family_entry=21,
                path=(21, 30, 40),
                value_family_signature=("split",),
                lineage_eas=(0x2000,),
            ),
        )
        flow_graph = _DummyFlowGraph({
            20: (30,),
            21: (30,),
            30: (40,),
            40: (),
        })

        proposals = build_terminal_family_split_proposals(
            candidates,
            projected_flow_graph=flow_graph,
            excluded_anchors=frozenset({21}),
        )

        assert proposals == ()


class TestBuildTerminalFamilySplitCandidates:
    def test_adapts_raw_candidate_objects(self):
        candidates = build_terminal_family_split_candidates(
            (
                _RawCandidate(
                    source_block=11,
                    branch_arm=1,
                    family_entry=21,
                    path=(21, 30, 40),
                    value_family_signature=("split",),
                    lineage_eas=(0x2000,),
                ),
            )
        )

        assert candidates == (
            TerminalFamilySplitCandidate(
                source_block=11,
                branch_arm=1,
                family_entry=21,
                path=(21, 30, 40),
                value_family_signature=("split",),
                lineage_eas=(0x2000,),
            ),
        )


class TestBuildTerminalFamilySplitModification:
    def test_rejects_non_terminal_suffix_in_projected_graph(self):
        flow_graph = _DummyFlowGraph({
            30: (40,),
            40: (50,),
            50: (),
        })

        modification = build_terminal_family_split_modification(
            builder=_DummyBuilder(),
            anchors=(21,),
            suffix_serials=(30, 40),
            projected_flow_graph=flow_graph,
        )

        assert modification is None


class TestBuildTerminalFamilyDirectConstLoweringModification:
    def test_builds_return_const_site_for_literal_materializer_signature(self):
        candidate = _RawCandidate(
            source_block=26,
            branch_arm=0,
            family_entry=27,
            path=(27, 218, 219),
            value_family_signature=(
                "terminal_value_chain",
                (
                    (
                        "op",
                        4,
                        "dst",
                        ("stk", 2032, 8),
                        "src_l",
                        ("const", 0x5644FD01B1049C4B),
                        "src_r",
                        ("none",),
                    ),
                    (
                        "op",
                        4,
                        "dst",
                        ("reg", 8, 8),
                        "src_l",
                        ("stk", 2032, 8),
                        "src_r",
                        ("none",),
                    ),
                ),
            ),
            lineage_eas=(0x180013B63,),
        )

        modification = build_terminal_family_direct_const_lowering_modification(
            builder=_DummyBuilder(),
            selected_anchors=(27,),
            selected_candidates=(candidate,),
            suffix_serials=(218, 219),
        )

        assert isinstance(modification, DirectTerminalLoweringGroup)
        assert modification.reason == "terminal_family_direct_const_lowering"
        assert len(modification.sites) == 1
        assert modification.sites[0].anchor_serial == 27
        assert modification.sites[0].kind is DirectTerminalLoweringKind.RETURN_CONST
        assert modification.sites[0].const_value == 0x5644FD01B1049C4B

    def test_skips_non_literal_materializer_signature(self):
        candidate = _RawCandidate(
            source_block=10,
            branch_arm=None,
            family_entry=20,
            path=(20, 30, 40),
            value_family_signature=(("not", "a", "literal"),),
            lineage_eas=(0x1000,),
        )

        assert (
            build_terminal_family_direct_const_lowering_modification(
                builder=_DummyBuilder(),
                selected_anchors=(20,),
                selected_candidates=(candidate,),
                suffix_serials=(30, 40),
            )
            is None
        )


class TestSelectTerminalFamilySplit:
    def test_returns_first_projectable_proposal(self):
        candidates = (
            TerminalFamilySplitCandidate(
                source_block=10,
                branch_arm=None,
                family_entry=20,
                path=(20, 30, 40),
                value_family_signature=("keep",),
                lineage_eas=(0x1000,),
            ),
            TerminalFamilySplitCandidate(
                source_block=11,
                branch_arm=None,
                family_entry=21,
                path=(21, 30, 40),
                value_family_signature=("split",),
                lineage_eas=(0x2000,),
            ),
        )
        base_flow_graph = _DummyFlowGraph({
            20: (30,),
            21: (30,),
            30: (40,),
            40: (),
        })
        projected_flow_graph = base_flow_graph

        original_compile = split_mod.compile_patch_plan
        original_project = split_mod.project_post_state
        try:
            split_mod.compile_patch_plan = lambda mods, _cfg: tuple(mods)
            split_mod.project_post_state = lambda _cfg, _plan: projected_flow_graph

            selection = select_terminal_family_split(
                candidates,
                base_flow_graph=base_flow_graph,
                projected_flow_graph=projected_flow_graph,
                builder=_DummyBuilder(),
                modifications=[],
                compute_reachable_blocks=lambda fg: set(fg._mapping),
            )
        finally:
            split_mod.compile_patch_plan = original_compile
            split_mod.project_post_state = original_project

        assert selection is not None
        assert selection.selected_candidate_indexes == (1,)
        assert selection.selected_anchors == (21,)
        assert selection.suffix_serials == (30, 40)


class TestPlanTerminalFamilySplits:
    def test_runs_one_split_iteration_and_applies_modification(self):
        raw_candidates = (
            _RawCandidate(
                source_block=10,
                branch_arm=None,
                family_entry=20,
                path=(20, 30, 40),
                value_family_signature=("keep",),
                lineage_eas=(0x1000,),
            ),
            _RawCandidate(
                source_block=11,
                branch_arm=None,
                family_entry=21,
                path=(21, 30, 40),
                value_family_signature=("split",),
                lineage_eas=(0x2000,),
            ),
        )
        base_flow_graph = _DummyFlowGraph({
            20: (30,),
            21: (30,),
            30: (40,),
            40: (),
        })
        projected_flow_graph = base_flow_graph
        modifications = []
        call_count = {"value": 0}

        def collect_report(*args, **kwargs):
            call_count["value"] += 1
            if call_count["value"] == 1:
                return _Report(raw_candidates)
            return _Report((raw_candidates[0],))

        original_compile = split_mod.compile_patch_plan
        original_project = split_mod.project_post_state
        try:
            split_mod.compile_patch_plan = lambda mods, _cfg: tuple(mods)
            split_mod.project_post_state = lambda _cfg, _plan: projected_flow_graph

            run = plan_terminal_family_splits(
                dag=object(),
                base_flow_graph=base_flow_graph,
                projected_flow_graph=projected_flow_graph,
                dispatcher_region=set(),
                state_var_stkoff=None,
                builder=_DummyBuilder(),
                modifications=modifications,
                collect_report=collect_report,
                compute_reachable_blocks=lambda fg: set(fg._mapping),
            )
        finally:
            split_mod.compile_patch_plan = original_compile
            split_mod.project_post_state = original_project

        assert run.emitted_count == 1
        assert len(run.iterations) == 2
        assert run.iterations[0].selected is not None
        assert run.iterations[0].selected_candidates == (raw_candidates[1],)
        assert run.iterations[1].selected is None
        assert modifications == [
            ("pts", 21, 30, 40, (30, 40), "terminal_family_split"),
        ]

    def test_appends_private_suffix_for_literal_terminal_split(self):
        raw_candidates = (
            _RawCandidate(
                source_block=10,
                branch_arm=None,
                family_entry=20,
                path=(20, 30, 40),
                value_family_signature=("keep",),
                lineage_eas=(0x1000,),
            ),
            _RawCandidate(
                source_block=11,
                branch_arm=None,
                family_entry=21,
                path=(21, 30, 40),
                value_family_signature=(
                    (
                        "op",
                        4,
                        "dst",
                        ("stk", 2032, 8),
                        "src_l",
                        ("const", 0x1234),
                        "src_r",
                        ("none",),
                    ),
                ),
                lineage_eas=(0x2000,),
            ),
        )
        base_flow_graph = _DummyFlowGraph({
            20: (30,),
            21: (30,),
            30: (40,),
            40: (),
        })
        projected_flow_graph = base_flow_graph
        modifications = []
        call_count = {"value": 0}

        def collect_report(*args, **kwargs):
            call_count["value"] += 1
            if call_count["value"] == 1:
                return _Report(raw_candidates)
            return _Report((raw_candidates[0],))

        original_compile = split_mod.compile_patch_plan
        original_project = split_mod.project_post_state
        try:
            split_mod.compile_patch_plan = lambda mods, _cfg: tuple(mods)
            split_mod.project_post_state = lambda _cfg, _plan: projected_flow_graph

            run = plan_terminal_family_splits(
                dag=object(),
                base_flow_graph=base_flow_graph,
                projected_flow_graph=projected_flow_graph,
                dispatcher_region=set(),
                state_var_stkoff=None,
                builder=_DummyBuilder(),
                modifications=modifications,
                collect_report=collect_report,
                compute_reachable_blocks=lambda fg: set(fg._mapping),
            )
        finally:
            split_mod.compile_patch_plan = original_compile
            split_mod.project_post_state = original_project

        assert run.emitted_count == 1
        assert len(modifications) == 1
        assert modifications == [
            ("pts", 21, 30, 40, (30, 40), "terminal_family_split"),
        ]

    def test_literal_anchor_reappears_until_projected_graph_changes(self):
        raw_candidates = (
            _RawCandidate(
                source_block=10,
                branch_arm=None,
                family_entry=20,
                path=(20, 30, 40),
                value_family_signature=("keep",),
                lineage_eas=(0x1000,),
            ),
            _RawCandidate(
                source_block=11,
                branch_arm=None,
                family_entry=21,
                path=(21, 30, 40),
                value_family_signature=(
                    (
                        "op",
                        4,
                        "dst",
                        ("stk", 2032, 8),
                        "src_l",
                        ("const", 0x1234),
                        "src_r",
                        ("none",),
                    ),
                ),
                lineage_eas=(0x2000,),
            ),
        )
        base_flow_graph = _DummyFlowGraph({
            20: (30,),
            21: (30,),
            30: (40,),
            40: (),
        })
        projected_flow_graph = base_flow_graph
        modifications = []
        call_count = {"value": 0}

        def collect_report(*args, **kwargs):
            call_count["value"] += 1
            if call_count["value"] <= 2:
                return _Report(raw_candidates)
            return _Report((raw_candidates[0],))

        original_compile = split_mod.compile_patch_plan
        original_project = split_mod.project_post_state
        try:
            split_mod.compile_patch_plan = lambda mods, _cfg: tuple(mods)
            split_mod.project_post_state = lambda _cfg, _plan: projected_flow_graph

            run = plan_terminal_family_splits(
                dag=object(),
                base_flow_graph=base_flow_graph,
                projected_flow_graph=projected_flow_graph,
                dispatcher_region=set(),
                state_var_stkoff=None,
                builder=_DummyBuilder(),
                modifications=modifications,
                collect_report=collect_report,
                compute_reachable_blocks=lambda fg: set(fg._mapping),
            )
        finally:
            split_mod.compile_patch_plan = original_compile
            split_mod.project_post_state = original_project

        assert run.emitted_count == 2
        assert modifications == [
            ("pts", 21, 30, 40, (30, 40), "terminal_family_split"),
            ("pts", 21, 30, 40, (30, 40), "terminal_family_split"),
        ]

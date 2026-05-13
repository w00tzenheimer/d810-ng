from __future__ import annotations

from types import SimpleNamespace

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.cfg.graph_modification import ConvertToGoto, RedirectBranch, RedirectGoto, ZeroStateWrite
from d810.optimizers.microcode.flow.flattening.hodur.strategies import (
    linearized_flow_graph as lfg_module,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.linearized_flow_graph import (
    _build_narrow_branch_local_region_fallback_candidates,
    _collect_consumed_structured_region_state_edges,
    _collect_structured_region_zero_state_write_modifications,
    _collect_trivial_redirect_tail_zero_state_write_modifications,
    _collect_unmatched_region_sites,
    _sanitize_progressive_topology_modifications,
    _match_accepted_region_sites,
    _filter_unsafe_preferred_region_lowering,
    _should_defer_transient_internal_region_site,
)


def test_collect_structured_region_zero_state_write_modifications_emits_path_tail_cleanup(monkeypatch):
    candidate = SimpleNamespace(
        edge=SimpleNamespace(
            ordered_path=(15, 16),
            target_state=0x4C77464F,
        )
    )

    def fake_find_last_state_write_site_on_path_snapshot(
        flow_graph,
        ordered_path,
        state_var_stkoff,
        *,
        in_stk_maps=None,
        in_reg_maps=None,
    ):
        assert ordered_path == (15, 16)
        assert state_var_stkoff == 0x7BC
        assert in_stk_maps == {15: {}}
        assert in_reg_maps == {15: {}}
        return (
            16,
            SimpleNamespace(
                state_value=0x4C77464F,
                insn_ea=0x180012EE2,
            ),
        )

    monkeypatch.setattr(
        lfg_module,
        "find_last_state_write_site_on_path_snapshot",
        fake_find_last_state_write_site_on_path_snapshot,
    )

    mods = _collect_structured_region_zero_state_write_modifications(
        accepted_candidates=(candidate,),
        flow_graph=object(),
        state_var_stkoff=0x7BC,
        constant_result=SimpleNamespace(
            in_stk_maps={15: {}},
            in_reg_maps={15: {}},
        ),
        existing_modifications=(),
    )

    assert mods == (ZeroStateWrite(block_serial=16, insn_ea=0x180012EE2),)


def test_collect_structured_region_zero_state_write_modifications_dedupes_existing_cleanup(monkeypatch):
    candidate = SimpleNamespace(
        edge=SimpleNamespace(
            ordered_path=(15, 17),
            target_state=0x296F2452,
        )
    )

    monkeypatch.setattr(
        lfg_module,
        "find_last_state_write_site_on_path_snapshot",
        lambda *args, **kwargs: (
            17,
            SimpleNamespace(
                state_value=0x296F2452,
                insn_ea=0x180012EEC,
            ),
        ),
    )

    mods = _collect_structured_region_zero_state_write_modifications(
        accepted_candidates=(candidate,),
        flow_graph=object(),
        state_var_stkoff=0x7BC,
        constant_result=SimpleNamespace(
            in_stk_maps={},
            in_reg_maps={},
        ),
        existing_modifications=(
            ZeroStateWrite(block_serial=17, insn_ea=0x180012EEC),
        ),
    )

    assert mods == ()


def test_collect_structured_region_zero_state_write_modifications_accepts_observed_alias_target_state(
    monkeypatch,
):
    candidate = SimpleNamespace(
        edge=SimpleNamespace(
            ordered_path=(15, 16),
            target_state=0x474EEEBB,
            observed_target_state=0x4C77464F,
        )
    )

    monkeypatch.setattr(
        lfg_module,
        "find_last_state_write_site_on_path_snapshot",
        lambda *args, **kwargs: (
            16,
            SimpleNamespace(
                state_value=0x4C77464F,
                insn_ea=0x180012EF2,
            ),
        ),
    )

    mods = _collect_structured_region_zero_state_write_modifications(
        accepted_candidates=(candidate,),
        flow_graph=object(),
        state_var_stkoff=0x7BC,
        constant_result=SimpleNamespace(
            in_stk_maps={},
            in_reg_maps={},
        ),
        existing_modifications=(),
    )

    assert mods == (ZeroStateWrite(block_serial=16, insn_ea=0x180012EF2),)


def test_collect_consumed_structured_region_state_edges_includes_observed_alias_targets():
    site = SimpleNamespace(
        source_state=0x6107F8EC,
        target_state=0x474EEEBB,
        successor_state_value=0x474EEEBB,
        edge=SimpleNamespace(
            source_key=SimpleNamespace(state_const=0x6107F8EC),
            target_state=0x474EEEBB,
            observed_target_state=0x4C77464F,
        ),
    )
    candidate = SimpleNamespace(
        edge=SimpleNamespace(
            source_key=SimpleNamespace(state_const=0x6107F8EC),
            target_state=0x474EEEBB,
            observed_target_state=0x4C77464F,
        ),
    )

    consumed = _collect_consumed_structured_region_state_edges(
        accepted_sites=(site,),
        accepted_candidates=(candidate,),
    )

    assert consumed == frozenset(
        {
            (0x6107F8EC, 0x474EEEBB),
            (0x6107F8EC, 0x4C77464F),
        }
    )


def test_collect_unmatched_region_sites_filters_out_already_materialized_site():
    matched_site = SimpleNamespace(source_state=0x6107F8EC, target_state=0x296F2452)
    unmatched_site = SimpleNamespace(source_state=0x6107F8EC, target_state=0x474EEEBB)

    unmatched = _collect_unmatched_region_sites(
        lowering_sites=(matched_site, unmatched_site),
        accepted_sites=(matched_site,),
    )

    assert unmatched == (unmatched_site,)


def test_build_narrow_branch_local_region_fallback_candidates_preserves_branch_local_alias_context():
    flow_graph = FlowGraph(
        blocks={
            15: BlockSnapshot(15, 0, (16, 17), (), 0, 0, ()),
            16: BlockSnapshot(16, 0, (2,), (15,), 0, 0, ()),
            17: BlockSnapshot(17, 0, (2,), (15,), 0, 0, ()),
            2: BlockSnapshot(2, 0, (), (16, 17), 0, 0, ()),
        },
        entry_serial=15,
        func_ea=0x180012B60,
    )
    edge = SimpleNamespace(
        source_key=SimpleNamespace(state_const=0x6107F8EC),
        source_anchor=SimpleNamespace(block_serial=15, branch_arm=0),
        ordered_path=(15, 16),
        target_state=0x474EEEBB,
        observed_target_state=0x4C77464F,
        site=SimpleNamespace(
            block_serial=16,
            state_value=0x4C77464F,
            insn_ea=0x180012EE2,
        ),
    )
    site = SimpleNamespace(
        site_kind="exit",
        source_state=0x6107F8EC,
        target_state=0x474EEEBB,
        source_entry_anchor=136,
        source_anchor_block=15,
        target_entry_anchor=63,
        ordered_path=(15, 16),
        edge=edge,
        semantic_target_label="STATE_474EEEBB",
        successor_state_value=0x474EEEBB,
    )

    candidates = _build_narrow_branch_local_region_fallback_candidates(
        unresolved_sites=(site,),
        flow_graph=flow_graph,
    )

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.emission_mode == "conditional_arm"
    assert candidate.conditional_group_policy == "rewrite_horizon"
    assert candidate.horizon_block == 15
    assert candidate.target_entry == 63
    assert candidate.edge is edge
    assert candidate.site.block_serial == 16
    assert candidate.site.state_value == 0x4C77464F


def test_build_narrow_branch_local_region_fallback_candidates_skips_non_branch_local_sites():
    flow_graph = FlowGraph(
        blocks={
            136: BlockSnapshot(136, 0, (137,), (), 0, 0, ()),
            137: BlockSnapshot(137, 0, (2,), (136,), 0, 0, ()),
            2: BlockSnapshot(2, 0, (), (137,), 0, 0, ()),
        },
        entry_serial=136,
        func_ea=0x180012B60,
    )
    site = SimpleNamespace(
        site_kind="exit",
        source_state=0x139F2922,
        target_state=0x2315233C,
        source_entry_anchor=136,
        source_anchor_block=136,
        target_entry_anchor=211,
        ordered_path=(136,),
        edge=SimpleNamespace(
            source_key=SimpleNamespace(state_const=0x139F2922),
            source_anchor=SimpleNamespace(block_serial=136, branch_arm=None),
            ordered_path=(136,),
            target_state=0x2315233C,
        ),
        semantic_target_label="STATE_2315233C",
        successor_state_value=0x2315233C,
    )

    candidates = _build_narrow_branch_local_region_fallback_candidates(
        unresolved_sites=(site,),
        flow_graph=flow_graph,
    )

    assert candidates == ()


def test_collect_trivial_redirect_tail_zero_state_write_modifications_emits_cleanup_for_redirected_dispatcher_feeder(
    monkeypatch,
):
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (), (), 0, 0, ()),
            16: BlockSnapshot(16, 0, (2,), (), 0, 0, ()),
        },
        entry_serial=16,
        func_ea=0x180012B60,
    )

    monkeypatch.setattr(
        lfg_module,
        "find_last_state_write_site_snapshot",
        lambda *args, **kwargs: SimpleNamespace(
            state_value=0x4C77464F,
            insn_ea=0x180012EE2,
            unsafe_trailing_insn_eas=(),
            trailing_insn_eas=(0x180012EEA,),
        ),
    )

    mods = _collect_trivial_redirect_tail_zero_state_write_modifications(
        modifications=(
            RedirectGoto(from_serial=16, old_target=2, new_target=66),
        ),
        flow_graph=flow_graph,
        dispatcher_serial=2,
        state_var_stkoff=0x7BC,
    )

    assert mods == (ZeroStateWrite(block_serial=16, insn_ea=0x180012EE2),)


def test_collect_trivial_redirect_tail_zero_state_write_modifications_skips_nontrivial_tail(
    monkeypatch,
):
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (), (), 0, 0, ()),
            17: BlockSnapshot(17, 0, (2,), (), 0, 0, ()),
        },
        entry_serial=17,
        func_ea=0x180012B60,
    )

    monkeypatch.setattr(
        lfg_module,
        "find_last_state_write_site_snapshot",
        lambda *args, **kwargs: SimpleNamespace(
            state_value=0x296F2452,
            insn_ea=0x180012EEC,
            unsafe_trailing_insn_eas=(0x180012EF0,),
            trailing_insn_eas=(0x180012EF0, 0x180012EF8),
        ),
    )

    mods = _collect_trivial_redirect_tail_zero_state_write_modifications(
        modifications=(
            RedirectGoto(from_serial=17, old_target=2, new_target=202),
        ),
        flow_graph=flow_graph,
        dispatcher_serial=2,
        state_var_stkoff=0x7BC,
    )

    assert mods == ()


def test_filter_unsafe_preferred_region_lowering_rejects_conditional_arm_when_write_horizon_is_later(
    monkeypatch,
):
    preferred = SimpleNamespace(
        emission_mode="conditional_arm",
        horizon_block=163,
        target_entry_anchor=72,
    )
    site = SimpleNamespace(
        ordered_path=(161, 163, 165),
        source_anchor_block=163,
    )

    monkeypatch.setattr(
        lfg_module,
        "find_last_state_write_site_on_path_snapshot",
        lambda *args, **kwargs: (
            165,
            SimpleNamespace(
                unsafe_trailing_insn_eas=(),
            ),
        ),
    )

    filtered = _filter_unsafe_preferred_region_lowering(
        preferred=preferred,
        site=site,
        flow_graph=object(),
        state_var_stkoff=0x7BC,
        constant_result=SimpleNamespace(in_stk_maps={}, in_reg_maps={}),
    )

    assert filtered is None


def test_filter_unsafe_preferred_region_lowering_keeps_conditional_arm_when_write_horizon_matches_source(
    monkeypatch,
):
    preferred = SimpleNamespace(
        emission_mode="conditional_arm",
        horizon_block=139,
        target_entry_anchor=211,
    )
    site = SimpleNamespace(
        ordered_path=(136, 137, 139),
        source_anchor_block=139,
    )

    monkeypatch.setattr(
        lfg_module,
        "find_last_state_write_site_on_path_snapshot",
        lambda *args, **kwargs: (
            139,
            SimpleNamespace(
                unsafe_trailing_insn_eas=(),
            ),
        ),
    )

    filtered = _filter_unsafe_preferred_region_lowering(
        preferred=preferred,
        site=site,
        flow_graph=object(),
        state_var_stkoff=0x7BC,
        constant_result=SimpleNamespace(in_stk_maps={}, in_reg_maps={}),
    )

    assert filtered is preferred


def test_match_accepted_region_sites_prefers_semantic_signature_over_edge_identity():
    edge_a = SimpleNamespace(
        source_key=SimpleNamespace(state_const=0x139F2922, handler_serial=136),
        target_state=0x2315233C,
        ordered_path=(136, 137, 139, 141),
    )
    edge_b = SimpleNamespace(
        source_key=SimpleNamespace(state_const=0x139F2922, handler_serial=136),
        target_state=0x2315233C,
        ordered_path=(136, 137, 139, 141),
    )
    site = SimpleNamespace(
        source_state=0x139F2922,
        target_state=0x2315233C,
        source_entry_anchor=136,
        target_entry_anchor=211,
        ordered_path=(136, 137, 139, 141),
        edge=edge_a,
    )
    candidate = SimpleNamespace(
        edge=edge_b,
        target_entry=211,
    )

    matched = _match_accepted_region_sites(
        lowering_sites=(site,),
        accepted_candidates=(candidate,),
    )

    assert matched == (site,)


def test_match_accepted_region_sites_falls_back_to_edge_identity_when_signature_is_incomplete():
    edge = SimpleNamespace(
        source_key=SimpleNamespace(state_const=0x5D0AEBD3),
        target_state=0x606DC166,
        ordered_path=(78,),
    )
    site = SimpleNamespace(
        source_state=0x5D0AEBD3,
        target_state=0x606DC166,
        source_entry_anchor=78,
        target_entry_anchor=14,
        ordered_path=(78,),
        edge=edge,
    )
    candidate = SimpleNamespace(
        edge=edge,
        target_entry=14,
    )

    matched = _match_accepted_region_sites(
        lowering_sites=(site,),
        accepted_candidates=(candidate,),
    )

    assert matched == (site,)


def test_filter_unsafe_preferred_region_lowering_keeps_conditional_arm_for_private_branch_feeder(
    monkeypatch,
):
    preferred = SimpleNamespace(
        emission_mode="conditional_arm",
        horizon_block=15,
        target_entry_anchor=68,
    )
    site = SimpleNamespace(
        ordered_path=(15, 16),
        source_anchor_block=15,
    )
    flow_graph = FlowGraph(
        blocks={
            15: BlockSnapshot(15, 0, (16, 17), (), 0, 0, ()),
            16: BlockSnapshot(16, 0, (2,), (15,), 0, 0, ()),
            17: BlockSnapshot(17, 0, (2,), (15,), 0, 0, ()),
            2: BlockSnapshot(2, 0, (), (16, 17), 0, 0, ()),
        },
        entry_serial=15,
        func_ea=0x180012B60,
    )

    monkeypatch.setattr(
        lfg_module,
        "find_last_state_write_site_on_path_snapshot",
        lambda *args, **kwargs: (
            16,
            SimpleNamespace(
                unsafe_trailing_insn_eas=(),
            ),
        ),
    )

    filtered = _filter_unsafe_preferred_region_lowering(
        preferred=preferred,
        site=site,
        flow_graph=flow_graph,
        state_var_stkoff=0x7BC,
        constant_result=SimpleNamespace(in_stk_maps={}, in_reg_maps={}),
    )

    assert filtered is preferred


def test_filter_unsafe_preferred_region_lowering_keeps_conditional_arm_for_singleton_branch_head(
    monkeypatch,
):
    preferred = SimpleNamespace(
        emission_mode="conditional_arm",
        horizon_block=136,
        target_entry_anchor=66,
    )
    site = SimpleNamespace(
        ordered_path=(136,),
        source_anchor_block=136,
    )
    flow_graph = FlowGraph(
        blocks={
            136: BlockSnapshot(136, 0, (137, 142), (), 0, 0, ()),
            137: BlockSnapshot(137, 0, (), (136,), 0, 0, ()),
            142: BlockSnapshot(142, 0, (), (136,), 0, 0, ()),
        },
        entry_serial=136,
        func_ea=0x180012B60,
    )

    monkeypatch.setattr(
        lfg_module,
        "find_last_state_write_site_on_path_snapshot",
        lambda *args, **kwargs: (
            158,
            SimpleNamespace(
                unsafe_trailing_insn_eas=(0x1234, 0x1235),
            ),
        ),
    )

    filtered = _filter_unsafe_preferred_region_lowering(
        preferred=preferred,
        site=site,
        flow_graph=flow_graph,
        state_var_stkoff=0x7BC,
        constant_result=SimpleNamespace(in_stk_maps={}, in_reg_maps={}),
    )

    assert filtered is preferred


def test_should_defer_transient_internal_region_site_for_transient_to_transient_direct_handoff():
    site = SimpleNamespace(
        site_kind="internal",
        source_state=0x1AB9946F,
        target_state=0x7C2C0220,
        edge=SimpleNamespace(
            source_anchor=SimpleNamespace(branch_arm=None),
        ),
    )
    dag = SimpleNamespace(
        transient_state_values=(0x1AB9946F, 0x7C2C0220, 0x2A5ADB57),
    )

    assert _should_defer_transient_internal_region_site(site=site, dag=dag) is True


def test_should_not_defer_transient_internal_region_site_for_nontransient_boundary():
    site = SimpleNamespace(
        site_kind="internal",
        source_state=0x7C2C0220,
        target_state=0x37B42A40,
        edge=SimpleNamespace(
            source_anchor=SimpleNamespace(branch_arm=None),
        ),
    )
    dag = SimpleNamespace(
        transient_state_values=(0x1AB9946F, 0x7C2C0220, 0x2A5ADB57),
    )

    assert _should_defer_transient_internal_region_site(site=site, dag=dag) is False


def test_sanitize_progressive_topology_modifications_drops_stale_redirect_after_prior_rewrite():
    flow_graph = FlowGraph(
        blocks={
            34: BlockSnapshot(34, 0, (35,), (), 0, 0, ()),
            35: BlockSnapshot(35, 0, (), (34,), 0, 0, ()),
            211: BlockSnapshot(211, 0, (), (), 0, 0, ()),
            212: BlockSnapshot(212, 0, (), (), 0, 0, ()),
        },
        entry_serial=34,
        func_ea=0x180012B60,
    )

    sanitized, normalized, dropped = _sanitize_progressive_topology_modifications(
        (
            RedirectGoto(from_serial=34, old_target=35, new_target=211),
            RedirectGoto(from_serial=34, old_target=35, new_target=212),
        ),
        flow_graph=flow_graph,
    )

    assert sanitized == (
        RedirectGoto(from_serial=34, old_target=35, new_target=211),
    )
    assert normalized == 0
    assert dropped == 1


def test_sanitize_progressive_topology_modifications_normalizes_duplicate_target_branch_to_goto():
    flow_graph = FlowGraph(
        blocks={
            15: BlockSnapshot(15, 0, (16, 17), (), 0, 0, ()),
            16: BlockSnapshot(16, 0, (), (15,), 0, 0, ()),
            17: BlockSnapshot(17, 0, (), (15,), 0, 0, ()),
        },
        entry_serial=15,
        func_ea=0x180012B60,
    )

    sanitized, normalized, dropped = _sanitize_progressive_topology_modifications(
        (
            RedirectBranch(from_serial=15, old_target=16, new_target=17),
        ),
        flow_graph=flow_graph,
    )

    assert sanitized == (
        ConvertToGoto(block_serial=15, goto_target=17),
    )
    assert normalized == 1
    assert dropped == 0

"""Whole-block purity of a literal switch router, not its branch name alone."""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from d810.ir.flowgraph import InsnKind, InsnSnapshot, MopSnapshot, OperandKind
from d810.transforms.dispatcher_corridor_coverage import _is_effect_free_dispatcher_router


@pytest.mark.parametrize("bad", [
    "nested_call", "nested_load", "case_args", "case_child", "bool_target",
    "bool_value", "not_final", "load_prefix", "missing_selector",
])
def test_switch_router_rejects_nested_effects_and_malformed_rows(bad):
    table = _table()
    prefix = suffix = ()
    if bad in {"nested_call", "nested_load"}:
        table = replace(table, l=MopSnapshot(
            kind=OperandKind.SUBINSN,
            sub_kind=InsnKind.CALL if bad == "nested_call" else InsnKind.LOAD,
            sub_l=table.l,
        ))
    elif bad == "case_args":
        table = replace(table, r=replace(table.r, args=(table.l,)))
    elif bad == "case_child":
        table = replace(table, r=replace(table.r, sub_l=table.l))
    elif bad == "bool_target":
        table = replace(table, r=replace(table.r, switch_cases=(((0,), True), ((), 2))))
    elif bad == "bool_value":
        table = replace(table, r=replace(table.r, switch_cases=(((True,), 3), ((), 2))))
    elif bad == "not_final":
        suffix = (InsnSnapshot(opcode=0, ea=0x1030, operands=(), kind=InsnKind.NOP),)
    elif bad == "load_prefix":
        prefix = (InsnSnapshot(opcode=0, ea=0x1010, operands=(), kind=InsnKind.LOAD),)
    else:
        table = replace(table, l=None)
    assert not _is_effect_free_dispatcher_router(SimpleNamespace(
        insn_snapshots=(*prefix, table, *suffix), succs=(3, 2),
    ))


@pytest.mark.parametrize("feeder_self_edge", [False, True])
def test_literal_switch_forecast_binds_full_retirement_with_shared_feeder(feeder_self_edge):
    from d810.ir.flowgraph import BlockSnapshot, FlowGraph
    from d810.transforms import dispatcher_corridor_coverage as coverage_api
    from d810.transforms.graph_modification import RedirectGoto
    from d810.transforms.unflatten_authority import bind, evaluate, model, proposal as proposal_api
    from d810.transforms.unflatten_authority.ids import semantic_graph_inventory_digest
    from tests.unit.transforms.unflatten_authority.test_bind import (
        _corridor_inventories, _inventory_with_edges,
    )

    proposal, source, candidate = _corridor_inventories(candidate_full=True)
    def with_entry_at_handler(inventory):
        return replace(inventory, entry_serial=2, inventory_digest=semantic_graph_inventory_digest(
            inventory.phase, inventory.graph_fingerprint, inventory.generation,
            inventory.blocks, inventory.subjects, inventory.bindings,
            inventory.effects, inventory.terminals, inventory.topology,
            inventory.reachable_serials, 2, inventory.source_subject_ids,
            inventory.function_ea,
        ))
    source = with_entry_at_handler(source)
    candidate = with_entry_at_handler(candidate)
    refs = {block.serial: block.block_ref for block in source.blocks}
    source = _inventory_with_edges(
        source, {0: (0, 2), 1: (0,), 2: (1,)}, {0: (0, 1), 1: (2,), 2: (0,)},
    )
    table = replace(
        _table(), ea=0x1000,
        r=MopSnapshot(kind=OperandKind.CASE_LIST, switch_cases=(((0,), 2), ((), 0))),
    )
    graph = FlowGraph(blocks={
        block.serial: BlockSnapshot(
            serial=block.serial, block_type=1, succs=block.successor_serials,
            preds=block.predecessor_serials, flags=0, start_ea=block.anchor_ea,
            insn_snapshots=(table,) if block.serial == 0 else (
                (InsnSnapshot(opcode=0, ea=0x1100, operands=(), kind=InsnKind.MOV),)
                if block.serial == 2 else ()
            ),
        ) for block in source.blocks
    }, entry_serial=2, func_ea=0x1000)
    coverage = coverage_api.analyze_dispatcher_corridor_coverage(
        graph, modifications=(RedirectGoto(from_serial=2, old_target=1, new_target=2),),
        dispatcher_entry_serial=0,
    )
    forecast = coverage_api.build_dispatcher_removal_forecast(
        graph, coverage=coverage, dispatcher_entry_serial=0,
    )
    assert {(row.role, row.anchor.serial) for row in forecast.retirement_candidates} == {
        ("comparison_dispatcher", 0), ("dispatcher_feeder", 1),
    }
    proposal = replace(proposal, corridor_coverage_forecast=(
        proposal_api.corridor_coverage_forecast_from_analysis(
            forecast, proposal=proposal, block_refs_by_serial=refs,
        )
    ))
    catalog = proposal_api.retirement_candidate_catalog_from_forecast(
        forecast, proposal=proposal, block_refs_by_serial=refs,
    )
    claims = proposal_api.claims_from_dispatcher_removal_forecast(
        forecast, proposal=proposal, block_refs_by_serial=refs,
    )
    assert catalog is not None
    assert set(catalog.candidate_refs) == set(proposal.plan_inputs.dispatcher_member_refs)
    claim = next(row for row in claims if type(row) is model.RetiredDispatcherInfrastructureClaim)
    proposal = replace(
        proposal, claims=proposal_api.canonical_model_order((*proposal.claims, claim), "claims"),
        retirement_candidate_catalog=catalog,
        plan_inputs=replace(proposal.plan_inputs, shape=model.UnflattenPlanShape.FULL_DISPATCHER_RETIREMENT),
    )
    # Keep the exact router and feeder physically indexed but enter the
    # retained handler directly, so both candidates are genuinely detached.
    candidate = _inventory_with_edges(
        candidate,
        {0: (0, 2), 1: (0, 1) if feeder_self_edge else (0,), 2: (2,)},
        {0: (0, 1), 1: (1,) if feeder_self_edge else (), 2: (0, 2)},
    )
    result = bind.bind_retired_dispatcher_infrastructure_claim(
        claim=claim, proposal=proposal, source_inventory=source,
        projected_inventory=candidate,
    )
    assert set(result.phase_result.retired_refs) == {refs[0], refs[1]}
    assert all(row.classification is model.RetirementPhaseClassification.RETIRED
               for row in result.phase_result.members)
    inputs = SimpleNamespace(
        retirement_phase_result=result.phase_result, proposal=proposal,
        claims=proposal.claims, source_inventory=source,
    )
    cycles = evaluate._projected_retirement_cycle_refs(
        candidate_refs=catalog.candidate_refs, inventory=candidate,
    )
    assert set(cycles) == (
        {frozenset({refs[0]}), frozenset({refs[1]})}
        if feeder_self_edge else {frozenset({refs[0]})}
    )
    for invalid_scope in (frozenset(), frozenset({refs[2]}), frozenset({refs[0], refs[2]})):
        assert not evaluate._retirement_cycle_allowance_covers(
            invalid_scope, inputs=inputs,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, candidate=candidate,
        )
    for cycle in cycles:
        assert evaluate._retirement_cycle_allowance_covers(
            cycle, inputs=inputs,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, candidate=candidate,
        )


def _table():
    return InsnSnapshot(
        opcode=53, ea=0x1020, operands=(), kind=InsnKind.TABLE_JUMP,
        l=MopSnapshot(kind=OperandKind.STACK, stkoff=0x20, size=4),
        r=MopSnapshot(kind=OperandKind.CASE_LIST, switch_cases=(((0,), 3), ((), 2))),
        d=MopSnapshot(kind=OperandKind.EMPTY),
    )


def test_literal_switch_router_is_effect_free():
    assert _is_effect_free_dispatcher_router(SimpleNamespace(insn_snapshots=(_table(),), succs=(3, 2)))


@pytest.mark.parametrize("bad", ["call", "global", "unknown", "store_prefix", "cases_missing", "foreign_target", "destination"])
def test_switch_router_rejects_unproven_effects_and_targets(bad):
    table = _table()
    prefix = ()
    if bad == "call":
        table = replace(table, is_call=True)
    elif bad == "global":
        table = replace(table, l=MopSnapshot(kind=OperandKind.GLOBAL, gaddr=0x1000))
    elif bad == "unknown":
        table = replace(table, l=MopSnapshot(kind=OperandKind.UNKNOWN))
    elif bad == "store_prefix":
        prefix = (InsnSnapshot(opcode=0, ea=0x1010, operands=(), kind=InsnKind.STORE),)
    elif bad == "cases_missing":
        table = replace(table, r=MopSnapshot(kind=OperandKind.CASE_LIST))
    elif bad == "foreign_target":
        table = replace(table, r=MopSnapshot(kind=OperandKind.CASE_LIST, switch_cases=(((0,), 99), ((), 2))))
    else:
        table = replace(table, d=MopSnapshot(kind=OperandKind.REGISTER, reg=0, size=4))
    assert not _is_effect_free_dispatcher_router(SimpleNamespace(insn_snapshots=(*prefix, table), succs=(3, 2)))

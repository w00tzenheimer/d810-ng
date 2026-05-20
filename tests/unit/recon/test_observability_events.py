"""Tests for the recon observability event API (Phase 2)."""
from __future__ import annotations

import pytest

from d810.core.observability import (
    SnapshotRef,
    reset_diagnostic_bus,
    subscribe,
)
from d810.core.observability_models import DagEdge, DagNode, Modification
from d810.recon.observability import (
    BranchOwnershipProofsObserved,
    DagLocalFactsObserved,
    DagObserved,
    FactConflictsObserved,
    FactConsumersObserved,
    FactMappingsObserved,
    FactObservationsObserved,
    ModificationsObserved,
    ReachabilityObserved,
    RenderedProgramObserved,
    diagnostics_enabled,
    observe_dag,
    observe_branch_ownership_proofs,
    observe_dag_local_facts,
    observe_fact_conflict,
    observe_fact_consumer,
    observe_fact_mapping,
    observe_fact_observation,
    observe_modifications,
    observe_reachability,
    observe_rendered_program,
)


@pytest.fixture(autouse=True)
def _bus_reset():
    reset_diagnostic_bus()
    yield
    reset_diagnostic_bus()


def _make_snap() -> SnapshotRef:
    return SnapshotRef(
        key="test-key",
        func_ea=0x401000,
        label="MMAT_GLBOPT1_post_d810",
        maturity="MMAT_GLBOPT1",
        phase="post_d810",
    )


def test_observe_dag_publishes_event_with_tuple_payloads():
    seen: list[DagObserved] = []
    subscribe(DagObserved, seen.append)

    snap = _make_snap()
    nodes = [
        DagNode(state=0x10, state_hex="0x10", entry_block=5, classification="X"),
    ]
    edges = [
        DagEdge(edge_id=0, source_state=0x10, target_state=0x20, edge_kind="K"),
    ]
    observe_dag(snap, nodes, edges)

    assert len(seen) == 1
    assert seen[0].snapshot is snap
    assert isinstance(seen[0].nodes, tuple)
    assert isinstance(seen[0].edges, tuple)
    assert seen[0].nodes[0].state == 0x10
    assert seen[0].edges[0].edge_id == 0


def test_observe_branch_ownership_proofs_publishes_tuple_payloads():
    seen: list[BranchOwnershipProofsObserved] = []
    subscribe(BranchOwnershipProofsObserved, seen.append)

    snap = _make_snap()
    observe_branch_ownership_proofs(snap, [{"proof_id": "p"}])

    assert len(seen) == 1
    assert seen[0].snapshot is snap
    assert seen[0].rows == ({"proof_id": "p"},)


def test_observe_fact_observation_carries_func_ea_and_tuple():
    seen: list[FactObservationsObserved] = []
    subscribe(FactObservationsObserved, seen.append)

    snap = _make_snap()
    observations = [{"k": "v"}]
    observe_fact_observation(snap, 0x401000, observations)

    assert len(seen) == 1
    assert seen[0].func_ea == 0x401000
    assert seen[0].observations == ({"k": "v"},)


def test_observe_rendered_program_passes_program_object_through():
    seen: list[RenderedProgramObserved] = []
    subscribe(RenderedProgramObserved, seen.append)

    snap = _make_snap()
    program = object()  # duck-typed; subscriber introspects in real flow
    observe_rendered_program(snap, program)

    assert len(seen) == 1
    assert seen[0].program is program


def test_observe_modifications_carries_tuple_of_modifications():
    seen: list[ModificationsObserved] = []
    subscribe(ModificationsObserved, seen.append)

    snap = _make_snap()
    mods = [
        Modification(mod_index=0, mod_type="goto_redirect"),
        Modification(mod_index=1, mod_type="insert_block"),
    ]
    observe_modifications(snap, mods)

    assert len(seen) == 1
    assert seen[0].modifications[0].mod_index == 0
    assert seen[0].modifications[1].mod_type == "insert_block"


def test_observe_reachability_converts_to_frozensets():
    seen: list[ReachabilityObserved] = []
    subscribe(ReachabilityObserved, seen.append)

    snap = _make_snap()
    observe_reachability(
        snap,
        all_serials=[1, 2, 3, 1],
        reachable=[1, 2],
        bst_serials=(2,),
        gutted=(3,),
        claimed_sources=(),
    )

    assert len(seen) == 1
    ev = seen[0]
    assert ev.all_serials == frozenset({1, 2, 3})
    assert ev.reachable == frozenset({1, 2})
    assert ev.bst_serials == frozenset({2})
    assert ev.gutted == frozenset({3})
    assert ev.claimed_sources == frozenset()


def test_observe_dag_local_facts_passes_dag_through():
    seen: list[DagLocalFactsObserved] = []
    subscribe(DagLocalFactsObserved, seen.append)

    snap = _make_snap()
    dag = object()
    observe_dag_local_facts(snap, dag)

    assert seen[0].dag is dag


def test_observe_fact_mapping_consumer_and_conflict():
    obs_map: list[FactMappingsObserved] = []
    obs_con: list[FactConsumersObserved] = []
    obs_cnf: list[FactConflictsObserved] = []
    subscribe(FactMappingsObserved, obs_map.append)
    subscribe(FactConsumersObserved, obs_con.append)
    subscribe(FactConflictsObserved, obs_cnf.append)

    snap = _make_snap()
    observe_fact_mapping(snap, 1, [{"a": 1}])
    observe_fact_consumer(snap, 1, [{"c": 1}])
    observe_fact_conflict(snap, 1, [{"x": 1}])

    assert obs_map and obs_con and obs_cnf
    assert obs_map[0].mappings == ({"a": 1},)
    assert obs_con[0].consumers == ({"c": 1},)
    assert obs_cnf[0].conflicts == ({"x": 1},)


def test_diagnostics_enabled_reflects_subscribers():
    assert diagnostics_enabled() is False
    subscribe(DagObserved, lambda _: None)
    assert diagnostics_enabled() is True


def test_observe_with_no_subscriber_is_noop():
    # Bus is empty; helpers should not raise and should not store anywhere.
    snap = _make_snap()
    observe_dag(snap, [], [])
    observe_fact_observation(snap, 1, [])
    observe_modifications(snap, [])
    observe_rendered_program(snap, object())

"""FragmentPlan lowering into the shared PatchPlan transaction IR."""

from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path
from dataclasses import replace

import pytest

from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.flowgraph import FlowGraph
from d810.transforms.cfg_transaction import CfgProjection, PlanBlockRef
from d810.transforms.fragment_to_patch import (
    CfgTransactionCoordinator,
    FragmentContractBundle,
    FragmentTransactionParticipant,
    PatchFragmentBlockMaterialization,
    PatchFragmentOperation,
    PatchFragmentRootPublication,
    PatchTransactionParticipant,
    lower_fragment_plan,
)
from d810.transforms.fragment_validation import validate_fragment_projection
from tests.unit.transforms.test_fragment_validation import (
    _plan,
    _projection,
    _terminal_plan,
    _terminal_projection,
)


def _prepared(plan, projection=None):
    projection = _projection(plan) if projection is None else projection
    cfg_projection = CfgProjection(
        plan_id=plan.plan_id,
        snapshot_id="fragment-snapshot",
        graph=FlowGraph(blocks={}, entry_serial=0, func_ea=0),
    )
    inventory = SimpleNamespace(
        plan_id=plan.plan_id,
        atomic_group_id=plan.atomic_group_id,
        items=(
            SimpleNamespace(
                root_block_id="replacement",
                original_block_id="original",
                predecessor_block_id="entry",
                role=SemanticEdgeRole.DIRECT,
                requires_helper=False,
            ),
        ),
    )
    return SimpleNamespace(
        plan_id=plan.plan_id,
        atomic_group_id=plan.atomic_group_id,
        snapshot_id="fragment-snapshot",
        generation=4,
        projection=projection,
        cfg_projection=cfg_projection,
        root_inventory=inventory,
    )


def test_lowering_preserves_plan_refs_and_complete_semantic_contract() -> None:
    plan = _plan()
    lowered = lower_fragment_plan(plan, _prepared(plan))

    assert lowered.plan_id == plan.plan_id
    assert lowered.snapshot_id == "fragment-snapshot"
    assert lowered.source_generation == 4
    assert isinstance(lowered.semantic_contract, FragmentContractBundle)
    assert lowered.semantic_contract.fragment_plan is plan
    assert lowered.semantic_contract.prepublication_validation == (
        validate_fragment_projection(plan, _projection(plan))
    )
    assert lowered.semantic_contract.fragment_postconditions

    block_steps = tuple(
        step
        for step in lowered.steps
        if isinstance(step, PatchFragmentBlockMaterialization)
    )
    assert {step.block_ref for step in block_steps} == {
        PlanBlockRef(plan.plan_id, block.block_id) for block in plan.blocks
    }
    replacement = next(
        step for step in block_steps if step.block_ref.local_block_id == "replacement"
    )
    assert replacement.source_ref == PlanBlockRef(plan.plan_id, "original")

    operation_steps = tuple(
        step for step in lowered.steps if isinstance(step, PatchFragmentOperation)
    )
    assert tuple(step.operation for step in operation_steps) == plan.operations
    assert operation_steps[0].source_ref == PlanBlockRef(plan.plan_id, "replacement")
    assert operation_steps[0].target_refs == tuple(
        PlanBlockRef(plan.plan_id, edge.target_block_id)
        for edge in plan.operations[0].edges
    )

    root_steps = tuple(
        step for step in lowered.steps if isinstance(step, PatchFragmentRootPublication)
    )
    assert root_steps == (
        PatchFragmentRootPublication(
            root_ref=PlanBlockRef(plan.plan_id, "replacement"),
            original_ref=PlanBlockRef(plan.plan_id, "original"),
            predecessor_ref=PlanBlockRef(plan.plan_id, "entry"),
            edge_role=SemanticEdgeRole.DIRECT,
        ),
    )
    assert operation_steps[0].fallthrough_helper_id == "fallthrough-helper:condition"
    assert operation_steps[0].fallthrough_helper_ref == PlanBlockRef(
        plan.plan_id,
        "fallthrough-helper:condition",
    )


def test_lowering_rejects_projection_that_failed_fragment_preflight() -> None:
    plan = _plan()
    prepared = _prepared(plan)
    bad = SimpleNamespace(**{**prepared.__dict__, "plan_id": "foreign"})

    try:
        lower_fragment_plan(plan, bad)
    except ValueError as exc:
        assert "authority" in str(exc)
    else:
        raise AssertionError("foreign preflight authority was accepted")


def test_coordinator_owns_complete_lifecycle_for_both_participants() -> None:
    plan = _plan()
    phases = []

    class Lifecycle:
        def begin(self, patch):
            phases.append("begin")
            return patch

        def realize(self, patch, begun):
            phases.append("realize")
            return begun

        def observe(self, patch, realized):
            phases.append("observe")
            return realized

        def validate(self, patch, observed):
            phases.append("validate")
            return observed

        def commit(self, patch, validated):
            phases.append("commit")
            return validated

        def fail(self, patch, error, phase):
            phases.append(f"fail:{phase}")

    coordinator = CfgTransactionCoordinator(Lifecycle())
    lowered = coordinator.execute(
        FragmentTransactionParticipant(), plan, prepared_projection=_prepared(plan)
    )
    coordinator.execute(PatchTransactionParticipant(), lowered)
    assert phases == [
        "begin",
        "realize",
        "observe",
        "validate",
        "commit",
        "begin",
        "realize",
        "observe",
        "validate",
        "commit",
    ]


def test_semantic_patch_steps_reject_forged_block_terminal_and_root_authority() -> None:
    plan = _plan()
    lowered = lower_fragment_plan(plan, _prepared(plan))
    block_index = next(
        index
        for index, step in enumerate(lowered.steps)
        if isinstance(step, PatchFragmentBlockMaterialization)
        and step.source_ref is not None
    )
    forged_block = list(lowered.steps)
    forged_block[block_index] = replace(
        forged_block[block_index],
        source_ref=PlanBlockRef(plan.plan_id, "target"),
    )
    with pytest.raises(ValueError, match="block PatchStep authority"):
        replace(lowered, steps=tuple(forged_block))

    root_index = next(
        index
        for index, step in enumerate(lowered.steps)
        if isinstance(step, PatchFragmentRootPublication)
    )
    forged_root = list(lowered.steps)
    forged_root[root_index] = replace(
        forged_root[root_index],
        original_ref=PlanBlockRef(plan.plan_id, "target"),
    )
    with pytest.raises(ValueError, match="root PatchStep payload"):
        replace(lowered, steps=tuple(forged_root))
    forged_helper = list(lowered.steps)
    forged_helper[root_index] = replace(
        forged_helper[root_index],
        fallthrough_helper_id="root-fallthrough-helper:entry:replacement",
        fallthrough_helper_ref=PlanBlockRef(
            plan.plan_id,
            "root-fallthrough-helper:entry:replacement",
        ),
    )
    with pytest.raises(ValueError, match="root PatchStep payload"):
        replace(lowered, steps=tuple(forged_helper))

    terminal_plan = _terminal_plan()
    prepared = _prepared(terminal_plan, _terminal_projection(terminal_plan))
    prepared.root_inventory.items = ()
    terminal_lowered = lower_fragment_plan(terminal_plan, prepared)
    terminal_index = next(
        index
        for index, step in enumerate(terminal_lowered.steps)
        if step.__class__.__name__ == "PatchFragmentTerminalEffects"
    )
    forged_terminal = list(terminal_lowered.steps)
    forged_terminal[terminal_index] = replace(
        forged_terminal[terminal_index], return_carriers=()
    )
    with pytest.raises(ValueError, match="terminal PatchStep payload"):
        replace(terminal_lowered, steps=tuple(forged_terminal))


def test_terminal_carrier_return_and_route_lower_as_one_atomic_patch_step() -> None:
    plan = _terminal_plan()
    projection = _terminal_projection(plan)
    prepared = _prepared(plan, projection)
    prepared.root_inventory.items = ()
    lowered = lower_fragment_plan(plan, prepared)

    terminal_steps = tuple(
        step
        for step in lowered.steps
        if step.__class__.__name__ == "PatchFragmentTerminalEffects"
    )
    assert len(terminal_steps) == 1
    assert terminal_steps[0].return_carriers == plan.return_carriers
    assert terminal_steps[0].terminal_returns == plan.terminal_returns
    assert terminal_steps[0].terminal_routes == plan.terminal_routes


def test_old_fragment_stage_and_root_executors_are_absent_from_production() -> None:
    source_root = Path(__file__).parents[3] / "src" / "d810"
    forbidden = (
        "def _stage_semantic_fragment(",
        "def _publish_semantic_fragment_roots(",
        "def publish_semantic_fragment(",
        ".publish_semantic_fragment(",
    )
    offenders = {
        str(path.relative_to(source_root)): name
        for path in source_root.rglob("*.py")
        for name in forbidden
        if name in path.read_text(encoding="utf-8")
    }
    assert offenders == {}


def test_both_production_paths_use_the_shared_transaction_coordinator() -> None:
    source_root = Path(__file__).parents[3] / "src" / "d810"
    backend = (
        source_root / "backends" / "hexrays" / "mutation" / "backend.py"
    ).read_text(encoding="utf-8")
    patch_transaction = (
        source_root / "hexrays" / "mutation" / "patch_transaction.py"
    ).read_text(encoding="utf-8")
    publication = (
        source_root / "hexrays" / "mutation" / "semantic_fragment_publication.py"
    ).read_text(encoding="utf-8")
    assert "execute_patch_transaction(" in backend
    assert "CfgTransactionCoordinator(" in patch_transaction
    assert "PatchTransactionParticipant()" in patch_transaction
    assert "from d810.passes.transaction_engine" not in backend
    assert "def publish_fragment(" not in backend
    assert "CfgTransactionCoordinator(" in publication
    assert "FragmentTransactionParticipant()" in publication
    assert "lambda lowered: lowered" not in publication
    assert "from d810.passes.transaction_engine" not in publication
    assert not (source_root / "passes" / "transaction_engine.py").exists()

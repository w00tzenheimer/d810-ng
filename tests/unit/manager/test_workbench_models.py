from __future__ import annotations

import dataclasses
import importlib.util

from d810.manager import workbench_models as models


def test_workbench_models_module_exists() -> None:
    assert importlib.util.find_spec("d810.manager.workbench_models") is not None


def test_outcome_status_uses_the_approved_vocabulary() -> None:
    assert tuple(status.value for status in models.OutcomeStatus) == (
        "Not run",
        "Ready",
        "Not eligible",
        "No match",
        "Changed",
        "Unchanged",
        "Abstained",
        "Blocked",
        "Failed",
        "Stale",
    )


def test_snapshot_freshness_is_explicit() -> None:
    assert tuple(value.value for value in models.SnapshotFreshness) == (
        "current",
        "stale",
        "unavailable",
    )


def _snapshot() -> object:
    generation = 7
    function = models.FunctionRef(
        ea=0x401000,
        name="target",
        fingerprint="sha256:abc",
        generation=generation,
    )
    runtime = models.RuntimeConfigRef(
        source_name="default_ollvm.json",
        source_path="/projects/default_ollvm.json",
        runtime_name="default_ollvm_v2.json",
        runtime_path="/projects/default_ollvm_v2.json",
        mode="config-v2",
        routed=True,
        hook_mode="config-v2",
        pass_ids=("recon", "recover_dispatcher"),
    )
    attack = models.AttackSummary(
        observed_shape="ollvm_flat",
        mechanism="state-variable dispatcher",
        selected_profile="ollvm",
        selection_mode="recon",
        confidence=0.91,
        recommended_inferences=("unflattening",),
        suppressed_rules=("UnsafeRule",),
        candidate_kinds=("flattened_switch",),
    )
    diagnostic = models.WorkbenchDiagnostic(
        code="missing-contract-input",
        message="requires.facts.required: dispatcher_state",
        pass_id="recover_dispatcher",
        namespace="requires.facts.required",
        missing=("dispatcher_state",),
        available=("cfg_shape",),
    )
    stage = models.PipelineStageSnapshot(
        ordinal=1,
        pass_id="recover_dispatcher",
        phase="function",
        scope="function",
        maturity="MMAT_GLBOPT1",
        status=models.OutcomeStatus.BLOCKED,
        summary="Missing dispatcher_state",
        contract_json='{"pass":"recover_dispatcher"}',
        diagnostics=(diagnostic,),
    )
    consumer = models.ConsumerOutcomeSnapshot(
        phase="supporting",
        consumer_name="rule_scope",
        status=models.OutcomeStatus.CHANGED,
        detail="inference applied",
        provenance_json=None,
    )
    rule_scope = models.RuleScopeSummary(
        project_instruction_rules=("ProjectInstructionRule",),
        project_block_rules=("ProjectBlockRule",),
        function_enabled_rules=("FunctionRule",),
        function_disabled_rules=("UnsafeRule",),
        function_tags=("hard",),
        function_notes="investigate",
        inference_name="unflattening",
        inference_enabled_rules=("UnflatteningRule",),
        inference_disabled_rules=(),
        inference_applies=True,
    )
    statistics = models.StatisticsSummary(
        optimizer_matches=(models.CountEntry("PatternOptimizer", 2),),
        rule_matches=(models.CountEntry("FunctionRule", 1),),
        cfg_patches=(models.PatchCountEntry("CfgRule", 1, 3),),
        total_rule_firings=1,
        cycles_detected=(),
        total_cycles_detected=0,
    )
    baseline = models.BaselineRef(
        available=False,
        fingerprint=None,
        path=None,
        generation=None,
    )
    output = models.D810OutputRef(
        available=True,
        fingerprint="sha256:def",
        path="/logs/target.c",
        generation=7,
    )
    artifact = models.ArtifactRef(
        kind="recon-db",
        label="Recon database",
        path="/logs/recon.db",
        available=True,
    )
    return models.DeobfuscationWorkbenchSnapshot(
        generation=generation,
        function=function,
        runtime=runtime,
        attack=attack,
        pipeline=(stage,),
        consumers=(consumer,),
        rule_scope=rule_scope,
        statistics=statistics,
        baseline=baseline,
        latest_output=output,
        artifacts=(artifact,),
        freshness=models.SnapshotFreshness.CURRENT,
        engine_started=True,
        collection_errors=(),
    )


def test_workbench_snapshot_is_deeply_immutable_and_slotted() -> None:
    snapshot = _snapshot()

    assert dataclasses.is_dataclass(snapshot)
    assert not hasattr(snapshot, "__dict__")
    assert isinstance(snapshot.pipeline, tuple)
    assert isinstance(snapshot.pipeline[0].diagnostics, tuple)
    assert isinstance(snapshot.consumers, tuple)
    assert isinstance(snapshot.rule_scope.function_tags, tuple)
    assert isinstance(snapshot.statistics.optimizer_matches, tuple)
    assert isinstance(snapshot.artifacts, tuple)
    assert isinstance(snapshot.collection_errors, tuple)

    try:
        snapshot.generation = 8
    except dataclasses.FrozenInstanceError:
        pass
    else:
        raise AssertionError("snapshot mutation unexpectedly succeeded")


def test_every_nested_record_is_frozen_and_slotted() -> None:
    snapshot = _snapshot()
    records = (
        snapshot.function,
        snapshot.runtime,
        snapshot.attack,
        snapshot.pipeline[0],
        snapshot.pipeline[0].diagnostics[0],
        snapshot.consumers[0],
        snapshot.rule_scope,
        snapshot.statistics,
        snapshot.statistics.optimizer_matches[0],
        snapshot.statistics.cfg_patches[0],
        snapshot.baseline,
        snapshot.latest_output,
        snapshot.artifacts[0],
    )

    assert all(dataclasses.is_dataclass(record) for record in records)
    assert all(not hasattr(record, "__dict__") for record in records)
    for record in records:
        assert record.__dataclass_params__.frozen is True


def test_workbench_command_request_and_result_are_frozen_and_generation_bound() -> None:
    request = models.WorkbenchCommandRequest(
        command="analyze",
        function_ea=0x401000,
        expected_generation=9,
        function_fingerprint="sha256:abc",
    )
    result = models.WorkbenchCommandResult(
        command="analyze",
        function_ea=0x401000,
        requested_generation=9,
        function_fingerprint="sha256:abc",
        status=models.OutcomeStatus.READY,
        succeeded=True,
        accepted=True,
        refresh_requested=True,
        message="Analysis completed",
    )

    assert request.expected_generation == result.requested_generation
    assert request.function_fingerprint == result.function_fingerprint
    assert not hasattr(request, "__dict__")
    assert not hasattr(result, "__dict__")
    assert request.__dataclass_params__.frozen is True
    assert result.__dataclass_params__.frozen is True

from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

from d810.analyses.control_flow.models import CandidateFlag, DeobfuscationHints
from d810.core.config import ProjectConfiguration
from d810.core.persistence import FunctionRuleConfig
from d810.core.rule_scope import RuleInferenceOverlay
from d810.manager.project_runtime import (
    ProjectConfigMode,
    ProjectIdentitySnapshot,
    ProjectRuntimeSnapshot,
    RuleProjectionKind,
)
from d810.manager.workbench_models import OutcomeStatus, SnapshotFreshness
from d810.manager import workbench_service as service_module
from d810.passes.pass_pipeline import (
    FactRequirement,
    PassContract,
    PassRequires,
    PassSpec,
    default,
    no_caps,
)


_ROOT = Path(__file__).resolve().parents[3]


def _method(path: Path, class_name: str, method_name: str) -> ast.FunctionDef:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == method_name:
                    return item
    raise AssertionError(f"{class_name}.{method_name} not found in {path}")


def _call_names(method: ast.FunctionDef) -> set[str]:
    result: set[str] = set()
    for node in ast.walk(method):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            result.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            result.add(node.func.attr)
    return result


def test_workbench_service_module_exists() -> None:
    assert importlib.util.find_spec("d810.manager.workbench_service") is not None


def _factory() -> None:
    raise AssertionError("workbench collection must not instantiate passes")


def _spec(pass_id: str, *, required_fact: str | None = None) -> PassSpec:
    required = frozenset({required_fact}) if required_fact is not None else frozenset()
    return PassSpec(
        pass_id,
        _factory,
        no_caps,
        default,
        contract=PassContract(
            requires=PassRequires(
                facts=FactRequirement(required=required),
            )
        ),
    )


class _Registry:
    def __init__(self, specs: tuple[PassSpec, ...]) -> None:
        self._specs = {spec.pass_id: spec for spec in specs}

    def build_spec(self, config: object) -> PassSpec:
        return self._specs[config.pass_id]


class _Facts:
    def __init__(self, facts: tuple[str, ...] = ()) -> None:
        self._facts = frozenset(facts)

    def has_fact(self, name: str) -> bool:
        return name in self._facts

    def has_evidence(self, name: str) -> bool:
        return False

    def has_analysis(self, name: str) -> bool:
        return False

    def available_facts(self) -> tuple[str, ...]:
        return tuple(sorted(self._facts))

    def available_evidence(self) -> tuple[str, ...]:
        return ()

    def available_analyses(self) -> tuple[str, ...]:
        return ()


class _Stats:
    def last_report(self) -> dict[str, object]:
        return {
            "optimizer_matches": {"PatternOptimizer": 2},
            "rule_matches": {"FoldRule": 3},
            "cfg_patches": {"CfgRule": {"uses": 1, "total_patches": 4}},
            "total_rule_firings": 3,
            "cycles_detected": {"PatternOptimizer": 1},
            "total_cycles_detected": 1,
        }


class _Report:
    def __init__(
        self,
        name: str,
        *,
        artifacts: bool,
        summary: bool,
        applied: bool,
        provenance: dict[str, object] | None = None,
    ) -> None:
        self.consumer_name = name
        self.source_artifacts_available = artifacts
        self.summary_available = summary
        self.consumer_verdict_applied = applied
        self.func_ea = 0x401000
        self.detail = f"{name} detail"
        self.provenance_dict = provenance


def _project_context(tmp_path: Path) -> tuple[ProjectRuntimeSnapshot, ProjectConfiguration]:
    source_path = tmp_path / "default_ollvm.json"
    runtime_path = tmp_path / "default_ollvm_v2.json"
    source_path.write_text("{}", encoding="utf-8")
    runtime_path.write_text("{}", encoding="utf-8")
    project_snapshot = ProjectRuntimeSnapshot(
        source=ProjectIdentitySnapshot(
            basename=source_path.name,
            path=source_path,
            description="source policy",
        ),
        runtime=ProjectIdentitySnapshot(
            basename=runtime_path.name,
            path=runtime_path,
            description="effective runtime",
        ),
        mode=ProjectConfigMode.CONFIG_V2,
        routed=True,
        hook_mode="config-v2",
        effective_pass_ids=("first", "second"),
        effective_instruction_rule_names=("ProjectInstructionRule",),
        effective_block_rule_names=("ProjectBlockRule",),
        rule_projection=RuleProjectionKind.RUNTIME_EXPANSION,
    )
    runtime_project = ProjectConfiguration(
        path=runtime_path,
        description="effective runtime",
        additional_configuration={
            "pipeline_v2": [
                {"pass": "first"},
                {"pass": "second"},
            ]
        },
    )
    return project_snapshot, runtime_project


def _manager(tmp_path: Path) -> SimpleNamespace:
    recon_db = tmp_path / "recon.db"
    recon_db.write_bytes(b"sqlite")
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    hints = DeobfuscationHints(
        func_ea=0x401000,
        obfuscation_type="ollvm_flat",
        confidence=0.91,
        recommended_inferences=("unflattening",),
        candidates=(
            CandidateFlag(
                kind="flattened_switch",
                block_serial=77,
                confidence=0.9,
                detail="serial is deliberately not projected",
            ),
        ),
        suppress_rules=("UnsafeRule",),
    )
    override = FunctionRuleConfig(
        function_addr=0x401000,
        enabled_rules={"FunctionRule"},
        disabled_rules={"UnsafeRule"},
        tags={"hard"},
        notes="investigate",
    )
    inference = RuleInferenceOverlay(
        name="unflattening",
        enabled_rules=frozenset({"UnflatteningRule"}),
        disabled_rules=frozenset({"PreRecoveryFcp"}),
        target_func_eas=frozenset({0x401000}),
        target_tags_all=frozenset({"hard"}),
    )
    reports = (
        _Report("not_eligible", artifacts=False, summary=False, applied=False),
        _Report("no_match", artifacts=True, summary=False, applied=False),
        _Report("changed", artifacts=True, summary=True, applied=True),
        _Report("abstained", artifacts=True, summary=True, applied=False),
        _Report(
            "explicit_unchanged",
            artifacts=True,
            summary=True,
            applied=False,
            provenance={"status": "Unchanged", "reason": "no delta"},
        ),
    )
    return SimpleNamespace(
        started=True,
        stats=_Stats(),
        log_dir=log_dir,
        recon_db=recon_db,
        storage=SimpleNamespace(db_path=tmp_path / "function-rules.db"),
        config={},
        load_recon_hints=lambda function_ea: hints,
        get_recon_outcome_reports=lambda function_ea: reports,
        get_function_rule_override=lambda function_ea: override,
        get_function_tags=lambda function_ea: {"hard", "priority"},
        get_active_rule_inference=lambda: inference,
    )


def _service(manager: object) -> object:
    return service_module.WorkbenchService(
        manager,
        registry=_Registry(
            (
                _spec("first"),
                _spec("second", required_fact="needed"),
            )
        ),
    )


def test_collect_projects_runtime_identity_order_and_not_run_without_facts(
    tmp_path: Path,
) -> None:
    project_snapshot, runtime_project = _project_context(tmp_path)
    service = _service(_manager(tmp_path))

    snapshot = service.collect(
        function_ea=0x401000,
        function_name="target",
        function_fingerprint="sha256:abc",
        project_snapshot=project_snapshot,
        runtime_project=runtime_project,
    )

    assert snapshot.generation == 1
    assert snapshot.function.ea == 0x401000
    assert snapshot.function.name == "target"
    assert snapshot.function.generation == snapshot.generation
    assert snapshot.runtime.source_name == "default_ollvm.json"
    assert snapshot.runtime.runtime_name == "default_ollvm_v2.json"
    assert snapshot.runtime.mode == "config-v2"
    assert snapshot.runtime.routed is True
    assert snapshot.runtime.pass_ids == ("first", "second")
    assert tuple(stage.pass_id for stage in snapshot.pipeline) == ("first", "second")
    assert tuple(stage.ordinal for stage in snapshot.pipeline) == (0, 1)
    assert tuple(stage.status for stage in snapshot.pipeline) == (
        OutcomeStatus.NOT_RUN,
        OutcomeStatus.NOT_RUN,
    )
    assert json.loads(snapshot.pipeline[0].contract_json)["pass"] == "first"
    assert snapshot.freshness is SnapshotFreshness.CURRENT
    assert snapshot.engine_started is True


def test_preflight_distinguishes_ready_and_blocked_with_structured_diagnostics(
    tmp_path: Path,
) -> None:
    project_snapshot, runtime_project = _project_context(tmp_path)
    service = _service(_manager(tmp_path))

    blocked = service.collect(
        function_ea=0x401000,
        function_name="target",
        function_fingerprint=None,
        project_snapshot=project_snapshot,
        runtime_project=runtime_project,
        facts=_Facts(),
    )
    ready = service.collect(
        function_ea=0x401000,
        function_name="target",
        function_fingerprint=None,
        project_snapshot=project_snapshot,
        runtime_project=runtime_project,
        facts=_Facts(("needed",)),
    )

    assert blocked.generation == 1
    assert ready.generation == 2
    assert tuple(stage.status for stage in blocked.pipeline) == (
        OutcomeStatus.READY,
        OutcomeStatus.BLOCKED,
    )
    diagnostic = blocked.pipeline[1].diagnostics[0]
    assert diagnostic.pass_id == "second"
    assert diagnostic.namespace == "requires.facts.required"
    assert diagnostic.missing == ("needed",)
    assert diagnostic.available == ()
    assert tuple(stage.status for stage in ready.pipeline) == (
        OutcomeStatus.READY,
        OutcomeStatus.READY,
    )


def test_attack_consumers_rule_scope_statistics_and_artifacts_are_truthful(
    tmp_path: Path,
) -> None:
    project_snapshot, runtime_project = _project_context(tmp_path)
    snapshot = _service(_manager(tmp_path)).collect(
        function_ea=0x401000,
        function_name="target",
        function_fingerprint=None,
        project_snapshot=project_snapshot,
        runtime_project=runtime_project,
    )

    assert snapshot.attack.observed_shape == "ollvm_flat"
    assert snapshot.attack.mechanism == "unavailable"
    assert snapshot.attack.selected_profile is None
    assert snapshot.attack.selection_mode == "recon-hints"
    assert snapshot.attack.confidence == 0.91
    assert snapshot.attack.recommended_inferences == ("unflattening",)
    assert snapshot.attack.suppressed_rules == ("UnsafeRule",)
    assert snapshot.attack.candidate_kinds == ("flattened_switch",)
    assert "77" not in repr(snapshot.attack)

    assert tuple(outcome.consumer_name for outcome in snapshot.consumers) == (
        "not_eligible",
        "no_match",
        "changed",
        "abstained",
        "explicit_unchanged",
    )
    assert tuple(outcome.status for outcome in snapshot.consumers) == (
        OutcomeStatus.NOT_ELIGIBLE,
        OutcomeStatus.NO_MATCH,
        OutcomeStatus.CHANGED,
        OutcomeStatus.ABSTAINED,
        OutcomeStatus.UNCHANGED,
    )
    assert all(outcome.phase == "supporting" for outcome in snapshot.consumers)
    assert json.loads(snapshot.consumers[-1].provenance_json or "{}") == {
        "reason": "no delta",
        "status": "Unchanged",
    }

    assert snapshot.rule_scope.project_instruction_rules == (
        "ProjectInstructionRule",
    )
    assert snapshot.rule_scope.project_block_rules == ("ProjectBlockRule",)
    assert snapshot.rule_scope.function_enabled_rules == ("FunctionRule",)
    assert snapshot.rule_scope.function_disabled_rules == ("UnsafeRule",)
    assert snapshot.rule_scope.function_tags == ("hard", "priority")
    assert snapshot.rule_scope.function_notes == "investigate"
    assert snapshot.rule_scope.inference_name == "unflattening"
    assert snapshot.rule_scope.inference_enabled_rules == ("UnflatteningRule",)
    assert snapshot.rule_scope.inference_disabled_rules == ("PreRecoveryFcp",)
    assert snapshot.rule_scope.inference_applies is True

    assert snapshot.statistics.optimizer_matches[0].name == "PatternOptimizer"
    assert snapshot.statistics.optimizer_matches[0].count == 2
    assert snapshot.statistics.cfg_patches[0].total_patches == 4
    assert snapshot.statistics.total_rule_firings == 3
    assert snapshot.statistics.total_cycles_detected == 1

    artifacts = {artifact.kind: artifact for artifact in snapshot.artifacts}
    assert artifacts["source-config"].available is True
    assert artifacts["runtime-config"].available is True
    assert artifacts["recon-db"].available is True
    assert artifacts["log-directory"].available is True
    assert artifacts["function-rules-db"].path is not None
    assert artifacts["function-rules-db"].available is False
    assert snapshot.baseline.available is False
    assert snapshot.latest_output.available is False


def test_collection_failure_is_reported_without_hiding_other_sections(
    tmp_path: Path,
) -> None:
    project_snapshot, runtime_project = _project_context(tmp_path)
    manager = _manager(tmp_path)

    def fail_hints(function_ea: int) -> object:
        raise RuntimeError("recon store is locked")

    manager.load_recon_hints = fail_hints
    snapshot = _service(manager).collect(
        function_ea=0x401000,
        function_name="target",
        function_fingerprint=None,
        project_snapshot=project_snapshot,
        runtime_project=runtime_project,
    )

    assert snapshot.attack.observed_shape == "unknown"
    assert snapshot.pipeline[0].pass_id == "first"
    assert snapshot.consumers[0].consumer_name == "not_eligible"
    assert snapshot.collection_errors == ("attack: recon store is locked",)


def test_manager_owns_service_and_exposes_read_only_recon_facades() -> None:
    manager_path = _ROOT / "src" / "d810" / "manager" / "manager.py"

    assert "WorkbenchService" in _call_names(
        _method(manager_path, "D810Manager", "__post_init__")
    )
    assert "collect" in _call_names(
        _method(manager_path, "D810Manager", "get_workbench_snapshot")
    )
    assert "load_hints" in _call_names(
        _method(manager_path, "D810Manager", "load_recon_hints")
    )
    assert "get_func_reports" in _call_names(
        _method(manager_path, "D810Manager", "get_recon_outcome_reports")
    )


def test_state_facade_supplies_current_runtime_context_without_parsing() -> None:
    state_path = _ROOT / "src" / "d810" / "manager" / "state.py"
    method = _method(state_path, "D810State", "get_workbench_snapshot")
    calls = _call_names(method)

    assert "get_workbench_snapshot" in calls
    assert "pass_specs_from_project_config" not in calls
    attributes = {
        node.attr
        for node in ast.walk(method)
        if isinstance(node, ast.Attribute)
    }
    assert "current_project_runtime_snapshot" in attributes
    assert "current_runtime_project" in attributes

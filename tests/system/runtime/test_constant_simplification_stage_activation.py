"""Live Hex-Rays activation of the compiled constant-stage schedule."""

from __future__ import annotations

from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration
from d810.hexrays.hooks.optblock_adapter import BlockOptimizerManager
from d810.hexrays.hooks.optinsn_adapter import InstructionOptimizerManager
from d810.hexrays.utils.hexrays_formatters import string_to_maturity
from d810.optimizers.microcode.flow.constant_prop.forward_const_prop import (
    ForwardConstantPropagationRule,
)
from d810.optimizers.microcode.handler import validate_rule_maturity_contract
from d810.optimizers.microcode.instructions.peephole.fold_constant_subtree import (
    ConstantSubtreeFoldRule,
)
from d810.optimizers.microcode.instructions.peephole.fold_readonlydata import (
    FoldReadonlyDataRule,
)
from d810.passes.constant_simplification import (
    constant_simplification_provider_maturities,
)
from d810.passes.pipeline_v2_hook_bridge import pipeline_v2_hook_activation


_RULE_TYPES = {
    "FoldReadonlyDataRule": FoldReadonlyDataRule,
    "ConstantSubtreeFoldRule": ConstantSubtreeFoldRule,
    "ForwardConstantPropagationRule": ForwardConstantPropagationRule,
}


def _project() -> ProjectConfiguration:
    return ProjectConfiguration(
        path=Path("constant-stage-activation.runtime-config-v2.json"),
        additional_configuration={
            "pipeline_v2_mode": "config-v2",
            "pipeline_v2": [
                {
                    "pass_id": "constant-simplification",
                    "maturity_gates": [
                        "CANONICAL",
                        "LOCAL_OPTIMIZED",
                        "CALL_MODELED",
                        "GLOBAL_ANALYZED",
                        "GLOBAL_OPTIMIZED",
                        "STRUCTURED",
                    ],
                    "options": {
                        "stages": {
                            "fold-readonly-data": {
                                "enabled": True,
                                "maturities": ["CANONICAL", "GLOBAL_ANALYZED"],
                            },
                            "fold-constant-subtree": {
                                "enabled": True,
                                "maturities": ["LOCAL_OPTIMIZED", "STRUCTURED"],
                            },
                            "forward-constants": {
                                "enabled": True,
                                "maturities": ["CALL_MODELED", "GLOBAL_OPTIMIZED"],
                            },
                        }
                    },
                }
            ],
        },
    )


def _project_with_constant_stages(*, enabled: bool) -> ProjectConfiguration:
    project = _project()
    pipeline = project.additional_configuration["pipeline_v2"]
    constant_pass = next(
        entry for entry in pipeline if entry["pass_id"] == "constant-simplification"
    )
    for stage in constant_pass["options"]["stages"].values():
        stage["enabled"] = enabled
    return project


def _live_rule_names(state) -> set[str]:
    names = {rule.name for rule in state.manager.instruction_optimizer.rules}
    names.update(rule.name for rule in state.manager.block_optimizer.rules)
    return names


def _prepare_started_manager(state) -> None:
    class RecordingOptimizer:
        """Small adapter model covering the live configure/reset state."""

        def __init__(self, rules, *, pipeline: str):
            self.pipeline = pipeline
            self.rules = list(rules)
            self.cfg_rules = self.rules
            self._execution_scope_service = None
            self._execution_scope_project_name = "baseline"
            self._execution_scope_idb_key = "baseline-idb"
            self._execution_scope_func_ea = 0x401000
            self._active_instruction_rule_names_by_maturity = {
                1: frozenset({"baseline-rule"})
            }
            self._residual_admission_cache_key = (1, frozenset({"baseline-rule"}))
            self._residual_admission_cache_value = True
            self._active_optimizers = ["baseline-optimizer"]
            self._indexed_storage = {"baseline": "index"}
            self._generation = 11
            self._flow_context = "baseline-flow-context"
            self._flow_context_key = (1, 2, 3, 4, 5)
            self._project_config = {"project_name": "baseline"}
            self.fail_restore = False

        def configure(self, **kwargs):
            self.configuration = kwargs
            self._execution_scope_service = kwargs.get(
                "execution_scope_service", self._execution_scope_service
            )
            self._execution_scope_project_name = kwargs.get(
                "execution_scope_project_name", self._execution_scope_project_name
            )
            self._execution_scope_idb_key = kwargs.get(
                "execution_scope_idb_key", self._execution_scope_idb_key
            )
            self._execution_scope_func_ea = -1
            self._active_instruction_rule_names_by_maturity.clear()
            self._residual_admission_cache_key = None
            self._residual_admission_cache_value = False
            self._active_optimizers = []
            self._indexed_storage = {"candidate": "index"}
            self._flow_context = None
            self._flow_context_key = None
            self._project_config = dict(kwargs)
            self._generation += 1

        def replace_rules(self, rules):
            self.rules = list(rules)
            self.cfg_rules = self.rules
            self._active_instruction_rule_names_by_maturity.clear()
            self._residual_admission_cache_key = None
            self._residual_admission_cache_value = False
            self._active_optimizers = []
            self._indexed_storage = {"candidate": "index"}
            self._flow_context = None
            self._flow_context_key = None
            self._generation += 1

        def capture_runtime_state(self):
            return {
                name: value.copy() if isinstance(value, dict) else value
                for name, value in vars(self).items()
                if name != "fail_restore"
            }

        def restore_runtime_state(self, snapshot):
            if self.fail_restore:
                raise RuntimeError(f"{self.pipeline} adapter restore failed")
            for name in tuple(vars(self)):
                if name not in snapshot and name != "fail_restore":
                    delattr(self, name)
            for name, value in snapshot.items():
                setattr(self, name, value.copy() if isinstance(value, dict) else value)

        def remove(self):
            return None

    manager = state.manager
    manager.instruction_optimizer_rules = list(state.current_ins_rules)
    manager.block_optimizer_rules = list(state.current_blk_rules)
    manager.instruction_optimizer = RecordingOptimizer(
        manager.instruction_optimizer_rules, pipeline="instruction"
    )
    manager.block_optimizer = RecordingOptimizer(
        manager.block_optimizer_rules, pipeline="block"
    )
    manager._sync_native_preanalysis_handlers = lambda: None
    manager._started = True


def _prepare_actual_started_manager(state) -> None:
    """Install the production adapter classes for protocol/rollback coverage."""

    manager = state.manager

    class RuleStore:
        def __init__(self):
            self._rules = {}

        def __iter__(self):
            return iter(self._rules)

    class Analyzer:
        def __init__(self):
            self.rules = RuleStore()

        def add_rule(self, _rule):
            return None

    instruction = InstructionOptimizerManager.__new__(InstructionOptimizerManager)
    instruction.instruction_optimizers = []
    instruction.analyzer = Analyzer()
    instruction.current_maturity = None
    instruction.current_blk_serial = None
    instruction.generate_z3_code = False
    instruction.dump_intermediate_microcode = False
    instruction._execution_scope_service = None
    instruction._execution_scope_project_name = ""
    instruction._execution_scope_idb_key = ""
    instruction._execution_scope_func_ea = -1
    instruction._active_instruction_rule_names_by_maturity = {}
    instruction._residual_admission_cache_key = None
    instruction._residual_admission_cache_value = False
    instruction._run_later_scheduler = None
    instruction._scheduled_stage_identities = frozenset()
    instruction._scheduled_implementation_names = frozenset()
    instruction._active_optimizers = []
    instruction._decompilation_lifecycle = None
    instruction._fact_consumer_callback = None

    block = BlockOptimizerManager.__new__(BlockOptimizerManager)
    block.cfg_rules = []
    block._execution_scope_service = None
    block._execution_scope_project_name = ""
    block._execution_scope_idb_key = ""
    block._perf_compare_execution_scope = False
    block._perf_counters = {}
    block.current_maturity = None
    block._pass_count = 0
    block._max_passes_current = 2000
    block._generation = 0
    block._flow_context = None
    block._flow_context_key = None
    block._validated_fact_view_provider = None
    block._fact_consumer_callback = None
    block._flow_context_summary_provider = None
    block._planner_outcome_callback = None
    block._flow_gate_outcome_callback = None
    block._decompilation_lifecycle = None
    block._prefold_rccc_by_func = {}
    block._function_priors_provider = None
    block._dispatcher_artifact_planner = None
    block._pass_pipeline = None
    block._pipeline_last_maturity = -1
    block._post_d810_pipeline_last_maturity = -1
    block._impossible_return_artifact_rewrite_applied = set()
    block._terminal_zero_literal_rewrite_applied = set()
    block._terminal_tail_cascade_egress_applied = set()
    block._project_config = {}
    block._pipeline_just_fired = False
    block._run_later_scheduler = None
    block._scheduled_stage_identities = frozenset()
    block._scheduled_flow_implementations = ()

    manager.instruction_optimizer_rules = []
    manager.block_optimizer_rules = []
    manager.instruction_optimizer_config = {}
    manager.block_optimizer_config = {}
    manager.instruction_optimizer = instruction
    manager.block_optimizer = block
    manager._sync_native_preanalysis_handlers = lambda: None
    manager._started = True


@pytest.mark.ida_required
def test_live_rules_receive_exact_compiled_provider_maturities() -> None:
    activation = pipeline_v2_hook_activation(_project())
    schedule = activation.constant_simplification_schedule
    assert schedule is not None

    for rule_config in (
        *activation.instruction_rules,
        *activation.block_rules,
    ):
        rule = _RULE_TYPES[rule_config.name]()
        rule.configure(dict(rule_config.config))
        stage = next(
            stage
            for stage in schedule.stages
            if stage.implementation_name == rule_config.name
        )
        supported = tuple(
            string_to_maturity(name)
            for name in constant_simplification_provider_maturities(
                stage.supported_maturities
            )
        )
        effective = tuple(
            string_to_maturity(name)
            for name in constant_simplification_provider_maturities(
                stage.effective_maturities
            )
        )
        assert None not in supported
        assert None not in effective
        assert set(rule.maturities) == set(effective)
        validate_rule_maturity_contract(
            rule,
            pass_id=stage.pass_id,
            stage_id=stage.stage_id,
            expected_supported=tuple(value for value in supported if value is not None),
            expected_effective=tuple(value for value in effective if value is not None),
        )


@pytest.mark.ida_required
def test_live_default_support_drift_fails_closed_with_stage_and_implementation() -> None:
    class DriftedRule:
        name = "FoldReadonlyDataRule"
        default_maturities = (1, 2)
        maturities = (1,)

    with pytest.raises(
        ValueError,
        match=(
            "constant-simplification stage fold-readonly-data implementation "
            "FoldReadonlyDataRule default maturity support drift"
        ),
    ):
        validate_rule_maturity_contract(
            DriftedRule(),
            pass_id="constant-simplification",
            stage_id="fold-readonly-data",
            expected_supported=(1, 2, 3),
            expected_effective=(1,),
        )


@pytest.mark.ida_required
def test_started_activation_replaces_live_rule_collections_for_stage_switches(
    d810_state, monkeypatch
) -> None:
    """A live project switch must add and remove the selected private rules."""
    with d810_state() as state:
        original_index = state.current_project_index
        disabled = _project_with_constant_stages(enabled=False)
        enabled = _project_with_constant_stages(enabled=True)
        try:
            known_rules = list(state.known_ins_rules)
            if not any(rule.name == "FoldReadonlyDataRule" for rule in known_rules):
                known_rules.append(FoldReadonlyDataRule())
            monkeypatch.setattr(
                state,
                "_build_known_instruction_rules",
                lambda: list(known_rules),
            )
            state._activate_runtime_project(
                project_index=9000,
                source_project=enabled,
                runtime_project=enabled,
                default_selection=None,
            )
            _prepare_started_manager(state)
            state._activate_runtime_project(
                project_index=9001,
                source_project=disabled,
                runtime_project=disabled,
                default_selection=None,
            )
            assert "FoldReadonlyDataRule" not in _live_rule_names(state)
            assert "ForwardConstantPropagationRule" not in _live_rule_names(state)
            assert [rule.name for rule in state.manager.instruction_optimizer_rules] == []
            assert [rule.name for rule in state.manager.block_optimizer_rules] == []

            state._activate_runtime_project(
                project_index=9002,
                source_project=enabled,
                runtime_project=enabled,
                default_selection=None,
            )
            assert {
                "FoldReadonlyDataRule",
                "ConstantSubtreeFoldRule",
                "ForwardConstantPropagationRule",
            } <= _live_rule_names(state)
            assert [rule.name for rule in state.manager.instruction_optimizer_rules] == [
                "FoldReadonlyDataRule",
                "ConstantSubtreeFoldRule",
            ]
            assert [rule.name for rule in state.manager.block_optimizer_rules] == [
                "ForwardConstantPropagationRule"
            ]
        finally:
            monkeypatch.undo()
            state.load_project(original_index)
            state.manager._started = False


@pytest.mark.ida_required
def test_started_activation_drift_preserves_previous_state_and_scope(
    d810_state, monkeypatch
) -> None:
    """A live contract failure must not partially install the rejected project."""
    with d810_state() as state:
        original_index = state.current_project_index
        baseline = _project_with_constant_stages(enabled=True)
        known_rules = [
            rule
            for rule in state.known_ins_rules
            if rule.name != "FoldReadonlyDataRule"
        ]
        known_rules.append(FoldReadonlyDataRule())
        monkeypatch.setattr(
            state,
            "_build_known_instruction_rules",
            lambda: list(known_rules),
        )
        state._activate_runtime_project(
            project_index=8999,
            source_project=baseline,
            runtime_project=baseline,
            default_selection=None,
        )
        _prepare_started_manager(state)
        before_project = state.current_project
        before_runtime_project = state.current_runtime_project
        before_ins_rules = tuple(state.current_ins_rules)
        before_blk_rules = tuple(state.current_blk_rules)
        before_snapshot = state.current_project_runtime_snapshot
        manager = state.manager
        before_manager_ins = tuple(manager.instruction_optimizer_rules)
        before_manager_blk = tuple(manager.block_optimizer_rules)
        before_manager_config = dict(manager.config)
        before_schedule = manager._constant_simplification_schedule
        before_scope = tuple(manager.execution_scope_service._stages)

        class DriftedFoldReadonlyDataRule(FoldReadonlyDataRule):
            NAME = "FoldReadonlyDataRule"

            def __init__(self):
                super().__init__()
                self.maturities = self.maturities[:1]

        drifted = DriftedFoldReadonlyDataRule()
        known_rules = list(state.known_ins_rules)
        drifted_index = next(
            (
                index
                for index, rule in enumerate(known_rules)
                if rule.name == drifted.name
            ),
            None,
        )
        if drifted_index is None:
            known_rules.append(drifted)
        else:
            known_rules[drifted_index] = drifted
        monkeypatch.setattr(
            state,
            "_build_known_instruction_rules",
            lambda: list(known_rules),
        )
        rejected = _project_with_constant_stages(enabled=True)
        try:
            with pytest.raises(
                ValueError,
                match=(
                    "constant-simplification stage fold-readonly-data "
                    "implementation FoldReadonlyDataRule"
                ),
            ) as failure:
                state._activate_runtime_project(
                    project_index=9003,
                    source_project=rejected,
                    runtime_project=rejected,
                    default_selection=None,
                )
            message = str(failure.value)
            assert "constant-simplification" in message
            assert "fold-readonly-data" in message
            assert "FoldReadonlyDataRule" in message
            assert state.current_project is before_project
            assert state.current_runtime_project is before_runtime_project
            assert tuple(state.current_ins_rules) == before_ins_rules
            assert tuple(state.current_blk_rules) == before_blk_rules
            assert state.current_project_runtime_snapshot is before_snapshot
            assert tuple(manager.instruction_optimizer_rules) == before_manager_ins
            assert tuple(manager.block_optimizer_rules) == before_manager_blk
            assert manager.config == before_manager_config
            assert manager._constant_simplification_schedule is before_schedule
            assert tuple(manager.execution_scope_service._stages) == before_scope
        finally:
            monkeypatch.undo()
            state.load_project(original_index)
            state.manager._started = False


@pytest.mark.ida_required
def test_started_activation_restores_scope_caches_and_adapter_context_after_late_failure(
    d810_state, monkeypatch
) -> None:
    """A late live failure restores adapter context and non-empty scope caches."""
    from d810.core.execution_scope import ExecutionScopeInvalidation

    with d810_state() as state:
        original_index = state.current_project_index
        baseline = _project_with_constant_stages(enabled=True)
        known_rules = [
            rule
            for rule in state.known_ins_rules
            if rule.name != "FoldReadonlyDataRule"
        ]
        known_rules.append(FoldReadonlyDataRule())
        monkeypatch.setattr(
            state,
            "_build_known_instruction_rules",
            lambda: list(known_rules),
        )
        state._activate_runtime_project(
            project_index=8998,
            source_project=baseline,
            runtime_project=baseline,
            default_selection=None,
        )
        _prepare_started_manager(state)
        manager = state.manager
        scope = manager.execution_scope_service
        scope._stages = ("baseline-stage",)
        scope._generation = 17
        scope._active_cache = {
            ("baseline", "baseline-idb", 0x401000, "pass", 1): (
                "baseline-decision",
            )
        }
        scope._metadata_cache = {0x401000: "baseline-metadata"}
        before_scope_stages = scope._stages
        before_scope_generation = scope._generation
        before_active_cache = dict(scope._active_cache)
        before_metadata_cache = dict(scope._metadata_cache)
        instruction = manager.instruction_optimizer
        block = manager.block_optimizer
        before_adapter_state = {
            "instruction": instruction.capture_runtime_state(),
            "block": block.capture_runtime_state(),
        }

        def invalidate(reason, **kwargs):
            scope.invalidate(
                ExecutionScopeInvalidation(
                    reason=reason,
                    project_name=kwargs.get("project_name"),
                )
            )

        monkeypatch.setattr(manager, "emit_execution_scope_invalidation", invalidate)
        monkeypatch.setattr(
            manager,
            "_compile_execution_scope",
            lambda: (_ for _ in ()).throw(RuntimeError("late scope compilation failure")),
        )
        try:
            with pytest.raises(RuntimeError, match="late scope compilation failure"):
                state._activate_runtime_project(
                    project_index=9004,
                    source_project=_project_with_constant_stages(enabled=False),
                    runtime_project=_project_with_constant_stages(enabled=False),
                    default_selection=None,
                )
            assert scope._stages == before_scope_stages
            assert scope._generation == before_scope_generation
            assert scope._active_cache == before_active_cache
            assert scope._metadata_cache == before_metadata_cache
            assert instruction.capture_runtime_state() == before_adapter_state["instruction"]
            assert block.capture_runtime_state() == before_adapter_state["block"]
        finally:
            monkeypatch.undo()
            state.load_project(original_index)
            state.manager._started = False


@pytest.mark.ida_required
def test_started_activation_marks_runtime_invalid_when_adapter_rollback_fails(
    d810_state, monkeypatch
) -> None:
    """A failed adapter restore must not report the live manager as healthy."""
    with d810_state() as state:
        original_index = state.current_project_index
        baseline = _project_with_constant_stages(enabled=True)
        known_rules = [
            rule
            for rule in state.known_ins_rules
            if rule.name != "FoldReadonlyDataRule"
        ]
        known_rules.append(FoldReadonlyDataRule())
        monkeypatch.setattr(
            state,
            "_build_known_instruction_rules",
            lambda: list(known_rules),
        )
        state._activate_runtime_project(
            project_index=8997,
            source_project=baseline,
            runtime_project=baseline,
            default_selection=None,
        )
        _prepare_started_manager(state)
        manager = state.manager
        manager.instruction_optimizer.fail_restore = True
        monkeypatch.setattr(
            manager,
            "_compile_execution_scope",
            lambda: (_ for _ in ()).throw(RuntimeError("late scope compilation failure")),
        )
        try:
            with pytest.raises(RuntimeError, match="rollback") as failure:
                state._activate_runtime_project(
                    project_index=9005,
                    source_project=_project_with_constant_stages(enabled=False),
                    runtime_project=_project_with_constant_stages(enabled=False),
                    default_selection=None,
                )
            assert "instruction" in str(failure.value)
            assert "adapter restore failed" in str(failure.value)
            assert manager.started is False
            assert getattr(manager, "runtime_invalidated", False) is True
        finally:
            monkeypatch.undo()
            state.manager._runtime_invalidated = False
            state.load_project(original_index)
            state.manager._started = False


@pytest.mark.ida_required
def test_production_adapters_restore_allowlisted_runtime_state(d810_state) -> None:
    """The live adapter classes own their explicit rollback protocol."""
    with d810_state() as state:
        _prepare_actual_started_manager(state)
        instruction = state.manager.instruction_optimizer
        block = state.manager.block_optimizer
        assert isinstance(instruction, InstructionOptimizerManager)
        assert isinstance(block, BlockOptimizerManager)

        instruction._execution_scope_project_name = "baseline"
        instruction._execution_scope_idb_key = "baseline-idb"
        instruction._execution_scope_func_ea = 0x401000
        instruction._active_instruction_rule_names_by_maturity = {
            1: frozenset({"baseline-rule"})
        }
        instruction._residual_admission_cache_key = (1, "baseline")
        instruction._residual_admission_cache_value = True
        instruction._active_optimizers = ["baseline-optimizer"]
        instruction._scheduled_stage_identities = frozenset({"baseline-stage"})
        instruction._scheduled_implementation_names = ("BaselineRule",)
        instruction.analyzer.rules._rules["baseline-rule"] = None
        block._execution_scope_project_name = "baseline"
        block._execution_scope_idb_key = "baseline-idb"
        block.cfg_rules = ["baseline-block-rule"]
        block._project_config = {"project_name": "baseline"}
        block._flow_context = "baseline-flow"
        block._flow_context_key = (1, 2, 3, 4, 5)
        block._scheduled_stage_identities = frozenset({"baseline-stage"})
        block._scheduled_flow_implementations = ("BaselineRule",)
        block._perf_counters = {"scoped_calls": 7, "legacy_calls": 3}
        before_instruction = instruction.capture_runtime_state()
        before_block = block.capture_runtime_state()

        candidate_scope = object()
        instruction.configure(
            execution_scope_service=candidate_scope,
            execution_scope_project_name="candidate",
            execution_scope_idb_key="candidate-idb",
        )
        block.configure(
            execution_scope_service=candidate_scope,
            execution_scope_project_name="candidate",
            execution_scope_idb_key="candidate-idb",
            project_name="candidate",
        )
        instruction.analyzer.rules._rules.clear()
        block.cfg_rules.clear()
        instruction._active_instruction_rule_names_by_maturity = {}
        instruction._residual_admission_cache_key = None
        instruction._residual_admission_cache_value = False
        instruction._active_optimizers = []
        instruction._scheduled_stage_identities = frozenset()
        instruction._scheduled_implementation_names = ()
        block._execution_scope_project_name = "candidate"
        block._execution_scope_idb_key = "candidate-idb"
        block._project_config = {"project_name": "candidate"}
        block._flow_context = None
        block._flow_context_key = None
        block._scheduled_stage_identities = frozenset()
        block._scheduled_flow_implementations = ()
        block._perf_counters = {"scoped_calls": 0, "legacy_calls": 0}

        instruction.restore_runtime_state(before_instruction)
        block.restore_runtime_state(before_block)
        assert instruction.capture_runtime_state() == before_instruction
        assert block.capture_runtime_state() == before_block
        assert tuple(instruction.analyzer.rules) == ("baseline-rule",)
        assert block.cfg_rules == ["baseline-block-rule"]


@pytest.mark.ida_required
def test_actual_adapter_restore_failure_runs_full_manager_cleanup(
    d810_state, monkeypatch
) -> None:
    """A failed live restore must leave every manager-owned hook/resource stopped."""
    with d810_state() as state:
        original_index = state.current_project_index
        baseline = _project_with_constant_stages(enabled=False)
        state._activate_runtime_project(
            project_index=8996,
            source_project=baseline,
            runtime_project=baseline,
            default_selection=None,
        )
        _prepare_actual_started_manager(state)
        manager = state.manager
        calls: list[str] = []

        class Resource:
            def close(self):
                calls.append("resource.close")

        class Hook:
            def unhook(self):
                calls.append("hooks.unhook")

        manager._native_preanalysis_handlers_installed = True
        manager._uninstall_native_preanalysis_handlers = lambda: calls.append(
            "native.uninstall"
        )
        monkeypatch.setattr(
            "d810.manager.hexrays_frontend_normalization.uninstall_live_frontend_normalization",
            lambda: calls.append("frontend.uninstall"),
        )
        monkeypatch.setattr(
            manager.instruction_optimizer,
            "remove",
            lambda: calls.append("instruction.remove"),
        )
        def block_remove():
            calls.append("block.remove")
            raise RuntimeError("forced block cleanup failure")

        monkeypatch.setattr(manager.block_optimizer, "remove", block_remove)
        manager.hx_decompiler_hook = Hook()
        monkeypatch.setattr(
            manager.execution_scope_service,
            "detach",
            lambda: calls.append("execution_scope.detach"),
        )
        monkeypatch.setattr(
            manager.event_emitter,
            "clear",
            lambda: calls.append("event_emitter.clear"),
        )
        manager._idb_preparation_journal = Resource()
        manager._native_patch_journal = Resource()
        manager._native_patch_execution_journal = Resource()
        manager.function_storage_runtime.close = lambda: calls.append(
            "function_storage.close"
        )
        manager._analysis_bundle = Resource()
        manager._started = True
        manager.instruction_optimizer.restore_runtime_state = lambda _state: (_ for _ in ()).throw(
            RuntimeError("forced instruction restore failure")
        )
        monkeypatch.setattr(
            manager,
            "_compile_execution_scope",
            lambda: (_ for _ in ()).throw(RuntimeError("late scope compilation failure")),
        )
        try:
            with pytest.raises(RuntimeError, match="rollback") as failure:
                state._activate_runtime_project(
                    project_index=9006,
                    source_project=_project_with_constant_stages(enabled=False),
                    runtime_project=_project_with_constant_stages(enabled=False),
                    default_selection=None,
                )
            failure_message = str(failure.value)
            assert "forced instruction restore failure" in failure_message
            assert "block.remove" in failure_message
            assert {
                "native.uninstall",
                "frontend.uninstall",
                "instruction.remove",
                "block.remove",
                "hooks.unhook",
                "execution_scope.detach",
                "event_emitter.clear",
                "resource.close",
                "function_storage.close",
            } <= set(calls)
            assert manager.started is False
            assert manager.runtime_invalidated is True
            assert manager._native_preanalysis_handlers_installed is False
            assert manager.decompilation_lifecycle is None
            assert manager._idb_preparation_journal is None
            assert manager._native_patch_journal is None
            assert manager._native_patch_execution_journal is None
            assert manager._analysis_bundle is None
        finally:
            monkeypatch.undo()
            state.manager._runtime_invalidated = False
            state.load_project(original_index)
            state.manager._started = False

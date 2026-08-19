"""Live Hex-Rays activation of the compiled constant-stage schedule."""

from __future__ import annotations

from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration
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

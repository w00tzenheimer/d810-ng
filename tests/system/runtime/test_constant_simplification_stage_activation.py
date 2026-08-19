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
        def __init__(self, rules):
            self.rules = list(rules)

        def configure(self, **kwargs):
            self.configuration = kwargs

        def replace_rules(self, rules):
            self.rules = list(rules)

        def remove(self):
            return None

    manager = state.manager
    manager.instruction_optimizer_rules = list(state.current_ins_rules)
    manager.block_optimizer_rules = list(state.current_blk_rules)
    manager.instruction_optimizer = RecordingOptimizer(
        manager.instruction_optimizer_rules
    )
    manager.block_optimizer = RecordingOptimizer(manager.block_optimizer_rules)
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
        known_rules = list(state.known_ins_rules)
        if not any(rule.name == "FoldReadonlyDataRule" for rule in known_rules):
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

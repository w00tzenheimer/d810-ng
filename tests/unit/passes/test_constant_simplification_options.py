from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from d810.ir.maturity import IRMaturity
from d810.passes.constant_simplification import (
    CONSTANT_SIMPLIFICATION_PASS_ID,
    build_constant_simplification_pass,
)
from d810.passes.constant_simplification_options import (
    CompiledConstantSimplificationSchedule,
    StageLifecycleDomain,
    compile_constant_simplification_schedule,
)
from d810.passes.pass_pipeline import PipelineConfig, PipelineConfigError


def _config(
    options: dict[str, object] | None = None,
    *,
    maturity_gates: frozenset[IRMaturity] = frozenset(),
) -> PipelineConfig:
    return PipelineConfig(
        pass_id=CONSTANT_SIMPLIFICATION_PASS_ID,
        maturity_gates=maturity_gates,
        options={} if options is None else options,
    )


def _stage(schedule: CompiledConstantSimplificationSchedule, stage_id: str):
    return next(stage for stage in schedule.stages if stage.stage_id == stage_id)


def test_default_schedule_compiles_current_support_and_runtime_order() -> None:
    schedule = build_constant_simplification_pass(_config()).options

    assert isinstance(schedule, CompiledConstantSimplificationSchedule)
    assert schedule.preparation.enabled is False
    assert schedule.preparation.discover_bounded_tables is True
    assert tuple(stage.stage_id for stage in schedule.stages) == (
        "fold-readonly-data",
        "fold-constant-subtree",
        "forward-constants",
    )
    assert all(stage.enabled for stage in schedule.stages)
    assert _stage(schedule, "fold-readonly-data").effective_maturities == (
        IRMaturity.CANONICAL,
        IRMaturity.LOCAL_OPTIMIZED,
        IRMaturity.CALL_MODELED,
        IRMaturity.GLOBAL_ANALYZED,
        IRMaturity.STRUCTURED,
    )
    assert _stage(schedule, "fold-constant-subtree").runtime_order == 1
    assert _stage(schedule, "forward-constants").runtime_order == 0
    assert all(
        stage.lifecycle_domain is StageLifecycleDomain.MICROCODE
        for stage in schedule.stages
    )


def test_canonical_options_compile_every_explicit_field() -> None:
    schedule = compile_constant_simplification_schedule(
        _config(
            {
                "preparation": {
                    "global_const_types": {
                        "enabled": True,
                        "discover_bounded_tables": False,
                    }
                },
                "stages": {
                    "fold-readonly-data": {
                        "enabled": False,
                        "maturities": ["STRUCTURED"],
                        "memory_policy": "aggressive_no_direct_writes",
                        "rva_guard": False,
                        "allow_executable_readonly": True,
                    },
                    "fold-constant-subtree": {
                        "enabled": True,
                        "maturities": ["MMAT_GLBOPT2", "LOCAL_OPTIMIZED"],
                    },
                    "forward-constants": {
                        "enabled": False,
                        "maturities": ["GLOBAL_ANALYZED"],
                    },
                },
            }
        )
    )

    assert schedule.preparation.enabled is True
    assert schedule.preparation.discover_bounded_tables is False
    readonly = _stage(schedule, "fold-readonly-data")
    assert readonly.enabled is False
    assert readonly.requested_maturities == (IRMaturity.STRUCTURED,)
    assert readonly.effective_maturities == ()
    assert readonly.inactive_reason == "disabled by configuration"
    assert dict(readonly.options) == {
        "memory_policy": "aggressive_no_direct_writes",
        "rva_guard": False,
        "allow_executable_readonly": True,
    }
    subtree = _stage(schedule, "fold-constant-subtree")
    assert subtree.requested_maturities == (
        IRMaturity.LOCAL_OPTIMIZED,
        IRMaturity.GLOBAL_OPTIMIZED,
    )
    forward = _stage(schedule, "forward-constants")
    assert forward.enabled is False
    assert forward.effective_maturities == ()
    assert forward.inactive_reason == "disabled by configuration"


def test_legacy_options_compile_to_the_exact_default_schedule() -> None:
    legacy = build_constant_simplification_pass(
        _config(
            {
                "memory_policy": "aggressive_no_direct_writes",
                "rva_guard": False,
                "allow_executable_readonly": True,
                "persist_global_const_annotations": True,
            }
        )
    ).options

    assert legacy.preparation.enabled is True
    assert legacy.preparation.discover_bounded_tables is True
    readonly = _stage(legacy, "fold-readonly-data")
    assert readonly.requested_maturities == readonly.supported_maturities
    assert dict(readonly.options) == {
        "memory_policy": "aggressive_no_direct_writes",
        "rva_guard": False,
        "allow_executable_readonly": True,
    }
    assert all(
        _stage(legacy, stage_id).requested_maturities
        == _stage(legacy, stage_id).supported_maturities
        for stage_id in ("fold-constant-subtree", "forward-constants")
    )


def test_maturity_names_are_deduplicated_and_ordered_by_portable_vocabulary() -> None:
    schedule = compile_constant_simplification_schedule(
        _config(
            {
                "stages": {
                    "fold-readonly-data": {
                        "maturities": [
                            "MMAT_GLBOPT1",
                            "CANONICAL",
                            "GLOBAL_ANALYZED",
                            "MMAT_PREOPTIMIZED",
                        ]
                    }
                }
            }
        )
    )

    assert _stage(schedule, "fold-readonly-data").requested_maturities == (
        IRMaturity.CANONICAL,
        IRMaturity.GLOBAL_ANALYZED,
    )


def test_pass_gates_intersect_requested_maturities() -> None:
    schedule = compile_constant_simplification_schedule(
        _config(
            {
                "stages": {
                    "forward-constants": {
                        "maturities": [
                            "CALL_MODELED",
                            "GLOBAL_ANALYZED",
                            "GLOBAL_OPTIMIZED",
                        ]
                    }
                }
            },
            maturity_gates=frozenset(
                {IRMaturity.GLOBAL_ANALYZED, IRMaturity.GLOBAL_OPTIMIZED}
            ),
        )
    )

    forward = _stage(schedule, "forward-constants")
    assert forward.pass_maturity_gates == (
        IRMaturity.GLOBAL_ANALYZED,
        IRMaturity.GLOBAL_OPTIMIZED,
    )
    assert forward.effective_maturities == (
        IRMaturity.GLOBAL_ANALYZED,
        IRMaturity.GLOBAL_OPTIMIZED,
    )


@pytest.mark.parametrize(
    ("options", "diagnostic"),
    [
        (
            {"memory_policy": "strict", "preparation": {}},
            "cannot mix legacy options with canonical",
        ),
        (
            {"preparation": {"unknown": True}},
            "preparation has unknown",
        ),
        (
            {"stages": {"unknown-stage": {}}},
            "unknown stage",
        ),
        (
            {"stages": {"fold-constant-subtree": {"unknown": True}}},
            "unknown option",
        ),
        (
            {"stages": {"fold-constant-subtree": {"maturities": "CALL_MODELED"}}},
            "maturities must be a list",
        ),
        (
            {"stages": {"fold-constant-subtree": {"maturities": [True]}}},
            "maturity",
        ),
        (
            {"stages": {"fold-constant-subtree": {"maturities": [""]}}},
            "maturity",
        ),
    ],
)
def test_invalid_canonical_options_are_rejected(
    options: dict[str, object], diagnostic: str
) -> None:
    with pytest.raises(PipelineConfigError, match=diagnostic):
        build_constant_simplification_pass(_config(options))


def test_unsupported_maturity_names_include_stage_and_supported_set() -> None:
    with pytest.raises(
        PipelineConfigError,
        match=(
            "constant-simplification.*fold-readonly-data.*LIFTED.*supported.*CANONICAL"
        ),
    ):
        build_constant_simplification_pass(
            _config(
                {
                    "stages": {
                        "fold-readonly-data": {"maturities": ["LIFTED"]}
                    }
                }
            )
        )


def test_enabled_stage_with_empty_gate_intersection_is_rejected() -> None:
    with pytest.raises(
        PipelineConfigError,
        match="forward-constants.*requested.*pass maturity_gates",
    ):
        build_constant_simplification_pass(
            _config(
                {
                    "stages": {
                        "fold-readonly-data": {"enabled": False},
                        "fold-constant-subtree": {"enabled": False},
                        "forward-constants": {"maturities": ["STRUCTURED"]},
                    }
                },
                maturity_gates=frozenset({IRMaturity.CANONICAL}),
            )
        )


def test_compiled_stage_options_are_deeply_immutable() -> None:
    schedule = build_constant_simplification_pass(_config()).options
    readonly = _stage(schedule, "fold-readonly-data")

    with pytest.raises(TypeError):
        readonly.options["memory_policy"] = "aggressive_no_direct_writes"  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        schedule.preparation.enabled = True  # type: ignore[misc]


def test_compiled_schedule_has_frozen_stage_tuple_and_preparation_domain_is_separate() -> None:
    schedule = build_constant_simplification_pass(_config()).options

    assert isinstance(schedule.stages, tuple)
    assert all(stage.pipeline is not None for stage in schedule.stages)
    assert all(stage.lifecycle_domain is StageLifecycleDomain.MICROCODE for stage in schedule.stages)


def test_disabled_first_instruction_stage_does_not_consume_runtime_order_slot() -> None:
    schedule = build_constant_simplification_pass(
        _config(
            {
                "stages": {
                    "fold-readonly-data": {"enabled": False},
                    "forward-constants": {"enabled": False},
                }
            }
        )
    ).options

    assert _stage(schedule, "fold-readonly-data").runtime_order is None
    assert _stage(schedule, "fold-constant-subtree").runtime_order == 0
    assert _stage(schedule, "forward-constants").runtime_order is None


def test_all_disabled_and_mixed_pipeline_orders_are_contiguous() -> None:
    all_disabled = build_constant_simplification_pass(
        _config(
            {
                "stages": {
                    "fold-readonly-data": {"enabled": False},
                    "fold-constant-subtree": {"enabled": False},
                    "forward-constants": {"enabled": False},
                }
            }
        )
    ).options
    assert [stage.runtime_order for stage in all_disabled.stages] == [None, None, None]

    mixed = build_constant_simplification_pass(
        _config(
            {
                "stages": {
                    "fold-constant-subtree": {"enabled": False},
                }
            }
        )
    ).options
    assert _stage(mixed, "fold-readonly-data").runtime_order == 0
    assert _stage(mixed, "fold-constant-subtree").runtime_order is None
    assert _stage(mixed, "forward-constants").runtime_order == 0

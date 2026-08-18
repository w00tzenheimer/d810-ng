"""Project configured passes onto their effective Hex-Rays maturity schedule."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence

from d810.core.execution_scope import ExecutionPipeline
from d810.ir.maturity import IRMaturity, IR_MATURITY_ORDER
from d810.manager.workbench_models import (
    EffectiveMaturitySchedule,
    EffectiveMaturityScheduleRow,
    EffectiveScheduleStage,
)
from d810.passes.pass_pipeline import MaturityRange, PipelineConfig


_PROVIDER_BY_IR = {
    IRMaturity.LIFTED: "MMAT_GENERATED",
    IRMaturity.CANONICAL: "MMAT_PREOPTIMIZED",
    IRMaturity.LOCAL_OPTIMIZED: "MMAT_LOCOPT",
    IRMaturity.CALL_MODELED: "MMAT_CALLS",
    IRMaturity.GLOBAL_ANALYZED: "MMAT_GLBOPT1",
    IRMaturity.GLOBAL_OPTIMIZED: "MMAT_GLBOPT2",
    IRMaturity.STRUCTURED: "MMAT_GLBOPT3",
    IRMaturity.VARIABLE_RECOVERED: "MMAT_LVARS",
}
_IR_BY_PROVIDER = {provider: maturity for maturity, provider in _PROVIDER_BY_IR.items()}
_PIPELINE_ORDER = {
    ExecutionPipeline.INSTRUCTION: 0,
    ExecutionPipeline.FLOW: 1,
    ExecutionPipeline.CTREE: 2,
}


def _implementation_name(value: object) -> str:
    return str(getattr(value, "name", value.__class__.__name__))


def normalize_maturity(
    value: object,
    maturity_name_provider: Callable[[int], str] = lambda value: f"MMAT_{value}",
) -> tuple[IRMaturity, str] | None:
    """Normalize portable or provider maturity spelling without importing IDA."""

    if isinstance(value, IRMaturity):
        return value, _PROVIDER_BY_IR[value]
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        provider = str(maturity_name_provider(value)).upper()
        maturity = _IR_BY_PROVIDER.get(provider)
        return None if maturity is None else (maturity, provider)
    text = str(value).strip().upper()
    if not text:
        return None
    if text in _IR_BY_PROVIDER:
        return _IR_BY_PROVIDER[text], text
    try:
        maturity = IRMaturity[text]
    except KeyError:
        try:
            maturity = IRMaturity(str(value))
        except ValueError:
            return None
    return maturity, _PROVIDER_BY_IR[maturity]


def _contract_maturities(config: PipelineConfig) -> tuple[IRMaturity, ...]:
    if config.maturity_gates:
        return tuple(
            maturity
            for maturity in IR_MATURITY_ORDER
            if maturity in config.maturity_gates
        )
    maturity_range = config.contract.maturity
    if maturity_range == MaturityRange():
        return ()
    return tuple(
        maturity for maturity in IR_MATURITY_ORDER if maturity_range.contains(maturity)
    )


def _requirements(contract: object) -> tuple[str, ...]:
    requires = getattr(contract, "requires", None)
    facts = getattr(getattr(requires, "facts", None), "required", ())
    return tuple(
        sorted(
            {
                *(str(value) for value in getattr(requires, "analyses", ())),
                *(str(value) for value in getattr(requires, "evidence", ())),
                *(str(value) for value in facts),
            }
        )
    )


def build_effective_maturity_schedule(
    configs: Sequence[PipelineConfig],
    *,
    registry: object,
    implementations: Mapping[ExecutionPipeline, Sequence[object]],
    maturity_name_provider: Callable[[int], str] = lambda value: f"MMAT_{value}",
) -> EffectiveMaturitySchedule:
    """Use live worklist objects first, then exact pass-owned maturity metadata."""

    worklists = {
        pipeline: tuple(values) for pipeline, values in implementations.items()
    }
    runtime_positions = {
        pipeline: {
            _implementation_name(implementation): index
            for index, implementation in enumerate(values)
        }
        for pipeline, values in worklists.items()
    }
    implementation_by_name = {
        pipeline: {
            _implementation_name(implementation): implementation
            for implementation in values
        }
        for pipeline, values in worklists.items()
    }

    projected: list[EffectiveScheduleStage] = []
    for configured_index, config in enumerate(configs):
        spec = registry.build_spec(config)
        requirements = _requirements(spec.contract)
        descriptors = tuple(registry.stages_for(config.pass_id))
        for descriptor in descriptors:
            descriptor_pipeline = getattr(descriptor, "pipeline", None)
            if not isinstance(descriptor_pipeline, ExecutionPipeline):
                continue
            implementation = implementation_by_name.get(descriptor_pipeline, {}).get(
                descriptor.implementation_name
            )
            normalized: list[tuple[IRMaturity, str]] = []
            maturity_source = "rule-defined-unknown"
            if implementation is not None:
                normalized = [
                    item
                    for value in tuple(getattr(implementation, "maturities", ()) or ())
                    if (item := normalize_maturity(value, maturity_name_provider))
                    is not None
                ]
                if normalized:
                    maturity_source = "private-rule"
            if not normalized:
                configured_maturities = config.options.get("maturities", ())
                if isinstance(configured_maturities, (list, tuple)):
                    normalized = [
                        item
                        for value in configured_maturities
                        if (item := normalize_maturity(value, maturity_name_provider))
                        is not None
                    ]
                    if normalized:
                        maturity_source = "configured-rule"
            if not normalized:
                contract_maturities = _contract_maturities(config)
                normalized = [
                    (maturity, _PROVIDER_BY_IR[maturity])
                    for maturity in contract_maturities
                ]
                if normalized:
                    maturity_source = (
                        "explicit-gate" if config.maturity_gates else "pass-contract"
                    )
            ordered_maturities = tuple(
                provider
                for maturity in IR_MATURITY_ORDER
                for candidate, provider in normalized
                if candidate is maturity
            )
            runtime_order = runtime_positions.get(descriptor_pipeline, {}).get(
                descriptor.implementation_name,
                -1,
            )
            projected.append(
                EffectiveScheduleStage(
                    configured_index=configured_index,
                    runtime_order=runtime_order,
                    pass_id=config.pass_id,
                    stage_id=descriptor.stage_id,
                    pipeline=descriptor_pipeline.value,
                    implementation_name=descriptor.implementation_name,
                    requirements=requirements,
                    provider_maturities=ordered_maturities,
                    maturity_source=maturity_source,
                )
            )

    stages = tuple(
        sorted(
            projected,
            key=lambda stage: (
                stage.configured_index,
                stage.pipeline,
                stage.runtime_order,
                stage.stage_id,
            ),
        )
    )
    rows: list[EffectiveMaturityScheduleRow] = []
    for ordinal, maturity in enumerate(IR_MATURITY_ORDER):
        provider = _PROVIDER_BY_IR[maturity]
        eligible = tuple(
            sorted(
                (stage for stage in stages if provider in stage.provider_maturities),
                key=lambda stage: (
                    _PIPELINE_ORDER.get(ExecutionPipeline(stage.pipeline), 99),
                    stage.runtime_order,
                    stage.configured_index,
                    stage.stage_id,
                ),
            )
        )
        rows.append(
            EffectiveMaturityScheduleRow(
                ordinal=ordinal,
                ir_maturity=maturity.value,
                provider_maturity=provider,
                stages=eligible,
            )
        )
    return EffectiveMaturitySchedule(rows=tuple(rows), stages=stages)


__all__ = ["build_effective_maturity_schedule", "normalize_maturity"]

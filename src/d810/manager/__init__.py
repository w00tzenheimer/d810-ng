"""Public manager API and manager-local orchestration helpers."""
from __future__ import annotations

__all__ = [
    "ArtifactRef",
    "AttackSummary",
    "BaselineRef",
    "ConsumerOutcomeSnapshot",
    "CountEntry",
    "D810_LOG_DIR_NAME",
    "D810Manager",
    "D810State",
    "D810OutputRef",
    "DeobfuscationWorkbenchSnapshot",
    "FunctionRef",
    "OutcomeStatus",
    "PatchCountEntry",
    "PipelineStageSnapshot",
    "ProjectConfigurationEditError",
    "ProjectConfigMode",
    "ProjectIdentitySnapshot",
    "ProjectRuntimeSnapshot",
    "RuleScopeSummary",
    "RuleProjectionKind",
    "RuntimeConfigRef",
    "SnapshotFreshness",
    "StatisticsSummary",
    "WorkbenchCommandRequest",
    "WorkbenchCommandResult",
    "WorkbenchDiagnostic",
    "d810_hooks_suppressed",
    "maybe_run_tail_distinct",
]

_WORKBENCH_MODEL_NAMES = {
    "ArtifactRef",
    "AttackSummary",
    "BaselineRef",
    "ConsumerOutcomeSnapshot",
    "CountEntry",
    "D810OutputRef",
    "DeobfuscationWorkbenchSnapshot",
    "FunctionRef",
    "OutcomeStatus",
    "PatchCountEntry",
    "PipelineStageSnapshot",
    "RuleScopeSummary",
    "RuntimeConfigRef",
    "SnapshotFreshness",
    "StatisticsSummary",
    "WorkbenchCommandRequest",
    "WorkbenchCommandResult",
    "WorkbenchDiagnostic",
}


def __getattr__(name: str):
    if name in _WORKBENCH_MODEL_NAMES:
        import d810.manager.workbench_models as workbench_models

        return getattr(workbench_models, name)
    if name in {
        "ProjectConfigurationEditError",
        "ProjectConfigMode",
        "ProjectIdentitySnapshot",
        "ProjectRuntimeSnapshot",
        "RuleProjectionKind",
    }:
        import d810.manager.project_runtime as project_runtime

        return getattr(project_runtime, name)
    if name == "D810State":
        from d810.manager.state import D810State

        return D810State
    if name in {
        "D810_LOG_DIR_NAME",
        "D810Manager",
        "d810_hooks_suppressed",
        "maybe_run_tail_distinct",
    }:
        from d810.manager import manager

        return getattr(manager, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

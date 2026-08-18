"""Qt-free presentation records for the primary Build Deobfuscator workspace."""

from __future__ import annotations

import dataclasses

from d810.core import typing
from d810.manager.workbench_models import SnapshotFreshness
from d810.ui.workbench_canvas_models import MaturityCanvasProjection


@dataclasses.dataclass(frozen=True, slots=True)
class BuildWorkspaceHeader:
    """Current function and action state for the compact workspace header."""

    function_label: str
    protection_label: str
    deobfuscate_enabled: bool
    deobfuscate_reason: str


@dataclasses.dataclass(frozen=True, slots=True)
class FunctionDossier:
    """Read-only function/case summary kept visible beside the timeline."""

    function_name: str
    function_ea: int | None
    protection_label: str
    summary: str
    shape_lines: tuple[str, ...]
    evidence_lines: tuple[str, ...]
    diagnostic_lines: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class BuildWorkspaceFooter:
    """Compact state that remains visible below the timeline."""

    diagnostics_capture: str
    maturity_summary: str
    project_summary: str
    engine_summary: str


@dataclasses.dataclass(frozen=True, slots=True)
class BuildWorkspaceProjection:
    """One truthful, immutable view of the existing authoritative state."""

    header: BuildWorkspaceHeader
    dossier: FunctionDossier
    footer: BuildWorkspaceFooter
    canvas: MaturityCanvasProjection


def _function_label(snapshot: typing.Any) -> tuple[str, int | None]:
    function = getattr(snapshot, "function", None)
    name = str(getattr(function, "name", "") or "No function selected")
    ea = getattr(function, "ea", None)
    return name, int(ea) if isinstance(ea, int) else None


def _case_evidence_lines(snapshot: typing.Any) -> tuple[str, ...]:
    case = getattr(snapshot, "case", None)
    evidence = getattr(case, "evidence", None)
    findings = tuple(getattr(evidence, "findings", ()) or ())
    return tuple(
        f"{getattr(finding, 'finding_id', 'finding')} @ "
        f"0x{int(getattr(finding, 'native_ea', 0)):X}: "
        f"{getattr(finding, 'summary', '')}"
        for finding in findings
        if isinstance(getattr(finding, "native_ea", None), int)
    )


def _protection(snapshot: typing.Any) -> tuple[str, str, tuple[str, ...]]:
    attack = getattr(snapshot, "attack", None)
    profile = getattr(attack, "selected_profile", None)
    if not isinstance(profile, str) or not profile:
        return (
            "Generic cleanup",
            "Generic cleanup - no classified protection-specific case evidence.",
            (),
        )
    observed_shape = str(getattr(attack, "observed_shape", "unknown") or "unknown")
    mechanism = str(getattr(attack, "mechanism", "unknown") or "unknown")
    return (
        profile,
        f"Classified protection profile: {profile}.",
        (f"Shape: {observed_shape}", f"Mechanism: {mechanism}"),
    )


def build_function_dossier(snapshot: typing.Any) -> FunctionDossier:
    """Return a truthful dossier without fabricating a protection classification."""

    name, ea = _function_label(snapshot)
    protection_label, summary, shape_lines = _protection(snapshot)
    diagnostics = tuple(str(value) for value in getattr(snapshot, "collection_errors", ()) or ())
    return FunctionDossier(
        function_name=name,
        function_ea=ea,
        protection_label=protection_label,
        summary=summary,
        shape_lines=shape_lines,
        evidence_lines=_case_evidence_lines(snapshot),
        diagnostic_lines=diagnostics,
    )


def _deobfuscate_state(snapshot: typing.Any) -> tuple[bool, str]:
    case = getattr(snapshot, "case", None)
    freshness = getattr(snapshot, "freshness", None)
    if freshness is not None and freshness is not SnapshotFreshness.CURRENT:
        return False, "Build evidence is stale; rebuild the deobfuscator first."
    if case is None:
        return False, "Build a deobfuscator to collect current case evidence."
    if bool(getattr(case, "direct_run_permitted", False)):
        return True, "Current case strategy is eligible for deobfuscation."
    evidence = getattr(case, "evidence", None)
    verdict = getattr(evidence, "verdict", None)
    blocked = getattr(verdict, "first_blocked_obligation", None)
    if isinstance(blocked, str) and blocked:
        return False, f"First blocked obligation: {blocked}"
    reason = getattr(case, "direct_run_reason", None)
    return False, str(reason or "No validated deobfuscation strategy is selected.")


def build_workspace_projection(
    snapshot: typing.Any,
    canvas: MaturityCanvasProjection,
    *,
    diagnostics_capture_enabled: bool = False,
) -> BuildWorkspaceProjection:
    """Project existing snapshot data without taking ownership of execution."""

    dossier = build_function_dossier(snapshot)
    function_label = dossier.function_name
    if dossier.function_ea is not None:
        function_label = f"{function_label} @ 0x{dossier.function_ea:X}"
    direct_enabled, direct_reason = _deobfuscate_state(snapshot)
    project = getattr(snapshot, "project", None)
    project_name = str(
        getattr(project, "project_name", "No project") or "No project"
    )
    engine_started = bool(getattr(snapshot, "engine_started", False))
    diagnostics_capture = (
        "Diagnostics capture ON"
        if diagnostics_capture_enabled
        else "Diagnostics capture OFF"
    )
    return BuildWorkspaceProjection(
        header=BuildWorkspaceHeader(
            function_label=function_label,
            protection_label=dossier.protection_label,
            deobfuscate_enabled=direct_enabled,
            deobfuscate_reason=direct_reason,
        ),
        dossier=dossier,
        footer=BuildWorkspaceFooter(
            diagnostics_capture=diagnostics_capture,
            maturity_summary=f"{len(canvas.maturities)} maturity stage(s)",
            project_summary=project_name,
            engine_summary="Engine running" if engine_started else "Engine idle",
        ),
        canvas=canvas,
    )


__all__ = [
    "BuildWorkspaceFooter",
    "BuildWorkspaceHeader",
    "BuildWorkspaceProjection",
    "FunctionDossier",
    "build_function_dossier",
    "build_workspace_projection",
]

"""Session-scoped evidence capture helpers for Rhad investigation probes."""

from __future__ import annotations

from d810.analyses.control_flow.native_preanalysis_session import (
    PreoptUnionPreparationResult,
    ResolverEvidenceAttachment,
)


def _resolver_attachment(state: object | None) -> ResolverEvidenceAttachment | None:
    if state is None:
        return None
    if not isinstance(state, ResolverEvidenceAttachment):
        raise TypeError("Rhad probe evidence requires a typed resolver attachment")
    return state


def capture_preopt_union_preparation(
    state: object,
    captured: list[object],
) -> None:
    """Capture live PREOPT preparation before lifecycle cleanup."""
    attachment = _resolver_attachment(state)
    if attachment is None:
        return
    preparation = attachment.native_preanalysis.resolver_evidence_for(
        attachment.native_key
    ).preopt_union_preparation
    if preparation is not None:
        captured[:] = [preparation]


def latest_preopt_union_preparation(
    state: object | None,
    captured: list[object],
) -> PreoptUnionPreparationResult | None:
    """Return PREOPT preparation visible to a completed probe."""
    attachment = _resolver_attachment(state)
    if attachment is not None:
        live = attachment.native_preanalysis.resolver_evidence_for(
            attachment.native_key
        ).preopt_union_preparation
        if live is not None:
            return live
    captured_preparation = captured[-1] if captured else None
    if captured_preparation is None:
        return None
    if not isinstance(captured_preparation, PreoptUnionPreparationResult):
        raise TypeError("captured PREOPT preparation has the wrong typed payload")
    return captured_preparation


def native_preanalysis_boundary_port_count(state: object | None) -> int:
    """Count canonical portable boundary facts without a live preparation."""
    attachment = _resolver_attachment(state)
    if attachment is None or attachment.native_preanalysis.facts is None:
        return 0
    ports = attachment.native_preanalysis.facts.boundary_ports
    return len(ports.direct) + len(ports.conditional)

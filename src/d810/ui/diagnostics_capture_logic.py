"""Pure presentation policy for diagnostics capture controls."""

from __future__ import annotations

import dataclasses


@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticsCapturePresentation:
    icon_name: str
    status_label: str
    tooltip: str
    action_label: str | None


def diagnostics_capture_presentation(enabled: bool) -> DiagnosticsCapturePresentation:
    """Describe the compact UI state without importing Qt or IDA."""
    if enabled:
        return DiagnosticsCapturePresentation(
            icon_name="diagnostics-capture-enabled",
            status_label="Capture enabled",
            tooltip=(
                "Diagnostics capture enabled - the next decompilation will "
                "record snapshots and structured evidence."
            ),
            action_label="Disable capture",
        )
    return DiagnosticsCapturePresentation(
        icon_name="diagnostics-capture-disabled",
        status_label="Capture disabled",
        tooltip="Diagnostics capture is disabled. Enable it before decompiling.",
        action_label="Enable capture",
    )


__all__ = ["DiagnosticsCapturePresentation", "diagnostics_capture_presentation"]

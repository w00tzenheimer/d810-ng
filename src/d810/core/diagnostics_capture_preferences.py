"""IDA-free persistence policy for the global diagnostics capture preference."""

from __future__ import annotations

from d810.core import typing


DIAGNOSTICS_CAPTURE_OPTION = "diag_snapshots"


def diagnostics_capture_enabled(
    configuration: typing.Any,
    *,
    runtime_default: bool,
) -> bool:
    """Return the persisted choice, falling back to the runtime default."""
    return bool(configuration.get(DIAGNOSTICS_CAPTURE_OPTION, runtime_default))


def enable_diagnostics_capture(configuration: typing.Any) -> bool:
    """Persist diagnostics capture without creating a diagnostic database."""
    configuration.set(DIAGNOSTICS_CAPTURE_OPTION, True)
    configuration.save()
    return True


__all__ = [
    "DIAGNOSTICS_CAPTURE_OPTION",
    "diagnostics_capture_enabled",
    "enable_diagnostics_capture",
]

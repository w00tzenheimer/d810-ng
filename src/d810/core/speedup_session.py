"""Session-only Cython speedup policy and user-facing status."""

import dataclasses
import enum
import importlib

from .cymode import CythonMode


class SpeedupHeadline(str, enum.Enum):
    """The three supported speedup states shown in the D810 title."""

    ENABLED = "SPEEDUPS ENABLED"
    DISABLED = "SPEEDUPS DISABLED"
    UNAVAILABLE = "SPEEDUPS UNAVAILABLE"


@dataclasses.dataclass(frozen=True, slots=True)
class SpeedupAvailability:
    """Whether the compatible compiled speedup sentinel can be imported."""

    installed: bool
    detail: str = ""


def probe_speedup_availability(
    import_module=importlib.import_module,
) -> SpeedupAvailability:
    """Probe one ABI-compatible compiled module and retain failure details."""

    try:
        import_module("d810.speedups.c_simd")
    except (ImportError, ModuleNotFoundError, OSError) as exc:
        return SpeedupAvailability(False, f"{type(exc).__name__}: {exc}")
    return SpeedupAvailability(True)


def current_speedup_headline(
    availability: SpeedupAvailability,
    *,
    cython_allowed: bool,
) -> SpeedupHeadline:
    """Project capability and session policy into the title headline."""

    if not availability.installed:
        return SpeedupHeadline.UNAVAILABLE
    return (
        SpeedupHeadline.ENABLED
        if cython_allowed
        else SpeedupHeadline.DISABLED
    )


def speedup_title_suffix(headline: SpeedupHeadline) -> str:
    """Return the exact title suffix for a speedup headline."""

    return headline.value


def apply_session_cython_disabled(disabled: bool) -> bool:
    """Apply a session policy and report whether a full reload is needed."""

    mode = CythonMode()
    desired_enabled = not disabled
    changed = mode.is_enabled() != desired_enabled
    if desired_enabled:
        mode.enable()
    else:
        mode.disable()
    return changed


__all__ = [
    "SpeedupAvailability",
    "SpeedupHeadline",
    "apply_session_cython_disabled",
    "current_speedup_headline",
    "probe_speedup_availability",
    "speedup_title_suffix",
]

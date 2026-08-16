"""Session-only Cython speedup policy and user-facing status."""

import dataclasses
import enum
import importlib
import sys

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
    core_backends_active: bool | None = None,
) -> SpeedupHeadline:
    """Project capability, policy, and loaded backends into the headline.

    ``core_backends_active`` is optional for compatibility with the pure
    capability/policy projector.  UI callers pass the observed state of the
    AST and pattern-engine dispatchers so a pending policy change cannot
    replace the implementations that are active until the supported reload
    has completed.
    """

    if not availability.installed:
        return SpeedupHeadline.UNAVAILABLE
    if core_backends_active is True:
        return SpeedupHeadline.ENABLED
    if core_backends_active is False:
        return (
            SpeedupHeadline.DISABLED
            if not cython_allowed
            else SpeedupHeadline.UNAVAILABLE
        )
    return SpeedupHeadline.ENABLED if cython_allowed else SpeedupHeadline.DISABLED


def core_speedups_active(module_lookup=sys.modules.get) -> bool:
    """Return whether both core dispatchers are bound to Cython.

    The lookup intentionally observes already-loaded modules instead of
    importing them while the title is being rendered.  That makes the title
    describe the last completed load rather than causing a new binding as a
    side effect of opening the dock.
    """

    ast_dispatcher = module_lookup("d810.hexrays.expr.ast")
    pattern_dispatcher = module_lookup(
        "d810.optimizers.microcode.instructions.pattern_matching.engine"
    )
    if ast_dispatcher is None or pattern_dispatcher is None:
        return False
    if not bool(getattr(ast_dispatcher, "_USING_CYTHON", False)):
        return False
    try:
        return pattern_dispatcher.get_engine_info().get("backend") == "cython"
    except Exception:  # noqa: BLE001 - status must fail closed during reloads
        return False


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
    "core_speedups_active",
    "current_speedup_headline",
    "probe_speedup_availability",
    "speedup_title_suffix",
]

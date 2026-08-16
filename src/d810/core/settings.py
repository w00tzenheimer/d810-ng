"""Centralized runtime settings for D810.

Replaces scattered ``os.environ.get("D810_*")`` calls with a single
``D810Settings`` dataclass.  The singleton is lazily created on first
``get_settings()`` call, seeded from environment variables, and can be
overridden at runtime via ``configure_settings(**overrides)``.

Phase 1 covers diagnostic env vars and the developer runtime controls. Later
phases will migrate the remaining ~25 env vars here.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, fields

from d810.core.maturity_labels import MaturityNumbering, mmat_value


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name, "")
    if not raw:
        return default
    return raw.lower() not in {"0", "false", "off", "no"}


def _env_str(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _execution_callback_detail(value: object, *, source: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{source} must be 'summary' or 'full'")
    normalized = value.strip().lower()
    if normalized not in {"summary", "full"}:
        raise ValueError(f"{source} must be 'summary' or 'full', got {value!r}")
    return normalized


def _env_int(name: str, default: int | None = None) -> int | None:
    raw = os.environ.get(name, "")
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_maturity(name: str, default: int | None = None) -> int | None:
    """Parse a maturity env var that accepts either an int or a symbolic name.

    Returns ``default`` only when the var is unset or empty.  An unparseable
    value (neither int nor known name) raises ``ValueError`` so the
    misconfiguration surfaces at startup instead of silently disabling the
    diagnostic that depends on it.
    """
    raw = os.environ.get(name, "")
    if not raw:
        return default
    parsed = mmat_value(raw, numbering=MaturityNumbering.IDA)
    if parsed is not None:
        return parsed
    raise ValueError(
        f"{name}={raw!r} is not an integer and not a known maturity name "
        "(expected one of: GENERATED, PREOPTIMIZED, LOCOPT, CALLS, "
        "GLBOPT1, GLBOPT2, GLBOPT3, LVARS)"
    )


_RUNTIME_SETTING_ENVIRONMENT = {
    "debug_logging": "D810_DEBUG_LOGGING",
    "verify_capture": "D810_VERIFY_CAPTURE",
    "verify_capture_dir": "D810_VERIFY_CAPTURE_DIR",
    "capture_post_maturity": "D810_CAPTURE_POST_MATURITY",
    "capture_post_file": "D810_CAPTURE_POST_FILE",
    "fact_lifecycle": "D810_FACT_LIFECYCLE",
    "trace_decompile_callers": "D810_TRACE_DECOMPILE_CALLERS",
    "native_perf": "D810_NATIVE_PERF",
    "nomut_matching": "D810_NOMUT_MATCHING",
}


def apply_saved_runtime_settings(
    config: object,
    *,
    environ: Mapping[str, str] | None = None,
) -> None:
    """Apply saved runtime settings while preserving explicit env precedence.

    ``D810State.reset()`` calls this narrow boundary after loading
    ``options.json``.  Keeping the preference merge independent of manager
    construction makes its precedence behavior directly testable.
    """
    config_get = getattr(config, "get", None)
    if not callable(config_get):
        raise TypeError("runtime settings config must provide get()")

    environment = os.environ if environ is None else environ
    missing = object()
    overrides = {}
    for setting_name, environment_name in _RUNTIME_SETTING_ENVIRONMENT.items():
        if environment_name in environment:
            continue
        saved_value = config_get(setting_name, missing)
        if saved_value is not missing:
            overrides[setting_name] = saved_value
    apply_runtime_settings(overrides, environ=environment)


def apply_runtime_settings(
    overrides: Mapping[str, object],
    *,
    environ: Mapping[str, str] | None = None,
) -> None:
    """Apply runtime overrides without letting explicit env values be replaced.

    The settings dialog uses this boundary for immediate checkbox changes;
    startup preference loading uses it for the same precedence semantics.
    Callers may still persist the requested values separately so they become
    effective when the corresponding environment override is later removed.
    """
    environment = os.environ if environ is None else environ
    effective_overrides = {}
    for setting_name, setting_value in overrides.items():
        environment_name = _RUNTIME_SETTING_ENVIRONMENT.get(setting_name)
        if environment_name is not None and environment_name in environment:
            continue
        effective_overrides[setting_name] = setting_value
    if effective_overrides:
        configure_settings(**effective_overrides)


@dataclass
class D810Settings:
    """Flat bag of every D810 runtime toggle.

    Constructed from env vars by ``_from_env()``.  Fields are grouped by
    phase; diagnostic fields and developer runtime controls are wired up.
    """

    # -- Phase 1: Diagnostics --
    diag_snapshots: bool = False
    """Enable SQLite diagnostic snapshots (D810_DIAG_SNAPSHOT)."""

    debug_logging: bool = False
    """Promote default log level to DEBUG (D810_DEBUG_LOGGING)."""

    verify_capture: bool = True
    """Persist CFG verification failure artifacts (D810_VERIFY_CAPTURE)."""

    verify_capture_dir: str = ""
    """Directory for verification captures (D810_VERIFY_CAPTURE_DIR).
    Empty string means use the default (~/.idapro/logs/d810_logs/verify_failures).
    """

    capture_post_maturity: int | None = None
    """Maturity level at which to dump post-D810 MBA (D810_CAPTURE_POST_MATURITY)."""

    capture_post_file: str = "/tmp/d810_capture.txt"
    """File path for post-maturity MBA capture (D810_CAPTURE_POST_FILE)."""

    fact_lifecycle: bool = True
    """Enable maturity fact lifecycle capture hooks (D810_FACT_LIFECYCLE=0 disables)."""

    trace_decompile_callers: bool = False
    """Log a Python stack for every top-level decompilation (D810_TRACE_DECOMPILE_CALLERS).

    Answers "who asked for this decompilation?" when the same function is
    decompiled more than once for a single user action. ``hxe_prolog`` fires
    once per microcode-generation pass, so the stack captured there names the
    requester. Off by default: capturing a stack on every decompilation is
    pure overhead once the question is answered.
    """

    execution_callback_detail: str = "summary"
    """Callback provenance retention (`D810_EXECUTION_CALLBACK_DETAIL`).

    ``summary`` aggregates no-op callbacks per decompilation session while
    retaining exact mutations and failures. ``full`` persists every callback.
    """

    # -- Developer runtime controls --
    native_perf: bool = False
    """Emit native performance receipts (D810_NATIVE_PERF)."""

    nomut_matching: bool = False
    """Use non-mutating pattern matching (D810_NOMUT_MATCHING)."""

    @classmethod
    def _from_env(cls) -> D810Settings:
        return cls(
            diag_snapshots=_env_bool("D810_DIAG_SNAPSHOT"),
            debug_logging=_env_bool("D810_DEBUG_LOGGING"),
            verify_capture=_env_bool("D810_VERIFY_CAPTURE", default=True),
            verify_capture_dir=_env_str(
                "D810_VERIFY_CAPTURE_DIR",
                os.path.expanduser("~/.idapro/logs/d810_logs/verify_failures"),
            ),
            capture_post_maturity=_env_maturity("D810_CAPTURE_POST_MATURITY"),
            capture_post_file=_env_str(
                "D810_CAPTURE_POST_FILE", "/tmp/d810_capture.txt"
            ),
            fact_lifecycle=_env_bool("D810_FACT_LIFECYCLE", default=True),
            trace_decompile_callers=_env_bool("D810_TRACE_DECOMPILE_CALLERS"),
            execution_callback_detail=_execution_callback_detail(
                _env_str("D810_EXECUTION_CALLBACK_DETAIL", "summary"),
                source="D810_EXECUTION_CALLBACK_DETAIL",
            ),
            native_perf=_env_bool("D810_NATIVE_PERF"),
            nomut_matching=_env_bool("D810_NOMUT_MATCHING"),
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_settings: D810Settings | None = None


def get_settings() -> D810Settings:
    """Return the global settings singleton, creating from env if needed."""
    global _settings
    if _settings is None:
        _settings = D810Settings._from_env()
    return _settings


def configure_settings(**overrides: object) -> D810Settings:
    """Override specific settings fields.  Creates from env first if needed."""
    s = get_settings()
    valid = {f.name for f in fields(D810Settings)}
    for k, v in overrides.items():
        if k not in valid:
            raise ValueError(f"Unknown D810Settings field: {k!r}")
        if k == "execution_callback_detail":
            v = _execution_callback_detail(v, source=k)
        setattr(s, k, v)
    return s


def reset_settings() -> D810Settings:
    """Re-read all settings from current environment.  Useful in tests."""
    global _settings
    _settings = D810Settings._from_env()
    return _settings

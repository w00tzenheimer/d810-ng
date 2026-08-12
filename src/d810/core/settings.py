"""Centralized runtime settings for D810.

Replaces scattered ``os.environ.get("D810_*")`` calls with a single
``D810Settings`` dataclass.  The singleton is lazily created on first
``get_settings()`` call, seeded from environment variables, and can be
overridden at runtime via ``configure_settings(**overrides)``.

Phase 1 covers 6 diagnostic env vars.  Later phases will migrate the
remaining ~25 env vars here.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, fields

from d810.core.maturity_labels import MaturityNumbering, mmat_value


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name, "")
    if not raw:
        return default
    return raw.lower() not in {"0", "false", "off", "no"}


def _env_str(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


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


@dataclass
class D810Settings:
    """Flat bag of every D810 runtime toggle.

    Constructed from env vars by ``_from_env()``.  Fields are grouped by
    phase — only Phase 1 (diagnostics) is wired up initially.
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

    allow_attested_input_identity_recovery: bool = False
    """Allow recovery of a matching IDB-local input identity attestation.

    Disabled by default.  It never authorizes SHA-bound external evidence
    until the current input file is present and freshly hashes to the
    attested SHA-256.
    """

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
            allow_attested_input_identity_recovery=_env_bool(
                "D810_ALLOW_ATTESTED_INPUT_IDENTITY_RECOVERY"
            ),
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
        setattr(s, k, v)
    return s


def reset_settings() -> D810Settings:
    """Re-read all settings from current environment.  Useful in tests."""
    global _settings
    _settings = D810Settings._from_env()
    return _settings

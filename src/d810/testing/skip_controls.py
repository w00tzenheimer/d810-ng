"""Central controls for skipping vs unskipping system test cases.

These helpers let local researchers opt into running tests that are normally
skipped due to known instability or missing expectations.
"""

from __future__ import annotations

import os


_TRUTHY = {"1", "true", "yes", "on"}
_DANGEROUS_SKIP_KEYWORDS = (
    "segfault",
    "hang",
    "infinite loop",
    "interr",
    "native bug",
)


def _env_flag(name: str) -> bool:
    value = os.environ.get(name, "")
    return value.strip().lower() in _TRUTHY


def unskip_cases_enabled() -> bool:
    """Return True if normal per-case skips should be bypassed."""
    return _env_flag("D810_UNSKIP_CASES")


def unskip_dangerous_enabled() -> bool:
    """Return True if known dangerous cases (hang/segfault) may run."""
    return _env_flag("D810_UNSKIP_DANGEROUS")


def is_dangerous_skip_reason(reason: str | None) -> bool:
    """Return True when a skip reason indicates crash/hang risk."""
    if not reason:
        return False
    lowered = reason.lower()
    return any(keyword in lowered for keyword in _DANGEROUS_SKIP_KEYWORDS)


def should_skip_reason(reason: str | None) -> bool:
    """Return True when a case should still be skipped in this environment."""
    if not reason:
        return False
    if not unskip_cases_enabled():
        return True
    if is_dangerous_skip_reason(reason) and not unskip_dangerous_enabled():
        return True
    return False


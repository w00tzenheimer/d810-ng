"""Dependency-free helpers for provider maturity compatibility labels.

Portable scheduling should use :mod:`d810.ir.maturity`.  This module is only
for boundary compatibility: parsing, ranking, and formatting persisted/provider
``MMAT_*`` spellings without importing Hex-Rays or IDA.
"""

from __future__ import annotations

from enum import Enum
from types import MappingProxyType

from d810.core.typing import Any, Mapping


class MaturityNumbering(str, Enum):
    """Numeric scheme used by a maturity label boundary."""

    IDA = "ida"
    WITH_ZERO = "with_zero"


IDA_MATURITY_NAMES = (
    "MMAT_GENERATED",
    "MMAT_PREOPTIMIZED",
    "MMAT_LOCOPT",
    "MMAT_CALLS",
    "MMAT_GLBOPT1",
    "MMAT_GLBOPT2",
    "MMAT_GLBOPT3",
    "MMAT_LVARS",
)
WITH_ZERO_MATURITY_NAMES = ("MMAT_ZERO",) + IDA_MATURITY_NAMES

IDA_MMAT_GENERATED = 0
IDA_MMAT_PREOPTIMIZED = 1
IDA_MMAT_LOCOPT = 2
IDA_MMAT_CALLS = 3
IDA_MMAT_GLBOPT1 = 4
IDA_MMAT_GLBOPT2 = 5
IDA_MMAT_GLBOPT3 = 6
IDA_MMAT_LVARS = 7

WITH_ZERO_MMAT_ZERO = 0
WITH_ZERO_MMAT_GENERATED = 1
WITH_ZERO_MMAT_PREOPTIMIZED = 2
WITH_ZERO_MMAT_LOCOPT = 3
WITH_ZERO_MMAT_CALLS = 4
WITH_ZERO_MMAT_GLBOPT1 = 5
WITH_ZERO_MMAT_GLBOPT2 = 6
WITH_ZERO_MMAT_GLBOPT3 = 7
WITH_ZERO_MMAT_LVARS = 8

EARLY_FACT_COLLECTION_MATURITIES = frozenset(
    {
        WITH_ZERO_MMAT_PREOPTIMIZED,
        WITH_ZERO_MMAT_LOCOPT,
        WITH_ZERO_MMAT_CALLS,
        WITH_ZERO_MMAT_GLBOPT1,
    }
)
LOCAL_FACT_COLLECTION_MATURITIES = frozenset(
    {
        WITH_ZERO_MMAT_PREOPTIMIZED,
        WITH_ZERO_MMAT_LOCOPT,
    }
)

_NAMES_BY_NUMBERING: Mapping[MaturityNumbering, tuple[str, ...]] = MappingProxyType(
    {
        MaturityNumbering.IDA: IDA_MATURITY_NAMES,
        MaturityNumbering.WITH_ZERO: WITH_ZERO_MATURITY_NAMES,
    }
)
_VALUE_BY_NAME: Mapping[MaturityNumbering, Mapping[str, int]] = MappingProxyType(
    {
        numbering: MappingProxyType(
            {name: index for index, name in enumerate(names)}
            | {name.removeprefix("MMAT_"): index for index, name in enumerate(names)}
        )
        for numbering, names in _NAMES_BY_NUMBERING.items()
    }
)
IDA_MATURITY_VALUES: Mapping[str, int] = MappingProxyType(
    {name: index for index, name in enumerate(IDA_MATURITY_NAMES)}
)
# Provider label owned at the core compatibility boundary. Portable pipeline
# assembly refers to this policy name rather than embedding an MMAT spelling.
POST_STATE_MACHINE_FCP_MATURITIES = (
    IDA_MATURITY_NAMES[IDA_MMAT_GLBOPT2],
)
WITH_ZERO_MATURITY_VALUES: Mapping[str, int] = MappingProxyType(
    {name: index for index, name in enumerate(WITH_ZERO_MATURITY_NAMES)}
)
_TIMELINE_PHASE_RANKS: Mapping[tuple[str, str], int] = MappingProxyType(
    {
        ("MMAT_LOCOPT", "pre_d810"): 0,
        ("MMAT_LOCOPT", "post_d810"): 1,
        ("MMAT_CALLS", "pre_d810"): 2,
        ("MMAT_CALLS", "post_d810"): 3,
        ("MMAT_GLBOPT1", "pre_d810"): 4,
        ("MMAT_GLBOPT1", "post_apply"): 5,
        ("MMAT_GLBOPT1", "post_gut_wire"): 6,
        ("MMAT_GLBOPT1", "post_pipeline"): 7,
        ("MMAT_GLBOPT1", "post_d810"): 8,
        ("MMAT_GLBOPT2", "pre_d810"): 9,
        ("MMAT_GLBOPT2", "post_apply"): 10,
        ("MMAT_GLBOPT2", "post_d810"): 11,
        ("MMAT_GLBOPT3", "pre_d810"): 12,
        ("MMAT_GLBOPT3", "post_d810"): 13,
        ("MMAT_LVARS", "pre_d810"): 14,
        ("MMAT_LVARS", "post_d810"): 15,
    }
)


def _names(numbering: MaturityNumbering) -> tuple[str, ...]:
    return _NAMES_BY_NUMBERING[MaturityNumbering(numbering)]


def mmat_name(
    value: int,
    *,
    numbering: MaturityNumbering = MaturityNumbering.IDA,
) -> str:
    """Return a provider ``MMAT_*`` name for ``value`` in ``numbering``."""
    value_int = int(value)
    names = _names(numbering)
    if 0 <= value_int < len(names):
        return names[value_int]
    return f"MMAT_{value_int}"


def numeric_mmat_name(value: int) -> str:
    """Return the legacy numeric provider ``MMAT_<n>`` label."""

    return f"MMAT_{int(value)}"


def mmat_value(
    value: Any,
    *,
    numbering: MaturityNumbering = MaturityNumbering.IDA,
) -> int | None:
    """Parse an integer, short name, ``MMAT_*`` name, or numeric ``MMAT_N``."""
    if value is None:
        return None
    try:
        if not isinstance(value, str):
            return int(value)
    except Exception:
        return None

    text = value.strip().upper()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        pass

    lookup = _VALUE_BY_NAME[MaturityNumbering(numbering)]
    if text in lookup:
        return lookup[text]
    if not text.startswith("MMAT_"):
        prefixed = f"MMAT_{text}"
        if prefixed in lookup:
            return lookup[prefixed]
    if text.startswith("MMAT_"):
        suffix = text.removeprefix("MMAT_")
        if suffix.lstrip("-").isdigit():
            return int(suffix)
    return None


def normalize_mmat_name(
    value: Any,
    *,
    numbering: MaturityNumbering = MaturityNumbering.IDA,
) -> str | None:
    """Normalize known maturity spellings to canonical ``MMAT_*`` names."""
    parsed = mmat_value(value, numbering=numbering)
    if parsed is not None:
        return mmat_name(parsed, numbering=numbering)
    if isinstance(value, str):
        text = value.strip().upper()
        if text.startswith("MMAT_"):
            return text
        if text:
            return f"MMAT_{text}"
    return None


def mmat_rank(
    value: Any,
    *,
    numbering: MaturityNumbering = MaturityNumbering.IDA,
    default: int = 99,
) -> int:
    """Return a stable rank for sorting provider maturity labels."""
    parsed = mmat_value(value, numbering=numbering)
    if parsed is None:
        return int(default)
    return int(parsed)


def mmat_label(
    value: Any,
    *,
    numbering: MaturityNumbering = MaturityNumbering.IDA,
) -> str:
    """Format ``maturity=<name>`` while preserving unknown string spellings."""
    if value is None:
        return "maturity=?"
    if isinstance(value, str):
        normalized = normalize_mmat_name(value, numbering=numbering)
        return f"maturity={normalized or value}"
    try:
        return f"maturity={mmat_name(int(value), numbering=numbering)}"
    except Exception:
        return "maturity=?"


def maturity_phase_rank(maturity: Any, phase: Any, *, default: int = 99) -> int:
    """Rank persisted maturity/phase snapshots on the diagnostic timeline."""
    name = normalize_mmat_name(maturity, numbering=MaturityNumbering.IDA)
    if name is None:
        return int(default)
    return _TIMELINE_PHASE_RANKS.get((name, str(phase)), int(default))


def is_glbopt1_post_d810(maturity: Any, phase: Any) -> bool:
    """Return true for the GLBOPT1 post-D810 diagnostic snapshot boundary."""
    return (
        maturity_phase_rank(maturity, phase)
        == _TIMELINE_PHASE_RANKS[("MMAT_GLBOPT1", "post_d810")]
    )


__all__ = [
    "EARLY_FACT_COLLECTION_MATURITIES",
    "IDA_MATURITY_NAMES",
    "IDA_MMAT_CALLS",
    "IDA_MMAT_GENERATED",
    "IDA_MMAT_GLBOPT1",
    "IDA_MMAT_GLBOPT2",
    "IDA_MMAT_GLBOPT3",
    "IDA_MMAT_LVARS",
    "IDA_MMAT_LOCOPT",
    "IDA_MMAT_PREOPTIMIZED",
    "IDA_MATURITY_VALUES",
    "LOCAL_FACT_COLLECTION_MATURITIES",
    "MaturityNumbering",
    "POST_STATE_MACHINE_FCP_MATURITIES",
    "WITH_ZERO_MATURITY_NAMES",
    "WITH_ZERO_MATURITY_VALUES",
    "WITH_ZERO_MMAT_CALLS",
    "WITH_ZERO_MMAT_GENERATED",
    "WITH_ZERO_MMAT_GLBOPT1",
    "WITH_ZERO_MMAT_GLBOPT2",
    "WITH_ZERO_MMAT_GLBOPT3",
    "WITH_ZERO_MMAT_LVARS",
    "WITH_ZERO_MMAT_LOCOPT",
    "WITH_ZERO_MMAT_PREOPTIMIZED",
    "WITH_ZERO_MMAT_ZERO",
    "is_glbopt1_post_d810",
    "maturity_phase_rank",
    "mmat_label",
    "mmat_name",
    "numeric_mmat_name",
    "mmat_rank",
    "mmat_value",
    "normalize_mmat_name",
]

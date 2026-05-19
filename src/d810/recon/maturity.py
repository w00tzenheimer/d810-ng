"""Friendly maturity labels for recon logs.

This module keeps recon free of module-level Hex-Rays imports.  In IDA
runtimes it resolves names from ``ida_hexrays``; outside IDA it falls back to
stable prefixed labels so logs never contain bare numeric maturity values.
"""
from __future__ import annotations

_MICROCODE_MATURITY_NAMES = (
    "MMAT_ZERO",
    "MMAT_GENERATED",
    "MMAT_PREOPTIMIZED",
    "MMAT_LOCOPT",
    "MMAT_CALLS",
    "MMAT_GLBOPT1",
    "MMAT_GLBOPT2",
    "MMAT_GLBOPT3",
    "MMAT_LVARS",
)

_CTREE_MATURITY_NAMES = (
    "CMAT_ZERO",
    "CMAT_BUILT",
    "CMAT_TRANS1",
    "CMAT_NICE",
    "CMAT_TRANS2",
    "CMAT_CPA",
    "CMAT_TRANS3",
    "CMAT_CASTED",
    "CMAT_FINAL",
)

_CTREE_MATURITY_FALLBACKS = {
    0: "CMAT_ZERO",
    1: "CMAT_BUILT",
    2: "CMAT_TRANS1",
    3: "CMAT_NICE",
    4: "CMAT_TRANS2",
    5: "CMAT_CPA",
    6: "CMAT_TRANS3",
    7: "CMAT_CASTED",
    8: "CMAT_FINAL",
    60: "CMAT_FINAL",
}


def _hexrays_maturity_name(maturity: int, names: tuple[str, ...]) -> str | None:
    try:
        import ida_hexrays  # type: ignore
    except Exception:
        return None

    maturity_value = int(maturity)
    for name in names:
        try:
            if int(getattr(ida_hexrays, name)) == maturity_value:
                return name
        except Exception:
            continue
    return None


def microcode_maturity_text(maturity: int) -> str:
    """Return a friendly ``MMAT_*`` label for a microcode maturity."""
    maturity_name = _hexrays_maturity_name(maturity, _MICROCODE_MATURITY_NAMES)
    if maturity_name is not None:
        return maturity_name
    return f"MMAT_{int(maturity)}"


def ctree_maturity_text(maturity: int) -> str:
    """Return a friendly ``CMAT_*`` label for a ctree maturity."""
    maturity_value = int(maturity)
    maturity_name = _hexrays_maturity_name(maturity_value, _CTREE_MATURITY_NAMES)
    if maturity_name is not None:
        return maturity_name
    return _CTREE_MATURITY_FALLBACKS.get(maturity_value, f"CMAT_{maturity_value}")

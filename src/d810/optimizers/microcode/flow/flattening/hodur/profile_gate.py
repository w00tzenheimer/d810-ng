"""Hodur profile admission gates for live strategy entrypoints.

The ``HodurProfileGateBackend`` Protocol's canonical home is
``d810.capabilities.profile_gate`` (slice 4b of the
llvm-lisa-restructure plan).  This module keeps the symbol importable
from the old path for back-compat with the in-file
``DEFAULT_HODUR_PROFILE_GATE`` annotation and the
``accepts_exact_sub7ffd_glbopt1`` parameter default.  New code should
import from the canonical location.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Canonical home for HodurProfileGateBackend; re-exported below for back-compat.
from d810.capabilities.profile_gate import HodurProfileGateBackend
from d810.core.typing import Mapping


def _default_maturity_name_to_int() -> dict[str, int]:
    try:
        import ida_hexrays

        glbopt1 = int(ida_hexrays.MMAT_GLBOPT1)
    except Exception:
        glbopt1 = 4
    return {
        "global_opt_1": glbopt1,
        "glbopt1": glbopt1,
        "MMAT_GLBOPT1": glbopt1,
        "GLBOPT1": glbopt1,
    }


@dataclass(frozen=True, slots=True)
class AttributeHodurProfileGate:
    """Attribute-based gate for Hex-Rays-like live function objects.

    The default mapping is deliberately name based so strategy modules do not
    import or inspect Hex-Rays maturity constants directly.
    """

    maturity_name_to_int: Mapping[str, int] = field(
        default_factory=_default_maturity_name_to_int
    )

    def accepts_function(
        self,
        live_function: object | None,
        *,
        expected_entry_ea: int,
        required_maturity: str,
    ) -> bool:
        if live_function is None:
            return False
        expected_maturity = self.maturity_name_to_int.get(str(required_maturity))
        if expected_maturity is None:
            return False
        try:
            entry_ea = int(getattr(live_function, "entry_ea", 0))
            maturity = int(getattr(live_function, "maturity", -1))
        except Exception:
            return False
        return (
            entry_ea == int(expected_entry_ea)
            and maturity == int(expected_maturity)
        )


DEFAULT_HODUR_PROFILE_GATE: HodurProfileGateBackend = AttributeHodurProfileGate()


def accepts_exact_sub7ffd_glbopt1(
    snapshot: object,
    *,
    expected_entry_ea: int,
    gate: HodurProfileGateBackend = DEFAULT_HODUR_PROFILE_GATE,
) -> bool:
    """Return True when ``snapshot`` matches the exact-node sub7FFD gate."""

    return gate.accepts_function(
        getattr(snapshot, "mba", None),
        expected_entry_ea=int(expected_entry_ea),
        required_maturity="global_opt_1",
    )

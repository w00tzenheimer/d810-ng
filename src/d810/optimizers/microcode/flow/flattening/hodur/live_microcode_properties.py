"""Hodur live microcode property normalization."""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.typing import Mapping, Protocol


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


def _default_block_type_name_to_int() -> dict[str, int]:
    try:
        import ida_hexrays

        two_way = int(ida_hexrays.BLT_2WAY)
    except Exception:
        two_way = -1
    return {
        "two_way": two_way,
        "BLT_2WAY": two_way,
    }


class HodurLiveMicrocodePropertiesBackend(Protocol):
    """Backend boundary for live Hex-Rays constants used by Hodur policy."""

    def has_maturity(
        self,
        live_function: object | None,
        required_maturity: str,
    ) -> bool:
        """Return True when ``live_function`` has the named maturity."""

    def is_two_way_block_type(self, block_type: object | None) -> bool:
        """Return True when ``block_type`` is a live two-way block type."""


@dataclass(frozen=True, slots=True)
class AttributeHodurLiveMicrocodeProperties:
    """Attribute-based Hex-Rays property normalizer."""

    maturity_name_to_int: Mapping[str, int] = field(
        default_factory=_default_maturity_name_to_int
    )
    block_type_name_to_int: Mapping[str, int] = field(
        default_factory=_default_block_type_name_to_int
    )

    def has_maturity(
        self,
        live_function: object | None,
        required_maturity: str,
    ) -> bool:
        if live_function is None:
            return False
        expected = self.maturity_name_to_int.get(str(required_maturity))
        if expected is None:
            return False
        try:
            observed = int(getattr(live_function, "maturity", -1))
        except Exception:
            return False
        return observed == int(expected)

    def is_two_way_block_type(self, block_type: object | None) -> bool:
        expected = self.block_type_name_to_int.get("two_way")
        if expected is None or int(expected) < 0:
            return False
        try:
            return int(block_type) == int(expected)
        except Exception:
            return False


DEFAULT_HODUR_LIVE_MICROCODE_PROPERTIES: HodurLiveMicrocodePropertiesBackend = (
    AttributeHodurLiveMicrocodeProperties()
)


__all__ = [
    "AttributeHodurLiveMicrocodeProperties",
    "DEFAULT_HODUR_LIVE_MICROCODE_PROPERTIES",
    "HodurLiveMicrocodePropertiesBackend",
]

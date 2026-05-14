"""Hex-Rays definition rescue evidence adapter."""
from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.core.typing import Protocol
from d810.evaluator.hexrays_microcode.chains import find_reaching_defs_for_stkvar
from d810.evaluator.hexrays_microcode.sccp import run_sccp


@dataclass(frozen=True, slots=True)
class DefinitionSiteEvidence:
    """Neutral reaching-definition site evidence."""

    block_serial: int
    insn_ea: int | None = None


class DefinitionRescueBackend(Protocol):
    """Backend boundary for reaching-def and SCCP rescue evidence."""

    def reaching_defs_for_stkvar(
        self,
        mba: object,
        block_serial: int,
        stkoff: int,
        size: int,
    ) -> tuple[DefinitionSiteEvidence, ...]:
        """Return reaching definitions for a stack variable at a block."""

    def run_sccp_overlay(self, mba: object) -> object:
        """Return backend-owned SCCP overlay data."""

    def lookup_sccp_stkvar(
        self,
        overlay: object,
        *,
        stkoff: int,
        size: int,
    ) -> object | None:
        """Return an SCCP overlay value for a stack variable."""


class HexRaysDefinitionRescueBackend:
    """Collect definition-rescue evidence from Hex-Rays microcode."""

    def reaching_defs_for_stkvar(
        self,
        mba: object,
        block_serial: int,
        stkoff: int,
        size: int,
    ) -> tuple[DefinitionSiteEvidence, ...]:
        try:
            sites = find_reaching_defs_for_stkvar(
                mba,
                int(block_serial),
                int(stkoff),
                int(size),
            )
        except Exception:
            return ()
        evidence: list[DefinitionSiteEvidence] = []
        for site in sites:
            try:
                serial = int(getattr(site, "block_serial"))
            except Exception:
                continue
            insn_ea = _optional_int(
                getattr(site, "insn_ea", getattr(site, "ins_ea", None))
            )
            evidence.append(
                DefinitionSiteEvidence(
                    block_serial=serial,
                    insn_ea=insn_ea,
                )
            )
        return tuple(evidence)

    def run_sccp_overlay(self, mba: object) -> object:
        return run_sccp(mba)

    def lookup_sccp_stkvar(
        self,
        overlay: object,
        *,
        stkoff: int,
        size: int,
    ) -> object | None:
        getter = getattr(overlay, "get", None)
        if getter is None:
            return None
        return getter((ida_hexrays.mop_S, int(size), int(stkoff)))


def _optional_int(value: object | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


__all__ = [
    "DefinitionRescueBackend",
    "DefinitionSiteEvidence",
    "HexRaysDefinitionRescueBackend",
]

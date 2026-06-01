"""Hodur Hex-Rays residual handoff evidence adapters."""
from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import ida_hexrays

from d810.ir.state_variable import StateVariableRef
from d810.core.typing import Protocol
from d810.analyses.control_flow.residual_handoff_discovery import (
    supplemental_selected_entry_for_state,
)
from d810.backends.hexrays.evidence.residual_handoff_resolution import (
    resolve_effective_target_entry as resolve_live_effective_target_entry,
    resolve_singleton_state_write_value,
)


@dataclass(frozen=True, slots=True)
class EffectiveTargetEvidence:
    """Resolved live effective-target entry for a state transition."""

    source_block: int | None
    target_state: int | None
    target_entry: int | None
    reason: str


@dataclass(frozen=True, slots=True)
class ResidualStateWriteEvidence:
    """Resolved singleton dispatcher-state write for a residual predecessor."""

    block_serial: int
    state_value: int
    reason: str


@dataclass(frozen=True, slots=True)
class ResidualEffectiveTargetEvidence:
    """Resolved effective target entry for a residual frontier handoff."""

    source_block: int
    state_value: int
    target_entry: int | None
    reason: str


class EffectiveTargetEvidenceBackend(Protocol):
    """Backend boundary for live effective-target resolution."""

    def resolve_effective_target_entry(
        self,
        dag: object,
        edge: object,
        *,
        bst_node_blocks: set[int] | frozenset[int],
        state_variable: StateVariableRef | None,
        dispatcher_lookup: object | None,
        dispatcher: object | None,
        mba: object | None,
    ) -> EffectiveTargetEvidence:
        """Resolve a transition target using backend-owned live evidence."""


class ResidualFrontierEvidenceBackend(Protocol):
    """Backend boundary for live residual frontier evidence."""

    def resolve_state_variable(
        self,
        *,
        state_machine: object | None,
    ) -> StateVariableRef | None:
        """Return the dispatcher state-variable identity, if available."""

    def resolve_singleton_state_write(
        self,
        mba: object,
        block_serial: int,
        *,
        state_variable: StateVariableRef,
    ) -> ResidualStateWriteEvidence | None:
        """Resolve the singleton state write for a residual predecessor."""

    def resolve_residual_effective_target(
        self,
        dag: object,
        *,
        pred_serial: int,
        state_value: int,
        dispatcher_model: object | None,
        bst_node_blocks: set[int] | frozenset[int],
        state_variable: StateVariableRef | None,
        mba: object | None,
    ) -> ResidualEffectiveTargetEvidence:
        """Resolve the live effective target for a residual handoff."""


class HexRaysEffectiveTargetEvidenceBackend:
    """Resolve effective transition targets with Hex-Rays-backed evidence."""

    def resolve_effective_target_entry(
        self,
        dag: object,
        edge: object,
        *,
        bst_node_blocks: set[int] | frozenset[int],
        state_variable: StateVariableRef | None,
        dispatcher_lookup: object | None,
        dispatcher: object | None,
        mba: object | None,
    ) -> EffectiveTargetEvidence:
        source_block = _edge_source_block(edge)
        target_state = _edge_target_state(edge)
        if state_variable is None or mba is None:
            return EffectiveTargetEvidence(
                source_block=source_block,
                target_state=target_state,
                target_entry=None,
                reason="missing_live_context",
            )

        target_entry = resolve_live_effective_target_entry(
            dag,
            edge,
            bst_node_blocks=set(int(block) for block in bst_node_blocks),
            state_var_stkoff=int(state_variable.stkoff),
            dispatcher_lookup=dispatcher_lookup,
            dispatcher=dispatcher,
            mba=mba,
        )
        return EffectiveTargetEvidence(
            source_block=source_block,
            target_state=target_state,
            target_entry=None if target_entry is None else int(target_entry),
            reason=(
                "effective_target_resolved"
                if target_entry is not None
                else "effective_target_unresolved"
            ),
        )


class HexRaysResidualFrontierEvidenceBackend:
    """Collect residual frontier evidence from live Hex-Rays microcode."""

    def resolve_state_variable(
        self,
        *,
        state_machine: object | None,
    ) -> StateVariableRef | None:
        if state_machine is None:
            return None
        state_var = getattr(state_machine, "state_var", None)
        if state_var is None or getattr(state_var, "t", None) != ida_hexrays.mop_S:
            return None
        state_ref = getattr(state_var, "s", None)
        if state_ref is None:
            return None
        try:
            stkoff = int(getattr(state_ref, "off"))
        except Exception:
            return None
        width = getattr(state_ref, "size", None)
        try:
            return StateVariableRef(
                stkoff=stkoff,
                width=4 if width is None else int(width),
            )
        except Exception:
            return StateVariableRef(stkoff=stkoff, width=4)

    def resolve_singleton_state_write(
        self,
        mba: object,
        block_serial: int,
        *,
        state_variable: StateVariableRef,
    ) -> ResidualStateWriteEvidence | None:
        state_value = resolve_singleton_state_write_value(
            mba,
            int(block_serial),
            state_var_stkoff=int(state_variable.stkoff),
        )
        if state_value is None:
            return None
        return ResidualStateWriteEvidence(
            block_serial=int(block_serial),
            state_value=int(state_value) & 0xFFFFFFFF,
            reason="singleton_state_write",
        )

    def resolve_residual_effective_target(
        self,
        dag: object,
        *,
        pred_serial: int,
        state_value: int,
        dispatcher_model: object | None,
        bst_node_blocks: set[int] | frozenset[int],
        state_variable: StateVariableRef | None,
        mba: object | None,
    ) -> ResidualEffectiveTargetEvidence:
        raw_state = int(state_value) & 0xFFFFFFFF
        if dispatcher_model is None or state_variable is None or mba is None:
            return ResidualEffectiveTargetEvidence(
                source_block=int(pred_serial),
                state_value=raw_state,
                target_entry=None,
                reason="missing_live_context",
            )

        synthetic_target_entry = supplemental_selected_entry_for_state(
            dag,
            raw_state,
        )
        synthetic_edge = SimpleNamespace(
            source_anchor=SimpleNamespace(
                block_serial=int(pred_serial),
                branch_arm=None,
            ),
            source_key=SimpleNamespace(state_const=None),
            target_key=None,
            target_state=raw_state,
            target_label=f"STATE_{raw_state:08X}",
            target_entry_anchor=synthetic_target_entry,
            ordered_path=(int(pred_serial),),
        )
        target_entry = resolve_live_effective_target_entry(
            dag,
            synthetic_edge,
            bst_node_blocks=set(int(block) for block in bst_node_blocks),
            state_var_stkoff=int(state_variable.stkoff),
            dispatcher_lookup=getattr(dispatcher_model, "lookup", None),
            dispatcher=dispatcher_model,
            mba=mba,
        )
        return ResidualEffectiveTargetEvidence(
            source_block=int(pred_serial),
            state_value=raw_state,
            target_entry=None if target_entry is None else int(target_entry),
            reason=(
                "effective_target_resolved"
                if target_entry is not None
                else "effective_target_unresolved"
            ),
        )


def _edge_source_block(edge: object) -> int | None:
    source_anchor = getattr(edge, "source_anchor", None)
    source_block = getattr(source_anchor, "block_serial", None)
    if source_block is None:
        return None
    try:
        return int(source_block)
    except Exception:
        return None


def _edge_target_state(edge: object) -> int | None:
    target_state = getattr(edge, "target_state", None)
    if target_state is None:
        return None
    try:
        return int(target_state) & 0xFFFFFFFF
    except Exception:
        return None


__all__ = [
    "EffectiveTargetEvidence",
    "EffectiveTargetEvidenceBackend",
    "HexRaysEffectiveTargetEvidenceBackend",
    "HexRaysResidualFrontierEvidenceBackend",
    "ResidualEffectiveTargetEvidence",
    "ResidualFrontierEvidenceBackend",
    "ResidualStateWriteEvidence",
    "StateVariableRef",
]

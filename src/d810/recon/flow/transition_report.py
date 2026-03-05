"""Canonical dispatcher transition report model and builder.

This module is the single source of truth for BST handler transition
classification used by both recon collectors and debug dump rendering.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Mapping, Optional, Tuple

from d810.recon.flow.bst_analysis import (
    _detect_state_var_stkoff,
    _dump_dispatcher_node,
    _find_pre_header_state,
    _walk_handler_chain,
)


class TransitionKind(Enum):
    """Semantic class for a handler transition row."""

    TRANSITION = auto()
    CONDITIONAL = auto()
    EXIT = auto()
    UNKNOWN = auto()


@dataclass(frozen=True)
class TransitionPath:
    """Detailed path diagnostics for one handler walk."""

    handler_serial: int
    chain: Tuple[int, ...]
    next_state: Optional[int]
    conditional_states: Tuple[int, ...]
    back_edge: bool
    reaches_exit_block: bool
    classified_exit: bool
    unresolved: bool


@dataclass(frozen=True)
class TransitionRow:
    """One transition row for rendering and recon metrics."""

    state_const: Optional[int]
    state_range_lo: Optional[int]
    state_range_hi: Optional[int]
    handler_serial: int
    kind: TransitionKind
    next_state: Optional[int]
    conditional_states: Tuple[int, ...]
    state_label: str
    transition_label: str
    chain_preview: Tuple[int, ...]
    path: TransitionPath


@dataclass(frozen=True)
class TransitionSummary:
    """Summary counters for the transition report."""

    handlers_total: int
    known_count: int
    conditional_count: int
    exit_count: int
    unknown_count: int


@dataclass(frozen=True)
class DispatcherTransitionReport:
    """Canonical transition report for one dispatcher root."""

    dispatcher_entry_serial: int
    state_var_stkoff: Optional[int]
    state_var_lvar_idx: Optional[int]
    pre_header_serial: Optional[int]
    initial_state: Optional[int]
    handler_state_map: Mapping[int, int]
    handler_range_map: Mapping[int, Tuple[Optional[int], Optional[int]]]
    bst_node_blocks: Tuple[int, ...]
    rows: Tuple[TransitionRow, ...]
    summary: TransitionSummary
    diagnostics: Tuple[str, ...]


def build_dispatcher_transition_report(
    mba: Any,
    dispatcher_entry_serial: int,
    *,
    state_var_stkoff: Optional[int] = None,
    state_var_lvar_idx: Optional[int] = None,
    max_bst_depth: int = 20,
    max_chain_depth: int = 64,
    transitions_hint_by_handler: Optional[dict[int, int]] = None,
    capture_diagnostics: bool = False,
    max_diag_handlers: int = 3,
    chain_preview_len: int = 4,
) -> DispatcherTransitionReport:
    """Build a canonical transition report for a BST dispatcher."""
    diagnostics: list[str] = [] if capture_diagnostics else []

    if state_var_stkoff is None:
        if capture_diagnostics:
            (detected, detected_lvar_idx), detect_diag = _detect_state_var_stkoff(
                mba, dispatcher_entry_serial, diag=True
            )
            diagnostics.extend(detect_diag)
        else:
            detected, detected_lvar_idx = _detect_state_var_stkoff(
                mba, dispatcher_entry_serial, diag=False
            )
        if detected is not None:
            state_var_stkoff = detected
            if state_var_lvar_idx is None:
                state_var_lvar_idx = detected_lvar_idx

    pre_header_serial, initial_state = _find_pre_header_state(
        mba,
        dispatcher_entry_serial,
        state_var_stkoff,
        diag_lines=diagnostics if capture_diagnostics else None,
        state_var_lvar_idx=state_var_lvar_idx,
    )

    handler_state_map: dict[int, int] = {}
    handler_serials: set[int] = set()
    handler_range_map: dict[int, tuple[Optional[int], Optional[int]]] = {}
    bst_node_blocks: set[int] = set()
    _dump_dispatcher_node(
        mba,
        dispatcher_entry_serial,
        indent=0,
        visited=set(),
        lines=[],
        depth=0,
        max_depth=max_bst_depth,
        value_lo=0,
        value_hi=0xFFFFFFFF,
        handler_state_map=handler_state_map,
        handler_serials=handler_serials,
        handler_range_map=handler_range_map,
        bst_node_blocks=bst_node_blocks,
    )

    rows_raw: list[tuple[Optional[int], int, dict[str, Any]]] = []
    diag_handlers = 0
    for h_serial in sorted(handler_serials):
        handler_diag: list[str] | None = None
        if capture_diagnostics and diag_handlers < max_diag_handlers:
            handler_diag = []
            diagnostics.append(
                f"Handler blk[{h_serial}] (state="
                f"{hex(handler_state_map.get(h_serial)) if handler_state_map.get(h_serial) is not None else '?'}):"
            )
            diag_handlers += 1

        if state_var_stkoff is not None:
            walk = _walk_handler_chain(
                mba,
                h_serial,
                dispatcher_entry_serial,
                state_var_stkoff,
                chain_visited=set(),
                max_chain_depth=max_chain_depth,
                diag_lines=handler_diag,
                state_var_lvar_idx=state_var_lvar_idx,
            )
        else:
            walk = {"next_state": None, "back_edge": False, "exit": False, "chain": []}

        if handler_diag is not None:
            diagnostics.extend(handler_diag)

        rows_raw.append((handler_state_map.get(h_serial), h_serial, walk))

    rows_raw.sort(key=lambda e: (e[0] is None, e[0] if e[0] is not None else 0))

    known_count = 0
    conditional_count = 0
    exit_count = 0
    unknown_count = 0
    rows: list[TransitionRow] = []

    for state_const, h_serial, walk in rows_raw:
        rng = handler_range_map.get(h_serial)
        range_lo = rng[0] if rng else None
        range_hi = rng[1] if rng else None
        if state_const is not None:
            state_label = f"State 0x{state_const:08x}"
        elif range_lo is not None and range_hi is not None:
            state_label = f"State range [0x{range_lo:x}..0x{range_hi:x}]"
        else:
            state_label = "State <unknown>"

        next_state = walk.get("next_state")
        if transitions_hint_by_handler is not None and next_state is None:
            hinted = transitions_hint_by_handler.get(h_serial)
            if hinted is not None:
                next_state = hinted

        conditional_states = tuple(sorted(walk.get("conditional_states", set())))
        is_exit = bool(walk.get("exit")) or (
            not bool(walk.get("back_edge")) and bool(walk.get("chain"))
        )

        if is_exit:
            kind = TransitionKind.EXIT
            transition_label = "RETURN (exit)"
            exit_count += 1
        elif bool(walk.get("back_edge")) and next_state is not None:
            kind = TransitionKind.TRANSITION
            transition_label = f"next=0x{next_state:08x} (back-edge)"
            known_count += 1
        elif conditional_states:
            kind = TransitionKind.CONDITIONAL
            cond_hex = ", ".join(f"0x{s:08x}" for s in conditional_states)
            transition_label = f"conditional transition -> {{{cond_hex}}}"
            conditional_count += 1
        elif bool(walk.get("back_edge")):
            kind = TransitionKind.UNKNOWN
            transition_label = "back-edge (next state unknown)"
            unknown_count += 1
        elif next_state is not None:
            kind = TransitionKind.TRANSITION
            transition_label = f"next=0x{next_state:08x}"
            known_count += 1
        else:
            kind = TransitionKind.UNKNOWN
            transition_label = "unknown"
            unknown_count += 1

        chain = tuple(walk.get("chain", ()))
        path = TransitionPath(
            handler_serial=h_serial,
            chain=chain,
            next_state=next_state,
            conditional_states=conditional_states,
            back_edge=bool(walk.get("back_edge")),
            reaches_exit_block=bool(walk.get("exit")),
            classified_exit=is_exit,
            unresolved=(kind == TransitionKind.UNKNOWN),
        )
        rows.append(
            TransitionRow(
                state_const=state_const,
                state_range_lo=range_lo,
                state_range_hi=range_hi,
                handler_serial=h_serial,
                kind=kind,
                next_state=next_state,
                conditional_states=conditional_states,
                state_label=state_label,
                transition_label=transition_label,
                chain_preview=chain[:chain_preview_len],
                path=path,
            )
        )

    summary = TransitionSummary(
        handlers_total=len(handler_serials),
        known_count=known_count,
        conditional_count=conditional_count,
        exit_count=exit_count,
        unknown_count=unknown_count,
    )

    return DispatcherTransitionReport(
        dispatcher_entry_serial=dispatcher_entry_serial,
        state_var_stkoff=state_var_stkoff,
        state_var_lvar_idx=state_var_lvar_idx,
        pre_header_serial=pre_header_serial,
        initial_state=initial_state,
        handler_state_map=handler_state_map,
        handler_range_map=handler_range_map,
        bst_node_blocks=tuple(sorted(bst_node_blocks)),
        rows=tuple(rows),
        summary=summary,
        diagnostics=tuple(diagnostics),
    )


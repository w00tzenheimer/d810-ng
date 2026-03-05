"""Handler transition collector and shared transition analysis helpers.

Extracts handler-chain walk results and transition labels from a BST
dispatcher state machine. Designed for reuse by both Recon collectors
and microcode dump diagnostics.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from d810.recon.models import CandidateFlag, ReconResult
from d810.recon.flow.bst_analysis import (
    _detect_state_var_stkoff,
    _dump_dispatcher_node,
    _walk_handler_chain,
)


@dataclass(frozen=True)
class HandlerTransitionEntry:
    """One analyzed handler transition entry."""

    state_const: int | None
    handler_serial: int
    state_label: str
    label: str
    next_state: int | None
    back_edge: bool
    is_exit: bool
    conditional_states: tuple[int, ...]
    chain: tuple[int, ...]


@dataclass(frozen=True)
class HandlerTransitionsReport:
    """Transition analysis result for all handlers under one dispatcher."""

    entries: tuple[HandlerTransitionEntry, ...]
    total_handlers: int
    known_count: int
    conditional_count: int
    exit_count: int
    unknown_count: int


def build_handler_transitions_report(
    mba: Any,
    dispatcher_entry_serial: int,
    state_var_stkoff: int | None,
    handler_serials: set[int],
    handler_state_map: dict[int, int],
    handler_range_map: dict[int, tuple[int | None, int | None]] | None = None,
    transitions: dict[int, int] | None = None,
    state_var_lvar_idx: int | None = None,
    diag_lines: list[str] | None = None,
    max_diag_handlers: int = 3,
) -> HandlerTransitionsReport:
    """Build transition labels by walking each handler chain.

    This is the extracted core previously implemented inline inside
    ``dump_dispatcher_tree``.
    """
    if not handler_serials:
        return HandlerTransitionsReport(
            entries=(),
            total_handlers=0,
            known_count=0,
            conditional_count=0,
            exit_count=0,
            unknown_count=0,
        )

    entries_raw: list[tuple[int | None, int, dict[str, Any], str]] = []
    diag_handler_count = 0

    for h_serial in sorted(handler_serials):
        state_const = handler_state_map.get(h_serial)
        if state_var_stkoff is not None:
            handler_diag: list[str] | None = None
            if diag_lines is not None and diag_handler_count < max_diag_handlers:
                handler_diag = []
                diag_lines.append(
                    f"Handler blk[{h_serial}] (state="
                    f"{hex(state_const) if state_const is not None else '?'}):"
                )
                diag_handler_count += 1

            per_handler_visited: set[int] = set()
            walk = _walk_handler_chain(
                mba,
                h_serial,
                dispatcher_entry_serial,
                state_var_stkoff,
                chain_visited=per_handler_visited,
                diag_lines=handler_diag,
                state_var_lvar_idx=state_var_lvar_idx,
            )
            if handler_diag and diag_lines is not None:
                diag_lines.extend(handler_diag)
        else:
            walk = {"next_state": None, "back_edge": False, "exit": False, "chain": []}

        if state_const is not None:
            state_label = f"State 0x{state_const:08x}"
        else:
            rng = handler_range_map.get(h_serial) if handler_range_map else None
            if rng is not None and rng[0] is not None and rng[1] is not None:
                state_label = f"State range [0x{rng[0]:x}..0x{rng[1]:x}]"
            else:
                state_label = "State <unknown>"

        entries_raw.append((state_const, h_serial, walk, state_label))

    entries_raw.sort(key=lambda e: (e[0] is None, e[0] if e[0] is not None else 0))

    known_count = 0
    exit_count = 0
    unknown_count = 0
    conditional_count = 0
    out_entries: list[HandlerTransitionEntry] = []

    for state_const, h_serial, walk, state_label in entries_raw:
        next_state = walk.get("next_state")
        if transitions is not None:
            trans_next = transitions.get(h_serial)
            if trans_next is not None and next_state is None:
                next_state = trans_next

        is_exit = walk.get("exit") or (not walk.get("back_edge") and walk.get("chain"))
        conditional_states = tuple(sorted(walk.get("conditional_states", set())))

        if is_exit:
            label = "RETURN (exit)"
            exit_count += 1
        elif walk.get("back_edge") and next_state is not None:
            label = f"next=0x{next_state:08x} (back-edge)"
            known_count += 1
        elif conditional_states:
            cond_hex = ", ".join(f"0x{s:08x}" for s in conditional_states)
            label = f"conditional transition -> {{{cond_hex}}}"
            conditional_count += 1
        elif walk.get("back_edge"):
            label = "back-edge (next state unknown)"
            unknown_count += 1
        elif next_state is not None:
            label = f"next=0x{next_state:08x}"
            known_count += 1
        else:
            label = "unknown"
            unknown_count += 1

        out_entries.append(
            HandlerTransitionEntry(
                state_const=state_const,
                handler_serial=h_serial,
                state_label=state_label,
                label=label,
                next_state=next_state,
                back_edge=bool(walk.get("back_edge")),
                is_exit=bool(is_exit),
                conditional_states=conditional_states,
                chain=tuple(walk.get("chain", ())),
            )
        )

    return HandlerTransitionsReport(
        entries=tuple(out_entries),
        total_handlers=len(handler_serials),
        known_count=known_count,
        conditional_count=conditional_count,
        exit_count=exit_count,
        unknown_count=unknown_count,
    )


class HandlerTransitionsCollector:
    """Recon collector for handler transition coverage and quality."""

    name: str = "handler_transitions"
    maturities: frozenset[int] = frozenset()  # all maturities
    level: str = "microcode"

    def collect(self, target: Any, func_ea: int, maturity: int) -> ReconResult:
        dispatcher_entry_serial = getattr(target, "dispatcher_entry_serial", None)
        if dispatcher_entry_serial is None:
            return ReconResult(
                collector_name=self.name,
                func_ea=func_ea,
                maturity=maturity,
                timestamp=time.time(),
                metrics=MappingProxyType({}),
                candidates=(),
            )

        state_var_stkoff = getattr(target, "state_var_stkoff", None)
        state_var_lvar_idx = None
        if state_var_stkoff is None:
            (detected, detected_lvar_idx) = _detect_state_var_stkoff(
                target, dispatcher_entry_serial, diag=False
            )
            state_var_stkoff = detected
            state_var_lvar_idx = detected_lvar_idx

        handler_state_map: dict[int, int] = {}
        handler_serials: set[int] = set()
        handler_range_map: dict[int, tuple[int | None, int | None]] = {}
        _dump_dispatcher_node(
            target,
            dispatcher_entry_serial,
            indent=0,
            visited=set(),
            lines=[],
            depth=0,
            max_depth=20,
            value_lo=0,
            value_hi=0xFFFFFFFF,
            handler_state_map=handler_state_map,
            handler_serials=handler_serials,
            handler_range_map=handler_range_map,
        )

        report = build_handler_transitions_report(
            mba=target,
            dispatcher_entry_serial=dispatcher_entry_serial,
            state_var_stkoff=state_var_stkoff,
            handler_serials=handler_serials,
            handler_state_map=handler_state_map,
            handler_range_map=handler_range_map,
            state_var_lvar_idx=state_var_lvar_idx,
        )

        candidates: list[CandidateFlag] = []
        for entry in report.entries:
            if entry.label == "unknown" or entry.label == "back-edge (next state unknown)":
                candidates.append(
                    CandidateFlag(
                        kind="handler_transition_unknown",
                        block_serial=entry.handler_serial,
                        confidence=0.9,
                        detail=entry.label,
                    )
                )

        return ReconResult(
            collector_name=self.name,
            func_ea=func_ea,
            maturity=maturity,
            timestamp=time.time(),
            metrics=MappingProxyType(
                {
                    "handlers_total": report.total_handlers,
                    "handlers_known": report.known_count,
                    "handlers_conditional": report.conditional_count,
                    "handlers_exit": report.exit_count,
                    "handlers_unknown": report.unknown_count,
                }
            ),
            candidates=tuple(candidates),
        )

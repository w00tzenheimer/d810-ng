"""Canonical dispatcher transition report model and rendering helpers."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

from d810.cfg.flowgraph import FlowGraph
from d810.core.typing import Any, Mapping, Optional, Tuple
from d810.recon.flow.transition_analysis import (
    DispatcherTransitionAnalysis,
    HandlerTransitionObservation,
    build_transition_analysis_from_graph,
)
from d810.recon.flow.transition_bst_adapter import analyze_bst_dispatcher
from d810.recon.flow.transition_builder import TransitionResult


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


def _state_label(observation: HandlerTransitionObservation) -> str:
    if observation.state_const is not None:
        return f"State 0x{observation.state_const:08x}"
    if (
        observation.state_range_lo is not None
        and observation.state_range_hi is not None
    ):
        return (
            f"State range [0x{observation.state_range_lo:x}.."
            f"0x{observation.state_range_hi:x}]"
        )
    return "State <unknown>"


def _classify_observation(
    observation: HandlerTransitionObservation,
) -> tuple[TransitionKind, str]:
    if observation.classified_exit:
        return TransitionKind.EXIT, "RETURN (exit)"
    if observation.back_edge and observation.next_state is not None:
        return (
            TransitionKind.TRANSITION,
            f"next=0x{observation.next_state:08x} (back-edge)",
        )
    if observation.conditional_states:
        cond_hex = ", ".join(f"0x{s:08x}" for s in observation.conditional_states)
        return (
            TransitionKind.CONDITIONAL,
            f"conditional transition -> {{{cond_hex}}}",
        )
    if observation.back_edge:
        return TransitionKind.UNKNOWN, "back-edge (next state unknown)"
    if observation.next_state is not None:
        return TransitionKind.TRANSITION, f"next=0x{observation.next_state:08x}"
    return TransitionKind.UNKNOWN, "unknown"


def _summary_from_rows(rows: tuple[TransitionRow, ...]) -> TransitionSummary:
    known_count = sum(1 for row in rows if row.kind == TransitionKind.TRANSITION)
    conditional_count = sum(1 for row in rows if row.kind == TransitionKind.CONDITIONAL)
    exit_count = sum(1 for row in rows if row.kind == TransitionKind.EXIT)
    unknown_count = sum(1 for row in rows if row.kind == TransitionKind.UNKNOWN)
    return TransitionSummary(
        handlers_total=len(rows),
        known_count=known_count,
        conditional_count=conditional_count,
        exit_count=exit_count,
        unknown_count=unknown_count,
    )


def render_dispatcher_transition_report(
    analysis: DispatcherTransitionAnalysis,
    *,
    chain_preview_len: int = 4,
) -> DispatcherTransitionReport:
    """Render a canonical report from portable analysis data."""
    rows: list[TransitionRow] = []
    for observation in analysis.observations:
        kind, transition_label = _classify_observation(observation)
        path = TransitionPath(
            handler_serial=observation.handler_serial,
            chain=observation.chain,
            next_state=observation.next_state,
            conditional_states=observation.conditional_states,
            back_edge=observation.back_edge,
            reaches_exit_block=observation.reaches_exit_block,
            classified_exit=observation.classified_exit,
            unresolved=observation.unresolved or kind == TransitionKind.UNKNOWN,
        )
        rows.append(
            TransitionRow(
                state_const=observation.state_const,
                state_range_lo=observation.state_range_lo,
                state_range_hi=observation.state_range_hi,
                handler_serial=observation.handler_serial,
                kind=kind,
                next_state=observation.next_state,
                conditional_states=observation.conditional_states,
                state_label=_state_label(observation),
                transition_label=transition_label,
                chain_preview=observation.chain[:chain_preview_len],
                path=path,
            )
        )

    rows_tuple = tuple(rows)
    return DispatcherTransitionReport(
        dispatcher_entry_serial=analysis.dispatcher_entry_serial,
        state_var_stkoff=analysis.state_var_stkoff,
        state_var_lvar_idx=analysis.state_var_lvar_idx,
        pre_header_serial=analysis.pre_header_serial,
        initial_state=analysis.initial_state,
        handler_state_map=dict(analysis.handler_state_map),
        handler_range_map=dict(analysis.handler_range_map),
        bst_node_blocks=tuple(analysis.bst_node_blocks),
        rows=rows_tuple,
        summary=_summary_from_rows(rows_tuple),
        diagnostics=tuple(analysis.diagnostics),
    )


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
    analysis = analyze_bst_dispatcher(
        mba,
        dispatcher_entry_serial,
        state_var_stkoff=state_var_stkoff,
        state_var_lvar_idx=state_var_lvar_idx,
        max_bst_depth=max_bst_depth,
        max_chain_depth=max_chain_depth,
        transitions_hint_by_handler=transitions_hint_by_handler,
        capture_diagnostics=capture_diagnostics,
        max_diag_handlers=max_diag_handlers,
    )
    return render_dispatcher_transition_report(
        analysis,
        chain_preview_len=chain_preview_len,
    )


def build_dispatcher_transition_report_from_graph(
    flow_graph: FlowGraph,
    transition_result: TransitionResult,
    *,
    dispatcher_entry_serial: int,
    state_var_stkoff: Optional[int] = None,
    state_var_lvar_idx: Optional[int] = None,
    pre_header_serial: Optional[int] = None,
    initial_state: Optional[int] = None,
    handler_range_map: Mapping[int, tuple[Optional[int], Optional[int]]] | None = None,
    bst_node_blocks: tuple[int, ...] = (),
    diagnostics: tuple[str, ...] = (),
    chain_preview_len: int = 4,
) -> DispatcherTransitionReport:
    """Build a canonical report from graph-portable analysis inputs."""
    analysis = build_transition_analysis_from_graph(
        flow_graph,
        transition_result,
        dispatcher_entry_serial=dispatcher_entry_serial,
        state_var_stkoff=state_var_stkoff,
        state_var_lvar_idx=state_var_lvar_idx,
        pre_header_serial=pre_header_serial,
        initial_state=initial_state,
        handler_range_map=handler_range_map,
        bst_node_blocks=bst_node_blocks,
        diagnostics=diagnostics,
    )
    return render_dispatcher_transition_report(
        analysis,
        chain_preview_len=chain_preview_len,
    )


def transition_report_to_dict(
    report: DispatcherTransitionReport,
) -> dict[str, object]:
    """Serialize a report to a JSON-friendly dict."""
    return {
        "dispatcher_entry_serial": report.dispatcher_entry_serial,
        "state_var_stkoff": report.state_var_stkoff,
        "state_var_lvar_idx": report.state_var_lvar_idx,
        "pre_header_serial": report.pre_header_serial,
        "initial_state": report.initial_state,
        "handler_state_map": {
            str(serial): state for serial, state in report.handler_state_map.items()
        },
        "handler_range_map": {
            str(serial): [range_lo, range_hi]
            for serial, (range_lo, range_hi) in report.handler_range_map.items()
        },
        "bst_node_blocks": list(report.bst_node_blocks),
        "rows": [
            {
                "state_const": row.state_const,
                "state_range_lo": row.state_range_lo,
                "state_range_hi": row.state_range_hi,
                "handler_serial": row.handler_serial,
                "kind": row.kind.name,
                "next_state": row.next_state,
                "conditional_states": list(row.conditional_states),
                "state_label": row.state_label,
                "transition_label": row.transition_label,
                "chain_preview": list(row.chain_preview),
                "path": {
                    "handler_serial": row.path.handler_serial,
                    "chain": list(row.path.chain),
                    "next_state": row.path.next_state,
                    "conditional_states": list(row.path.conditional_states),
                    "back_edge": row.path.back_edge,
                    "reaches_exit_block": row.path.reaches_exit_block,
                    "classified_exit": row.path.classified_exit,
                    "unresolved": row.path.unresolved,
                },
            }
            for row in report.rows
        ],
        "summary": {
            "handlers_total": report.summary.handlers_total,
            "known_count": report.summary.known_count,
            "conditional_count": report.summary.conditional_count,
            "exit_count": report.summary.exit_count,
            "unknown_count": report.summary.unknown_count,
        },
        "diagnostics": list(report.diagnostics),
    }


def transition_report_from_dict(
    payload: Mapping[str, object],
) -> DispatcherTransitionReport:
    """Deserialize a report from ``transition_report_to_dict`` payload."""
    rows: list[TransitionRow] = []
    for row_payload in payload.get("rows", []):
        row_map = dict(row_payload)
        path_payload = dict(row_map["path"])
        path = TransitionPath(
            handler_serial=int(path_payload["handler_serial"]),
            chain=tuple(int(v) for v in path_payload.get("chain", [])),
            next_state=(
                None if path_payload.get("next_state") is None
                else int(path_payload["next_state"])
            ),
            conditional_states=tuple(
                int(v) for v in path_payload.get("conditional_states", [])
            ),
            back_edge=bool(path_payload["back_edge"]),
            reaches_exit_block=bool(path_payload["reaches_exit_block"]),
            classified_exit=bool(path_payload["classified_exit"]),
            unresolved=bool(path_payload["unresolved"]),
        )
        rows.append(
            TransitionRow(
                state_const=(
                    None if row_map.get("state_const") is None
                    else int(row_map["state_const"])
                ),
                state_range_lo=(
                    None if row_map.get("state_range_lo") is None
                    else int(row_map["state_range_lo"])
                ),
                state_range_hi=(
                    None if row_map.get("state_range_hi") is None
                    else int(row_map["state_range_hi"])
                ),
                handler_serial=int(row_map["handler_serial"]),
                kind=TransitionKind[str(row_map["kind"])],
                next_state=(
                    None if row_map.get("next_state") is None
                    else int(row_map["next_state"])
                ),
                conditional_states=tuple(
                    int(v) for v in row_map.get("conditional_states", [])
                ),
                state_label=str(row_map["state_label"]),
                transition_label=str(row_map["transition_label"]),
                chain_preview=tuple(int(v) for v in row_map.get("chain_preview", [])),
                path=path,
            )
        )

    summary_payload = dict(payload["summary"])
    return DispatcherTransitionReport(
        dispatcher_entry_serial=int(payload["dispatcher_entry_serial"]),
        state_var_stkoff=(
            None if payload.get("state_var_stkoff") is None
            else int(payload["state_var_stkoff"])
        ),
        state_var_lvar_idx=(
            None if payload.get("state_var_lvar_idx") is None
            else int(payload["state_var_lvar_idx"])
        ),
        pre_header_serial=(
            None if payload.get("pre_header_serial") is None
            else int(payload["pre_header_serial"])
        ),
        initial_state=(
            None if payload.get("initial_state") is None
            else int(payload["initial_state"])
        ),
        handler_state_map={
            int(serial): int(state)
            for serial, state in dict(payload.get("handler_state_map", {})).items()
        },
        handler_range_map={
            int(serial): (
                None if values[0] is None else int(values[0]),
                None if values[1] is None else int(values[1]),
            )
            for serial, values in dict(payload.get("handler_range_map", {})).items()
        },
        bst_node_blocks=tuple(int(v) for v in payload.get("bst_node_blocks", [])),
        rows=tuple(rows),
        summary=TransitionSummary(
            handlers_total=int(summary_payload["handlers_total"]),
            known_count=int(summary_payload["known_count"]),
            conditional_count=int(summary_payload["conditional_count"]),
            exit_count=int(summary_payload["exit_count"]),
            unknown_count=int(summary_payload["unknown_count"]),
        ),
        diagnostics=tuple(str(v) for v in payload.get("diagnostics", [])),
    )


__all__ = [
    "TransitionKind",
    "TransitionPath",
    "TransitionRow",
    "TransitionSummary",
    "DispatcherTransitionReport",
    "render_dispatcher_transition_report",
    "build_dispatcher_transition_report",
    "build_dispatcher_transition_report_from_graph",
    "transition_report_to_dict",
    "transition_report_from_dict",
]

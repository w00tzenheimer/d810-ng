"""Structured transition evidence for the PREOPT union-region experiment."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import sqlite3

from d810.analyses.control_flow.minimal_state_recovery import StateWriteTransition
from d810.core.typing import Mapping, Sequence
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, OperandKind


@dataclass(frozen=True, slots=True)
class PreoptTransitionManifestRow:
    capture_index: int
    source_block_serial: int
    source_block_ea: int
    write_site_ea: int
    via_block_serial: int | None
    via_block_ea: int | None
    next_state: int | None
    target_handler_serial: int | None
    target_handler_ea: int | None
    is_return: bool
    branch_arm: int | None
    oracle_kind: str
    proof_kind: str
    trusted: bool
    status: str
    reason: str


class PreoptManifestBoundaryAbstentionReason(str, Enum):
    """Why a trusted manifest row cannot become one PREOPT edge."""

    CONFLICTING_TRANSITIONS = "conflicting_transitions"


@dataclass(frozen=True, slots=True)
class PreoptManifestDirectBoundary:
    """One exact CALLS transition projected back onto native PREOPT EAs."""

    source_ea: int
    target_ea: int
    state_constant: int
    state_register: int
    via_ea: int | None = None
    requires_literal_state_write: bool = False


@dataclass(frozen=True, slots=True)
class PreoptManifestBoundaryAbstention:
    source_ea: int
    reason: PreoptManifestBoundaryAbstentionReason


@dataclass(frozen=True, slots=True)
class PreoptManifestBoundaryPlan:
    direct: tuple[PreoptManifestDirectBoundary, ...]
    abstentions: tuple[PreoptManifestBoundaryAbstention, ...]


def _replay_semantic_key(
    row: PreoptTransitionManifestRow,
) -> tuple[int, int, int, int | None] | None:
    if (
        row.status != "resolved"
        or not row.trusted
        or row.is_return
        or row.next_state is None
        or row.target_handler_ea is None
    ):
        return None
    return (
        int(row.write_site_ea),
        int(row.next_state) & 0xFFFFFFFF,
        int(row.target_handler_ea),
        None if row.via_block_ea is None else int(row.via_block_ea),
    )


def select_replay_transition_manifest(
    captures: Sequence[Sequence[PreoptTransitionManifestRow]],
) -> tuple[PreoptTransitionManifestRow, ...]:
    """Select the capture with the greatest exact replay coverage."""
    nonempty = [tuple(rows) for rows in captures if rows]
    if not nonempty:
        return ()

    def rank(
        rows: tuple[PreoptTransitionManifestRow, ...],
    ) -> tuple[int, int, int]:
        semantic_keys = {
            key
            for row in rows
            if (key := _replay_semantic_key(row)) is not None
        }
        capture_index = max(int(row.capture_index) for row in rows)
        return len(semantic_keys), capture_index, len(rows)

    return max(nonempty, key=rank)


def select_timed_replay_transition_manifest(
    local_captures: Sequence[Sequence[PreoptTransitionManifestRow]],
    external_rows: Sequence[PreoptTransitionManifestRow],
) -> tuple[PreoptTransitionManifestRow, ...]:
    """Select replay contents without advancing the local callback timing.

    A local capture is the timing token: external rows may replace its
    contents, but must not make replay happen before that capture exists.
    """
    if not local_captures:
        return ()
    if external_rows:
        return tuple(external_rows)
    return select_replay_transition_manifest(local_captures)


def plan_preopt_manifest_boundaries(
    rows: Sequence[PreoptTransitionManifestRow],
    *,
    state_register: int,
) -> PreoptManifestBoundaryPlan:
    """Classify exact CALLS proofs for conservative replay at PREOPT."""
    candidates_by_source: dict[int, set[PreoptManifestDirectBoundary]] = {}
    for row in rows:
        semantic_key = _replay_semantic_key(row)
        if semantic_key is None:
            continue
        source_ea, state_constant, target_ea, via_ea = semantic_key
        candidates_by_source.setdefault(source_ea, set()).add(
            PreoptManifestDirectBoundary(
                source_ea=source_ea,
                target_ea=target_ea,
                state_constant=state_constant,
                state_register=int(state_register),
                via_ea=via_ea,
            )
        )

    direct: list[PreoptManifestDirectBoundary] = []
    abstentions: list[PreoptManifestBoundaryAbstention] = []
    for source_ea, candidates in sorted(candidates_by_source.items()):
        if len(candidates) == 1:
            direct.append(next(iter(candidates)))
            continue
        abstentions.append(
            PreoptManifestBoundaryAbstention(
                source_ea=source_ea,
                reason=(
                    PreoptManifestBoundaryAbstentionReason.CONFLICTING_TRANSITIONS
                ),
            )
        )
    return PreoptManifestBoundaryPlan(
        direct=tuple(
            sorted(direct, key=lambda row: (row.source_ea, row.target_ea))
        ),
        abstentions=tuple(abstentions),
    )


def _native_ea(ea: int, instruction_origins: Mapping[int, int]) -> int:
    return int(instruction_origins.get(int(ea), int(ea)))


def _block_anchor_ea(
    block: BlockSnapshot,
    instruction_origins: Mapping[int, int],
) -> int:
    mapped_start = instruction_origins.get(int(block.start_ea))
    if mapped_start is not None:
        return int(mapped_start)
    for instruction in block.insn_snapshots:
        mapped_instruction = instruction_origins.get(int(instruction.ea))
        if mapped_instruction is not None:
            return int(mapped_instruction)
    return int(block.start_ea)


def _optional_block_anchor_ea(
    graph: FlowGraph,
    serial: int | None,
    instruction_origins: Mapping[int, int],
) -> int | None:
    if serial is None:
        return None
    block = graph.get_block(int(serial))
    if block is None:
        return None
    return _block_anchor_ea(block, instruction_origins)


def _state_write_ea(
    block: BlockSnapshot,
    instruction_origins: Mapping[int, int],
    state_var_reg: int | None,
) -> int:
    write_ea: int | None = None
    if state_var_reg is not None:
        for instruction in block.insn_snapshots:
            destination = instruction.d
            if (
                destination is not None
                and destination.kind is OperandKind.REGISTER
                and destination.reg == int(state_var_reg)
            ):
                write_ea = _native_ea(instruction.ea, instruction_origins)
    if write_ea is not None:
        return write_ea
    return _block_anchor_ea(block, instruction_origins)


def build_transition_manifest(
    graph: FlowGraph,
    transitions: Sequence[StateWriteTransition],
    *,
    instruction_origins: Mapping[int, int],
    state_var_reg: int | None,
    capture_index: int,
) -> tuple[PreoptTransitionManifestRow, ...]:
    """Project maturity-local transition serials onto stable native EA anchors."""
    rows: list[PreoptTransitionManifestRow] = []
    for transition in transitions:
        source = graph.get_block(int(transition.write_block))
        if source is None:
            continue
        proof = transition.proof
        proof_kind = "unattributed" if proof is None else str(proof.kind)
        reason = (
            proof_kind
            if proof is None or not proof.reason
            else str(proof.reason)
        )
        rows.append(
            PreoptTransitionManifestRow(
                capture_index=int(capture_index),
                source_block_serial=int(transition.write_block),
                source_block_ea=_block_anchor_ea(source, instruction_origins),
                write_site_ea=_state_write_ea(
                    source,
                    instruction_origins,
                    state_var_reg,
                ),
                via_block_serial=(
                    None
                    if transition.via_block is None
                    else int(transition.via_block)
                ),
                via_block_ea=_optional_block_anchor_ea(
                    graph,
                    transition.via_block,
                    instruction_origins,
                ),
                next_state=(
                    None
                    if transition.next_state is None
                    else int(transition.next_state) & 0xFFFFFFFF
                ),
                target_handler_serial=(
                    None
                    if transition.target_handler is None
                    else int(transition.target_handler)
                ),
                target_handler_ea=_optional_block_anchor_ea(
                    graph,
                    transition.target_handler,
                    instruction_origins,
                ),
                is_return=bool(transition.is_return),
                branch_arm=(
                    None
                    if transition.branch_arm is None
                    else int(transition.branch_arm)
                ),
                oracle_kind=(
                    "unattributed" if proof is None else str(proof.oracle_kind)
                ),
                proof_kind=proof_kind,
                trusted=False if proof is None else bool(proof.trusted),
                status=(
                    "unresolved"
                    if transition.next_state is None
                    else "resolved"
                ),
                reason=reason,
            )
        )
    return tuple(rows)


def _hex_or_none(value: int | None) -> str | None:
    return None if value is None else f"0x{int(value):X}"


def persist_transition_manifest(
    database: Path,
    rows: Sequence[PreoptTransitionManifestRow],
) -> None:
    """Replace the investigation-only manifest table in a copied diag DB."""
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS preopt_transition_manifest (
                capture_index INTEGER NOT NULL,
                source_block_serial INTEGER NOT NULL,
                source_block_ea_hex TEXT NOT NULL,
                source_block_ea_i64 INTEGER NOT NULL,
                write_site_ea_hex TEXT NOT NULL,
                write_site_ea_i64 INTEGER NOT NULL,
                via_block_serial INTEGER,
                via_block_ea_hex TEXT,
                via_block_ea_i64 INTEGER,
                next_state_hex TEXT,
                next_state_i64 INTEGER,
                target_handler_serial INTEGER,
                target_handler_ea_hex TEXT,
                target_handler_ea_i64 INTEGER,
                is_return INTEGER NOT NULL,
                branch_arm INTEGER,
                oracle_kind TEXT NOT NULL,
                proof_kind TEXT NOT NULL,
                trusted INTEGER NOT NULL,
                status TEXT NOT NULL,
                reason TEXT NOT NULL
            )
            """
        )
        connection.execute("DELETE FROM preopt_transition_manifest")
        connection.executemany(
            """
            INSERT INTO preopt_transition_manifest (
                capture_index,
                source_block_serial, source_block_ea_hex, source_block_ea_i64,
                write_site_ea_hex, write_site_ea_i64,
                via_block_serial, via_block_ea_hex, via_block_ea_i64,
                next_state_hex, next_state_i64,
                target_handler_serial, target_handler_ea_hex,
                target_handler_ea_i64,
                is_return, branch_arm,
                oracle_kind, proof_kind, trusted, status, reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                (
                    row.capture_index,
                    row.source_block_serial,
                    _hex_or_none(row.source_block_ea),
                    row.source_block_ea,
                    _hex_or_none(row.write_site_ea),
                    row.write_site_ea,
                    row.via_block_serial,
                    _hex_or_none(row.via_block_ea),
                    row.via_block_ea,
                    _hex_or_none(row.next_state),
                    row.next_state,
                    row.target_handler_serial,
                    _hex_or_none(row.target_handler_ea),
                    row.target_handler_ea,
                    int(row.is_return),
                    row.branch_arm,
                    row.oracle_kind,
                    row.proof_kind,
                    int(row.trusted),
                    row.status,
                    row.reason,
                )
                for row in rows
            ),
        )


def load_transition_manifest(
    database: Path,
) -> tuple[PreoptTransitionManifestRow, ...]:
    """Load one persisted EA-anchored manifest for controlled replay."""
    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            """
            SELECT capture_index,
                   source_block_serial, source_block_ea_i64,
                   write_site_ea_i64,
                   via_block_serial, via_block_ea_i64,
                   next_state_i64,
                   target_handler_serial, target_handler_ea_i64,
                   is_return, branch_arm,
                   oracle_kind, proof_kind, trusted, status, reason
            FROM preopt_transition_manifest
            ORDER BY capture_index, write_site_ea_i64,
                     next_state_i64, target_handler_ea_i64
            """
        ).fetchall()
    return tuple(
        PreoptTransitionManifestRow(
            capture_index=int(row[0]),
            source_block_serial=int(row[1]),
            source_block_ea=int(row[2]),
            write_site_ea=int(row[3]),
            via_block_serial=None if row[4] is None else int(row[4]),
            via_block_ea=None if row[5] is None else int(row[5]),
            next_state=None if row[6] is None else int(row[6]),
            target_handler_serial=(
                None if row[7] is None else int(row[7])
            ),
            target_handler_ea=None if row[8] is None else int(row[8]),
            is_return=bool(row[9]),
            branch_arm=None if row[10] is None else int(row[10]),
            oracle_kind=str(row[11]),
            proof_kind=str(row[12]),
            trusted=bool(row[13]),
            status=str(row[14]),
            reason=str(row[15]),
        )
        for row in rows
    )


__all__ = [
    "PreoptManifestBoundaryAbstention",
    "PreoptManifestBoundaryAbstentionReason",
    "PreoptManifestBoundaryPlan",
    "PreoptManifestDirectBoundary",
    "PreoptTransitionManifestRow",
    "build_transition_manifest",
    "load_transition_manifest",
    "persist_transition_manifest",
    "plan_preopt_manifest_boundaries",
    "select_replay_transition_manifest",
    "select_timed_replay_transition_manifest",
]

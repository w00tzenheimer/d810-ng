"""Read-only transition facts for switch-table state-machine case bodies."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from d810.recon.flow.branch_ownership import (
    BranchOwnershipProof,
    BranchOwnershipProofKind,
)
from d810.recon.flow.dispatcher_map import StateDispatcherMap


class SwitchCaseTransitionKind(str, Enum):
    DIRECT = "DIRECT"
    CONDITIONAL = "CONDITIONAL"
    RETURN_FRONTIER = "RETURN_FRONTIER"
    DIAGNOSTIC = "DIAGNOSTIC"
    UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True, slots=True)
class SwitchCaseBody:
    """Pure input view of one switch case body."""

    state: int
    entry_block: int | None = None
    state_writes: tuple[int, ...] = ()
    state_write_exit_blocks: tuple[int | None, ...] = ()
    state_write_ordered_paths: tuple[tuple[int, ...], ...] = ()
    returns: tuple[int | None, ...] = ()
    return_exit_blocks: tuple[int | None, ...] = ()
    predicate_kind: str | None = None
    source_predicate: bool = False
    payload: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SwitchCaseTransitionFact:
    """Typed diagnostic fact for one switch-table case transition."""

    fact_id: str
    transition_kind: SwitchCaseTransitionKind | str
    source_state: int | None
    case_entry_block: int | None
    next_states: tuple[int, ...] = ()
    return_value: int | None = None
    state_var_stkoff: int | None = None
    state_var_lvar_idx: int | None = None
    proof: BranchOwnershipProof | None = None
    reason: str = ""
    row_kind: str | None = None
    target_block: int | None = None
    exit_block: int | None = None
    ordered_path: tuple[int, ...] = ()
    payload: dict[str, object] = field(default_factory=dict)

    @property
    def transition_kind_name(self) -> str:
        if isinstance(self.transition_kind, SwitchCaseTransitionKind):
            return self.transition_kind.value
        return str(self.transition_kind)

    @property
    def source_state_hex(self) -> str | None:
        if self.source_state is None:
            return None
        return _hex_u64(self.source_state)

    def to_diag_row(self) -> dict[str, object]:
        next_a = self.next_states[0] if len(self.next_states) >= 1 else None
        next_b = self.next_states[1] if len(self.next_states) >= 2 else None
        proof_kind = self.proof.proof_kind_name if self.proof is not None else None
        trusted = int(bool(self.proof.trusted)) if self.proof is not None else 0
        payload = dict(self.payload)
        if self.exit_block is not None:
            payload.setdefault("exit_block", self.exit_block)
        if self.ordered_path:
            payload.setdefault("ordered_path", tuple(int(serial) for serial in self.ordered_path))
        if self.proof is not None:
            payload.setdefault("proof_id", self.proof.proof_id)
            payload.setdefault("proof_reason", self.proof.reason)
            payload.setdefault("proof_oracle_kind", self.proof.oracle_kind)
        return {
            "fact_id": self.fact_id,
            "source_state_hex": self.source_state_hex,
            "source_state_i64": _sqlite_i64(self.source_state),
            "case_entry_block": self.case_entry_block,
            "transition_kind": self.transition_kind_name,
            "next_state_a_hex": _hex_or_none(next_a),
            "next_state_a_i64": _sqlite_i64(next_a),
            "next_state_b_hex": _hex_or_none(next_b),
            "next_state_b_i64": _sqlite_i64(next_b),
            "return_value": self.return_value,
            "state_var_stkoff": self.state_var_stkoff,
            "state_var_lvar_idx": self.state_var_lvar_idx,
            "proof_kind": proof_kind,
            "trusted": trusted,
            "reason": self.reason,
            "row_kind": self.row_kind,
            "target_block": self.target_block,
            "payload": payload,
        }


def collect_switch_case_transition_facts(
    *,
    dispatch_map: StateDispatcherMap,
    case_bodies: tuple[SwitchCaseBody, ...] | list[SwitchCaseBody],
    profile_name: str = "tigress_switch",
) -> tuple[SwitchCaseTransitionFact, ...]:
    """Collect read-only case transition facts from exact switch rows.

    The helper trusts only table-visible states. Conditional transitions are
    classified as REAL_DATA_DEPENDENT when both arms resolve to valid switch
    states and the case body marks the predicate as source-derived.
    """
    visible_states = {int(row.state_const) for row in dispatch_map.rows}
    body_by_state = {int(body.state): body for body in case_bodies}
    facts: list[SwitchCaseTransitionFact] = []

    for row in dispatch_map.rows:
        state = int(row.state_const)
        if row.row_kind != "handler":
            facts.append(_diagnostic_fact(
                dispatch_map=dispatch_map,
                state=state,
                row_kind=row.row_kind,
                target_block=int(row.target_block),
                reason=f"switch_row_{row.row_kind}",
                profile_name=profile_name,
            ))
            continue
        body = body_by_state.get(state)
        if body is None:
            facts.append(_unresolved_fact(
                dispatch_map=dispatch_map,
                state=state,
                case_entry_block=int(row.target_block),
                reason="case_body_missing",
                profile_name=profile_name,
            ))
            continue
        facts.extend(_facts_for_body(
            dispatch_map=dispatch_map,
            body=body,
            visible_states=visible_states,
            profile_name=profile_name,
        ))

    if dispatch_map.default_target_block is not None:
        facts.append(SwitchCaseTransitionFact(
            fact_id=f"{profile_name}:switch_default:target={dispatch_map.default_target_block}",
            transition_kind=SwitchCaseTransitionKind.DIAGNOSTIC,
            source_state=None,
            case_entry_block=None,
            state_var_stkoff=dispatch_map.state_var_stkoff,
            state_var_lvar_idx=dispatch_map.state_var_lvar_idx,
            reason=dispatch_map.default_row_kind or "dispatcher_default",
            row_kind=dispatch_map.default_row_kind,
            target_block=dispatch_map.default_target_block,
            payload={"profile_name": profile_name},
        ))
    return tuple(facts)


def collect_switch_case_transition_facts_from_mba(
    *,
    mba: object,
    dispatch_map: StateDispatcherMap,
    profile_name: str = "tigress_switch",
) -> tuple[SwitchCaseTransitionFact, ...]:
    """Collect switch case transition facts from live MBA handler bodies."""
    if dispatch_map.state_var_stkoff is None:
        return tuple(
            _unresolved_fact(
                dispatch_map=dispatch_map,
                state=int(row.state_const),
                case_entry_block=int(row.target_block),
                reason="state_var_stkoff_missing",
                profile_name=profile_name,
            )
            for row in dispatch_map.rows
        )

    from d810.recon.flow.state_machine_analysis import evaluate_handler_paths

    handler_rows = tuple(row for row in dispatch_map.rows if row.is_handler_row)
    handler_entry_blocks = {int(row.target_block) for row in handler_rows}
    case_bodies: list[SwitchCaseBody] = []
    for row in handler_rows:
        source_state = int(row.state_const)
        entry_block = int(row.target_block)
        try:
            path_results = evaluate_handler_paths(
                mba,
                entry_serial=entry_block,
                incoming_state=source_state,
                bst_node_blocks=set(dispatch_map.dispatcher_blocks),
                state_var_stkoff=int(dispatch_map.state_var_stkoff),
                handler_entry_blocks=handler_entry_blocks,
            )
        except Exception:
            case_bodies.append(
                SwitchCaseBody(
                    state=source_state,
                    entry_block=entry_block,
                    payload={"live_extraction_error": "evaluate_handler_paths_failed"},
                )
            )
            continue

        next_states: list[int] = []
        next_state_exits: list[int | None] = []
        next_state_paths: list[tuple[int, ...]] = []
        returns: list[int | None] = []
        return_exits: list[int | None] = []
        for path in path_results:
            final_state = getattr(path, "final_state", None)
            exit_block = getattr(path, "exit_block", None)
            ordered_path = tuple(int(serial) for serial in getattr(path, "ordered_path", ()) or ())
            if final_state is None:
                returns.append(_return_value_for_path(mba, getattr(path, "ordered_path", ()) or ()))
                return_exits.append(None if exit_block is None else int(exit_block))
                continue
            state_value = int(final_state) & 0xFFFFFFFFFFFFFFFF
            if state_value not in next_states:
                next_states.append(state_value)
                next_state_exits.append(None if exit_block is None else int(exit_block))
                next_state_paths.append(ordered_path)
        case_bodies.append(
            SwitchCaseBody(
                state=source_state,
                entry_block=entry_block,
                state_writes=tuple(next_states),
                state_write_exit_blocks=tuple(next_state_exits),
                state_write_ordered_paths=tuple(next_state_paths),
                returns=tuple(returns),
                return_exit_blocks=tuple(return_exits),
                predicate_kind="live_mba_branch" if len(next_states) == 2 else None,
                source_predicate=_has_live_conditional_branch(
                    mba,
                    tuple(getattr(path, "ordered_path", ()) or () for path in path_results),
                    dispatch_map.dispatcher_blocks,
                ),
                payload={"runtime_source": "live_mba"},
            )
        )

    return collect_switch_case_transition_facts(
        dispatch_map=dispatch_map,
        case_bodies=tuple(case_bodies),
        profile_name=profile_name,
    )


def _facts_for_body(
    *,
    dispatch_map: StateDispatcherMap,
    body: SwitchCaseBody,
    visible_states: set[int],
    profile_name: str,
) -> tuple[SwitchCaseTransitionFact, ...]:
    state = int(body.state)
    writes = tuple(int(value) for value in body.state_writes)
    entry_block = body.entry_block
    if body.returns:
        return tuple(
            SwitchCaseTransitionFact(
                fact_id=f"{profile_name}:case={state}:return:{index}",
                transition_kind=SwitchCaseTransitionKind.RETURN_FRONTIER,
                source_state=state,
                case_entry_block=entry_block,
                return_value=value,
                state_var_stkoff=dispatch_map.state_var_stkoff,
                state_var_lvar_idx=dispatch_map.state_var_lvar_idx,
                proof=BranchOwnershipProof(
                    proof_id=f"{profile_name}:case={state}:return:{index}",
                    proof_kind=BranchOwnershipProofKind.TERMINAL_RETURN_FRONTIER,
                    trusted=True,
                    reason="case_body_returns",
                    source_state=state,
                    source_block=entry_block,
                    predicate_block=entry_block,
                    dispatcher_entry_block=dispatch_map.dispatcher_entry_block,
                    oracle_kind="switch_case_return_frontier",
                ),
                reason="case_body_returns",
                exit_block=_return_exit_block(body, index),
                payload=dict(body.payload),
            )
            for index, value in enumerate(body.returns)
        )
    if len(writes) == 1:
        next_state = writes[0]
        kind = (
            SwitchCaseTransitionKind.DIRECT
            if next_state in visible_states else SwitchCaseTransitionKind.UNRESOLVED
        )
        return (SwitchCaseTransitionFact(
            fact_id=f"{profile_name}:case={state}:direct",
            transition_kind=kind,
            source_state=state,
            case_entry_block=entry_block,
            next_states=(next_state,),
            state_var_stkoff=dispatch_map.state_var_stkoff,
            state_var_lvar_idx=dispatch_map.state_var_lvar_idx,
            reason=(
                "direct_case_transition"
                if next_state in visible_states else "direct_target_not_in_switch_rows"
            ),
            exit_block=_state_write_exit_block(body, 0),
            ordered_path=_state_write_ordered_path(body, 0),
            payload=dict(body.payload),
        ),)
    if len(writes) == 2:
        valid_targets = all(value in visible_states for value in writes)
        real_predicate = bool(body.source_predicate)
        proof_kind = (
            BranchOwnershipProofKind.REAL_DATA_DEPENDENT
            if valid_targets and real_predicate else BranchOwnershipProofKind.UNRESOLVED
        )
        trusted = proof_kind == BranchOwnershipProofKind.REAL_DATA_DEPENDENT
        reason = (
            "conditional_case_transition_source_predicate"
            if trusted else "conditional_case_transition_unresolved"
        )
        return (SwitchCaseTransitionFact(
            fact_id=f"{profile_name}:case={state}:conditional",
            transition_kind=(
                SwitchCaseTransitionKind.CONDITIONAL
                if trusted else SwitchCaseTransitionKind.UNRESOLVED
            ),
            source_state=state,
            case_entry_block=entry_block,
            next_states=writes,
            state_var_stkoff=dispatch_map.state_var_stkoff,
            state_var_lvar_idx=dispatch_map.state_var_lvar_idx,
            proof=BranchOwnershipProof(
                proof_id=f"{profile_name}:case={state}:conditional",
                proof_kind=proof_kind,
                trusted=trusted,
                reason=reason,
                source_state=state,
                source_block=entry_block,
                predicate_block=entry_block,
                dispatcher_entry_block=dispatch_map.dispatcher_entry_block,
                oracle_kind="switch_case_branch_ownership",
                evidence={
                    "predicate_kind": body.predicate_kind,
                    "targets_visible": valid_targets,
                    "source_predicate": real_predicate,
                },
            ),
            reason=reason,
            exit_block=_state_write_exit_block(body, 0),
            ordered_path=_state_write_ordered_path(body, 0),
            payload={
                "arm_exit_blocks": tuple(
                    _state_write_exit_block(body, index)
                    for index in range(len(writes))
                ),
                "arm_ordered_paths": tuple(
                    _state_write_ordered_path(body, index)
                    for index in range(len(writes))
                ),
                **dict(body.payload),
            },
        ),)
    return (_unresolved_fact(
        dispatch_map=dispatch_map,
        state=state,
        case_entry_block=entry_block,
        reason="case_body_state_write_count_unresolved",
        profile_name=profile_name,
        payload={"state_write_count": len(writes), **dict(body.payload)},
    ),)


def _diagnostic_fact(
    *,
    dispatch_map: StateDispatcherMap,
    state: int,
    row_kind: str,
    target_block: int,
    reason: str,
    profile_name: str,
) -> SwitchCaseTransitionFact:
    return SwitchCaseTransitionFact(
        fact_id=f"{profile_name}:case={state}:diagnostic:{row_kind}",
        transition_kind=SwitchCaseTransitionKind.DIAGNOSTIC,
        source_state=state,
        case_entry_block=target_block,
        state_var_stkoff=dispatch_map.state_var_stkoff,
        state_var_lvar_idx=dispatch_map.state_var_lvar_idx,
        proof=BranchOwnershipProof(
            proof_id=f"{profile_name}:case={state}:diagnostic:{row_kind}",
            proof_kind=BranchOwnershipProofKind.UNRESOLVED,
            trusted=False,
            reason=reason,
            source_state=state,
            source_block=target_block,
            target_entry=target_block,
            dispatcher_entry_block=dispatch_map.dispatcher_entry_block,
            oracle_kind="switch_case_dispatcher_row_diagnostic",
        ),
        reason=reason,
        row_kind=row_kind,
        target_block=target_block,
        payload={"profile_name": profile_name},
    )


def _state_write_exit_block(body: SwitchCaseBody, index: int) -> int | None:
    if index < len(body.state_write_exit_blocks):
        value = body.state_write_exit_blocks[index]
        return None if value is None else int(value)
    return body.entry_block


def _state_write_ordered_path(body: SwitchCaseBody, index: int) -> tuple[int, ...]:
    if index < len(body.state_write_ordered_paths):
        return tuple(int(serial) for serial in body.state_write_ordered_paths[index])
    return ()


def _return_exit_block(body: SwitchCaseBody, index: int) -> int | None:
    if index < len(body.return_exit_blocks):
        value = body.return_exit_blocks[index]
        return None if value is None else int(value)
    return body.entry_block


def _unresolved_fact(
    *,
    dispatch_map: StateDispatcherMap,
    state: int,
    case_entry_block: int | None,
    reason: str,
    profile_name: str,
    payload: dict[str, object] | None = None,
) -> SwitchCaseTransitionFact:
    return SwitchCaseTransitionFact(
        fact_id=f"{profile_name}:case={state}:unresolved:{reason}",
        transition_kind=SwitchCaseTransitionKind.UNRESOLVED,
        source_state=state,
        case_entry_block=case_entry_block,
        state_var_stkoff=dispatch_map.state_var_stkoff,
        state_var_lvar_idx=dispatch_map.state_var_lvar_idx,
        proof=BranchOwnershipProof(
            proof_id=f"{profile_name}:case={state}:unresolved:{reason}",
            proof_kind=BranchOwnershipProofKind.UNRESOLVED,
            trusted=False,
            reason=reason,
            source_state=state,
            source_block=case_entry_block,
            dispatcher_entry_block=dispatch_map.dispatcher_entry_block,
            oracle_kind="switch_case_transition_unresolved",
        ),
        reason=reason,
        payload={"profile_name": profile_name, **(payload or {})},
    )


def _hex_u64(value: int) -> str:
    return f"0x{int(value) & 0xFFFFFFFFFFFFFFFF:016x}"


def _hex_or_none(value: int | None) -> str | None:
    if value is None:
        return None
    return _hex_u64(value)


def _sqlite_i64(value: int | None) -> int | None:
    if value is None:
        return None
    value = int(value) & 0xFFFFFFFFFFFFFFFF
    if value >= 0x8000000000000000:
        value -= 0x10000000000000000
    return value


def _has_live_conditional_branch(
    mba: object,
    ordered_paths: tuple[tuple[int, ...], ...],
    dispatcher_blocks: frozenset[int],
) -> bool:
    visited: set[int] = set()
    for path in ordered_paths:
        for serial in path:
            if serial in visited or serial in dispatcher_blocks:
                continue
            visited.add(int(serial))
            blk = _get_block(mba, int(serial))
            if blk is not None and _block_nsucc(blk) > 1:
                return True
    return False


def _return_value_for_path(mba: object, ordered_path: tuple[int, ...]) -> int | None:
    try:
        import ida_hexrays

        m_ret = ida_hexrays.m_ret
    except Exception:
        m_ret = None
    from d810.recon.flow.bst_analysis import _get_mop_const_value

    for serial in reversed(tuple(int(value) for value in ordered_path)):
        blk = _get_block(mba, serial)
        if blk is None:
            continue
        insn = getattr(blk, "head", None)
        while insn is not None:
            if m_ret is not None and getattr(insn, "opcode", None) == m_ret:
                for attr in ("l", "r", "d"):
                    value = _get_mop_const_value(getattr(insn, attr, None))
                    if value is not None:
                        return int(value) & 0xFFFFFFFFFFFFFFFF
            insn = getattr(insn, "next", None)
    value = _return_value_from_frontier_writer(mba, ordered_path)
    if value is not None:
        return value
    return None


def _return_value_from_frontier_writer(
    mba: object,
    ordered_path: tuple[int, ...],
) -> int | None:
    try:
        import ida_hexrays

        m_mov = ida_hexrays.m_mov
        m_stx = ida_hexrays.m_stx
        m_add = ida_hexrays.m_add
        mop_r = ida_hexrays.mop_r
        mop_n = ida_hexrays.mop_n
        mop_l = ida_hexrays.mop_l
        mop_S = ida_hexrays.mop_S
        BLT_STOP = ida_hexrays.BLT_STOP
    except Exception:
        return None

    from d810.recon.flow.bst_analysis import _get_mop_const_value
    from d810.recon.flow.return_frontier_carrier_audit import _walk_to_return_writer

    path_blocks = {int(serial) for serial in ordered_path}
    for serial in _candidate_return_frontiers(mba, ordered_path, BLT_STOP):
        blk = _get_block(mba, serial)
        if blk is None:
            continue
        writers, _note = _walk_to_return_writer(
            mba,
            blk,
            m_mov=m_mov,
            m_stx=m_stx,
            m_add=m_add,
            mop_r=mop_r,
            mop_n=mop_n,
            mop_l=mop_l,
            mop_S=mop_S,
            return_stkoff=None,
        )
        selected = []
        for writer, writer_path in writers:
            if writer_path and int(writer_path[-1]) in path_blocks:
                selected.append((writer, writer_path))
        if selected:
            writers = selected
        for writer, _path in writers:
            value = _get_mop_const_value(getattr(writer, "l", None))
            if value is not None:
                return int(value) & 0xFFFFFFFFFFFFFFFF
    return None


def _candidate_return_frontiers(
    mba: object,
    ordered_path: tuple[int, ...],
    blt_stop: int,
) -> tuple[int, ...]:
    candidates: list[int] = []
    seen: set[int] = set()

    def add(serial: int) -> None:
        if serial not in seen:
            seen.add(serial)
            candidates.append(serial)

    for serial in reversed(tuple(int(value) for value in ordered_path)):
        blk = _get_block(mba, serial)
        if blk is None:
            continue
        if getattr(blk, "type", None) == blt_stop or _block_nsucc(blk) == 0:
            add(serial)

    if candidates:
        return tuple(candidates)

    # Terminal path summaries may stop at the case block before the shared
    # epilogue.  Follow the straight-line tail a short distance to find the
    # actual return frontier without interpreting or mutating the CFG.
    frontier = list(reversed(tuple(int(value) for value in ordered_path)))
    depth = 0
    while frontier and depth < 8:
        serial = frontier.pop(0)
        blk = _get_block(mba, serial)
        if blk is None:
            depth += 1
            continue
        if getattr(blk, "type", None) == blt_stop or _block_nsucc(blk) == 0:
            add(serial)
            break
        if _block_nsucc(blk) == 1:
            try:
                frontier.append(int(blk.succ(0)))
            except Exception:
                pass
        depth += 1
    return tuple(candidates)


def _get_block(mba: object, serial: int) -> object | None:
    try:
        if serial < 0 or serial >= int(getattr(mba, "qty")):
            return None
        return mba.get_mblock(serial)
    except Exception:
        return None


def _block_nsucc(blk: object) -> int:
    try:
        return int(blk.nsucc())
    except Exception:
        return 0


__all__ = [
    "SwitchCaseBody",
    "SwitchCaseTransitionFact",
    "SwitchCaseTransitionKind",
    "collect_switch_case_transition_facts",
    "collect_switch_case_transition_facts_from_mba",
]

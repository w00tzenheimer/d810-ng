"""Live switch-case transition adapter for switch-table dispatchers."""
from __future__ import annotations

from d810.analyses.control_flow.dispatcher_resolution import StateDispatcherMap
from d810.analyses.control_flow.switch_case_transition_analysis import (
    SwitchCaseBody,
    SwitchCaseTransitionFact,
    collect_switch_case_transition_facts,
)


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

    from d810.analyses.control_flow.state_machine_analysis import evaluate_handler_paths

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
            ordered_path = tuple(
                int(serial) for serial in getattr(path, "ordered_path", ()) or ()
            )
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


def _unresolved_fact(
    *,
    dispatch_map: StateDispatcherMap,
    state: int,
    case_entry_block: int | None,
    reason: str,
    profile_name: str,
) -> SwitchCaseTransitionFact:
    from d810.analyses.control_flow.switch_case_transition_analysis import _unresolved_fact as _pure

    return _pure(
        dispatch_map=dispatch_map,
        state=state,
        case_entry_block=case_entry_block,
        reason=reason,
        profile_name=profile_name,
    )


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
    from d810.backends.hexrays.evidence.bst_analysis import _get_mop_const_value

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

    from d810.backends.hexrays.evidence.bst_analysis import _get_mop_const_value
    from d810.backends.hexrays.evidence.dispatcher.return_frontier_carrier_audit import (
        _walk_to_return_writer,
    )

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

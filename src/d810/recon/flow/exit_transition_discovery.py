"""Exit-transition discovery helpers for late handler/BST recovery."""

from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.recon.flow.bst_analysis import resolve_via_bst_walk
from d810.recon.flow.bst_model import resolve_target_via_bst
from d810.recon.flow.transition_builder import _get_state_var_stkoff


@dataclass(frozen=True, slots=True)
class ExitTransitionCandidate:
    """One discovered redirect candidate from an exit-state family."""

    state_value: int
    from_block: int
    target_entry: int
    exit_state_value: int | None
    discovery_kind: str


def resolve_state_var_stkoff(
    *,
    detector: object | None,
    state_var: object | None,
) -> int | None:
    """Resolve the state-variable stack offset from detector or state var."""
    stkoff: int | None = None
    if detector is not None:
        try:
            stkoff = _get_state_var_stkoff(detector)
        except Exception:
            pass
    if stkoff is None and state_var is not None:
        try:
            if state_var.t == ida_hexrays.mop_S:
                stkoff = state_var.s.off
        except Exception:
            pass
    return stkoff


def collect_exit_transition_candidates(
    snapshot: object,
    *,
    sm: object,
    bst_result: object,
    handler_state_map: dict[int, int],
    bst_node_blocks: set[int],
    max_bfs_depth: int = 6,
) -> tuple[ExitTransitionCandidate, ...]:
    """Collect redirect candidates for handler exit-state recovery."""
    mba = getattr(snapshot, "mba", None)
    if mba is None:
        return ()

    stkoff = resolve_state_var_stkoff(
        detector=getattr(snapshot, "detector", None),
        state_var=getattr(sm, "state_var", None),
    )
    if stkoff is None:
        return ()

    state_to_entry: dict[int, int] = {v: k for k, v in handler_state_map.items()}
    exit_dispatcher = getattr(bst_result, "dispatcher", None)

    transitions = tuple(getattr(sm, "transitions", ()))
    handlers = dict(getattr(sm, "handlers", {}))

    states_with_outgoing: set[int] = {
        int(t.from_state)
        for t in transitions
        if getattr(t, "from_state", None) is not None
    }

    self_loop_only: set[int] = set()
    for state_val, handler in handlers.items():
        if state_val not in states_with_outgoing:
            continue
        handler_transitions = [t for t in transitions if t.from_state == state_val]
        all_self_loop = True
        for transition in handler_transitions:
            target = resolve_target_via_bst(bst_result, transition.to_state)
            if target is None or transition.from_block != target:
                all_self_loop = False
                break
        if all_self_loop and handler_transitions:
            self_loop_only.add(int(state_val))

    exit_states = [
        int(state_val)
        for state_val in handlers
        if state_val not in states_with_outgoing or state_val in self_loop_only
    ]
    if not exit_states:
        return ()

    candidates: list[ExitTransitionCandidate] = []
    for state_val in exit_states:
        handler = handlers[state_val]
        correct_entry = state_to_entry.get(state_val)
        if correct_entry is None and exit_dispatcher is not None:
            correct_entry = exit_dispatcher.lookup(state_val)

        if correct_entry is None:
            dispatcher_serial = int(getattr(snapshot, "bst_dispatcher_serial", -1))
            if dispatcher_serial < 0 or not bst_node_blocks:
                continue
            target_serial = resolve_via_bst_walk(
                mba,
                dispatcher_serial,
                state_val,
                bst_node_blocks,
            )
            if target_serial is None:
                continue

            from_block: int | None = None
            for transition in transitions:
                if getattr(transition, "to_state", None) == state_val:
                    from_block = int(transition.from_block)
                    break
            if from_block is None:
                handler_blocks = tuple(getattr(handler, "handler_blocks", ()))
                from_block = (
                    int(handler_blocks[0])
                    if handler_blocks
                    else int(getattr(handler, "check_block", -1))
                )
            if from_block in bst_node_blocks or from_block == target_serial:
                continue
            candidates.append(
                ExitTransitionCandidate(
                    state_value=state_val,
                    from_block=from_block,
                    target_entry=int(target_serial),
                    exit_state_value=None,
                    discovery_kind="bst_walk",
                )
            )
            continue

        visited: set[int] = set()
        queue: list[tuple[int, int]] = [(int(correct_entry), 0)]
        found_writes: list[tuple[int, int]] = []

        while queue:
            blk_serial, depth = queue.pop(0)
            if blk_serial in visited:
                continue
            visited.add(blk_serial)
            if blk_serial in bst_node_blocks:
                continue

            try:
                blk = mba.get_mblock(blk_serial)  # type: ignore[attr-defined]
            except Exception:
                blk = None
            if blk is None:
                continue

            insn = blk.head
            while insn is not None:
                if insn.opcode == ida_hexrays.m_mov:
                    d = insn.d
                    if (
                        d is not None
                        and d.t == ida_hexrays.mop_S
                        and d.s is not None
                        and d.s.off == stkoff
                        and insn.l is not None
                        and insn.l.t == ida_hexrays.mop_n
                    ):
                        found_writes.append((int(blk_serial), int(insn.l.nnn.value)))
                insn = insn.next

            if depth < max_bfs_depth:
                try:
                    nsucc = blk.nsucc()
                    for idx in range(nsucc):
                        succ_serial = int(blk.succ(idx))
                        if succ_serial not in visited:
                            queue.append((succ_serial, depth + 1))
                except Exception:
                    pass

        for write_blk, exit_state_value in found_writes:
            target_entry = resolve_target_via_bst(bst_result, exit_state_value)
            if target_entry is None or write_blk == target_entry:
                continue
            candidates.append(
                ExitTransitionCandidate(
                    state_value=state_val,
                    from_block=write_blk,
                    target_entry=int(target_entry),
                    exit_state_value=int(exit_state_value),
                    discovery_kind="write",
                )
            )

    return tuple(candidates)


__all__ = [
    "ExitTransitionCandidate",
    "collect_exit_transition_candidates",
    "resolve_state_var_stkoff",
]

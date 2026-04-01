"""Exit-transition discovery helpers for late handler/BST recovery."""

from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.recon.flow.bst_analysis import resolve_via_bst_walk
from d810.recon.flow.bst_model import resolve_target_via_bst
from d810.recon.flow.state_machine_analysis import evaluate_handler_paths
from d810.recon.flow.transition_builder import _get_state_var_stkoff


@dataclass(frozen=True, slots=True)
class ExitTransitionCandidate:
    """One discovered redirect candidate from an exit-state family."""

    state_value: int
    from_block: int
    target_entry: int
    exit_state_value: int | None
    discovery_kind: str


@dataclass(frozen=True, slots=True)
class BstDefaultTransitionCandidate:
    """One discovered redirect candidate from BST-default path evaluation."""

    handler_state: int
    handler_entry: int
    from_block: int
    target_entry: int
    final_state: int


@dataclass(frozen=True, slots=True)
class ValrangeExitTransitionCandidate:
    """One unresolved exit recovered via evaluator valranges."""

    from_state: int
    to_state: int
    from_block: int
    target_entry: int
    resolved_state_value: int


@dataclass(frozen=True, slots=True)
class ValrangeExitTransitionDiscovery:
    """Batch result for valrange-based unresolved exit recovery."""

    total_unresolved: int = 0
    candidates: tuple[ValrangeExitTransitionCandidate, ...] = ()


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


def collect_bst_default_transition_candidates(
    snapshot: object,
    *,
    sm: object,
    bst_result: object,
    handler_state_map: dict[int, int],
    bst_node_blocks: set[int],
) -> tuple[BstDefaultTransitionCandidate, ...]:
    """Collect raw BST-default transition candidates via handler-path eval."""
    mba = getattr(snapshot, "mba", None)
    if mba is None:
        return ()

    stkoff = resolve_state_var_stkoff(
        detector=getattr(snapshot, "detector", None),
        state_var=getattr(sm, "state_var", None),
    )
    if stkoff is None:
        return ()

    handler_entry_blocks: set[int] = set(handler_state_map.values())
    candidates: list[BstDefaultTransitionCandidate] = []
    for handler_state, handler_entry in handler_state_map.items():
        paths = evaluate_handler_paths(
            mba=mba,
            entry_serial=handler_entry,
            incoming_state=handler_state,
            bst_node_blocks=bst_node_blocks,
            state_var_stkoff=stkoff,
            handler_entry_blocks=handler_entry_blocks,
        )

        for path_result in paths:
            if path_result.final_state is None:
                continue

            final_state = path_result.final_state & 0xFFFFFFFF
            from_block = path_result.exit_block
            target_entry = resolve_target_via_bst(bst_result, final_state)
            if target_entry is None or from_block == target_entry:
                continue
            candidates.append(
                BstDefaultTransitionCandidate(
                    handler_state=handler_state,
                    handler_entry=handler_entry,
                    from_block=from_block,
                    target_entry=int(target_entry),
                    final_state=final_state,
                )
            )

    return tuple(candidates)


def collect_valrange_exit_transition_candidates(
    snapshot: object,
    *,
    sm: object,
    bst_result: object,
    resolve_state_via_valranges: object | None,
) -> ValrangeExitTransitionDiscovery:
    """Collect unresolved handler exits that valranges resolves to one target."""
    mba = getattr(snapshot, "mba", None)
    if mba is None or not callable(resolve_state_via_valranges):
        return ValrangeExitTransitionDiscovery()

    state_var = getattr(sm, "state_var", None)
    handlers = dict(getattr(sm, "handlers", {}) or {})
    if state_var is None or not handlers:
        return ValrangeExitTransitionDiscovery()

    already_resolved = set(getattr(snapshot, "resolved_transitions", ()) or ())
    candidates: list[ValrangeExitTransitionCandidate] = []
    total_unresolved = 0

    for handler in handlers.values():
        for transition in tuple(getattr(handler, "transitions", ())):
            key = (int(transition.from_state), int(transition.to_state))
            if key in already_resolved:
                continue

            total_unresolved += 1
            exit_serial = int(transition.from_block)
            try:
                exit_blk = mba.get_mblock(exit_serial)
            except Exception:
                exit_blk = None
            if exit_blk is None:
                continue

            tail_ins = getattr(exit_blk, "tail", None)
            if tail_ins is None:
                continue

            resolved_value = resolve_state_via_valranges(exit_blk, state_var, tail_ins)
            if resolved_value is None:
                continue

            target_entry = resolve_target_via_bst(bst_result, resolved_value)
            if target_entry is None:
                continue

            candidates.append(
                ValrangeExitTransitionCandidate(
                    from_state=int(transition.from_state),
                    to_state=int(transition.to_state),
                    from_block=exit_serial,
                    target_entry=int(target_entry),
                    resolved_state_value=int(resolved_value),
                )
            )

    return ValrangeExitTransitionDiscovery(
        total_unresolved=total_unresolved,
        candidates=tuple(candidates),
    )


__all__ = [
    "BstDefaultTransitionCandidate",
    "ExitTransitionCandidate",
    "ValrangeExitTransitionCandidate",
    "ValrangeExitTransitionDiscovery",
    "collect_bst_default_transition_candidates",
    "collect_exit_transition_candidates",
    "collect_valrange_exit_transition_candidates",
    "resolve_state_var_stkoff",
]

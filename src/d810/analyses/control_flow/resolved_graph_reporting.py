from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ResolvedStateMachineDotReport:
    dot_lines: tuple[str, ...]
    node_count: int
    edge_count: int
    resolved_count: int
    unresolved_count: int
    exit_count: int
    conditional_count: int


def build_resolved_state_machine_dot_report(
    sm: object,
    bst_result: object,
    handler_state_map: dict[int, int],
) -> ResolvedStateMachineDotReport:
    state_to_serial: dict[int, int] = {}
    for serial, state_val in handler_state_map.items():
        state_to_serial[int(state_val)] = int(serial)

    transitions_by_from: dict[int, list] = {}
    for transition in getattr(sm, "transitions", ()):
        if getattr(transition, "from_state", None) is not None:
            transitions_by_from.setdefault(int(transition.from_state), []).append(transition)

    node_states: set[int] = set()
    resolved_edges: list[tuple[int, int, bool]] = []
    exit_states: set[int] = set()
    unresolved_states: set[int] = set()

    range_map: dict[int, tuple[int | None, int | None]] = getattr(
        bst_result, "handler_range_map", {}
    ) or {}

    for state_val, _handler in getattr(sm, "handlers", {}).items():
        state_val = int(state_val)
        node_states.add(state_val)
        handler_transitions = transitions_by_from.get(state_val, [])

        if not handler_transitions:
            exit_states.add(state_val)
            continue

        has_resolved = False
        for transition in handler_transitions:
            target_entry = _resolve_target_via_range_map(
                bst_result=bst_result,
                range_map=range_map,
                to_state=int(transition.to_state),
            )
            if target_entry is None:
                continue
            target_state = handler_state_map.get(int(target_entry))
            if target_state is not None:
                resolved_edges.append(
                    (state_val, int(target_state), bool(getattr(transition, "is_conditional", False)))
                )
                has_resolved = True
            else:
                has_resolved = True

        if not has_resolved:
            unresolved_states.add(state_val)

    seen_edges: set[tuple[int, int, bool]] = set()
    unique_edges: list[tuple[int, int, bool]] = []
    for edge in resolved_edges:
        if edge in seen_edges:
            continue
        seen_edges.add(edge)
        unique_edges.append(edge)

    targets_per_handler: dict[int, set[int]] = {}
    for from_state, to_state, _is_conditional in unique_edges:
        targets_per_handler.setdefault(int(from_state), set()).add(int(to_state))
    conditional_states: set[int] = {
        int(state) for state, targets in targets_per_handler.items() if len(targets) >= 2
    }

    dot: list[str] = []
    dot.append("digraph resolved_state_machine {")
    dot.append("    rankdir=LR;")
    dot.append("    node [shape=record];")

    initial_state = getattr(sm, "initial_state", None)
    if initial_state is not None:
        dot.append("")
        dot.append("    START [shape=point];")
        dot.append('    START -> "0x%08X";' % int(initial_state))

    dot.append("")
    for state_val in sorted(node_states):
        serial = state_to_serial.get(int(state_val), -1)
        label_parts = ["0x%08X" % int(state_val), "blk[%d]" % int(serial)]

        if state_val in exit_states:
            label_parts.append("EXIT")
            dot.append(
                '    "0x%08X" [label="%s" style=filled fillcolor=lightgreen];'
                % (int(state_val), "\\n".join(label_parts))
            )
        elif state_val in unresolved_states:
            label_parts.append("UNRESOLVED")
            dot.append(
                '    "0x%08X" [label="%s" style=filled fillcolor=orange];'
                % (int(state_val), "\\n".join(label_parts))
            )
        elif state_val in conditional_states:
            label_parts.append("BRANCH")
            dot.append(
                '    "0x%08X" [label="%s" style=filled fillcolor=lightskyblue];'
                % (int(state_val), "\\n".join(label_parts))
            )
        else:
            dot.append(
                '    "0x%08X" [label="%s"];'
                % (int(state_val), "\\n".join(label_parts))
            )

    dot.append("")
    for from_state, to_state, is_conditional in unique_edges:
        if is_conditional:
            dot.append(
                '    "0x%08X" -> "0x%08X" [color=blue];'
                % (int(from_state), int(to_state))
            )
        else:
            dot.append(
                '    "0x%08X" -> "0x%08X";' % (int(from_state), int(to_state))
            )

    for state_val in sorted(unresolved_states):
        dot.append(
            '    "0x%08X" -> "0x%08X" [style=dashed color=red];'
            % (int(state_val), int(state_val))
        )

    dot.append("}")

    return ResolvedStateMachineDotReport(
        dot_lines=tuple(dot),
        node_count=len(node_states),
        edge_count=len(unique_edges),
        resolved_count=(len(node_states) - len(exit_states) - len(unresolved_states)),
        unresolved_count=len(unresolved_states),
        exit_count=len(exit_states),
        conditional_count=len(conditional_states),
    )


def _resolve_target_via_range_map(
    *,
    bst_result: object,
    range_map: dict[int, tuple[int | None, int | None]],
    to_state: int,
) -> int | None:
    resolve_target = getattr(bst_result, "resolve_target", None)
    if callable(resolve_target):
        target_entry = resolve_target(int(to_state))
        if target_entry is not None:
            return int(target_entry)

    for serial, (low, high) in range_map.items():
        lo = low if low is not None else 0
        hi = high if high is not None else 0xFFFFFFFF
        if int(lo) <= int(to_state) <= int(hi):
            return int(serial)
    return None


__all__ = [
    "ResolvedStateMachineDotReport",
    "build_resolved_state_machine_dot_report",
]

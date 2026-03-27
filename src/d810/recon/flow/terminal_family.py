from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, replace

import ida_hexrays

from d810.recon.flow.linearized_state_dag import SemanticEdgeKind, StateDagEdge


@dataclass(frozen=True, slots=True)
class TerminalFamilyCandidate:
    """One reachable projected terminal path that may need suffix privatization."""

    edge: StateDagEdge | None
    source_block: int
    branch_arm: int | None
    family_entry: int
    path: tuple[int, ...]
    stop_block: int
    materializer_block: int | None
    writer_block: int | None
    materializer_chain_blocks: tuple[int, ...]
    value_family_signature: tuple[object, ...]
    lineage_eas: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class TerminalFamilySeed:
    """One projected terminal-arm seed inspected for suffix privatization."""

    source_block: int
    branch_arm: int | None
    edge: StateDagEdge | None


@dataclass(frozen=True, slots=True)
class TerminalFamilySeedProbe:
    """One probed terminal-arm seed plus its pre-collection outcome."""

    seed: TerminalFamilySeed
    seed_origins: tuple[str, ...]
    source_reachable: bool
    source_nsucc: int | None
    arm_target: int | None
    arm_target_projected_only: bool
    family_entry: int | None
    family_entry_projected_only: bool
    path: tuple[int, ...]
    path_projected_only_blocks: tuple[int, ...]
    stop_block: int | None
    rejection_reason: str


def terminal_locator_key(mop: object | None) -> tuple[object, ...] | None:
    if mop is None:
        return None
    mop_type = getattr(mop, "t", None)
    if mop_type == getattr(ida_hexrays, "mop_S", None):
        stkoff = getattr(mop, "stkoff", None)
        if stkoff is None:
            stack_ref = getattr(mop, "s", None)
            stkoff = getattr(stack_ref, "off", None) if stack_ref is not None else None
        if stkoff is not None:
            return ("stk", int(stkoff), int(getattr(mop, "size", 0) or 0))
        return None
    if mop_type == getattr(ida_hexrays, "mop_r", None):
        reg = getattr(mop, "reg", None)
        if reg is None:
            reg = getattr(mop, "r", None)
        if reg is not None:
            return ("reg", int(reg), int(getattr(mop, "size", 0) or 0))
        return None
    return None


def terminal_source_signature(mop: object | None) -> tuple[object, ...]:
    if mop is None:
        return ("none",)

    locator = terminal_locator_key(mop)
    if locator is not None:
        return locator

    mop_type = getattr(mop, "t", None)
    if mop_type == getattr(ida_hexrays, "mop_n", None):
        value = getattr(mop, "value", None)
        if value is None:
            nnn = getattr(mop, "nnn", None)
            value = getattr(nnn, "value", None) if nnn is not None else None
        if value is not None:
            return ("const", int(value))
        return ("const", None)

    if mop_type == getattr(ida_hexrays, "mop_a", None):
        return ("ptr", int(getattr(mop, "size", 0) or 0))
    if mop_type == getattr(ida_hexrays, "mop_b", None):
        block_ref = getattr(mop, "block_ref", None)
        if block_ref is None:
            block_ref = getattr(mop, "b", None)
        return ("block", int(block_ref) if block_ref is not None else None)
    return (
        "mop",
        int(mop_type) if mop_type is not None else None,
        int(getattr(mop, "size", 0) or 0),
    )


def terminal_write_signature(insn: object) -> tuple[object, ...]:
    return (
        "op",
        int(getattr(insn, "opcode", 0)),
        "dst",
        terminal_locator_key(getattr(insn, "d", None))
        or terminal_source_signature(getattr(insn, "d", None)),
        "src_l",
        terminal_source_signature(getattr(insn, "l", None)),
        "src_r",
        terminal_source_signature(getattr(insn, "r", None)),
    )


def insn_is_copy_like(insn: object) -> bool:
    opcode = getattr(insn, "opcode", None)
    return opcode in (
        int(ida_hexrays.m_mov),
        int(ida_hexrays.m_xdu),
    )


def is_state_var_dest(insn: object, state_var_stkoff: int | None) -> bool:
    if state_var_stkoff is None:
        return False
    dest = getattr(insn, "d", None)
    if dest is None:
        return False
    if getattr(dest, "t", None) != getattr(ida_hexrays, "mop_S", None):
        return False
    stkoff = getattr(dest, "stkoff", None)
    if stkoff is None:
        stack_ref = getattr(dest, "s", None)
        stkoff = getattr(stack_ref, "off", None) if stack_ref is not None else None
    return stkoff is not None and int(stkoff) == int(state_var_stkoff)


def resolve_terminal_source_arm_entry(
    source_serial: int,
    branch_arm: int | None,
    *,
    projected_flow_graph,
    dispatcher_region: set[int],
) -> int | None:
    source_block = projected_flow_graph.get_block(source_serial)
    if source_block is None:
        return None

    candidate_targets: list[int] = []
    if branch_arm is not None and 0 <= int(branch_arm) < source_block.nsucc:
        candidate_targets.append(int(source_block.succs[int(branch_arm)]))
    elif source_block.nsucc == 1:
        candidate_targets.append(int(source_block.succs[0]))
    else:
        candidate_targets.extend(int(succ) for succ in source_block.succs)

    for target in candidate_targets:
        if target not in dispatcher_region:
            return target
    return None


def is_projected_only_block(
    block_serial: int,
    *,
    base_flow_graph,
) -> bool:
    return base_flow_graph.get_block(int(block_serial)) is None


def collect_linear_terminal_path(
    projected_flow_graph,
    *,
    start_block: int,
    dispatcher_region: set[int],
    limit: int = 64,
) -> tuple[int, ...] | None:
    path: list[int] = []
    current = int(start_block)
    visited: set[int] = set()

    while len(path) < limit:
        if current in visited or current in dispatcher_region:
            return None
        block = projected_flow_graph.get_block(current)
        if block is None:
            return None
        visited.add(current)
        path.append(current)
        if block.nsucc == 0:
            return tuple(path)
        if block.nsucc != 1:
            return None
        current = int(block.succs[0])
    return None


def probe_terminal_family_seed(
    seed: TerminalFamilySeed,
    *,
    base_flow_graph,
    projected_flow_graph,
    dispatcher_region: set[int],
    reachable_blocks: set[int],
) -> TerminalFamilySeedProbe:
    source_block = int(seed.source_block)
    source_snapshot = projected_flow_graph.get_block(source_block)
    source_reachable = source_block in reachable_blocks
    source_nsucc = int(source_snapshot.nsucc) if source_snapshot is not None else None

    arm_target: int | None = None
    family_entry: int | None = None
    path: tuple[int, ...] = ()
    stop_block: int | None = None
    rejection_reason = "accepted"

    if source_snapshot is None:
        rejection_reason = "source_missing"
    elif not source_reachable:
        rejection_reason = "source_unreachable"
    else:
        candidate_targets: list[int] = []
        if seed.branch_arm is not None:
            arm_index = int(seed.branch_arm)
            if 0 <= arm_index < source_snapshot.nsucc:
                arm_target = int(source_snapshot.succs[arm_index])
                candidate_targets.append(arm_target)
            else:
                rejection_reason = "arm_target_unresolved"
        elif source_snapshot.nsucc == 1:
            arm_target = int(source_snapshot.succs[0])
            candidate_targets.append(arm_target)
        else:
            candidate_targets.extend(int(succ) for succ in source_snapshot.succs)
            non_dispatcher_targets = [
                target for target in candidate_targets
                if target not in dispatcher_region
            ]
            if non_dispatcher_targets:
                arm_target = int(non_dispatcher_targets[0])

        if rejection_reason == "accepted":
            non_dispatcher_targets = [
                target for target in candidate_targets
                if target not in dispatcher_region
            ]
            if not non_dispatcher_targets:
                rejection_reason = "arm_target_dispatcher"
            else:
                family_entry = int(non_dispatcher_targets[0])
                if family_entry not in reachable_blocks:
                    rejection_reason = "family_entry_unreachable"
                else:
                    path = collect_linear_terminal_path(
                        projected_flow_graph,
                        start_block=family_entry,
                        dispatcher_region=dispatcher_region,
                    ) or ()
                    if not path:
                        rejection_reason = "terminal_path_non_linear"
                    elif len(path) < 2:
                        stop_block = int(path[-1])
                        rejection_reason = "terminal_path_too_short"
                    else:
                        stop_block = int(path[-1])
                        stop_snapshot = projected_flow_graph.get_block(stop_block)
                        if stop_snapshot is None:
                            rejection_reason = "stop_block_missing"
                        elif stop_snapshot.nsucc != 0:
                            rejection_reason = "stop_not_terminal"

    if stop_block is None and path:
        stop_block = int(path[-1])

    arm_target_projected_only = (
        arm_target is not None
        and is_projected_only_block(
            arm_target,
            base_flow_graph=base_flow_graph,
        )
    )
    family_entry_projected_only = (
        family_entry is not None
        and is_projected_only_block(
            family_entry,
            base_flow_graph=base_flow_graph,
        )
    )
    path_projected_only_blocks = tuple(
        int(block_serial)
        for block_serial in path
        if is_projected_only_block(
            int(block_serial),
            base_flow_graph=base_flow_graph,
        )
    )
    if (
        rejection_reason == "terminal_path_non_linear"
        and (
            arm_target_projected_only
            or family_entry_projected_only
            or path_projected_only_blocks
        )
    ):
        rejection_reason = "terminal_path_collapsed_into_projected_only"

    return TerminalFamilySeedProbe(
        seed=seed,
        seed_origins=(),
        source_reachable=source_reachable,
        source_nsucc=source_nsucc,
        arm_target=arm_target,
        arm_target_projected_only=arm_target_projected_only,
        family_entry=family_entry,
        family_entry_projected_only=family_entry_projected_only,
        path=path,
        path_projected_only_blocks=path_projected_only_blocks,
        stop_block=stop_block,
        rejection_reason=rejection_reason,
    )


def seed_terminal_family_probes(
    dag,
    *,
    base_flow_graph,
    projected_flow_graph,
    dispatcher_region: set[int],
    reachable_blocks: set[int],
) -> tuple[TerminalFamilySeedProbe, ...]:
    seeds_by_key: dict[tuple[int, int | None], TerminalFamilySeed] = {}
    seed_origins: defaultdict[tuple[int, int | None], set[str]] = defaultdict(set)

    for edge in dag.edges:
        if edge.kind != SemanticEdgeKind.CONDITIONAL_RETURN:
            continue
        source_block = int(edge.source_anchor.block_serial)
        branch_arm = (
            int(edge.source_anchor.branch_arm)
            if edge.source_anchor.branch_arm is not None
            else None
        )
        seed_key = (source_block, branch_arm)
        existing_seed = seeds_by_key.get(seed_key)
        if existing_seed is None or existing_seed.edge is None:
            seeds_by_key[seed_key] = TerminalFamilySeed(
                source_block=source_block,
                branch_arm=branch_arm,
                edge=edge,
            )
        seed_origins[seed_key].add("dag_edge")

    for source_block in sorted(int(serial) for serial in projected_flow_graph.blocks):
        if source_block in dispatcher_region:
            continue
        source_snapshot = projected_flow_graph.get_block(source_block)
        if source_snapshot is None or source_snapshot.nsucc < 2:
            continue
        for branch_arm in range(int(source_snapshot.nsucc)):
            seed_key = (int(source_block), int(branch_arm))
            seeds_by_key.setdefault(
                seed_key,
                TerminalFamilySeed(
                    source_block=int(source_block),
                    branch_arm=int(branch_arm),
                    edge=None,
                ),
            )
            seed_origins[seed_key].add("projected_cfg")

    probes: list[TerminalFamilySeedProbe] = []
    for seed in sorted(
        seeds_by_key.values(),
        key=lambda seed: (
            int(seed.source_block),
            -1 if seed.branch_arm is None else int(seed.branch_arm),
        ),
    ):
        probe = probe_terminal_family_seed(
            seed,
            base_flow_graph=base_flow_graph,
            projected_flow_graph=projected_flow_graph,
            dispatcher_region=dispatcher_region,
            reachable_blocks=reachable_blocks,
        )
        probe = replace(
            probe,
            seed_origins=tuple(
                sorted(
                    seed_origins[
                        (
                            int(seed.source_block),
                            int(seed.branch_arm) if seed.branch_arm is not None else None,
                        )
                    ]
                )
            ),
        )
        probes.append(probe)

    return tuple(probes)


def resolve_terminal_edge_entry(
    edge: StateDagEdge,
    *,
    projected_flow_graph,
    dispatcher_region: set[int],
) -> int | None:
    return resolve_terminal_source_arm_entry(
        int(edge.source_anchor.block_serial),
        (
            int(edge.source_anchor.branch_arm)
            if edge.source_anchor.branch_arm is not None
            else None
        ),
        projected_flow_graph=projected_flow_graph,
        dispatcher_region=dispatcher_region,
    )


def find_last_terminal_write(
    projected_flow_graph,
    *,
    path: tuple[int, ...],
    state_var_stkoff: int | None,
) -> tuple[int, int, object] | None:
    for block_serial in reversed(path):
        block = projected_flow_graph.get_block(block_serial)
        if block is None:
            continue
        for insn_index in range(len(block.insn_snapshots) - 1, -1, -1):
            insn = block.insn_snapshots[insn_index]
            if getattr(insn, "opcode", None) == int(ida_hexrays.m_goto):
                continue
            if getattr(insn, "d", None) is None:
                continue
            if is_state_var_dest(insn, state_var_stkoff):
                continue
            return int(block_serial), int(insn_index), insn
    return None


def find_prev_terminal_write_to_locator(
    projected_flow_graph,
    *,
    path: tuple[int, ...],
    locator: tuple[object, ...],
    before_block: int,
    before_insn_index: int,
    state_var_stkoff: int | None,
) -> tuple[int, int, object] | None:
    try:
        before_path_index = path.index(int(before_block))
    except ValueError:
        return None

    for path_index in range(before_path_index, -1, -1):
        block_serial = int(path[path_index])
        block = projected_flow_graph.get_block(block_serial)
        if block is None:
            continue
        start_index = len(block.insn_snapshots) - 1
        if path_index == before_path_index:
            start_index = int(before_insn_index) - 1
        for insn_index in range(start_index, -1, -1):
            insn = block.insn_snapshots[insn_index]
            if getattr(insn, "opcode", None) == int(ida_hexrays.m_goto):
                continue
            if getattr(insn, "d", None) is None:
                continue
            if is_state_var_dest(insn, state_var_stkoff):
                continue
            if terminal_locator_key(getattr(insn, "d", None)) != locator:
                continue
            return block_serial, int(insn_index), insn
    return None


def resolve_terminal_value_chain(
    projected_flow_graph,
    *,
    path: tuple[int, ...],
    state_var_stkoff: int | None,
) -> tuple[tuple[int, int, object], ...]:
    materializer = find_last_terminal_write(
        projected_flow_graph,
        path=path,
        state_var_stkoff=state_var_stkoff,
    )
    if materializer is None:
        return ()

    chain = [materializer]
    current = materializer
    visited_locators: set[tuple[object, ...]] = set()

    while True:
        _block_serial, _insn_index, insn = current
        if not insn_is_copy_like(insn):
            break
        locator = terminal_locator_key(getattr(insn, "l", None))
        if locator is None or locator in visited_locators:
            break
        visited_locators.add(locator)
        previous = find_prev_terminal_write_to_locator(
            projected_flow_graph,
            path=path,
            locator=locator,
            before_block=int(_block_serial),
            before_insn_index=int(_insn_index),
            state_var_stkoff=state_var_stkoff,
        )
        if previous is None:
            break
        chain.append(previous)
        current = previous

    chain.reverse()
    return tuple(chain)


def terminal_value_family_signature(
    chain: tuple[tuple[int, int, object], ...],
) -> tuple[object, ...]:
    if not chain:
        return ("unresolved_terminal_value",)
    semantic_chain = tuple(
        terminal_write_signature(insn)
        for _block_serial, _insn_index, insn in chain
    )
    return ("terminal_value_chain", semantic_chain)


def terminal_candidate_key(
    candidate: TerminalFamilyCandidate,
) -> tuple[int, int | None, int, tuple[int, ...]]:
    return (
        int(candidate.source_block),
        candidate.branch_arm,
        int(candidate.family_entry),
        tuple(int(s) for s in candidate.path),
    )


def candidate_shared_suffix_entries(
    candidates: tuple[TerminalFamilyCandidate, ...],
) -> dict[tuple[int, int | None, int, tuple[int, ...]], int]:
    suffix_entries: dict[tuple[int, int | None, int, tuple[int, ...]], int] = {}
    suffix_lengths: dict[tuple[int, int | None, int, tuple[int, ...]], int] = {}
    groups_by_suffix: dict[tuple[int, ...], list[TerminalFamilyCandidate]] = {}

    for candidate in candidates:
        for suffix_len in range(2, len(candidate.path) + 1):
            suffix = candidate.path[-suffix_len:]
            groups_by_suffix.setdefault(suffix, []).append(candidate)

    for suffix_serials, group_members in sorted(
        groups_by_suffix.items(),
        key=lambda item: (-len(item[0]), int(item[0][0])),
    ):
        unique_members: dict[
            tuple[int, int | None, int, tuple[int, ...]],
            TerminalFamilyCandidate,
        ] = {}
        for candidate in group_members:
            unique_members.setdefault(terminal_candidate_key(candidate), candidate)
        if len(unique_members) < 2:
            continue
        for candidate_key in unique_members:
            if len(suffix_serials) <= suffix_lengths.get(candidate_key, 0):
                continue
            suffix_entries[candidate_key] = int(suffix_serials[0])
            suffix_lengths[candidate_key] = len(suffix_serials)

    return suffix_entries


def build_terminal_family_candidates(
    seed_probes: tuple[TerminalFamilySeedProbe, ...],
    *,
    projected_flow_graph,
    state_var_stkoff: int | None,
) -> tuple[TerminalFamilyCandidate, ...]:
    candidates: list[TerminalFamilyCandidate] = []
    seen_keys: set[tuple[int, int | None, int, tuple[int, ...]]] = set()

    for probe in seed_probes:
        seed = probe.seed
        if probe.rejection_reason != "accepted":
            continue
        source_block = int(seed.source_block)
        family_entry = int(probe.family_entry)
        path = tuple(int(serial) for serial in probe.path)
        stop_block = int(probe.stop_block)

        chain = resolve_terminal_value_chain(
            projected_flow_graph,
            path=path,
            state_var_stkoff=state_var_stkoff,
        )
        materializer_block = int(chain[-1][0]) if chain else None
        writer_block = int(chain[0][0]) if chain else None
        materializer_chain_blocks = tuple(
            int(block_serial) for block_serial, _idx, _insn in chain
        )
        lineage_eas = tuple(int(getattr(insn, "ea", 0)) for _blk, _idx, insn in chain)
        signature = terminal_value_family_signature(chain)

        candidate = TerminalFamilyCandidate(
            edge=seed.edge,
            source_block=source_block,
            branch_arm=int(seed.branch_arm) if seed.branch_arm is not None else None,
            family_entry=family_entry,
            path=path,
            stop_block=stop_block,
            materializer_block=materializer_block,
            writer_block=writer_block,
            materializer_chain_blocks=materializer_chain_blocks,
            value_family_signature=signature,
            lineage_eas=lineage_eas,
        )
        candidate_key = terminal_candidate_key(candidate)
        if candidate_key in seen_keys:
            continue
        seen_keys.add(candidate_key)
        candidates.append(candidate)

    return tuple(candidates)


__all__ = [
    "TerminalFamilyCandidate",
    "TerminalFamilySeed",
    "TerminalFamilySeedProbe",
    "build_terminal_family_candidates",
    "candidate_shared_suffix_entries",
    "collect_linear_terminal_path",
    "find_last_terminal_write",
    "find_prev_terminal_write_to_locator",
    "insn_is_copy_like",
    "is_projected_only_block",
    "is_state_var_dest",
    "probe_terminal_family_seed",
    "resolve_terminal_edge_entry",
    "resolve_terminal_source_arm_entry",
    "resolve_terminal_value_chain",
    "seed_terminal_family_probes",
    "terminal_candidate_key",
    "terminal_locator_key",
    "terminal_source_signature",
    "terminal_value_family_signature",
    "terminal_write_signature",
]

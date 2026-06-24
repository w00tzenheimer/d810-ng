from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, replace

from d810.ir.expressions import ValueOpKind
from d810.ir.instructions import Instruction
from d810.ir.storage_identity import (
    StorageIdentityKind,
    storage_identity_from_varnode,
)
from d810.ir.varnode import Space, Varnode
from d810.analyses.control_flow.linearized_state_dag import SemanticEdgeKind, StateDagEdge


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


@dataclass(frozen=True, slots=True)
class TerminalValueWrite:
    """Canonical terminal-value write with lift provenance attached."""

    block_serial: int
    instruction_index: int
    instruction: Instruction
    provenance: object | None = None

    @property
    def ea(self) -> int:
        value = self.instruction.attrs.get("ea")
        if value is None and self.provenance is not None:
            value = getattr(self.provenance, "ea", 0)
        return int(value or 0)


def _locator_key_for_identity(
    identity,
    *,
    size: int,
) -> tuple[object, ...] | None:
    if identity is None:
        return None
    if identity.kind is StorageIdentityKind.STACK:
        return ("stk", int(identity.offset), int(size))
    if identity.kind is StorageIdentityKind.REGISTER:
        return ("reg", int(identity.offset), int(size))
    return None


def terminal_varnode_locator_key(vn: Varnode | None) -> tuple[object, ...] | None:
    if vn is None:
        return None
    return _locator_key_for_identity(
        storage_identity_from_varnode(vn),
        size=int(vn.size),
    )


def terminal_varnode_source_signature(vn: Varnode | None) -> tuple[object, ...]:
    if vn is None:
        return ("none",)
    locator = terminal_varnode_locator_key(vn)
    if locator is not None:
        return locator
    if vn.space is Space.CONST:
        return ("const", int(vn.offset))
    return ("varnode", vn.space.value, int(vn.offset), int(vn.size))


def terminal_instruction_write_signature(instruction: Instruction) -> tuple[object, ...]:
    inputs = instruction.inputs
    return (
        "op",
        getattr(instruction.operation, "value", str(instruction.operation)),
        "dst",
        terminal_varnode_locator_key(instruction.result)
        or terminal_varnode_source_signature(instruction.result),
        "src_l",
        terminal_varnode_source_signature(inputs[0] if len(inputs) >= 1 else None),
        "src_r",
        terminal_varnode_source_signature(inputs[1] if len(inputs) >= 2 else None),
    )


def terminal_write_signature(insn: object) -> tuple[object, ...]:
    if isinstance(insn, TerminalValueWrite):
        return terminal_instruction_write_signature(insn.instruction)
    if isinstance(insn, Instruction):
        return terminal_instruction_write_signature(insn)
    return ("unsupported_terminal_write", type(insn).__name__)


def insn_is_copy_like(insn: object) -> bool:
    if isinstance(insn, TerminalValueWrite):
        return terminal_instruction_is_copy_like(insn.instruction)
    if isinstance(insn, Instruction):
        return terminal_instruction_is_copy_like(insn)
    return False


def terminal_instruction_is_copy_like(instruction: Instruction) -> bool:
    return instruction.operation in {ValueOpKind.MOVE, ValueOpKind.ZEXT}


def instruction_writes_state_var(
    instruction: Instruction,
    state_var_stkoff: int | None,
) -> bool:
    if state_var_stkoff is None:
        return False
    identity = storage_identity_from_varnode(instruction.result)
    return (
        identity is not None
        and identity.kind is StorageIdentityKind.STACK
        and int(identity.offset) == int(state_var_stkoff)
    )


def is_state_var_dest(insn: object, state_var_stkoff: int | None) -> bool:
    if isinstance(insn, TerminalValueWrite):
        return instruction_writes_state_var(insn.instruction, state_var_stkoff)
    if isinstance(insn, Instruction):
        return instruction_writes_state_var(insn, state_var_stkoff)
    return False


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
) -> TerminalValueWrite | None:
    for block_serial in reversed(path):
        block = projected_flow_graph.get_block(block_serial)
        if block is None:
            continue
        instructions = tuple(getattr(block, "instructions", ()))
        for insn_index in range(len(instructions) - 1, -1, -1):
            instruction = instructions[insn_index]
            if instruction.result is None:
                continue
            if instruction_writes_state_var(instruction, state_var_stkoff):
                continue
            return TerminalValueWrite(
                block_serial=int(block_serial),
                instruction_index=int(insn_index),
                instruction=instruction,
            )
    return None


def find_prev_terminal_write_to_locator(
    projected_flow_graph,
    *,
    path: tuple[int, ...],
    locator: tuple[object, ...],
    before_block: int,
    before_insn_index: int,
    state_var_stkoff: int | None,
) -> TerminalValueWrite | None:
    try:
        before_path_index = path.index(int(before_block))
    except ValueError:
        return None

    for path_index in range(before_path_index, -1, -1):
        block_serial = int(path[path_index])
        block = projected_flow_graph.get_block(block_serial)
        if block is None:
            continue
        instructions = tuple(getattr(block, "instructions", ()))
        start_index = len(instructions) - 1
        if path_index == before_path_index:
            start_index = int(before_insn_index) - 1
        for insn_index in range(start_index, -1, -1):
            instruction = instructions[insn_index]
            if instruction.result is None:
                continue
            if instruction_writes_state_var(instruction, state_var_stkoff):
                continue
            if terminal_varnode_locator_key(instruction.result) != locator:
                continue
            return TerminalValueWrite(
                block_serial=block_serial,
                instruction_index=int(insn_index),
                instruction=instruction,
            )
    return None


def resolve_terminal_value_chain(
    projected_flow_graph,
    *,
    path: tuple[int, ...],
    state_var_stkoff: int | None,
) -> tuple[TerminalValueWrite, ...]:
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
        if not terminal_instruction_is_copy_like(current.instruction):
            break
        locator = terminal_varnode_locator_key(
            current.instruction.inputs[0] if current.instruction.inputs else None
        )
        if locator is None or locator in visited_locators:
            break
        visited_locators.add(locator)
        previous = find_prev_terminal_write_to_locator(
            projected_flow_graph,
            path=path,
            locator=locator,
            before_block=int(current.block_serial),
            before_insn_index=int(current.instruction_index),
            state_var_stkoff=state_var_stkoff,
        )
        if previous is None:
            break
        chain.append(previous)
        current = previous

    chain.reverse()
    return tuple(chain)


def terminal_value_family_signature(
    chain: tuple[TerminalValueWrite, ...],
) -> tuple[object, ...]:
    if not chain:
        return ("unresolved_terminal_value",)
    semantic_chain = tuple(
        terminal_write_signature(write)
        for write in chain
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
        materializer_block = int(chain[-1].block_serial) if chain else None
        writer_block = int(chain[0].block_serial) if chain else None
        materializer_chain_blocks = tuple(
            int(write.block_serial) for write in chain
        )
        lineage_eas = tuple(int(write.ea) for write in chain)
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
    "TerminalValueWrite",
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
    "terminal_varnode_locator_key",
    "terminal_varnode_source_signature",
    "terminal_value_family_signature",
    "terminal_write_signature",
]

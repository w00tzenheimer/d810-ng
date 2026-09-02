"""Exact state-dispatcher row model.

This model is intentionally dispatcher-shape neutral. Equality chains,
interval trees, and future switch-table adapters can all provide the same
core relation: concrete state constant -> handler entry block.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from d810.analyses.control_flow.comparison_dispatcher_model import (
    build_partition,
    route_via_interval_sets,
)
from d810.capabilities.dispatcher import RouterKind, TableProvenance
from d810.analyses.control_flow.route_comparison import current_u32_route_comparison
from d810.analyses.control_flow.route_predicate import satisfying_set
from d810.ir.flowgraph import FlowGraph, InsnKind, OperandKind
from d810.ir.graph_fingerprint import (
    InsnRecord,
    instruction_projection_without_block_references,
)
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind


@dataclass(frozen=True, slots=True)
class InitialStateWriteWitness:
    """The single physical write selected by initial-state recovery.

    This is recovery evidence, not a route allowance.  It retains the stable
    source coordinates which older recovery collapsed into ``initial_state``.
    Consumers must rebind this exact write; they must not rediscover one by
    scanning an arbitrary prologue corridor.
    """

    source_block_serial: int
    source_instruction: InsnRecord
    state_identity: StorageIdentity
    width: int
    normalized_state: int
    dispatcher_entry_serial: int
    redirect_predecessor_serial: int
    delivery_path_serials: tuple[int, ...]
    delivery_path_edges: tuple[tuple[int, int], ...]
    # Optional closure for a preheader write whose feasibility depends on a
    # second selector value and the exact conditional edge into the dispatcher.
    # All fields are present together or absent together; older direct P/D
    # witnesses intentionally use the latter form.
    selector_instruction: InsnRecord | None = None
    selector_identity: StorageIdentity | None = None
    selector_width: int | None = None
    selector_value: int | None = None
    comparison_instruction: InsnRecord | None = None
    comparison_identity: StorageIdentity | None = None
    comparison_constant: int | None = None
    comparison_true_target_serial: int | None = None
    comparison_false_target_serial: int | None = None
    comparison_selected_target_serial: int | None = None

    def __post_init__(self) -> None:
        if int(self.source_block_serial) < 0 or int(self.dispatcher_entry_serial) < 0:
            raise ValueError("initial-state write source serial must be non-negative")
        if type(self.source_instruction) is not InsnRecord:
            raise TypeError("initial-state write requires exact InsnRecord")
        if not isinstance(self.state_identity, StorageIdentity):
            raise TypeError("initial-state write requires typed storage identity")
        if self.state_identity.kind is not StorageIdentityKind.STACK or int(self.width) != 4:
            raise ValueError("initial-state write requires a U32 stack state slot")
        source_ea = int(self.source_instruction.native_ea or self.source_instruction.ea)
        if not 0 < source_ea < 0xFFFFFFFFFFFFFFFF:
            raise ValueError("initial-state write instruction must have a native EA")
        dest = self.source_instruction.d
        if self.source_instruction.kind not in {InsnKind.MOV, InsnKind.STORE}:
            raise ValueError("initial-state write requires MOV or STORE")
        if dest is None or dest.stkoff != int(self.state_identity.offset) or int(dest.size) != 4:
            raise ValueError("initial-state write destination differs from typed state slot")
        serials = tuple(int(item) for item in self.delivery_path_serials)
        edges = tuple((int(left), int(right)) for left, right in self.delivery_path_edges)
        if (
            not serials
            or serials[0] != int(self.source_block_serial)
            or serials[-1] != int(self.dispatcher_entry_serial)
            or len(serials) < 2
            or serials[-2] != int(self.redirect_predecessor_serial)
            or len(set(serials)) != len(serials)
            or len(edges) != len(serials) - 1
            or tuple(left for left, _ in edges) != serials[:-1]
            or tuple(right for _, right in edges) != serials[1:]
        ):
            raise ValueError("initial-state write requires one exact W-to-dispatcher corridor")
        object.__setattr__(self, "source_block_serial", int(self.source_block_serial))
        object.__setattr__(self, "dispatcher_entry_serial", int(self.dispatcher_entry_serial))
        object.__setattr__(self, "redirect_predecessor_serial", int(self.redirect_predecessor_serial))
        object.__setattr__(self, "width", 4)
        object.__setattr__(self, "normalized_state", int(self.normalized_state) & 0xFFFFFFFF)
        object.__setattr__(self, "delivery_path_serials", serials)
        object.__setattr__(self, "delivery_path_edges", edges)
        selector_values = (
            self.selector_instruction, self.selector_identity, self.selector_width,
            self.selector_value, self.comparison_instruction, self.comparison_identity,
            self.comparison_constant, self.comparison_true_target_serial,
            self.comparison_false_target_serial, self.comparison_selected_target_serial,
        )
        if any(value is not None for value in selector_values):
            if any(value is None for value in selector_values):
                raise ValueError("feasible entry witness selector closure is incomplete")
            if (
                type(self.selector_instruction) is not InsnRecord
                or not isinstance(self.selector_identity, StorageIdentity)
                or int(self.selector_width) != 4
                or type(self.comparison_instruction) is not InsnRecord
                or self.comparison_identity != self.selector_identity
                or int(self.comparison_selected_target_serial)
                != int(self.dispatcher_entry_serial)
                or int(self.comparison_selected_target_serial) not in {
                    int(self.comparison_true_target_serial),
                    int(self.comparison_false_target_serial),
                }
            ):
                raise ValueError("feasible entry witness selector closure is invalid")
            selector_dest = self.selector_instruction.d
            if (
                self.selector_instruction.kind not in {InsnKind.MOV, InsnKind.STORE}
                or selector_dest is None
                or selector_dest.stkoff != int(self.selector_identity.offset)
                or int(selector_dest.size) != 4
                or int(self.selector_instruction.native_ea or self.selector_instruction.ea) <= 0
                or int(self.comparison_instruction.native_ea or self.comparison_instruction.ea) <= 0
            ):
                raise ValueError("feasible entry witness selector operation drifted")
            object.__setattr__(self, "selector_width", 4)
            object.__setattr__(self, "selector_value", int(self.selector_value) & 0xFFFFFFFF)
            object.__setattr__(self, "comparison_constant", int(self.comparison_constant) & 0xFFFFFFFF)
            object.__setattr__(self, "comparison_true_target_serial", int(self.comparison_true_target_serial))
            object.__setattr__(self, "comparison_false_target_serial", int(self.comparison_false_target_serial))
            object.__setattr__(self, "comparison_selected_target_serial", int(self.comparison_selected_target_serial))


def _writes_u32_stack_identity(
    instruction: object,
    identity: StorageIdentity,
) -> bool:
    """Whether an instruction defines the typed U32 state namespace."""
    if not hasattr(instruction, "kind") or not hasattr(instruction, "d"):
        return False
    destination = instruction.d
    return bool(
        destination is not None
        and destination.kind is OperandKind.STACK
        and destination.stkoff is not None
        and int(destination.stkoff) == int(identity.offset)
        and int(destination.size) == 4
    )


def _is_exact_u32_stack_write(
    instruction: object,
    identity: StorageIdentity,
) -> bool:
    """Whether ``instruction`` is an admissible literal state assignment."""
    return bool(
        hasattr(instruction, "kind")
        and instruction.kind in {InsnKind.MOV, InsnKind.STORE}
        and _writes_u32_stack_identity(instruction, identity)
    )


def _exact_projected_instruction_in_block(
    block: object,
    expected: InsnRecord,
) -> tuple[int, object] | None:
    matches = tuple(
        (index, instruction)
        for index, instruction in enumerate(block.insn_snapshots)
        if instruction_projection_without_block_references(instruction) == expected
    )
    return matches[0] if len(matches) == 1 else None


def _write_is_effective_along_path(
    graph: FlowGraph,
    path: tuple[int, ...],
    source_index: int,
    identity: StorageIdentity,
) -> bool:
    """Reject a definition superseded anywhere on its exact delivery path."""
    for path_index, serial in enumerate(path):
        block = graph.get_block(int(serial))
        if block is None:
            return False
        start = source_index + 1 if path_index == 0 else 0
        for instruction in block.insn_snapshots[start:]:
            if _writes_u32_stack_identity(instruction, identity):
                return False
    return True


def _delivered_state_write_is_effective(
    graph: FlowGraph,
    witness: InitialStateWriteWitness,
    source_index: int,
) -> bool:
    """Reject a write superseded before the recorded dispatcher delivery.

    The witness is deliberately a *definition-to-use* claim.  A matching
    scalar somewhere in a prologue does not remain authority once a later
    write to the state namespace is possible on its asserted corridor.
    """
    return _write_is_effective_along_path(
        graph,
        witness.delivery_path_serials,
        source_index,
        witness.state_identity,
    )


def _unique_current_delivery_prefix(
    graph: FlowGraph,
    witness: InitialStateWriteWitness,
) -> tuple[int, ...] | None:
    """Recompute the unique current source-to-predecessor cut path."""
    source = int(witness.source_block_serial)
    predecessor = int(witness.redirect_predecessor_serial)
    dispatcher = int(witness.dispatcher_entry_serial)
    pending: list[tuple[int, tuple[int, ...]]] = [(source, (source,))]
    paths: list[tuple[int, ...]] = []
    while pending and len(paths) < 2:
        serial, path = pending.pop()
        if serial == predecessor:
            paths.append(path)
            continue
        block = graph.get_block(serial)
        if block is None:
            return None
        for successor in block.succs:
            target = int(successor)
            if target == dispatcher or target in path:
                continue
            pending.append((target, (*path, target)))
    return paths[0] if len(paths) == 1 else None


def _selector_closure_rebinds(
    graph: FlowGraph,
    witness: InitialStateWriteWitness,
) -> bool:
    """Rebind the optional selector/comparison proof against current CFG data."""
    selector_fields = (
        witness.selector_instruction, witness.selector_identity, witness.selector_width,
        witness.selector_value, witness.comparison_instruction, witness.comparison_identity,
        witness.comparison_constant, witness.comparison_true_target_serial,
        witness.comparison_false_target_serial, witness.comparison_selected_target_serial,
    )
    has_closure = any(item is not None for item in selector_fields)
    predecessor = graph.get_block(int(witness.redirect_predecessor_serial))
    if predecessor is None:
        return False
    if len(tuple(predecessor.succs)) == 1:
        # A direct edge needs no feasibility proof; reject surplus closure data
        # so producers cannot hide a stale conditional claim in a direct route.
        return not has_closure
    if len(tuple(predecessor.succs)) != 2 or not has_closure:
        return False
    if any(item is None for item in selector_fields):
        return False
    source = graph.get_block(int(witness.source_block_serial))
    if source is None:
        return False
    selected_selector = _exact_projected_instruction_in_block(
        source, witness.selector_instruction)
    if selected_selector is None:
        return False
    selector_index, selector = selected_selector
    if (
        not _is_exact_u32_stack_write(selector, witness.selector_identity)
        or int(selector.l.value if selector.l is not None and selector.l.value is not None else -1)
        != int(witness.selector_value)
        or int(selector.l.size if selector.l is not None else -1) != 4
        or not _write_is_effective_along_path(
            graph,
            witness.delivery_path_serials[:-1],
            selector_index,
            witness.selector_identity,
        )
    ):
        return False
    current = current_u32_route_comparison(
        graph,
        int(witness.redirect_predecessor_serial),
        expected_identities=frozenset({witness.selector_identity}),
    )
    if current is None:
        return False
    comparison, identity, _block_ea, _branch_ea = current
    branch_matches = tuple(
        instruction_projection_without_block_references(instruction)
        for instruction in predecessor.insn_snapshots
        if instruction.control_transfer_kind.name == "CONDITIONAL_BRANCH"
    )
    if (
        len(branch_matches) != 1
        or branch_matches[0] != witness.comparison_instruction
        or identity != witness.comparison_identity
        or identity != witness.selector_identity
        or int(comparison.const) != int(witness.comparison_constant)
        or int(comparison.true_target) != int(witness.comparison_true_target_serial)
        or int(comparison.false_target) != int(witness.comparison_false_target_serial)
    ):
        return False
    selected = (
        int(comparison.true_target)
        if satisfying_set(32, comparison.op, int(comparison.const)).contains(
            int(witness.selector_value)
        )
        else int(comparison.false_target)
    )
    return (
        selected == int(witness.comparison_selected_target_serial)
        and selected == int(witness.dispatcher_entry_serial)
    )


def bind_initial_state_write_witness(
    graph: FlowGraph,
    witness: InitialStateWriteWitness | None,
) -> InitialStateWriteWitness | None:
    """Rebind one initial-state definition-to-dispatcher proof exactly once.

    This is the portable analysis owner for entry-delivery authority.  The
    emitter must consume this result, never recreate a weaker corridor check.
    """
    if witness is None:
        return None
    try:
        path = tuple(int(item) for item in witness.delivery_path_serials)
        edges = tuple((int(left), int(right)) for left, right in witness.delivery_path_edges)
        if (
            not path
            or path[0] != int(witness.source_block_serial)
            or path[-1] != int(witness.dispatcher_entry_serial)
            or len(path) < 2
            or path[-2] != int(witness.redirect_predecessor_serial)
            or edges != tuple(zip(path, path[1:]))
            or witness.state_identity.kind is not StorageIdentityKind.STACK
            or int(witness.width) != 4
            or _unique_current_delivery_prefix(graph, witness) != path[:-1]
        ):
            return None
        for source_serial, target_serial in edges:
            source = graph.get_block(source_serial)
            target = graph.get_block(target_serial)
            if (
                source is None or target is None
                or target_serial not in tuple(int(item) for item in source.succs)
                or source_serial not in tuple(int(item) for item in target.preds)
            ):
                return None
        source = graph.get_block(int(witness.source_block_serial))
        if source is None:
            return None
        selected = _exact_projected_instruction_in_block(source, witness.source_instruction)
        if selected is None:
            return None
        source_index, current_write = selected
        if (
            not _is_exact_u32_stack_write(current_write, witness.state_identity)
            or current_write.l is None
            or current_write.l.kind is not OperandKind.NUMBER
            or current_write.l.value is None
            or int(current_write.l.size) != 4
            or (int(current_write.l.value) & 0xFFFFFFFF) != int(witness.normalized_state)
            or not _delivered_state_write_is_effective(graph, witness, source_index)
            or not _selector_closure_rebinds(graph, witness)
        ):
            return None
    except (AttributeError, TypeError, ValueError):
        return None
    return witness


def initial_state_write_witness_from_entry_cut(
    graph: FlowGraph,
    entry: int,
    stkoff: int,
    initial_state: int,
) -> InitialStateWriteWitness | None:
    """Mint the unique physical initial-state writer in an exact entry cut.

    A recovered scalar is deliberately insufficient authority for an entry
    redirect.  This binds it to one literal U32 stack write and one unique
    source-to-dispatcher corridor.  Equal writes are accepted only when a
    second selector write proves the precise predecessor-to-dispatcher arm.
    """
    reachable: set[int] = set()
    stack = [int(graph.entry_serial)]
    while stack:
        serial = stack.pop()
        if serial in reachable or serial not in graph.blocks:
            continue
        reachable.add(serial)
        if serial == int(entry):
            continue
        stack.extend(int(successor) for successor in graph.blocks[serial].succs)

    occurrences: list[tuple[int, InsnRecord]] = []
    for serial in sorted(reachable):
        block = graph.blocks.get(serial)
        if block is None:
            continue
        writes = tuple(
            insn for insn in block.insn_snapshots
            if (
                insn.kind in {InsnKind.MOV, InsnKind.STORE}
                and insn.d is not None
                and insn.d.kind is OperandKind.STACK
                and insn.d.stkoff is not None
                and int(insn.d.stkoff) == int(stkoff)
                and int(insn.d.size) == 4
                and insn.l is not None
                and insn.l.kind is OperandKind.NUMBER
                and int(insn.l.size) == 4
                and insn.l.value is not None
                and (int(insn.l.value) & 0xFFFFFFFF)
                == (int(initial_state) & 0xFFFFFFFF)
            )
        )
        if len(writes) != 1:
            continue
        write = writes[0]
        if not 0 < int(write.native_ea or write.ea) < 0xFFFFFFFFFFFFFFFF:
            continue
        occurrences.append(
            (serial, instruction_projection_without_block_references(write))
        )

    qualifying = [
        int(pred) for pred in graph.blocks[int(entry)].preds
        if int(pred) in reachable
    ]
    if len(qualifying) != 1:
        return None
    predecessor = qualifying[0]

    def unique_path(source: int) -> tuple[int, ...] | None:
        queue = [(source, (source,))]
        paths: list[tuple[int, ...]] = []
        while queue:
            serial, path = queue.pop(0)
            if serial == predecessor:
                paths.append(path)
                continue
            for successor in graph.blocks[serial].succs:
                if int(successor) in reachable and int(successor) not in path:
                    queue.append((int(successor), (*path, int(successor))))
        return paths[0] if len(paths) == 1 else None

    candidates = [
        (source, instruction, path, None)
        for source, instruction in occurrences
        if (path := unique_path(source)) is not None
    ]
    # A conditional predecessor is not a simple delivery merely because it has
    # one recovered writer.  It needs the exact selector/comparison closure.
    if len(tuple(graph.blocks[predecessor].succs)) != 1:
        candidates = []
    if len(candidates) != 1:
        feasible: list[tuple[int, InsnRecord, tuple[int, ...], tuple[InsnRecord, StorageIdentity, object, int]]] = []
        state_identity = StorageIdentity(StorageIdentityKind.STACK, int(stkoff))
        for source, instruction in occurrences:
            block = graph.blocks[source]
            for selector_index, selector in enumerate(block.insn_snapshots):
                if (
                    selector.kind not in {InsnKind.MOV, InsnKind.STORE}
                    or selector.d is None
                    or selector.d.kind is not OperandKind.STACK
                    or selector.l is None
                    or selector.l.kind is not OperandKind.NUMBER
                    or selector.l.value is None
                    or int(selector.d.size) != 4
                    or int(selector.l.size) != 4
                ):
                    continue
                selector_identity = StorageIdentity(
                    StorageIdentityKind.STACK, int(selector.d.stkoff)
                )
                if selector_identity == state_identity:
                    continue
                comparison_current = current_u32_route_comparison(
                    graph, predecessor,
                    expected_identities=frozenset({selector_identity}),
                )
                if comparison_current is None:
                    continue
                comparison, identity, _block_ea, _branch_ea = comparison_current
                value = int(selector.l.value) & 0xFFFFFFFF
                selected = (
                    int(comparison.true_target)
                    if satisfying_set(
                        32, comparison.op, int(comparison.const),
                    ).contains(value)
                    else int(comparison.false_target)
                )
                path = unique_path(source)
                if (
                    identity == selector_identity
                    and selected == int(entry)
                    and path is not None
                    and _write_is_effective_along_path(
                        graph,
                        path,
                        selector_index,
                        selector_identity,
                    )
                ):
                    feasible.append((
                        source, instruction, path,
                        (selector, selector_identity, comparison, selected),
                    ))
        if len(feasible) != 1:
            return None
        candidates = feasible

    source, instruction, prefix_path, selector_closure = candidates[0]
    path = (*prefix_path, int(entry))
    selector_kwargs = {}
    if selector_closure is not None:
        selector, selector_identity, comparison, selected = selector_closure
        branch = next(
            item for item in graph.blocks[predecessor].insn_snapshots
            if item.control_transfer_kind.name == "CONDITIONAL_BRANCH"
        )
        selector_kwargs = dict(
            selector_instruction=instruction_projection_without_block_references(selector),
            selector_identity=selector_identity,
            selector_width=4,
            selector_value=int(selector.l.value),
            comparison_instruction=instruction_projection_without_block_references(branch),
            comparison_identity=selector_identity,
            comparison_constant=int(comparison.const),
            comparison_true_target_serial=int(comparison.true_target),
            comparison_false_target_serial=int(comparison.false_target),
            comparison_selected_target_serial=int(selected),
        )
    witness = InitialStateWriteWitness(
        source, instruction, StorageIdentity(StorageIdentityKind.STACK, int(stkoff)),
        4, int(initial_state), int(entry), predecessor, path,
        tuple(zip(path, path[1:])), **selector_kwargs,
    )
    return bind_initial_state_write_witness(graph, witness)


@dataclass(frozen=True, slots=True)
class DispatcherCandidateIdentity:
    """Stable identity of one dispatcher candidate across FlowGraph relifts.

    Block serials are deliberately excluded: they are snapshot-local.  The
    resolver provenance, native dispatcher EA, and state storage identify the
    candidate whose exact graph-local attempt stalled without suppressing a
    different dispatcher in the same function.
    """

    resolver_name: str
    router_kind: RouterKind
    table_provenance: TableProvenance | None
    dispatcher_entry_ea: int
    state_location_kind: str
    state_location_value: int | None


@dataclass(frozen=True, slots=True)
class StateDispatcherRow:
    """One exact dispatcher row: ``state_const`` routes to ``target_block``."""

    state_const: int
    target_block: int
    dispatcher_block: int
    compare_block: int | None
    branch_kind: str
    router_kind: RouterKind
    confidence: float = 1.0
    row_kind: str = "handler"
    table_provenance: TableProvenance | None = None
    payload: dict[str, object] = field(default_factory=dict)

    @property
    def is_handler_row(self) -> bool:
        """Whether this row names a semantic handler entry."""
        return self.row_kind in {"handler", "handler_alias"}

    @property
    def is_dispatcher_self_loop(self) -> bool:
        """Whether this exact state routes back to the dispatcher."""
        return self.row_kind == "dispatcher_self_loop"


@dataclass(frozen=True, slots=True)
class StateDispatcherMap:
    """Exact dispatcher table for one dispatcher entry."""

    rows: tuple[StateDispatcherRow, ...]
    dispatcher_entry_block: int
    dispatcher_blocks: frozenset[int]
    state_var_stkoff: int | None
    state_var_lvar_idx: int | None
    router_kind: RouterKind
    initial_state: int | None = None
    default_target_block: int | None = None
    default_row_kind: str | None = None
    table_provenance: TableProvenance | None = None
    # Register id of a REGISTER-resident state variable (d81-3rja): set ONLY when
    # the voted state var is a register with no stack home
    # (``state_var_stkoff is None``). Every stack-resident golden keeps this
    # ``None``, so the disjoint register-lowering path never fires for them.
    # Appended last with a default so the 9 positional/keyword construction sites
    # stay byte-identical.
    state_var_reg: int | None = None

    def state_to_handler(self) -> dict[int, int]:
        """Return exact routable ``state_const -> target_block`` rows.

        This intentionally includes exact dispatcher self-loop rows: they are
        part of the state-machine table even though older handler-map adapters
        skip them. Diagnostic rows that do not name live handler/self-loop
        blocks are preserved in ``rows`` but are not routable CFG targets.
        """
        return {
            int(row.state_const): int(row.target_block)
            for row in self.rows
            if row.is_handler_row or row.is_dispatcher_self_loop
        }

    def handler_state_map(self) -> dict[int, int]:
        """Return lossy ``handler_block -> first_state_const`` adapter rows.

        ``DispatcherHandlerMap`` cannot represent switch aliases or dispatcher
        self-loops. Keep those in ``StateDispatcherMap.rows`` and expose only a
        compatibility view here for existing consumers.
        """
        handler_map: dict[int, int] = {}
        for row in self.rows:
            if not row.is_handler_row:
                continue
            handler_map.setdefault(int(row.target_block), int(row.state_const))
        return handler_map

    def states_by_target(self) -> dict[int, tuple[int, ...]]:
        """Return every exact state value grouped by target block."""
        grouped: dict[int, list[int]] = {}
        for row in self.rows:
            grouped.setdefault(int(row.target_block), []).append(int(row.state_const))
        return {target: tuple(states) for target, states in grouped.items()}

    def resolve_target(self, state_value: int) -> int | None:
        """Resolve a concrete state value to a handler block (EXACT rows only).

        Routes through the ONE mechanism -- the abstract-domain
        :class:`IntervalSet` partition (:func:`build_partition` over this map's
        exact rows as singletons, then :func:`route_via_interval_sets` membership)
        -- so there is no separate ``dict.get`` resolution path.  Exact-only here;
        range routing needs a ``ComparisonDispatcherModel`` built with range evidence.
        """
        return route_via_interval_sets(
            state_value,
            target_intervals=build_partition(self.state_to_handler()),
        )

    def to_dispatcher_handler_map(self):
        """Convert to the existing dispatcher-agnostic handler map."""
        from d810.analyses.control_flow.dispatcher_handler_map import (
            DispatcherHandlerMap,
        )

        return DispatcherHandlerMap.from_state_dispatcher_map(self)


@dataclass(frozen=True, slots=True)
class ResolverCandidate:
    """Ranked dispatcher-resolver evidence (LS11 C6).

    A candidate is NOT a bool ownership claim -- it is ranked evidence that a
    resolver could resolve a dispatcher.  ``accepts()`` returns this, never a
    bool, so the resolver chain can rank competing providers deterministically.
    """

    resolver_name: str
    router_kind: RouterKind
    confidence: float
    specificity: int = 0
    table_provenance: TableProvenance | None = None
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DispatcherResolution:
    """Provenance envelope around the selected ``StateDispatcherMap`` (LS11 C6).

    ``resolve()`` may fail after ``accepts()`` succeeds; on success it returns
    this envelope so strategies consume stable ``dispatcher_map`` evidence plus
    the resolver/confidence/ranking provenance.
    """

    dispatcher_map: StateDispatcherMap
    resolver_name: str
    router_kind: RouterKind
    confidence: float
    table_provenance: TableProvenance | None = None
    ranking_reason: tuple[str, ...] = ()
    initial_state_write_witness: InitialStateWriteWitness | None = None


__all__ = [
    "DispatcherCandidateIdentity",
    "InitialStateWriteWitness",
    "bind_initial_state_write_witness",
    "initial_state_write_witness_from_entry_cut",
    "DispatcherResolution",
    "ResolverCandidate",
    "StateDispatcherMap",
    "StateDispatcherRow",
]

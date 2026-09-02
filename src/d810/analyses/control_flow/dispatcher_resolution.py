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
from d810.ir.flowgraph import InsnKind
from d810.ir.graph_fingerprint import InsnRecord
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
    "DispatcherResolution",
    "ResolverCandidate",
    "StateDispatcherMap",
    "StateDispatcherRow",
]

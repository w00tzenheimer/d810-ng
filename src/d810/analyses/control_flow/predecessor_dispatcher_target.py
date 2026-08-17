"""Resolve predecessor-carried states through dispatcher row evidence."""

from __future__ import annotations

from dataclasses import dataclass, replace

from d810.analyses.control_flow.condition_chain_model import (
    ConditionChainAnalysisResult,
)
from d810.analyses.control_flow.dispatcher_resolution import StateDispatcherMap
from d810.analyses.control_flow.state_machine_analysis import (
    find_last_state_write_site_on_path_snapshot,
    resolve_exit_via_condition_chain_default_snapshot,
)
from d810.analyses.control_flow.semantic_transition import (
    SUPPORTED_PREDECESSOR_ROUTE_RESOLVERS as _SUPPORTED_PREDECESSOR_ROUTE_RESOLVERS,
    SUCCESSFUL_TRANSITION_RESOLUTION_REASONS as _SUCCESSFUL_TRANSITION_RESOLUTION_REASONS,
)
from d810.ir.flowgraph import OperandKind


PREDECESSOR_DISPATCHER_TARGET_FACT_TYPE = "predecessor_dispatcher_target"
PREDECESSOR_DISPATCHER_TARGET_FACTS_ANALYSIS = (
    "predecessor_dispatcher_target_facts"
)

_STATE_MASK_32 = 0xFFFFFFFF


@dataclass(frozen=True, slots=True)
class PredecessorDispatcherTargetFact:
    """One proof that a predecessor state value routes to a dispatcher target.

    ``state_const`` is the value reaching the dispatcher from
    ``predecessor_block_serial``.  The fact records whether that value was
    resolved by an exact state-dispatcher row or by an interval/range row, so
    consumers do not need to rediscover the dispatcher topology.
    """

    fact_id: str
    predecessor_block_serial: int
    dispatcher_entry_serial: int
    state_const: int
    target_block_serial: int
    resolver_kind: str
    row_kind: str
    dispatcher_block_serial: int | None = None
    compare_block_serial: int | None = None
    branch_kind: str | None = None
    row_lo_inclusive: int | None = None
    row_hi_exclusive: int | None = None
    source_state_const: int | None = None
    transition_provenance_kind: str | None = None
    condition_block_serial: int | None = None
    state_var_stkoff: int | None = None
    confidence: float = 1.0
    source_instruction_ea: int | None = None
    state_var_reg: int | None = None
    target_native_ea: int | None = None

    @property
    def state_const_hex(self) -> str:
        return _hex_u64(self.state_const)

    @property
    def source_state_const_hex(self) -> str | None:
        if self.source_state_const is None:
            return None
        return _hex_u64(self.source_state_const)

    def to_dict(self) -> dict[str, object]:
        return {
            "fact_id": self.fact_id,
            "predecessor_block_serial": self.predecessor_block_serial,
            "dispatcher_entry_serial": self.dispatcher_entry_serial,
            "state_const": self.state_const,
            "state_const_hex": self.state_const_hex,
            "target_block_serial": self.target_block_serial,
            "resolver_kind": self.resolver_kind,
            "row_kind": self.row_kind,
            "dispatcher_block_serial": self.dispatcher_block_serial,
            "compare_block_serial": self.compare_block_serial,
            "branch_kind": self.branch_kind,
            "row_lo_inclusive": self.row_lo_inclusive,
            "row_hi_exclusive": self.row_hi_exclusive,
            "source_state_const": self.source_state_const,
            "source_state_const_hex": self.source_state_const_hex,
            "transition_provenance_kind": self.transition_provenance_kind,
            "condition_block_serial": self.condition_block_serial,
            "state_var_stkoff": self.state_var_stkoff,
            "state_var_reg": self.state_var_reg,
            "source_instruction_ea": self.source_instruction_ea,
            "target_native_ea": self.target_native_ea,
            "confidence": self.confidence,
        }


def _hex_u64(value: int) -> str:
    return f"0x{int(value) & 0xFFFFFFFFFFFFFFFF:016x}"


def _parse_state_value(value: object | None) -> int | None:
    """Parse one state value without widening malformed/boolean inputs."""
    if value is None or isinstance(value, bool):
        return None
    try:
        if isinstance(value, str):
            try:
                return int(value, 0)
            except ValueError:
                return int(value, 16)
        return int(value)
    except (OverflowError, TypeError, ValueError):
        return None


def _normalize_state32(value: object | None) -> int | None:
    """Return a state only when it is an explicit unsigned 32-bit value."""
    parsed = _parse_state_value(value)
    if parsed is None or not 0 <= parsed <= _STATE_MASK_32:
        return None
    return parsed


def _normalize_low32(value: object | None) -> int | None:
    """Normalize a source operand's low 32 bits for a canonical state write."""
    parsed = _parse_state_value(value)
    if parsed is None:
        return None
    return parsed & _STATE_MASK_32


def _normalize_native_ea(value: object | None) -> int | None:
    """Return one valid non-zero native address, or ``None``."""
    parsed = _parse_state_value(value)
    if parsed is None or not 0 < parsed < 0xFFFFFFFFFFFFFFFF:
        return None
    return parsed


def _state_block_key(predecessor: object, state: object) -> tuple[int, int] | None:
    """Build a blocked-resolution key using the state's low 32-bit identity.

    A rejected wide alias must still poison a same-predecessor fallback whose
    state is presented in its valid 32-bit form.  The key therefore normalizes
    the parsed value once, while route construction separately requires the
    strict 32-bit validator above.
    """
    predecessor_value = _maybe_int(predecessor)
    state_value = _parse_state_value(state)
    if predecessor_value is None or state_value is None:
        return None
    return (int(predecessor_value), int(state_value) & _STATE_MASK_32)


def _fact_id(
    *,
    dispatcher_entry_serial: int,
    predecessor_block_serial: int,
    state_const: int,
    target_block_serial: int,
    resolver_kind: str,
) -> str:
    return (
        "predecessor_dispatcher_target:"
        f"dispatcher={int(dispatcher_entry_serial)}:"
        f"pred={int(predecessor_block_serial)}:"
        f"state={_hex_u64(state_const)}:"
        f"target={int(target_block_serial)}:"
        f"resolver={resolver_kind}"
    )


def _build_fact(
    *,
    predecessor_block_serial: int,
    dispatcher_entry_serial: int,
    state_const: int,
    target_block_serial: int,
    resolver_kind: str,
    row_kind: str,
    dispatcher_block_serial: int | None,
    compare_block_serial: int | None,
    branch_kind: str | None,
    row_lo_inclusive: int | None,
    row_hi_exclusive: int | None,
    source_state_const: int | None,
    transition_provenance_kind: str | None,
    condition_block_serial: int | None,
    state_var_stkoff: int | None,
    confidence: float = 1.0,
    source_instruction_ea: int | None = None,
    state_var_reg: int | None = None,
    target_native_ea: int | None = None,
) -> PredecessorDispatcherTargetFact:
    normalized_state = _normalize_state32(state_const)
    if normalized_state is None:
        raise ValueError("predecessor route state must be an unsigned 32-bit value")
    normalized_source_state = _normalize_state32(source_state_const)
    return PredecessorDispatcherTargetFact(
        fact_id=_fact_id(
            dispatcher_entry_serial=dispatcher_entry_serial,
            predecessor_block_serial=predecessor_block_serial,
            state_const=normalized_state,
            target_block_serial=target_block_serial,
            resolver_kind=resolver_kind,
        ),
        predecessor_block_serial=int(predecessor_block_serial),
        dispatcher_entry_serial=int(dispatcher_entry_serial),
        state_const=normalized_state,
        target_block_serial=int(target_block_serial),
        resolver_kind=resolver_kind,
        row_kind=row_kind,
        dispatcher_block_serial=dispatcher_block_serial,
        compare_block_serial=compare_block_serial,
        branch_kind=branch_kind,
        row_lo_inclusive=row_lo_inclusive,
        row_hi_exclusive=row_hi_exclusive,
        source_state_const=normalized_source_state,
        transition_provenance_kind=transition_provenance_kind,
        condition_block_serial=condition_block_serial,
        state_var_stkoff=state_var_stkoff,
        confidence=confidence,
        source_instruction_ea=(
            None
            if source_instruction_ea is None
            else int(source_instruction_ea)
        ),
        state_var_reg=(None if state_var_reg is None else int(state_var_reg)),
        target_native_ea=_normalize_native_ea(target_native_ea),
    )


def _dispatcher_topology_serials(
    state_dispatcher_map: StateDispatcherMap | None,
) -> frozenset[int]:
    """Return every serial that belongs to the current dispatcher topology."""
    if state_dispatcher_map is None:
        return frozenset()
    serials = {
        int(state_dispatcher_map.dispatcher_entry_block),
        *(int(serial) for serial in state_dispatcher_map.dispatcher_blocks),
    }
    for row in state_dispatcher_map.rows:
        serials.add(int(row.dispatcher_block))
        if row.compare_block is not None:
            serials.add(int(row.compare_block))
    return frozenset(serials)


def _dispatcher_state_identity(
    state_dispatcher_map: StateDispatcherMap | None,
) -> StateIdentity | None:
    """Return the dispatcher map's current state-cell identity, if explicit."""
    if state_dispatcher_map is None:
        return None
    stkoff = _maybe_int(getattr(state_dispatcher_map, "state_var_stkoff", None))
    reg = _maybe_int(getattr(state_dispatcher_map, "state_var_reg", None))
    if stkoff is None and reg is None:
        return None
    return (stkoff, reg)


def _condition_chain_region_serials(
    range_evidence: ConditionChainAnalysisResult | None,
) -> frozenset[int]:
    """Collect only structured condition-chain comparison serials.

    ``condition_chain_blocks`` is intentionally accepted only through its
    structured node-map interface.  Plain tuples are broad compatibility
    metadata and may contain handler leaves; treating them as a complete
    dispatcher region would reject valid handler routes.
    """
    if range_evidence is None:
        return frozenset()
    serials: set[int] = set()
    node_map = getattr(range_evidence, "condition_chain_blocks", None)
    if node_map is not None and not isinstance(
        node_map, (tuple, list, set, frozenset)
    ):
        for serial in node_map:
            try:
                serials.add(int(serial))
            except (TypeError, ValueError):
                continue
    dag = getattr(range_evidence, "decision_dag", None)
    for serial in getattr(dag, "nodes", {}) or {}:
        try:
            serials.add(int(serial))
        except (TypeError, ValueError):
            continue
    return frozenset(serials)


def _native_ea_block_serial(
    flow_graph: object,
    native_ea: int,
    *,
    state_const: int,
    state_var_reg: int | None,
) -> int | None:
    """Find exactly one current instruction writing ``state_const`` to ``state_var_reg``."""
    blocks = getattr(flow_graph, "blocks", {})
    matches: list[tuple[int, object]] = []
    for serial, block in getattr(blocks, "items", lambda: ())():
        for instruction in getattr(block, "insn_snapshots", ()) or ():
            if _maybe_int(getattr(instruction, "native_ea", None)) == int(native_ea):
                matches.append((int(serial), instruction))
    if len(matches) != 1:
        return None
    serial, instruction = matches[0]
    destination = getattr(instruction, "d", None)
    source = getattr(instruction, "l", None)
    if (
        state_var_reg is None
        or getattr(destination, "kind", None) is not OperandKind.REGISTER
        or _maybe_int(getattr(destination, "reg", None)) != int(state_var_reg)
        or _maybe_int(getattr(destination, "size", None)) not in (4, 8)
        or getattr(source, "kind", None) is not OperandKind.NUMBER
        or _maybe_int(getattr(source, "size", None)) not in (4, 8)
        or _normalize_low32(getattr(source, "value", None))
        != _normalize_low32(state_const)
    ):
        return None
    return serial


def _unique_snapshot_path(
    flow_graph: object,
    start_serial: int,
    target_serial: int,
) -> tuple[int, ...] | None:
    """Return a bounded one-successor path, rejecting forks and cycles."""
    get_block = getattr(flow_graph, "get_block", None)
    if not callable(get_block) or get_block(int(start_serial)) is None:
        return None
    current = int(start_serial)
    target = int(target_serial)
    path = [current]
    visited: set[int] = set()
    while current != target:
        if current in visited:
            return None
        visited.add(current)
        block = get_block(current)
        if block is None:
            return None
        try:
            successors = tuple(int(serial) for serial in block.succs)
        except (AttributeError, TypeError, ValueError):
            return None
        if len(successors) != 1:
            return None
        current = successors[0]
        if get_block(current) is None:
            return None
        path.append(current)
        if len(path) > len(getattr(flow_graph, "blocks", ())) + 1:
            return None
    return tuple(path)


def _dag_path_for_state(dag: object | None, state: int):
    """Return the unique decision-DAG path for one state, if available."""
    resolve_paths = getattr(dag, "resolve_paths", None)
    if not callable(resolve_paths):
        return None
    matches = []
    try:
        for path in resolve_paths():
            domain = getattr(path, "domain", None)
            contains = getattr(domain, "contains", None)
            if callable(contains) and contains(int(state)):
                matches.append(path)
    except (AttributeError, TypeError, ValueError):
        return None
    return matches[0] if len(matches) == 1 else None


def _unique_target_native_ea(
    flow_graph: object | None,
    target_block_serial: int,
) -> int | None:
    """Return a target block's portable native anchor when it is unique."""
    get_block = getattr(flow_graph, "get_block", None)
    if not callable(get_block):
        return None
    block = get_block(int(target_block_serial))
    if block is None:
        return None
    native_start_ea = _normalize_native_ea(
        getattr(block, "native_start_ea", None)
    )
    if native_start_ea is not None:
        return native_start_ea
    instruction_eas = {
        native_ea
        for instruction in getattr(block, "insn_snapshots", ()) or ()
        if (native_ea := _normalize_native_ea(getattr(instruction, "native_ea", None)))
        is not None
    }
    return next(iter(instruction_eas)) if len(instruction_eas) == 1 else None


def _attach_target_native_ea(
    fact: PredecessorDispatcherTargetFact,
    flow_graph: object | None,
) -> PredecessorDispatcherTargetFact:
    """Attach a producer-snapshot target identity without guessing."""
    if fact.target_native_ea is not None:
        return fact
    target_native_ea = _unique_target_native_ea(
        flow_graph,
        fact.target_block_serial,
    )
    if target_native_ea is None:
        return fact
    return replace(fact, target_native_ea=target_native_ea)


def _fact_from_predecessor_observation(
    observation: object,
) -> PredecessorDispatcherTargetFact | None:
    """Parse one validated predecessor observation without trusting its serials."""
    if getattr(observation, "kind", None) != PREDECESSOR_DISPATCHER_TARGET_FACT_TYPE:
        return None
    payload = getattr(observation, "payload", None)
    if not hasattr(payload, "get"):
        return None
    observation_fact_id = getattr(observation, "fact_id", None)
    payload_fact_id = payload.get("fact_id")
    if not isinstance(observation_fact_id, str) or payload_fact_id != observation_fact_id:
        return None
    resolver_kind = payload.get("resolver_kind")
    row_kind = payload.get("row_kind")
    if (
        not isinstance(resolver_kind, str)
        or resolver_kind not in _SUPPORTED_PREDECESSOR_ROUTE_RESOLVERS
        or not isinstance(row_kind, str)
    ):
        return None
    target_native_ea = _normalize_native_ea(payload.get("target_native_ea"))
    if target_native_ea is None:
        return None
    state_const = _normalize_state32(payload.get("state_const"))
    predecessor_block_serial = _maybe_int(payload.get("predecessor_block_serial"))
    dispatcher_entry_serial = _maybe_int(payload.get("dispatcher_entry_serial"))
    target_block_serial = _maybe_int(payload.get("target_block_serial"))
    if (
        state_const is None
        or predecessor_block_serial is None
        or dispatcher_entry_serial is None
        or target_block_serial is None
    ):
        return None
    source_instruction_ea = _maybe_int(payload.get("source_instruction_ea"))
    observation_source_ea = _maybe_int(getattr(observation, "source_ea", None))
    if observation_source_ea is not None and observation_source_ea != source_instruction_ea:
        return None
    try:
        fact = _build_fact(
            predecessor_block_serial=predecessor_block_serial,
            dispatcher_entry_serial=dispatcher_entry_serial,
            state_const=state_const,
            target_block_serial=target_block_serial,
            resolver_kind=resolver_kind,
            row_kind=row_kind,
            dispatcher_block_serial=_maybe_int(
                payload.get("dispatcher_block_serial")
            ),
            compare_block_serial=_maybe_int(payload.get("compare_block_serial")),
            branch_kind=(
                None
                if payload.get("branch_kind") is None
                else str(payload.get("branch_kind"))
            ),
            row_lo_inclusive=_maybe_int(payload.get("row_lo_inclusive")),
            row_hi_exclusive=_maybe_int(payload.get("row_hi_exclusive")),
            source_state_const=_maybe_int(payload.get("source_state_const")),
            transition_provenance_kind=(
                None
                if payload.get("transition_provenance_kind") is None
                else str(payload.get("transition_provenance_kind"))
            ),
            condition_block_serial=_maybe_int(payload.get("condition_block_serial")),
            state_var_stkoff=_maybe_int(payload.get("state_var_stkoff")),
            confidence=float(payload.get("confidence", 1.0)),
            source_instruction_ea=source_instruction_ea,
            state_var_reg=_maybe_int(payload.get("state_var_reg")),
            target_native_ea=target_native_ea,
        )
    except (TypeError, ValueError, OverflowError):
        return None
    return fact if fact.fact_id == observation_fact_id else None


def project_predecessor_dispatcher_target_observations(
    observations: object,
) -> tuple[PredecessorDispatcherTargetFact, ...]:
    """Project current-session predecessor observations into typed facts.

    A target native identity is mandatory for projection because block serials
    are snapshot-local.  Identical duplicate observations collapse; conflicting
    observations for one fact ID are discarded rather than arbitrated.
    """
    projected: dict[str, PredecessorDispatcherTargetFact] = {}
    conflicts: set[str] = set()
    for observation in observations or ():
        fact = _fact_from_predecessor_observation(observation)
        if fact is None or fact.fact_id in conflicts:
            continue
        existing = projected.get(fact.fact_id)
        if existing is None:
            projected[fact.fact_id] = fact
        elif existing != fact:
            conflicts.add(fact.fact_id)
            projected.pop(fact.fact_id, None)
    return tuple(projected.values())


def _current_snapshot_dispatcher_route_context(
    *,
    flow_graph: object | None,
    coarse_target: int,
    exit_state: int,
    dispatcher_entry_serial: int,
    range_evidence: ConditionChainAnalysisResult | None,
) -> tuple[int, object] | None:
    """Validate current DAG-root context shared by strict route and fallback."""
    get_block = getattr(flow_graph, "get_block", None)
    if not callable(get_block):
        return None
    coarse_target_serial = _maybe_int(coarse_target)
    if (
        coarse_target_serial is None
        or get_block(coarse_target_serial) is None
    ):
        return None
    dag = getattr(range_evidence, "decision_dag", None)
    dag_root = _maybe_int(getattr(dag, "root", None))
    if dag_root is None:
        return None
    entry_to_root = _unique_snapshot_path(
        flow_graph,
        int(dispatcher_entry_serial),
        int(dag_root),
    )
    if entry_to_root is None:
        return None
    dag_path = _dag_path_for_state(dag, int(exit_state))
    if dag_path is None:
        return None
    path_serials = {int(serial) for serial in getattr(dag_path, "path", ())}
    path_serials.add(int(getattr(dag_path, "target", -1)))
    if coarse_target_serial not in path_serials:
        return None
    if get_block(int(dag_root)) is None:
        return None
    return int(coarse_target_serial), dag_path


def resolve_current_snapshot_dispatcher_route(
    *,
    flow_graph: object | None,
    coarse_target: int,
    exit_state: int,
    dispatcher_entry_serial: int,
    range_evidence: ConditionChainAnalysisResult | None,
    dispatcher_region_serials: frozenset[int],
) -> int | None:
    """Replay one coarse route from the proven decision-DAG root.

    Interval/exact rows identify a dispatcher-region anchor, not necessarily
    the first comparison block in the current snapshot.  A route is accepted
    only when the entry has a unique one-successor connector to the DAG root,
    the coarse target belongs to the state's unique DAG subchain, and the
    canonical condition-chain evaluator reaches one existing block outside the
    complete dispatcher region.
    """
    context = _current_snapshot_dispatcher_route_context(
        flow_graph=flow_graph,
        coarse_target=coarse_target,
        exit_state=exit_state,
        dispatcher_entry_serial=dispatcher_entry_serial,
        range_evidence=range_evidence,
    )
    if context is None:
        return None
    coarse_target_serial, dag_path = context
    get_block = getattr(flow_graph, "get_block")
    dag_root = _maybe_int(
        getattr(getattr(range_evidence, "decision_dag", None), "root", None)
    )
    if dag_root is None:
        return None
    try:
        resolved = resolve_exit_via_condition_chain_default_snapshot(
            flow_graph,
            int(dag_root),
            int(exit_state),
        )
    except (
        AttributeError,
        LookupError,
        TypeError,
        ValueError,
        KeyError,
        IndexError,
    ):
        return None
    resolved_serial = _maybe_int(resolved)
    if resolved_serial is None or resolved_serial in dispatcher_region_serials:
        return None
    if get_block(resolved_serial) is None:
        return None
    dag_target = _maybe_int(getattr(dag_path, "target", None))
    if dag_target is not None and dag_target not in dispatcher_region_serials:
        if resolved_serial != dag_target:
            return None
    return resolved_serial


def _current_snapshot_entry_route_proof(
    *,
    flow_graph: object | None,
    source_instruction_ea: int | None,
    predecessor_block_serial: int,
    dispatcher_entry_serial: int,
    coarse_target: int,
    state_const: int,
    state_var_stkoff: int | None,
    source_state_var_reg: int | None,
    range_evidence: ConditionChainAnalysisResult | None,
    dispatcher_region_serials: frozenset[int],
) -> int | None:
    """Prove a current dispatcher-input path without claiming an alias.

    The native anchor must own the predecessor's current entry-prefix block.  A
    unique one-successor path then carries that block to the dispatcher entry
    and its decision-DAG root.  The canonical path-local state-write evaluator
    must find the candidate value in the selected stack cell at that entry.  No
    register-to-stack alias is inferred; ``None`` means the route abstains.
    """
    if not _current_snapshot_entry_carrier_proof(
        flow_graph=flow_graph,
        source_instruction_ea=source_instruction_ea,
        predecessor_block_serial=predecessor_block_serial,
        dispatcher_entry_serial=dispatcher_entry_serial,
        state_const=state_const,
        state_var_stkoff=state_var_stkoff,
        source_state_var_reg=source_state_var_reg,
        range_evidence=range_evidence,
    ):
        return None
    return resolve_current_snapshot_dispatcher_route(
        flow_graph=flow_graph,
        coarse_target=int(coarse_target),
        exit_state=int(state_const),
        dispatcher_entry_serial=int(dispatcher_entry_serial),
        dispatcher_region_serials=dispatcher_region_serials,
        range_evidence=range_evidence,
    )


def _current_snapshot_entry_carrier_proof(
    *,
    flow_graph: object | None,
    source_instruction_ea: int | None,
    predecessor_block_serial: int,
    dispatcher_entry_serial: int,
    state_const: int,
    state_var_stkoff: int | None,
    source_state_var_reg: int | None,
    range_evidence: ConditionChainAnalysisResult | None,
) -> bool:
    """Prove the source-to-entry selected-cell carrier path in one snapshot."""
    if (
        flow_graph is None
        or source_instruction_ea is None
        or state_var_stkoff is None
    ):
        return False
    source_serial = _native_ea_block_serial(
        flow_graph,
        int(source_instruction_ea),
        state_const=int(state_const),
        state_var_reg=source_state_var_reg,
    )
    if source_serial is None or int(source_serial) != int(predecessor_block_serial):
        return False
    source_to_entry = _unique_snapshot_path(
        flow_graph,
        int(source_serial),
        int(dispatcher_entry_serial),
    )
    if source_to_entry is None:
        return False
    dag = getattr(range_evidence, "decision_dag", None)
    dag_root = _maybe_int(getattr(dag, "root", None))
    get_block = getattr(flow_graph, "get_block", None)
    if dag_root is None or not callable(get_block):
        return False
    entry_to_root = _unique_snapshot_path(
        flow_graph,
        int(dispatcher_entry_serial),
        int(dag_root),
    )
    if entry_to_root is None:
        return False
    path = (*source_to_entry, *entry_to_root[1:])
    if len(set(path)) != len(path):
        return False
    try:
        state_write = find_last_state_write_site_on_path_snapshot(
            flow_graph,
            path,
            int(state_var_stkoff),
        )
    except (
        AttributeError,
        LookupError,
        TypeError,
        ValueError,
        KeyError,
        IndexError,
    ):
        return False
    if state_write is None:
        return False
    write_block_serial, write_site = state_write
    return not (
        int(write_block_serial) != int(dispatcher_entry_serial)
        or int(write_site.state_value) != (int(state_const) & _STATE_MASK_32)
        or bool(getattr(write_site, "unsafe_trailing_insn_eas", ()))
        or bool(getattr(write_site, "unsafe_trailing_reasons", ()))
    )


StateIdentity = tuple[int | None, int | None]


def _transition_identity(row: object) -> StateIdentity | None:
    """Return one transition row's exact state-cell identity, if present."""
    stkoff = _maybe_int(getattr(row, "state_var_stkoff", None))
    reg = _maybe_int(getattr(row, "state_var_reg", None))
    if stkoff is None and reg is None:
        return None
    return (stkoff, reg)


def _coarse_dispatcher_target_for_state(
    *,
    state_const: int,
    state_dispatcher_map: StateDispatcherMap | None,
    range_evidence: ConditionChainAnalysisResult | None,
    dispatcher_topology_serials: frozenset[int],
) -> int | None:
    """Return one dispatcher-topology target from exact/interval evidence."""
    candidates: set[int] = set()
    normalized_state = _normalize_state32(state_const)
    if normalized_state is None:
        return None
    for row in getattr(state_dispatcher_map, "rows", ()) or ():
        row_state = _normalize_state32(getattr(row, "state_const", None))
        target = _maybe_int(getattr(row, "target_block", None))
        if row_state == normalized_state and target in dispatcher_topology_serials:
            candidates.add(int(target))
    dispatcher = getattr(range_evidence, "dispatcher", None)
    lookup_row = getattr(dispatcher, "lookup_row", None)
    if callable(lookup_row):
        try:
            row = lookup_row(normalized_state)
        except (AttributeError, TypeError, ValueError, KeyError, IndexError):
            row = None
        target = _maybe_int(getattr(row, "target", None))
        if target is not None and target in dispatcher_topology_serials:
            candidates.add(target)
    return next(iter(candidates)) if len(candidates) == 1 else None


def select_supported_transition_identity(
    transition_resolutions: object | None,
    *,
    dispatcher_topology_serials: frozenset[int] = frozenset(),
) -> StateIdentity | None:
    """Select one state identity supported by successful handler resolutions.

    Support is deliberately derived only from the active in-memory resolution
    tuple.  A successful resolution contributes a vote when it has a concrete
    non-dispatcher target and an explicit state-cell identity.  Repeated rows
    are deduplicated before selecting; any zero-or-many supported identities is
    an abstention rather than an insertion-order tie break.
    """
    supported: set[StateIdentity] = set()
    seen_observations: set[tuple[str, str, int, StateIdentity]] = set()
    dispatcher_topology = {
        int(serial) for serial in (dispatcher_topology_serials or ())
    }
    for row in transition_resolutions or ():
        if (
            getattr(row, "resolution_reason", None)
            not in _SUCCESSFUL_TRANSITION_RESOLUTION_REASONS
        ):
            continue
        target = getattr(row, "resolved_next_block_serial", None)
        if target is None or isinstance(target, bool):
            continue
        try:
            target = int(target)
        except (TypeError, ValueError):
            continue
        if target < 0 or target in dispatcher_topology:
            continue
        identity = _transition_identity(row)
        if identity is None:
            continue
        observation_key = (
            str(getattr(row, "source_block_serial", "")),
            str(getattr(row, "source_state_const_hex", "")),
            target,
            identity,
        )
        if observation_key in seen_observations:
            continue
        seen_observations.add(observation_key)
        supported.add(identity)
    if len(supported) != 1:
        return None
    return next(iter(supported))


def resolve_predecessor_dispatcher_target(
    *,
    predecessor_block_serial: int,
    dispatcher_entry_serial: int,
    state_const: int,
    state_dispatcher_map: StateDispatcherMap | None = None,
    range_evidence: ConditionChainAnalysisResult | None = None,
    source_state_const: int | None = None,
    transition_provenance_kind: str | None = None,
    condition_block_serial: int | None = None,
    state_var_stkoff: int | None = None,
    state_var_reg: int | None = None,
    source_instruction_ea: int | None = None,
    flow_graph: object | None = None,
    allow_handler_map_fallback_after_incomplete_route: bool = False,
) -> PredecessorDispatcherTargetFact | None:
    """Resolve one predecessor-carried state through exact or interval rows.

    ``allow_handler_map_fallback_after_incomplete_route`` is reserved for the
    caller that has already proven the current source-to-entry carrier and DAG
    context.  It falls through to one unique non-dispatcher handler map entry;
    it never turns a coarse dispatcher target into a typed handler fact.
    """

    normalized_state = _normalize_state32(state_const)
    if normalized_state is None:
        return None
    dispatcher_topology = set(_dispatcher_topology_serials(state_dispatcher_map))
    dispatcher_topology.update(_condition_chain_region_serials(range_evidence))
    coarse_target: int | None = None
    coarse_fact_kwargs: dict[str, object] | None = None
    if state_dispatcher_map is not None:
        for row in state_dispatcher_map.rows:
            row_state = _normalize_state32(getattr(row, "state_const", None))
            if row_state != normalized_state:
                continue
            target_block = _maybe_int(getattr(row, "target_block", None))
            if target_block is None:
                continue
            if target_block in dispatcher_topology:
                # A dispatcher self-loop is not a handler route.  Keep looking
                # for stronger condition-chain interval/handler evidence below.
                coarse_target = target_block
                coarse_fact_kwargs = {
                    "resolver_kind": "state_dispatcher_map_exact_row",
                    "row_kind": str(row.row_kind),
                    "dispatcher_block_serial": int(row.dispatcher_block),
                    "compare_block_serial": (
                        None
                        if row.compare_block is None
                        else int(row.compare_block)
                    ),
                    "branch_kind": str(row.branch_kind),
                    "row_lo_inclusive": normalized_state,
                    "row_hi_exclusive": normalized_state + 1,
                    "confidence": float(row.confidence),
                }
                continue
            return _build_fact(
                predecessor_block_serial=predecessor_block_serial,
                dispatcher_entry_serial=dispatcher_entry_serial,
                state_const=normalized_state,
                target_block_serial=target_block,
                resolver_kind="state_dispatcher_map_exact_row",
                row_kind=str(row.row_kind),
                dispatcher_block_serial=int(row.dispatcher_block),
                compare_block_serial=(
                    None if row.compare_block is None else int(row.compare_block)
                ),
                branch_kind=str(row.branch_kind),
                row_lo_inclusive=normalized_state,
                row_hi_exclusive=normalized_state + 1,
                source_state_const=source_state_const,
                transition_provenance_kind=transition_provenance_kind,
                condition_block_serial=condition_block_serial,
                state_var_stkoff=state_var_stkoff,
                confidence=float(row.confidence),
                source_instruction_ea=source_instruction_ea,
                state_var_reg=state_var_reg,
            )

    if range_evidence is None:
        # Exact-row metadata without a current decision DAG has no principled
        # root identity.  Do not resurrect the old coarse-target walker.
        return None

    dispatcher = getattr(range_evidence, "dispatcher", None)
    if dispatcher is not None:
        row = dispatcher.lookup_row(normalized_state)
        if row is not None and row.target is not None:
            interval_target = _maybe_int(row.target)
            if interval_target is None:
                return None
            interval_kwargs = {
                "resolver_kind": "interval_dispatcher_row",
                "row_kind": (
                    "interval_exact"
                    if int(row.hi) - int(row.lo) == 1
                    else "interval_range"
                ),
                "dispatcher_block_serial": None,
                "compare_block_serial": None,
                "branch_kind": None,
                "row_lo_inclusive": int(row.lo),
                "row_hi_exclusive": int(row.hi),
                "confidence": 1.0,
            }
            if interval_target in dispatcher_topology:
                coarse_target = interval_target
                coarse_fact_kwargs = interval_kwargs
            else:
                return _build_fact(
                    predecessor_block_serial=predecessor_block_serial,
                    dispatcher_entry_serial=dispatcher_entry_serial,
                    state_const=normalized_state,
                    target_block_serial=interval_target,
                    resolver_kind=str(interval_kwargs["resolver_kind"]),
                    row_kind=str(interval_kwargs["row_kind"]),
                    dispatcher_block_serial=None,
                    compare_block_serial=None,
                    branch_kind=None,
                    row_lo_inclusive=int(row.lo),
                    row_hi_exclusive=int(row.hi),
                    source_state_const=source_state_const,
                    transition_provenance_kind=transition_provenance_kind,
                    condition_block_serial=condition_block_serial,
                    state_var_stkoff=state_var_stkoff,
                    source_instruction_ea=source_instruction_ea,
                    state_var_reg=state_var_reg,
                )

    if coarse_target is not None and coarse_fact_kwargs is not None:
        fallback_target = resolve_current_snapshot_dispatcher_route(
            flow_graph=flow_graph,
            coarse_target=coarse_target,
            exit_state=normalized_state,
            dispatcher_entry_serial=int(dispatcher_entry_serial),
            dispatcher_region_serials=frozenset(dispatcher_topology),
            range_evidence=range_evidence,
        )
        if fallback_target is None:
            if not allow_handler_map_fallback_after_incomplete_route:
                return None
        else:
            return _build_fact(
                predecessor_block_serial=predecessor_block_serial,
                dispatcher_entry_serial=dispatcher_entry_serial,
                state_const=normalized_state,
                target_block_serial=fallback_target,
                resolver_kind=str(coarse_fact_kwargs["resolver_kind"]),
                row_kind=str(coarse_fact_kwargs["row_kind"]),
                dispatcher_block_serial=coarse_fact_kwargs["dispatcher_block_serial"],
                compare_block_serial=coarse_fact_kwargs["compare_block_serial"],
                branch_kind=coarse_fact_kwargs["branch_kind"],
                row_lo_inclusive=coarse_fact_kwargs["row_lo_inclusive"],
                row_hi_exclusive=coarse_fact_kwargs["row_hi_exclusive"],
                source_state_const=source_state_const,
                transition_provenance_kind=transition_provenance_kind,
                condition_block_serial=condition_block_serial,
                state_var_stkoff=state_var_stkoff,
                confidence=float(coarse_fact_kwargs["confidence"]),
                source_instruction_ea=source_instruction_ea,
                state_var_reg=state_var_reg,
            )

    current_handler_facts: list[PredecessorDispatcherTargetFact] = []
    exact_handler_serials = {
        serial
        for serial in (
            _maybe_int(value)
            for value in getattr(range_evidence, "handler_state_map", {})
        )
        if serial is not None
    }

    for handler_serial, handler_state in getattr(
        range_evidence, "handler_state_map", {}
    ).items():
        normalized_handler_state = _normalize_state32(handler_state)
        if normalized_handler_state != normalized_state:
            continue
        handler_serial_int = _maybe_int(handler_serial)
        if handler_serial_int is None or handler_serial_int in dispatcher_topology:
            continue
        target_native_ea = None
        if allow_handler_map_fallback_after_incomplete_route:
            target_native_ea = _unique_target_native_ea(
                flow_graph,
                handler_serial_int,
            )
            if target_native_ea is None:
                return None
        fact = _build_fact(
            predecessor_block_serial=predecessor_block_serial,
            dispatcher_entry_serial=dispatcher_entry_serial,
            state_const=normalized_state,
            target_block_serial=handler_serial_int,
            resolver_kind="condition_chain_handler_state_map_exact_row",
            row_kind="exact",
            dispatcher_block_serial=None,
            compare_block_serial=None,
            branch_kind=None,
            row_lo_inclusive=normalized_state,
            row_hi_exclusive=normalized_state + 1,
            source_state_const=source_state_const,
            transition_provenance_kind=transition_provenance_kind,
            condition_block_serial=condition_block_serial,
            state_var_stkoff=state_var_stkoff,
            source_instruction_ea=source_instruction_ea,
            state_var_reg=state_var_reg,
            target_native_ea=target_native_ea,
        )
        if allow_handler_map_fallback_after_incomplete_route:
            current_handler_facts.append(fact)
            continue
        return fact

    for handler_serial, (lo, hi) in getattr(
        range_evidence, "handler_range_map", {}
    ).items():
        if handler_serial in exact_handler_serials:
            continue
        handler_serial_int = _maybe_int(handler_serial)
        if handler_serial_int is None or handler_serial_int in dispatcher_topology:
            continue
        if lo is None or hi is None:
            continue
        lo_int = int(lo)
        hi_int = int(hi)
        if (hi_int - lo_int) >= 0xFFFF0000:
            continue
        if lo_int <= normalized_state <= hi_int:
            target_native_ea = None
            if allow_handler_map_fallback_after_incomplete_route:
                target_native_ea = _unique_target_native_ea(
                    flow_graph,
                    handler_serial_int,
                )
                if target_native_ea is None:
                    return None
            fact = _build_fact(
                predecessor_block_serial=predecessor_block_serial,
                dispatcher_entry_serial=dispatcher_entry_serial,
                state_const=normalized_state,
                target_block_serial=handler_serial_int,
                resolver_kind="condition_chain_handler_range_map_row",
                row_kind="range",
                dispatcher_block_serial=None,
                compare_block_serial=None,
                branch_kind=None,
                row_lo_inclusive=lo_int,
                row_hi_exclusive=hi_int + 1,
                source_state_const=source_state_const,
                transition_provenance_kind=transition_provenance_kind,
                condition_block_serial=condition_block_serial,
                state_var_stkoff=state_var_stkoff,
                source_instruction_ea=source_instruction_ea,
                state_var_reg=state_var_reg,
                target_native_ea=target_native_ea,
            )
            if allow_handler_map_fallback_after_incomplete_route:
                current_handler_facts.append(fact)
                continue
            return fact

    if allow_handler_map_fallback_after_incomplete_route:
        return current_handler_facts[0] if len(current_handler_facts) == 1 else None
    return None


def collect_predecessor_dispatcher_target_facts(
    *,
    transition_result: object | None,
    dispatcher_entry_serial: int,
    state_dispatcher_map: StateDispatcherMap | None = None,
    range_evidence: ConditionChainAnalysisResult | None = None,
    transition_resolutions: object | None = None,
    transition_report: object | None = None,
    dag: object | None = None,
    state_var_stkoff: int | None = None,
    state_var_reg: int | None = None,
    flow_graph: object | None = None,
) -> tuple[PredecessorDispatcherTargetFact, ...]:
    """Resolve transition target states into predecessor-target facts."""

    facts: list[PredecessorDispatcherTargetFact] = []
    seen: set[str] = set()
    blocked_resolution_keys: set[tuple[int, int]] = set()
    # Identity support must use only the proven dispatcher topology.  Range
    # and decision-DAG metadata also describes handler leaves, so it is kept
    # for route resolution below rather than treated as dispatcher serials.
    dispatcher_topology = set(_dispatcher_topology_serials(state_dispatcher_map))
    dispatcher_topology.add(int(dispatcher_entry_serial))
    dispatcher_identity = _dispatcher_state_identity(state_dispatcher_map)
    supported_identity = select_supported_transition_identity(
        transition_resolutions,
        dispatcher_topology_serials=frozenset(dispatcher_topology),
    )
    for row in transition_resolutions or ():
        predecessor = getattr(row, "source_block_serial", None)
        source_state_hex = getattr(row, "source_state_const_hex", None)
        resolution_reason = getattr(row, "resolution_reason", None)
        if predecessor is None or source_state_hex is None:
            continue
        resolution_key = _state_block_key(predecessor, source_state_hex)
        if resolution_key is None:
            continue
        source_state = _normalize_state32(source_state_hex)
        prior_target = getattr(row, "resolved_next_block_serial", None)
        if source_state is None:
            blocked_resolution_keys.add(resolution_key)
            continue
        if resolution_reason not in _SUCCESSFUL_TRANSITION_RESOLUTION_REASONS and (
            resolution_reason != "target_is_dispatcher_block"
        ):
            blocked_resolution_keys.add(resolution_key)
            continue
        if (
            resolution_reason in _SUCCESSFUL_TRANSITION_RESOLUTION_REASONS
            and prior_target is None
        ):
            blocked_resolution_keys.add(resolution_key)
            continue
        # A target-is-dispatcher resolution deliberately carries no target
        # serial.  Its source state is still useful when the condition-chain
        # interval evidence can identify the real handler, but only when the
        # native anchor is retained for the later current-MBA binding.
        if (
            resolution_reason == "target_is_dispatcher_block"
            and getattr(row, "source_instruction_ea", None) is None
        ):
            blocked_resolution_keys.add(resolution_key)
            continue
        target_candidate_identity = _transition_identity(row)
        current_snapshot_target: int | None = None
        allow_handler_map_fallback_after_incomplete_route = False
        if resolution_reason == "target_is_dispatcher_block":
            if (
                supported_identity is None
                or target_candidate_identity is None
                or target_candidate_identity != supported_identity
            ):
                blocked_resolution_keys.add(resolution_key)
                continue
            if (
                dispatcher_identity is not None
                and target_candidate_identity != dispatcher_identity
            ):
                # A typed fact must not turn a prior register carrier into the
                # current stack carrier.  The only bridge is a path-local
                # current-snapshot proof anchored by this native source EA.
                current_topology = set(dispatcher_topology)
                current_topology.update(
                    _condition_chain_region_serials(range_evidence)
                )
                coarse_target = _coarse_dispatcher_target_for_state(
                    state_const=source_state,
                    state_dispatcher_map=state_dispatcher_map,
                    range_evidence=range_evidence,
                    dispatcher_topology_serials=frozenset(current_topology),
                )
                if coarse_target is None:
                    blocked_resolution_keys.add(resolution_key)
                    continue
                current_snapshot_target = _current_snapshot_entry_route_proof(
                    flow_graph=flow_graph,
                    source_instruction_ea=_maybe_int(
                        getattr(row, "source_instruction_ea", None)
                    ),
                    predecessor_block_serial=int(predecessor),
                    dispatcher_entry_serial=int(dispatcher_entry_serial),
                    coarse_target=coarse_target,
                    state_const=source_state,
                    state_var_stkoff=dispatcher_identity[0],
                    source_state_var_reg=target_candidate_identity[1],
                    range_evidence=range_evidence,
                    dispatcher_region_serials=frozenset(current_topology),
                )
                if current_snapshot_target is None:
                    carrier_proven = _current_snapshot_entry_carrier_proof(
                        flow_graph=flow_graph,
                        source_instruction_ea=_maybe_int(
                            getattr(row, "source_instruction_ea", None)
                        ),
                        predecessor_block_serial=int(predecessor),
                        dispatcher_entry_serial=int(dispatcher_entry_serial),
                        state_const=source_state,
                        state_var_stkoff=dispatcher_identity[0],
                        source_state_var_reg=target_candidate_identity[1],
                        range_evidence=range_evidence,
                    )
                    route_context = _current_snapshot_dispatcher_route_context(
                        flow_graph=flow_graph,
                        coarse_target=coarse_target,
                        exit_state=source_state,
                        dispatcher_entry_serial=int(dispatcher_entry_serial),
                        range_evidence=range_evidence,
                    )
                    if not carrier_proven or route_context is None:
                        blocked_resolution_keys.add(resolution_key)
                        continue
                    allow_handler_map_fallback_after_incomplete_route = True
                candidate_state_var_stkoff = dispatcher_identity[0]
                candidate_state_var_reg = dispatcher_identity[1]
            else:
                candidate_state_var_stkoff = target_candidate_identity[0]
                candidate_state_var_reg = target_candidate_identity[1]
        else:
            candidate_state_var_stkoff = (
                state_var_stkoff
                if getattr(row, "state_var_stkoff", None) is None
                else _maybe_int(getattr(row, "state_var_stkoff"))
            )
            candidate_state_var_reg = (
                state_var_reg
                if getattr(row, "state_var_reg", None) is None
                else _maybe_int(getattr(row, "state_var_reg"))
            )
        try:
            fact = resolve_predecessor_dispatcher_target(
                predecessor_block_serial=int(predecessor),
                dispatcher_entry_serial=int(dispatcher_entry_serial),
                state_const=source_state,
                state_dispatcher_map=state_dispatcher_map,
                range_evidence=range_evidence,
                source_state_const=source_state,
                transition_provenance_kind=_maybe_str(
                    getattr(row, "resolution_kind", None)
                ),
                condition_block_serial=None,
                state_var_stkoff=candidate_state_var_stkoff,
                state_var_reg=candidate_state_var_reg,
                source_instruction_ea=_maybe_int(
                    getattr(row, "source_instruction_ea", None)
                ),
                flow_graph=flow_graph,
                allow_handler_map_fallback_after_incomplete_route=(
                    allow_handler_map_fallback_after_incomplete_route
                ),
            )
        except (TypeError, ValueError):
            blocked_resolution_keys.add(resolution_key)
            continue
        if fact is not None:
            fact = _attach_target_native_ea(fact, flow_graph)
        if (
            allow_handler_map_fallback_after_incomplete_route
            and (
                fact is None
                or fact.target_native_ea is None
                or int(fact.target_block_serial) in current_topology
            )
        ):
            blocked_resolution_keys.add(resolution_key)
            continue
        if fact is None or fact.fact_id in seen:
            if fact is None:
                blocked_resolution_keys.add(resolution_key)
            continue
        if resolution_reason in _SUCCESSFUL_TRANSITION_RESOLUTION_REASONS:
            try:
                if int(prior_target) != int(fact.target_block_serial):
                    blocked_resolution_keys.add(resolution_key)
                    continue
            except (TypeError, ValueError):
                blocked_resolution_keys.add(resolution_key)
                continue
        if (
            current_snapshot_target is not None
            and int(fact.target_block_serial) != int(current_snapshot_target)
        ):
            blocked_resolution_keys.add(resolution_key)
            continue
        seen.add(fact.fact_id)
        facts.append(fact)

    for transition in getattr(transition_result, "transitions", ()) or ():
        to_state = getattr(transition, "to_state", None)
        predecessor = getattr(transition, "from_block", None)
        if to_state is None or predecessor is None:
            continue
        transition_key = _state_block_key(predecessor, to_state)
        normalized_to_state = _normalize_state32(to_state)
        if transition_key is None or normalized_to_state is None:
            continue
        if transition_key in blocked_resolution_keys:
            continue
        source_instruction_ea = _maybe_int(
            getattr(transition, "source_instruction_ea", None)
        )
        if source_instruction_ea is None:
            source_instruction_ea = _maybe_int(
                getattr(transition, "provenance_ea", None)
            )
        try:
            fact = resolve_predecessor_dispatcher_target(
                predecessor_block_serial=int(predecessor),
                dispatcher_entry_serial=int(dispatcher_entry_serial),
                state_const=normalized_to_state,
                state_dispatcher_map=state_dispatcher_map,
                range_evidence=range_evidence,
                source_state_const=_maybe_int(getattr(transition, "from_state", None)),
                transition_provenance_kind=_maybe_str(
                    getattr(transition, "provenance_kind", None)
                ),
                condition_block_serial=_maybe_int(
                    getattr(transition, "condition_block", None)
                ),
                state_var_stkoff=state_var_stkoff,
                state_var_reg=(
                    state_var_reg
                    if getattr(transition, "state_var_reg", None) is None
                    else _maybe_int(getattr(transition, "state_var_reg"))
                ),
                source_instruction_ea=source_instruction_ea,
                flow_graph=flow_graph,
            )
        except (TypeError, ValueError):
            continue
        if fact is not None:
            fact = _attach_target_native_ea(fact, flow_graph)
        if fact is None or fact.fact_id in seen:
            continue
        seen.add(fact.fact_id)
        facts.append(fact)

    for row in getattr(transition_report, "rows", ()) or ():
        next_state = getattr(row, "next_state", None)
        predecessor = getattr(row, "handler_serial", None)
        if predecessor is None:
            continue
        if next_state is not None:
            next_state_normalized = _normalize_state32(next_state)
            next_state_key = _state_block_key(predecessor, next_state)
            if (
                next_state_normalized is None
                or next_state_key is None
                or next_state_key in blocked_resolution_keys
            ):
                continue
            try:
                fact = resolve_predecessor_dispatcher_target(
                    predecessor_block_serial=int(predecessor),
                    dispatcher_entry_serial=int(dispatcher_entry_serial),
                    state_const=next_state_normalized,
                    state_dispatcher_map=state_dispatcher_map,
                    range_evidence=range_evidence,
                    source_state_const=_maybe_int(getattr(row, "state_const", None)),
                    transition_provenance_kind="transition_report",
                    condition_block_serial=None,
                    state_var_stkoff=state_var_stkoff,
                    state_var_reg=(
                        state_var_reg
                        if getattr(row, "state_var_reg", None) is None
                        else _maybe_int(getattr(row, "state_var_reg"))
                    ),
                    source_instruction_ea=_maybe_int(
                        getattr(row, "source_instruction_ea", None)
                    ),
                    flow_graph=flow_graph,
                )
            except (TypeError, ValueError):
                fact = None
            if fact is not None:
                fact = _attach_target_native_ea(fact, flow_graph)
            if fact is not None and fact.fact_id not in seen:
                seen.add(fact.fact_id)
                facts.append(fact)

        for conditional_state in getattr(row, "conditional_states", ()) or ():
            conditional_state_normalized = _normalize_state32(conditional_state)
            conditional_state_key = _state_block_key(predecessor, conditional_state)
            if (
                conditional_state_normalized is None
                or conditional_state_key is None
                or conditional_state_key in blocked_resolution_keys
            ):
                continue
            try:
                conditional_fact = resolve_predecessor_dispatcher_target(
                    predecessor_block_serial=int(predecessor),
                    dispatcher_entry_serial=int(dispatcher_entry_serial),
                    state_const=conditional_state_normalized,
                    state_dispatcher_map=state_dispatcher_map,
                    range_evidence=range_evidence,
                    source_state_const=_maybe_int(getattr(row, "state_const", None)),
                    transition_provenance_kind="transition_report_conditional",
                    condition_block_serial=None,
                    state_var_stkoff=state_var_stkoff,
                    state_var_reg=(
                        state_var_reg
                        if getattr(row, "state_var_reg", None) is None
                        else _maybe_int(getattr(row, "state_var_reg"))
                    ),
                    source_instruction_ea=_maybe_int(
                        getattr(row, "source_instruction_ea", None)
                    ),
                    flow_graph=flow_graph,
                )
            except (TypeError, ValueError):
                continue
            if conditional_fact is not None:
                conditional_fact = _attach_target_native_ea(
                    conditional_fact,
                    flow_graph,
                )
            if conditional_fact is None or conditional_fact.fact_id in seen:
                continue
            seen.add(conditional_fact.fact_id)
            facts.append(conditional_fact)

    for edge in getattr(dag, "edges", ()) or ():
        kind_name = str(getattr(getattr(edge, "kind", None), "name", ""))
        if kind_name not in {"TRANSITION", "CONDITIONAL_TRANSITION"}:
            continue
        next_state = getattr(edge, "target_state", None)
        if next_state is None:
            continue
        source_anchor = getattr(edge, "source_anchor", None)
        predecessor = _maybe_int(getattr(source_anchor, "block_serial", None))
        source_key = getattr(edge, "source_key", None)
        if predecessor is None:
            predecessor = _maybe_int(getattr(source_key, "handler_serial", None))
        if predecessor is None:
            continue
        next_state_normalized = _normalize_state32(next_state)
        next_state_key = _state_block_key(predecessor, next_state)
        if (
            next_state_normalized is None
            or next_state_key is None
            or next_state_key in blocked_resolution_keys
        ):
            continue
        try:
            fact = resolve_predecessor_dispatcher_target(
                predecessor_block_serial=int(predecessor),
                dispatcher_entry_serial=int(dispatcher_entry_serial),
                state_const=next_state_normalized,
                state_dispatcher_map=state_dispatcher_map,
                range_evidence=range_evidence,
                source_state_const=_maybe_int(getattr(source_key, "state_const", None)),
                transition_provenance_kind=f"state_dag_{kind_name.lower()}",
                condition_block_serial=None,
                state_var_stkoff=state_var_stkoff,
                state_var_reg=(
                    state_var_reg
                    if getattr(edge, "state_var_reg", None) is None
                    else _maybe_int(getattr(edge, "state_var_reg"))
                ),
                source_instruction_ea=_maybe_int(
                    getattr(edge, "source_instruction_ea", None)
                ),
                flow_graph=flow_graph,
            )
        except (TypeError, ValueError):
            continue
        if fact is not None:
            fact = _attach_target_native_ea(fact, flow_graph)
        if fact is None or fact.fact_id in seen:
            continue
        seen.add(fact.fact_id)
        facts.append(fact)
    return tuple(facts)


def _maybe_int(value: object | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _maybe_str(value: object | None) -> str | None:
    if value is None:
        return None
    return str(value)


__all__ = [
    "PREDECESSOR_DISPATCHER_TARGET_FACT_TYPE",
    "PREDECESSOR_DISPATCHER_TARGET_FACTS_ANALYSIS",
    "PredecessorDispatcherTargetFact",
    "StateIdentity",
    "collect_predecessor_dispatcher_target_facts",
    "project_predecessor_dispatcher_target_observations",
    "resolve_current_snapshot_dispatcher_route",
    "resolve_predecessor_dispatcher_target",
    "select_supported_transition_identity",
]

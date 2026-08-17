"""In-memory transition resolution through exact state-dispatcher maps."""

from __future__ import annotations

import enum
from dataclasses import dataclass

from d810.analyses.control_flow.dispatcher_resolution import StateDispatcherMap
from d810.analyses.control_flow.state_machine_analysis import (
    find_last_state_write_site_on_path_snapshot,
)
from d810.analyses.data_flow.abstract_value import Block
from d810.ir import ValueRef

# Maximum corridor depth followed when folding a binop-computed next-state.
# A handler whose next-state is computed (not a literal ``mov #const``) is
# resolved by carrying a const env down its UNIQUE successor chain; the bound
# keeps the walk finite for malformed graphs.
_MAX_CORRIDOR_HOPS = 8

SUCCESSFUL_TRANSITION_RESOLUTION_REASONS = frozenset(
    {
        "resolved_exact_state",
        "resolved_folded_state_write",
    }
)

SUPPORTED_PREDECESSOR_ROUTE_RESOLVERS = frozenset(
    {
        "state_dispatcher_map_exact_row",
        "interval_dispatcher_row",
        "condition_chain_interval_route",
        "condition_chain_handler_state_map_exact_row",
        "condition_chain_handler_range_map_row",
    }
)


@dataclass(frozen=True, slots=True)
class StateTransitionFact:
    """Portable view of one state-transition observation."""

    fact_id: str
    source_block_serial: int
    source_state_const: int
    source_state_const_hex: str | None = None
    successor_kind: str = "branch"
    state_var_stkoff: int | None = None
    state_var_reg: int | None = None
    source_instruction_ea: int | None = None


@dataclass(frozen=True, slots=True)
class StateWriteAnchor:
    """Portable view of a state write observed at a handler block."""

    block_serial: int
    state_const: int
    state_var_stkoff: int | None = None
    state_var_reg: int | None = None
    instruction_ea: int | None = None


def rebind_state_write_anchors(
    anchors: tuple[StateWriteAnchor, ...],
    *,
    block_serial_for_instruction_ea,
) -> tuple[StateWriteAnchor, ...]:
    """Rebind portable state-write anchors into the current MBA.

    ``block_serial`` is snapshot-local, so only the native instruction EA may
    carry an anchor across maturity or regeneration.  Missing and ambiguous
    EA bindings are explicit abstentions; falling back to the recorded serial
    would silently route a mutation through an unrelated live block.
    """
    rebound: list[StateWriteAnchor] = []
    seen: set[StateWriteAnchor] = set()
    for anchor in anchors:
        if anchor.instruction_ea is None:
            continue
        block_serial = block_serial_for_instruction_ea(int(anchor.instruction_ea))
        if block_serial is None:
            continue
        current = StateWriteAnchor(
            block_serial=int(block_serial),
            state_const=int(anchor.state_const),
            state_var_stkoff=anchor.state_var_stkoff,
            state_var_reg=anchor.state_var_reg,
            instruction_ea=int(anchor.instruction_ea),
        )
        if current not in seen:
            rebound.append(current)
            seen.add(current)
    return tuple(rebound)


@dataclass(frozen=True, slots=True)
class StateTransitionResolution:
    """Result of resolving one transition through a state-dispatcher map."""

    fact_id: str
    source_block_serial: int
    source_state_const_hex: str
    resolved_next_block_serial: int | None
    resolved_next_state_const_hex: str | None
    resolved_next_state_const_u64: int | None
    resolution_kind: str
    resolution_reason: str
    source_instruction_ea: int | None = None
    state_var_stkoff: int | None = None
    state_var_reg: int | None = None

    def to_diag_row(self, *, resolution_maturity: str) -> dict[str, object]:
        """Return the row shape expected by the diag snapshot sink."""
        return {
            "fact_id": self.fact_id,
            "source_block_serial": self.source_block_serial,
            "source_state_const_hex": self.source_state_const_hex,
            "resolved_next_block_serial": self.resolved_next_block_serial,
            "resolved_next_state_const_hex": self.resolved_next_state_const_hex,
            "resolved_next_state_const_u64": self.resolved_next_state_const_u64,
            "resolution_kind": self.resolution_kind,
            "resolution_reason": self.resolution_reason,
            "source_instruction_ea": self.source_instruction_ea,
            "resolution_maturity": str(resolution_maturity),
        }


@dataclass(frozen=True, slots=True)
class NativeBoundTransitionRoute:
    """Portable route evidence rebound to the current MBA.

    The native instruction EA is the cross-maturity identity.  The source
    block serial is deliberately the *current* serial returned by the caller's
    native-EA index; a serial recorded in a prior snapshot is never carried as
    authority.  ``state_constant`` is an exact 32-bit state value and
    ``target_handler_serial`` is the current dispatcher route target.
    """

    fact_id: str
    source_instruction_ea: int
    source_block_serial: int
    state_constant: int
    target_handler_serial: int

    def __post_init__(self) -> None:
        fact_id = str(self.fact_id).strip()
        if not fact_id:
            raise ValueError("native-bound transition route requires a fact id")
        source_instruction_ea = int(self.source_instruction_ea)
        if not 0 <= source_instruction_ea < 0xFFFFFFFFFFFFFFFF:
            raise ValueError("native-bound transition route requires a native EA")
        source_block_serial = int(self.source_block_serial)
        target_handler_serial = int(self.target_handler_serial)
        if source_block_serial < 0 or target_handler_serial < 0:
            raise ValueError("native-bound transition route serials must be non-negative")
        state_constant = int(self.state_constant)
        if not 0 <= state_constant <= 0xFFFFFFFF:
            raise ValueError("native-bound transition route state must be 32-bit")
        object.__setattr__(self, "fact_id", fact_id)
        object.__setattr__(self, "source_instruction_ea", source_instruction_ea)
        object.__setattr__(self, "source_block_serial", source_block_serial)
        object.__setattr__(self, "state_constant", state_constant)
        object.__setattr__(self, "target_handler_serial", target_handler_serial)

    @property
    def state(self) -> int:
        """Compatibility spelling for consumers that call the value ``state``."""
        return self.state_constant

    @property
    def target_block_serial(self) -> int:
        """Compatibility spelling for the exact handler target serial."""
        return self.target_handler_serial


def _serial_candidates(value: object | None) -> tuple[int, ...]:
    """Normalize one native-EA index result without accepting ambiguity."""
    if value is None:
        return ()
    if hasattr(value, "serial"):
        value = getattr(value, "serial")
    if isinstance(value, bool):
        return ()
    if isinstance(value, int):
        return (int(value),)
    try:
        values = tuple(int(item) for item in value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return ()
    if not values or len(set(values)) != 1:
        return ()
    return values


def _resolution_state_constant(resolution: object) -> int | None:
    """Read the source state while preserving a strict 32-bit boundary."""
    raw = getattr(resolution, "source_state_const", None)
    if raw is None:
        raw = getattr(resolution, "source_state_const_hex", None)
    if raw is None:
        return None
    if isinstance(raw, bool):
        return None
    try:
        if isinstance(raw, str):
            try:
                value = int(raw, 0)
            except ValueError:
                value = int(raw, 16)
        else:
            value = int(raw)
    except (OverflowError, TypeError, ValueError):
        return None
    if not 0 <= value <= 0xFFFFFFFF:
        return None
    return value


def _bounded_state_constant(value: object | None) -> int | None:
    """Parse one typed predecessor state without widening its 32-bit contract."""
    if value is None or isinstance(value, bool):
        return None
    try:
        if isinstance(value, str):
            try:
                value = int(value, 0)
            except ValueError:
                value = int(value, 16)
        else:
            value = int(value)
    except (OverflowError, TypeError, ValueError):
        return None
    return int(value) if 0 <= int(value) <= 0xFFFFFFFF else None


def _native_instruction_ea(value: object | None) -> int | None:
    """Parse one optional native instruction EA without accepting booleans."""
    if value is None or isinstance(value, bool):
        return None
    try:
        value = int(value)
    except (OverflowError, TypeError, ValueError):
        return None
    return value if 0 <= value < 0xFFFFFFFFFFFFFFFF else None


def _native_route_observation(
    observation: object,
) -> tuple[str, int, int, int, bool, int | None] | None:
    """Project either a raw resolution or a typed predecessor fact.

    The final boolean marks a typed predecessor fact.  Typed facts carry a
    source and target native identity; their recorded serials remain
    cross-maturity provenance only.
    """
    fact_id = getattr(observation, "fact_id", None)
    source_ea = getattr(observation, "source_instruction_ea", None)
    if not isinstance(fact_id, str) or not fact_id.strip() or source_ea is None:
        return None
    fact_id = fact_id.strip()
    source_ea = _native_instruction_ea(source_ea)
    if source_ea is None:
        return None

    if hasattr(observation, "target_block_serial"):
        resolver_kind = str(getattr(observation, "resolver_kind", ""))
        if resolver_kind not in SUPPORTED_PREDECESSOR_ROUTE_RESOLVERS:
            return None
        state = _bounded_state_constant(getattr(observation, "state_const", None))
        target = getattr(observation, "target_block_serial", None)
        if state is None or target is None or isinstance(target, bool):
            return None
        try:
            target = int(target)
        except (OverflowError, TypeError, ValueError):
            return None
        target_ea_value = getattr(observation, "target_native_ea", None)
        target_ea = (
            None
            if target_ea_value is None
            else _native_instruction_ea(target_ea_value)
        )
        if target_ea_value is None or target_ea is None:
            return None
        return str(fact_id), source_ea, state, target, True, target_ea

    if (
        str(getattr(observation, "resolution_reason", ""))
        not in SUCCESSFUL_TRANSITION_RESOLUTION_REASONS
    ):
        return None
    state = _resolution_state_constant(observation)
    target = getattr(observation, "resolved_next_block_serial", None)
    if state is None or target is None or isinstance(target, bool):
        return None
    try:
        return str(fact_id), source_ea, state, int(target), False, None
    except (OverflowError, TypeError, ValueError):
        return None


def bind_native_bound_transition_routes(
    resolutions: tuple[object, ...],
    *,
    block_serial_for_instruction_ea,
    current_block_serials: object | None = None,
    dispatcher_block_serials: object | None = None,
    route_target_for_state=None,
    dispatcher_map: StateDispatcherMap | None = None,
    state_var_stkoff: int | None = None,
    state_var_reg: int | None = None,
) -> tuple[NativeBoundTransitionRoute, ...]:
    """Select fail-closed native-bound route candidates from resolutions.

    This is a portable contract.  The caller supplies only a native-EA ->
    current-serial binder and current graph/router facts; no Hex-Rays object is
    imported or inspected here.  A recorded ``source_block_serial`` is retained
    only as diagnostic provenance and is never consulted for binding.
    """
    if dispatcher_map is not None:
        if state_var_stkoff is None:
            state_var_stkoff = dispatcher_map.state_var_stkoff
        if state_var_reg is None:
            state_var_reg = getattr(dispatcher_map, "state_var_reg", None)
        if dispatcher_block_serials is None:
            dispatcher_block_serials = dispatcher_map.dispatcher_blocks
        if route_target_for_state is None:
            route_target_for_state = dispatcher_map.resolve_target

    dispatcher_serials = {
        int(serial) for serial in (dispatcher_block_serials or ())
    }
    if dispatcher_map is not None:
        dispatcher_serials.add(int(dispatcher_map.dispatcher_entry_block))
        for row in dispatcher_map.rows:
            try:
                dispatcher_serials.add(int(row.dispatcher_block))
            except (AttributeError, OverflowError, TypeError, ValueError):
                pass
            compare_block = getattr(row, "compare_block", None)
            if compare_block is not None:
                try:
                    dispatcher_serials.add(int(compare_block))
                except (OverflowError, TypeError, ValueError):
                    pass
    if current_block_serials is None:
        if dispatcher_map is None:
            current_serials: set[int] = set()
        else:
            current_serials = {
                int(row.target_block) for row in dispatcher_map.rows
            } | dispatcher_serials
    else:
        current_serials = {int(serial) for serial in current_block_serials}

    expected_identity = (
        None if state_var_stkoff is None else int(state_var_stkoff),
        None if state_var_reg is None else int(state_var_reg),
    )
    # Bind every observation by native EA before selecting a route.  A
    # A predecessor fact's source/target serials are snapshot-local provenance;
    # native-EA bindings are current authority.  A concrete current router
    # answer must agree with a dual-bound target, while an incomplete router
    # may defer to that current native target binding.
    grouped_observations: dict[
        int, list[tuple[str, int, int, int, bool, int, int | None]]
    ] = {}
    invalid_source_eas: set[int] = set()
    for resolution in resolutions:
        source_hint = getattr(resolution, "source_instruction_ea", None)
        try:
            source_hint = (
                None
                if source_hint is None or isinstance(source_hint, bool)
                else int(source_hint)
            )
        except (OverflowError, TypeError, ValueError):
            source_hint = None
        if source_hint is not None and not (
            0 <= source_hint < 0xFFFFFFFFFFFFFFFF
        ):
            source_hint = None
        if source_hint is not None:
            if hasattr(resolution, "target_block_serial"):
                resolver_kind = str(getattr(resolution, "resolver_kind", ""))
                state = _bounded_state_constant(
                    getattr(resolution, "state_const", None)
                )
                target = getattr(resolution, "target_block_serial", None)
                if (
                    resolver_kind not in SUPPORTED_PREDECESSOR_ROUTE_RESOLVERS
                    or state is None
                    or target is None
                    or isinstance(target, bool)
                ):
                    invalid_source_eas.add(source_hint)
            else:
                reason = str(getattr(resolution, "resolution_reason", ""))
                state = _resolution_state_constant(resolution)
                target = getattr(resolution, "resolved_next_block_serial", None)
                if (
                    reason not in SUCCESSFUL_TRANSITION_RESOLUTION_REASONS
                    or state is None
                    or target is None
                    or isinstance(target, bool)
                ):
                    invalid_source_eas.add(source_hint)
        projected = _native_route_observation(resolution)
        if projected is None and source_hint is not None:
            # A malformed observation sharing a native EA poisons the complete
            # group.  Silently dropping it would let a valid sibling win over
            # contradictory or corrupted evidence.
            invalid_source_eas.add(source_hint)
        if projected is None:
            continue
        (
            fact_id,
            source_ea,
            state_constant,
            target_serial,
            typed_fact,
            target_native_ea,
        ) = projected
        try:
            bound_serials = _serial_candidates(
                block_serial_for_instruction_ea(source_ea)
            )
        except (AttributeError, OverflowError, TypeError, ValueError):
            invalid_source_eas.add(source_ea)
            continue
        if not 0 <= source_ea < 0xFFFFFFFFFFFFFFFF or len(bound_serials) != 1:
            invalid_source_eas.add(source_ea)
            continue
        source_serial = bound_serials[0]
        if source_serial < 0:
            invalid_source_eas.add(source_ea)
            continue

        if not typed_fact:
            resolution_identity = (
                getattr(resolution, "state_var_stkoff", None),
                getattr(resolution, "state_var_reg", None),
            )
            try:
                resolution_identity = (
                    None
                    if resolution_identity[0] is None
                    else int(resolution_identity[0]),
                    None
                    if resolution_identity[1] is None
                    else int(resolution_identity[1]),
                )
            except (OverflowError, TypeError, ValueError):
                invalid_source_eas.add(source_ea)
                continue
            if expected_identity == (None, None) or (
                resolution_identity != expected_identity
            ):
                invalid_source_eas.add(source_ea)
                continue
        # A malformed prior target is not useful provenance.  It must not be
        # coerced into a current target by an adapter, even though typed facts
        # do not compare this old serial to the current route numerically.
        if target_serial < 0:
            invalid_source_eas.add(source_ea)
            continue
        grouped_observations.setdefault(source_ea, []).append(
            (
                fact_id,
                source_ea,
                state_constant,
                target_serial,
                typed_fact,
                source_serial,
                target_native_ea,
            )
        )

    # Resolve each source group against the selected *current* router.  Raw
    # resolution rows retain their stricter prior-target corroboration, while
    # typed predecessor facts deliberately treat that target as provenance
    # only.  Any malformed/conflicting member rejects the complete group.
    grouped: dict[
        tuple[int, int], list[tuple[str, int, int, int, int, bool]]
    ] = {}
    for source_ea, observations in grouped_observations.items():
        if source_ea in invalid_source_eas:
            continue
        source_serials = {item[5] for item in observations}
        if len(source_serials) != 1:
            continue
        typed_prior_targets: dict[int, set[int]] = {}
        typed_target_native_eas: set[int] = set()
        for item in observations:
            (
                _fact_id,
                _ea,
                state_constant,
                prior_target,
                typed_fact,
                _serial,
                target_native_ea,
            ) = item
            if typed_fact:
                typed_prior_targets.setdefault(state_constant, set()).add(
                    prior_target
                )
                if target_native_ea is not None:
                    typed_target_native_eas.add(target_native_ea)
        if any(len(targets) != 1 for targets in typed_prior_targets.values()):
            # Contradictory predecessor provenance is itself a failed
            # corroboration.  Do not silently select one typed fact merely
            # because the current router happens to agree for both.
            continue
        if len(typed_target_native_eas) > 1:
            # Two native target identities for one source group cannot be
            # reconciled by a stale serial or by whichever route happens to
            # win in the current dispatcher.
            continue
        bound_target_serial: int | None = None
        if typed_target_native_eas:
            target_native_ea = next(iter(typed_target_native_eas))
            try:
                bound_target_serials = _serial_candidates(
                    block_serial_for_instruction_ea(target_native_ea)
                )
            except (AttributeError, OverflowError, TypeError, ValueError):
                continue
            if len(bound_target_serials) != 1:
                continue
            bound_target_serial = bound_target_serials[0]
            if (
                bound_target_serial < 0
                or bound_target_serial not in current_serials
                or bound_target_serial in dispatcher_serials
            ):
                continue
        candidates: list[tuple[str, int, int, int, int, bool]] = []
        invalid_group = False
        for (
            fact_id,
            _source_ea,
            state_constant,
            prior_target_serial,
            typed_fact,
            source_serial,
            _target_native_ea,
        ) in observations:
            routed_targets: tuple[int, ...] = ()
            if route_target_for_state is not None:
                try:
                    routed_targets = _serial_candidates(
                        route_target_for_state(state_constant)
                    )
                except (TypeError, ValueError, AttributeError):
                    invalid_group = True
                    break
            if len(routed_targets) == 1:
                routed_target_serial = routed_targets[0]
                if routed_target_serial not in current_serials:
                    invalid_group = True
                    break
                if routed_target_serial in dispatcher_serials:
                    if bound_target_serial is None:
                        invalid_group = True
                        break
                    current_target_serial = bound_target_serial
                else:
                    if (
                        bound_target_serial is not None
                        and routed_target_serial != bound_target_serial
                    ):
                        invalid_group = True
                        break
                    current_target_serial = routed_target_serial
            elif bound_target_serial is not None:
                # A dual-bound native target is sufficient when the current
                # router has no concrete non-dispatcher answer (for example,
                # it returns None, an ambiguous result, or a topology block).
                current_target_serial = bound_target_serial
            else:
                invalid_group = True
                break
            if not typed_fact and prior_target_serial != current_target_serial:
                invalid_group = True
                break
            candidates.append(
                (
                    fact_id,
                    source_ea,
                    source_serial,
                    state_constant,
                    current_target_serial,
                    typed_fact,
                )
            )
        if invalid_group or not candidates:
            continue
        route_pairs = {(item[3], item[4]) for item in candidates}
        if len(route_pairs) != 1:
            continue
        grouped[(source_ea, next(iter(source_serials)))] = candidates

    selected: list[NativeBoundTransitionRoute] = []
    for items in grouped.values():
        route_pairs = {(item[3], item[4]) for item in items}
        if len(route_pairs) != 1:
            continue
        fact_id, source_ea, source_serial, state_constant, target_serial, _ = min(
            items,
            # If both safe paths are present, use typed predecessor evidence as
            # the single authority for this source rather than duplicating it.
            key=lambda item: (not item[5], str(item[0])),
        )
        selected.append(
            NativeBoundTransitionRoute(
                fact_id=fact_id,
                source_instruction_ea=source_ea,
                source_block_serial=source_serial,
                state_constant=state_constant,
                target_handler_serial=target_serial,
            )
        )
    return tuple(
        sorted(
            selected,
            key=lambda route: (
                route.source_instruction_ea,
                route.source_block_serial,
                route.fact_id,
            ),
        )
    )


# The selector spelling is useful to callers that treat this as a pure
# candidate-selection step rather than a native adapter operation.
select_native_bound_transition_routes = bind_native_bound_transition_routes


def _hex_u64(value: int) -> str:
    return f"0x{int(value) & 0xFFFFFFFFFFFFFFFF:016x}"


def _state_write_lookup(
    anchors: tuple[StateWriteAnchor, ...],
) -> dict[tuple[int, int | None, int | None], int]:
    lookup: dict[tuple[int, int | None, int | None], int] = {}
    for anchor in anchors:
        key = (
            int(anchor.block_serial),
            anchor.state_var_stkoff,
            anchor.state_var_reg,
        )
        lookup.setdefault(key, int(anchor.state_const) & 0xFFFFFFFFFFFFFFFF)
    return lookup


def _select_state_write(
    lookup: dict[tuple[int, int | None, int | None], int],
    *,
    block_serial: int,
    state_var_stkoff: int | None,
    state_var_reg: int | None,
) -> int | None:
    exact = lookup.get((int(block_serial), state_var_stkoff, state_var_reg))
    if exact is not None:
        return exact
    if state_var_stkoff is not None:
        return lookup.get((int(block_serial), None))
    for (
        candidate_block,
        _candidate_stkoff,
        _candidate_reg,
    ), state_const in lookup.items():
        if candidate_block == int(block_serial):
            return state_const
    return None


def _route_target(
    model: object | None,
    dispatch_map: StateDispatcherMap,
    source_state: int,
) -> int | None:
    """Route a source state to a target block via ``model.route()`` (S2) or exact rows.

    When a ``model`` (e.g. ``ComparisonDispatcherModel``) is supplied, route
    through it and unwrap a single :class:`Block` (interval-aware); else fall
    back to the exact-only ``dispatch_map.resolve_target`` (legacy behaviour).
    """
    if model is not None and hasattr(model, "route"):
        rr = model.route(int(source_state))
        return rr.serial if isinstance(rr, Block) else None
    return dispatch_map.resolve_target(int(source_state))


def _build_corridor_path(
    graph: object,
    target_block: int,
    dispatch_map: StateDispatcherMap,
    *,
    max_hops: int = _MAX_CORRIDOR_HOPS,
) -> tuple[int, ...]:
    """Follow the UNIQUE successor chain from *target_block* into a corridor path.

    Stops when a block has != 1 successor, when the next block re-enters the
    dispatcher, on a cycle, or after *max_hops* hops.  The returned path always
    starts with ``target_block`` so the snapshot path-eval can carry the
    handler-local const env (the two ``mov #const`` register loads) forward into
    the corridor block that performs the binop state write.
    """
    path: list[int] = [int(target_block)]
    visited: set[int] = {int(target_block)}
    current = int(target_block)
    for _ in range(max_hops):
        block = graph.get_block(current)
        if block is None:
            break
        succs = tuple(block.succs)
        if len(succs) != 1:
            break
        nxt = int(succs[0])
        if nxt in visited or nxt in dispatch_map.dispatcher_blocks:
            break
        path.append(nxt)
        visited.add(nxt)
        current = nxt
    return tuple(path)


def _fold_corridor_state_write(
    graph: object | None,
    dispatch_map: StateDispatcherMap,
    *,
    target_block: int,
    state_var_stkoff: int | None,
) -> int | None:
    """Fold a binop-computed next-state along *target_block*'s single corridor.

    Returns the folded 32-bit next-state ONLY when it is a known dispatcher
    target (``dispatch_map.resolve_target`` succeeds, or it appears as a state
    constant in the map); otherwise ``None`` so the caller keeps the next-state
    BLANK.  This handles UNCONDITIONAL single-corridor handlers only.
    """
    if graph is None or state_var_stkoff is None:
        return None

    ordered_path = _build_corridor_path(graph, int(target_block), dispatch_map)
    folded = find_last_state_write_site_on_path_snapshot(
        graph,
        ordered_path,
        int(state_var_stkoff),
    )
    if folded is None:
        return None

    _write_block, site = folded
    candidate = int(site.state_value) & 0xFFFFFFFF
    known_states = set(dispatch_map.state_to_handler().keys())
    if dispatch_map.resolve_target(candidate) is not None or candidate in known_states:
        return candidate
    return None


def resolve_state_transitions_with_dispatcher_map(
    transition_facts: tuple[StateTransitionFact, ...],
    *,
    dispatch_map: StateDispatcherMap | None,
    state_write_anchors: tuple[StateWriteAnchor, ...] = (),
    resolution_kind: str = "state_dispatcher_map",
    model: object | None = None,
    graph: object | None = None,
    state_var_stkoff: int | None = None,
) -> tuple[StateTransitionResolution, ...]:
    """Resolve transition facts using in-memory dispatcher rows.

    ``model`` (S2) is an optional ``ComparisonDispatcherModel`` (any object with
    a ``route(value) -> RouteResult`` method).  When supplied, routing goes
    through ``model.route()`` — exact *and* interval rows — so an interval-routed
    next-state (``0x79F598F7 ∈ [..] -> blk 52``) resolves instead of being
    dropped as ``"state_not_in_dispatcher_map"`` (the 28-orphan fix).  Absent a
    model, routing stays exact-only via ``dispatch_map.resolve_target``
    (byte-identical legacy behaviour).
    """
    write_lookup = _state_write_lookup(state_write_anchors)
    resolutions: list[StateTransitionResolution] = []
    for fact in transition_facts:
        source_state = int(fact.source_state_const) & 0xFFFFFFFFFFFFFFFF
        source_hex = fact.source_state_const_hex or _hex_u64(source_state)
        target_block: int | None = None
        next_state: int | None = None
        next_state_hex: str | None = None

        if fact.successor_kind != "branch":
            reason = (
                f"successor_kind={fact.successor_kind}; "
                "not a dispatcher-bound transition"
            )
        elif dispatch_map is None or not dispatch_map.rows:
            reason = "no_dispatcher_rows_available"
        else:
            target_block = _route_target(model, dispatch_map, source_state)
            if target_block is None:
                reason = "state_not_in_dispatcher_map"
            elif target_block in dispatch_map.dispatcher_blocks:
                reason = "target_is_dispatcher_block"
                target_block = None
            else:
                next_state = _select_state_write(
                    write_lookup,
                    block_serial=target_block,
                    state_var_stkoff=fact.state_var_stkoff,
                    state_var_reg=fact.state_var_reg,
                )
                if next_state is not None:
                    next_state_hex = _hex_u64(next_state)
                    reason = "resolved_exact_state"
                else:
                    # No LITERAL state-write anchor at the routed handler: the
                    # next-state is binop-computed (e.g. ``xor eax,ecx``).  Fold
                    # it along the handler's single corridor.  Additive/safe:
                    # only fills a previously-BLANK next-state, never overrides
                    # an existing literal resolution.
                    fold_stkoff = (
                        fact.state_var_stkoff
                        if fact.state_var_stkoff is not None
                        else state_var_stkoff
                        if state_var_stkoff is not None
                        else dispatch_map.state_var_stkoff
                    )
                    folded = _fold_corridor_state_write(
                        graph,
                        dispatch_map,
                        target_block=target_block,
                        state_var_stkoff=fold_stkoff,
                    )
                    if folded is not None:
                        next_state = folded
                        next_state_hex = _hex_u64(next_state)
                        reason = "resolved_folded_state_write"
                    else:
                        reason = "resolved_exact_state"

        resolutions.append(
            StateTransitionResolution(
                fact_id=str(fact.fact_id),
                source_block_serial=int(fact.source_block_serial),
                source_state_const_hex=str(source_hex),
                resolved_next_block_serial=target_block,
                resolved_next_state_const_hex=next_state_hex,
                resolved_next_state_const_u64=next_state,
                resolution_kind=resolution_kind,
                resolution_reason=reason,
                source_instruction_ea=(
                    None
                    if fact.source_instruction_ea is None
                    else int(fact.source_instruction_ea)
                ),
                state_var_stkoff=(
                    None
                    if fact.state_var_stkoff is None
                    else int(fact.state_var_stkoff)
                ),
                state_var_reg=(
                    None if fact.state_var_reg is None else int(fact.state_var_reg)
                ),
            )
        )
    return tuple(resolutions)


def facts_from_validated_view(
    fact_view: object | None,
) -> tuple[tuple[StateTransitionFact, ...], tuple[StateWriteAnchor, ...]]:
    """Project a validated fact view into in-memory transition evidence."""
    if fact_view is None:
        return (), ()
    observations = tuple(getattr(fact_view, "active_observations", ()) or ())
    transition_facts: list[StateTransitionFact] = []
    state_write_anchors: list[StateWriteAnchor] = []

    for observation in observations:
        kind = str(getattr(observation, "kind", ""))
        payload = dict(getattr(observation, "payload", {}) or {})
        if kind == "StateTransitionAnchorFact":
            source_block = payload.get("source_block_serial")
            source_state = payload.get("source_state_const")
            if source_block is None or source_state is None:
                continue
            try:
                transition_facts.append(
                    StateTransitionFact(
                        fact_id=str(getattr(observation, "fact_id")),
                        source_block_serial=int(source_block),
                        source_state_const=int(source_state),
                        source_state_const_hex=_maybe_str(
                            payload.get("source_state_const_hex")
                        ),
                        successor_kind=str(payload.get("successor_kind", "branch")),
                        state_var_stkoff=_maybe_int(payload.get("state_var_stkoff")),
                        state_var_reg=_maybe_int(payload.get("state_var_reg")),
                        source_instruction_ea=_maybe_int(
                            payload.get("source_instruction_ea")
                        ),
                    )
                )
            except (TypeError, ValueError):
                continue
        elif kind == "StateWriteAnchorFact":
            block_serial = payload.get("block_serial")
            state_const = payload.get("state_const_u64")
            if state_const is None:
                state_const = payload.get("state_const")
            if block_serial is None or state_const is None:
                continue
            try:
                state_write_anchors.append(
                    StateWriteAnchor(
                        block_serial=int(block_serial),
                        state_const=int(state_const),
                        state_var_stkoff=_maybe_int(payload.get("state_var_stkoff")),
                        state_var_reg=_maybe_int(payload.get("state_var_reg")),
                        instruction_ea=_maybe_int(payload.get("instruction_ea")),
                    )
                )
            except (TypeError, ValueError):
                continue

    return tuple(transition_facts), tuple(state_write_anchors)


def _maybe_int(value: object | None) -> int | None:
    if value is None:
        return None
    try:
        if isinstance(value, str):
            return int(value, 0)
        return int(value)
    except (TypeError, ValueError):
        return None


def _maybe_str(value: object | None) -> str | None:
    if value is None:
        return None
    return str(value)


class SemanticTransitionKind(str, enum.Enum):
    """Normalized vocabulary for every state-transition source (LS11 C7)."""

    HANDLER_WRITE = "handler_write"
    CASE_WRITE = "case_write"
    LOOP_UPDATE = "loop_update"
    CARRIED_STATE = "carried_state"
    CONDITIONAL_RETURN = "conditional_return"
    EXIT_ROUTINE = "exit_routine"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class SemanticTransition:
    """One normalized semantic state transition (LS11 C7).

    ``subject`` carries portable value identity (LS11 C4) for the value whose
    write drives the transition, typed as ``d810.ir.ValueRef`` (analyses -> ir
    is downward-legal).  Net-new and unwired in LS11; future slices consume it
    in place of the ad-hoc transition shapes scattered across the dispatcher
    cluster.
    """

    source_block_serial: int
    source_state_const: int
    kind: SemanticTransitionKind
    target_block_serial: int | None = None
    target_state_const: int | None = None
    subject: ValueRef | None = None
    source_state_const_hex: str | None = None
    evidence_fact_id: str | None = None


def semantic_transition_from_fact(
    fact: StateTransitionFact,
) -> SemanticTransition:
    """Project a legacy ``StateTransitionFact`` into the normalized vocabulary.

    Conservative: an unrecognized ``successor_kind`` maps to ``UNKNOWN`` rather
    than guessing a specific transition source.
    """
    kind = (
        SemanticTransitionKind.HANDLER_WRITE
        if fact.successor_kind == "branch"
        else SemanticTransitionKind.UNKNOWN
    )
    return SemanticTransition(
        source_block_serial=fact.source_block_serial,
        source_state_const=fact.source_state_const,
        kind=kind,
        source_state_const_hex=fact.source_state_const_hex,
        evidence_fact_id=fact.fact_id,
    )


def resolve_state_transitions(
    graph,
    facts,
    *,
    dispatch_map: "StateDispatcherMap | None" = None,
    model: object | None = None,
    state_var_stkoff: int | None = None,
) -> "tuple[StateTransitionResolution, ...]":
    """unflatten pass #2: resolve transition facts through the portable dispatcher map.

    Composes the canonical portable resolver — ``facts_from_validated_view`` projects the
    validated facts into ``(transition_facts, state_write_anchors)``, then
    ``resolve_state_transitions_with_dispatcher_map`` resolves each transition. LiSA-style: this is
    the transfer step over the state-machine graph. ``dispatch_map`` is the seam input produced by
    ``recover_dispatcher``; while it is ``None`` (state-machine detection not yet ported into this
    portable resolver), transitions resolve to an explicit ``unresolved`` kind
    rather than silently dropping. ``graph``/``facts`` are duck-typed (FlowGraph / ValidatedFactView).
    """
    transition_facts, state_write_anchors = facts_from_validated_view(facts)
    return resolve_state_transitions_with_dispatcher_map(
        transition_facts,
        dispatch_map=dispatch_map,
        state_write_anchors=state_write_anchors,
        model=model,
        graph=graph,
        state_var_stkoff=state_var_stkoff,
    )


__all__ = [
    "SemanticTransition",
    "SemanticTransitionKind",
    "NativeBoundTransitionRoute",
    "SUCCESSFUL_TRANSITION_RESOLUTION_REASONS",
    "bind_native_bound_transition_routes",
    "facts_from_validated_view",
    "rebind_state_write_anchors",
    "select_native_bound_transition_routes",
    "semantic_transition_from_fact",
    "resolve_state_transitions",
    "StateTransitionFact",
    "StateTransitionResolution",
    "StateWriteAnchor",
    "resolve_state_transitions_with_dispatcher_map",
]

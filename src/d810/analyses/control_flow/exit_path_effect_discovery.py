from __future__ import annotations

import enum
from dataclasses import dataclass

from d810.analyses.control_flow.terminal_frontier import (
    TerminalCfgSuffixFrontier,
    TerminalLoweringAction,
    classify_cfg_suffix_action,
    compute_terminal_cfg_suffix_frontier,
)
from d810.ir.flowgraph import PredicateKind, InsnKind, OperandKind
from d810.core.typing import AbstractSet, Mapping, Protocol, Sequence
from d810.analyses.control_flow.carrier_resolution import CarrierResolver
from d810.analyses.control_flow.state_machine_analysis import (
    CarrierResolutionResult,
    ResolutionMethod,
    find_terminal_exit_target_snapshot,
)
from d810.analyses.control_flow.transition_builder import _get_state_var_stkoff


class CarrierSourceKind(str, enum.Enum):
    """Classify what the forward-frontier candidate block carries."""

    STATE_CONST = "state_const"
    REAL_CONST = "real_const"
    CURSOR_OR_PTR = "cursor_or_ptr"
    EXPR = "expr"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ForwardFrontierEntry:
    """Per-handler-entry forward ownership frontier diagnostic record."""

    handler_entry: int
    exit_path: tuple[int, ...]
    forward_candidate: int | None
    candidate_succ: int | None
    shared_entry: int | None
    return_block: int | None
    suffix_serials: tuple[int, ...]
    semantic_action: TerminalLoweringAction
    carrier_source_kind: CarrierSourceKind
    proof_status: str
    notes: str = ""
    state_const_written: int | None = None
    requires_dtl: bool = False


class ExitPathShape(str, enum.Enum):
    """Shape classification of a shared exit path."""

    LINEAR = "linear"
    FAN_IN = "fan_in"
    BRANCHING = "branching"
    COMPLEX = "complex"


class ExitPathRecommendation(str, enum.Enum):
    """Recommended semantic action for a shared exit-path effect group."""

    PRIVATE_RETURN_BLOCK = "private_return_block"
    PRIVATE_TERMINAL_SUFFIX = "private_terminal_suffix"
    PRIVATE_EXIT_PATH_EFFECT = "private_exit_path_effect"
    DIRECT_TERMINAL_LOWERING = "direct_terminal_lowering"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True, slots=True)
class SharedExitPathInfo:
    """Diagnostic info for a shared exit-path effect group."""

    shared_entry: int
    return_block: int
    suffix_serials: tuple[int, ...]
    exit_path_blocks: tuple[int, ...]
    exit_path_shape: ExitPathShape
    exit_path_length: int
    handler_entries: tuple[int, ...]
    handler_count: int
    entry_fan_in: int
    carrier_in_exit_path: bool
    clonable: bool
    recommendation: ExitPathRecommendation
    notes: str


@dataclass(frozen=True, slots=True)
class ExitPathEffectGroup:
    """Shared exit-path effect facts harvested from a snapshot."""

    state_var_stkoff: int
    terminal_target: int
    cfg_frontier: TerminalCfgSuffixFrontier
    semantic_action: TerminalLoweringAction
    full_infra: frozenset[int]
    anchors: tuple[int, ...]
    known_state_constants: frozenset[int]
    forward_entries: tuple[ForwardFrontierEntry, ...]
    exit_path_info: SharedExitPathInfo

    @property
    def shared_entry(self) -> int:
        return int(self.cfg_frontier.shared_entry_serial)

    @property
    def return_block(self) -> int:
        return int(self.cfg_frontier.return_block_serial)

    @property
    def suffix_serials(self) -> tuple[int, ...]:
        return tuple(int(serial) for serial in self.cfg_frontier.suffix_serials)


@dataclass(frozen=True, slots=True)
class ExitPathEffectDiscoveryResult:
    """Result wrapper so callers can log why discovery failed."""

    group: ExitPathEffectGroup | None
    failure_reason: str | None = None


class _StateMachineHandlerLike(Protocol):
    check_block: int
    handler_blocks: Sequence[int]


class _StateMachineLike(Protocol):
    handlers: Mapping[int, _StateMachineHandlerLike]
    state_var: object | None


class _ExitPathEffectSnapshot(Protocol):
    flow_graph: object | None
    state_machine: _StateMachineLike | None
    dispatcher_serial: int
    detector: object | None
    dispatcher_blocks: AbstractSet[int]
    carrier_resolver: CarrierResolver | None
    state_var_stkoff: int | None
    state_constants: AbstractSet[int]


def _collect_state_machine_blocks(state_machine: _StateMachineLike | None) -> set[int]:
    if state_machine is None:
        return set()
    blocks: set[int] = set()
    for handler in state_machine.handlers.values():
        blocks.add(int(handler.check_block))
        blocks.update(int(serial) for serial in handler.handler_blocks)
    return blocks


def resolve_state_var_stkoff(snapshot: _ExitPathEffectSnapshot) -> int | None:
    """Resolve the state variable stack offset from a snapshot."""

    state_var_stkoff: int | None = None
    detector = snapshot.detector
    if detector is not None:
        try:
            state_var_stkoff = _get_state_var_stkoff(detector)
        except Exception:
            pass
    # Explicit evidence carried by the snapshot producer (preferred):
    # the state-var offset is input, not a live dataflow query.
    if state_var_stkoff is None:
        explicit = getattr(snapshot, "state_var_stkoff", None)
        if explicit is not None:
            state_var_stkoff = int(explicit)
    # Portable state-variable representation, if the producer attached one.
    if (
        state_var_stkoff is None
        and snapshot.state_machine is not None
        and snapshot.state_machine.state_var is not None
    ):
        sv = snapshot.state_machine.state_var
        if getattr(sv, "kind", None) is OperandKind.STACK:
            off = getattr(sv, "stkoff", None)
            if off is not None:
                state_var_stkoff = int(off)
    return state_var_stkoff


def _resolve_pre_header_serial(
    flow_graph,
    *,
    dispatcher_serial: int,
    dispatcher_blocks: set[int],
) -> int | None:
    blk0 = flow_graph.get_block(0)
    if blk0 is None or blk0.nsucc != 1:
        return None
    succ0 = blk0.succs[0] if blk0.succs else None
    if succ0 is None:
        return None
    if succ0 == dispatcher_serial or succ0 in dispatcher_blocks:
        return 0
    return None


def _extract_const_from_snapshot_mop(mop_snap: object) -> int | None:
    if mop_snap is None:
        return None
    if getattr(mop_snap, "kind", None) is not OperandKind.NUMBER:
        return None
    val = getattr(mop_snap, "value", None)
    if val is not None:
        return int(val)
    return None


def _mop_matches_stkoff_snapshot(mop_snap: object | None, stkoff: int) -> bool:
    if mop_snap is None:
        return False
    return getattr(mop_snap, "stkoff", None) == stkoff


def _is_exit_path_control_flow_insn(insn: object) -> bool:
    """Match the original local set {m_goto, m_jnz, m_ijmp, m_jtbl}.

    Exact parity via portable kinds: exit_path control flow is ``GOTO``,
    ``m_jnz`` (``EQUALITY_JUMP`` with a ``NOT_EQUAL`` predicate -- NOT
    ``m_jz``), ``INDIRECT_JUMP`` (``m_ijmp``), or ``TABLE_JUMP``
    (``m_jtbl``).  Anything else in a exit_path block counts as a carrier
    (semantic) instruction.
    """
    kind = insn.kind
    return (
        kind is InsnKind.GOTO
        or (
            kind is InsnKind.EQUALITY_JUMP
            and insn.branch_predicate is PredicateKind.NE
        )
        or kind is InsnKind.INDIRECT_JUMP
        or kind is InsnKind.TABLE_JUMP
    )


def classify_carrier_source_rich(
    flow_graph,
    candidate_serial: int,
    state_var_stkoff: int,
    infra_blocks: frozenset[int],
    *,
    resolver: CarrierResolver | None = None,
) -> CarrierResolutionResult:
    del infra_blocks
    blk_snap = flow_graph.get_block(candidate_serial)
    if blk_snap is None:
        return CarrierResolutionResult(kind=CarrierSourceKind.UNKNOWN.value)

    has_state_write = False
    has_const_write = False
    has_ptr_write = False
    has_expr_write = False
    state_const_written: int | None = None
    state_write_source_indirect = False
    resolution: CarrierResolutionResult | None = None

    for insn in blk_snap.iter_insns():
        if insn.kind is InsnKind.MOV and insn.d is not None:
            if _mop_matches_stkoff_snapshot(insn.d, state_var_stkoff):
                has_state_write = True
                const_val = _extract_const_from_snapshot_mop(insn.l)
                if const_val is not None:
                    state_const_written = const_val
                elif insn.l is not None:
                    state_write_source_indirect = True
                continue
            if insn.l is not None:
                src_kind = insn.l.kind
                if src_kind is OperandKind.NUMBER:
                    has_const_write = True
                elif src_kind is OperandKind.ADDRESS:
                    has_ptr_write = True
                elif src_kind is not None:
                    has_expr_write = True

    if (
        has_state_write
        and state_const_written is None
        and state_write_source_indirect
        and resolver is not None
    ):
        try:
            resolution = resolver.resolve_indirect_state_write(
                candidate_serial,
                state_var_stkoff,
            )
            if resolution is not None:
                state_const_written = resolution.const_value
        except Exception:
            pass

    if has_state_write and not (has_const_write or has_ptr_write or has_expr_write):
        kind = CarrierSourceKind.STATE_CONST
    elif has_const_write and not has_state_write:
        kind = CarrierSourceKind.REAL_CONST
    elif has_ptr_write:
        kind = CarrierSourceKind.CURSOR_OR_PTR
    elif has_expr_write:
        kind = CarrierSourceKind.EXPR
    else:
        kind = CarrierSourceKind.UNKNOWN

    if resolution is not None:
        return CarrierResolutionResult(
            kind=kind.value,
            const_value=state_const_written,
            method=resolution.method,
            def_blk_serial=resolution.def_blk_serial,
            def_insn_ea=resolution.def_insn_ea,
            source_mop_type=resolution.source_mop_type,
            source_stkoff=resolution.source_stkoff,
            source_mreg=resolution.source_mreg,
        )
    return CarrierResolutionResult(
        kind=kind.value,
        const_value=state_const_written,
        method=ResolutionMethod.SNAPSHOT,
    )


def classify_carrier_source(
    flow_graph,
    candidate_serial: int,
    state_var_stkoff: int,
    infra_blocks: frozenset[int],
    *,
    resolver: CarrierResolver | None = None,
) -> tuple[CarrierSourceKind, int | None]:
    result = classify_carrier_source_rich(
        flow_graph,
        candidate_serial,
        state_var_stkoff,
        infra_blocks,
        resolver=resolver,
    )
    return CarrierSourceKind(result.kind), result.const_value


def discover_shared_exit_path(
    flow_graph,
    shared_entry_serial: int,
    suffix_serials: tuple[int, ...],
    full_infra: frozenset[int],
    forward_entries: list[ForwardFrontierEntry] | tuple[ForwardFrontierEntry, ...],
) -> SharedExitPathInfo:
    suffix_set = frozenset(suffix_serials)

    handler_entries_list: list[int] = []
    return_block = 0
    for entry in forward_entries:
        handler_entries_list.append(int(entry.handler_entry))
        if entry.return_block is not None:
            return_block = int(entry.return_block)
    handler_entries_tuple = tuple(sorted(set(handler_entries_list)))

    exit_path: list[int] = []
    if shared_entry_serial not in suffix_set:
        current = shared_entry_serial
        visited: set[int] = set()
        while current not in suffix_set and current not in visited:
            visited.add(current)
            exit_path.append(current)
            succs = flow_graph.successors(current)
            if len(succs) != 1:
                break
            nxt = succs[0]
            if nxt in suffix_set or nxt == return_block:
                break
            current = nxt

    exit_path_tuple = tuple(exit_path)
    exit_path_length = len(exit_path_tuple)

    has_branching = False
    has_fan_in = False
    exit_path_set = frozenset(exit_path_tuple)
    for blk_serial in exit_path_tuple:
        blk_snap = flow_graph.get_block(blk_serial)
        if blk_snap is None:
            continue
        if blk_snap.nsucc > 1:
            has_branching = True
        outside_preds = [pred for pred in blk_snap.preds if pred not in exit_path_set]
        if len(outside_preds) > 1:
            has_fan_in = True

    if has_branching and has_fan_in:
        exit_path_shape = ExitPathShape.COMPLEX
    elif has_branching:
        exit_path_shape = ExitPathShape.BRANCHING
    elif has_fan_in:
        exit_path_shape = ExitPathShape.FAN_IN
    else:
        exit_path_shape = ExitPathShape.LINEAR

    entry_fan_in = 0
    if exit_path_tuple:
        entry_snap = flow_graph.get_block(exit_path_tuple[0])
        if entry_snap is not None:
            entry_fan_in = len([pred for pred in entry_snap.preds if pred not in exit_path_set])

    carrier_in_exit_path = False
    for blk_serial in exit_path_tuple:
        blk_snap = flow_graph.get_block(blk_serial)
        if blk_snap is None:
            continue
        for insn in blk_snap.iter_insns():
            if not _is_exit_path_control_flow_insn(insn):
                carrier_in_exit_path = True
                break
        if carrier_in_exit_path:
            break

    handler_count = len(handler_entries_tuple)
    clonable = (
        exit_path_shape in (ExitPathShape.LINEAR, ExitPathShape.FAN_IN)
        and exit_path_length <= 8
        and handler_count >= 2
    )

    notes_parts: list[str] = []
    if handler_count < 2:
        recommendation = ExitPathRecommendation.UNRESOLVED
        notes_parts.append("handler_count < 2")
    elif exit_path_shape in (ExitPathShape.BRANCHING, ExitPathShape.COMPLEX):
        recommendation = ExitPathRecommendation.UNRESOLVED
        notes_parts.append("exit_path has branching/complex shape")
    elif exit_path_length == 0:
        recommendation = ExitPathRecommendation.PRIVATE_TERMINAL_SUFFIX
        notes_parts.append("degenerate exit_path (length=0)")
    elif clonable:
        recommendation = ExitPathRecommendation.PRIVATE_EXIT_PATH_EFFECT
        notes_parts.append(
            "exit_path clonable (len=%d, shape=%s)"
            % (exit_path_length, exit_path_shape.value)
        )
    else:
        recommendation = ExitPathRecommendation.UNRESOLVED
        notes_parts.append("exit_path not clonable")

    return SharedExitPathInfo(
        shared_entry=int(shared_entry_serial),
        return_block=int(return_block),
        suffix_serials=tuple(int(serial) for serial in suffix_serials),
        exit_path_blocks=exit_path_tuple,
        exit_path_shape=exit_path_shape,
        exit_path_length=exit_path_length,
        handler_entries=handler_entries_tuple,
        handler_count=handler_count,
        entry_fan_in=entry_fan_in,
        carrier_in_exit_path=carrier_in_exit_path,
        clonable=clonable,
        recommendation=recommendation,
        notes="; ".join(notes_parts) if notes_parts else "",
    )


def discover_exit_path_effect_group(
    snapshot: _ExitPathEffectSnapshot,
    *,
    anchor_note: str,
) -> ExitPathEffectDiscoveryResult:
    if snapshot.flow_graph is None:
        return ExitPathEffectDiscoveryResult(None, "missing_flow_graph")
    if snapshot.state_machine is None:
        return ExitPathEffectDiscoveryResult(None, "missing_state_machine")

    state_var_stkoff = resolve_state_var_stkoff(snapshot)
    if state_var_stkoff is None:
        return ExitPathEffectDiscoveryResult(None, "state_var_stkoff is None")

    flow_graph = snapshot.flow_graph
    dispatcher_serial = int(snapshot.dispatcher_serial)
    if dispatcher_serial < 0:
        return ExitPathEffectDiscoveryResult(None, "missing_dispatcher_root")
    state_machine = snapshot.state_machine

    dispatcher_blocks: set[int] = set(
        int(block) for block in snapshot.dispatcher_blocks
    )
    dispatcher_blocks.add(dispatcher_serial)

    handlers = state_machine.handlers
    if not handlers:
        return ExitPathEffectDiscoveryResult(None, "no handlers in state machine")

    sm_blocks = _collect_state_machine_blocks(state_machine)
    terminal_target = find_terminal_exit_target_snapshot(
        flow_graph,
        dispatcher_serial,
        sm_blocks,
    )
    if terminal_target is None:
        return ExitPathEffectDiscoveryResult(None, "no terminal exit target found")

    cfg_frontier = compute_terminal_cfg_suffix_frontier(
        return_block_serial=terminal_target,
        predecessors_of=flow_graph.predecessors,
    )
    if cfg_frontier is None:
        return ExitPathEffectDiscoveryResult(None, "no CFG suffix frontier")

    semantic_frontier = classify_cfg_suffix_action(cfg_frontier)
    shared_entry = int(cfg_frontier.shared_entry_serial)
    return_block = int(cfg_frontier.return_block_serial)
    suffix_serials = tuple(int(serial) for serial in cfg_frontier.suffix_serials)

    pre_header_serial = _resolve_pre_header_serial(
        flow_graph,
        dispatcher_serial=dispatcher_serial,
        dispatcher_blocks=dispatcher_blocks,
    )
    full_infra = frozenset(
        dispatcher_blocks
        | {dispatcher_serial}
        | set(suffix_serials)
        | ({pre_header_serial} if pre_header_serial is not None else set())
    )

    shared_entry_blk = flow_graph.get_block(shared_entry)
    if shared_entry_blk is None:
        return ExitPathEffectDiscoveryResult(None, "shared_entry block unavailable")

    anchors: list[int] = []
    for pred_serial in shared_entry_blk.preds:
        if pred_serial in full_infra:
            continue
        pred_blk = flow_graph.get_block(pred_serial)
        if pred_blk is not None and pred_blk.nsucc == 1:
            anchors.append(int(pred_serial))

    if len(anchors) < 2:
        return ExitPathEffectDiscoveryResult(
            None,
            f"only {len(anchors)} anchors, need >= 2",
        )

    known_state_constants = frozenset(int(value) for value in snapshot.state_constants)

    forward_entries: list[ForwardFrontierEntry] = []
    for anchor_serial in anchors:
        carrier, carrier_const = classify_carrier_source(
            flow_graph,
            anchor_serial,
            state_var_stkoff,
            full_infra,
            resolver=snapshot.carrier_resolver,
        )
        requires_dtl = (
            carrier_const is not None and carrier_const in known_state_constants
        )
        forward_entries.append(
            ForwardFrontierEntry(
                handler_entry=anchor_serial,
                exit_path=(anchor_serial,),
                forward_candidate=anchor_serial,
                candidate_succ=shared_entry,
                shared_entry=shared_entry,
                return_block=return_block,
                suffix_serials=suffix_serials,
                semantic_action=semantic_frontier.action,
                carrier_source_kind=carrier,
                proof_status="unresolved",
                notes=anchor_note,
                state_const_written=carrier_const,
                requires_dtl=requires_dtl,
            )
        )

    exit_path_info = discover_shared_exit_path(
        flow_graph,
        shared_entry,
        suffix_serials,
        full_infra,
        forward_entries,
    )
    return ExitPathEffectDiscoveryResult(
        ExitPathEffectGroup(
            state_var_stkoff=state_var_stkoff,
            terminal_target=int(terminal_target),
            cfg_frontier=cfg_frontier,
            semantic_action=semantic_frontier.action,
            full_infra=full_infra,
            anchors=tuple(anchors),
            known_state_constants=known_state_constants,
            forward_entries=tuple(forward_entries),
            exit_path_info=exit_path_info,
        )
    )


__all__ = [
    "CarrierSourceKind",
    "ExitPathRecommendation",
    "ExitPathShape",
    "ForwardFrontierEntry",
    "SharedExitPathInfo",
    "ExitPathEffectDiscoveryResult",
    "ExitPathEffectGroup",
    "classify_carrier_source",
    "classify_carrier_source_rich",
    "discover_shared_exit_path",
    "discover_exit_path_effect_group",
    "resolve_state_var_stkoff",
]

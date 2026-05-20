from __future__ import annotations

import enum
from dataclasses import dataclass

import ida_hexrays
from d810.cfg.flow.terminal_frontier import (
    TerminalCfgSuffixFrontier,
    TerminalLoweringAction,
    classify_cfg_suffix_action,
    compute_terminal_cfg_suffix_frontier,
)
from d810.core.typing import TYPE_CHECKING
from d810.recon.flow.state_machine_analysis import (
    CarrierResolutionResult,
    ResolutionMethod,
    find_terminal_exit_target_snapshot,
)
from d810.recon.flow.transition_builder import _get_state_var_stkoff

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
        AnalysisSnapshot,
    )


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
    terminal_path: tuple[int, ...]
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


class CorridorShape(str, enum.Enum):
    """Shape classification of shared terminal corridor."""

    LINEAR = "linear"
    FAN_IN = "fan_in"
    BRANCHING = "branching"
    COMPLEX = "complex"


class CorridorRecommendation(str, enum.Enum):
    """Recommended semantic action for a shared terminal corridor group."""

    PRIVATE_RETURN_BLOCK = "private_return_block"
    PRIVATE_TERMINAL_SUFFIX = "private_terminal_suffix"
    PRIVATE_TERMINAL_CORRIDOR = "private_terminal_corridor"
    DIRECT_TERMINAL_LOWERING = "direct_terminal_lowering"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True, slots=True)
class SharedCorridorInfo:
    """Diagnostic info for a shared terminal corridor group."""

    shared_entry: int
    return_block: int
    suffix_serials: tuple[int, ...]
    corridor_blocks: tuple[int, ...]
    corridor_shape: CorridorShape
    corridor_length: int
    handler_entries: tuple[int, ...]
    handler_count: int
    entry_fan_in: int
    carrier_in_corridor: bool
    clonable: bool
    recommendation: CorridorRecommendation
    notes: str


@dataclass(frozen=True, slots=True)
class TerminalCorridorGroup:
    """Shared terminal-corridor facts harvested from a snapshot."""

    state_var_stkoff: int
    terminal_target: int
    cfg_frontier: TerminalCfgSuffixFrontier
    semantic_action: TerminalLoweringAction
    full_infra: frozenset[int]
    anchors: tuple[int, ...]
    known_state_constants: frozenset[int]
    forward_entries: tuple[ForwardFrontierEntry, ...]
    corridor_info: SharedCorridorInfo

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
class TerminalCorridorDiscoveryResult:
    """Result wrapper so callers can log why discovery failed."""

    group: TerminalCorridorGroup | None
    failure_reason: str | None = None


def _collect_state_machine_blocks(state_machine: object | None) -> set[int]:
    if state_machine is None:
        return set()
    blocks: set[int] = set()
    for handler in getattr(state_machine, "handlers", {}).values():
        blocks.add(int(handler.check_block))
        blocks.update(int(serial) for serial in handler.handler_blocks)
    return blocks


def resolve_state_var_stkoff(snapshot: AnalysisSnapshot) -> int | None:
    """Resolve the state variable stack offset from a snapshot."""

    state_var_stkoff: int | None = None
    detector = snapshot.detector
    if detector is not None:
        try:
            state_var_stkoff = _get_state_var_stkoff(detector)
        except Exception:
            pass
    if (
        state_var_stkoff is None
        and snapshot.state_machine is not None
        and snapshot.state_machine.state_var is not None
    ):
        sv = snapshot.state_machine.state_var
        try:
            if sv.t == ida_hexrays.mop_S:
                state_var_stkoff = int(sv.s.off)
        except Exception:
            pass
    return state_var_stkoff


def _resolve_pre_header_serial(
    flow_graph,
    *,
    dispatcher_serial: int,
    bst_node_blocks: set[int],
) -> int | None:
    blk0 = flow_graph.get_block(0)
    if blk0 is None or blk0.nsucc != 1:
        return None
    succ0 = blk0.succs[0] if blk0.succs else None
    if succ0 is None:
        return None
    if succ0 == dispatcher_serial or succ0 in bst_node_blocks:
        return 0
    return None


def _extract_const_from_snapshot_mop(mop_snap: object) -> int | None:
    if mop_snap is None:
        return None
    src_t = getattr(mop_snap, "t", None)
    if src_t != ida_hexrays.mop_n:
        return None
    nnn = getattr(mop_snap, "nnn", None)
    if nnn is not None:
        val = getattr(nnn, "value", None)
        if val is not None:
            return int(val)
    val = getattr(mop_snap, "value", None)
    if val is not None:
        return int(val)
    return None


def _mop_matches_stkoff_snapshot(mop_snap: object | None, stkoff: int) -> bool:
    if mop_snap is None:
        return False
    return getattr(mop_snap, "stkoff", None) == stkoff


def _resolve_indirect_state_write_via_mba(
    mba: object,
    candidate_serial: int,
    state_var_stkoff: int,
) -> CarrierResolutionResult | None:
    try:
        from d810.evaluator.hexrays_microcode.def_search import find_def_in_block
    except ImportError:
        return None

    try:
        live_blk = mba.get_mblock(candidate_serial)
    except Exception:
        return None
    if live_blk is None:
        return None

    cur_ins = live_blk.tail
    while cur_ins is not None:
        if cur_ins.opcode == ida_hexrays.m_mov and cur_ins.d is not None:
            if (
                cur_ins.d.t == ida_hexrays.mop_S
                and cur_ins.d.s is not None
                and cur_ins.d.s.off == state_var_stkoff
            ):
                source_mop = cur_ins.l
                if source_mop is None:
                    break
                if source_mop.t == ida_hexrays.mop_n:
                    nnn = source_mop.nnn
                    if nnn is not None:
                        return CarrierResolutionResult(
                            kind=CarrierSourceKind.STATE_CONST.value,
                            const_value=int(nnn.value),
                            method=ResolutionMethod.MBA_DEF_SEARCH,
                            def_blk_serial=None,
                            def_insn_ea=None,
                            source_mop_type=int(source_mop.t),
                        )
                    break
                if source_mop.t not in (ida_hexrays.mop_r, ida_hexrays.mop_S):
                    break
                def_ins = find_def_in_block(source_mop, live_blk, cur_ins)
                if def_ins is None:
                    pred_blk = live_blk
                    for _depth in range(3):
                        npred = pred_blk.npred()
                        if npred != 1:
                            break
                        pred_serial = pred_blk.pred(0)
                        try:
                            pred_blk = mba.get_mblock(pred_serial)
                        except Exception:
                            break
                        if pred_blk is None:
                            break
                        scan = pred_blk.tail
                        while scan is not None:
                            if (
                                scan.opcode == ida_hexrays.m_mov
                                and scan.d is not None
                                and scan.d.t == source_mop.t
                            ):
                                dest_matches = False
                                if source_mop.t == ida_hexrays.mop_S:
                                    try:
                                        dest_matches = scan.d.s.off == source_mop.s.off
                                    except Exception:
                                        pass
                                elif source_mop.t == ida_hexrays.mop_r:
                                    try:
                                        dest_matches = scan.d.r == source_mop.r
                                    except Exception:
                                        pass
                                if (
                                    dest_matches
                                    and scan.l is not None
                                    and scan.l.t == ida_hexrays.mop_n
                                ):
                                    def_ins = scan
                                    live_blk = pred_blk
                                    break
                            scan = scan.prev
                        if def_ins is not None:
                            break
                if def_ins is None:
                    break
                if (
                    def_ins.opcode == ida_hexrays.m_mov
                    and def_ins.l is not None
                    and def_ins.l.t == ida_hexrays.mop_n
                ):
                    nnn = def_ins.l.nnn
                    if nnn is not None:
                        src_stkoff: int | None = None
                        src_mreg: int | None = None
                        if source_mop.t == ida_hexrays.mop_S:
                            try:
                                src_stkoff = source_mop.s.off
                            except Exception:
                                pass
                        elif source_mop.t == ida_hexrays.mop_r:
                            try:
                                src_mreg = int(source_mop.r)
                            except Exception:
                                pass
                        return CarrierResolutionResult(
                            kind=CarrierSourceKind.STATE_CONST.value,
                            const_value=int(nnn.value),
                            method=ResolutionMethod.MBA_DEF_SEARCH,
                            def_blk_serial=live_blk.serial,
                            def_insn_ea=def_ins.ea,
                            source_mop_type=int(source_mop.t),
                            source_stkoff=src_stkoff,
                            source_mreg=src_mreg,
                        )
                break
        cur_ins = cur_ins.prev
    return None


def _resolve_state_const_via_valranges(
    mba: object,
    candidate_serial: int,
    state_var_stkoff: int,
) -> CarrierResolutionResult | None:
    try:
        from d810.evaluator.hexrays_microcode.valranges import (
            ValrangeLocation,
            ValrangeLocationKind,
            collect_instruction_valrange_record_for_location,
        )
    except ImportError:
        return None

    try:
        live_blk = mba.get_mblock(candidate_serial)
    except Exception:
        return None
    if live_blk is None:
        return None

    cur_ins = live_blk.tail
    state_write_ins = None
    while cur_ins is not None:
        if cur_ins.opcode == ida_hexrays.m_mov and cur_ins.d is not None:
            if (
                cur_ins.d.t == ida_hexrays.mop_S
                and cur_ins.d.s is not None
                and cur_ins.d.s.off == state_var_stkoff
            ):
                state_write_ins = cur_ins
                break
        cur_ins = cur_ins.prev
    if state_write_ins is None:
        return None

    source_mop = state_write_ins.l
    if source_mop is None or source_mop.t not in (ida_hexrays.mop_r, ida_hexrays.mop_S):
        return None

    if source_mop.t == ida_hexrays.mop_r:
        location = ValrangeLocation(
            kind=ValrangeLocationKind.REGISTER,
            identifier=int(source_mop.r),
            width=int(source_mop.size),
        )
    else:
        try:
            stkoff = source_mop.s.off
        except Exception:
            return None
        location = ValrangeLocation(
            kind=ValrangeLocationKind.STACK,
            identifier=int(stkoff),
            width=int(source_mop.size),
        )

    try:
        record = collect_instruction_valrange_record_for_location(
            live_blk,
            state_write_ins,
            location,
        )
    except Exception:
        return None
    if record is None:
        return None

    range_text = record.range_text.strip()
    if range_text.startswith("{") and range_text.endswith("}"):
        inner = range_text[1:-1].strip()
        if "," not in inner and ".." not in inner:
            try:
                val = int(inner, 0)
            except ValueError:
                return None
            return CarrierResolutionResult(
                kind=CarrierSourceKind.STATE_CONST.value,
                const_value=val,
                method=ResolutionMethod.VALRANGES,
                def_blk_serial=None,
                def_insn_ea=None,
                source_mop_type=int(source_mop.t),
            )
    return None


def classify_carrier_source_rich(
    flow_graph,
    candidate_serial: int,
    state_var_stkoff: int,
    infra_blocks: frozenset[int],
    *,
    mba: object | None = None,
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
    mba_resolution: CarrierResolutionResult | None = None

    for insn in blk_snap.iter_insns():
        if insn.opcode == ida_hexrays.m_mov and insn.d is not None:
            if _mop_matches_stkoff_snapshot(insn.d, state_var_stkoff):
                has_state_write = True
                const_val = _extract_const_from_snapshot_mop(insn.l)
                if const_val is not None:
                    state_const_written = const_val
                elif insn.l is not None:
                    state_write_source_indirect = True
                continue
            if insn.l is not None:
                src_t = getattr(insn.l, "t", None)
                if src_t == ida_hexrays.mop_n:
                    has_const_write = True
                elif src_t == ida_hexrays.mop_a:
                    has_ptr_write = True
                elif src_t is not None:
                    has_expr_write = True

    if (
        has_state_write
        and state_const_written is None
        and state_write_source_indirect
        and mba is not None
    ):
        try:
            mba_resolution = _resolve_indirect_state_write_via_mba(
                mba,
                candidate_serial,
                state_var_stkoff,
            )
            if mba_resolution is not None:
                state_const_written = mba_resolution.const_value
        except Exception:
            pass

        if state_const_written is None:
            try:
                vr_resolution = _resolve_state_const_via_valranges(
                    mba,
                    candidate_serial,
                    state_var_stkoff,
                )
                if vr_resolution is not None:
                    state_const_written = vr_resolution.const_value
                    mba_resolution = vr_resolution
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

    if mba_resolution is not None:
        return CarrierResolutionResult(
            kind=kind.value,
            const_value=state_const_written,
            method=mba_resolution.method,
            def_blk_serial=mba_resolution.def_blk_serial,
            def_insn_ea=mba_resolution.def_insn_ea,
            source_mop_type=mba_resolution.source_mop_type,
            source_stkoff=mba_resolution.source_stkoff,
            source_mreg=mba_resolution.source_mreg,
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
    mba: object | None = None,
) -> tuple[CarrierSourceKind, int | None]:
    result = classify_carrier_source_rich(
        flow_graph,
        candidate_serial,
        state_var_stkoff,
        infra_blocks,
        mba=mba,
    )
    return CarrierSourceKind(result.kind), result.const_value


def discover_shared_corridor(
    flow_graph,
    shared_entry_serial: int,
    suffix_serials: tuple[int, ...],
    full_infra: frozenset[int],
    forward_entries: list[ForwardFrontierEntry] | tuple[ForwardFrontierEntry, ...],
) -> SharedCorridorInfo:
    suffix_set = frozenset(suffix_serials)

    handler_entries_list: list[int] = []
    return_block = 0
    for entry in forward_entries:
        handler_entries_list.append(int(entry.handler_entry))
        if entry.return_block is not None:
            return_block = int(entry.return_block)
    handler_entries_tuple = tuple(sorted(set(handler_entries_list)))

    corridor: list[int] = []
    if shared_entry_serial not in suffix_set:
        current = shared_entry_serial
        visited: set[int] = set()
        while current not in suffix_set and current not in visited:
            visited.add(current)
            corridor.append(current)
            succs = flow_graph.successors(current)
            if len(succs) != 1:
                break
            nxt = succs[0]
            if nxt in suffix_set or nxt == return_block:
                break
            current = nxt

    corridor_tuple = tuple(corridor)
    corridor_length = len(corridor_tuple)

    has_branching = False
    has_fan_in = False
    corridor_set = frozenset(corridor_tuple)
    for blk_serial in corridor_tuple:
        blk_snap = flow_graph.get_block(blk_serial)
        if blk_snap is None:
            continue
        if blk_snap.nsucc > 1:
            has_branching = True
        outside_preds = [pred for pred in blk_snap.preds if pred not in corridor_set]
        if len(outside_preds) > 1:
            has_fan_in = True

    if has_branching and has_fan_in:
        corridor_shape = CorridorShape.COMPLEX
    elif has_branching:
        corridor_shape = CorridorShape.BRANCHING
    elif has_fan_in:
        corridor_shape = CorridorShape.FAN_IN
    else:
        corridor_shape = CorridorShape.LINEAR

    entry_fan_in = 0
    if corridor_tuple:
        entry_snap = flow_graph.get_block(corridor_tuple[0])
        if entry_snap is not None:
            entry_fan_in = len([pred for pred in entry_snap.preds if pred not in corridor_set])

    control_flow_opcodes = frozenset(
        {
            ida_hexrays.m_goto,
            ida_hexrays.m_jnz,
            ida_hexrays.m_ijmp,
            ida_hexrays.m_jtbl,
        }
    )
    carrier_in_corridor = False
    for blk_serial in corridor_tuple:
        blk_snap = flow_graph.get_block(blk_serial)
        if blk_snap is None:
            continue
        for insn in blk_snap.iter_insns():
            if insn.opcode not in control_flow_opcodes:
                carrier_in_corridor = True
                break
        if carrier_in_corridor:
            break

    handler_count = len(handler_entries_tuple)
    clonable = (
        corridor_shape in (CorridorShape.LINEAR, CorridorShape.FAN_IN)
        and corridor_length <= 8
        and handler_count >= 2
    )

    notes_parts: list[str] = []
    if handler_count < 2:
        recommendation = CorridorRecommendation.UNRESOLVED
        notes_parts.append("handler_count < 2")
    elif corridor_shape in (CorridorShape.BRANCHING, CorridorShape.COMPLEX):
        recommendation = CorridorRecommendation.UNRESOLVED
        notes_parts.append("corridor has branching/complex shape")
    elif corridor_length == 0:
        recommendation = CorridorRecommendation.PRIVATE_TERMINAL_SUFFIX
        notes_parts.append("degenerate corridor (length=0)")
    elif clonable:
        recommendation = CorridorRecommendation.PRIVATE_TERMINAL_CORRIDOR
        notes_parts.append(
            "corridor clonable (len=%d, shape=%s)"
            % (corridor_length, corridor_shape.value)
        )
    else:
        recommendation = CorridorRecommendation.UNRESOLVED
        notes_parts.append("corridor not clonable")

    return SharedCorridorInfo(
        shared_entry=int(shared_entry_serial),
        return_block=int(return_block),
        suffix_serials=tuple(int(serial) for serial in suffix_serials),
        corridor_blocks=corridor_tuple,
        corridor_shape=corridor_shape,
        corridor_length=corridor_length,
        handler_entries=handler_entries_tuple,
        handler_count=handler_count,
        entry_fan_in=entry_fan_in,
        carrier_in_corridor=carrier_in_corridor,
        clonable=clonable,
        recommendation=recommendation,
        notes="; ".join(notes_parts) if notes_parts else "",
    )


def discover_terminal_corridor_group(
    snapshot: AnalysisSnapshot,
    *,
    anchor_note: str,
) -> TerminalCorridorDiscoveryResult:
    if snapshot.flow_graph is None:
        return TerminalCorridorDiscoveryResult(None, "missing_flow_graph")
    if snapshot.bst_result is None:
        return TerminalCorridorDiscoveryResult(None, "missing_bst_result")
    if snapshot.state_machine is None:
        return TerminalCorridorDiscoveryResult(None, "missing_state_machine")

    state_var_stkoff = resolve_state_var_stkoff(snapshot)
    if state_var_stkoff is None:
        return TerminalCorridorDiscoveryResult(None, "state_var_stkoff is None")

    flow_graph = snapshot.flow_graph
    dispatcher_serial = int(snapshot.bst_dispatcher_serial)
    bst_result = snapshot.bst_result
    state_machine = snapshot.state_machine

    bst_node_blocks: set[int] = set(getattr(bst_result, "bst_node_blocks", set()) or set())
    bst_node_blocks.add(dispatcher_serial)

    handlers = getattr(state_machine, "handlers", {}) or {}
    if not handlers:
        return TerminalCorridorDiscoveryResult(None, "no handlers in state machine")

    sm_blocks = _collect_state_machine_blocks(state_machine)
    terminal_target = find_terminal_exit_target_snapshot(
        flow_graph,
        dispatcher_serial,
        sm_blocks,
    )
    if terminal_target is None:
        return TerminalCorridorDiscoveryResult(None, "no terminal exit target found")

    cfg_frontier = compute_terminal_cfg_suffix_frontier(
        return_block_serial=terminal_target,
        predecessors_of=flow_graph.predecessors,
    )
    if cfg_frontier is None:
        return TerminalCorridorDiscoveryResult(None, "no CFG suffix frontier")

    semantic_frontier = classify_cfg_suffix_action(cfg_frontier)
    shared_entry = int(cfg_frontier.shared_entry_serial)
    return_block = int(cfg_frontier.return_block_serial)
    suffix_serials = tuple(int(serial) for serial in cfg_frontier.suffix_serials)

    pre_header_serial = _resolve_pre_header_serial(
        flow_graph,
        dispatcher_serial=dispatcher_serial,
        bst_node_blocks=bst_node_blocks,
    )
    full_infra = frozenset(
        bst_node_blocks
        | {dispatcher_serial}
        | set(suffix_serials)
        | ({pre_header_serial} if pre_header_serial is not None else set())
    )

    shared_entry_blk = flow_graph.get_block(shared_entry)
    if shared_entry_blk is None:
        return TerminalCorridorDiscoveryResult(None, "shared_entry block unavailable")

    anchors: list[int] = []
    for pred_serial in shared_entry_blk.preds:
        if pred_serial in full_infra:
            continue
        pred_blk = flow_graph.get_block(pred_serial)
        if pred_blk is not None and pred_blk.nsucc == 1:
            anchors.append(int(pred_serial))

    if len(anchors) < 2:
        return TerminalCorridorDiscoveryResult(
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
            mba=snapshot.mba,
        )
        requires_dtl = (
            carrier_const is not None and carrier_const in known_state_constants
        )
        forward_entries.append(
            ForwardFrontierEntry(
                handler_entry=anchor_serial,
                terminal_path=(anchor_serial,),
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

    corridor_info = discover_shared_corridor(
        flow_graph,
        shared_entry,
        suffix_serials,
        full_infra,
        forward_entries,
    )
    return TerminalCorridorDiscoveryResult(
        TerminalCorridorGroup(
            state_var_stkoff=state_var_stkoff,
            terminal_target=int(terminal_target),
            cfg_frontier=cfg_frontier,
            semantic_action=semantic_frontier.action,
            full_infra=full_infra,
            anchors=tuple(anchors),
            known_state_constants=known_state_constants,
            forward_entries=tuple(forward_entries),
            corridor_info=corridor_info,
        )
    )


__all__ = [
    "CarrierSourceKind",
    "CorridorRecommendation",
    "CorridorShape",
    "ForwardFrontierEntry",
    "SharedCorridorInfo",
    "TerminalCorridorDiscoveryResult",
    "TerminalCorridorGroup",
    "classify_carrier_source",
    "classify_carrier_source_rich",
    "discover_shared_corridor",
    "discover_terminal_corridor_group",
    "resolve_state_var_stkoff",
]

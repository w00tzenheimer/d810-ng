"""Publish portable evidence for register-computed goto dispatchers.

The resolver uses concolic execution or a static constant-propagation fixpoint
to recover native transfer targets, predicate anchors, proof corridors, and
owned native ranges.  It never changes native bytes or IDA's CFG.  PREOPT
frontend normalization consumes the portable plans to preserve only the
minimum faithful computed-branch IR, and canonical D810 passes own subsequent
state-machine recovery and semantic-fragment publication.
"""

from __future__ import annotations

import collections
import itertools
import struct
from dataclasses import replace

import ida_funcs  # type: ignore[import-untyped]
import ida_hexrays  # type: ignore[import-untyped]
import idaapi  # type: ignore[import-untyped]

from d810.core.typing import Callable, Mapping, NamedTuple, Sequence

from d810.backends.emulation.common import CorridorEventKind
from d810.backends.emulation.oracle import EmulationOracle
from d810.backends.hexrays.evidence.call_abi import (
    apply_three_argument_stdcall_type,
    build_three_argument_stdcall_callinfo,
    collect_three_argument_callee_purged_evidence,
    native_call_stack_deficit,
    native_corridor_has_no_stack_adjustment,
)
from d810.analyses.control_flow.call_abi import (
    project_detached_call_stack_point,
    prove_three_argument_callee_purged_call,
)
from d810.analyses.control_flow.detached_handler_island import (
    DetachedSnippetBoundaryPortOwner,
    DetachedSnippetBoundaryPorts,
    DetachedSnippetConditionalBoundaryPort,
    DetachedSnippetDirectBoundaryPort,
    make_resolver_cut_boundary_port,
    merge_detached_snippet_ranges,
    normalize_detached_snippet_boundary_ports,
)
from d810.analyses.control_flow.native_semantic_closure import (
    NativeCfg,
    NativeEdgeKind,
    NativeRange,
    NativeSemanticClosure,
    NativeTerminalKind,
    ResolverProvenHandlerEntry,
    plan_native_generation_ranges,
    plan_native_semantic_closure,
)
from d810.analyses.control_flow.native_preanalysis_session import (
    ComputedGotoPatchPlan,
    ComputedGotoResolution,
    PreoptUnionPreparationResult,
    PrepatchPreoptUnionSource,
    ResolverLifecycleSession,
)
from d810.analyses.control_flow.preopt_union_region import (
    PreoptUnionRegionPlan,
    plan_preopt_union_region,
    select_missing_preopt_union_region,
)
from d810.backends.hexrays.evidence.native_semantic_closure import (
    build_native_semantic_cfg,
)
from d810.backends.hexrays.evidence.residual_entry_bridge import (
    recognize_preoptimized_residual_entry_bridge,
)
from d810.analyses.control_flow.residual_entry_bridge import EntryBridgeEvidence
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
    MaterializedStateRoute,
    PortableStateWriteRouteEvidence,
    StateWriteRouteDeliveryKind,
    StateWriteRouteProofKind,
    TerminalReturnCarrierRequest,
    find_unique_target_block,
    find_unique_target_entry_block,
    is_conditional_handler_bridge_kind,
    plan_terminal_return_carrier_requests_from_native_routes,
    plan_terminal_return_carrier_requests_from_state_writes,
    route_materialized_transfer_chain,
    route_transfer_target_through_condition_chain,
    unique_materialized_equality_target_eas,
    unique_materialized_state_register,
)
from d810.analyses.control_flow.native_compare import (
    normalize_register_compare_predicate,
    swapped_x86_condition_code,
)
from d810.analyses.control_flow.route_predicate import DecisionDag
from d810.analyses.control_flow.semantic_transition import StateWriteAnchor
from d810.analyses.control_flow.state_machine_analysis import (
    _transfer_snapshot_constant_block,
)
from d810.analyses.control_flow.terminal_return_carrier_evidence import (
    TerminalReturnCarrierEvidence,
)
from d810.core.logging import getLogger
from d810.core.observability import emit as emit_diagnostic
from d810.core.observability_events import LifecycleEventObserved
from d810.ir.flowgraph import (
    BlockKind,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    OperandKind,
)
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.hexrays.preanalysis.flowchart_preanalysis import (
    register_flowchart_preanalysis_handler,
    request_hexrays_redo,
    unregister_flowchart_preanalysis_handler,
)
from d810.hexrays.preanalysis.calls_done_preanalysis import (
    register_calls_done_preanalysis_handler,
    unregister_calls_done_preanalysis_handler,
)
from d810.hexrays.preanalysis.callinfo_preanalysis import (
    register_callinfo_preanalysis_handler,
    unregister_callinfo_preanalysis_handler,
)
from d810.hexrays.preanalysis.stkpnts_preanalysis import (
    register_stkpnts_preanalysis_handler,
    unregister_stkpnts_preanalysis_handler,
)
from d810.hexrays.utils.hexrays_formatters import maturity_to_string
from d810.hexrays.hooks.optimization_suppression import (
    suppress_d810_optimization,
)
from d810.hexrays.mutation.detached_handler_island import (
    bind_preopt_union_snippet_boundary_ports,
    capture_detached_callinfo_templates,
    capture_preopt_union_call_companion_template,
    capture_preopt_union_snippet_template,
    detached_callinfo_template_eas,
    detached_preopt_call_stack_points,
    exact_live_predicate_true_is_taken,
    imported_detached_snippet_instruction_origins,
    last_imported_detached_snippet_instruction_origins,
    native_stack_frame_offsets_for_ranges,
    prepare_detached_callinfo_template,
)
from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
    ResolverSessionState,
    resolver_session_state,
)

_PatchPlan = ComputedGotoPatchPlan
_PrepatchPreoptUnionSource = PrepatchPreoptUnionSource


class _DecodedStateRouteInstruction(NamedTuple):
    """IDA-free instruction facts used to prove one direct state route."""

    ea: int
    end_ea: int
    mnemonic: str
    destination_mreg: int | None
    writes_destination: bool
    immediate: int | None


class _NativeStateRouteDeliverySite(NamedTuple):
    """One bounded native delivery that returns a state to its dispatcher."""

    block_entry_ea: int
    delivery_ea: int
    delivery_region_start_ea: int
    delivery_region_end_ea: int


class _DecodedNativeFlowInstruction(NamedTuple):
    """IDA-free native facts consumed by immediate state-route recovery."""

    ea: int
    end_ea: int
    mnemonic: str
    destination_mreg: int | None
    writes_destination: bool
    source_immediate: int | None
    direct_target_ea: int | None = None


class _ImmediateNativeFlowRoute(NamedTuple):
    """One source-specific immediate state route recovered before mutation."""

    source_write_ea: int
    delivery_ea: int
    delivery_end_ea: int
    corridor_instruction_eas: tuple[int, ...]
    state_constant: int
    target_ea: int


class _FrontendNormalizationUnionSource(NamedTuple):
    """Portable native closure backing one frontend normalization generation."""

    region: PreoptUnionRegionPlan
    cfg: NativeCfg
    closure: NativeSemanticClosure


def _discover_immediate_native_state_routes(
    decoded: Sequence[_DecodedNativeFlowInstruction],
    *,
    state_var_reg: int,
    state_targets: Mapping[int, int],
) -> tuple[_ImmediateNativeFlowRoute, ...]:
    """Recover complete one-target native flow-state transactions.

    A state assignment becomes authoritative only after the later dispatcher
    comparison and branch identify a complete replacement cut.
    Branch-staged, conditional-move, register, and memory assignments abstain
    here; they require atomic two-arm evidence in a separate slice.
    """
    ordered = tuple(sorted(decoded, key=lambda instruction: int(instruction.ea)))
    if not ordered:
        return ()
    branch_target_eas = frozenset(
        int(instruction.direct_target_ea)
        for instruction in ordered
        if instruction.direct_target_ea is not None
        and (
            str(instruction.mnemonic).lower() == "jmp"
            or str(instruction.mnemonic).lower() in _SV_JCC_MNEMS
        )
    )
    current_assignment: _DecodedNativeFlowInstruction | None = None
    saved_assignment: _DecodedNativeFlowInstruction | None = None
    branch_assignment: _DecodedNativeFlowInstruction | None = None
    target: int | None = None
    state_constant: int | None = None
    had_state_comparison = False
    proof: list[_DecodedNativeFlowInstruction] = []
    routes: set[_ImmediateNativeFlowRoute] = set()

    for instruction in ordered:
        mnemonic = str(instruction.mnemonic).lower()
        is_jump = mnemonic == "jmp" or mnemonic in _SV_JCC_MNEMS
        is_direct_jump = is_jump and instruction.direct_target_ea is not None
        is_conditional_jump = mnemonic in _SV_JCC_MNEMS
        is_state_operand = instruction.destination_mreg is not None and int(
            instruction.destination_mreg
        ) == int(state_var_reg)

        if saved_assignment is not None and int(instruction.ea) in branch_target_eas:
            branch_assignment = saved_assignment

        if (
            (mnemonic == "mov" or mnemonic.startswith("cmov"))
            and is_state_operand
            and instruction.writes_destination
        ):
            if mnemonic == "mov":
                branch_assignment = None
            current_assignment = instruction
            target = None
            state_constant = None
            had_state_comparison = False
            proof = []

        if is_jump and not is_direct_jump:
            current_assignment = None
            saved_assignment = None
            branch_assignment = None
            target = None
            state_constant = None
            had_state_comparison = False
            proof = []
            continue

        if is_conditional_jump:
            saved_assignment = current_assignment

        validates_assignment = (
            mnemonic == "cmp"
            and is_state_operand
            and instruction.source_immediate is not None
        ) or is_direct_jump
        if validates_assignment and current_assignment is not None:
            immediate = current_assignment.source_immediate
            if (
                str(current_assignment.mnemonic).lower() == "mov"
                and immediate is not None
            ):
                state_constant = int(immediate) & _MASK32
                target = state_targets.get(state_constant)
            else:
                state_constant = None
                target = None
            if target is not None:
                proof.extend((current_assignment, instruction))
            current_assignment = None

        if target is None or state_constant is None:
            continue
        if mnemonic == "cmp" and is_state_operand:
            had_state_comparison = True
        if mnemonic != "jmp" and not (had_state_comparison and is_direct_jump):
            continue
        proof.append(instruction)
        if branch_assignment is None:
            proof_eas = tuple(sorted({int(item.ea) for item in proof}))
            routes.add(
                _ImmediateNativeFlowRoute(
                    int(proof[0].ea),
                    int(instruction.ea),
                    int(instruction.end_ea),
                    proof_eas,
                    int(state_constant),
                    int(target),
                )
            )
        target = None
        state_constant = None
        saved_assignment = None
        branch_assignment = None
        had_state_comparison = False
        proof = []

    return tuple(sorted(routes))


def _select_static_state_write_delivery(
    decoded: Sequence[_DecodedStateRouteInstruction],
    *,
    state_var_reg: int,
    state_constant: int,
    delivery_ea: int,
) -> tuple[int, tuple[int, ...]] | None:
    """Select one direct write-to-delivery corridor without conditional flow."""
    selected = _select_static_state_write_assignment(
        decoded,
        state_var_reg=int(state_var_reg),
        delivery_ea=int(delivery_ea),
    )
    if selected is None or int(selected[1]) != (int(state_constant) & _MASK32):
        return None
    return int(selected[0]), tuple(selected[2])


def _select_static_state_write_assignment(
    decoded: Sequence[_DecodedStateRouteInstruction],
    *,
    state_var_reg: int,
    delivery_ea: int,
) -> tuple[int, int, tuple[int, ...]] | None:
    """Recover the final immediate flow-state assignment for one direct route."""
    ordered = tuple(decoded)
    if (
        not ordered
        or int(ordered[-1].ea) != int(delivery_ea)
        or str(ordered[-1].mnemonic).lower() != "jmp"
    ):
        return None
    state_writes = tuple(
        (index, instruction)
        for index, instruction in enumerate(ordered[:-1])
        if instruction.writes_destination
        and instruction.destination_mreg is not None
        and int(instruction.destination_mreg) == int(state_var_reg)
    )
    if not state_writes:
        return None
    write_index, write = state_writes[-1]
    if write.immediate is None or not _state_write_values_match(
        mnemonic=str(write.mnemonic),
        destination_mreg=write.destination_mreg,
        immediate=write.immediate,
        state_var_reg=int(state_var_reg),
        state_constant=int(write.immediate),
    ):
        return None
    corridor = ordered[write_index:]
    if any(
        str(instruction.mnemonic).lower() in _SV_JCC_MNEMS
        or str(instruction.mnemonic).lower() in {"call", "ret", "retn", "retf"}
        for instruction in corridor[:-1]
    ):
        return None
    heads = tuple(int(instruction.ea) for instruction in corridor)
    if heads != tuple(sorted(set(heads))):
        return None
    return int(write.ea), int(write.immediate) & _MASK32, heads


def _merge_materialized_transfers(
    state: ResolverSessionState,
    transfers: tuple[MaterializedIndirectTransfer, ...],
) -> bool:
    """Publish portable transfers and discard any prior live-MBA binding."""
    changed = state.native_preanalysis.merge_materialized_transfers(
        state.native_key,
        transfers,
    )
    if changed:
        state.invalidate_current_mba_binding()
    return changed


def _merge_native_facts(
    state: ResolverSessionState,
    **facts: object,
) -> bool:
    """Publish portable native facts and invalidate the old live-MBA index."""
    changed = state.native_preanalysis.merge_native_facts(
        state.native_key,
        **facts,
    )
    if changed:
        state.invalidate_current_mba_binding()
    return changed


def _merge_terminal_return_carriers(
    state: ResolverSessionState,
    carriers: tuple[TerminalReturnCarrierEvidence, ...],
) -> bool:
    """Publish portable return carriers and invalidate any older MBA binding."""
    changed = state.native_preanalysis.merge_terminal_return_carriers(
        state.native_key,
        carriers,
    )
    if changed:
        state.invalidate_current_mba_binding()
    return changed


try:
    from d810.speedups.cythxr._chexrays_api import (
        copy_mcallinfo as _copy_mcallinfo,
        upsert_stkpnt as _upsert_stkpnt,
    )
except ImportError:  # Optional native SDK bridge; provider abstains when absent.
    _copy_mcallinfo = None
    _upsert_stkpnt = None

logger = getLogger("D810.hexrays.preanalysis.computed_goto")

_HANDLER_NAME = "computed_goto_resolver"
_CALLS_HANDLER_NAME = "computed_goto_resolver.calls_done"
_CALLINFO_HANDLER_NAME = "computed_goto_resolver.callinfo"
_STKPNTS_HANDLER_NAME = "computed_goto_resolver.stkpnts"
#: Cap on emulated instructions for one corridor trace (a flattened state machine
#: with N states * M handler instructions; generous headroom, fail-open on hit).
_DEFAULT_MAX_INSTRUCTIONS = 20000
#: Scratch stack window mapped for the corridor emulation (well away from image).
_STACK_BASE = 0x00F00000
_STACK_SIZE = 0x00040000
_STACK_TOP = _STACK_BASE + _STACK_SIZE // 2


# --------------------------------------------------------------------------- #
# arch / segment helpers (IDA runtime)                                        #
# --------------------------------------------------------------------------- #
def _detect_arch() -> str | None:
    """Return the EmulationOracle arch string for the current database, or None
    if it is not an x86 family target this resolver understands."""
    try:
        import ida_ida  # type: ignore[import-untyped]
        import idaapi  # type: ignore[import-untyped]

        proc = ""
        try:
            proc = str(idaapi.inf_get_procname() or "").lower()
        except Exception:
            proc = str(getattr(getattr(idaapi, "cvar", None), "inf", None) and "" or "")
        if proc and proc not in ("metapc", "8086", "80386", "80486", "80586", "80686"):
            return None
        return "x86_64" if bool(ida_ida.inf_is_64bit()) else "x86"
    except Exception:
        logger.debug("arch detection failed", exc_info=True)
        return None


def _sp_reg(arch: str) -> str:
    return "rsp" if arch == "x86_64" else "esp"


def _text_segment(func_ea: int) -> tuple[int, int, bytes] | None:
    import ida_bytes  # type: ignore[import-untyped]
    import ida_segment  # type: ignore[import-untyped]

    seg = ida_segment.getseg(int(func_ea))
    if seg is None:
        return None
    start, end = int(seg.start_ea), int(seg.end_ea)
    data = ida_bytes.get_bytes(start, end - start)
    if not data:
        return None
    return start, end, bytes(data)


def _other_segment_bytes(text_start: int) -> dict[int, bytes]:
    """Map every non-code-text segment (rdata tables, data) for the emulation."""
    import ida_bytes  # type: ignore[import-untyped]
    import ida_segment  # type: ignore[import-untyped]

    out: dict[int, bytes] = {}
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if seg is None or int(seg.start_ea) == int(text_start):
            continue
        data = ida_bytes.get_bytes(seg.start_ea, seg.end_ea - seg.start_ea)
        if data:
            out[int(seg.start_ea)] = bytes(data)
    return out


def _reg_indirect_jump_sites(text_start: int, text_end: int) -> list[int]:
    """EAs of ``jmp reg`` instructions in the segment window (cheap gate)."""
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    sites: list[int] = []
    insn = ida_ua.insn_t()
    ea = int(text_start)
    while ea < int(text_end):
        length = ida_ua.decode_insn(insn, ea)
        if length <= 0:
            ea += 1
            continue
        if idaapi.print_insn_mnem(ea) == "jmp" and insn.ops[0].type == idaapi.o_reg:
            sites.append(ea)
        ea += length
    return sites


# --------------------------------------------------------------------------- #
# resolution (concolic execution)                                             #
# --------------------------------------------------------------------------- #
def resolve_computed_gotos(
    function_ea: int,
    *,
    max_instructions: int = _DEFAULT_MAX_INSTRUCTIONS,
    initial_seeds: Sequence[Mapping[str, object]] | None = None,
) -> ComputedGotoResolution | None:
    """Execute the dispatcher with d810's concolic engine and read each computed
    ``jmp reg`` target as the instruction that runs next.

    ``initial_seeds`` is an optional list of ``{"regs": {...}, "stack": {...}}``
    dicts; each is one emulation run whose discovered targets are merged, so
    input-dependent 2-way branches can be covered by seeding both input values.
    """
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    arch = _detect_arch()
    if arch is None:
        return None
    oracle = EmulationOracle.create(arch)
    if not oracle.has_unicorn:
        logger.debug("Unicorn unavailable; cannot resolve computed gotos")
        return None

    text = _text_segment(function_ea)
    if text is None:
        return None
    text_start, text_end, text_bytes = text

    base_mem = _other_segment_bytes(text_start)
    base_mem[_STACK_BASE] = b"\x00" * _STACK_SIZE
    sp_reg = _sp_reg(arch)

    seeds = list(initial_seeds) if initial_seeds else [{}]
    jmp_targets: dict[int, set[int]] = {}
    reachable: set[int] = set()
    total_insns = 0
    stop_reasons: list[str] = []
    insn = ida_ua.insn_t()

    for seed in seeds:
        regs = {sp_reg: _STACK_TOP}
        regs.update(dict(seed.get("regs", {})))  # type: ignore[arg-type]
        stack_vals = {0: text_end}  # sentinel return address -> stop at seg end
        stack_vals.update(dict(seed.get("stack", {})))  # type: ignore[arg-type]
        res = oracle.trace_corridor(
            text_bytes,
            code_base=text_start,
            entry_addr=int(function_ea),
            initial_regs=regs,
            initial_mem=dict(base_mem),
            initial_stack_values=stack_vals,
            max_instructions=max_instructions,
        )
        stop_reasons.append(res.stop_reason)
        eas = [e.address for e in res.events if e.kind == CorridorEventKind.INSN]
        total_insns += len(eas)
        for idx, ea in enumerate(eas):
            if not (text_start <= ea < text_end):
                continue
            reachable.add(ea)
            if idx + 1 >= len(eas):
                continue
            if idaapi.print_insn_mnem(ea) != "jmp":
                continue
            length = ida_ua.decode_insn(insn, ea)
            if length <= 0 or insn.ops[0].type != idaapi.o_reg:
                continue
            nxt = eas[idx + 1]
            if text_start <= nxt < text_end:
                jmp_targets.setdefault(ea, set()).add(nxt)

    if not jmp_targets:
        return None
    return ComputedGotoResolution(
        function_ea=int(function_ea),
        jmp_targets={k: tuple(sorted(v)) for k, v in jmp_targets.items()},
        reachable_eas=tuple(sorted(reachable)),
        arch=arch,
        executed_insns=total_insns,
        seeds_run=len(seeds),
        stop_reasons=tuple(stop_reasons),
    )


# --------------------------------------------------------------------------- #
# static const-prop fixpoint resolver (x86 setcc/cmov binary-search shape)     #
#                                                                             #
# The concolic corridor trace can fault at instruction 0 when a prologue      #
# writes an unmapped stack                                                    #
# and reads unseeded arguments, so the binary-search dispatcher state is never #
# established (measured: 0/190 sites, UC_ERR_WRITE_UNMAPPED at executed=0). A   #
# monotone forward-dataflow FIXPOINT that JOINs register value-sets at merge   #
# blocks resolves every reachable ``jmp reg`` WITHOUT executing -- an unknown  #
# read is Top, not a fault. Ported from the proven spike (190/190 sites, 157   #
# one-way + 33 two-way). x86 (32-bit, no REX) only; x86-64 keeps the concolic  #
# path (the fixture's cmov-pointer-select shape).                              #
#                                                                             #
# Lattice per register: Bottom (absent) < finite frozenset[int] < Top (None). #
# join(Bottom,x)=x; join(Top,_)=Top; join(A,B)=A|B (Top if > _MAX_SET). A      #
# block re-processes whenever its joined entry state GROWS, so a ``jmp reg``   #
# that read Top on first arrival is re-resolved once a later path supplies the #
# missing KEY/table value. Terminates: the lattice has finite height.          #
# --------------------------------------------------------------------------- #
_MASK32 = 0xFFFFFFFF
_MAX_SET = 32  # multi-cmov chains produce value-sets bigger than 8
_MAX_FIXPOINT_STEPS = 400000  # the fixpoint reprocesses blocks; give it room
_SV_REG_NAMES = {
    0: "eax",
    1: "ecx",
    2: "edx",
    3: "ebx",
    4: "esp",
    5: "ebp",
    6: "esi",
    7: "edi",
}
_SV_CALLER_CLOBBERED = ("eax", "ecx", "edx")
_SV_SHIFT_MNEMS = {"shl", "sal", "shr"}
_SV_CMOV_MNEMS = {
    "cmovz",
    "cmovnz",
    "cmove",
    "cmovne",
    "cmovl",
    "cmovle",
    "cmovg",
    "cmovge",
    "cmova",
    "cmovae",
    "cmovb",
    "cmovbe",
    "cmovs",
    "cmovns",
    "cmovo",
    "cmovno",
    "cmovp",
    "cmovnp",
    "cmovpe",
    "cmovpo",
}
_SV_JCC_MNEMS = {
    "jz",
    "jnz",
    "je",
    "jne",
    "jl",
    "jle",
    "jg",
    "jge",
    "ja",
    "jae",
    "jb",
    "jbe",
    "js",
    "jns",
    "jo",
    "jno",
    "jp",
    "jnp",
    "jcxz",
    "jecxz",
}
_SV_JCC_CONDITION_CODES = {
    "jb": 2,
    "jae": 3,
    "jz": 4,
    "je": 4,
    "jnz": 5,
    "jne": 5,
    "jbe": 6,
    "ja": 7,
    "jl": 12,
    "jge": 13,
    "jle": 14,
    "jg": 15,
}
#: instructions whose bytes are safe to overwrite when redirecting a jmp reg
#: (the address-computation chain + the setcc/shift/select that feed it).
_SV_CHAIN_MNEMS = {"mov", "lea", "add", "sub", "xor", "and", "or", "shl", "sal", "shr"}
#: instructions safe to RELOCATE verbatim (position-independent, flag-neutral).
_SV_FLAG_SAFE_RELOC = {"mov", "lea", "push", "pop", "nop", "movzx", "movsx"}


def _branch_state_choice_candidates(
    *,
    source_block_ea: int,
    predicate_ea: int,
    condition_code: int | None,
    source_state: Mapping[str, frozenset[int] | None],
    taken_state: Mapping[str, frozenset[int] | None],
    fallthrough_state: Mapping[str, frozenset[int] | None],
    taken_resolved_target_ea: int,
    fallthrough_resolved_target_ea: int,
    register_mregs: Mapping[str, int],
    predicate_register_names: frozenset[str] = frozenset(),
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Prove a native branch that overrides one default dispatcher state."""
    if (
        int(source_block_ea) <= 0
        or int(predicate_ea) <= 0
        or condition_code not in _SV_JCC_CONDITION_CODES.values()
        or int(taken_resolved_target_ea) <= 0
        or int(fallthrough_resolved_target_ea) <= 0
        or int(taken_resolved_target_ea) == int(fallthrough_resolved_target_ea)
    ):
        return ()
    candidates: list[MaterializedIndirectTransfer] = []
    for register_name in sorted(
        set(source_state) & set(taken_state) & set(fallthrough_state)
    ):
        mreg = register_mregs.get(register_name)
        source_values = source_state.get(register_name)
        taken_values = taken_state.get(register_name)
        fallthrough_values = fallthrough_state.get(register_name)
        if (
            mreg is None
            or register_name in predicate_register_names
            or source_values is None
            or taken_values is None
            or fallthrough_values is None
            or len(source_values) != 1
            or len(taken_values) != 1
            or len(fallthrough_values) != 1
        ):
            continue
        source_value = int(next(iter(source_values))) & _MASK32
        taken_value = int(next(iter(taken_values))) & _MASK32
        fallthrough_value = int(next(iter(fallthrough_values))) & _MASK32
        if taken_value == fallthrough_value or source_value not in {
            taken_value,
            fallthrough_value,
        }:
            continue
        candidates.append(
            MaterializedIndirectTransfer(
                source_jmp_ea=int(predicate_ea),
                source_block_ea=int(source_block_ea),
                materialized_anchor_eas=(int(predicate_ea),),
                target_eas=(),
                condition_code=int(condition_code),
                selector_state_var_reg=int(mreg),
                predicate_true_state=taken_value,
                predicate_false_state=fallthrough_value,
                resolver_kind="static_conditional_state_choice",
            )
        )
    return tuple(candidates)


def _unique_static_equality_handler_routes(
    transfers: Sequence[MaterializedIndirectTransfer],
    state_var_reg: int,
) -> dict[int, tuple[int, int | None]]:
    """Exact state-to-handler labels from resolver and condition-chain proof."""
    candidates: dict[int, dict[int, set[int]]] = {}
    for transfer in transfers:
        if transfer.resolver_kind in {
            "static_equality_fixpoint",
            "static_fixpoint",
        }:
            if (
                transfer.selector_state_var_reg != int(state_var_reg)
                or transfer.selector_compare_constant is None
            ):
                continue
            if transfer.condition_code == 4:
                target_ea = transfer.true_target_ea
            elif transfer.condition_code == 5:
                target_ea = transfer.false_target_ea
            else:
                continue
            state = int(transfer.selector_compare_constant) & _MASK32
        elif transfer.resolver_kind in {
            "static_equality_route",
            "static_handler_entry_route",
            "residual_state_route_evidence",
        }:
            if (
                transfer.selector_state_var_reg != int(state_var_reg)
                or transfer.selector_state_constant is None
                or len(transfer.target_eas) != 1
            ):
                continue
            target_ea = int(transfer.target_eas[0])
            state = int(transfer.selector_state_constant) & _MASK32
        else:
            continue
        if target_ea is None:
            continue
        target = int(target_ea)
        bounds = candidates.setdefault(state, {}).setdefault(target, set())
        if (
            transfer.next_target_ea is not None
            and int(transfer.next_target_ea) > target
        ):
            bounds.add(int(transfer.next_target_ea))
    routes: dict[int, tuple[int, int | None]] = {}
    for state, targets in candidates.items():
        if len(targets) != 1:
            continue
        target, bounds = next(iter(targets.items()))
        routes[state] = (target, min(bounds) if bounds else None)
    return routes


def _unique_static_equality_handler_targets(
    transfers: Sequence[MaterializedIndirectTransfer],
    state_var_reg: int,
) -> dict[int, int]:
    """Compatibility projection of exact state-to-handler labels."""
    return {
        state: target
        for state, (target, _bound) in _unique_static_equality_handler_routes(
            transfers,
            state_var_reg,
        ).items()
    }


def _resolve_static_conditional_state_choice_targets(
    choices: Sequence[MaterializedIndirectTransfer],
    transfers: Sequence[MaterializedIndirectTransfer],
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Bind exact native state choices to one unambiguous dispatcher map.

    The native resolver proves the predicate and both selected constants before
    import.  This stage deliberately waits for independently recovered
    state-to-handler routes.  Missing, conflicting, or same-target arms abstain.
    """
    state_registers = {
        int(transfer.selector_state_var_reg)
        for transfer in transfers
        if transfer.selector_state_var_reg is not None
        and transfer.resolver_kind
        in {
            "static_equality_fixpoint",
            "static_handler_entry_route",
            "static_equality_route",
        }
    }
    if len(state_registers) > 1:
        return ()
    if state_registers:
        state_register = next(iter(state_registers))
    else:
        choice_registers = {
            int(choice.selector_state_var_reg)
            for choice in choices
            if choice.resolver_kind == "static_conditional_state_choice"
            and choice.selector_state_var_reg is not None
        }
        if len(choice_registers) != 1:
            return ()
        state_register = next(iter(choice_registers))
        if not any(
            transfer.resolver_kind == "static_fixpoint"
            and transfer.selector_state_var_reg == state_register
            for transfer in transfers
        ):
            return ()
    state_targets = _unique_static_equality_handler_targets(
        transfers,
        state_register,
    )
    resolved: list[MaterializedIndirectTransfer] = []
    for choice in choices:
        if (
            choice.resolver_kind != "static_conditional_state_choice"
            or choice.predicate_true_state is None
            or choice.predicate_false_state is None
            or (
                choice.selector_state_var_reg is not None
                and int(choice.selector_state_var_reg) != state_register
            )
        ):
            continue
        true_state = int(choice.predicate_true_state) & _MASK32
        false_state = int(choice.predicate_false_state) & _MASK32
        true_target = state_targets.get(true_state)
        false_target = state_targets.get(false_state)
        if (
            true_target is None
            or false_target is None
            or int(true_target) == int(false_target)
        ):
            continue
        carried_through_stack = (
            choice.state_carrier_store_ea is not None
            and choice.state_carrier_stack_displacement is not None
        )
        resolved.append(
            replace(
                choice,
                target_eas=(int(true_target), int(false_target)),
                true_target_ea=int(true_target),
                false_target_ea=int(false_target),
                selector_state_var_reg=state_register,
                predicate_true_is_taken=True,
                predicate_preserve_live=True,
                resolver_kind=(
                    "static_stack_carried_state_choice"
                    if carried_through_stack
                    else "static_conditional_state_choice_bridge"
                ),
            )
        )
    return tuple(
        sorted(
            set(resolved),
            key=lambda row: (
                int(row.source_block_ea),
                int(row.source_jmp_ea),
            ),
        )
    )


def _native_entry_corridor_serials(flow_graph: FlowGraph) -> tuple[int, ...]:
    """Return the one forward native corridor rooted at the function entry.

    Bootstrap evidence is intentionally narrower than general state routing:
    only the first state write on an unbranched forward entry path may create
    it.  Do not fan out into the dispatcher or follow a loop back into the
    entry; those blocks are ordinary handler-routing evidence and can be much
    larger than the bootstrap proof slice.
    """
    current = int(flow_graph.entry_serial)
    seen: set[int] = set()
    corridor: list[int] = []
    while current not in seen:
        block = flow_graph.get_block(current)
        if block is None or int(block.start_ea) <= 0:
            break
        seen.add(current)
        corridor.append(current)
        successors = tuple(int(serial) for serial in block.succs)
        if len(successors) != 1:
            break
        successor = successors[0]
        next_block = flow_graph.get_block(successor)
        if (
            next_block is None
            or int(next_block.start_ea) < int(block.start_ea)
            or (
                int(next_block.start_ea) == int(block.start_ea)
                and block.tail is not None
            )
        ):
            break
        current = successor
    return tuple(corridor)


def _static_native_bootstrap_route_candidates(
    flow_graph: FlowGraph,
    transfers: Sequence[MaterializedIndirectTransfer],
    *,
    native_route_resolver: Callable[[int, int, int], int | None] | None = None,
) -> tuple[tuple[int, int, int], ...]:
    """Return entry-owned state writes with one static native handler route.

    A bootstrap route is deliberately narrower than an ordinary state route:
    its state write must be the first write to that state register along the
    entry corridor, and the same source block must end in one direct goto into
    the dispatcher.  The handler target comes only from a native static
    handler-entry proof.  This produces native EA anchors exclusively; a
    caller must still bind them through the current MBA identity index before
    storing or mutating anything.
    """

    def immediate_state_write(
        block: BlockSnapshot,
        *,
        state_var_reg: int,
    ) -> tuple[int, int] | None:
        writes = {
            (int(insn.ea), int(source.value) & _MASK32)
            for insn in block.insn_snapshots
            if (
                insn.kind is InsnKind.MOV
                and (source := insn.l) is not None
                and source.kind is OperandKind.NUMBER
                and source.value is not None
                and (destination := insn.d) is not None
                and destination.kind is OperandKind.REGISTER
                and destination.reg is not None
                and int(destination.reg) == int(state_var_reg)
                and int(insn.ea) > 0
            )
        }
        return next(iter(writes)) if len(writes) == 1 else None

    def has_earlier_state_write(
        *,
        source_serial: int,
        source_start_ea: int,
        state_var_reg: int,
    ) -> bool:
        """Reject a prior entry-corridor write, without following loop backs.

        The native dispatcher is cyclic.  Walking every predecessor from an
        entry seed eventually reaches state writes from later handler bodies,
        which are not semantically prior to the bootstrap.  A bootstrap has a
        strictly monotone native corridor from the function entry to its
        source; only that corridor can disqualify it.
        """
        pending = list(flow_graph.get_block(int(source_serial)).preds)
        seen: set[int] = set()
        reached_entry = int(source_serial) == int(flow_graph.entry_serial)
        while pending:
            serial = int(pending.pop())
            if serial in seen:
                continue
            seen.add(serial)
            block = flow_graph.get_block(serial)
            if block is None:
                return True
            if serial != int(flow_graph.entry_serial) and (
                int(block.start_ea) <= 0 or int(block.start_ea) >= int(source_start_ea)
            ):
                # A same-or-later native predecessor is a dispatcher loop
                # backedge, not part of the one-time entry corridor.
                continue
            if immediate_state_write(block, state_var_reg=state_var_reg) is not None:
                return True
            if serial == int(flow_graph.entry_serial):
                reached_entry = True
                continue
            pending.extend(int(pred) for pred in block.preds)
        return not reached_entry

    state_registers = {
        int(transfer.selector_state_var_reg)
        for transfer in transfers
        if transfer.selector_state_var_reg is not None
    }
    handler_targets: dict[tuple[int, int], set[int]] = {}
    for transfer in transfers:
        if (
            transfer.resolver_kind != "static_handler_entry_route"
            or transfer.selector_state_var_reg is None
            or transfer.selector_state_constant is None
            or len(transfer.target_eas) != 1
        ):
            continue
        key = (
            int(transfer.selector_state_var_reg),
            int(transfer.selector_state_constant) & _MASK32,
        )
        handler_targets.setdefault(key, set()).add(int(transfer.target_eas[0]))

    candidates: set[tuple[int, int, int]] = set()
    for serial in _native_entry_corridor_serials(flow_graph):
        block = flow_graph.get_block(int(serial))
        if block is None:
            continue
        tail = block.tail
        if (
            tail is None
            or tail.kind is not InsnKind.GOTO
            or int(tail.ea) <= 0
            or len(block.succs) != 1
        ):
            continue
        found_entry_state_write = False
        for state_var_reg in state_registers:
            write = immediate_state_write(block, state_var_reg=state_var_reg)
            if write is None:
                continue
            found_entry_state_write = True
            if has_earlier_state_write(
                source_serial=int(block.serial),
                source_start_ea=int(block.start_ea),
                state_var_reg=state_var_reg,
            ):
                continue
            _write_ea, state = write
            targets = set(handler_targets.get((state_var_reg, state), set()))
            if native_route_resolver is not None:
                native_target = native_route_resolver(
                    int(tail.ea),
                    int(state_var_reg),
                    int(state),
                )
                if native_target is not None and int(native_target) > 0:
                    targets.add(int(native_target))
            if len(targets) != 1:
                continue
            candidates.add((int(tail.ea), state, next(iter(targets))))
        if found_entry_state_write:
            break
    return tuple(sorted(candidates))


def _static_materialized_transfer_batch(
    resolution: ComputedGotoResolution,
    *,
    static_transfers: Sequence[MaterializedIndirectTransfer],
    equality_transfers: Sequence[MaterializedIndirectTransfer],
    static_handler_entry_routes: Sequence[MaterializedIndirectTransfer],
    native_handler_entry_routes: Sequence[MaterializedIndirectTransfer],
    static_handler_exit_routes: Sequence[MaterializedIndirectTransfer] = (),
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Compose the persistent static evidence, including bound state choices.

    Conditional state choices are discovered before byte materialization, but
    their handler targets are known only after the state-to-handler routes have
    been recovered.  Keep the bridge in the same batch as those routes so the
    later PREOPT boundary-port planner can consume the proof.
    """
    source_transfers = (
        *static_transfers,
        *static_handler_entry_routes,
        *native_handler_entry_routes,
    )
    return (
        *static_transfers,
        *equality_transfers,
        *static_handler_entry_routes,
        *native_handler_entry_routes,
        *static_handler_exit_routes,
        *_resolve_static_conditional_state_choice_targets(
            resolution.conditional_state_choices,
            source_transfers,
        ),
    )


def _resolve_static_handler_exit_routes(
    terminal_transfers: Sequence[MaterializedIndirectTransfer],
    handler_entry_routes: Sequence[MaterializedIndirectTransfer],
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Map exact native handler-exit states directly to final handlers.

    The detached static replay proves the state register at the original
    ``jmp reg`` boundary.  The independently recovered BST map proves the
    handler for that state.  Their composition is the native semantic edge
    that the reference rewriter materializes, without retaining a trip through
    the dispatcher.  Missing or conflicting state-register evidence abstains.
    """
    state_registers = {
        int(route.selector_state_var_reg)
        for route in handler_entry_routes
        if route.resolver_kind == "static_handler_entry_route"
        and route.selector_state_var_reg is not None
    }
    if len(state_registers) != 1:
        logger.info(
            "static state-write route discovery abstained: "
            "reason=state_register_count registers=%s transfer_kinds=%s",
            sorted(state_registers),
            dict(
                collections.Counter(
                    route.resolver_kind for route in handler_entry_routes
                )
            ),
        )
        return ()
    state_register = next(iter(state_registers))
    state_targets = _unique_static_equality_handler_targets(
        handler_entry_routes,
        state_register,
    )
    routes: set[MaterializedIndirectTransfer] = set()
    for terminal in terminal_transfers:
        state_values = {
            int(value) & _MASK32
            for register, value in terminal.source_register_values
            if int(register) == state_register
        }
        if len(state_values) != 1:
            continue
        state = next(iter(state_values))
        target_ea = state_targets.get(state)
        if target_ea is None:
            continue
        routes.add(
            MaterializedIndirectTransfer(
                source_jmp_ea=int(terminal.source_jmp_ea),
                source_block_ea=int(terminal.source_block_ea),
                materialized_anchor_eas=(),
                target_eas=(int(target_ea),),
                selector_state_var_reg=state_register,
                selector_state_constant=state,
                source_register_values=tuple(sorted(terminal.source_register_values)),
                dispatcher_envelope_target_eas=tuple(
                    sorted({int(target_ea) for target_ea in terminal.target_eas})
                ),
                resolver_kind="static_handler_exit_route",
            )
        )
    return tuple(
        sorted(
            routes,
            key=lambda route: (
                int(route.source_jmp_ea),
                int(route.target_eas[0]),
            ),
        )
    )


def _recover_prepatch_handler_exit_routes(
    resolution: ComputedGotoResolution,
    static_transfers: Sequence[MaterializedIndirectTransfer],
    handler_entry_routes: Sequence[MaterializedIndirectTransfer],
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Replay every proven handler entry to its original indirect frontier."""
    connected_routes = _recover_connected_static_handler_exit_routes(
        resolution,
        handler_entry_routes,
    )
    entry_eas = tuple(
        sorted(
            {
                int(route.target_eas[0])
                for route in handler_entry_routes
                if route.resolver_kind == "static_handler_entry_route"
                and len(route.target_eas) == 1
            }
        )
    )
    terminal_transfers = _detached_static_terminal_transfers(
        resolution,
        entry_eas,
        entry_context_transfers=tuple(static_transfers),
    )
    detached_routes = _resolve_static_handler_exit_routes(
        terminal_transfers, handler_entry_routes
    )
    return tuple(dict.fromkeys((*connected_routes, *detached_routes)))


def _recover_connected_static_handler_exit_routes(
    resolution: ComputedGotoResolution,
    handler_entry_routes: Sequence[MaterializedIndirectTransfer],
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Project connected-fixpoint snapshots onto original indirect exits."""
    state_registers = {
        int(route.selector_state_var_reg)
        for route in handler_entry_routes
        if route.resolver_kind == "static_handler_entry_route"
        and route.selector_state_var_reg is not None
    }
    if len(state_registers) != 1:
        return ()
    state_register = next(iter(state_registers))
    state_register_name = next(
        (
            name
            for name in _SV_REG_NAMES.values()
            if _native_register_mreg(name) == state_register
        ),
        None,
    )
    if state_register_name is None:
        return ()
    snapshots = {
        int(block_entry): {
            str(name): _sv_singleton(int(value)) for name, value in register_values
        }
        for block_entry, register_values in resolution.corridor_register_snapshots
    }
    terminal_transfers: list[MaterializedIndirectTransfer] = []
    for plan in resolution.patch_plans:
        entry_state = snapshots.get(int(plan.block_entry))
        if entry_state is None:
            continue
        exit_state = _static_register_state_before_jmp(
            int(plan.block_entry),
            entry_state,
            int(plan.jmp_ea),
        )
        state_values = exit_state.get(state_register_name)
        if state_values is None or len(state_values) != 1:
            continue
        source_register_values = tuple(
            sorted(
                _residual_context_mregs(
                    _sv_concrete_register_values(exit_state)
                ).items()
            )
        )
        terminal_transfers.append(
            MaterializedIndirectTransfer(
                source_jmp_ea=int(plan.jmp_ea),
                source_block_ea=int(plan.block_entry),
                materialized_anchor_eas=(),
                target_eas=tuple(int(target) for target in plan.target_eas),
                source_register_values=source_register_values,
                resolver_kind="connected_static_fixpoint",
            )
        )
    return _resolve_static_handler_exit_routes(
        terminal_transfers,
        handler_entry_routes,
    )


def _resolver_targets_by_source(
    transfers: Sequence[MaterializedIndirectTransfer],
) -> dict[int, tuple[int, ...]]:
    """Prefer final handler routes over their obsolete dispatcher envelope."""
    candidates: dict[int, set[int]] = {}
    exact: dict[int, set[int]] = {}
    for transfer in transfers:
        if not transfer.target_eas:
            continue
        source_ea = int(transfer.source_jmp_ea)
        targets = {int(target_ea) for target_ea in transfer.target_eas}
        candidates.setdefault(source_ea, set()).update(targets)
        if transfer.resolver_kind == "static_handler_exit_route":
            exact.setdefault(source_ea, set()).update(targets)
    return {
        source_ea: tuple(sorted(exact.get(source_ea, targets)))
        for source_ea, targets in sorted(candidates.items())
    }


def _state_write_values_match(
    *,
    mnemonic: str,
    destination_mreg: int | None,
    immediate: int | None,
    state_var_reg: int,
    state_constant: int,
) -> bool:
    """Pure identity check for a native immediate register-state write."""
    return (
        str(mnemonic).lower() == "mov"
        and destination_mreg is not None
        and int(destination_mreg) == int(state_var_reg)
        and immediate is not None
        and (int(immediate) & _MASK32) == (int(state_constant) & _MASK32)
    )


class _NativeEqualityRow(NamedTuple):
    """One native equality leaf and the block that initializes its selector."""

    register_name: str
    state_constant: int
    direct_target_ea: int
    block_entry_ea: int
    branch_ea: int
    branch_size: int
    condition_code: int
    terminal_jmp_ea: int
    terminal_end_ea: int
    selector_kind: str


def _encode_two_way_branch(
    *,
    branch_ea: int,
    condition_code: int,
    true_target_ea: int,
    false_target_ea: int,
) -> bytes:
    """Encode ``j<cc> true; jmp false`` without reinterpreting native semantics.

    Callers supply an already-proven condition code and arm polarity from
    microcode.  This helper is delivery-only: it exists because byte-patch
    materialization is the one mechanism that preserves the condition through
    Hex-Rays lifting.
    """
    cc = int(condition_code)
    if not 0 <= cc <= 0xF:
        raise ValueError(f"invalid x86 condition-code nibble: {cc}")
    start = int(branch_ea)
    jcc_end = start + 6
    jmp_end = jcc_end + 5
    return (
        bytes([0x0F, 0x80 + cc])
        + struct.pack("<i", int(true_target_ea) - jcc_end)
        + b"\xe9"
        + struct.pack("<i", int(false_target_ea) - jmp_end)
    )


def _canonical_low_byte_parent(register_name: str | None) -> str | None:
    """Return the 32-bit parent of an x86 low-byte register."""
    return {
        "al": "eax",
        "cl": "ecx",
        "dl": "edx",
        "bl": "ebx",
    }.get(str(register_name).lower() if register_name is not None else "")


def _sv_reg_name(op) -> str | None:
    return _SV_REG_NAMES.get(op.reg)


def _sv_setcc_reg_name(op) -> str | None:
    """Resolve a setcc destination, including IDA's separate low-byte IDs."""
    direct = _sv_reg_name(op)
    if direct is not None:
        return direct
    try:
        import idaapi  # type: ignore[import-untyped]

        return _canonical_low_byte_parent(idaapi.get_reg_name(int(op.reg), 1))
    except Exception:
        return None


def _sv_singleton(v: int) -> frozenset:
    return frozenset({v & _MASK32})


def _sv_combine(a, b, fn):
    if a is None or b is None:
        return None
    out: set[int] = set()
    for x, y in itertools.product(a, b):
        out.add(fn(x, y) & _MASK32)
        if len(out) > _MAX_SET:
            return None
    return frozenset(out)


def _sv_mem_addr_set(op, state):
    """Effective-address SET for a memory operand (o_mem/o_displ/o_phrase),
    modelling base register + disp + SIB index*scale. None (Top) if any needed
    register is unknown."""
    import idaapi  # type: ignore[import-untyped]

    disp = op.addr & _MASK32
    base_set = None
    if op.type == idaapi.o_phrase:
        b = _SV_REG_NAMES.get(op.reg)  # o_phrase base lives in op.reg
        if b is None:
            return None
        base_set = state.get(b)
        if base_set is None:
            return None
    elif op.type == idaapi.o_displ:
        b = _SV_REG_NAMES.get(op.phrase) or _SV_REG_NAMES.get(op.reg)
        if b is not None:
            base_set = state.get(b)
            if base_set is None:
                return None
    if base_set is None:  # o_mem: pure disp (+ optional SIB index)
        addrs = {disp}
    else:
        addrs = {(disp + x) & _MASK32 for x in base_set}
    if op.specflag1:  # SIB present
        sib = op.specflag2 & 0xFF
        scale = 1 << ((sib >> 6) & 3)
        idx = (sib >> 3) & 7
        if idx != 4:  # 4 == no index (esp slot)
            iname = _SV_REG_NAMES.get(idx)
            ivals = state.get(iname) if iname else None
            if ivals is None:
                return None
            addrs = {(a + i * scale) & _MASK32 for a in addrs for i in ivals}
    if not addrs or len(addrs) > _MAX_SET:
        return None
    return addrs


def _sv_resolve_source(op, state, *, is_lea: bool):
    import ida_bytes  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    if op.type == idaapi.o_imm:
        return _sv_singleton(op.value)
    if op.type == idaapi.o_reg:
        return state.get(_sv_reg_name(op))
    if op.type in (idaapi.o_mem, idaapi.o_displ, idaapi.o_phrase):
        aset = _sv_mem_addr_set(op, state)
        if aset is None:
            return None
        if is_lea:
            return frozenset(aset)
        out: set[int] = set()
        for a in aset:
            try:
                out.add(ida_bytes.get_dword(a))
            except Exception:
                return None
            if len(out) > _MAX_SET:
                return None
        return frozenset(out) if out else None
    return None


def _sv_process_writer(mnem: str, insn, state) -> None:
    """Transfer function for one register-writing instruction. Updates *state*
    in place; unknown/unsupported writes set the destination to Top (None)."""
    import idaapi  # type: ignore[import-untyped]

    op0 = insn.ops[0]
    if op0.type != idaapi.o_reg or not _insn_writes_first_operand(insn, idaapi.CF_CHG1):
        return
    dst = (
        _sv_setcc_reg_name(op0)
        if mnem.startswith("set") and len(mnem) > 3
        else _sv_reg_name(op0)
    )
    if dst is None:
        return
    if mnem == "mov":
        state[dst] = _sv_resolve_source(insn.ops[1], state, is_lea=False)
    elif mnem == "lea":
        state[dst] = _sv_resolve_source(insn.ops[1], state, is_lea=True)
    elif mnem == "add":
        state[dst] = _sv_combine(
            state.get(dst),
            _sv_resolve_source(insn.ops[1], state, is_lea=False),
            lambda a, b: a + b,
        )
    elif mnem == "sub":
        state[dst] = _sv_combine(
            state.get(dst),
            _sv_resolve_source(insn.ops[1], state, is_lea=False),
            lambda a, b: a - b,
        )
    elif mnem == "xor":
        op1 = insn.ops[1]
        if op1.type == idaapi.o_reg and op1.reg == op0.reg:
            state[dst] = _sv_singleton(0)
        else:
            state[dst] = _sv_combine(
                state.get(dst),
                _sv_resolve_source(op1, state, is_lea=False),
                lambda a, b: a ^ b,
            )
    elif mnem == "and":
        state[dst] = _sv_combine(
            state.get(dst),
            _sv_resolve_source(insn.ops[1], state, is_lea=False),
            lambda a, b: a & b,
        )
    elif mnem == "or":
        state[dst] = _sv_combine(
            state.get(dst),
            _sv_resolve_source(insn.ops[1], state, is_lea=False),
            lambda a, b: a | b,
        )
    elif mnem in _SV_CMOV_MNEMS:
        src_val = _sv_resolve_source(insn.ops[1], state, is_lea=False)
        old = state.get(dst)
        if old is None or src_val is None:
            state[dst] = None
        else:
            merged = old | src_val
            state[dst] = merged if len(merged) <= _MAX_SET else None
    elif mnem in _SV_SHIFT_MNEMS:
        amt = _sv_resolve_source(insn.ops[1], state, is_lea=False)
        cur = state.get(dst)
        if cur is None or amt is None:
            state[dst] = None
        else:
            out: set[int] = set()
            for v in cur:
                for s in amt:
                    out.add(
                        (v << s) & _MASK32
                        if mnem in ("shl", "sal")
                        else (v >> s) & _MASK32
                    )
            state[dst] = frozenset(out) if len(out) <= _MAX_SET else None
    elif mnem.startswith("set") and len(mnem) > 3:  # setcc: low byte := {0,1}
        cur = state.get(dst)
        if cur is None:
            state[dst] = frozenset({0, 1})
        else:
            nxt = frozenset({(v & 0xFFFFFF00) | b for v in cur for b in (0, 1)})
            state[dst] = nxt if len(nxt) <= _MAX_SET else None
    else:
        state[dst] = None


def _sv_join_val(a, b):
    """a, b are frozenset|None(Top). (Bottom handled by presence in caller.)"""
    if a is None or b is None:
        return None
    u = a | b
    return u if len(u) <= _MAX_SET else None


def _sv_join_state(base: dict, incoming: dict) -> tuple[dict, bool]:
    """Join *incoming* into *base*. Returns (merged, changed). Missing key ==
    Bottom; stored None == Top."""
    merged = dict(base)
    changed = False
    for reg, v in incoming.items():
        if reg not in merged:
            merged[reg] = v
            changed = True
        else:
            jv = _sv_join_val(merged[reg], v)
            if jv != merged[reg]:
                merged[reg] = jv
                changed = True
    return merged, changed


def _sv_concrete_register_values(state: Mapping[str, frozenset[int] | None]):
    """Return the exact singleton native-register cells in one fixpoint state."""
    return tuple(
        sorted(
            (str(name), next(iter(values)))
            for name, values in state.items()
            if values is not None and len(values) == 1
        )
    )


def _function_context_register_values(
    entry_state: Mapping[int, Mapping[str, frozenset[int] | None]],
) -> tuple[tuple[str, int], ...]:
    """Return concrete register values invariant wherever the fixpoint defines them.

    A missing mapping is pre-definition and is ignored.  A present ``Top`` or
    multi-value set rejects that register: an orphan snippet cannot safely use
    a value which is path-dependent in the connected static graph.
    """
    observed: dict[str, set[int]] = {}
    rejected: set[str] = set()
    for state in entry_state.values():
        for reg, values in state.items():
            if values is None or len(values) != 1:
                rejected.add(str(reg))
                continue
            observed.setdefault(str(reg), set()).update(int(v) for v in values)
    return tuple(
        sorted(
            (reg, next(iter(values)))
            for reg, values in observed.items()
            if reg not in rejected and len(values) == 1
        )
    )


def _dispatcher_context_register_values(
    entry_state: Mapping[int, Mapping[str, frozenset[int] | None]],
    dispatcher_entries: Sequence[int],
) -> tuple[tuple[str, int], ...]:
    """Return singleton registers equal at every proven dispatcher entry."""
    entries = tuple(dict.fromkeys(int(ea) for ea in dispatcher_entries))
    if not entries:
        return ()
    states: list[Mapping[str, frozenset[int] | None]] = []
    for entry_ea in entries:
        state = entry_state.get(entry_ea)
        if state is None:
            return ()
        states.append(state)
    shared_registers = set(states[0])
    for state in states[1:]:
        shared_registers &= set(state)
    result: list[tuple[str, int]] = []
    for register in sorted(shared_registers):
        values = [state.get(register) for state in states]
        if any(value is None or len(value) != 1 for value in values):
            continue
        concrete = {next(iter(value)) for value in values if value is not None}
        if len(concrete) == 1:
            result.append((str(register), int(next(iter(concrete)))))
    return tuple(result)


def _make_static_conditional_state_choice(
    *,
    source_block_ea: int,
    compare_ea: int,
    select_ea: int,
    condition_code: int | None,
    predicate_register: int | None,
    predicate_stack_ida_stkoff: int | None = None,
    predicate_size: int,
    predicate_constant: int,
    true_values: frozenset[int] | None,
    false_values: frozenset[int] | None,
    state_carrier_store_ea: int | None = None,
    state_carrier_stack_displacement: int | None = None,
) -> MaterializedIndirectTransfer | None:
    """Normalize one exact native compare/CMOV into portable state evidence."""
    if (
        int(source_block_ea) <= 0
        or int(compare_ea) <= 0
        or int(select_ea) <= 0
        or condition_code not in {2, 3, 4, 5, 6, 7, 12, 13, 14, 15}
        or (predicate_register is None) == (predicate_stack_ida_stkoff is None)
        or int(predicate_size) <= 0
        or true_values is None
        or false_values is None
        or len(true_values) != 1
        or len(false_values) != 1
    ):
        return None
    true_state = int(next(iter(true_values))) & _MASK32
    false_state = int(next(iter(false_values))) & _MASK32
    if true_state == false_state:
        return None
    return MaterializedIndirectTransfer(
        source_jmp_ea=int(select_ea),
        source_block_ea=int(source_block_ea),
        materialized_anchor_eas=(
            int(compare_ea),
            int(select_ea),
            *(() if state_carrier_store_ea is None else (int(state_carrier_store_ea),)),
        ),
        target_eas=(),
        condition_code=int(condition_code),
        predicate_register=(
            None if predicate_register is None else int(predicate_register)
        ),
        predicate_stack_ida_stkoff=(
            None
            if predicate_stack_ida_stkoff is None
            else int(predicate_stack_ida_stkoff)
        ),
        predicate_size=int(predicate_size),
        predicate_compare_constant=int(predicate_constant) & _MASK32,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        resolver_kind="static_conditional_state_choice",
        state_carrier_store_ea=(
            None if state_carrier_store_ea is None else int(state_carrier_store_ea)
        ),
        state_carrier_stack_displacement=(
            None
            if state_carrier_stack_displacement is None
            else int(state_carrier_stack_displacement) & _MASK32
        ),
    )


def _branch_state_choice_candidates(
    *,
    source_block_ea: int,
    predicate_ea: int,
    condition_code: int | None,
    source_state: Mapping[str, frozenset[int] | None],
    taken_state: Mapping[str, frozenset[int] | None],
    fallthrough_state: Mapping[str, frozenset[int] | None],
    taken_resolved_target_ea: int,
    fallthrough_resolved_target_ea: int,
    register_mregs: Mapping[str, int],
    predicate_register_names: frozenset[str] = frozenset(),
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Prove a native branch that overrides one default dispatcher state.

    Both arms must already terminate at distinct resolver-owned computed-jump
    frontiers.  A candidate register qualifies only when its value is singleton
    on all three observations, the two arms differ, and the pre-branch value is
    retained by exactly one arm.  The independently recovered equality router
    later decides whether that register and both constants are dispatcher state.
    """
    if (
        int(source_block_ea) <= 0
        or int(predicate_ea) <= 0
        or condition_code not in _SV_JCC_CONDITION_CODES.values()
        or int(taken_resolved_target_ea) <= 0
        or int(fallthrough_resolved_target_ea) <= 0
        or int(taken_resolved_target_ea) == int(fallthrough_resolved_target_ea)
    ):
        return ()
    candidates: list[MaterializedIndirectTransfer] = []
    for register_name in sorted(
        set(source_state) & set(taken_state) & set(fallthrough_state)
    ):
        mreg = register_mregs.get(register_name)
        source_values = source_state.get(register_name)
        taken_values = taken_state.get(register_name)
        fallthrough_values = fallthrough_state.get(register_name)
        if (
            mreg is None
            or register_name in predicate_register_names
            or source_values is None
            or taken_values is None
            or fallthrough_values is None
            or len(source_values) != 1
            or len(taken_values) != 1
            or len(fallthrough_values) != 1
        ):
            continue
        source_value = int(next(iter(source_values))) & _MASK32
        taken_value = int(next(iter(taken_values))) & _MASK32
        fallthrough_value = int(next(iter(fallthrough_values))) & _MASK32
        if taken_value == fallthrough_value or source_value not in {
            taken_value,
            fallthrough_value,
        }:
            continue
        candidates.append(
            MaterializedIndirectTransfer(
                source_jmp_ea=int(predicate_ea),
                source_block_ea=int(source_block_ea),
                materialized_anchor_eas=(int(predicate_ea),),
                target_eas=(),
                condition_code=int(condition_code),
                selector_state_var_reg=int(mreg),
                predicate_true_state=taken_value,
                predicate_false_state=fallthrough_value,
                resolver_kind="static_conditional_state_choice",
            )
        )
    return tuple(candidates)


def _sv_stack_pointer_displacement(op) -> int | None:
    """Return one exact x86 ESP-relative displacement, if present."""
    import idaapi  # type: ignore[import-untyped]

    if int(op.type) != int(idaapi.o_displ):
        return None
    base_name = _SV_REG_NAMES.get(int(op.phrase)) or _SV_REG_NAMES.get(int(op.reg))
    if base_name != "esp":
        return None
    return int(op.addr) & _MASK32


def _static_stack_carrier_frame_offset_overrides(
    choices: Sequence[MaterializedIndirectTransfer],
    *,
    consumer_load_eas_by_displacement: Mapping[int, Sequence[int]],
    native_stack_frame_offsets_by_ea: Mapping[int, tuple[int, ...]],
) -> dict[int, tuple[int, ...]]:
    """Project a connected prologue store identity onto detached consumers.

    IDA can assign ``spd=0`` to a detached handler even though the resolver
    proves that it is entered from the function's established stack frame.
    Match only an explicit stack-carried state choice and an exact native
    ESP displacement; the connected prologue store's IDA-frame identity then
    overrides the detached consumer's transient one.
    """
    overrides: dict[int, tuple[int, ...]] = {}
    for choice in choices:
        store_ea = choice.state_carrier_store_ea
        displacement = choice.state_carrier_stack_displacement
        if store_ea is None or displacement is None:
            continue
        store_offsets = native_stack_frame_offsets_by_ea.get(int(store_ea), ())
        if len(store_offsets) != 1:
            continue
        for consumer_ea in consumer_load_eas_by_displacement.get(
            int(displacement) & _MASK32,
            (),
        ):
            overrides[int(consumer_ea)] = tuple(int(value) for value in store_offsets)
    return overrides


def _bind_static_stack_carrier_consumers(
    choices: Sequence[MaterializedIndirectTransfer],
    *,
    consumer_load_eas_by_displacement: Mapping[int, Sequence[int]],
    native_stack_frame_offsets_by_ea: Mapping[int, tuple[int, ...]],
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Attach stable native producer/consumer identities to carried choices."""
    bound: list[MaterializedIndirectTransfer] = []
    for choice in choices:
        store_ea = choice.state_carrier_store_ea
        displacement = choice.state_carrier_stack_displacement
        if store_ea is None or displacement is None:
            bound.append(choice)
            continue
        store_offsets = native_stack_frame_offsets_by_ea.get(int(store_ea), ())
        consumer_load_eas = tuple(
            sorted(
                {
                    int(ea)
                    for ea in consumer_load_eas_by_displacement.get(
                        int(displacement) & _MASK32,
                        (),
                    )
                }
            )
        )
        if len(store_offsets) != 1 or not consumer_load_eas:
            bound.append(choice)
            continue
        bound.append(
            replace(
                choice,
                state_carrier_consumer_load_eas=consumer_load_eas,
                state_carrier_ida_stkoff=int(store_offsets[0]),
            )
        )
    return tuple(bound)


def _static_conditional_state_choices(
    entry_state: Mapping[int, Mapping[str, frozenset[int] | None]],
    *,
    native_stack_frame_offsets_by_ea: Mapping[int, tuple[int, ...]] | None = None,
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Recover exact compare/CMOV state choices before byte materialization.

    Only an exact register or canonical stack predicate followed by flag-neutral
    instructions and a CMOV with two singleton values qualifies.  The selected
    constants are evidence only; a later stage must map both through the
    dispatcher.
    """
    import ida_ua  # type: ignore[import-untyped]

    stack_offsets_by_ea = (
        {}
        if native_stack_frame_offsets_by_ea is None
        else native_stack_frame_offsets_by_ea
    )
    choices: set[MaterializedIndirectTransfer] = set()
    for block_entry, block_state in sorted(entry_state.items()):
        state = dict(block_state)
        pending_compare: tuple[int, int | None, int | None, int, bool] | None = None
        pending_choice: tuple[MaterializedIndirectTransfer, str] | None = None
        instruction = ida_ua.insn_t()
        ea = int(block_entry)
        while True:
            length = int(ida_ua.decode_insn(instruction, ea))
            if length <= 0:
                break
            mnemonic = idaapi.print_insn_mnem(ea) or ""
            if not mnemonic:
                break
            next_ea = ea + length
            if pending_choice is not None:
                choice, selected_register = pending_choice
                destination = instruction.ops[0]
                source = instruction.ops[1]
                stack_displacement = _sv_stack_pointer_displacement(destination)
                if (
                    mnemonic == "mov"
                    and stack_displacement is not None
                    and source.type == idaapi.o_reg
                    and _sv_reg_name(source) == selected_register
                ):
                    choices.discard(choice)
                    choice = replace(
                        choice,
                        materialized_anchor_eas=(
                            *choice.materialized_anchor_eas,
                            int(ea),
                        ),
                        state_carrier_store_ea=int(ea),
                        state_carrier_stack_displacement=stack_displacement,
                    )
                    choices.add(choice)
                # The carrier store must immediately follow the select.  This
                # avoids carrying flag/register assumptions across unrelated
                # native instructions.
                pending_choice = None
            if mnemonic in {"cmp", "test"}:
                left = instruction.ops[0]
                right = instruction.ops[1]
                left_name = _sv_reg_name(left)
                left_mreg = _native_register_mreg(left_name)
                if (
                    left.type == idaapi.o_reg
                    and left_mreg is not None
                    and (
                        (mnemonic == "cmp" and right.type == idaapi.o_imm)
                        or (
                            mnemonic == "test"
                            and right.type == idaapi.o_reg
                            and _sv_reg_name(right) == left_name
                        )
                    )
                ):
                    pending_compare = (
                        int(ea),
                        int(left_mreg),
                        None,
                        (int(right.value) & _MASK32 if mnemonic == "cmp" else 0),
                        False,
                    )
                elif (
                    mnemonic == "cmp"
                    and _sv_stack_pointer_displacement(left) is not None
                    and right.type == idaapi.o_imm
                    and len(stack_offsets_by_ea.get(int(ea), ())) == 1
                ):
                    pending_compare = (
                        int(ea),
                        None,
                        int(stack_offsets_by_ea[int(ea)][0]),
                        int(right.value) & _MASK32,
                        False,
                    )
                elif (
                    mnemonic == "cmp"
                    and left.type == idaapi.o_reg
                    and right.type == idaapi.o_reg
                ):
                    normalized = normalize_register_compare_predicate(
                        left_mreg=left_mreg,
                        left_values=(
                            state.get(left_name) if left_name is not None else None
                        ),
                        right_mreg=_native_register_mreg(_sv_reg_name(right)),
                        right_values=state.get(_sv_reg_name(right)),
                    )
                    if normalized is None:
                        pending_compare = None
                    else:
                        predicate_register, predicate_constant, swapped = normalized
                        pending_compare = (
                            int(ea),
                            predicate_register,
                            None,
                            predicate_constant,
                            swapped,
                        )
                else:
                    pending_compare = None
            elif mnemonic in _SV_CMOV_MNEMS:
                destination_name = _sv_reg_name(instruction.ops[0])
                source_values = _sv_resolve_source(
                    instruction.ops[1],
                    state,
                    is_lea=False,
                )
                if pending_compare is not None and destination_name is not None:
                    (
                        compare_ea,
                        predicate_register,
                        predicate_stack_ida_stkoff,
                        predicate_constant,
                        swapped,
                    ) = pending_compare
                    condition_code = _select_cc_nibble(int(ea), length)
                    if swapped:
                        condition_code = swapped_x86_condition_code(condition_code)
                    choice = _make_static_conditional_state_choice(
                        source_block_ea=int(block_entry),
                        compare_ea=compare_ea,
                        select_ea=int(ea),
                        condition_code=condition_code,
                        predicate_register=predicate_register,
                        predicate_stack_ida_stkoff=predicate_stack_ida_stkoff,
                        predicate_size=4,
                        predicate_constant=predicate_constant,
                        true_values=source_values,
                        false_values=state.get(destination_name),
                    )
                    if choice is not None:
                        choices.add(choice)
                        pending_choice = (choice, destination_name)
                pending_compare = None
            elif mnemonic not in _SV_FLAG_SAFE_RELOC:
                pending_compare = None

            if mnemonic == "call":
                for register in _SV_CALLER_CLOBBERED:
                    state[register] = None
                pending_compare = None
            else:
                _sv_process_writer(mnemonic, instruction, state)
            if (
                mnemonic == "jmp"
                or mnemonic in _SV_JCC_MNEMS
                or mnemonic in ("retn", "ret", "retf")
            ):
                break
            ea = next_ea
    return tuple(
        sorted(
            choices,
            key=lambda row: (
                int(row.source_block_ea),
                int(row.source_jmp_ea),
            ),
        )
    )


def _static_stack_carrier_consumer_load_eas(
    resolution: ComputedGotoResolution,
) -> dict[int, tuple[int, ...]]:
    """Find exact native state-register reloads before resolver-owned exits."""
    import ida_ua  # type: ignore[import-untyped]

    by_displacement: dict[int, set[int]] = {}
    for plan in resolution.patch_plans:
        selector_name = plan.selector_register_name
        if selector_name is None:
            continue
        instruction = ida_ua.insn_t()
        ea = int(plan.block_entry)
        while ea <= int(plan.jmp_ea):
            length = int(ida_ua.decode_insn(instruction, ea))
            if length <= 0:
                break
            mnemonic = idaapi.print_insn_mnem(ea) or ""
            if (
                mnemonic == "mov"
                and instruction.ops[0].type == idaapi.o_reg
                and _sv_reg_name(instruction.ops[0]) == selector_name
            ):
                displacement = _sv_stack_pointer_displacement(instruction.ops[1])
                if displacement is not None:
                    by_displacement.setdefault(displacement, set()).add(int(ea))
            if ea == int(plan.jmp_ea):
                break
            ea += length
    return {
        displacement: tuple(sorted(load_eas))
        for displacement, load_eas in sorted(by_displacement.items())
    }


def _static_resolver_fixpoint(
    function_ea: int,
    *,
    initial_register_values: tuple[tuple[str, int], ...] = (),
    follow_indirect_targets: bool = True,
) -> tuple[dict, dict, dict, dict, int]:
    """Monotone forward-dataflow fixpoint from *function_ea* that JOINs register
    value-sets at merges. Returns
    ``(entry_state, resolved_sites, unresolved_sites, block_entry_of, steps)``
    where ``resolved_sites`` maps each ``jmp reg`` EA to its sorted target list.

    When ``follow_indirect_targets`` is false, resolved indirect targets are
    recorded but not enqueued.  Detached replay uses that bounded mode to stop
    at the first computed-jump frontier instead of absorbing a target handler.
    """
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    initial_state = {
        str(name): frozenset({int(value) & _MASK32})
        for name, value in initial_register_values
    }
    entry_state: dict[int, dict] = {int(function_ea): initial_state}
    worklist = collections.deque([int(function_ea)])
    in_wl = {int(function_ea)}
    resolved_sites: dict[int, list[int]] = {}
    unresolved_sites: dict[int, str] = {}
    block_entry_of: dict[int, int] = {}
    steps = 0
    insn = ida_ua.insn_t()

    def enqueue(succ: int, exit_state: dict) -> None:
        if succ not in entry_state:
            entry_state[succ] = dict(exit_state)
            if succ not in in_wl:
                worklist.append(succ)
                in_wl.add(succ)
            return
        merged, changed = _sv_join_state(entry_state[succ], exit_state)
        if changed:
            entry_state[succ] = merged
            if succ not in in_wl:
                worklist.append(succ)
                in_wl.add(succ)

    while worklist and steps < _MAX_FIXPOINT_STEPS:
        block_entry = worklist.popleft()
        in_wl.discard(block_entry)
        state = dict(entry_state.get(block_entry, {}))
        ea = block_entry
        succ_list: list[int] = []
        exit_state = state
        while steps < _MAX_FIXPOINT_STEPS:
            steps += 1
            length = ida_ua.decode_insn(insn, ea)
            if length <= 0:
                break
            mnem = idaapi.print_insn_mnem(ea)
            if not mnem:
                break
            next_ea = ea + length
            if mnem == "jmp" and insn.ops[0].type == idaapi.o_reg:
                reg = _sv_reg_name(insn.ops[0])
                block_entry_of[ea] = block_entry
                targets = state.get(reg) if reg else None
                if not targets:
                    unresolved_sites[ea] = f"reg={reg} Top"
                    resolved_sites.pop(ea, None)
                else:
                    resolved_sites[ea] = sorted(targets)
                    unresolved_sites.pop(ea, None)
                    if follow_indirect_targets:
                        succ_list.extend(resolved_sites[ea])
                exit_state = state
                break
            if mnem == "jmp":
                op0 = insn.ops[0]
                if op0.type in (idaapi.o_near, idaapi.o_far):
                    succ_list.append(op0.addr)
                exit_state = state
                break
            if mnem in _SV_JCC_MNEMS:
                op0 = insn.ops[0]
                if op0.type in (idaapi.o_near, idaapi.o_far):
                    succ_list.append(op0.addr)
                succ_list.append(next_ea)
                exit_state = state
                break
            if mnem in ("retn", "ret", "retf"):
                exit_state = state
                break
            if mnem == "call":
                for c in _SV_CALLER_CLOBBERED:
                    state[c] = None
                ea = next_ea
                continue
            _sv_process_writer(mnem, insn, state)
            ea = next_ea
        for s in succ_list:
            enqueue(s, exit_state)
    return entry_state, resolved_sites, unresolved_sites, block_entry_of, steps


def _static_register_state_before_jmp(
    block_entry: int,
    entry_state: Mapping[str, frozenset[int] | None],
    jmp_ea: int,
) -> dict[str, frozenset[int] | None]:
    """Replay one straight native block and return register state at its jump."""
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    state = dict(entry_state)
    insn = ida_ua.insn_t()
    ea = int(block_entry)
    while ea < int(jmp_ea):
        length = ida_ua.decode_insn(insn, ea)
        if length <= 0:
            return {}
        mnem = idaapi.print_insn_mnem(ea)
        if not mnem:
            return {}
        if mnem == "call":
            for register in _SV_CALLER_CLOBBERED:
                state[register] = None
        elif (
            mnem == "jmp"
            or mnem in _SV_JCC_MNEMS
            or mnem
            in {
                "retn",
                "ret",
                "retf",
            }
        ):
            return {}
        else:
            _sv_process_writer(mnem, insn, state)
        ea += length
    return state if ea == int(jmp_ea) else {}


def _static_branch_state_choices(
    entry_state: Mapping[int, Mapping[str, frozenset[int] | None]],
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Recover default-state/override-state branches before materialization.

    Each arm is replayed independently by the existing bounded static fixpoint
    and must reach exactly one uniquely resolved ``jmp reg`` frontier.
    """
    import ida_ua  # type: ignore[import-untyped]

    def first_block_overrides(
        arm_entry_ea: int,
        source_state: Mapping[str, frozenset[int] | None],
    ) -> frozenset[str]:
        arm_state = dict(source_state)
        arm_instruction = ida_ua.insn_t()
        arm_ea = int(arm_entry_ea)
        while True:
            arm_length = int(ida_ua.decode_insn(arm_instruction, arm_ea))
            if arm_length <= 0:
                return frozenset()
            arm_mnemonic = idaapi.print_insn_mnem(arm_ea) or ""
            if not arm_mnemonic:
                return frozenset()
            if (
                arm_mnemonic == "jmp"
                or arm_mnemonic in _SV_JCC_MNEMS
                or arm_mnemonic in {"retn", "ret", "retf"}
            ):
                break
            if arm_mnemonic == "call":
                for register in _SV_CALLER_CLOBBERED:
                    arm_state[register] = None
            else:
                _sv_process_writer(arm_mnemonic, arm_instruction, arm_state)
            arm_ea += arm_length
        return frozenset(
            register_name
            for register_name, source_values in source_state.items()
            for arm_values in (arm_state.get(register_name),)
            if source_values is not None
            and arm_values is not None
            and len(source_values) == 1
            and len(arm_values) == 1
            and source_values != arm_values
        )

    arm_frontier_cache: dict[
        tuple[int, tuple[tuple[str, int], ...]],
        tuple[int, Mapping[str, frozenset[int] | None]] | None,
    ] = {}

    def arm_frontier(
        arm_entry_ea: int,
        source_state: Mapping[str, frozenset[int] | None],
    ) -> tuple[int, Mapping[str, frozenset[int] | None]] | None:
        initial_register_values = _sv_concrete_register_values(source_state)
        cache_key = (int(arm_entry_ea), initial_register_values)
        if cache_key in arm_frontier_cache:
            return arm_frontier_cache[cache_key]
        initial_mregs = {
            int(mreg): int(value)
            for register_name, value in initial_register_values
            for mreg in (_native_register_mreg(register_name),)
            if mreg is not None
        }
        resolved = _resolve_concrete_dispatch_corridor(
            int(arm_entry_ea),
            initial_mregs=initial_mregs,
            handler_eas=frozenset(),
            return_first_indirect_target=True,
            return_first_indirect_result=True,
        )
        result = None
        if isinstance(resolved, _ConcreteDispatchResult):
            result = (
                int(resolved.target_ea),
                {
                    str(register_name): _sv_singleton(int(value))
                    for register_name, value in resolved.register_values
                },
            )
        arm_frontier_cache[cache_key] = result
        return result

    choices: set[MaterializedIndirectTransfer] = set()
    instruction = ida_ua.insn_t()
    for source_block_ea, initial_state in sorted(entry_state.items()):
        state = dict(initial_state)
        predicate_register_names: frozenset[str] = frozenset()
        ea = int(source_block_ea)
        while True:
            length = int(ida_ua.decode_insn(instruction, ea))
            if length <= 0:
                break
            mnemonic = idaapi.print_insn_mnem(ea) or ""
            if not mnemonic:
                break
            next_ea = ea + length
            if mnemonic in _SV_JCC_MNEMS:
                condition_code = _SV_JCC_CONDITION_CODES.get(mnemonic)
                target = instruction.ops[0]
                if condition_code is None or target.type not in {
                    idaapi.o_near,
                    idaapi.o_far,
                }:
                    break
                taken_entry = int(target.addr)
                fallthrough_entry = int(next_ea)
                taken_overrides = first_block_overrides(taken_entry, state)
                fallthrough_overrides = first_block_overrides(
                    fallthrough_entry,
                    state,
                )
                if not taken_overrides and not fallthrough_overrides:
                    break
                taken_result = arm_frontier(
                    taken_entry,
                    state,
                )
                fallthrough_result = arm_frontier(
                    fallthrough_entry,
                    state,
                )
                if taken_result is None or fallthrough_result is None:
                    break
                taken_resolved_target, taken_register_state = taken_result
                fallthrough_resolved_target, fallthrough_register_state = (
                    fallthrough_result
                )
                register_mregs = {
                    register_name: mreg
                    for register_name in (
                        set(state)
                        & set(taken_register_state)
                        & set(fallthrough_register_state)
                    )
                    for mreg in (_native_register_mreg(register_name),)
                    if mreg is not None
                }
                choices.update(
                    _branch_state_choice_candidates(
                        source_block_ea=int(source_block_ea),
                        predicate_ea=int(ea),
                        condition_code=condition_code,
                        source_state=state,
                        taken_state=taken_register_state,
                        fallthrough_state=fallthrough_register_state,
                        taken_resolved_target_ea=taken_resolved_target,
                        fallthrough_resolved_target_ea=(fallthrough_resolved_target),
                        register_mregs=register_mregs,
                        predicate_register_names=predicate_register_names,
                    )
                )
                break
            if mnemonic in {"jmp", "retn", "ret", "retf"}:
                break
            if mnemonic in {"cmp", "test"}:
                predicate_register_names = frozenset(
                    register_name
                    for operand in (instruction.ops[0], instruction.ops[1])
                    for register_name in (_sv_reg_name(operand),)
                    if operand.type == idaapi.o_reg and register_name is not None
                )
            if mnemonic == "call":
                for register in _SV_CALLER_CLOBBERED:
                    state[register] = None
            else:
                _sv_process_writer(mnemonic, instruction, state)
            ea = next_ea
    return tuple(
        sorted(
            choices,
            key=lambda row: (
                int(row.source_block_ea),
                int(row.source_jmp_ea),
                int(row.selector_state_var_reg or -1),
            ),
        )
    )


def _detached_static_terminal_transfers(
    resolution: ComputedGotoResolution,
    entry_eas: tuple[int, ...],
    *,
    entry_context_transfers: tuple[MaterializedIndirectTransfer, ...] = (),
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Resolve detached native ``jmp reg`` sites with proven function context.

    Detached handler ranges are not reachable from the main native CFG, so the
    main fixpoint cannot enumerate their terminal jumps.  Replaying the same
    static fixpoint from each detached entry is sound only with register values
    that were invariant throughout the connected function fixpoint.
    """
    context_register_values = tuple(resolution.function_context_register_values)
    transfers: list[MaterializedIndirectTransfer] = []
    for entry_ea in sorted(set(int(ea) for ea in entry_eas)):
        target_snapshots = {
            tuple(sorted(transfer.target_register_values))
            for transfer in entry_context_transfers
            if int(entry_ea) in {int(target_ea) for target_ea in transfer.target_eas}
            and transfer.target_register_values
        }
        target_context: dict[int, int] = {}
        if target_snapshots:
            snapshots = [dict(snapshot) for snapshot in target_snapshots]
            shared_registers = set(snapshots[0])
            for snapshot in snapshots[1:]:
                shared_registers.intersection_update(snapshot)
            target_context = {
                int(register): int(snapshots[0][register])
                for register in shared_registers
                if all(
                    int(snapshot[register]) == int(snapshots[0][register])
                    for snapshot in snapshots[1:]
                )
            }
        initial_registers = dict(context_register_values)
        initial_registers.update(
            _native_register_values(tuple(sorted(target_context.items())))
        )
        (
            entry_state,
            resolved_sites,
            _unresolved_sites,
            block_entry_of,
            _steps,
        ) = _static_resolver_fixpoint(
            int(entry_ea),
            initial_register_values=tuple(sorted(initial_registers.items())),
            follow_indirect_targets=False,
        )
        if resolved_sites:
            logger.info(
                "detached static replay: entry=0x%X initial=%s resolved=%s",
                int(entry_ea),
                [
                    (name, hex(int(value)))
                    for name, value in sorted(initial_registers.items())
                ],
                {
                    hex(int(source_ea)): [hex(int(target)) for target in targets]
                    for source_ea, targets in sorted(resolved_sites.items())
                },
            )
        for jmp_ea, target_eas in sorted(resolved_sites.items()):
            targets = tuple(int(target_ea) for target_ea in target_eas)
            if not targets:
                continue
            block_entry = int(block_entry_of.get(jmp_ea, entry_ea))
            source_state = _static_register_state_before_jmp(
                block_entry,
                entry_state.get(block_entry, {}),
                int(jmp_ea),
            )
            two_way = (
                _replay_two_way(
                    block_entry,
                    entry_state.get(block_entry, {}),
                    int(jmp_ea),
                )
                if len(targets) == 2
                else None
            )
            if two_way is not None and {
                int(two_way["true"]),
                int(two_way["false"]),
            } != set(targets):
                two_way = None
            transfers.append(
                MaterializedIndirectTransfer(
                    source_jmp_ea=int(jmp_ea),
                    source_block_ea=block_entry,
                    materialized_anchor_eas=(),
                    target_eas=targets,
                    source_register_values=tuple(
                        sorted(
                            _residual_context_mregs(
                                _sv_concrete_register_values(source_state)
                            ).items()
                        )
                    ),
                    condition_code=(
                        int(two_way["cc"]) if two_way is not None else None
                    ),
                    true_target_ea=(
                        int(two_way["true"]) if two_way is not None else None
                    ),
                    false_target_ea=(
                        int(two_way["false"]) if two_way is not None else None
                    ),
                    selector_state_var_reg=(
                        _native_register_mreg(two_way.get("selector_register_name"))
                        if two_way is not None
                        else None
                    ),
                    selector_compare_constant=(
                        two_way.get("selector_compare_constant")
                        if two_way is not None
                        else None
                    ),
                    selector_state_on_left=(
                        two_way.get("selector_state_on_left")
                        if two_way is not None
                        else None
                    ),
                    resolver_kind="detached_static_fixpoint",
                )
            )
    return tuple(dict.fromkeys(transfers))


# --------------------------------------------------------------------------- #
# static delivery: relocate-live-tail byte-patch                              #
# --------------------------------------------------------------------------- #
def _replay_two_way(block_entry: int, entry_state0: dict, jmp_ea: int) -> dict | None:
    """Re-walk ``block_entry..jmp_ea`` keeping TWO forks at the single cmov/setcc
    select to recover ``(cc, true_target, false_target)``. ``true`` is the target
    when the condition is TAKEN. None if the block has no single 2-way select or
    the two forks do not each land on exactly one address."""
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    state_f = dict(entry_state0)
    state_t = dict(entry_state0)
    info: dict | None = None
    selector: dict | None = None
    condition_producer_ea: int | None = None
    insn = ida_ua.insn_t()
    ea = int(block_entry)
    while ea <= int(jmp_ea):
        length = ida_ua.decode_insn(insn, ea)
        if length <= 0:
            return None
        mnem = idaapi.print_insn_mnem(ea)
        if not mnem:
            return None
        if ea == int(jmp_ea):
            break
        if mnem in {"cmp", "test"}:
            condition_producer_ea = int(ea)
            left, right = insn.ops[0], insn.ops[1]
            if (
                mnem == "cmp"
                and left.type == idaapi.o_reg
                and right.type == idaapi.o_imm
            ):
                selector = {
                    "selector_register_name": _sv_reg_name(left),
                    "selector_compare_constant": int(right.value) & _MASK32,
                    "selector_state_on_left": True,
                }
            elif (
                mnem == "cmp"
                and left.type == idaapi.o_imm
                and right.type == idaapi.o_reg
            ):
                selector = {
                    "selector_register_name": _sv_reg_name(right),
                    "selector_compare_constant": int(left.value) & _MASK32,
                    "selector_state_on_left": False,
                }
            else:
                selector = None
        elif mnem == "call":
            for c in _SV_CALLER_CLOBBERED:
                state_f[c] = None
                state_t[c] = None
            selector = None
            condition_producer_ea = None
        elif mnem in _SV_CMOV_MNEMS and insn.ops[0].type == idaapi.o_reg:
            dst = _sv_reg_name(insn.ops[0])
            state_t[dst] = _sv_resolve_source(
                insn.ops[1], state_t, is_lea=False
            )  # taken: dst=src
            # not-taken: dst unchanged
            info = {"ea": ea, "cc": _select_cc_nibble(ea, length)}
            info["condition_producer_ea"] = condition_producer_ea
            if selector is not None:
                info.update(selector)
        elif (
            mnem.startswith("set")
            and len(mnem) > 3
            and insn.ops[0].type == idaapi.o_reg
        ):
            dst = _sv_setcc_reg_name(insn.ops[0])
            if dst is None:
                return None
            old_t = state_t.get(dst)
            old_f = state_f.get(dst)
            base_t = (
                (next(iter(old_t)) & 0xFFFFFF00) if old_t and len(old_t) == 1 else 0
            )
            base_f = (
                (next(iter(old_f)) & 0xFFFFFF00) if old_f and len(old_f) == 1 else 0
            )
            state_t[dst] = _sv_singleton(base_t | 1)  # taken: al = 1
            state_f[dst] = _sv_singleton(base_f | 0)  # not-taken: al = 0
            info = {"ea": ea, "cc": _select_cc_nibble(ea, length)}
            info["condition_producer_ea"] = condition_producer_ea
            if selector is not None:
                info.update(selector)
        else:
            _sv_process_writer(mnem, insn, state_f)
            _sv_process_writer(mnem, insn, state_t)
            if mnem not in _SV_FLAG_SAFE_RELOC:
                selector = None
                condition_producer_ea = None
        ea += length
    if info is None or info.get("cc") is None:
        return None
    reg = _sv_reg_name(insn.ops[0])
    f_vals = state_f.get(reg)
    t_vals = state_t.get(reg)
    if not f_vals or not t_vals or len(f_vals) != 1 or len(t_vals) != 1:
        return None
    ft = next(iter(f_vals))
    tt = next(iter(t_vals))
    if ft == tt:
        return None
    info["false"] = ft
    info["true"] = tt
    return info


def _sv_is_overwritable(mnem: str) -> bool:
    return (
        mnem in _SV_CHAIN_MNEMS
        or mnem in _SV_CMOV_MNEMS
        or (mnem.startswith("set") and len(mnem) > 3)
    )


def _last_reg_writer_end(block_entry: int, jmp_ea: int, reg: str | None) -> int:
    """End-EA of the last instruction (before *jmp_ea*) that writes *reg*.
    Everything after it up to *jmp_ea* is the LIVE tail (target-independent) that
    must be preserved when the jump is redirected."""
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    insn = ida_ua.insn_t()
    ea = int(block_entry)
    last_end = int(block_entry)
    while ea < int(jmp_ea):
        length = ida_ua.decode_insn(insn, ea)
        if length <= 0:
            break
        if insn.ops[0].type == idaapi.o_reg and _sv_reg_name(insn.ops[0]) == reg:
            last_end = ea + length
        ea += length
    return last_end


def _live_tail_bytes(split_ea: int, jmp_ea: int) -> bytes | None:
    """Raw bytes of the live tail ``[split_ea, jmp_ea)`` iff every instruction is
    position-independent and flag-neutral (safe to relocate). None otherwise."""
    import ida_bytes  # type: ignore[import-untyped]
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    insn = ida_ua.insn_t()
    ea = int(split_ea)
    while ea < int(jmp_ea):
        length = ida_ua.decode_insn(insn, ea)
        if length <= 0:
            return None
        if (idaapi.print_insn_mnem(ea) or "") not in _SV_FLAG_SAFE_RELOC:
            return None
        ea += length
    return bytes(ida_bytes.get_bytes(int(split_ea), int(jmp_ea) - int(split_ea)) or b"")


def _find_patch_start(block_entry: int, jmp_ea: int) -> int:
    """Conservative start for delivery: end of the last instruction that is NOT
    an overwritable register-chain op, so ``[start, jmp)`` is all dead chain and
    safe to blanket-overwrite (live mem-stores stay boundaries, preserved)."""
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    insn = ida_ua.insn_t()
    ea = int(block_entry)
    last_boundary_end = int(block_entry)
    while ea <= int(jmp_ea):
        length = ida_ua.decode_insn(insn, ea)
        if length <= 0:
            break
        if ea == int(jmp_ea):
            break
        mnem = idaapi.print_insn_mnem(ea) or ""
        is_chain = _sv_is_overwritable(mnem) and insn.ops[0].type == idaapi.o_reg
        if not is_chain:
            last_boundary_end = ea + length
        ea += length
    return last_boundary_end


def _find_reloc_patch_start(block_entry: int, jmp_ea: int) -> int:
    """Start for relocate-live-tail delivery: end of the last ANCHOR instruction
    (flag-setter / call / anything neither overwritable nor relocatable).
    Everything after it is dead address-chain or a relocatable live op."""
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    insn = ida_ua.insn_t()
    ea = int(block_entry)
    last_anchor_end = int(block_entry)
    while ea < int(jmp_ea):
        length = ida_ua.decode_insn(insn, ea)
        if length <= 0:
            break
        mnem = idaapi.print_insn_mnem(ea) or ""
        is_reg_chain = _sv_is_overwritable(mnem) and insn.ops[0].type == idaapi.o_reg
        is_reloc = mnem in _SV_FLAG_SAFE_RELOC
        if not (is_reg_chain or is_reloc):
            last_anchor_end = ea + length
        ea += length
    return last_anchor_end


def _extend_for_padding(
    region_end: int, needed_extra: int, forbidden_starts: set[int]
) -> int:
    """How many trailing NOP bytes past *region_end* can be reclaimed (stopping at
    any jump-target leader) to fit a longer rewrite."""
    import ida_bytes  # type: ignore[import-untyped]

    extra = 0
    while extra < needed_extra:
        ea = region_end + extra
        if ea in forbidden_starts:
            break
        try:
            b = ida_bytes.get_byte(ea)
        except Exception:
            break
        if b != 0x90:
            break
        extra += 1
    return extra


def _bake_patch_plans(
    resolved_sites: dict,
    block_entry_of: dict,
    entry_state: dict,
    forbidden_starts: set[int],
) -> tuple[list[_PatchPlan], list[tuple[int, int, str]]]:
    """Compute the condition-preserving byte-patch for every resolved site.
    Returns ``(plans, skipped)``; *skipped* is ``(jmp_ea, n_targets, reason)``
    so uncovered sites are logged, never silently dropped."""
    import ida_ua  # type: ignore[import-untyped]

    plans: list[_PatchPlan] = []
    skipped: list[tuple[int, int, str]] = []
    jmp_insn = ida_ua.insn_t()
    for jmp_ea, targets in resolved_sites.items():
        block_entry = block_entry_of.get(jmp_ea, jmp_ea)
        entry_state0 = entry_state.get(block_entry, {})
        jmp_len = ida_ua.decode_insn(jmp_insn, jmp_ea)
        jmp_reg = _sv_reg_name(jmp_insn.ops[0])
        region_end = jmp_ea + jmp_len
        try:
            if len(targets) == 1:
                patch_start = _find_patch_start(block_entry, jmp_ea)
                region_len = region_end - patch_start
                if region_len < 5:
                    region_len += _extend_for_padding(
                        region_end, 5 - region_len, forbidden_starts
                    )
                if region_len < 5:
                    skipped.append((jmp_ea, 1, "no room (uncond)"))
                    continue
                rel = targets[0] - (patch_start + 5)
                body = b"\xe9" + struct.pack("<i", rel)
                body += b"\x90" * (region_len - len(body))
                plans.append(
                    _PatchPlan(
                        jmp_ea=jmp_ea,
                        block_entry=block_entry,
                        patch_start=patch_start,
                        patch_bytes=body,
                        region_end=patch_start + region_len,
                        insn_heads=(patch_start,),
                        new_block_eas=(patch_start,),
                        target_eas=tuple(int(target) for target in targets),
                        source_register_values=_sv_concrete_register_values(
                            entry_state0
                        ),
                    )
                )
            elif len(targets) == 2:
                info = _replay_two_way(block_entry, entry_state0, jmp_ea)
                if info is None:
                    skipped.append((jmp_ea, 2, "2-way replay failed"))
                    continue
                # Conservative patch_start first (live mem-stores are boundaries,
                # preserved outside the region); fall back to anchor-based start
                # (relocates interleaved live movs) only if there is no room.
                done = False
                fail_reason = ""
                for ps_fn in (_find_patch_start, _find_reloc_patch_start):
                    patch_start = ps_fn(block_entry, jmp_ea)
                    split = max(
                        _last_reg_writer_end(block_entry, jmp_ea, jmp_reg), patch_start
                    )
                    tail = _live_tail_bytes(split, jmp_ea)
                    if tail is None:
                        fail_reason = "live tail not relocatable"
                        continue
                    # layout at patch_start: [tail][0F 8x rel32(true)][E9 rel32(false)]
                    jcc_start = patch_start + len(tail)
                    jcc_end = jcc_start + 6
                    jmp_end = jcc_end + 5
                    body = (
                        tail
                        + bytes([0x0F, 0x80 + (info["cc"] & 0xF)])
                        + struct.pack("<i", info["true"] - jcc_end)
                        + b"\xe9"
                        + struct.pack("<i", info["false"] - jmp_end)
                    )
                    region_len = region_end - patch_start
                    if region_len < len(body):
                        region_len += _extend_for_padding(
                            region_end, len(body) - region_len, forbidden_starts
                        )
                    if region_len < len(body):
                        fail_reason = f"no room (need {len(body)} have {region_end - patch_start})"
                        continue
                    body += b"\x90" * (region_len - len(body))
                    plans.append(
                        _PatchPlan(
                            jmp_ea=jmp_ea,
                            block_entry=block_entry,
                            patch_start=patch_start,
                            patch_bytes=body,
                            region_end=patch_start + region_len,
                            insn_heads=(patch_start, jcc_start, jcc_end),
                            # the E9 at jcc_end is a NEW instruction (not in any trace);
                            # both jcc and its E9 fall-through must be pulled into the func.
                            new_block_eas=(jcc_start, jcc_end),
                            target_eas=tuple(int(target) for target in targets),
                            condition_code=int(info["cc"]),
                            true_target_ea=int(info["true"]),
                            false_target_ea=int(info["false"]),
                            selector_register_name=info.get("selector_register_name"),
                            selector_compare_constant=info.get(
                                "selector_compare_constant"
                            ),
                            selector_state_on_left=info.get("selector_state_on_left"),
                            source_register_values=_sv_concrete_register_values(
                                entry_state0
                            ),
                            condition_producer_ea=info.get("condition_producer_ea"),
                        )
                    )
                    done = True
                    break
                if not done:
                    skipped.append((jmp_ea, 2, fail_reason))
            else:
                skipped.append(
                    (jmp_ea, len(targets), f"{len(targets)}-way (needs N-way delivery)")
                )
        except Exception as exc:  # noqa: BLE001
            skipped.append((jmp_ea, len(targets), f"exception: {exc!r}"))
    return plans, skipped


def _static_branch_state_choices(
    entry_state: Mapping[int, Mapping[str, frozenset[int] | None]],
    *,
    target_patch_plans: list[_PatchPlan] | None = None,
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Recover default-state/override-state branches before materialization."""
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    def first_block_overrides(
        arm_entry_ea: int,
        source_state: Mapping[str, frozenset[int] | None],
    ) -> frozenset[str]:
        arm_state = dict(source_state)
        arm_instruction = ida_ua.insn_t()
        arm_ea = int(arm_entry_ea)
        while True:
            arm_length = int(ida_ua.decode_insn(arm_instruction, arm_ea))
            if arm_length <= 0:
                return frozenset()
            arm_mnemonic = (idaapi.print_insn_mnem(arm_ea) or "").lower()
            if not arm_mnemonic:
                return frozenset()
            if (
                arm_mnemonic == "jmp"
                or arm_mnemonic in _SV_JCC_MNEMS
                or arm_mnemonic in {"retn", "ret", "retf"}
            ):
                break
            if arm_mnemonic == "call":
                for register in _SV_CALLER_CLOBBERED:
                    arm_state[register] = None
            else:
                _sv_process_writer(arm_mnemonic, arm_instruction, arm_state)
            arm_ea += arm_length
        return frozenset(
            register_name
            for register_name, source_values in source_state.items()
            for arm_values in (arm_state.get(register_name),)
            if source_values is not None
            and arm_values is not None
            and len(source_values) == 1
            and len(arm_values) == 1
            and source_values != arm_values
        )

    arm_frontier_cache: dict[
        tuple[int, tuple[tuple[str, int], ...]],
        _ConcreteDispatchResult | None,
    ] = {}

    def arm_frontier(
        arm_entry_ea: int,
        source_state: Mapping[str, frozenset[int] | None],
    ) -> _ConcreteDispatchResult | None:
        initial_register_values = _sv_concrete_register_values(source_state)
        cache_key = (int(arm_entry_ea), initial_register_values)
        if cache_key in arm_frontier_cache:
            return arm_frontier_cache[cache_key]
        initial_mregs = {
            int(mreg): int(value)
            for register_name, value in initial_register_values
            for mreg in (_native_register_mreg(register_name),)
            if mreg is not None
        }
        resolved = _resolve_concrete_dispatch_corridor(
            int(arm_entry_ea),
            initial_mregs=initial_mregs,
            handler_eas=frozenset(),
            return_first_indirect_target=True,
            return_first_indirect_result=True,
        )
        result = resolved if isinstance(resolved, _ConcreteDispatchResult) else None
        arm_frontier_cache[cache_key] = result
        return result

    choices: set[MaterializedIndirectTransfer] = set()
    instruction = ida_ua.insn_t()
    for source_block_ea, initial_state in sorted(entry_state.items()):
        state = dict(initial_state)
        predicate_register_names: frozenset[str] = frozenset()
        condition_producer_ea: int | None = None
        ea = int(source_block_ea)
        while True:
            length = int(ida_ua.decode_insn(instruction, ea))
            if length <= 0:
                break
            mnemonic = (idaapi.print_insn_mnem(ea) or "").lower()
            if not mnemonic:
                break
            next_ea = ea + length
            if mnemonic in _SV_JCC_MNEMS:
                condition_code = _SV_JCC_CONDITION_CODES.get(mnemonic)
                target = instruction.ops[0]
                if condition_code is None or target.type not in {
                    idaapi.o_near,
                    idaapi.o_far,
                }:
                    break
                taken_entry = int(target.addr)
                fallthrough_entry = int(next_ea)
                if not (
                    first_block_overrides(taken_entry, state)
                    or first_block_overrides(fallthrough_entry, state)
                ):
                    break
                taken_result = arm_frontier(taken_entry, state)
                fallthrough_result = arm_frontier(fallthrough_entry, state)
                if taken_result is None or fallthrough_result is None:
                    break
                taken_state = {
                    str(register_name): _sv_singleton(int(value))
                    for register_name, value in taken_result.register_values
                }
                fallthrough_state = {
                    str(register_name): _sv_singleton(int(value))
                    for register_name, value in fallthrough_result.register_values
                }
                if (
                    target_patch_plans is not None
                    and taken_result.transfer_ea is not None
                ):
                    transfer_instruction = ida_ua.insn_t()
                    transfer_length = int(
                        ida_ua.decode_insn(
                            transfer_instruction,
                            int(taken_result.transfer_ea),
                        )
                    )
                    target_plan = (
                        None
                        if transfer_length <= 0
                        else _branch_target_patch_plan(
                            source_block_ea=int(source_block_ea),
                            condition_producer_ea=condition_producer_ea,
                            predicate_ea=int(ea),
                            condition_code=condition_code,
                            source_state=state,
                            taken_result=taken_result,
                            fallthrough_result=fallthrough_result,
                            transfer_end_ea=(
                                int(taken_result.transfer_ea) + transfer_length
                            ),
                        )
                    )
                    if target_plan is not None:
                        target_patch_plans.append(target_plan)
                register_mregs = {
                    register_name: mreg
                    for register_name in (
                        set(state) & set(taken_state) & set(fallthrough_state)
                    )
                    for mreg in (_native_register_mreg(register_name),)
                    if mreg is not None
                }
                choices.update(
                    _branch_state_choice_candidates(
                        source_block_ea=int(source_block_ea),
                        predicate_ea=int(ea),
                        condition_code=condition_code,
                        source_state=state,
                        taken_state=taken_state,
                        fallthrough_state=fallthrough_state,
                        taken_resolved_target_ea=int(taken_result.target_ea),
                        fallthrough_resolved_target_ea=int(
                            fallthrough_result.target_ea
                        ),
                        register_mregs=register_mregs,
                        predicate_register_names=predicate_register_names,
                    )
                )
                break
            if mnemonic in {"jmp", "retn", "ret", "retf"}:
                break
            if mnemonic in {"cmp", "test"}:
                condition_producer_ea = int(ea)
                predicate_register_names = frozenset(
                    register_name
                    for operand in (instruction.ops[0], instruction.ops[1])
                    for register_name in (_sv_reg_name(operand),)
                    if operand.type == idaapi.o_reg and register_name is not None
                )
            if mnemonic == "call":
                for register in _SV_CALLER_CLOBBERED:
                    state[register] = None
                condition_producer_ea = None
            else:
                _sv_process_writer(mnemonic, instruction, state)
                if (
                    condition_producer_ea is not None
                    and mnemonic not in {"cmp", "test"}
                    and mnemonic not in _SV_FLAG_SAFE_RELOC
                ):
                    condition_producer_ea = None
            ea = next_ea
    return tuple(
        sorted(
            choices,
            key=lambda row: (
                int(row.source_block_ea),
                int(row.source_jmp_ea),
                int(row.selector_state_var_reg or -1),
            ),
        )
    )


def resolve_computed_gotos_static(function_ea: int) -> ComputedGotoResolution | None:
    """Static x86 fixpoint resolver + pre-baked relocate-live-tail patch plans.
    Returns None unless the database is x86 (32-bit) and at least one ``jmp reg``
    site resolves. This is the fallback for functions the from-entry concolic
    trace cannot execute (unmapped/unseeded prologue)."""
    arch = _detect_arch()
    if arch != "x86":
        return None
    text = _text_segment(function_ea)
    if text is None:
        return None
    text_start, text_end, _ = text

    entry_state, resolved_sites, unresolved_sites, block_entry_of, steps = (
        _static_resolver_fixpoint(function_ea)
    )
    branch_target_candidates: list[_PatchPlan] = []
    branch_state_choices = _static_branch_state_choices(
        entry_state,
        target_patch_plans=branch_target_candidates,
    )
    branch_target_plans, ambiguous_branch_sites = (
        _select_unique_branch_target_patch_plans(branch_target_candidates)
    )
    if not resolved_sites:
        return None

    all_targets: set[int] = set()
    for tgts in resolved_sites.values():
        all_targets.update(tgts)
    forbidden = all_targets | set(entry_state)
    plans, skipped = _bake_patch_plans(
        resolved_sites,
        block_entry_of,
        entry_state,
        forbidden,
    )
    if skipped:
        logger.info(
            "computed-goto(static): %d/%d sites patched; %d skipped: %s",
            len(plans),
            len(resolved_sites),
            len(skipped),
            ", ".join(f"0x{ea:x}:{n}way:{r}" for ea, n, r in skipped[:12]),
        )
    if not plans:
        return None

    reachable = tuple(sorted(set(entry_state) | all_targets))
    stack_envelope_end = (
        max(
            (
                int(ea)
                for ea in (
                    *reachable,
                    *entry_state,
                )
            ),
            default=int(function_ea),
        )
        + 0x100
    )
    native_stack_offsets = native_stack_frame_offsets_for_ranges(
        int(function_ea),
        ((int(function_ea), int(stack_envelope_end)),),
    )
    return ComputedGotoResolution(
        function_ea=int(function_ea),
        jmp_targets={
            int(k): tuple(int(t) for t in v) for k, v in resolved_sites.items()
        },
        reachable_eas=reachable,
        arch=arch,
        executed_insns=steps,
        seeds_run=0,
        stop_reasons=(
            "static_fixpoint",
            f"unresolved={len(unresolved_sites)}",
            f"ambiguous_contextual={len(ambiguous_branch_sites)}",
        ),
        patch_plans=tuple(plans),
        contextual_patch_plans=branch_target_plans,
        block_entries=tuple(sorted(set(entry_state))),
        function_context_register_values=_function_context_register_values(entry_state),
        corridor_register_snapshots=tuple(
            (int(ea), _sv_concrete_register_values(state))
            for ea, state in sorted(entry_state.items())
            if _sv_concrete_register_values(state)
        ),
        dispatcher_context_register_values=_dispatcher_context_register_values(
            entry_state,
            tuple(int(plan.block_entry) for plan in plans),
        ),
        native_stack_frame_offsets=tuple(sorted(native_stack_offsets.items())),
        conditional_state_choices=tuple(
            sorted(
                {
                    *_static_conditional_state_choices(
                        entry_state,
                        native_stack_frame_offsets_by_ea=native_stack_offsets,
                    ),
                    *branch_state_choices,
                },
                key=lambda row: (
                    int(row.source_block_ea),
                    int(row.source_jmp_ea),
                    int(row.selector_state_var_reg or -1),
                ),
            )
        ),
    )


def _static_materialized_transfers(
    resolution: ComputedGotoResolution,
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Convert successful static delivery plans into portable transfer proof.

    The proof is derived from pre-baked plans rather than re-reading the patched
    bytes.  That preserves the resolver's target ordering and predicate polarity
    exactly as the byte-patch delivery used it.  Two-way records are retained but
    intentionally not consumed until recovery has an arm-aware proof.
    """
    all_targets = sorted(
        {
            int(target)
            for plan in resolution.patch_plans
            for target in (
                plan.target_eas or resolution.jmp_targets.get(plan.jmp_ea, ())
            )
        }
    )
    next_target_by_ea = {
        target: (all_targets[index + 1] if index + 1 < len(all_targets) else None)
        for index, target in enumerate(all_targets)
    }
    context_register_values = tuple(
        sorted(
            _residual_context_mregs(resolution.function_context_register_values).items()
        )
    )
    corridor_register_snapshots = tuple(
        (
            int(source_ea),
            tuple(sorted(_residual_context_mregs(register_values).items())),
        )
        for source_ea, register_values in resolution.corridor_register_snapshots
    )
    transfers: list[MaterializedIndirectTransfer] = []
    for plan_index, plan in enumerate(resolution.patch_plans):
        targets = tuple(
            int(target)
            for target in (
                plan.target_eas or resolution.jmp_targets.get(plan.jmp_ea, ())
            )
        )
        if not targets:
            continue
        anchors = tuple(dict.fromkeys((*plan.insn_heads, *plan.new_block_eas)))
        transfers.append(
            MaterializedIndirectTransfer(
                source_jmp_ea=int(plan.jmp_ea),
                source_block_ea=int(plan.block_entry),
                materialized_anchor_eas=anchors,
                target_eas=targets,
                materialized_predicate_ea=(
                    int(plan.new_block_eas[0])
                    if len(targets) == 2 and plan.new_block_eas
                    else None
                ),
                next_target_ea=(
                    next_target_by_ea.get(targets[0]) if len(targets) == 1 else None
                ),
                condition_code=plan.condition_code,
                true_target_ea=plan.true_target_ea,
                false_target_ea=plan.false_target_ea,
                selector_state_var_reg=_native_register_mreg(
                    plan.selector_register_name
                ),
                selector_compare_constant=plan.selector_compare_constant,
                selector_state_on_left=plan.selector_state_on_left,
                context_register_values=context_register_values,
                source_register_values=tuple(
                    sorted(_residual_context_mregs(plan.source_register_values).items())
                ),
                corridor_register_snapshots=(
                    corridor_register_snapshots if plan_index == 0 else ()
                ),
                resolver_kind="static_fixpoint",
                materialized_region_end_ea=int(plan.region_end),
            )
        )
    router_eas_by_state_register: dict[int, tuple[int, ...]] = {}
    state_registers = {
        int(transfer.selector_state_var_reg)
        for transfer in transfers
        if transfer.selector_state_var_reg is not None
    }
    for state_register in state_registers:
        handler_entry_eas = frozenset(
            unique_materialized_equality_target_eas(
                transfers,
                state_register,
            ).values()
        )
        router_eas_by_state_register[state_register] = tuple(
            sorted(
                {
                    int(transfer.source_block_ea)
                    for transfer in transfers
                    if transfer.selector_state_var_reg == state_register
                    and transfer.resolver_kind
                    in {
                        "static_fixpoint",
                        "static_equality_fixpoint",
                    }
                    and int(transfer.source_block_ea) not in handler_entry_eas
                }
            )
        )
    return tuple(
        (
            replace(
                transfer,
                dispatcher_router_eas=router_eas_by_state_register.get(
                    int(transfer.selector_state_var_reg),
                    (),
                ),
            )
            if transfer.selector_state_var_reg is not None
            else transfer
        )
        for transfer in transfers
    )


def _native_register_mreg(name: str | None) -> int | None:
    """Map one resolver-native x86 register name to its Hex-Rays mreg."""
    if name is None:
        return None
    import ida_hexrays  # type: ignore[import-untyped]
    import ida_idp  # type: ignore[import-untyped]

    reg = int(ida_idp.str2reg(str(name)))
    if reg < 0:
        return None
    return int(ida_hexrays.reg2mreg(reg))


def _native_register_state(mreg_values: Mapping[int, int]) -> dict[str, frozenset[int]]:
    """Convert concrete Hex-Rays mregs to resolver-native x86 register names."""
    import ida_hexrays  # type: ignore[import-untyped]
    import ida_idp  # type: ignore[import-untyped]

    state: dict[str, frozenset[int]] = {}
    for mreg, value in mreg_values.items():
        reg = int(ida_hexrays.mreg2reg(int(mreg), 4))
        if reg < 0:
            continue
        name = ida_idp.get_reg_name(reg, 4)
        if name:
            state[str(name).lower()] = _sv_singleton(int(value))
    return state


def _native_register_values(
    mreg_values: tuple[tuple[int, int], ...],
) -> tuple[tuple[str, int], ...]:
    """Convert exact Hex-Rays mreg values to static-resolver register values."""
    state = _native_register_state(dict(mreg_values))
    return tuple(
        sorted(
            (name, next(iter(values)))
            for name, values in state.items()
            if len(values) == 1
        )
    )


def _is_concrete_handler_entry(
    ea: int,
    handler_eas: frozenset[int],
    completed_dispatches: int,
) -> bool:
    """Whether corridor replay has reached a handler after real dispatch."""
    return int(completed_dispatches) > 0 and int(ea) in handler_eas


def _is_ignorable_corridor_store(mnem: str) -> bool:
    """Whether a memory write is register/flags-neutral for route replay."""
    return str(mnem).lower() == "mov"


def _is_materialized_dispatch_instruction(mnem: str) -> bool:
    """Whether one patched branch instruction selects a dispatch arm."""
    name = str(mnem).lower()
    return name == "jmp" or name in _SV_JCC_MNEMS


def _native_return_epilogue_instruction_ea(
    target_ea: int,
    *,
    max_instructions: int = 8,
) -> int | None:
    """Return the exact ``ret`` EA for one proven native epilogue corridor.

    Hex-Rays can expose a resolver-proven function epilogue as ``BLT_XTRN``
    after disconnecting its native tail from the MBA.  This bounded recognizer
    classifies only a straight-line return-value load plus stack/frame teardown;
    calls, branches, stores, arithmetic on non-stack registers, and undecodable
    bytes abstain.
    """
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    ea = int(target_ea)
    saw_teardown = False
    saw_return_value_load = False
    insn = ida_ua.insn_t()
    for _ in range(int(max_instructions)):
        length = int(ida_ua.decode_insn(insn, ea))
        if length <= 0:
            return None
        mnemonic = (idaapi.print_insn_mnem(ea) or "").lower()
        if mnemonic in {"ret", "retn", "retf"}:
            return ea if saw_teardown else None
        if mnemonic == "leave":
            saw_teardown = True
        elif mnemonic == "pop" and insn.ops[0].type == idaapi.o_reg:
            saw_teardown = True
        elif mnemonic == "lea":
            if (
                insn.ops[0].type != idaapi.o_reg
                or _sv_reg_name(insn.ops[0]) != "esp"
                or insn.ops[1].type not in {idaapi.o_displ, idaapi.o_phrase}
                or _SV_REG_NAMES.get(insn.ops[1].reg) != "ebp"
            ):
                return None
            saw_teardown = True
        elif mnemonic == "mov":
            is_stack_return_value_load = (
                not saw_teardown
                and not saw_return_value_load
                and insn.ops[0].type == idaapi.o_reg
                and _sv_reg_name(insn.ops[0]) == "eax"
                and insn.ops[1].type in {idaapi.o_displ, idaapi.o_phrase}
                and _SV_REG_NAMES.get(insn.ops[1].reg) in {"esp", "ebp"}
            )
            if is_stack_return_value_load:
                saw_return_value_load = True
            elif (
                insn.ops[0].type != idaapi.o_reg
                or insn.ops[1].type != idaapi.o_reg
                or _sv_reg_name(insn.ops[0]) != "esp"
                or _sv_reg_name(insn.ops[1]) != "ebp"
            ):
                return None
            saw_teardown = True
        elif mnemonic == "add":
            if (
                insn.ops[0].type != idaapi.o_reg
                or _sv_reg_name(insn.ops[0]) != "esp"
                or insn.ops[1].type != idaapi.o_imm
            ):
                return None
            saw_teardown = True
        elif mnemonic != "nop":
            return None
        ea += length
    return None


def _native_target_is_return_epilogue(
    target_ea: int,
    *,
    max_instructions: int = 8,
) -> bool:
    """Return whether a native target owns one bounded return epilogue."""
    return (
        _native_return_epilogue_instruction_ea(
            int(target_ea),
            max_instructions=int(max_instructions),
        )
        is not None
    )


def _corridor_memory_spaces_may_alias(left: str, right: str) -> bool:
    """Conservative two-space alias rule for corridor memory effects."""
    return "unknown" in (str(left), str(right)) or str(left) == str(right)


def _apply_concrete_equality_setcc(
    mnemonic: str,
    comparison: tuple[int, int],
    current_value: int,
) -> int | None:
    """Apply an equality ``setcc`` to the low byte of one concrete register."""
    condition_code = _equality_setcc_condition_code(mnemonic)
    if condition_code == 4:
        bit = int(int(comparison[0]) == int(comparison[1]))
    elif condition_code == 5:
        bit = int(int(comparison[0]) != int(comparison[1]))
    else:
        return None
    return (int(current_value) & 0xFFFFFF00) | bit


class _ConcreteDispatchResult(NamedTuple):
    """Exact first indirect target plus the register state at that transfer."""

    target_ea: int
    register_values: tuple[tuple[str, int], ...]
    transfer_ea: int | None = None


def _branch_target_patch_plan(
    *,
    source_block_ea: int,
    condition_producer_ea: int | None,
    predicate_ea: int,
    condition_code: int | None,
    source_state: Mapping[str, frozenset[int] | None],
    taken_result: _ConcreteDispatchResult,
    fallthrough_result: _ConcreteDispatchResult,
    transfer_end_ea: int,
) -> _PatchPlan | None:
    """Retain one native JCC whose arms feed the same indirect transfer."""
    taken_transfer_ea = taken_result.transfer_ea
    fallthrough_transfer_ea = fallthrough_result.transfer_ea
    if (
        condition_producer_ea is None
        or condition_code not in _SV_JCC_CONDITION_CODES.values()
        or taken_transfer_ea is None
        or fallthrough_transfer_ea is None
        or int(taken_transfer_ea) != int(fallthrough_transfer_ea)
        or int(taken_result.target_ea) == int(fallthrough_result.target_ea)
        or not int(source_block_ea)
        <= int(condition_producer_ea)
        < int(predicate_ea)
        < int(taken_transfer_ea)
        < int(transfer_end_ea)
    ):
        return None
    transfer_ea = int(taken_transfer_ea)
    return _PatchPlan(
        jmp_ea=transfer_ea,
        block_entry=int(source_block_ea),
        patch_start=int(predicate_ea),
        patch_bytes=b"",
        region_end=int(transfer_end_ea),
        insn_heads=(int(predicate_ea), transfer_ea),
        new_block_eas=(int(predicate_ea), transfer_ea),
        target_eas=(
            int(taken_result.target_ea),
            int(fallthrough_result.target_ea),
        ),
        condition_code=int(condition_code),
        true_target_ea=int(taken_result.target_ea),
        false_target_ea=int(fallthrough_result.target_ea),
        source_register_values=_sv_concrete_register_values(source_state),
        condition_producer_ea=int(condition_producer_ea),
    )


def _select_unique_branch_target_patch_plans(
    candidates: Sequence[_PatchPlan],
) -> tuple[tuple[_PatchPlan, ...], frozenset[int]]:
    """Select one exact branch-target proof per indirect-transfer site."""
    plans_by_site: dict[int, set[_PatchPlan]] = {}
    for plan in candidates:
        plans_by_site.setdefault(int(plan.jmp_ea), set()).add(plan)
    selected: list[_PatchPlan] = []
    ambiguous_sites: set[int] = set()
    for jmp_ea, plans in sorted(plans_by_site.items()):
        if len(plans) != 1:
            ambiguous_sites.add(int(jmp_ea))
            continue
        selected.append(next(iter(plans)))
    return tuple(selected), frozenset(ambiguous_sites)


def _common_concrete_register_values(
    *snapshots: tuple[tuple[str, int], ...],
) -> tuple[tuple[str, int], ...]:
    """Return singleton register values identical in every target snapshot."""
    if not snapshots:
        return ()
    states = [dict(snapshot) for snapshot in snapshots]
    shared_names = set(states[0])
    for state in states[1:]:
        shared_names.intersection_update(state)
    return tuple(
        sorted(
            (name, int(states[0][name]))
            for name in shared_names
            if all(int(state[name]) == int(states[0][name]) for state in states[1:])
        )
    )


def _resolve_concrete_dispatch_corridor(
    start_ea: int,
    *,
    initial_mregs: Mapping[int, int],
    handler_eas: frozenset[int],
    register_snapshots_by_ea: Mapping[int, Mapping[int, int]] | None = None,
    dispatch_anchor_eas: frozenset[int] = frozenset(),
    max_instructions: int = 512,
    return_first_indirect_target: bool = False,
    return_first_indirect_result: bool = False,
    selector_write_handler_mregs: frozenset[int] = frozenset(),
    known_block_entry_eas: frozenset[int] = frozenset(),
) -> int | _ConcreteDispatchResult | None:
    """Interpret a concrete x86 dispatcher corridor to one known handler EA.

    This is resolver evidence only.  It follows register arithmetic, table
    reads, direct predicates, cmov selectors, and indirect jumps.  Calls,
    stores, unknown operands, cycles, or a non-handler leaf abstain.
    """
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    from d810.analyses.control_flow.conditional_jump_eval import predicate_jump_taken
    from d810.ir.semantics import PredicateKind

    jcc_predicates = {
        "jb": PredicateKind.ULT,
        "jc": PredicateKind.ULT,
        "jae": PredicateKind.UGE,
        "jnb": PredicateKind.UGE,
        "jz": PredicateKind.EQ,
        "je": PredicateKind.EQ,
        "jnz": PredicateKind.NE,
        "jne": PredicateKind.NE,
        "jbe": PredicateKind.ULE,
        "ja": PredicateKind.UGT,
        "jl": PredicateKind.SLT,
        "jge": PredicateKind.SGE,
        "jle": PredicateKind.SLE,
        "jg": PredicateKind.SGT,
    }

    def singleton(values) -> int | None:
        return next(iter(values)) if values is not None and len(values) == 1 else None

    def memory_space(op) -> str | None:
        if op.type not in (idaapi.o_mem, idaapi.o_displ, idaapi.o_phrase):
            return None
        base_name = _SV_REG_NAMES.get(op.reg)
        if base_name in ("esp", "ebp"):
            return "stack"
        if op.type == idaapi.o_mem or _sv_mem_addr_set(op, state) is not None:
            return "nonstack"
        return "unknown"

    def memory_read_conflicts(op) -> bool:
        read_space = memory_space(op)
        return read_space is not None and any(
            _corridor_memory_spaces_may_alias(write_space, read_space)
            for write_space in written_memory_spaces
        )

    state = _native_register_state(initial_mregs)
    source_snapshots = {
        int(source_ea): _native_register_state(mregs)
        for source_ea, mregs in (register_snapshots_by_ea or {}).items()
    }
    comparison: tuple[int, int] | None = None
    completed_dispatches = 0
    current_dispatch_target_ea: int | None = None
    current_known_block_entry_ea: int | None = None
    selector_write_handler_names = frozenset(
        _native_register_state({int(mreg): 0 for mreg in selector_write_handler_mregs})
    )
    written_memory_spaces: set[str] = set()
    ea = int(start_ea)
    seen: set[tuple[int, tuple[tuple[str, int], ...]]] = set()
    insn = ida_ua.insn_t()
    for step in range(int(max_instructions)):
        if int(ea) in known_block_entry_eas:
            current_known_block_entry_ea = int(ea)
        for name, values in source_snapshots.get(ea, {}).items():
            if state.get(name) is None:
                state[name] = values
        if _is_concrete_handler_entry(ea, handler_eas, completed_dispatches):
            return ea
        state_key = tuple(
            sorted(
                (name, value)
                for name, values in state.items()
                if (value := singleton(values)) is not None
            )
        )
        key = (ea, state_key)
        if key in seen:
            return None
        seen.add(key)
        length = ida_ua.decode_insn(insn, ea)
        if length <= 0:
            return None
        mnem = (idaapi.print_insn_mnem(ea) or "").lower()
        next_ea = ea + length
        destination_name = (
            _sv_reg_name(insn.ops[0]) if insn.ops[0].type == idaapi.o_reg else None
        )
        if (
            current_dispatch_target_ea is not None
            and destination_name in selector_write_handler_names
            and mnem not in ("cmp", "test")
        ):
            # A dispatcher router consumes the selector; a definition of that
            # selector after at least one proven dispatch marks entry into a
            # handler/state-transition body.  Return its dispatch target, not
            # the later instruction that happened to perform the write.
            handler_entry_ea = (
                current_known_block_entry_ea
                if current_known_block_entry_ea is not None
                else current_dispatch_target_ea
            )
            logger.debug(
                "native corridor selector boundary: entry=0x%X write=0x%X "
                "register=%s mnemonic=%s dispatches=%d",
                int(handler_entry_ea),
                int(ea),
                destination_name,
                mnem,
                int(completed_dispatches),
            )
            return int(handler_entry_ea)
        if mnem == "cmp":
            if any(memory_read_conflicts(insn.ops[index]) for index in (0, 1)):
                return None
            left = singleton(_sv_resolve_source(insn.ops[0], state, is_lea=False))
            right = singleton(_sv_resolve_source(insn.ops[1], state, is_lea=False))
            if left is None or right is None:
                return None
            comparison = (left, right)
            ea = next_ea
            continue
        if mnem in _SV_JCC_MNEMS:
            predicate = jcc_predicates.get(mnem)
            if predicate is None or comparison is None:
                return None
            taken = predicate_jump_taken(
                predicate,
                comparison[0],
                comparison[1],
                operand_size=4,
            )
            if taken is None:
                return None
            target_ea = int(insn.ops[0].addr) if taken else next_ea
            if ea in dispatch_anchor_eas:
                completed_dispatches += 1
                current_dispatch_target_ea = target_ea
            ea = target_ea
            continue
        if mnem in _SV_CMOV_MNEMS:
            if memory_read_conflicts(insn.ops[1]):
                return None
            predicate = jcc_predicates.get("j" + mnem[4:])
            if predicate is None or comparison is None:
                return None
            taken = predicate_jump_taken(
                predicate,
                comparison[0],
                comparison[1],
                operand_size=4,
            )
            if taken:
                dst = _sv_reg_name(insn.ops[0])
                if dst is None:
                    return None
                state[dst] = _sv_resolve_source(insn.ops[1], state, is_lea=False)
            ea = next_ea
            continue
        if _equality_setcc_condition_code(mnem) is not None:
            if comparison is None:
                return None
            dst = _sv_setcc_reg_name(insn.ops[0])
            current = singleton(state.get(dst)) if dst is not None else None
            if dst is None or current is None:
                return None
            updated = _apply_concrete_equality_setcc(
                mnem,
                comparison,
                current,
            )
            if updated is None:
                return None
            state[dst] = _sv_singleton(updated)
            ea = next_ea
            continue
        if mnem == "jmp" and insn.ops[0].type == idaapi.o_reg:
            target = singleton(state.get(_sv_reg_name(insn.ops[0])))
            if target is None:
                return None
            if return_first_indirect_target:
                if return_first_indirect_result:
                    return _ConcreteDispatchResult(
                        int(target),
                        _sv_concrete_register_values(state),
                        int(ea),
                    )
                return int(target)
            completed_dispatches += 1
            current_dispatch_target_ea = int(target)
            ea = int(target)
            continue
        if mnem == "jmp":
            if insn.ops[0].type not in (idaapi.o_near, idaapi.o_far):
                return None
            target_ea = int(insn.ops[0].addr)
            if ea in dispatch_anchor_eas and _is_materialized_dispatch_instruction(
                mnem
            ):
                if return_first_indirect_target:
                    if return_first_indirect_result:
                        return _ConcreteDispatchResult(
                            target_ea,
                            _sv_concrete_register_values(state),
                            int(ea),
                        )
                    return target_ea
                completed_dispatches += 1
            if completed_dispatches > 0:
                # Delivery may place the final direct jump at a sibling head
                # in the same patched region.  Once dispatch is proven, every
                # unconditional transfer updates the candidate block entry.
                current_dispatch_target_ea = target_ea
            ea = target_ea
            continue
        if mnem in ("call", "ret", "retn", "retf"):
            return None
        if insn.ops[0].type != idaapi.o_reg and mnem != "nop":
            if _is_ignorable_corridor_store(mnem):
                written_memory_spaces.add(memory_space(insn.ops[0]) or "unknown")
                ea = next_ea
                continue
            return None
        if memory_read_conflicts(insn.ops[1]):
            return None
        _sv_process_writer(mnem, insn, state)
        ea = next_ea
    return None


def _recover_static_handler_entry_route_transfers(
    transfers: tuple[MaterializedIndirectTransfer, ...],
    *,
    route_resolver=None,
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Resolve condition-chain leaves to their first native handler entry."""
    if route_resolver is None:
        route_resolver = _resolve_concrete_dispatch_corridor

    state_registers = {
        int(transfer.selector_state_var_reg)
        for transfer in transfers
        if transfer.selector_state_var_reg is not None
    }
    context_candidates: dict[int, set[int]] = {}
    for transfer in transfers:
        for mreg, value in transfer.context_register_values:
            if int(mreg) in state_registers:
                continue
            context_candidates.setdefault(int(mreg), set()).add(int(value))
    if not context_candidates or any(
        len(values) != 1 for values in context_candidates.values()
    ):
        return ()
    context_mregs = {
        mreg: next(iter(values)) for mreg, values in context_candidates.items()
    }
    context_register_values = tuple(sorted(context_mregs.items()))
    dispatch_anchor_eas = frozenset(
        int(anchor_ea)
        for transfer in transfers
        for anchor_ea in transfer.materialized_anchor_eas
    )

    leaf_candidates: dict[
        tuple[int, int, int],
        set[tuple[int, int]],
    ] = {}
    for transfer in transfers:
        if (
            transfer.resolver_kind != "condition_chain_handler_evidence"
            or transfer.selector_state_var_reg is None
            or transfer.selector_state_constant is None
            or len(transfer.target_eas) != 1
        ):
            continue
        key = (
            int(transfer.source_jmp_ea),
            int(transfer.selector_state_var_reg),
            int(transfer.selector_state_constant) & _MASK32,
        )
        leaf_candidates.setdefault(key, set()).add(
            (int(transfer.source_block_ea), int(transfer.target_eas[0]))
        )

    result: list[MaterializedIndirectTransfer] = []
    for (source_jmp_ea, state_var_reg, state), proofs in sorted(
        leaf_candidates.items()
    ):
        if len(proofs) != 1:
            continue
        source_block_ea, leaf_target_ea = next(iter(proofs))
        initial_mregs = dict(context_mregs)
        initial_mregs[state_var_reg] = state
        target_ea = route_resolver(
            source_jmp_ea,
            initial_mregs=initial_mregs,
            handler_eas=frozenset(),
            dispatch_anchor_eas=dispatch_anchor_eas,
            return_first_indirect_target=True,
        )
        if (
            target_ea is None
            or int(target_ea) <= 0
            or int(target_ea) in {source_jmp_ea, leaf_target_ea}
        ):
            continue
        result.append(
            MaterializedIndirectTransfer(
                source_jmp_ea=source_jmp_ea,
                source_block_ea=source_block_ea,
                materialized_anchor_eas=(),
                target_eas=(int(target_ea),),
                selector_state_var_reg=state_var_reg,
                selector_state_constant=state,
                context_register_values=context_register_values,
                resolver_kind="static_handler_entry_route",
            )
        )
    return tuple(result)


def _recover_static_choice_handler_entry_routes(
    resolution: ComputedGotoResolution,
    transfers: Sequence[MaterializedIndirectTransfer],
    *,
    entry_seed_resolver=None,
    route_resolver=None,
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Replay exact native choice states through the entry dispatcher.

    The native branch producer proves only which selector state each arm
    chooses.  This second, independent proof starts at the function's first
    direct entry jump and asks the concrete dispatcher to route each state to
    one already-known native block entry.  A state is published only when all
    applicable entry sources agree on one target.
    """
    if resolution.arch != "x86":
        return ()
    if entry_seed_resolver is None:
        entry_seed_resolver = _native_entry_bootstrap_seeds
    if route_resolver is None:
        route_resolver = _resolve_concrete_dispatch_corridor

    states_by_mreg: dict[int, set[int]] = {}
    for choice in resolution.conditional_state_choices:
        if (
            choice.resolver_kind != "static_conditional_state_choice"
            or choice.selector_state_var_reg is None
            or choice.predicate_true_state is None
            or choice.predicate_false_state is None
        ):
            continue
        state_mreg = int(choice.selector_state_var_reg)
        states_by_mreg.setdefault(state_mreg, set()).update(
            {
                int(choice.predicate_true_state) & _MASK32,
                int(choice.predicate_false_state) & _MASK32,
            }
        )
    selector_mregs = frozenset(states_by_mreg)
    if not selector_mregs:
        return ()

    entry_sources_by_mreg: dict[int, set[int]] = {}
    for seed in entry_seed_resolver(
        int(resolution.function_ea),
        selector_mregs,
    ):
        source_ea = int(seed.source_anchor_ea)
        state_mreg = int(seed.state_mreg)
        if int(source_ea) <= 0 or int(state_mreg) not in selector_mregs:
            continue
        entry_sources_by_mreg.setdefault(int(state_mreg), set()).add(int(source_ea))
    if not entry_sources_by_mreg:
        return ()

    known_entries = {
        int(entry_ea) for entry_ea in resolution.block_entries if int(entry_ea) > 0
    }
    known_entries.update(
        int(target_ea)
        for target_eas in resolution.jmp_targets.values()
        for target_ea in target_eas
        if int(target_ea) > 0
    )
    if not known_entries:
        return ()

    context_mregs, register_snapshots_by_ea, dispatch_anchor_eas = (
        _bootstrap_native_replay_inputs(transfers)
    )
    candidates: dict[tuple[int, int], set[tuple[int, int]]] = {}
    for state_mreg, states in sorted(states_by_mreg.items()):
        for state in sorted(states):
            for source_ea in sorted(entry_sources_by_mreg.get(state_mreg, ())):
                initial_mregs = dict(context_mregs)
                initial_mregs[int(state_mreg)] = int(state)
                target_ea = route_resolver(
                    int(source_ea),
                    initial_mregs=initial_mregs,
                    handler_eas=frozenset(),
                    register_snapshots_by_ea=register_snapshots_by_ea,
                    dispatch_anchor_eas=dispatch_anchor_eas,
                    selector_write_handler_mregs=frozenset({int(state_mreg)}),
                    known_block_entry_eas=frozenset(known_entries),
                )
                if (
                    target_ea is None
                    or not isinstance(target_ea, int)
                    or int(target_ea) not in known_entries
                ):
                    continue
                candidates.setdefault((state_mreg, state), set()).add(
                    (int(source_ea), int(target_ea))
                )

    result: list[MaterializedIndirectTransfer] = []
    for (state_mreg, state), facts in sorted(candidates.items()):
        target_eas = {target_ea for _source_ea, target_ea in facts}
        if len(target_eas) != 1:
            continue
        target_ea = next(iter(target_eas))
        source_ea = min(
            source_ea
            for source_ea, candidate_target_ea in facts
            if candidate_target_ea == target_ea
        )
        result.append(
            MaterializedIndirectTransfer(
                source_jmp_ea=int(source_ea),
                source_block_ea=int(source_ea),
                materialized_anchor_eas=(),
                target_eas=(int(target_ea),),
                selector_state_var_reg=int(state_mreg),
                selector_state_constant=int(state),
                context_register_values=tuple(
                    sorted(
                        (int(mreg), int(value))
                        for mreg, value in context_mregs.items()
                        if int(mreg) != int(state_mreg)
                    )
                ),
                resolver_kind="static_handler_entry_route",
            )
        )
    return tuple(result)


def _recover_prepatch_handler_entry_routes(
    resolution: ComputedGotoResolution,
    native_rows: tuple[_NativeEqualityRow, ...],
    *,
    route_resolver=None,
    range_resolver=None,
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Replay native equality leaves before byte delivery destroys them."""
    if resolution.arch != "x86":
        return ()
    if route_resolver is None:
        route_resolver = _resolve_concrete_dispatch_corridor
    if range_resolver is None:
        envelope_end = (
            max(
                (
                    int(ea)
                    for ea in (*resolution.reachable_eas, *resolution.block_entries)
                ),
                default=int(resolution.function_ea),
            )
            + 0x100
        )

        def range_resolver(target_ea: int):
            return _native_residual_fragment_ranges(
                int(target_ea),
                envelope_start_ea=int(resolution.function_ea),
                envelope_end_ea=int(envelope_end),
                max_blocks=128,
                max_bytes=max(0x100, int(envelope_end) - int(resolution.function_ea)),
                require_indirect=False,
            )

    context_candidates: dict[int, set[int]] = {}
    for register_name, value in resolution.function_context_register_values:
        mreg = _native_register_mreg(register_name)
        if mreg is not None:
            context_candidates.setdefault(int(mreg), set()).add(int(value))
    if any(len(values) != 1 for values in context_candidates.values()):
        return ()
    context_mregs = {
        mreg: next(iter(values)) for mreg, values in context_candidates.items()
    }
    context_register_values = tuple(sorted(context_mregs.items()))

    candidates: dict[tuple[int, int], set[tuple[int, int]]] = {}
    for row in native_rows:
        if row.selector_kind not in {"jcc", "setcc"}:
            continue
        state_var_reg = _native_register_mreg(row.register_name)
        if state_var_reg is None:
            continue
        state = int(row.state_constant) & _MASK32
        entry_mregs = _corridor_entry_mregs(
            resolution,
            int(row.block_entry_ea),
        )
        if entry_mregs is None:
            continue
        initial_mregs = dict(context_mregs)
        initial_mregs.update(entry_mregs)
        initial_mregs[int(state_var_reg)] = state
        target_ea = route_resolver(
            int(row.block_entry_ea),
            initial_mregs=initial_mregs,
            handler_eas=frozenset(),
            return_first_indirect_target=True,
        )
        if (
            target_ea is None
            or int(target_ea) <= 0
            or int(target_ea)
            in {
                int(row.block_entry_ea),
                int(row.direct_target_ea),
                int(row.terminal_jmp_ea),
            }
        ):
            continue
        candidates.setdefault((int(state_var_reg), state), set()).add(
            (int(row.block_entry_ea), int(target_ea))
        )

    result: list[MaterializedIndirectTransfer] = []
    for (state_var_reg, state), facts in sorted(candidates.items()):
        target_eas = {target_ea for _source_ea, target_ea in facts}
        if len(target_eas) != 1:
            continue
        target_ea = next(iter(target_eas))
        owned_native_ranges = tuple(
            sorted(
                (int(start_ea), int(end_ea))
                for start_ea, end_ea in range_resolver(int(target_ea))
                if int(start_ea) < int(end_ea)
            )
        )
        source_ea = min(
            source_ea
            for source_ea, candidate_target_ea in facts
            if candidate_target_ea == target_ea
        )
        result.append(
            MaterializedIndirectTransfer(
                source_jmp_ea=source_ea,
                source_block_ea=source_ea,
                materialized_anchor_eas=(),
                target_eas=(target_ea,),
                selector_state_var_reg=state_var_reg,
                selector_state_constant=state,
                context_register_values=context_register_values,
                resolver_kind="static_handler_entry_route",
                owned_native_ranges=owned_native_ranges,
            )
        )
    return tuple(result)


def _recover_static_fixpoint_handler_entry_routes(
    resolution: ComputedGotoResolution,
    transfers: tuple[MaterializedIndirectTransfer, ...],
    *,
    range_resolver=None,
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Preserve exact equality-handler closures before byte delivery.

    The static fixpoint already proves the selected arm of every equality
    leaf.  Replaying that leaf from function-wide register invariants can lose
    path-local address registers, so native ownership is derived directly from
    the proven target while its handler still ends at the original indirect
    transfer.
    """
    if resolution.arch != "x86":
        return ()
    if range_resolver is None:
        envelope_end = (
            max(
                (
                    int(ea)
                    for ea in (*resolution.reachable_eas, *resolution.block_entries)
                ),
                default=int(resolution.function_ea),
            )
            + 0x100
        )

        def range_resolver(target_ea: int):
            return _native_residual_fragment_ranges(
                int(target_ea),
                envelope_start_ea=int(resolution.function_ea),
                envelope_end_ea=int(envelope_end),
                max_blocks=128,
                max_bytes=max(0x100, int(envelope_end) - int(resolution.function_ea)),
                require_indirect=False,
            )

    candidates: dict[
        tuple[int, int, int],
        set[
            tuple[
                int,
                tuple[tuple[int, int], ...],
                tuple[tuple[int, int], ...],
            ]
        ],
    ] = {}
    for transfer in transfers:
        if (
            transfer.resolver_kind
            not in {
                "static_equality_fixpoint",
                "static_fixpoint",
            }
            or transfer.selector_state_var_reg is None
            or transfer.selector_compare_constant is None
            or transfer.condition_code not in {4, 5}
        ):
            continue
        target_ea = (
            transfer.true_target_ea
            if int(transfer.condition_code) == 4
            else transfer.false_target_ea
        )
        if target_ea is None or int(target_ea) not in {
            int(candidate) for candidate in transfer.target_eas
        }:
            continue
        prepatch_ranges = tuple(
            sorted(
                (int(start_ea), int(end_ea))
                for start_ea, end_ea in range_resolver(int(target_ea))
                if int(start_ea) < int(end_ea)
            )
        )
        if not prepatch_ranges:
            continue
        materialized_ranges = tuple(
            (
                int(candidate.source_block_ea),
                int(candidate.materialized_region_end_ea),
            )
            for candidate in transfers
            if candidate.materialized_region_end_ea is not None
            and int(candidate.materialized_region_end_ea)
            > int(candidate.source_block_ea)
            and any(
                int(start_ea) <= int(candidate.source_block_ea) < int(end_ea)
                for start_ea, end_ea in prepatch_ranges
            )
        )
        owned_ranges = merge_detached_snippet_ranges(
            (*prepatch_ranges, *materialized_ranges)
        )
        key = (
            int(transfer.selector_state_var_reg),
            int(transfer.selector_compare_constant) & _MASK32,
            int(target_ea),
        )
        candidates.setdefault(key, set()).add(
            (
                int(transfer.source_block_ea),
                tuple(sorted(transfer.context_register_values)),
                owned_ranges,
            )
        )

    result: list[MaterializedIndirectTransfer] = []
    for (state_var_reg, state, target_ea), facts in sorted(candidates.items()):
        contexts = {context for _source_ea, context, _ranges in facts}
        owned_range_sets = {ranges for _source_ea, _context, ranges in facts}
        if len(contexts) != 1 or len(owned_range_sets) != 1:
            continue
        result.append(
            MaterializedIndirectTransfer(
                source_jmp_ea=min(source_ea for source_ea, _context, _ranges in facts),
                source_block_ea=min(
                    source_ea for source_ea, _context, _ranges in facts
                ),
                materialized_anchor_eas=(),
                target_eas=(int(target_ea),),
                selector_state_var_reg=int(state_var_reg),
                selector_state_constant=int(state),
                context_register_values=next(iter(contexts)),
                resolver_kind="static_handler_entry_route",
                owned_native_ranges=next(iter(owned_range_sets)),
            )
        )
    return tuple(result)


class _ConcreteHandlerStateWrite(NamedTuple):
    """Exact state value and native jump that exits one handler body."""

    next_state: int
    exit_ea: int


def _resolve_concrete_handler_state_write(
    start_ea: int,
    *,
    initial_mregs: Mapping[int, int],
    state_register_name: str,
    dispatch_anchor_eas: frozenset[int] = frozenset(),
    max_instructions: int = 96,
) -> _ConcreteHandlerStateWrite | None:
    """Recover one exact state-register value at a straight-line handler exit.

    This intentionally does not resolve the computed target.  It interprets
    register writers until the first jump and abstains on conditional control
    flow; the portable dispatcher map remains the routing authority.  Calls
    invalidate the x86 caller-saved registers but preserve callee-saved state,
    matching the same transfer rule used by the static dispatcher fixpoint.
    """
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    state = _native_register_state(initial_mregs)
    wanted = str(state_register_name).lower()
    ea = int(start_ea)
    insn = ida_ua.insn_t()
    for _ in range(int(max_instructions)):
        length = ida_ua.decode_insn(insn, ea)
        if length <= 0:
            return None
        mnem = (idaapi.print_insn_mnem(ea) or "").lower()
        if mnem in _SV_JCC_MNEMS:
            values = state.get(wanted)
            if (
                int(ea) in dispatch_anchor_eas
                and values is not None
                and len(values) == 1
            ):
                return _ConcreteHandlerStateWrite(next(iter(values)), int(ea))
            return None
        if mnem == "call":
            for register in _SV_CALLER_CLOBBERED:
                state[register] = None
            ea += length
            continue
        if mnem in ("ret", "retn", "retf"):
            return None
        if mnem == "jmp":
            values = state.get(wanted)
            return (
                _ConcreteHandlerStateWrite(next(iter(values)), int(ea))
                if values is not None and len(values) == 1
                else None
            )
        if insn.ops[0].type == idaapi.o_reg and _insn_writes_first_operand(
            insn, idaapi.CF_CHG1
        ):
            _sv_process_writer(mnem, insn, state)
        ea += length
    return None


def _native_final_state_write_before_live_tail(
    block: BlockSnapshot,
    *,
    state_var_reg: int,
    incoming_state: int,
    radius: int = 0x30,
) -> int | None:
    """Recover one final native state write owned by a live microcode tail.

    Byte-materialized routes can make Hex-Rays fold the state assignment out of
    the MBA while retaining the following branch/jump EA as the block's final
    provenance.  Search backward only from the latest represented microcode
    anchors, take the latest immediate write to the known state register, and
    abstain on ambiguity or an unchanged state.  Earlier represented anchors
    are considered only when a later anchor has no nearby state write.
    """
    import idautils  # type: ignore[import-untyped]
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    anchors = tuple(int(insn.ea) for insn in block.insn_snapshots)
    if not anchors:
        anchors = (int(block.start_ea),)
    insn = ida_ua.insn_t()
    for anchor_ea in reversed(anchors):
        candidates: list[tuple[int, int]] = []
        for instruction_ea in idautils.Heads(
            max(
                int(block.start_ea),
                int(anchor_ea) - int(radius),
            ),
            int(anchor_ea) + 1,
        ):
            if ida_ua.decode_insn(insn, int(instruction_ea)) <= 0:
                continue
            destination_mreg = None
            if insn.ops[0].type == idaapi.o_reg:
                destination_mreg = _native_register_mreg(
                    _sv_reg_name(insn.ops[0]) or ""
                )
            immediate = (
                int(insn.ops[1].value) if insn.ops[1].type == idaapi.o_imm else None
            )
            if not _state_write_values_match(
                mnemonic=idaapi.print_insn_mnem(int(instruction_ea)) or "",
                destination_mreg=destination_mreg,
                immediate=immediate,
                state_var_reg=int(state_var_reg),
                state_constant=int(immediate) if immediate is not None else 0,
            ):
                continue
            candidates.append((int(instruction_ea), int(immediate) & _MASK32))
        if not candidates:
            continue
        latest_ea = max(ea for ea, _state in candidates)
        latest_states = {state for ea, state in candidates if int(ea) == int(latest_ea)}
        if len(latest_states) != 1:
            return None
        state = next(iter(latest_states))
        return int(state) if int(state) != (int(incoming_state) & _MASK32) else None
    return None


def _insn_writes_first_operand(insn, change_first_mask: int) -> bool:
    """Whether the processor descriptor marks operand zero as modified."""
    return bool(int(insn.get_canon_feature()) & int(change_first_mask))


def _block_has_live_register_state_write(
    block: BlockSnapshot,
    *,
    state_var_reg: int,
    state_constant: int,
    instruction_ea: int | None,
) -> bool:
    """Confirm that a cross-maturity anchor still names the live write.

    State-write anchors can outlive the instruction shape that produced them.
    In particular, a later snapshot may contain ``mov stack, state_reg`` at an
    EA previously classified as ``mov #constant, state_reg``.  Such an anchor
    must not publish an unowned route from a handler back to itself.
    """
    for instruction in block.insn_snapshots:
        if instruction_ea is not None and int(instruction.ea) != int(instruction_ea):
            continue
        if instruction.kind is not InsnKind.MOV:
            continue
        source = instruction.l
        destination = instruction.d
        if source is None or destination is None:
            continue
        if (
            source.kind is OperandKind.NUMBER
            and source.value is not None
            and (int(source.value) & _MASK32) == (int(state_constant) & _MASK32)
            and destination.kind is OperandKind.REGISTER
            and destination.reg is not None
            and int(destination.reg) == int(state_var_reg)
        ):
            return True
    return False


def _last_one_way_block_before_target(
    flow_graph: FlowGraph,
    source_serial: int,
    target_serial: int,
) -> int | None:
    """Preserve a live handler corridor before bypassing a terminal epilogue."""
    current = int(source_serial)
    target = int(target_serial)
    seen: set[int] = set()
    while current not in seen and current != target:
        seen.add(current)
        block = flow_graph.get_block(current)
        if block is None or block.nsucc != 1:
            return None
        successor = int(block.succs[0])
        if successor == target:
            return current
        current = successor
    return None


def _build_materialized_state_routes(
    flow_graph: FlowGraph,
    *,
    state_write_anchors: tuple[StateWriteAnchor, ...],
    out_reg_maps: Mapping[int, Mapping[int, int]],
    dispatcher_entry_serial: int,
    state_var_reg: int,
    handler_serials: frozenset[int],
    transfers: tuple[MaterializedIndirectTransfer, ...],
    authoritative_handler_serials: frozenset[int] = frozenset(),
    dispatcher_block_serials: frozenset[int] = frozenset(),
    in_stk_maps: Mapping[int, Mapping[int, int]] | None = None,
    in_reg_maps: Mapping[int, Mapping[int, int]] | None = None,
    out_stk_maps: Mapping[int, Mapping[int, int]] | None = None,
    route_resolver=None,
    handler_states: Mapping[int, tuple[int, ...]] | None = None,
    handler_targets: Mapping[int, int] | None = None,
    replacement_handler_serials: frozenset[int] = frozenset(),
    exact_handler_override_serials: frozenset[int] = frozenset(),
    handler_entry_eas_by_serial: Mapping[int, int] | None = None,
    handler_target_resolver: Callable[[int], int | None] | None = None,
    handler_state_resolver=None,
    handler_entry_resolver=None,
    handler_exit_state_resolver=None,
    terminal_target_resolver=None,
    state_register_name: str | None = None,
    condition_chain_dag: DecisionDag | None = None,
    applied_direct_boundary_evidence: tuple[object, ...] = (),
) -> tuple[MaterializedStateRoute, ...]:
    """Build exact per-state logical-CFG routes from microcode snapshots.

    The portable fixpoint supplies the full register snapshot at each state
    write.  Native decoding is confined to ``route_resolver`` (the concrete
    corridor by default), while the published result contains only portable
    block serials and constants.  Every ambiguity or off-handler result
    abstains.
    """
    if route_resolver is None:
        route_resolver = _resolve_concrete_dispatch_corridor
    if handler_state_resolver is None:
        handler_state_resolver = _resolve_concrete_handler_state_write
    if handler_entry_resolver is None:
        handler_entry_resolver = _resolve_concrete_dispatch_corridor
    if handler_exit_state_resolver is None:
        handler_exit_state_resolver = _native_final_state_write_before_live_tail
    if terminal_target_resolver is None:
        terminal_target_resolver = _native_target_is_return_epilogue
    replacement_handler_serials = frozenset(
        int(serial) for serial in replacement_handler_serials
    )
    trusted_handler_override_serials = frozenset(
        {
            *replacement_handler_serials,
            *(int(serial) for serial in exact_handler_override_serials),
        }
    )
    handler_entry_eas_by_serial = handler_entry_eas_by_serial or {}
    in_stk_maps = in_stk_maps or {}
    in_reg_maps = in_reg_maps or {}
    out_stk_maps = out_stk_maps or {}
    resolver_proven_handlers = set(int(s) for s in authoritative_handler_serials)
    for transfer in transfers:
        if (
            transfer.resolver_kind != "condition_chain_handler_evidence"
            or transfer.selector_state_constant is None
            or len(transfer.target_eas) != 1
        ):
            continue
        target_serial = find_unique_target_entry_block(
            flow_graph,
            int(transfer.target_eas[0]),
        )
        if target_serial is not None:
            resolver_proven_handlers.add(int(target_serial))
    for state_constant in _states_with_validated_exact_equality_routes(transfers):
        exact_native_route = _exact_equality_native_route(
            transfers,
            state_constant,
        )
        target_serial = (
            find_unique_target_entry_block(flow_graph, *exact_native_route)
            if exact_native_route is not None
            else None
        )
        if (
            target_serial is not None
            and int(target_serial) not in dispatcher_block_serials
        ):
            resolver_proven_handlers.add(int(target_serial))
    handler_serials = frozenset(
        int(serial)
        for serial in set(handler_serials).union(resolver_proven_handlers)
        if int(serial) not in dispatcher_block_serials
        or int(serial) in resolver_proven_handlers
    )
    dispatcher_block = flow_graph.get_block(int(dispatcher_entry_serial))
    if dispatcher_block is None or not handler_serials:
        return ()

    handler_by_ea: dict[int, set[int]] = {}
    handler_eas_by_serial: dict[int, frozenset[int]] = {}
    for serial in handler_serials:
        block = flow_graph.get_block(int(serial))
        if block is not None:
            serial_eas = {int(block.start_ea)}
            native_entry_ea = handler_entry_eas_by_serial.get(int(serial))
            if native_entry_ea is not None:
                serial_eas.add(int(native_entry_ea))
            handler_by_ea.setdefault(int(block.start_ea), set()).add(int(serial))
            if native_entry_ea is not None:
                handler_by_ea.setdefault(int(native_entry_ea), set()).add(int(serial))
            for insn in block.insn_snapshots:
                serial_eas.add(int(insn.ea))
                handler_by_ea.setdefault(int(insn.ea), set()).add(int(serial))
            handler_eas_by_serial[int(serial)] = frozenset(serial_eas)
    handler_eas = frozenset(handler_by_ea)
    if not handler_eas:
        return ()

    context_candidates: dict[int, set[int]] = {}
    for transfer in transfers:
        for mreg, value in transfer.context_register_values:
            context_candidates.setdefault(int(mreg), set()).add(int(value))
    context_mregs = {
        mreg: next(iter(values))
        for mreg, values in context_candidates.items()
        if len(values) == 1
    }
    source_candidates: dict[int, dict[int, set[int]]] = {}
    for transfer in transfers:
        for source_ea, register_values in transfer.corridor_register_snapshots:
            by_reg = source_candidates.setdefault(int(source_ea), {})
            for mreg, value in register_values:
                by_reg.setdefault(int(mreg), set()).add(int(value))
        by_reg = source_candidates.setdefault(int(transfer.source_block_ea), {})
        for mreg, value in transfer.source_register_values:
            by_reg.setdefault(int(mreg), set()).add(int(value))
    register_snapshots_by_ea = {
        source_ea: {
            mreg: next(iter(values))
            for mreg, values in by_reg.items()
            if len(values) == 1
        }
        for source_ea, by_reg in source_candidates.items()
    }
    dispatch_anchor_eas = frozenset(
        int(anchor_ea)
        for transfer in transfers
        for anchor_ea in transfer.materialized_anchor_eas
    )

    routes: set[MaterializedStateRoute] = set()
    for transfer in transfers:
        if (
            transfer.resolver_kind != "residual_state_route"
            or transfer.selector_state_constant is None
            or transfer.selector_state_var_reg is None
            or int(transfer.selector_state_var_reg) != int(state_var_reg)
            or len(transfer.target_eas) != 1
        ):
            continue
        state_constant = int(transfer.selector_state_constant) & _MASK32
        target_serial = find_unique_target_entry_block(
            flow_graph,
            int(transfer.target_eas[0]),
            transfer.next_target_ea,
        )
        if (
            target_serial is None
            or int(target_serial) not in trusted_handler_override_serials
            or handler_targets is None
            or handler_targets.get(state_constant) != int(target_serial)
        ):
            continue
        evidence_source_eas = {
            int(evidence.source_block_ea)
            for evidence in transfers
            if (
                evidence.resolver_kind == "residual_state_route_evidence"
                and evidence.selector_state_constant is not None
                and (int(evidence.selector_state_constant) & _MASK32) == state_constant
                and evidence.selector_state_var_reg is not None
                and int(evidence.selector_state_var_reg) == int(state_var_reg)
                and tuple(int(ea) for ea in evidence.target_eas)
                == tuple(int(ea) for ea in transfer.target_eas)
            )
        }
        if len(evidence_source_eas) > 1:
            continue
        primary_source_ea = (
            next(iter(evidence_source_eas))
            if evidence_source_eas
            else int(transfer.source_block_ea)
        )
        source_eas = {
            int(transfer.source_jmp_ea),
            *(int(ea) for ea in transfer.materialized_anchor_eas),
        }
        source_start_serials = {
            int(block.serial)
            for block in flow_graph.blocks.values()
            if int(block.start_ea) == primary_source_ea
        }
        if len(source_start_serials) == 1:
            source_serials = source_start_serials
        elif source_start_serials:
            continue
        else:
            secondary_start_serials = {
                int(block.serial)
                for block in flow_graph.blocks.values()
                if int(block.start_ea) in source_eas
            }
            if len(secondary_start_serials) == 1:
                source_serials = secondary_start_serials
            elif secondary_start_serials:
                continue
            else:
                source_serials = {
                    int(block.serial)
                    for block in flow_graph.blocks.values()
                    if any(
                        int(instruction.ea) in source_eas
                        for instruction in block.insn_snapshots
                    )
                }
        if len(source_serials) != 1:
            continue
        source_serial = next(iter(source_serials))
        source_block = flow_graph.get_block(source_serial)
        if source_block is None or int(target_serial) not in source_block.succs:
            continue
        # The state write may be gone after Hex-Rays folds the already-patched
        # native corridor.  The committed residual transfer plus the exact live
        # source edge is then stronger than a later coarse dispatcher replay.
        routes.add(
            MaterializedStateRoute(
                source_block_serial=source_serial,
                state_constant=state_constant,
                target_handler_serial=int(target_serial),
                proof_kind="exact_live_state_edge",
            )
        )
    for anchor in state_write_anchors:
        if anchor.state_var_reg is None or int(anchor.state_var_reg) != int(
            state_var_reg
        ):
            continue
        source_block = flow_graph.get_block(int(anchor.block_serial))
        if source_block is None:
            continue
        route_source_serials = {int(anchor.block_serial)}
        state_constant = int(anchor.state_const) & _MASK32
        exact_native_route = _exact_equality_native_route(
            transfers,
            state_constant,
        )
        exact_native_target_ea = (
            int(exact_native_route[0]) if exact_native_route is not None else None
        )
        exact_target_serial = (
            find_unique_target_entry_block(flow_graph, *exact_native_route)
            if exact_native_route is not None
            else None
        )
        expected_target_serial = (
            handler_targets.get(state_constant) if handler_targets else None
        )
        terminal_target_omitted = False
        exact_target_is_terminal = False
        if exact_target_serial is not None:
            exact_target_block = flow_graph.get_block(int(exact_target_serial))
            exact_target_is_terminal = (
                exact_target_block is not None
                and exact_target_block.kind is BlockKind.STOP
            )
            if (
                exact_target_block is not None
                and exact_target_block.kind is BlockKind.EXTERNAL
            ):
                try:
                    exact_target_is_terminal = bool(
                        terminal_target_resolver(int(exact_target_block.start_ea))
                    )
                except Exception:
                    exact_target_is_terminal = False
        elif exact_native_target_ea is not None:
            try:
                exact_target_is_terminal = bool(
                    terminal_target_resolver(exact_native_target_ea)
                )
            except Exception:
                exact_target_is_terminal = False
            if exact_target_is_terminal:
                stop_serials = {
                    int(serial)
                    for serial, block in flow_graph.blocks.items()
                    if block.kind is BlockKind.STOP
                }
                if len(stop_serials) == 1:
                    exact_target_serial = next(iter(stop_serials))
                    terminal_target_omitted = True
                else:
                    exact_target_is_terminal = False
        if exact_target_is_terminal and exact_target_serial is not None:
            # The byte-patch plan proves this exact state reaches the native
            # terminal arm.  A coarse imported equality handler is an
            # intermediate selector block and must not replace the terminal
            # endpoint merely because it is a trusted import.  If Hex-Rays
            # omitted the endpoint entirely, retain its stable native identity
            # while projecting the route onto the unique live STOP.
            source_native_ea = None
            if terminal_target_omitted:
                source_native_ea = handler_entry_eas_by_serial.get(
                    int(anchor.block_serial)
                )
                if (
                    source_native_ea is None
                    and int(anchor.block_serial) not in replacement_handler_serials
                    and 0 < int(source_block.start_ea) < 0xFFFFFFFFFFFFFFFF
                ):
                    source_native_ea = int(source_block.start_ea)
            routes.add(
                MaterializedStateRoute(
                    source_block_serial=int(anchor.block_serial),
                    state_constant=state_constant,
                    target_handler_serial=int(exact_target_serial),
                    proof_kind="terminal_state_route",
                    source_native_ea=(
                        int(source_native_ea) if source_native_ea is not None else None
                    ),
                    target_native_ea=(
                        exact_native_target_ea if terminal_target_omitted else None
                    ),
                )
            )
            continue
        if (
            expected_target_serial is not None
            and int(expected_target_serial) in trusted_handler_override_serials
        ):
            exact_target_serial = int(expected_target_serial)
        if exact_target_serial is not None and (
            int(exact_target_serial) in handler_serials
            or (
                expected_target_serial is not None
                and int(expected_target_serial) in dispatcher_block_serials
                and int(exact_target_serial) not in dispatcher_block_serials
            )
        ):
            if int(exact_target_serial) == int(anchor.block_serial) and not (
                _block_has_live_register_state_write(
                    source_block,
                    state_var_reg=int(state_var_reg),
                    state_constant=state_constant,
                    instruction_ea=anchor.instruction_ea,
                )
            ):
                continue
            routes.add(
                MaterializedStateRoute(
                    source_block_serial=int(anchor.block_serial),
                    state_constant=state_constant,
                    target_handler_serial=int(exact_target_serial),
                )
            )
            continue
        expected_handler_eas = (
            handler_eas_by_serial.get(int(expected_target_serial), frozenset())
            if expected_target_serial is not None
            else frozenset()
        )
        route_handler_eas = expected_handler_eas or handler_eas
        for successor_serial in source_block.succs:
            successor = flow_graph.get_block(int(successor_serial))
            if (
                successor is not None
                and tuple(int(pred) for pred in successor.preds)
                == (int(anchor.block_serial),)
                and int(dispatcher_entry_serial)
                in tuple(int(succ) for succ in successor.succs)
                and out_reg_maps.get(int(successor_serial), {}).get(int(state_var_reg))
                == state_constant
            ):
                route_source_serials.add(int(successor_serial))
        source_eas = {int(source_block.start_ea)}
        source_eas.update(int(insn.ea) for insn in source_block.insn_snapshots)
        if anchor.instruction_ea is not None:
            start_eas = (
                int(anchor.instruction_ea),
                int(dispatcher_block.start_ea),
            )
            prefix = tuple(
                insn
                for insn in source_block.insn_snapshots
                if int(insn.ea) <= int(anchor.instruction_ea)
            )
            prefix_block = replace(source_block, insn_snapshots=prefix)
            entry_stores = [
                (
                    dict(in_stk_maps.get(int(anchor.block_serial), {})),
                    dict(in_reg_maps.get(int(anchor.block_serial), {})),
                )
            ]
            entry_stores.extend(
                (
                    dict(out_stk_maps.get(int(pred), {})),
                    dict(out_reg_maps.get(int(pred), {})),
                )
                for pred in source_block.preds
            )
            snapshots = []
            for stk_map, reg_map in entry_stores:
                try:
                    snapshots.append(
                        _transfer_snapshot_constant_block(
                            prefix_block,
                            stk_map,
                            reg_map,
                            -1,
                        )[1]
                    )
                except Exception:
                    continue
        else:
            matching_transfers = tuple(
                transfer
                for transfer in transfers
                if int(transfer.source_block_ea) == int(source_block.start_ea)
                or source_eas.intersection(transfer.materialized_anchor_eas)
            )
            start_ea = int(dispatcher_block.start_ea)
            if matching_transfers:
                latest = max(
                    matching_transfers,
                    key=lambda transfer: int(transfer.source_jmp_ea),
                )
                start_ea = int(latest.source_block_ea)
            start_eas = (start_ea,)
            snapshots = [dict(out_reg_maps.get(int(anchor.block_serial), {}))]

        seen_attempts: set[tuple[int, tuple[tuple[int, int], ...]]] = set()
        for start_ea in dict.fromkeys(start_eas):
            for register_snapshot in snapshots:
                initial_mregs = dict(context_mregs)
                initial_mregs.update(register_snapshot)
                initial_mregs[int(state_var_reg)] = state_constant
                snapshot_key = tuple(sorted(initial_mregs.items()))
                attempt_key = (int(start_ea), snapshot_key)
                if attempt_key in seen_attempts:
                    continue
                seen_attempts.add(attempt_key)
                try:
                    target_ea = route_resolver(
                        int(start_ea),
                        initial_mregs=initial_mregs,
                        handler_eas=route_handler_eas,
                        register_snapshots_by_ea=register_snapshots_by_ea,
                        dispatch_anchor_eas=dispatch_anchor_eas,
                    )
                except Exception:
                    continue
                if target_ea is None:
                    continue
                target_serials = handler_by_ea.get(int(target_ea), set())
                if len(target_serials) != 1:
                    continue
                target_serial = next(iter(target_serials))
                for route_source_serial in route_source_serials:
                    routes.add(
                        MaterializedStateRoute(
                            source_block_serial=int(route_source_serial),
                            state_constant=state_constant,
                            target_handler_serial=target_serial,
                        )
                    )
    replay_states: dict[int, set[int]] = {
        int(source): {int(state) & _MASK32 for state in states}
        for source, states in (handler_states or {}).items()
    }
    for incoming_state in _states_with_validated_exact_equality_routes(transfers):
        exact_native_route = _exact_equality_native_route(
            transfers,
            incoming_state,
        )
        exact_handler_serial = (
            find_unique_target_entry_block(flow_graph, *exact_native_route)
            if exact_native_route is not None
            else None
        )
        if (
            exact_handler_serial is None
            or int(exact_handler_serial) not in handler_serials
            or int(exact_handler_serial) in dispatcher_block_serials
        ):
            continue
        replay_states.setdefault(int(exact_handler_serial), set()).add(
            int(incoming_state) & _MASK32
        )
    for transfer in transfers:
        if (
            transfer.resolver_kind != "condition_chain_handler_evidence"
            or transfer.selector_state_constant is None
            or len(transfer.target_eas) != 1
        ):
            continue
        source_serial = find_unique_target_entry_block(
            flow_graph,
            int(transfer.target_eas[0]),
        )
        if source_serial is None:
            continue
        if (
            int(source_serial) in dispatcher_block_serials
            and int(source_serial) not in resolver_proven_handlers
        ):
            continue
        replay_states.setdefault(int(source_serial), set()).add(
            int(transfer.selector_state_constant) & _MASK32
        )
    if replay_states and handler_targets:
        if state_register_name is None:
            state_register_name = next(
                (
                    name
                    for name in _SV_REG_NAMES.values()
                    if _native_register_mreg(name) == int(state_var_reg)
                ),
                None,
            )
        if state_register_name is not None:
            for source_serial, incoming_states in sorted(replay_states.items()):
                source_block = flow_graph.get_block(int(source_serial))
                if source_block is None:
                    continue
                source_entry_ea = int(
                    handler_entry_eas_by_serial.get(
                        int(source_serial),
                        int(source_block.start_ea),
                    )
                )
                for incoming_state in sorted(incoming_states):
                    initial_mregs = dict(context_mregs)
                    initial_mregs[int(state_var_reg)] = int(incoming_state) & _MASK32
                    try:
                        replay_result = handler_state_resolver(
                            source_entry_ea,
                            initial_mregs=initial_mregs,
                            state_register_name=str(state_register_name),
                            dispatch_anchor_eas=dispatch_anchor_eas,
                        )
                    except Exception:
                        # A native replay can fail before entering a handler
                        # tail that Hex-Rays still represents in microcode.
                        # Keep the independent live-tail proof available.
                        replay_result = None
                    replay_exit_proven = isinstance(
                        replay_result,
                        _ConcreteHandlerStateWrite,
                    )
                    if replay_result is None:
                        next_state = None
                        route_source_serial = None
                    elif isinstance(replay_result, _ConcreteHandlerStateWrite):
                        next_state = int(replay_result.next_state) & _MASK32
                        route_source_serial = find_unique_target_block(
                            flow_graph,
                            int(replay_result.exit_ea),
                        )
                        if route_source_serial in dispatcher_block_serials:
                            route_source_serial = None
                    else:
                        next_state = int(replay_result) & _MASK32
                        route_source_serial = None
                    if next_state == (int(incoming_state) & _MASK32):
                        try:
                            body_ea = handler_entry_resolver(
                                source_entry_ea,
                                initial_mregs=initial_mregs,
                                handler_eas=handler_eas_by_serial.get(
                                    int(source_serial),
                                    frozenset(),
                                ),
                                register_snapshots_by_ea=register_snapshots_by_ea,
                                dispatch_anchor_eas=dispatch_anchor_eas,
                                return_first_indirect_target=False,
                            )
                        except Exception:
                            body_ea = None
                        if body_ea is not None and int(body_ea) != source_entry_ea:
                            try:
                                replay_result = handler_state_resolver(
                                    int(body_ea),
                                    initial_mregs=initial_mregs,
                                    state_register_name=str(state_register_name),
                                    dispatch_anchor_eas=dispatch_anchor_eas,
                                )
                            except Exception:
                                replay_result = None
                            if isinstance(replay_result, _ConcreteHandlerStateWrite):
                                replay_exit_proven = True
                                next_state = int(replay_result.next_state) & _MASK32
                                route_source_serial = find_unique_target_block(
                                    flow_graph,
                                    int(replay_result.exit_ea),
                                )
                                if route_source_serial in dispatcher_block_serials:
                                    route_source_serial = None
                            elif replay_result is not None:
                                next_state = int(replay_result) & _MASK32
                    try:
                        tail_state = handler_exit_state_resolver(
                            source_block,
                            state_var_reg=int(state_var_reg),
                            incoming_state=int(incoming_state) & _MASK32,
                        )
                    except Exception:
                        tail_state = None
                    if tail_state is not None:
                        # The latest state write immediately preceding the
                        # live microcode tail is later evidence than a native
                        # replay that stopped at an intermediate selector.
                        next_state = int(tail_state) & _MASK32
                        if route_source_serial is None:
                            route_source_serial = int(source_serial)
                        replay_exit_proven = True
                    if next_state is None or next_state == (
                        int(incoming_state) & _MASK32
                    ):
                        continue
                    state_constant = int(next_state) & _MASK32
                    exact_native_route = _exact_equality_native_route(
                        transfers,
                        state_constant,
                    )
                    exact_target_serial = (
                        find_unique_target_entry_block(flow_graph, *exact_native_route)
                        if exact_native_route is not None
                        else None
                    )
                    expected_target_serial = handler_targets.get(state_constant)
                    if (
                        expected_target_serial is not None
                        and int(expected_target_serial)
                        in trusted_handler_override_serials
                    ):
                        exact_target_serial = int(expected_target_serial)
                    exact_target_authoritative = exact_target_serial is not None and (
                        int(exact_target_serial) in handler_serials
                        or (
                            expected_target_serial is not None
                            and int(expected_target_serial) in dispatcher_block_serials
                            and int(exact_target_serial) not in dispatcher_block_serials
                        )
                    )
                    target_serial = (
                        exact_target_serial
                        if exact_target_authoritative
                        else expected_target_serial
                    )
                    native_dispatch_start_ea = int(dispatcher_block.start_ea)
                    if target_serial is None and handler_target_resolver is not None:
                        try:
                            target_serial = handler_target_resolver(state_constant)
                        except Exception:
                            target_serial = None
                    if (
                        target_serial is not None
                        and int(target_serial) not in handler_serials
                        and not exact_target_authoritative
                    ):
                        router_block = flow_graph.get_block(int(target_serial))
                        if router_block is not None:
                            native_dispatch_start_ea = int(router_block.start_ea)
                        condition_chain_target = (
                            route_transfer_target_through_condition_chain(
                                flow_graph,
                                condition_chain_dag,
                                int(target_serial),
                                state_constant,
                                handler_serials,
                            )
                            if condition_chain_dag is not None
                            else None
                        )
                        if condition_chain_target is not None:
                            target_serial = int(condition_chain_target)
                        else:
                            target_serial = route_materialized_transfer_chain(
                                flow_graph,
                                transfers,
                                start_block=int(target_serial),
                                state_constant=state_constant,
                                state_var_reg=int(state_var_reg),
                                handler_serials=handler_serials,
                            )
                    if target_serial is None:
                        dispatch_mregs = dict(initial_mregs)
                        dispatch_mregs[int(state_var_reg)] = state_constant
                        try:
                            target_ea = route_resolver(
                                native_dispatch_start_ea,
                                initial_mregs=dispatch_mregs,
                                handler_eas=handler_eas,
                                register_snapshots_by_ea=register_snapshots_by_ea,
                                dispatch_anchor_eas=dispatch_anchor_eas,
                            )
                        except Exception:
                            target_ea = None
                        target_serials = (
                            handler_by_ea.get(int(target_ea), set())
                            if target_ea is not None
                            else set()
                        )
                        if len(target_serials) == 1:
                            target_serial = next(iter(target_serials))
                    if target_serial is None:
                        successor_targets: set[int] = set()
                        for successor_serial in dispatcher_block.succs:
                            if int(successor_serial) in handler_serials:
                                continue
                            if (
                                dispatcher_block_serials
                                and int(successor_serial)
                                not in dispatcher_block_serials
                            ):
                                continue
                            successor = flow_graph.get_block(int(successor_serial))
                            if successor is None:
                                continue
                            try:
                                target_ea = route_resolver(
                                    int(successor.start_ea),
                                    initial_mregs=dispatch_mregs,
                                    handler_eas=handler_eas,
                                    register_snapshots_by_ea=register_snapshots_by_ea,
                                    dispatch_anchor_eas=dispatch_anchor_eas,
                                )
                            except Exception:
                                continue
                            target_serials = (
                                handler_by_ea.get(int(target_ea), set())
                                if target_ea is not None
                                else set()
                            )
                            if len(target_serials) == 1:
                                successor_targets.add(next(iter(target_serials)))
                        if len(successor_targets) == 1:
                            target_serial = next(iter(successor_targets))
                    if target_serial is None or (
                        int(target_serial) not in handler_serials
                        and not exact_target_authoritative
                    ):
                        continue
                    terminal_target_eas = {
                        int(transfer.target_eas[0])
                        for transfer in transfers
                        if transfer.resolver_kind == "static_handler_exit_route"
                        and int(transfer.source_block_ea) == source_entry_ea
                        and transfer.selector_state_var_reg is not None
                        and int(transfer.selector_state_var_reg) == int(state_var_reg)
                        and transfer.selector_state_constant is not None
                        and (int(transfer.selector_state_constant) & _MASK32)
                        == state_constant
                        and len(transfer.target_eas) == 1
                    }
                    terminal_target_ea = (
                        next(iter(terminal_target_eas))
                        if len(terminal_target_eas) == 1
                        else None
                    )
                    target_block = flow_graph.get_block(int(target_serial))
                    terminal_route_target_serial: int | None = None
                    if terminal_target_ea is not None and target_block is not None:
                        try:
                            if terminal_target_resolver(terminal_target_ea):
                                if target_block.nsucc == 0:
                                    terminal_route_target_serial = int(target_serial)
                                elif target_block.nsucc == 1:
                                    successor_serial = int(target_block.succs[0])
                                    successor_block = flow_graph.get_block(
                                        successor_serial
                                    )
                                    if (
                                        successor_block is not None
                                        and successor_block.kind is BlockKind.STOP
                                        and successor_block.nsucc == 0
                                    ):
                                        terminal_route_target_serial = successor_serial
                        except Exception:
                            terminal_route_target_serial = None
                    terminal_route = terminal_route_target_serial is not None
                    selected_route_source_serial = int(
                        route_source_serial
                        if route_source_serial is not None
                        else source_serial
                    )
                    if terminal_route:
                        terminal_predecessor = _last_one_way_block_before_target(
                            flow_graph,
                            selected_route_source_serial,
                            int(target_serial),
                        )
                        if terminal_predecessor is not None:
                            selected_route_source_serial = terminal_predecessor
                    routes.add(
                        MaterializedStateRoute(
                            source_block_serial=selected_route_source_serial,
                            state_constant=state_constant,
                            target_handler_serial=(
                                int(terminal_route_target_serial)
                                if terminal_route_target_serial is not None
                                else int(target_serial)
                            ),
                            source_handler_serial=int(source_serial),
                            handler_exit_proven=bool(replay_exit_proven),
                            proof_kind=(
                                "terminal_state_route"
                                if terminal_route
                                else "state_route"
                            ),
                            source_native_ea=(
                                source_entry_ea if terminal_route else None
                            ),
                            target_native_ea=(
                                terminal_target_ea if terminal_route else None
                            ),
                        )
                    )
    stop_serials = {
        int(serial)
        for serial, block in flow_graph.blocks.items()
        if block.kind is BlockKind.STOP and block.nsucc == 0
    }
    if len(stop_serials) == 1:
        terminal_stop_serial = next(iter(stop_serials))
        for transfer in transfers:
            if (
                transfer.resolver_kind != "static_handler_exit_route"
                or transfer.selector_state_var_reg is None
                or int(transfer.selector_state_var_reg) != int(state_var_reg)
                or transfer.selector_state_constant is None
                or len(transfer.target_eas) != 1
            ):
                continue
            state_constant = int(transfer.selector_state_constant) & _MASK32
            target_native_ea = int(transfer.target_eas[0])
            try:
                if not terminal_target_resolver(target_native_ea):
                    continue
            except Exception:
                continue
            receipt_sources: set[int] = set()
            for applied in applied_direct_boundary_evidence:
                port = getattr(applied, "port", None)
                if (
                    port is None
                    or str(getattr(port, "delivery_mode", "")) != "terminal_goto"
                    or int(getattr(port, "source_block_ea", 0) or 0)
                    != int(transfer.source_block_ea)
                    or int(getattr(port, "endpoint_block_ea", 0) or 0)
                    != int(transfer.source_block_ea)
                    or int(getattr(port, "target_ea", 0) or 0) != target_native_ea
                    or (
                        getattr(port, "state_register", None) is not None
                        and int(port.state_register) != int(state_var_reg)
                    )
                    or (
                        getattr(port, "state_constant", None) is not None
                        and (int(port.state_constant) & _MASK32) != state_constant
                    )
                ):
                    continue
                endpoint_anchors = {
                    int(ea)
                    for ea in getattr(applied, "endpoint_anchor_eas", ())
                    if int(ea) > 0
                }
                if not endpoint_anchors:
                    continue
                receipt_sources.update(
                    int(block.serial)
                    for block in flow_graph.blocks.values()
                    if any(
                        int(instruction.ea) in endpoint_anchors
                        for instruction in block.insn_snapshots
                    )
                )
            if len(receipt_sources) != 1:
                continue
            source_serial = next(iter(receipt_sources))
            source_block = flow_graph.get_block(source_serial)
            if source_block is None or source_block.nsucc != 1:
                continue
            routes.add(
                MaterializedStateRoute(
                    source_block_serial=source_serial,
                    state_constant=state_constant,
                    target_handler_serial=terminal_stop_serial,
                    source_handler_serial=source_serial,
                    handler_exit_proven=True,
                    proof_kind="terminal_state_route",
                    source_native_ea=int(transfer.source_block_ea),
                    target_native_ea=target_native_ea,
                )
            )

    canonical_routes: set[MaterializedStateRoute] = set()
    exact_handlers: dict[int, int | None] = {}
    for route in routes:
        state_constant = int(route.state_constant) & _MASK32
        if state_constant not in exact_handlers:
            exact_native_route = _exact_equality_native_route(
                transfers,
                state_constant,
            )
            exact_serial = (
                find_unique_target_entry_block(flow_graph, *exact_native_route)
                if exact_native_route is not None
                else None
            )
            exact_handlers[state_constant] = (
                int(exact_serial)
                if exact_serial is not None
                and int(exact_serial) not in dispatcher_block_serials
                else None
            )
        exact_handler = exact_handlers[state_constant]
        if int(route.target_handler_serial) in trusted_handler_override_serials:
            exact_handler = int(route.target_handler_serial)
        if (
            exact_handler is not None
            and int(route.target_handler_serial) not in dispatcher_block_serials
            and int(route.target_handler_serial) != int(exact_handler)
        ):
            exact_handler = None
        canonical_routes.add(
            replace(route, target_handler_serial=exact_handler)
            if exact_handler is not None
            else route
        )
    return tuple(
        sorted(
            canonical_routes,
            key=lambda route: (
                int(route.source_block_serial),
                int(route.state_constant),
                int(route.target_handler_serial),
            ),
        )
    )


def _build_conditional_handler_state_routes(
    flow_graph: FlowGraph,
    transfers: tuple[MaterializedIndirectTransfer, ...],
    *,
    exact_handler_by_state: Mapping[int, int] | None = None,
    target_serial_resolver: Callable[[int], int | None] | None = None,
    arm_source_serial_resolver: (
        Callable[[MaterializedIndirectTransfer], tuple[int, int] | None] | None
    ) = None,
) -> tuple[MaterializedStateRoute, ...]:
    """Bind exact live-predicate states to current handler block serials."""
    exact_handlers = {
        int(state) & _MASK32: int(serial)
        for state, serial in (exact_handler_by_state or {}).items()
        if flow_graph.get_block(int(serial)) is not None
    }
    routes: set[MaterializedStateRoute] = set()
    for transfer in transfers:
        if (
            not is_conditional_handler_bridge_kind(transfer.resolver_kind)
            or transfer.predicate_true_state is None
            or transfer.predicate_false_state is None
            or transfer.true_target_ea is None
            or transfer.false_target_ea is None
        ):
            continue
        arm_source_serials = None
        if arm_source_serial_resolver is not None:
            try:
                arm_source_serials = arm_source_serial_resolver(transfer)
            except Exception:
                arm_source_serials = None
        if arm_source_serials is None:
            source_matches = tuple(
                int(block.serial)
                for block in flow_graph.blocks.values()
                if any(
                    int(instruction.ea) == int(transfer.source_jmp_ea)
                    for instruction in block.insn_snapshots
                )
            )
            if len(source_matches) != 1:
                anchored_matches: list[int] = []
                conditional_matches: list[int] = []
                for serial in source_matches:
                    block = flow_graph.get_block(int(serial))
                    if block is None:
                        continue
                    if int(block.start_ea) == int(transfer.source_block_ea):
                        anchored_matches.append(int(serial))
                    if (
                        block.preds
                        and block.insn_snapshots
                        and block.insn_snapshots[-1].is_conditional_jump
                        and int(block.insn_snapshots[-1].ea)
                        == int(transfer.source_jmp_ea)
                    ):
                        conditional_matches.append(int(serial))
                source_matches = (
                    tuple(anchored_matches)
                    if len(anchored_matches) == 1
                    else tuple(conditional_matches)
                )
            if len(source_matches) != 1:
                continue
            source_serials = (int(source_matches[0]), int(source_matches[0]))
        else:
            source_serials = tuple(int(serial) for serial in arm_source_serials)
            if any(
                flow_graph.get_block(int(serial)) is None for serial in source_serials
            ):
                continue
        for source_serial, state_constant, target_ea in (
            (
                source_serials[0],
                int(transfer.predicate_true_state),
                int(transfer.true_target_ea),
            ),
            (
                source_serials[1],
                int(transfer.predicate_false_state),
                int(transfer.false_target_ea),
            ),
        ):
            target_serial = None
            target_serial = exact_handlers.get(int(state_constant) & _MASK32)
            if target_serial_resolver is not None:
                if target_serial is None:
                    try:
                        target_serial = target_serial_resolver(target_ea)
                    except Exception:
                        target_serial = None
            if target_serial is None:
                target_serial = find_unique_target_entry_block(
                    flow_graph,
                    target_ea,
                )
            if (
                target_serial is None
                or flow_graph.get_block(int(target_serial)) is None
            ):
                continue
            routes.add(
                MaterializedStateRoute(
                    source_block_serial=source_serial,
                    state_constant=int(state_constant) & _MASK32,
                    target_handler_serial=int(target_serial),
                    proof_kind="conditional_arm",
                )
            )
    return tuple(
        sorted(
            routes,
            key=lambda route: (
                int(route.source_block_serial),
                int(route.state_constant),
                int(route.target_handler_serial),
            ),
        )
    )


def _residual_context_mregs(
    values: tuple[tuple[str, int], ...],
) -> dict[int, int]:
    """Convert static architectural-register evidence to Hex-Rays mreg ids."""
    import ida_hexrays  # type: ignore[import-untyped]
    import ida_idp  # type: ignore[import-untyped]

    result: dict[int, int] = {}
    for name, value in values:
        try:
            reg = int(ida_idp.str2reg(str(name)))
            if reg >= 0:
                result[int(ida_hexrays.reg2mreg(reg))] = int(value)
        except Exception:
            continue
    return result


def _dispatcher_replay_context_mregs(
    resolution: ComputedGotoResolution,
) -> dict[int, int] | None:
    """Combine whole-function and dispatcher-site context without conflicts."""
    values_by_name = dict(resolution.function_context_register_values)
    for register, value in resolution.dispatcher_context_register_values:
        previous = values_by_name.get(str(register))
        if previous is not None and int(previous) != int(value):
            return None
        values_by_name[str(register)] = int(value)
    return _residual_context_mregs(tuple(sorted(values_by_name.items())))


def _native_selector_block_entry(cmp_ea: int, text_start: int) -> int:
    """Find the contiguous selector initializer immediately before ``cmp``."""
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    candidates: list[int] = []
    insn = ida_ua.insn_t()
    lower = max(int(text_start), int(cmp_ea) - 15)
    for candidate_ea in range(lower, int(cmp_ea)):
        size = ida_ua.decode_insn(insn, int(candidate_ea))
        if size <= 0 or int(candidate_ea) + int(size) != int(cmp_ea):
            continue
        if (idaapi.print_insn_mnem(int(candidate_ea)) or "") in {
            "lea",
            "mov",
        } and insn.ops[0].type == idaapi.o_reg:
            candidates.append(int(candidate_ea))
    if candidates:
        return max(candidates)
    return _block_start_of(int(cmp_ea), int(text_start))


def _equality_setcc_condition_code(mnemonic: str) -> int | None:
    """Map x86 equality ``setcc`` aliases to Hex-Rays condition codes."""
    normalized = str(mnemonic).lower()
    if normalized in {"sete", "setz"}:
        return 4
    if normalized in {"setne", "setnz"}:
        return 5
    return None


def _native_equality_selector_is_materializable(selector_kind: str) -> bool:
    """Only native jcc leaves are safe for condition-preserving byte delivery."""
    return str(selector_kind) == "jcc"


def _static_equality_route_candidate(
    row: _NativeEqualityRow,
    plan: _PatchPlan | None,
    *,
    state_var_reg: int,
    context_mregs: dict[int, int],
    replay_match_target_ea: int | None = None,
    replay_nonmatch_target_ea: int | None = None,
    match_target_register_values: tuple[tuple[str, int], ...] = (),
) -> MaterializedIndirectTransfer | None:
    """Preserve a native setcc route until CALLS can validate its handler.

    The candidate is ownership and provenance evidence, not a logical edge.
    It becomes a ``static_equality_route`` only after the selected target EA
    maps to exactly one block in the live microcode CFG.  A detached setcc
    selector can be absent from the resolver's reachable patch plans; in that
    case, exact two-arm replay is sufficient only when the matching arm is the
    selector's immediate post-terminal handler and the other arm is distinct.
    """
    if row.selector_kind != "setcc":
        return None
    dispatcher_entry_ea = None
    if plan is None:
        if replay_match_target_ea is None or replay_nonmatch_target_ea is None:
            return None
        replay_match = int(replay_match_target_ea)
        replay_nonmatch = int(replay_nonmatch_target_ea)
        if replay_match != int(row.terminal_end_ea) or replay_match == replay_nonmatch:
            return None
        selected_target_ea = replay_match
        dispatcher_entry_ea = replay_nonmatch
    else:
        if int(plan.jmp_ea) != int(row.terminal_jmp_ea):
            return None
        if int(plan.block_entry) != int(row.block_entry_ea):
            return None
        if len(plan.target_eas) != 1:
            return None
        selected_target_ea = int(plan.target_eas[0])
    if replay_match_target_ea is not None or replay_nonmatch_target_ea is not None:
        if replay_match_target_ea is None or replay_nonmatch_target_ea is None:
            return None
        replay_match = int(replay_match_target_ea)
        replay_nonmatch = int(replay_nonmatch_target_ea)
        if replay_match == replay_nonmatch:
            return None
        if selected_target_ea == replay_match:
            pass
        elif selected_target_ea == replay_nonmatch and replay_match == int(
            row.terminal_end_ea
        ):
            selected_target_ea = replay_match
        else:
            return None
        if selected_target_ea == replay_match and replay_match == int(
            row.terminal_end_ea
        ):
            dispatcher_entry_ea = replay_nonmatch
    return MaterializedIndirectTransfer(
        source_jmp_ea=int(row.terminal_jmp_ea),
        source_block_ea=int(row.block_entry_ea),
        materialized_anchor_eas=(),
        target_eas=(selected_target_ea,),
        selector_state_constant=int(row.state_constant) & _MASK32,
        selector_state_var_reg=int(state_var_reg),
        context_register_values=tuple(sorted(context_mregs.items())),
        source_register_values=tuple(
            sorted(_residual_context_mregs(match_target_register_values).items())
        ),
        target_register_values=tuple(
            sorted(_residual_context_mregs(match_target_register_values).items())
        ),
        resolver_kind="static_equality_candidate",
        materialized_region_end_ea=int(row.terminal_end_ea),
        dispatcher_entry_ea=dispatcher_entry_ea,
    )


def _static_equality_candidate_target(
    transfer: MaterializedIndirectTransfer,
    state_var_reg: int,
    *,
    live_target_block: int,
    dispatcher_blocks: frozenset[int],
    dispatch_anchor_eas: frozenset[int],
    dispatcher_fallback_eas: frozenset[int],
) -> tuple[int, int] | None:
    """Return a candidate only when its live target is outside the router."""
    if transfer.resolver_kind != "static_equality_candidate":
        return None
    if transfer.selector_state_var_reg != int(state_var_reg):
        return None
    if transfer.selector_state_constant is None or len(transfer.target_eas) != 1:
        return None
    if int(live_target_block) in dispatcher_blocks:
        return None
    if int(transfer.target_eas[0]) in dispatch_anchor_eas:
        return None
    if int(transfer.target_eas[0]) in dispatcher_fallback_eas:
        return None
    return (
        int(transfer.selector_state_constant) & _MASK32,
        int(transfer.target_eas[0]),
    )


def _static_equality_dispatcher_fallback_eas(
    transfers: tuple[MaterializedIndirectTransfer, ...],
) -> frozenset[int]:
    """Native nonmatching arms of materialized exact-equality leaves."""
    fallbacks: set[int] = set()
    for transfer in transfers:
        if transfer.resolver_kind != "static_equality_fixpoint":
            continue
        if transfer.condition_code == 4:
            fallback = transfer.false_target_ea
        elif transfer.condition_code == 5:
            fallback = transfer.true_target_ea
        else:
            continue
        if fallback is not None:
            fallbacks.add(int(fallback))
    return frozenset(fallbacks)


def _next_transfer_target_ea(
    transfers: tuple[MaterializedIndirectTransfer, ...],
    target_ea: int,
) -> int | None:
    """Return the nearest greater resolver target as a strict label bound."""
    target = int(target_ea)
    later = {
        int(candidate)
        for transfer in transfers
        for candidate in transfer.target_eas
        if int(candidate) > target
    }
    return min(later) if later else None


def _setcc_equality_delivery_targets(
    row: _NativeEqualityRow,
    *,
    match_target_ea: int,
    nonmatch_target_ea: int,
    proven_match_target_ea: int,
    dispatcher_fallback_eas: frozenset[int],
) -> tuple[int, int] | None:
    """Return predicate-ordered targets for one safe setcc materialization."""
    match_target = int(match_target_ea)
    nonmatch_target = int(nonmatch_target_ea)
    if match_target != int(proven_match_target_ea):
        return None
    if row.selector_kind != "setcc" or match_target == nonmatch_target:
        return None
    if match_target in dispatcher_fallback_eas:
        return None
    if nonmatch_target not in dispatcher_fallback_eas:
        return None
    if row.condition_code == 4:
        return (match_target, nonmatch_target)
    if row.condition_code == 5:
        return (nonmatch_target, match_target)
    return None


def _native_equality_state_rows(
    function_ea: int,
    *,
    envelope_end_ea: int | None = None,
) -> tuple[_NativeEqualityRow, ...]:
    """Extract native ``cmp reg, K`` equality-leaf targets from function tails.

    The rows are evidence only.  A later microcode recovery supplies the actual
    state-register identity and the exact dispatcher-bound write sites.
    """
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]
    import idautils  # type: ignore[import-untyped]
    import ida_bytes  # type: ignore[import-untyped]
    import ida_funcs  # type: ignore[import-untyped]

    rows: set[_NativeEqualityRow] = set()
    func = ida_funcs.get_func(int(function_ea))
    default_end = int(func.end_ea) if func is not None else int(function_ea) + 1
    end_ea = max(default_end, int(envelope_end_ea or default_end))
    text = _text_segment(int(function_ea))
    text_start = int(text[0]) if text is not None else int(function_ea)
    for ea in idautils.Heads(int(function_ea), end_ea):
        if not ida_bytes.is_code(ida_bytes.get_flags(int(ea))):
            continue
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, int(ea))
        if (
            size <= 0
            or idaapi.print_insn_mnem(int(ea)) != "cmp"
            or insn.ops[0].type != idaapi.o_reg
            or insn.ops[1].type != idaapi.o_imm
        ):
            continue
        register_name = _sv_reg_name(insn.ops[0])
        if register_name is None:
            continue
        cursor = int(ea) + int(size)
        branch = None
        for _ in range(8):
            candidate = ida_ua.insn_t()
            candidate_size = ida_ua.decode_insn(candidate, cursor)
            if candidate_size <= 0:
                break
            mnemonic = idaapi.print_insn_mnem(cursor)
            if (
                mnemonic in _SV_JCC_MNEMS
                or mnemonic == "jmp"
                or _equality_setcc_condition_code(mnemonic) is not None
            ):
                branch = (cursor, candidate, candidate_size, mnemonic)
                break
            cursor += int(candidate_size)
        if branch is None:
            continue
        branch_ea, branch_insn, branch_size, mnemonic = branch
        setcc_condition_code = _equality_setcc_condition_code(mnemonic)
        if setcc_condition_code is not None:
            terminal_jmp_ea = _native_first_register_indirect_jump(int(branch_ea))
            if terminal_jmp_ea is None:
                continue
            terminal = ida_ua.insn_t()
            terminal_size = ida_ua.decode_insn(terminal, int(terminal_jmp_ea))
            if terminal_size <= 0:
                continue
            rows.add(
                _NativeEqualityRow(
                    str(register_name),
                    int(insn.ops[1].value) & _MASK32,
                    int(branch_ea),
                    _native_selector_block_entry(int(ea), text_start),
                    int(branch_ea),
                    int(branch_size),
                    int(setcc_condition_code),
                    int(terminal_jmp_ea),
                    int(terminal_jmp_ea) + int(terminal_size),
                    "setcc",
                )
            )
            continue
        target_ea = None
        if mnemonic in {"jz", "je"} and branch_insn.ops[0].type in {
            idaapi.o_near,
            idaapi.o_far,
        }:
            target_ea = int(branch_insn.ops[0].addr)
        elif mnemonic in {"jnz", "jne"}:
            following_ea = int(branch_ea) + int(branch_size)
            following = ida_ua.insn_t()
            following_size = ida_ua.decode_insn(following, following_ea)
            if (
                following_size > 0
                and idaapi.print_insn_mnem(following_ea) == "jmp"
                and following.ops[0].type in {idaapi.o_near, idaapi.o_far}
            ):
                target_ea = int(following.ops[0].addr)
        if target_ea is not None:
            condition_code = 4 if mnemonic in {"jz", "je"} else 5
            terminal_jmp_ea = _native_first_register_indirect_jump(int(target_ea))
            if terminal_jmp_ea is None:
                continue
            terminal = ida_ua.insn_t()
            terminal_size = ida_ua.decode_insn(terminal, int(terminal_jmp_ea))
            if terminal_size <= 0:
                continue
            rows.add(
                _NativeEqualityRow(
                    str(register_name),
                    int(insn.ops[1].value) & _MASK32,
                    int(target_ea),
                    _native_selector_block_entry(int(ea), text_start),
                    int(branch_ea),
                    int(branch_size),
                    int(condition_code),
                    int(terminal_jmp_ea),
                    int(terminal_jmp_ea) + int(terminal_size),
                    "jcc",
                )
            )
    return tuple(sorted(rows))


def _corridor_entry_mregs(
    resolution: ComputedGotoResolution,
    entry_ea: int,
) -> dict[int, int] | None:
    """Combine invariant and exact path-local resolver state at one entry.

    Path-local snapshots override function invariants. Conflicting snapshots
    for the same native entry abstain instead of selecting one by tuple order.
    """
    context_mregs = _dispatcher_replay_context_mregs(resolution)
    if context_mregs is None:
        return None
    snapshots: set[tuple[tuple[str, int], ...]] = set()
    for source_ea, register_values in resolution.corridor_register_snapshots:
        if int(source_ea) != int(entry_ea):
            continue
        snapshots.add(
            tuple(sorted((str(name), int(value)) for name, value in register_values))
        )
    if len(snapshots) > 1:
        return None
    if snapshots:
        context_mregs.update(_residual_context_mregs(next(iter(snapshots))))
    return context_mregs


def _resolve_native_setcc_route_facts(
    resolution: ComputedGotoResolution,
    rows: tuple[_NativeEqualityRow, ...],
    *,
    route_resolver=None,
    match_register_values_by_row: (
        dict[
            _NativeEqualityRow,
            tuple[tuple[str, int], ...],
        ]
        | None
    ) = None,
) -> tuple[tuple[_NativeEqualityRow, int, int], ...]:
    """Replay setcc selectors before any byte patch invalidates their arms."""
    if route_resolver is None:
        route_resolver = _resolve_concrete_dispatch_corridor
    facts: list[tuple[_NativeEqualityRow, int, int]] = []
    for row in rows:
        if row.selector_kind != "setcc":
            continue
        state_var_reg = _native_register_mreg(row.register_name)
        if state_var_reg is None:
            continue
        entry_mregs = _corridor_entry_mregs(resolution, int(row.block_entry_ea))
        if entry_mregs is None:
            continue
        match_mregs = dict(entry_mregs)
        match_mregs[int(state_var_reg)] = int(row.state_constant)
        nonmatch_mregs = dict(entry_mregs)
        nonmatch_mregs[int(state_var_reg)] = int(row.state_constant) ^ 1
        match_result = route_resolver(
            int(row.block_entry_ea),
            initial_mregs=match_mregs,
            handler_eas=frozenset(),
            return_first_indirect_target=True,
            **(
                {"return_first_indirect_result": True}
                if match_register_values_by_row is not None
                else {}
            ),
        )
        nonmatch_result = route_resolver(
            int(row.block_entry_ea),
            initial_mregs=nonmatch_mregs,
            handler_eas=frozenset(),
            return_first_indirect_target=True,
        )
        if match_register_values_by_row is not None:
            if not isinstance(match_result, _ConcreteDispatchResult):
                continue
            match_register_values_by_row[row] = tuple(match_result.register_values)
            match_target = int(match_result.target_ea)
        else:
            match_target = match_result
        nonmatch_target = nonmatch_result
        if (
            match_target is None
            or nonmatch_target is None
            or int(match_target) == int(nonmatch_target)
        ):
            continue
        facts.append((row, int(match_target), int(nonmatch_target)))
    return tuple(facts)


def _native_first_register_indirect_jump(
    start_ea: int,
    *,
    max_instructions: int = 16,
) -> int | None:
    """Return the first straight-line ``jmp reg`` at or after *start_ea*."""
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    insn = ida_ua.insn_t()
    ea = int(start_ea)
    for _ in range(int(max_instructions)):
        size = ida_ua.decode_insn(insn, ea)
        if size <= 0:
            return None
        mnemonic = idaapi.print_insn_mnem(ea) or ""
        if mnemonic == "jmp" and insn.ops[0].type == idaapi.o_reg:
            return ea
        if mnemonic in _SV_JCC_MNEMS or mnemonic in {"ret", "retn", "retf"}:
            return None
        ea += int(size)
    return None


def _equality_fragment_owned_ranges(
    transfers: tuple[MaterializedIndirectTransfer, ...],
    *,
    block_end: Callable[[int], int],
) -> tuple[tuple[int, int], ...]:
    """Ranges the parent must own before IDA analyzes equality fragments."""
    ranges: set[tuple[int, int]] = set()
    for transfer in transfers:
        region_end = transfer.materialized_region_end_ea
        if region_end is not None and int(region_end) > int(transfer.source_block_ea):
            ranges.add((int(transfer.source_block_ea), int(region_end)))
        for target_ea in transfer.target_eas:
            end_ea = int(block_end(int(target_ea)))
            if end_ea > int(target_ea):
                ranges.add((int(target_ea), end_ea))
    return tuple(sorted(ranges))


def _claim_exact_function_tail_range(
    parent_function: object,
    start_ea: int,
    end_ea: int,
    *,
    get_function: Callable[[int], object | None],
    append_function_tail: Callable[[object, int, int], bool],
    delete_function: Callable[[int], bool],
) -> bool:
    """Attach an evidence-bounded handler range to its parent function.

    IDA can promote an otherwise detached handler block to a standalone
    function before the computed-goto resolver reconnects it.  Merely checking
    ``get_func(start) is None`` then leaves the proven handler outside the
    parent's next MBA.  First ask IDA to share an existing tail.  If the range
    is instead an exact standalone function, delete only that exact function
    and retry the tail attachment.  Broader or interior ownership is ambiguous
    and must remain untouched.
    """
    start = int(start_ea)
    end = int(end_ea)
    if end <= start:
        return False
    parent_start = int(parent_function.start_ea)
    owner = get_function(start)
    if owner is not None and int(owner.start_ea) == parent_start:
        return True
    if append_function_tail(parent_function, start, end):
        return True
    owner = get_function(start)
    if owner is None:
        return False
    if int(owner.start_ea) != start or int(owner.end_ea) != end:
        return False
    if not delete_function(start):
        return False
    return bool(append_function_tail(parent_function, start, end))


def _equality_transfers_activated_by_targets(
    transfers: tuple[MaterializedIndirectTransfer, ...],
    target_eas: Sequence[int],
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Equality fragments whose roots just became reachable by a residual edge."""
    targets = {int(target_ea) for target_ea in target_eas}
    return tuple(
        transfer
        for transfer in transfers
        if transfer.resolver_kind == "static_equality_fixpoint"
        and int(transfer.source_block_ea) in targets
    )


def _exact_equality_fragment_transfers(
    transfers: tuple[MaterializedIndirectTransfer, ...],
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Materialized equality fragments that must remain parent-owned.

    These transfers have already passed concrete two-arm resolution and were
    byte-materialized as an explicit conditional edge.  Their ownership is
    independent of whether a residual state route happened to activate their
    root in the current redo round; otherwise IDA can drop initial-state or
    loop-break leaves between global-analysis rounds.
    """
    return tuple(
        transfer
        for transfer in transfers
        if transfer.resolver_kind == "static_equality_fixpoint"
    )


def _decode_static_state_route_corridor(
    start_ea: int,
    delivery_ea: int,
    *,
    max_instructions: int = 128,
) -> tuple[_DecodedStateRouteInstruction, ...]:
    """Decode one forward native corridor ending at an indirect delivery."""
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    decoded: list[_DecodedStateRouteInstruction] = []
    cursor = int(start_ea)
    delivery = int(delivery_ea)
    for _ in range(int(max_instructions)):
        if cursor > delivery:
            return ()
        instruction = ida_ua.insn_t()
        size = int(ida_ua.decode_insn(instruction, cursor))
        if size <= 0:
            return ()
        mnemonic = (idaapi.print_insn_mnem(cursor) or "").lower()
        destination_mreg = None
        writes_destination = False
        if instruction.ops[0].type == idaapi.o_reg:
            destination_mreg = _native_register_mreg(_sv_reg_name(instruction.ops[0]))
            writes_destination = _insn_writes_first_operand(
                instruction,
                idaapi.CF_CHG1,
            )
        immediate = (
            int(instruction.ops[1].value)
            if instruction.ops[1].type == idaapi.o_imm
            else None
        )
        decoded.append(
            _DecodedStateRouteInstruction(
                cursor,
                cursor + size,
                mnemonic,
                destination_mreg,
                writes_destination,
                immediate,
            )
        )
        if cursor == delivery:
            return tuple(decoded)
        if mnemonic in {"jmp", "ret", "retn", "retf"}:
            return ()
        cursor += size
    return ()


def _frontend_normalized_state_route_delivery_site(
    plan: ComputedGotoPatchPlan,
) -> _NativeStateRouteDeliverySite:
    """Project one validated normalization plan to its semantic delivery root.

    A direct normalization keeps the original indirect-transfer EA as its
    source anchor.  A complete conditional normalization introduces a
    predicate earlier in the owned patch region; later state-route lowering
    must supersede that predicate root rather than the now-unreachable indirect
    tail.  The plan itself is portable proof of this intermediate shape, so no
    native byte mutation is required.
    """
    target_eas = tuple(int(target_ea) for target_ea in plan.target_eas)
    delivery_ea = int(plan.jmp_ea)
    if (
        len(target_eas) == 2
        and plan.condition_code is not None
        and plan.true_target_ea is not None
        and plan.false_target_ea is not None
        and plan.condition_producer_ea is not None
        and len(plan.insn_heads) >= 2
        and len(plan.new_block_eas) >= 2
        and int(plan.true_target_ea) != int(plan.false_target_ea)
        and {int(plan.true_target_ea), int(plan.false_target_ea)} == set(target_eas)
        and int(plan.new_block_eas[0]) == int(plan.insn_heads[-2])
        and int(plan.block_entry)
        <= int(plan.condition_producer_ea)
        < int(plan.patch_start)
    ):
        delivery_ea = int(plan.new_block_eas[0])
    return _NativeStateRouteDeliverySite(
        int(plan.block_entry),
        delivery_ea,
        int(plan.patch_start),
        int(plan.region_end),
    )


def _select_frontend_normalized_state_write_assignment(
    decoded: Sequence[_DecodedStateRouteInstruction],
    *,
    state_var_reg: int,
    delivery_ea: int,
) -> tuple[int, int, tuple[int, ...]] | None:
    """Consume the semantic branch root proved by frontend normalization."""
    ordered = tuple(decoded)
    if not ordered or int(ordered[-1].ea) != int(delivery_ea):
        return None
    terminal = ordered[-1]
    normalized = (
        *ordered[:-1],
        _DecodedStateRouteInstruction(
            int(terminal.ea),
            int(terminal.end_ea),
            "jmp",
            None,
            False,
            None,
        ),
    )
    return _select_static_state_write_assignment(
        normalized,
        state_var_reg=int(state_var_reg),
        delivery_ea=int(delivery_ea),
    )


def _select_handler_exit_backed_frontend_state_write_assignment(
    decoded: Sequence[_DecodedStateRouteInstruction],
    *,
    state_var_reg: int,
    delivery_ea: int,
) -> tuple[int, int, tuple[int, ...], tuple[int, ...]] | None:
    """Select a normalized state route whose intervening calls are proven.

    The caller must separately bind an exact ``static_handler_exit_route`` at
    the original indirect transfer.  Neutralizing calls only for the pure
    selector lets the existing straight-corridor checks prove every other
    instruction while returning the exact call heads that require that exit
    authority.
    """
    ordered = tuple(decoded)
    call_instruction_eas = tuple(
        int(instruction.ea)
        for instruction in ordered
        if str(instruction.mnemonic).lower() == "call"
    )
    if not call_instruction_eas:
        return None
    call_neutralized = tuple(
        _DecodedStateRouteInstruction(
            int(instruction.ea),
            int(instruction.end_ea),
            (
                "nop"
                if str(instruction.mnemonic).lower() == "call"
                else str(instruction.mnemonic)
            ),
            instruction.destination_mreg,
            bool(instruction.writes_destination),
            instruction.immediate,
        )
        for instruction in ordered
    )
    selected = _select_frontend_normalized_state_write_assignment(
        call_neutralized,
        state_var_reg=int(state_var_reg),
        delivery_ea=int(delivery_ea),
    )
    if selected is None:
        return None
    corridor_instruction_eas = tuple(int(ea) for ea in selected[2])
    corridor_heads = frozenset(corridor_instruction_eas)
    preserved_call_instruction_eas = tuple(
        ea for ea in call_instruction_eas if ea in corridor_heads
    )
    if not preserved_call_instruction_eas:
        return None
    return (
        int(selected[0]),
        int(selected[1]),
        corridor_instruction_eas,
        preserved_call_instruction_eas,
    )


def _exact_handler_exit_authority_for_normalization(
    plan: ComputedGotoPatchPlan,
    transfers: Sequence[MaterializedIndirectTransfer],
    *,
    state_var_reg: int,
    state_targets: Mapping[int, int],
) -> MaterializedIndirectTransfer | None:
    """Bind one normalized transfer to one exact post-call state proof."""
    plan_targets = frozenset(int(target_ea) for target_ea in plan.target_eas)
    candidates = tuple(
        transfer
        for transfer in transfers
        if transfer.resolver_kind == "static_handler_exit_route"
        and int(transfer.source_jmp_ea) == int(plan.jmp_ea)
        and int(transfer.source_block_ea) == int(plan.block_entry)
        and transfer.selector_state_var_reg is not None
        and int(transfer.selector_state_var_reg) == int(state_var_reg)
        and transfer.selector_state_constant is not None
        and len(transfer.target_eas) == 1
        and frozenset(
            int(target_ea) for target_ea in transfer.dispatcher_envelope_target_eas
        )
        == plan_targets
    )
    if len(candidates) != 1:
        return None
    authority = candidates[0]
    state_constant = int(authority.selector_state_constant) & _MASK32
    state_values = {
        int(value) & _MASK32
        for register, value in authority.source_register_values
        if int(register) == int(state_var_reg)
    }
    target_ea = int(authority.target_eas[0])
    if (
        state_values != {state_constant}
        or state_targets.get(state_constant) != target_ea
    ):
        return None
    return authority


def _decode_native_flow_route_inventory(
    function_ea: int,
    envelope_end_ea: int,
) -> tuple[_DecodedNativeFlowInstruction, ...]:
    """Decode the ordered native facts used by the per-site flow-route scan."""
    import ida_bytes  # type: ignore[import-untyped]
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]
    import idautils  # type: ignore[import-untyped]

    decoded: list[_DecodedNativeFlowInstruction] = []
    for ea in idautils.Heads(int(function_ea), int(envelope_end_ea)):
        instruction_ea = int(ea)
        if not ida_bytes.is_code(ida_bytes.get_flags(instruction_ea)):
            continue
        instruction = ida_ua.insn_t()
        size = int(ida_ua.decode_insn(instruction, instruction_ea))
        if size <= 0:
            continue
        mnemonic = (idaapi.print_insn_mnem(instruction_ea) or "").lower()
        destination_mreg = (
            _native_register_mreg(_sv_reg_name(instruction.ops[0]))
            if instruction.ops[0].type == idaapi.o_reg
            else None
        )
        direct_target_ea = (
            int(instruction.ops[0].addr)
            if (mnemonic == "jmp" or mnemonic in _SV_JCC_MNEMS)
            and instruction.ops[0].type in {idaapi.o_near, idaapi.o_far}
            else None
        )
        decoded.append(
            _DecodedNativeFlowInstruction(
                instruction_ea,
                instruction_ea + size,
                mnemonic,
                destination_mreg,
                instruction.ops[0].type == idaapi.o_reg
                and _insn_writes_first_operand(instruction, idaapi.CF_CHG1),
                (
                    int(instruction.ops[1].value)
                    if instruction.ops[1].type == idaapi.o_imm
                    else None
                ),
                direct_target_ea,
            )
        )
    return tuple(decoded)


def _native_direct_dispatch_delivery_sites(
    function_ea: int,
    envelope_end_ea: int,
    *,
    dispatcher_router_eas: frozenset[int],
    excluded_delivery_eas: frozenset[int] = frozenset(),
) -> tuple[_NativeStateRouteDeliverySite, ...]:
    """Find direct native jumps that deliver a state to a proven dispatcher."""
    import ida_bytes  # type: ignore[import-untyped]
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]
    import idautils  # type: ignore[import-untyped]

    if not dispatcher_router_eas:
        return ()
    sites: set[_NativeStateRouteDeliverySite] = set()
    for ea in idautils.Heads(int(function_ea), int(envelope_end_ea)):
        delivery_ea = int(ea)
        if delivery_ea in excluded_delivery_eas or not ida_bytes.is_code(
            ida_bytes.get_flags(delivery_ea)
        ):
            continue
        instruction = ida_ua.insn_t()
        size = int(ida_ua.decode_insn(instruction, delivery_ea))
        if (
            size <= 0
            or (idaapi.print_insn_mnem(delivery_ea) or "").lower() != "jmp"
            or instruction.ops[0].type not in {idaapi.o_near, idaapi.o_far}
            or int(instruction.ops[0].addr) not in dispatcher_router_eas
        ):
            continue
        sites.add(
            _NativeStateRouteDeliverySite(
                _block_start_of(delivery_ea, int(function_ea)),
                delivery_ea,
                delivery_ea,
                delivery_ea + size,
            )
        )
    return tuple(sorted(sites))


def _discover_static_state_write_routes(
    state: ResolverSessionState,
    resolution: ComputedGotoResolution,
    transfers: Sequence[MaterializedIndirectTransfer],
) -> tuple[PortableStateWriteRouteEvidence, ...]:
    """Publish direct reference-style state routes before top-level PREOPT."""
    state_registers = {
        int(route.selector_state_var_reg)
        for route in transfers
        if route.resolver_kind == "static_handler_entry_route"
        and route.selector_state_var_reg is not None
    }
    if len(state_registers) != 1:
        return ()
    state_var_reg = next(iter(state_registers))
    state_targets = _unique_static_equality_handler_targets(
        transfers,
        int(state_var_reg),
    )
    if not state_targets:
        logger.info(
            "static state-write route discovery abstained: func=0x%X "
            "reason=no_state_targets state_register=%d",
            int(resolution.function_ea),
            int(state_var_reg),
        )
        return ()
    decoded_count = 0
    assignment_count = 0
    mapped_count = 0
    delivery_region_count = 0
    candidates: dict[
        tuple[int, int, int, int], set[PortableStateWriteRouteEvidence]
    ] = {}
    patch_delivery_sites = tuple(
        (
            _frontend_normalized_state_route_delivery_site(plan),
            plan,
        )
        for plan in resolution.patch_plans
    )
    dispatcher_router_eas = frozenset(
        int(router_ea)
        for transfer in transfers
        for router_ea in transfer.dispatcher_router_eas
    )
    envelope_end_ea = (
        max(
            (
                int(ea)
                for ea in (
                    *resolution.reachable_eas,
                    *resolution.block_entries,
                    *(
                        site.delivery_region_end_ea
                        for site, _plan in patch_delivery_sites
                    ),
                    *(router_ea for router_ea in dispatcher_router_eas),
                    *(
                        end_ea
                        for transfer in transfers
                        for _start_ea, end_ea in transfer.owned_native_ranges
                    ),
                )
            ),
            default=int(resolution.function_ea),
        )
        + 1
    )
    direct_delivery_sites = _native_direct_dispatch_delivery_sites(
        int(resolution.function_ea),
        int(envelope_end_ea),
        dispatcher_router_eas=dispatcher_router_eas,
        excluded_delivery_eas=frozenset(
            int(site.delivery_ea) for site, _plan in patch_delivery_sites
        ),
    )
    immediate_routes = _discover_immediate_native_state_routes(
        _decode_native_flow_route_inventory(
            int(resolution.function_ea),
            int(envelope_end_ea),
        ),
        state_var_reg=int(state_var_reg),
        state_targets=state_targets,
    )
    immediate_assignment_keys: set[tuple[int, int, int]] = set()
    for route in immediate_routes:
        evidence = PortableStateWriteRouteEvidence(
            write_identity=StableBlockIdentity.from_intervals(
                (
                    NativeEaInterval(
                        int(route.source_write_ea),
                        int(route.source_write_ea) + 1,
                    ),
                ),
                native_key=state.native_key,
            ),
            delivery_identity=StableBlockIdentity.from_intervals(
                (
                    NativeEaInterval(
                        int(route.delivery_ea),
                        int(route.delivery_ea) + 1,
                    ),
                ),
                native_key=state.native_key,
            ),
            source_write_ea=int(route.source_write_ea),
            delivery_ea=int(route.delivery_ea),
            delivery_region_start_ea=int(route.delivery_ea),
            delivery_region_end_ea=int(route.delivery_end_ea),
            corridor_instruction_eas=tuple(route.corridor_instruction_eas),
            state_var_reg=int(state_var_reg),
            state_constant=int(route.state_constant),
            target_identity=StableBlockIdentity.from_intervals(
                (NativeEaInterval(int(route.target_ea), int(route.target_ea) + 1),),
                native_key=state.native_key,
            ),
            target_ea=int(route.target_ea),
            authority_transfer_ea=None,
            preserved_call_instruction_eas=(),
            proof_kind=StateWriteRouteProofKind.STATE_ASSIGNMENT,
            delivery_kind=StateWriteRouteDeliveryKind.DIRECT_TARGET,
        )
        semantic_key = (
            int(route.source_write_ea),
            int(route.delivery_ea),
            int(route.state_constant),
            int(state_var_reg),
        )
        immediate_assignment_keys.add(
            (
                int(route.source_write_ea),
                int(route.state_constant) & _MASK32,
                int(state_var_reg),
            )
        )
        candidates.setdefault(semantic_key, set()).add(evidence)
    delivery_sites = (
        *patch_delivery_sites,
        *((site, None) for site in direct_delivery_sites),
    )
    for site, normalization_plan in delivery_sites:
        authority_transfer_ea: int | None = None
        preserved_call_instruction_eas: tuple[int, ...] = ()
        decoded = _decode_static_state_route_corridor(
            int(site.block_entry_ea),
            int(site.delivery_ea),
        )
        decoded_count += bool(decoded)
        selected = (
            _select_static_state_write_assignment(
                decoded,
                state_var_reg=int(state_var_reg),
                delivery_ea=int(site.delivery_ea),
            )
            if normalization_plan is None
            or int(site.delivery_ea) == int(normalization_plan.jmp_ea)
            else _select_frontend_normalized_state_write_assignment(
                decoded,
                state_var_reg=int(state_var_reg),
                delivery_ea=int(site.delivery_ea),
            )
        )
        if (
            selected is None
            and normalization_plan is not None
            and int(site.delivery_ea) != int(normalization_plan.jmp_ea)
        ):
            exit_authority = _exact_handler_exit_authority_for_normalization(
                normalization_plan,
                transfers,
                state_var_reg=int(state_var_reg),
                state_targets=state_targets,
            )
            if exit_authority is not None:
                backed = _select_handler_exit_backed_frontend_state_write_assignment(
                    decoded,
                    state_var_reg=int(state_var_reg),
                    delivery_ea=int(site.delivery_ea),
                )
                if (
                    backed is not None
                    and (int(backed[1]) & _MASK32)
                    == (int(exit_authority.selector_state_constant) & _MASK32)
                    and state_targets.get(int(backed[1]) & _MASK32)
                    == int(exit_authority.target_eas[0])
                ):
                    selected = (int(backed[0]), int(backed[1]), tuple(backed[2]))
                    authority_transfer_ea = int(exit_authority.source_jmp_ea)
                    preserved_call_instruction_eas = tuple(backed[3])
        if selected is None:
            continue
        assignment_count += 1
        write_ea, state_constant, corridor_instruction_eas = selected
        target_ea = state_targets.get(int(state_constant))
        if target_ea is None:
            continue
        mapped_count += 1
        delivery_region_start_ea = int(site.delivery_region_start_ea)
        delivery_region_end_ea = int(site.delivery_region_end_ea)
        delivery_ea = int(site.delivery_ea)
        if not int(delivery_region_start_ea) <= delivery_ea < delivery_region_end_ea:
            continue
        delivery_region_count += 1
        target_ea = int(target_ea)
        evidence = PortableStateWriteRouteEvidence(
            write_identity=StableBlockIdentity.from_intervals(
                (NativeEaInterval(int(write_ea), int(write_ea) + 1),),
                native_key=state.native_key,
            ),
            delivery_identity=StableBlockIdentity.from_intervals(
                (NativeEaInterval(int(delivery_ea), int(delivery_ea) + 1),),
                native_key=state.native_key,
            ),
            source_write_ea=int(write_ea),
            delivery_ea=int(delivery_ea),
            delivery_region_start_ea=int(delivery_region_start_ea),
            delivery_region_end_ea=int(delivery_region_end_ea),
            corridor_instruction_eas=tuple(corridor_instruction_eas),
            state_var_reg=int(state_var_reg),
            state_constant=int(state_constant),
            target_identity=StableBlockIdentity.from_intervals(
                (NativeEaInterval(target_ea, target_ea + 1),),
                native_key=state.native_key,
            ),
            target_ea=target_ea,
            authority_transfer_ea=authority_transfer_ea,
            preserved_call_instruction_eas=preserved_call_instruction_eas,
            delivery_kind=(
                StateWriteRouteDeliveryKind.DIRECT_TARGET
                if normalization_plan is not None
                and int(site.delivery_ea) != int(normalization_plan.jmp_ea)
                else StateWriteRouteDeliveryKind.DISPATCHER
            ),
        )
        semantic_key = (
            int(write_ea),
            int(delivery_ea),
            int(state_constant),
            int(state_var_reg),
        )
        if (
            int(write_ea),
            int(state_constant) & _MASK32,
            int(state_var_reg),
        ) in immediate_assignment_keys:
            continue
        candidates.setdefault(semantic_key, set()).add(evidence)

    discovered = tuple(
        sorted(
            (next(iter(proofs)) for proofs in candidates.values() if len(proofs) == 1),
            key=lambda evidence: (
                int(evidence.source_write_ea),
                int(evidence.delivery_ea),
                int(evidence.state_constant),
                int(evidence.target_ea),
            ),
        )
    )
    if discovered:
        state.native_preanalysis.merge_state_write_routes(
            state.native_key,
            discovered,
        )
        logger.info(
            "static state-write routes published: func=0x%X count=%d "
            "immediate_native=%d routes=%s",
            int(resolution.function_ea),
            len(discovered),
            len(immediate_routes),
            [
                (
                    hex(int(evidence.source_write_ea)),
                    hex(int(evidence.delivery_ea)),
                    hex(int(evidence.state_constant)),
                    hex(int(evidence.target_ea)),
                )
                for evidence in discovered
            ],
        )
    else:
        logger.info(
            "static state-write route discovery abstained: func=0x%X "
            "reason=no_direct_routes plans=%d direct_deliveries=%d decoded=%d "
            "immediate_native=%d assignments=%d "
            "mapped=%d delivery_regions=%d state_targets=%d",
            int(resolution.function_ea),
            len(resolution.patch_plans),
            len(direct_delivery_sites),
            decoded_count,
            len(immediate_routes),
            assignment_count,
            mapped_count,
            delivery_region_count,
            len(state_targets),
        )
    return discovered


def _native_residual_fragment_ranges(
    start_ea: int,
    *,
    envelope_start_ea: int,
    envelope_end_ea: int,
    max_blocks: int = 32,
    max_bytes: int = 0x100,
    require_indirect: bool = True,
) -> tuple[tuple[int, int], ...]:
    """Recover the bounded native CFG ending in a register-indirect transfer.

    This helper establishes function ownership only; it is not semantic
    authority.  The next CALLS round must still accept the fragment through
    ``recognize_residual_indirect_transfer`` before any arm is consumed.
    """
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    lower = max(int(envelope_start_ea), int(start_ea) - int(max_bytes))
    upper = min(int(envelope_end_ea), int(start_ea) + int(max_bytes))
    pending = collections.deque([int(start_ea)])
    seen: set[int] = set()
    ranges: list[tuple[int, int]] = []
    saw_indirect = False
    insn = ida_ua.insn_t()
    while pending and len(seen) < int(max_blocks):
        block_start = int(pending.popleft())
        if block_start in seen or not (lower <= block_start < upper):
            continue
        seen.add(block_start)
        ea = block_start
        for _ in range(128):
            size = ida_ua.decode_insn(insn, ea)
            if size <= 0:
                break
            next_ea = int(ea) + int(size)
            mnemonic = idaapi.print_insn_mnem(int(ea)) or ""
            if mnemonic == "jmp":
                if insn.ops[0].type == idaapi.o_reg:
                    saw_indirect = True
                elif insn.ops[0].type in {idaapi.o_near, idaapi.o_far}:
                    pending.append(int(insn.ops[0].addr))
                ea = next_ea
                break
            if mnemonic in _SV_JCC_MNEMS:
                if insn.ops[0].type in {idaapi.o_near, idaapi.o_far}:
                    pending.append(int(insn.ops[0].addr))
                pending.append(next_ea)
                ea = next_ea
                break
            if mnemonic in {"ret", "retn", "retf", "int"}:
                ea = next_ea
                break
            ea = next_ea
            if ea >= upper:
                break
        if ea > block_start:
            ranges.append((block_start, ea))
    return tuple(sorted(set(ranges))) if saw_indirect or not require_indirect else ()


def _recover_static_equality_route_transfers_from_mba(
    resolution: ComputedGotoResolution,
    transfers: tuple[MaterializedIndirectTransfer, ...],
    mba: object,
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Replay native equality leaves to exact live microcode handlers.

    Native replay selects a target EA, but the live MBA remains authoritative:
    a target is retained only when it maps to exactly one current microcode
    block.  Consumers apply the record only to an unresolved transition with
    the same state and re-check condition-chain handler membership.
    """
    from d810.analyses.control_flow.dispatcher_recovery import recover_dispatcher
    from d810.hexrays.mutation.ir_translator import lift

    if resolution.arch != "x86" or not resolution.patch_plans:
        return ()
    try:
        graph = lift(mba)
        recovery = recover_dispatcher(
            graph,
            None,
            materialized_indirect_transfers=transfers,
        )
    except Exception:
        logger.debug("static equality-route recovery setup failed", exc_info=True)
        return ()
    if recovery.state_var_reg is None:
        return ()
    state_var_reg = int(recovery.state_var_reg)
    envelope_end = (
        max(
            (int(ea) for ea in (*resolution.reachable_eas, *resolution.block_entries)),
            default=int(resolution.function_ea),
        )
        + 0x100
    )
    context_mregs = _residual_context_mregs(resolution.function_context_register_values)
    register_snapshots_by_ea = {
        int(source_ea): _residual_context_mregs(register_values)
        for source_ea, register_values in resolution.corridor_register_snapshots
    }
    dispatch_anchor_eas = frozenset(
        int(anchor_ea)
        for transfer in transfers
        for anchor_ea in transfer.materialized_anchor_eas
    )
    dispatcher_fallback_eas = _static_equality_dispatcher_fallback_eas(transfers)
    live_eas = frozenset(
        int(ea)
        for block in graph.blocks.values()
        for ea in (
            int(block.start_ea),
            *(int(insn.ea) for insn in block.insn_snapshots),
        )
    )
    targets_by_state: dict[int, set[tuple[int, int, int]]] = {}
    for transfer in transfers:
        if transfer.resolver_kind == "static_equality_candidate":
            if len(transfer.target_eas) != 1:
                continue
            target_ea = int(transfer.target_eas[0])
            target_block = find_unique_target_entry_block(
                graph,
                target_ea,
                transfer.next_target_ea,
            )
            if target_block is None or recovery.dispatch_map is None:
                continue
            candidate = _static_equality_candidate_target(
                transfer,
                state_var_reg,
                live_target_block=int(target_block),
                dispatcher_blocks=recovery.dispatch_map.dispatcher_blocks,
                dispatch_anchor_eas=dispatch_anchor_eas,
                dispatcher_fallback_eas=dispatcher_fallback_eas,
            )
            if candidate is None:
                continue
            state_constant, target_ea = candidate
            targets_by_state.setdefault(int(state_constant), set()).add(
                (
                    int(transfer.source_jmp_ea),
                    int(transfer.source_block_ea),
                    int(target_ea),
                )
            )
            continue
        if (
            transfer.resolver_kind != "static_equality_fixpoint"
            or transfer.selector_compare_constant is None
            or transfer.selector_state_var_reg != state_var_reg
        ):
            continue
        if transfer.condition_code == 4:
            target_ea = transfer.true_target_ea
        elif transfer.condition_code == 5:
            target_ea = transfer.false_target_ea
        else:
            continue
        if (
            target_ea is None
            or find_unique_target_entry_block(graph, int(target_ea)) is None
        ):
            continue
        targets_by_state.setdefault(
            int(transfer.selector_compare_constant) & _MASK32,
            set(),
        ).add(
            (
                int(transfer.source_jmp_ea),
                int(transfer.source_block_ea),
                int(target_ea),
            )
        )
    for row in _native_equality_state_rows(
        int(resolution.function_ea),
        envelope_end_ea=envelope_end,
    ):
        if _native_register_mreg(row.register_name) != state_var_reg:
            continue
        initial_mregs = dict(context_mregs)
        initial_mregs[state_var_reg] = int(row.state_constant)
        target_ea = _resolve_concrete_dispatch_corridor(
            int(row.block_entry_ea),
            initial_mregs=initial_mregs,
            handler_eas=live_eas,
            register_snapshots_by_ea=register_snapshots_by_ea,
            dispatch_anchor_eas=dispatch_anchor_eas,
        )
        if (
            target_ea is None
            or find_unique_target_entry_block(graph, int(target_ea)) is None
        ):
            continue
        jmp_ea = _native_first_register_indirect_jump(int(row.direct_target_ea))
        if jmp_ea is None:
            continue
        targets_by_state.setdefault(int(row.state_constant), set()).add(
            (int(jmp_ea), int(row.block_entry_ea), int(target_ea))
        )

    produced: list[MaterializedIndirectTransfer] = []
    for state_constant, facts in sorted(targets_by_state.items()):
        target_eas = {target_ea for _jmp_ea, _root_ea, target_ea in facts}
        if len(target_eas) != 1:
            continue
        target_ea = next(iter(target_eas))
        jmp_ea, root_ea, _target_ea = min(facts)
        produced.append(
            MaterializedIndirectTransfer(
                source_jmp_ea=int(jmp_ea),
                source_block_ea=int(root_ea),
                materialized_anchor_eas=(),
                target_eas=(int(target_ea),),
                next_target_ea=_next_transfer_target_ea(
                    transfers,
                    int(target_ea),
                ),
                selector_state_constant=int(state_constant),
                selector_state_var_reg=int(state_var_reg),
                context_register_values=tuple(sorted(context_mregs.items())),
                resolver_kind="static_equality_route",
            )
        )
    logger.info(
        "static equality-route recovery: rows=%d states=%d transfers=%d",
        len(
            _native_equality_state_rows(
                int(resolution.function_ea),
                envelope_end_ea=envelope_end,
            )
        ),
        len(targets_by_state),
        len(produced),
    )
    return tuple(produced)


def _keep_static_equality_route_blocks(
    mba: object,
    transfers: tuple[MaterializedIndirectTransfer, ...],
) -> int:
    """Keep resolver-proven equality roots/targets through local DCE."""
    import ida_hexrays  # type: ignore[import-untyped]

    protected_eas = {
        int(ea)
        for transfer in transfers
        if transfer.resolver_kind
        in {
            "static_equality_fixpoint",
            "static_equality_candidate",
            "residual_state_route_evidence",
        }
        for ea in (int(transfer.source_block_ea), *transfer.target_eas)
    }
    kept = 0
    for serial in range(int(mba.qty)):
        block = mba.get_mblock(serial)
        if block is None:
            continue
        block_eas = {int(block.start)}
        current = block.head
        while current is not None:
            block_eas.add(int(current.ea))
            if current is block.tail or current == block.tail:
                break
            current = current.next
        if block_eas.isdisjoint(protected_eas):
            continue
        block.flags |= int(ida_hexrays.MBL_KEEP)
        kept += 1
    return kept


def _exact_equality_native_route(
    transfers: tuple[MaterializedIndirectTransfer, ...],
    state_constant: int,
) -> tuple[int, int | None] | None:
    """Return the unique native target and its tightest proven label bound."""
    state = int(state_constant) & _MASK32
    resolver_candidates: dict[int, set[int]] = {}
    condition_chain_candidates: dict[int, set[int]] = {}
    for transfer in transfers:
        if transfer.resolver_kind not in {
            "static_fixpoint",
            "static_equality_fixpoint",
            "static_equality_route",
            "residual_state_route_evidence",
            "condition_chain_handler_evidence",
        }:
            continue
        selector = transfer.selector_state_constant
        compared = transfer.selector_compare_constant
        if selector is not None:
            if (int(selector) & _MASK32) != state:
                continue
        elif compared is None or (int(compared) & _MASK32) != state:
            continue
        if transfer.condition_code == 4:
            target = transfer.true_target_ea
        elif transfer.condition_code == 5:
            target = transfer.false_target_ea
        elif transfer.condition_code is None and len(transfer.target_eas) == 1:
            target = transfer.target_eas[0]
        else:
            continue
        if target is not None and int(target) in transfer.target_eas:
            target_ea = int(target)
            candidate_map = (
                condition_chain_candidates
                if transfer.resolver_kind == "condition_chain_handler_evidence"
                else resolver_candidates
            )
            bounds = candidate_map.setdefault(target_ea, set())
            if (
                transfer.next_target_ea is not None
                and int(transfer.next_target_ea) > target_ea
            ):
                bounds.add(int(transfer.next_target_ea))
    candidates = resolver_candidates or condition_chain_candidates
    if len(candidates) != 1:
        return None
    target_ea, bounds = next(iter(candidates.items()))
    return (target_ea, min(bounds) if bounds else None)


def _exact_equality_native_target(
    transfers: tuple[MaterializedIndirectTransfer, ...],
    state_constant: int,
) -> int | None:
    """Return the unique native target of an exact equality leaf."""
    route = _exact_equality_native_route(transfers, state_constant)
    return route[0] if route is not None else None


def _preopt_entry_bridge_transfer(
    evidence: EntryBridgeEvidence,
    transfers: tuple[MaterializedIndirectTransfer, ...],
) -> MaterializedIndirectTransfer | None:
    """Bind one portable PREOPT entry predicate to two exact handler EAs."""
    source_ea = evidence.predicate_block_ea
    predicate_ea = evidence.conditional_tail_ea
    predicate_stack_identity = evidence.canonical_predicate_stack_identity
    state_register = unique_materialized_state_register(transfers)
    state_targets = (
        {}
        if state_register is None
        else _unique_static_equality_handler_targets(transfers, state_register)
    )
    taken_target = state_targets.get(int(evidence.taken_state_constant) & _MASK32)
    fallthrough_target = state_targets.get(
        int(evidence.fallthrough_state_constant) & _MASK32
    )
    if (
        source_ea is None
        or predicate_ea is None
        or predicate_stack_identity is None
        or int(predicate_stack_identity[1]) <= 0
        or int(evidence.condition_code) not in {4, 5}
        or state_register is None
        or taken_target is None
        or fallthrough_target is None
        or int(taken_target) == int(fallthrough_target)
    ):
        return None
    return MaterializedIndirectTransfer(
        source_jmp_ea=int(predicate_ea),
        source_block_ea=int(source_ea),
        materialized_anchor_eas=(int(evidence.source_store_ea),),
        target_eas=(int(taken_target), int(fallthrough_target)),
        condition_code=int(evidence.condition_code),
        true_target_ea=int(taken_target),
        false_target_ea=int(fallthrough_target),
        selector_state_var_reg=int(state_register),
        resolver_kind="preopt_entry_bridge",
        predicate_size=int(predicate_stack_identity[1]),
        predicate_stack_ida_stkoff=int(predicate_stack_identity[0]),
        predicate_true_state=int(evidence.taken_state_constant) & _MASK32,
        predicate_false_state=(int(evidence.fallthrough_state_constant) & _MASK32),
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
        state_carrier_store_ea=int(evidence.source_store_ea),
        state_carrier_ida_stkoff=(
            None
            if evidence.canonical_stack_cell_identity is None
            else int(evidence.canonical_stack_cell_identity[0])
        ),
    )


def _preopt_entry_bridge_transfers(
    evidence_rows: tuple[EntryBridgeEvidence, ...],
    transfers: tuple[MaterializedIndirectTransfer, ...],
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Project one unambiguous PREOPT entry proof, or abstain."""
    if len(evidence_rows) != 1:
        return ()
    transfer = _preopt_entry_bridge_transfer(evidence_rows[0], transfers)
    return () if transfer is None else (transfer,)


def _bind_preopt_entry_bridge_consumers(
    transfers: tuple[MaterializedIndirectTransfer, ...],
    *,
    consumer_load_eas_by_displacement: Mapping[int, Sequence[int]],
    store_displacement_resolver=None,
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Attach the unique native stack consumer to a portable entry proof."""
    if store_displacement_resolver is None:
        import ida_ua  # type: ignore[import-untyped]

        def store_displacement_resolver(store_ea: int) -> int | None:
            instruction = ida_ua.insn_t()
            if int(ida_ua.decode_insn(instruction, int(store_ea))) <= 0:
                return None
            if (idaapi.print_insn_mnem(int(store_ea)) or "").lower() != "mov":
                return None
            return _sv_stack_pointer_displacement(instruction.ops[0])

    bound: list[MaterializedIndirectTransfer] = []
    for transfer in transfers:
        store_ea = transfer.state_carrier_store_ea
        if transfer.resolver_kind != "preopt_entry_bridge" or store_ea is None:
            continue
        displacement = store_displacement_resolver(int(store_ea))
        if displacement is None:
            continue
        consumers = tuple(
            sorted(
                {
                    int(ea)
                    for ea in consumer_load_eas_by_displacement.get(
                        int(displacement) & _MASK32,
                        (),
                    )
                }
            )
        )
        if len(consumers) != 1:
            continue
        bound.append(
            replace(
                transfer,
                state_carrier_stack_displacement=(int(displacement) & _MASK32),
                state_carrier_consumer_load_eas=consumers,
            )
        )
    return tuple(bound)


def _bind_preopt_entry_consumer_owned_ranges(
    transfers: tuple[MaterializedIndirectTransfer, ...],
    *,
    native_cfg: NativeCfg,
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Attach the exact native consumer block as its replacement corridor."""
    bound: list[MaterializedIndirectTransfer] = []
    for transfer in transfers:
        if len(transfer.state_carrier_consumer_load_eas) != 1:
            bound.append(transfer)
            continue
        (consumer_ea,) = transfer.state_carrier_consumer_load_eas
        block = native_cfg.blocks_by_ea.get(int(consumer_ea))
        if (
            block is None
            or int(block.start_ea) != int(consumer_ea)
            or int(block.end_ea) <= int(consumer_ea)
        ):
            bound.append(transfer)
            continue
        bound.append(
            replace(
                transfer,
                owned_native_ranges=((int(block.start_ea), int(block.end_ea)),),
            )
        )
    return tuple(bound)


def _project_preopt_entry_consumer_routes(
    evidence_rows: tuple[EntryBridgeEvidence, ...],
    transfers: tuple[MaterializedIndirectTransfer, ...],
    *,
    consumer_load_eas_by_displacement: Mapping[int, Sequence[int]],
    native_cfg: NativeCfg,
    store_displacement_resolver=None,
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Build complete portable carried choices from one pristine entry proof."""
    projected = _preopt_entry_bridge_transfers(evidence_rows, transfers)
    if not projected:
        return ()
    bound = _bind_preopt_entry_bridge_consumers(
        projected,
        consumer_load_eas_by_displacement=consumer_load_eas_by_displacement,
        store_displacement_resolver=store_displacement_resolver,
    )
    return _bind_preopt_entry_consumer_owned_ranges(
        bound,
        native_cfg=native_cfg,
    )


def _without_replaced_imported_dispatcher_ports(
    ports: tuple[DetachedSnippetConditionalBoundaryPort, ...],
    transfers: tuple[MaterializedIndirectTransfer, ...],
    *,
    native_cfg: NativeCfg | None,
    diagnostic: dict[str, object] | None = None,
) -> tuple[DetachedSnippetConditionalBoundaryPort, ...]:
    """Reserve one imported consumer envelope for the atomic route batch."""
    if diagnostic is not None:
        diagnostic.clear()
    choices = tuple(
        transfer
        for transfer in transfers
        if transfer.resolver_kind
        in {"preopt_entry_bridge", "static_stack_carried_state_choice"}
        and len(transfer.state_carrier_consumer_load_eas) == 1
        and transfer.state_carrier_store_ea is not None
        and transfer.state_carrier_ida_stkoff is not None
        and transfer.predicate_size is not None
        and int(transfer.predicate_size) > 0
        and transfer.predicate_true_state is not None
        and transfer.predicate_false_state is not None
        and transfer.true_target_ea is not None
        and transfer.false_target_ea is not None
    )
    choice_rows = tuple(
        {
            "resolver_kind": str(transfer.resolver_kind),
            "consumer_load_ea": (
                f"0x{int(transfer.state_carrier_consumer_load_eas[0]):X}"
            ),
            "store_ea": f"0x{int(transfer.state_carrier_store_ea):X}",
            "ida_stkoff": int(transfer.state_carrier_ida_stkoff),
            "predicate_size": int(transfer.predicate_size),
            "states": tuple(
                f"0x{int(value) & _MASK32:X}"
                for value in sorted(
                    {
                        int(transfer.predicate_true_state),
                        int(transfer.predicate_false_state),
                    }
                )
            ),
            "targets": tuple(
                f"0x{int(value):X}"
                for value in sorted(
                    {
                        int(transfer.true_target_ea),
                        int(transfer.false_target_ea),
                    }
                )
            ),
        }
        for transfer in choices
    )
    signatures = {
        (
            int(transfer.state_carrier_consumer_load_eas[0]),
            int(transfer.state_carrier_store_ea),
            int(transfer.state_carrier_ida_stkoff),
            int(transfer.predicate_size),
            frozenset(
                {
                    int(transfer.predicate_true_state) & _MASK32,
                    int(transfer.predicate_false_state) & _MASK32,
                }
            ),
            frozenset(
                {
                    int(transfer.true_target_ea),
                    int(transfer.false_target_ea),
                }
            ),
        )
        for transfer in choices
    }
    if diagnostic is not None:
        diagnostic.update(
            {
                "choice_count": len(choices),
                "signature_count": len(signatures),
                "choices": choice_rows,
            }
        )
    if native_cfg is None or len(signatures) != 1:
        if diagnostic is not None:
            diagnostic.update(
                {
                    "outcome": "abstained",
                    "reason": (
                        "native_cfg_missing"
                        if native_cfg is None
                        else "ambiguous_consumer_envelopes"
                    ),
                    "suppressed_port_count": 0,
                }
            )
        return ports
    consumer_load_ea = int(next(iter(signatures))[0])
    entries = {
        int(entry_ea)
        for entry_ea, block in native_cfg.blocks_by_ea.items()
        if int(block.start_ea) <= int(consumer_load_ea) < int(block.end_ea)
    }
    if len(entries) != 1:
        if diagnostic is not None:
            diagnostic.update(
                {
                    "outcome": "abstained",
                    "reason": "consumer_native_entry_not_unique",
                    "consumer_entries": tuple(
                        f"0x{int(entry_ea):X}" for entry_ea in sorted(entries)
                    ),
                    "suppressed_port_count": 0,
                }
            )
        return ports
    (consumer_entry_ea,) = entries
    retained = tuple(
        port
        for port in ports
        if not (
            port.source_owner is DetachedSnippetBoundaryPortOwner.IMPORTED
            and int(port.source_block_ea) == int(consumer_entry_ea)
            and port.old_taken_target_ea is None
            and port.old_fallthrough_target_ea is None
            and port.logical_source_anchor_ea is None
        )
    )
    suppressed_count = len(ports) - len(retained)
    if diagnostic is not None:
        diagnostic.update(
            {
                "outcome": "suppressed" if suppressed_count else "not_present",
                "reason": (
                    "consumer_route_owns_envelope"
                    if suppressed_count
                    else "matching_dispatcher_port_not_present"
                ),
                "consumer_entry_ea": f"0x{int(consumer_entry_ea):X}",
                "suppressed_port_count": int(suppressed_count),
            }
        )
    return retained


def _capture_preopt_entry_bridge_evidence(
    state: ResolverSessionState,
    mba: object,
) -> bool:
    """Publish the pristine PREOPT entry choice before any union mutation."""
    evidence = recognize_preoptimized_residual_entry_bridge(mba)
    if evidence is None:
        return False
    changed = state.native_preanalysis.merge_preopt_entry_bridge_evidence(
        state.native_key,
        evidence,
    )
    if changed:
        state.invalidate_current_mba_binding()
        logger.info(
            "PREOPT entry bridge captured: predicate=0x%X source=0x%X "
            "store=0x%X taken_state=0x%X fallthrough_state=0x%X",
            int(evidence.conditional_tail_ea or evidence.predicate_ea),
            int(evidence.predicate_block_ea or evidence.predicate_ea),
            int(evidence.source_store_ea),
            int(evidence.taken_state_constant) & _MASK32,
            int(evidence.fallthrough_state_constant) & _MASK32,
        )
    return changed


def _states_with_validated_exact_equality_routes(
    transfers: tuple[MaterializedIndirectTransfer, ...],
) -> frozenset[int]:
    """States whose exact native target already passed live-CFG validation."""
    return frozenset(
        int(transfer.selector_state_constant) & _MASK32
        for transfer in transfers
        if transfer.resolver_kind
        in {"static_equality_route", "residual_state_route_evidence"}
        and transfer.selector_state_constant is not None
        and len(transfer.target_eas) == 1
    )


def _encode_direct_jump(
    source_ea: int, region_size: int, target_ea: int
) -> bytes | None:
    """Encode a size-preserving direct jump, preferring the original short form."""
    source = int(source_ea)
    size = int(region_size)
    target = int(target_ea)
    short_delta = target - (source + 2)
    if size == 2 and -128 <= short_delta <= 127:
        return b"\xeb" + struct.pack("b", short_delta)
    if size >= 5:
        body = b"\xe9" + struct.pack("<i", target - (source + 5))
        return body + b"\x90" * (size - len(body))
    return None


def _encode_x86_register_immediate32(
    processor_register: int, value: int
) -> bytes | None:
    """Encode ``mov r32, imm32`` for one legacy x86 general register."""
    register = int(processor_register)
    if not 0 <= register <= 7:
        return None
    return bytes((0xB8 + register,)) + struct.pack("<I", int(value) & _MASK32)


def _select_prologue_entry_jump(
    entry_sites: Sequence[tuple[int, int]],
    *,
    routing_start_ea: int,
) -> tuple[int, int] | None:
    """Select the unique anchor jump before the first proven routing node."""
    candidates = tuple(
        (int(ea), int(size))
        for ea, size in entry_sites
        if int(ea) < int(routing_start_ea)
    )
    return candidates[0] if len(candidates) == 1 else None


def _native_entry_bridge_trampoline(
    *,
    predicate_ea: int,
    source_store_ea: int,
    routing_start_ea: int,
    dispatcher_anchor_ea: int,
    required_cave_size: int = 11,
) -> tuple[int, int, int, int] | None:
    """Find a flag-preserving prologue jump and a NOP cave before the dispatcher."""
    import ida_bytes  # type: ignore[import-untyped]
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    predicate = ida_ua.insn_t()
    predicate_size = int(ida_ua.decode_insn(predicate, int(predicate_ea)))
    if predicate_size <= 0:
        logger.info(
            "residual entry trampoline: predicate decode failed at 0x%X",
            int(predicate_ea),
        )
        return None

    entry_sites: list[tuple[int, int]] = []
    cave_sites: list[tuple[int, int]] = []
    cursor = int(source_store_ea)
    while cursor < int(dispatcher_anchor_ea):
        insn = ida_ua.insn_t()
        size = int(ida_ua.decode_insn(insn, cursor))
        if size <= 0:
            cursor = int(ida_bytes.next_head(cursor, int(dispatcher_anchor_ea)))
            if cursor <= 0:
                break
            continue
        mnemonic = (idaapi.print_insn_mnem(cursor) or "").lower()
        if (
            mnemonic == "jmp"
            and insn.ops[0].type in (idaapi.o_near, idaapi.o_far)
            and int(insn.ops[0].addr) == int(dispatcher_anchor_ea)
        ):
            entry_sites.append((cursor, size))
        # IDA's metapc decoder reports the canonical long NOP as NN_nop but
        # print_insn_mnem() can return an empty string for the 11-byte form.
        if (mnemonic == "nop" or int(insn.itype) == int(idaapi.NN_nop)) and size >= int(
            required_cave_size
        ):
            cave_sites.append((cursor, size))
        cursor += size
    logger.info(
        "residual entry trampoline scan: entries=%s caves=%s",
        [(hex(int(ea)), int(size)) for ea, size in entry_sites],
        [(hex(int(ea)), int(size)) for ea, size in cave_sites],
    )
    entry_site = _select_prologue_entry_jump(
        entry_sites,
        routing_start_ea=int(routing_start_ea),
    )
    if entry_site is None or not cave_sites:
        return None
    entry_ea, entry_size = entry_site

    # The copied predicate's flags must still be live at the prologue jump.
    # Find the jump first, then prove that every intervening instruction is
    # flag-neutral.  Scanning through the dispatcher would reject unrelated
    # comparison-tree instructions and would not prove the property we need.
    allowed_flag_preserving = {"mov", "lea", "nop"}
    cursor = int(predicate_ea) + predicate_size
    while cursor < entry_ea:
        insn = ida_ua.insn_t()
        size = int(ida_ua.decode_insn(insn, cursor))
        if size <= 0:
            return None
        mnemonic = (idaapi.print_insn_mnem(cursor) or "").lower()
        if mnemonic not in allowed_flag_preserving and not mnemonic.startswith("cmov"):
            logger.info(
                "residual entry trampoline: flag-clobber at 0x%X mnemonic=%s",
                int(cursor),
                mnemonic,
            )
            return None
        cursor += size
    if cursor != entry_ea or int(source_store_ea) >= entry_ea:
        logger.info(
            "residual entry trampoline: corridor mismatch cursor=0x%X entry=0x%X store=0x%X",
            int(cursor),
            int(entry_ea),
            int(source_store_ea),
        )
        return None

    viable = [
        (cave_ea, cave_size)
        for cave_ea, cave_size in cave_sites
        if cave_ea > entry_ea
        and _encode_direct_jump(entry_ea, entry_size, cave_ea) is not None
    ]
    if len(viable) != 1:
        logger.info(
            "residual entry trampoline: viable caves=%s entry=0x%X size=%d",
            [(hex(int(ea)), int(size)) for ea, size in viable],
            int(entry_ea),
            int(entry_size),
        )
        return None
    cave_ea, cave_size = viable[0]
    return (entry_ea, entry_size, cave_ea, cave_size)


def _condition_chain_handler_transfers_from_recovery(
    transfers: tuple[MaterializedIndirectTransfer, ...],
    graph: FlowGraph,
    recovery: object,
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Project one recovered live condition-chain map into portable evidence.

    Hex-Rays can fold a handful of detached equality leaves after the entry
    bridge makes the computed-goto BST reachable from the real prologue.  The
    rows are nevertheless proven in the pre-bridge CALLS MBA.  Preserve them as
    state plus native-handler-EA evidence so the next portable FlowGraph can
    remap each target to its new block serial without carrying stale serials.
    """
    from d810.capabilities.dispatcher import RouterKind

    dmap = recovery.dispatch_map
    if (
        dmap is None
        or dmap.router_kind is not RouterKind.CONDITION_CHAIN
        or recovery.state_var_reg is None
    ):
        return ()
    dispatcher_entry = graph.get_block(int(dmap.dispatcher_entry_block))
    if dispatcher_entry is None or int(dispatcher_entry.start_ea) <= 0:
        return ()
    dispatcher_entry_ea = int(dispatcher_entry.start_ea)
    dispatcher_router_eas = tuple(
        sorted(
            {
                int(block.start_ea)
                for serial in dmap.dispatcher_blocks
                if (block := graph.get_block(int(serial))) is not None
                and int(block.start_ea) > 0
            }
        )
    )
    if not dispatcher_router_eas:
        return ()
    existing_states = {
        int(transfer.selector_state_constant)
        for transfer in transfers
        if transfer.resolver_kind == "condition_chain_handler_evidence"
        and transfer.selector_state_constant is not None
    }
    existing_states.update(_states_with_validated_exact_equality_routes(transfers))
    existing_live_states = {
        int(transfer.selector_state_constant)
        for transfer in transfers
        if transfer.resolver_kind == "live_state_dispatcher_row_evidence"
        and transfer.selector_state_constant is not None
    }
    evidence: list[MaterializedIndirectTransfer] = []
    for row in dmap.rows:
        state = int(row.state_const)
        target = graph.get_block(int(row.target_block))
        source_serial = (
            int(row.compare_block)
            if row.compare_block is not None
            else int(dmap.dispatcher_entry_block)
        )
        source = graph.get_block(source_serial)
        if target is None or source is None:
            continue
        target_ea = int(target.start_ea)
        source_ea = int(source.start_ea)
        if target_ea <= 0 or source_ea <= 0:
            continue
        if target_ea in dispatcher_router_eas:
            # A condition-chain row may route into another comparison subtree.
            # That landing is dispatcher navigation, not handler authority.
            continue
        if state not in existing_live_states:
            evidence.append(
                MaterializedIndirectTransfer(
                    source_jmp_ea=source_ea,
                    source_block_ea=source_ea,
                    materialized_anchor_eas=(),
                    target_eas=(target_ea,),
                    selector_state_var_reg=int(recovery.state_var_reg),
                    selector_state_constant=state,
                    resolver_kind="live_state_dispatcher_row_evidence",
                    dispatcher_entry_ea=dispatcher_entry_ea,
                    dispatcher_router_eas=dispatcher_router_eas,
                )
            )
            existing_live_states.add(state)
        if state in existing_states:
            continue
        evidence.append(
            MaterializedIndirectTransfer(
                source_jmp_ea=source_ea,
                source_block_ea=source_ea,
                materialized_anchor_eas=(),
                target_eas=(target_ea,),
                selector_state_var_reg=int(recovery.state_var_reg),
                selector_state_constant=state,
                resolver_kind="condition_chain_handler_evidence",
                dispatcher_entry_ea=dispatcher_entry_ea,
                dispatcher_router_eas=dispatcher_router_eas,
            )
        )
        existing_states.add(state)
    return tuple(evidence)


def _recover_condition_chain_handler_transfers_from_mba(
    transfers: tuple[MaterializedIndirectTransfer, ...],
    mba: object,
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Recover and snapshot live state-to-handler rows from one CALLS MBA."""
    from d810.analyses.control_flow.dispatcher_recovery import recover_dispatcher
    from d810.hexrays.mutation.ir_translator import lift

    graph = lift(mba)
    recovery = recover_dispatcher(
        graph,
        None,
        materialized_indirect_transfers=transfers,
    )
    return _condition_chain_handler_transfers_from_recovery(
        transfers,
        graph,
        recovery,
    )


def _unique_import_owned_tail_eas(
    mba: object,
    imported_instruction_eas: frozenset[int],
) -> frozenset[int]:
    """Return unique live block tails whose block contains imported code."""
    if not imported_instruction_eas:
        return frozenset()
    try:
        quantity = int(mba.qty)
    except (AttributeError, TypeError, ValueError):
        return frozenset()
    block_instruction_eas: list[frozenset[int]] = []
    candidate_tail_eas: set[int] = set()
    for serial in range(quantity):
        try:
            block = mba.get_mblock(serial)
            current = block.head
            tail = block.tail
        except (AttributeError, TypeError):
            continue
        instruction_eas: set[int] = set()
        while current is not None:
            instruction_eas.add(int(current.ea))
            if current is tail or current == tail:
                break
            current = current.next
        frozen_eas = frozenset(instruction_eas)
        block_instruction_eas.append(frozen_eas)
        if tail is not None and not frozen_eas.isdisjoint(imported_instruction_eas):
            candidate_tail_eas.add(int(tail.ea))
    return frozenset(
        tail_ea
        for tail_ea in candidate_tail_eas
        if sum(tail_ea in instruction_eas for instruction_eas in block_instruction_eas)
        == 1
    )


def _predicate_block_has_imported_instruction(
    mba: object,
    predicate_ea: int,
    imported_instruction_eas: frozenset[int],
) -> bool:
    """Prove that one unique live predicate block belongs to an import.

    Hex-Rays may synthesize a normalized conditional instruction and therefore
    give it no direct native-origin row.  Sibling instructions in the same
    unique live block retain their imported-EA provenance.  That block-local
    provenance is sufficient only while the predicate itself is still present
    in exactly one current block.
    """
    return int(predicate_ea) in _unique_import_owned_tail_eas(
        mba,
        imported_instruction_eas,
    )


def recover_conditional_handler_bridge_transfers_from_mba(
    transfers: tuple[MaterializedIndirectTransfer, ...],
    mba: object,
    *,
    inherited_states_by_predicate_ea: Mapping[int, int] | None = None,
    imported_predicate_eas: frozenset[int] = frozenset(),
    imported_instruction_origins: Mapping[int, int] | None = None,
    arm_states_by_predicate_ea: Mapping[int, tuple[int, int]] | None = None,
    native_cfg: NativeCfg | None = None,
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Preserve live handler predicates before staged routing folds them.

    Condition-chain evidence supplies the exact state-to-handler EA map.  The
    backend recognizer contributes the live predicate and concrete state
    selected by each immediate arm.  A residual native route normally proves
    that one arm cannot be delivered by the live equality router.  For a live
    nested predicate with no reconstructable register identity, exact
    predicate-EA handler-replay evidence may supply the same authorization.
    This keeps ordinary handler predicates in the regular transition pipeline
    instead of publishing a competing bridge.
    """
    from d810.backends.hexrays.evidence.residual_entry_bridge import (
        predicate_arm_reaches_ea,
        recognize_conditional_handler_bridges,
    )

    state_registers = {
        int(transfer.selector_state_var_reg)
        for transfer in transfers
        if transfer.resolver_kind
        in {
            "condition_chain_handler_evidence",
            "static_equality_fixpoint",
            "static_handler_entry_route",
        }
        and transfer.selector_state_var_reg is not None
    }
    if len(state_registers) != 1:
        return ()
    state_register = next(iter(state_registers))
    target_candidates: dict[int, set[int]] = {}
    for transfer in transfers:
        state: int | None = None
        target: int | None = None
        if transfer.resolver_kind == "static_equality_fixpoint":
            if transfer.selector_compare_constant is None:
                continue
            state = int(transfer.selector_compare_constant) & _MASK32
            if transfer.condition_code == 4:
                target = transfer.true_target_ea
            elif transfer.condition_code == 5:
                target = transfer.false_target_ea
        elif transfer.resolver_kind in {
            "condition_chain_handler_evidence",
            "static_handler_entry_route",
            "static_equality_route",
            "residual_state_route",
            "residual_state_route_evidence",
        }:
            if (
                transfer.selector_state_constant is None
                or len(transfer.target_eas) != 1
            ):
                continue
            state = int(transfer.selector_state_constant) & _MASK32
            target = int(transfer.target_eas[0])
        if state is None or target is None or int(target) not in transfer.target_eas:
            continue
        target_candidates.setdefault(state, set()).add(int(target))
    fallback_state_targets = {
        state: next(iter(targets))
        for state, targets in target_candidates.items()
        if len(targets) == 1
    }
    state_targets = _unique_static_equality_handler_targets(
        transfers,
        state_register,
    )
    for state, target in fallback_state_targets.items():
        state_targets.setdefault(state, target)
    if not state_targets:
        return ()
    static_choices_by_predicate: dict[
        int,
        set[tuple[int, int, int]],
    ] = {}
    for transfer in transfers:
        if (
            transfer.resolver_kind != "static_conditional_state_choice"
            or transfer.selector_state_var_reg is None
            or transfer.predicate_true_state is None
            or transfer.predicate_false_state is None
        ):
            continue
        static_choices_by_predicate.setdefault(
            int(transfer.source_jmp_ea),
            set(),
        ).add(
            (
                int(transfer.selector_state_var_reg),
                int(transfer.predicate_true_state) & _MASK32,
                int(transfer.predicate_false_state) & _MASK32,
            )
        )
    existing_bridges_by_predicate: dict[
        int,
        set[MaterializedIndirectTransfer],
    ] = {}
    for transfer in transfers:
        if transfer.resolver_kind != "conditional_handler_bridge":
            continue
        existing_bridges_by_predicate.setdefault(
            int(transfer.source_jmp_ea),
            set(),
        ).add(transfer)
    residual_route_proofs = tuple(
        (
            int(transfer.source_jmp_ea),
            int(transfer.selector_state_constant) & _MASK32,
            int(transfer.target_eas[0]),
        )
        for transfer in transfers
        if transfer.resolver_kind
        in {
            "residual_state_route",
            "residual_state_route_evidence",
        }
        and transfer.selector_state_constant is not None
        and len(transfer.target_eas) == 1
    )
    preserve_live_predicate_eas = _unique_import_owned_tail_eas(
        mba,
        imported_predicate_eas,
    )
    evidence = recognize_conditional_handler_bridges(
        mba,
        state_register=state_register,
        state_targets=state_targets,
        inherited_states_by_predicate_ea=inherited_states_by_predicate_ea,
        arm_states_by_predicate_ea=arm_states_by_predicate_ea,
        preserve_live_predicate_eas=preserve_live_predicate_eas,
    )
    result: list[MaterializedIndirectTransfer] = []
    for row in evidence:
        predicate_ea = int(row.predicate_ea)
        source_block_ea = int(row.source_block_ea)
        predicate_predecessor_ea = (
            int(row.predicate_predecessor_ea)
            if row.predicate_predecessor_ea is not None
            else None
        )
        if imported_instruction_origins is not None:
            predicate_ea = int(
                imported_instruction_origins.get(predicate_ea, predicate_ea)
            )
            source_block_ea = int(
                imported_instruction_origins.get(source_block_ea, source_block_ea)
            )
            if predicate_predecessor_ea is not None:
                predicate_predecessor_ea = int(
                    imported_instruction_origins.get(
                        predicate_predecessor_ea,
                        predicate_predecessor_ea,
                    )
                )
        if native_cfg is not None:
            native_source_blocks = tuple(
                block
                for block in native_cfg.blocks_by_ea.values()
                if int(block.start_ea) <= predicate_ea < int(block.end_ea)
            )
            if len(native_source_blocks) == 1:
                source_block_ea = int(native_source_blocks[0].start_ea)
        arm_proofs = {
            (
                int(row.true_state) & _MASK32,
                int(row.true_target_ea),
            ),
            (
                int(row.false_state) & _MASK32,
                int(row.false_target_ea),
            ),
        }
        residual_arm_proven = any(
            (state, target_ea) in arm_proofs
            and predicate_arm_reaches_ea(
                mba,
                predicate_ea=int(row.predicate_ea),
                route_ea=int(route_ea),
            )
            for route_ea, state, target_ea in residual_route_proofs
        )
        inherited_state = (
            inherited_states_by_predicate_ea.get(int(row.predicate_ea))
            if inherited_states_by_predicate_ea is not None
            else None
        )
        inherited_arm_proven = inherited_state is not None and any(
            int(state) == (int(inherited_state) & _MASK32)
            and state_targets.get(int(state)) == int(target_ea)
            for state, target_ea in arm_proofs
        )
        imported_predicate_proven = int(
            row.predicate_ea
        ) in imported_predicate_eas or _predicate_block_has_imported_instruction(
            mba,
            int(row.predicate_ea),
            imported_predicate_eas,
        )
        imported_arm_proven = imported_predicate_proven and all(
            state_targets.get(int(state)) == int(target_ea)
            for state, target_ea in arm_proofs
        )
        static_choice_proofs = static_choices_by_predicate.get(
            int(row.predicate_ea),
            set(),
        )
        row_taken_state = (
            int(row.true_state) if bool(row.true_is_taken) else int(row.false_state)
        ) & _MASK32
        row_fallthrough_state = (
            int(row.false_state) if bool(row.true_is_taken) else int(row.true_state)
        ) & _MASK32
        static_choice_proven = static_choice_proofs == {
            (state_register, row_taken_state, row_fallthrough_state)
        }
        if (
            not residual_arm_proven
            and not inherited_arm_proven
            and not imported_arm_proven
            and not static_choice_proven
        ):
            continue
        candidate = MaterializedIndirectTransfer(
            source_jmp_ea=predicate_ea,
            source_block_ea=source_block_ea,
            materialized_anchor_eas=(predicate_ea,),
            target_eas=(
                int(row.true_target_ea),
                int(row.false_target_ea),
            ),
            condition_code=int(row.condition_code),
            true_target_ea=int(row.true_target_ea),
            false_target_ea=int(row.false_target_ea),
            selector_state_var_reg=state_register,
            resolver_kind=(
                "static_conditional_state_choice_bridge"
                if static_choice_proven
                else "conditional_handler_bridge"
            ),
            predicate_register=(
                int(row.predicate_register)
                if row.predicate_register is not None
                else None
            ),
            predicate_size=int(row.predicate_size),
            predicate_compare_register=row.predicate_compare_register,
            predicate_compare_constant=row.predicate_compare_constant,
            predicate_predecessor_ea=predicate_predecessor_ea,
            predicate_true_state=int(row.true_state) & _MASK32,
            predicate_false_state=int(row.false_state) & _MASK32,
            predicate_true_is_taken=bool(row.true_is_taken),
            predicate_preserve_live=bool(
                imported_arm_proven
                or (inherited_arm_proven and not residual_arm_proven)
                or static_choice_proven
            ),
        )
        if candidate in existing_bridges_by_predicate.get(
            predicate_ea,
            set(),
        ):
            continue
        result.append(candidate)
        existing_bridges_by_predicate.setdefault(
            predicate_ea,
            set(),
        ).add(candidate)
    return tuple(result)


def _canonicalize_imported_transfer_eas(
    transfer: MaterializedIndirectTransfer,
    imported_instruction_origins: Mapping[int, int],
) -> MaterializedIndirectTransfer:
    """Translate transient imported instruction identities back to native EAs."""

    def native(ea: int | None) -> int | None:
        if ea is None:
            return None
        value = int(ea)
        return int(imported_instruction_origins.get(value, value))

    source_jmp_ea = native(transfer.source_jmp_ea)
    source_block_ea = native(transfer.source_block_ea)
    assert source_jmp_ea is not None
    assert source_block_ea is not None
    return replace(
        transfer,
        source_jmp_ea=source_jmp_ea,
        source_block_ea=source_block_ea,
        materialized_anchor_eas=tuple(
            int(native(anchor_ea)) for anchor_ea in transfer.materialized_anchor_eas
        ),
        materialized_predicate_ea=native(transfer.materialized_predicate_ea),
        predicate_predecessor_ea=native(transfer.predicate_predecessor_ea),
    )


# Compatibility for existing diagnostic probes; production imports the public
# name above.
_recover_conditional_handler_bridge_transfers_from_mba = (
    recover_conditional_handler_bridge_transfers_from_mba
)


def _static_absorb_eas(
    resolution: ComputedGotoResolution,
    *,
    new_block_eas: Sequence[int],
) -> tuple[int, ...]:
    """All native leaders that static delivery proved belong to the function."""
    proven_targets = {
        int(target)
        for plan in resolution.patch_plans
        for target in (
            plan.target_eas or resolution.jmp_targets.get(int(plan.jmp_ea), ())
        )
    }
    return tuple(
        sorted(
            set(int(ea) for ea in resolution.block_entries)
            | set(int(ea) for ea in new_block_eas)
            | set(int(ea) for ea in resolution.reachable_eas)
            | proven_targets
        )
    )


def _block_end(start: int) -> int:
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    insn = ida_ua.insn_t()
    ea = int(start)
    while True:
        length = ida_ua.decode_insn(insn, ea)
        if length <= 0:
            return ea
        mnem = idaapi.print_insn_mnem(ea) or ""
        nxt = ea + length
        if mnem in ("jmp", "retn", "ret", "retf", "int") or mnem.startswith("j"):
            return nxt
        ea = nxt


def _select_cc_nibble(select_ea: int, length: int) -> int | None:
    """Condition-code nibble of a cmov/setcc (``0F 4x`` / ``0F 9x``), robust to a
    REX prefix on x86-64."""
    import ida_bytes  # type: ignore[import-untyped]

    raw = ida_bytes.get_bytes(int(select_ea), int(length))
    if not raw:
        return None
    idx = raw.find(0x0F)
    if idx < 0 or idx + 1 >= len(raw):
        return None
    return raw[idx + 1] & 0x0F


def _analyze_select_block(jmp_ea: int, block_start: int, arch: str) -> dict | None:
    """Structurally recover a cmov-pointer-select 2-way computed goto:
    ``lea dst,cell_false; lea src,cell_true; cmp state,K; cmov<cc> dst,src;
    mov reg,[dst]; add reg,KEY; jmp reg``. Returns the flag-setter end, the cc,
    and the concrete false/true targets (``[cell]+KEY``), or None if the block
    is not this shape."""
    import ida_bytes  # type: ignore[import-untyped]
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    elsize = 8 if arch == "x86_64" else 4
    getptr = ida_bytes.get_qword if elsize == 8 else ida_bytes.get_dword
    mask = (1 << (elsize * 8)) - 1

    lea_cell: dict[int, int] = {}
    cmp_ea: int | None = None
    cmp_end: int | None = None
    cmov: tuple[int, int] | None = None
    cc: int | None = None
    key: int | None = None
    insn = ida_ua.insn_t()
    ea = int(block_start)
    while ea < int(jmp_ea):
        length = ida_ua.decode_insn(insn, ea)
        if length <= 0:
            break
        mnem = idaapi.print_insn_mnem(ea) or ""
        if (
            mnem == "lea"
            and insn.ops[0].type == idaapi.o_reg
            and insn.ops[1].type in (idaapi.o_mem, idaapi.o_displ)
        ):
            lea_cell[insn.ops[0].reg] = int(insn.ops[1].addr)
        elif mnem == "cmp" and insn.ops[1].type == idaapi.o_imm:
            cmp_ea = int(ea)
            cmp_end = ea + length
        elif mnem.startswith("cmov"):
            cmov = (insn.ops[0].reg, insn.ops[1].reg)
            cc = _select_cc_nibble(ea, length)
        elif mnem == "add" and insn.ops[1].type == idaapi.o_imm:
            key = int(insn.ops[1].value) & mask
        ea += length

    if cmov is None or cc is None or key is None or cmp_ea is None or cmp_end is None:
        return None
    dst, src = cmov
    cell_false, cell_true = lea_cell.get(dst), lea_cell.get(src)
    if cell_false is None or cell_true is None:
        return None
    return {
        "cmp_ea": int(cmp_ea),
        "cmp_end": int(cmp_end),
        "cc": int(cc),
        "target_false": (getptr(cell_false) + key)
        & mask,  # cc false → dst keeps its lea
        "target_true": (getptr(cell_true) + key) & mask,  # cc true  → dst = src
    }


def _block_start_of(jmp_ea: int, text_start: int) -> int:
    """Leader of the block containing ``jmp_ea`` (walk back to the previous
    terminator / filler byte)."""
    import ida_bytes  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    ea = int(jmp_ea)
    while True:
        prev = ida_bytes.prev_head(ea, int(text_start))
        if prev == int(getattr(idaapi, "BADADDR", -1)) or prev < int(text_start):
            return ea
        mnem = idaapi.print_insn_mnem(prev) or ""
        if (
            mnem in ("retn", "ret", "retf")
            or mnem.startswith(("j", "int"))
            or int(ida_bytes.get_byte(prev)) == 0xCC
        ):
            return ea
        ea = prev


def _concolic_frontend_normalization_plans(
    resolution: ComputedGotoResolution,
    *,
    instruction_end: Callable[[int], int] | None = None,
    block_start: Callable[[int], int] | None = None,
    select_analyzer: Callable[[int, int, str], dict | None] | None = None,
) -> tuple[_PatchPlan, ...]:
    """Convert a complete concolic target ledger into portable branch proofs.

    The returned records describe native identities and semantic destinations;
    they intentionally contain no native byte payload.  If any resolved site
    cannot provide a complete direct or predicate-preserving conditional proof,
    the whole ledger abstains so no partial frontend authority is published.
    """
    if not resolution.jmp_targets:
        return ()

    if instruction_end is None:
        import ida_ua  # type: ignore[import-untyped]

        def instruction_end(ea: int) -> int:
            insn = ida_ua.insn_t()
            length = int(ida_ua.decode_insn(insn, int(ea)))
            return int(ea) + length if length > 0 else int(ea)

    if block_start is None:
        function_start = int(resolution.function_ea)

        def block_start(ea: int) -> int:
            return _block_start_of(int(ea), function_start)

    analyzer = _analyze_select_block if select_analyzer is None else select_analyzer
    plans: list[_PatchPlan] = []
    for jmp_ea, resolved_targets in sorted(resolution.jmp_targets.items()):
        jmp_ea = int(jmp_ea)
        target_eas = tuple(int(target) for target in resolved_targets)
        block_entry = int(block_start(jmp_ea))
        region_end = int(instruction_end(jmp_ea))
        if (
            block_entry < 0
            or block_entry > jmp_ea
            or region_end <= jmp_ea
            or len(target_eas) not in {1, 2}
        ):
            return ()
        if len(target_eas) == 1:
            plans.append(
                _PatchPlan(
                    jmp_ea=jmp_ea,
                    block_entry=block_entry,
                    patch_start=jmp_ea,
                    patch_bytes=b"",
                    region_end=region_end,
                    insn_heads=(jmp_ea,),
                    new_block_eas=(),
                    target_eas=target_eas,
                )
            )
            continue

        analysis = analyzer(jmp_ea, block_entry, resolution.arch)
        if analysis is None:
            return ()
        try:
            condition_producer_ea = int(analysis["cmp_ea"])
            predicate_ea = int(analysis["cmp_end"])
            condition_code = int(analysis["cc"])
            true_target_ea = int(analysis["target_true"])
            false_target_ea = int(analysis["target_false"])
        except (KeyError, TypeError, ValueError):
            return ()
        if (
            not block_entry <= condition_producer_ea < predicate_ea < jmp_ea
            or true_target_ea == false_target_ea
            or {true_target_ea, false_target_ea} != set(target_eas)
        ):
            return ()
        plans.append(
            _PatchPlan(
                jmp_ea=jmp_ea,
                block_entry=block_entry,
                patch_start=predicate_ea,
                patch_bytes=b"",
                region_end=region_end,
                insn_heads=(predicate_ea, jmp_ea),
                new_block_eas=(predicate_ea, jmp_ea),
                target_eas=target_eas,
                condition_code=condition_code,
                true_target_ea=true_target_ea,
                false_target_ea=false_target_ea,
                condition_producer_ea=condition_producer_ea,
            )
        )
    return tuple(plans)


def _has_unresolved_computed_goto(function_ea: int) -> bool:
    """Cheap gate: the function contains a ``jmp reg`` whose target IDA has not
    resolved (no outgoing code cref)."""
    import ida_funcs  # type: ignore[import-untyped]
    import ida_xref  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    func = ida_funcs.get_func(int(function_ea))
    if func is None:
        return False
    badaddr = int(getattr(idaapi, "BADADDR", -1))
    for jmp_ea in _reg_indirect_jump_sites(int(func.start_ea), int(func.end_ea)):
        if ida_xref.get_first_cref_from(jmp_ea) == badaddr:
            return True
    return False


def _resolve_computed_goto_resolution(
    function_ea: int, **kwargs: object
) -> ComputedGotoResolution | None:
    """Resolve one computed goto without changing native bytes."""
    resolution = resolve_computed_gotos(int(function_ea), **kwargs)  # type: ignore[arg-type]
    if resolution is not None and resolution.jmp_targets and not resolution.patch_plans:
        plans = _concolic_frontend_normalization_plans(resolution)
        if len(plans) == len(resolution.jmp_targets) and {
            int(plan.jmp_ea) for plan in plans
        } == {int(ea) for ea in resolution.jmp_targets}:
            resolution = replace(resolution, patch_plans=plans)
        else:
            resolution = None
    if resolution is None or not resolution.jmp_targets:
        static = resolve_computed_gotos_static(int(function_ea))
        if static is not None:
            resolution = static
    if resolution is None:
        return None
    if resolution.arch == "x86" and resolution.patch_plans:
        native_stack_offsets = dict(resolution.native_stack_frame_offsets)
        if not native_stack_offsets:
            stack_envelope_end = (
                max(
                    (
                        int(ea)
                        for ea in (
                            *resolution.reachable_eas,
                            *resolution.block_entries,
                        )
                    ),
                    default=int(function_ea),
                )
                + 0x100
            )
            native_stack_offsets = native_stack_frame_offsets_for_ranges(
                int(function_ea),
                ((int(function_ea), int(stack_envelope_end)),),
            )
        consumer_load_eas = _static_stack_carrier_consumer_load_eas(resolution)
        carrier_overrides = _static_stack_carrier_frame_offset_overrides(
            resolution.conditional_state_choices,
            consumer_load_eas_by_displacement=consumer_load_eas,
            native_stack_frame_offsets_by_ea=native_stack_offsets,
        )
        native_stack_offsets.update(carrier_overrides)
        resolution = replace(
            resolution,
            native_stack_frame_offsets=tuple(sorted(native_stack_offsets.items())),
            conditional_state_choices=_bind_static_stack_carrier_consumers(
                resolution.conditional_state_choices,
                consumer_load_eas_by_displacement=consumer_load_eas,
                native_stack_frame_offsets_by_ea=native_stack_offsets,
            ),
        )
    return resolution


def stage_computed_goto_preanalysis(
    function_ea: int,
    *,
    state: ResolverSessionState,
    **kwargs: object,
) -> ComputedGotoResolution | None:
    """Publish portable computed-goto evidence without native CFG mutation."""
    resolution = _resolve_computed_goto_resolution(function_ea, **kwargs)
    if resolution is None or not resolution.jmp_targets or not resolution.patch_plans:
        return None

    state.begin_materialization(resolution)
    logger.info(
        "computed-goto portable evidence staged: "
        "func=0x%x sites=%d targets=%d reachable=%d arch=%s",
        int(function_ea),
        resolution.site_count,
        resolution.target_count,
        len(resolution.reachable_eas),
        resolution.arch,
    )
    return resolution


def _generate_microcode_without_d810(
    generate_microcode: Callable,
    *args,
):
    """Build an evidence-only MBA without recursively applying d810 rewrites."""
    with suppress_d810_optimization():
        return generate_microcode(*args)


def capture_detached_route_callinfo_templates(
    state: ResolverSessionState,
    native_ranges: Sequence[tuple[int, int]],
) -> tuple[int, ...]:
    """Capture CALLS authority with every proven range tried as the entry.

    Hex-Rays may omit valid calls when a disconnected native-range union has
    one arbitrary entry.  Rotating each range to the first position gives each
    resolver-proven route one conservative CALLS view.  The native-EA registry
    merges equivalent observations and tombstones conflicts.
    """
    import ida_hexrays  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    resolution = state.portable_evidence.computed_goto_resolution
    if not isinstance(resolution, ComputedGotoResolution):
        return ()
    key = int(resolution.function_ea)
    normalized_ranges = tuple(
        dict.fromkeys(
            (int(start_ea), int(end_ea))
            for start_ea, end_ea in native_ranges
            if int(end_ea) > int(start_ea)
        )
    )
    if not normalized_ranges:
        return ()
    if (
        state.snippet_capture_active
        and state.snippet_capture_profile_ea is not None
        and int(state.snippet_capture_profile_ea) != key
    ):
        return ()

    established_scope = not state.snippet_capture_active
    if established_scope:
        state.begin_snippet_capture(key)

    captured: set[int] = set()
    try:
        for entry_range in normalized_ranges:
            ordered_ranges = (
                entry_range,
                *(row for row in normalized_ranges if row != entry_range),
            )
            ranges = ida_hexrays.mba_ranges_t()
            for start_ea, end_ea in ordered_ranges:
                ranges.ranges.push_back(idaapi.range_t(int(start_ea), int(end_ea)))
            failure = ida_hexrays.hexrays_failure_t()
            try:
                calls_mba = _generate_microcode_without_d810(
                    ida_hexrays.gen_microcode,
                    ranges,
                    failure,
                    None,
                    int(ida_hexrays.DECOMP_NO_WAIT),
                    ida_hexrays.MMAT_CALLS,
                )
            except Exception:
                logger.info(
                    "detached route CALLS generation failed: func=0x%X "
                    "entry=[0x%X,0x%X)",
                    key,
                    int(entry_range[0]),
                    int(entry_range[1]),
                    exc_info=True,
                )
                continue
            if calls_mba is None:
                logger.info(
                    "detached route CALLS generation abstained: func=0x%X "
                    "entry=[0x%X,0x%X) reason=%s",
                    key,
                    int(entry_range[0]),
                    int(entry_range[1]),
                    failure.desc(),
                )
                continue
            captured.update(capture_detached_callinfo_templates(key, calls_mba))
    finally:
        if established_scope:
            state.finish_snippet_capture()
    return tuple(sorted(captured))


class CallCompanionPreparationOutcome(NamedTuple):
    """One manager-preflight result keyed only by a portable native range."""

    native_range: tuple[int, int]
    calls_native_ranges: tuple[tuple[int, int], ...]
    component_target_ea: int | None
    captured: bool
    preopt_call_eas: tuple[int, ...]
    calls_call_eas: tuple[int, ...]
    mismatch_ea: int | None
    reason: str


def _native_range_is_covered(
    requested: tuple[int, int],
    owned_ranges: Sequence[tuple[int, int]],
) -> bool:
    """Return whether a sorted interval union completely owns one request."""
    start_ea, end_ea = map(int, requested)
    cursor = start_ea
    for owned_start, owned_end in sorted(
        (int(start), int(end)) for start, end in owned_ranges
    ):
        if owned_end <= cursor:
            continue
        if owned_start > cursor:
            break
        cursor = max(cursor, owned_end)
        if cursor >= end_ea:
            return True
    return False


def _call_companion_native_ranges(
    native_range: tuple[int, int],
    cfg: NativeCfg,
) -> tuple[tuple[int, int], ...]:
    """Exclude only a uniquely proven trailing resolver transfer from CALLS.

    The complete native range remains the pristine PREOPT inventory authority.
    Isolated CALLS generation needs the semantic body and analyzed call owners,
    but exposing its resolver-owned terminal indirect jump lets Hex-Rays
    reclassify that jump as a tail call.  Trim only when the portable CFG proves
    that every outgoing edge of the unique terminal block is the same resolved
    indirect-transfer site.
    """
    start_ea, end_ea = map(int, native_range)
    complete_range = ((start_ea, end_ea),)
    if start_ea <= 0 or end_ea <= start_ea:
        return complete_range
    terminal_blocks = tuple(
        block
        for block in cfg.blocks_by_ea.values()
        if start_ea <= int(block.start_ea) < end_ea
        and int(block.end_ea) == end_ea
        and block.terminal is NativeTerminalKind.STOP
    )
    if len(terminal_blocks) != 1:
        return complete_range
    outgoing_edges = tuple(terminal_blocks[0].outgoing_edges)
    if not outgoing_edges or any(
        edge.kind is not NativeEdgeKind.INDIRECT
        or not edge.resolver_proven
        or edge.provenance != "resolver_proven_native_cut"
        or edge.target_ea is None
        or edge.source_instruction_ea is None
        for edge in outgoing_edges
    ):
        return complete_range
    source_eas = {
        int(edge.source_instruction_ea)
        for edge in outgoing_edges
        if edge.source_instruction_ea is not None
    }
    if len(source_eas) != 1:
        return complete_range
    resolver_exit_ea = next(iter(source_eas))
    if not start_ea < resolver_exit_ea < end_ea:
        return complete_range
    return ((start_ea, resolver_exit_ea),)


def prepare_requested_detached_call_companions(
    state: ResolverSessionState,
) -> tuple[CallCompanionPreparationOutcome, ...]:
    """Generate exact CALLS components requested by canonical preparation.

    This runs only between top-level decompilations.  The current live MBA is
    never retained or mutated: a failed canonical preparation queues portable
    native ranges, the manager generates detached CALLS authority here, and
    the controlled follow-up consumes that authority on a fresh MBA.
    """
    requested_ranges = tuple(state.pending_call_companion_ranges)
    if not requested_ranges:
        return ()
    resolution = state.portable_evidence.computed_goto_resolution
    source = state.portable_evidence.prepatch_preopt_union_source
    if not isinstance(resolution, ComputedGotoResolution) or not isinstance(
        source, _PrepatchPreoptUnionSource
    ):
        return tuple(
            CallCompanionPreparationOutcome(
                native_range=native_range,
                calls_native_ranges=(),
                component_target_ea=None,
                captured=False,
                preopt_call_eas=(),
                calls_call_eas=(),
                mismatch_ea=None,
                reason="portable_preopt_union_source_missing",
            )
            for native_range in requested_ranges
        )
    key = int(resolution.function_ea)
    if state.snippet_capture_active or not state.begin_snippet_capture(key):
        return tuple(
            CallCompanionPreparationOutcome(
                native_range=native_range,
                calls_native_ranges=(),
                component_target_ea=None,
                captured=False,
                preopt_call_eas=(),
                calls_call_eas=(),
                mismatch_ea=None,
                reason="snippet_capture_active",
            )
            for native_range in requested_ranges
        )

    outcomes: list[CallCompanionPreparationOutcome] = []
    try:
        for native_range in requested_ranges:
            normalized_range = (
                int(native_range[0]),
                int(native_range[1]),
            )
            if not _native_range_is_covered(
                normalized_range,
                source.native_ranges,
            ):
                outcomes.append(
                    CallCompanionPreparationOutcome(
                        native_range=normalized_range,
                        calls_native_ranges=(),
                        component_target_ea=None,
                        captured=False,
                        preopt_call_eas=(),
                        calls_call_eas=(),
                        mismatch_ea=None,
                        reason="requested_range_outside_preopt_union",
                    )
                )
                continue
            component_owned_entries = tuple(
                int(entry_ea)
                for entry_ea in source.imported_block_entry_eas
                if normalized_range[0] <= int(entry_ea) < normalized_range[1]
            )
            if not component_owned_entries:
                outcomes.append(
                    CallCompanionPreparationOutcome(
                        native_range=normalized_range,
                        calls_native_ranges=(),
                        component_target_ea=None,
                        captured=False,
                        preopt_call_eas=(),
                        calls_call_eas=(),
                        mismatch_ea=None,
                        reason="requested_range_has_no_owned_entry",
                    )
                )
                continue
            component_target_ea = int(min(component_owned_entries))
            calls_native_ranges = _call_companion_native_ranges(
                normalized_range,
                source.cfg,
            )
            owned_entries = tuple(
                entry_ea
                for entry_ea in component_owned_entries
                if any(
                    int(start_ea) <= entry_ea < int(end_ea)
                    for start_ea, end_ea in calls_native_ranges
                )
            )
            if component_target_ea not in owned_entries:
                outcomes.append(
                    CallCompanionPreparationOutcome(
                        native_range=normalized_range,
                        calls_native_ranges=calls_native_ranges,
                        component_target_ea=component_target_ea,
                        captured=False,
                        preopt_call_eas=(),
                        calls_call_eas=(),
                        mismatch_ea=None,
                        reason="calls_range_excludes_component_target",
                    )
                )
                continue
            ranges = ida_hexrays.mba_ranges_t()
            for calls_start_ea, calls_end_ea in calls_native_ranges:
                ranges.ranges.push_back(
                    idaapi.range_t(
                        int(calls_start_ea),
                        int(calls_end_ea),
                    )
                )
            failure = ida_hexrays.hexrays_failure_t()
            try:
                calls_mba = _generate_microcode_without_d810(
                    ida_hexrays.gen_microcode,
                    ranges,
                    failure,
                    None,
                    int(ida_hexrays.DECOMP_NO_WAIT | ida_hexrays.DECOMP_ALL_BLKS),
                    int(ida_hexrays.MMAT_CALLS),
                )
            except Exception:
                logger.info(
                    "requested CALLS companion generation failed: "
                    "func=0x%X range=[0x%X,0x%X)",
                    key,
                    normalized_range[0],
                    normalized_range[1],
                    exc_info=True,
                )
                calls_mba = None
            if calls_mba is None:
                outcomes.append(
                    CallCompanionPreparationOutcome(
                        native_range=normalized_range,
                        calls_native_ranges=calls_native_ranges,
                        component_target_ea=component_target_ea,
                        captured=False,
                        preopt_call_eas=(),
                        calls_call_eas=(),
                        mismatch_ea=None,
                        reason=(f"calls_generation_failed:{failure.desc()}"),
                    )
                )
                continue
            calls_mba.build_graph()
            stack_offsets = {
                int(instruction_ea): tuple(int(value) for value in offsets)
                for instruction_ea, offsets in dict(
                    resolution.native_stack_frame_offsets
                ).items()
                if any(
                    int(start_ea) <= int(instruction_ea) < int(end_ea)
                    for start_ea, end_ea in calls_native_ranges
                )
            }
            capture = capture_preopt_union_call_companion_template(
                key,
                int(source.primary_seed_ea),
                component_target_ea,
                calls_mba,
                normalized_range,
                calls_native_ranges=calls_native_ranges,
                owned_block_entry_eas=owned_entries,
                native_stack_frame_offsets_by_ea=stack_offsets,
            )
            outcome = CallCompanionPreparationOutcome(
                native_range=normalized_range,
                calls_native_ranges=calls_native_ranges,
                component_target_ea=component_target_ea,
                captured=bool(capture.captured),
                preopt_call_eas=tuple(int(ea) for ea in capture.call_eas),
                calls_call_eas=tuple(int(ea) for ea in capture.observed_call_eas),
                mismatch_ea=(
                    None if capture.mismatch_ea is None else int(capture.mismatch_ea)
                ),
                reason=str(capture.reason or "captured"),
            )
            outcomes.append(outcome)
            if outcome.captured:
                state.acknowledge_call_companion_range(normalized_range)
    finally:
        state.finish_snippet_capture()
    return tuple(outcomes)


def _live_mba_native_eas(
    mba: object,
    *,
    imported_instruction_origins: tuple[tuple[int, int], ...] = (),
) -> frozenset[int]:
    """Enumerate instruction-backed MBA EAs with imported origins rebound.

    An empty ``BLT_XTRN`` block names an address outside the generated MBA; its
    start EA is a frontier placeholder, not proof that the target body is live.
    Require at least one microinstruction before admitting a block start.
    """
    origins = {
        int(imported_ea): int(native_ea)
        for imported_ea, native_ea in imported_instruction_origins
    }
    live_eas: set[int] = set()
    for serial in range(int(mba.qty)):
        block = mba.get_mblock(serial)
        if block is None:
            continue
        instruction = block.head
        start_ea = int(block.start)
        if instruction is not None and 0 < start_ea < 0xFFFFFFFFFFFFFFFF:
            live_eas.add(origins.get(start_ea, start_ea))
        while instruction is not None:
            instruction_ea = int(instruction.ea)
            if 0 < instruction_ea < 0xFFFFFFFFFFFFFFFF:
                live_eas.add(origins.get(instruction_ea, instruction_ea))
            if instruction is block.tail or instruction == block.tail:
                break
            instruction = instruction.next
    return frozenset(live_eas)


def _terminal_return_carrier_capture_identities(
    state: ResolverSessionState,
    request: TerminalReturnCarrierRequest,
    *,
    terminal_return_ea: int,
) -> tuple[StableBlockIdentity, StableBlockIdentity] | None:
    """Bind one carrier request to its unique exact state-route anchors."""
    routes = tuple(
        route
        for route in state.portable_evidence.state_write_routes
        if int(route.source_write_ea) == int(request.source_handler_ea)
        and int(route.state_var_reg) == int(request.state_var_reg)
        and (int(route.state_constant) & _MASK32)
        == (int(request.state_constant) & _MASK32)
        and int(route.target_ea) == int(request.terminal_target_ea)
        and int(request.source_handler_ea) in route.write_identity.exact_instruction_eas
        and int(request.terminal_target_ea)
        in route.target_identity.exact_instruction_eas
    )
    if len(routes) != 1:
        return None
    route = routes[0]
    capture_exact_eas = tuple(
        dict.fromkeys(
            (
                int(request.source_handler_ea),
                *(int(ea) for ea in route.corridor_instruction_eas),
            )
        )
    )
    capture_identity = StableBlockIdentity.from_intervals(
        (
            *route.write_identity.native_ranges.intervals,
            *(NativeEaInterval(ea, ea + 1) for ea in capture_exact_eas),
        ),
        native_key=state.native_key,
        exact_instruction_eas=capture_exact_eas,
    )
    terminal_ea = int(request.terminal_target_ea)
    exact_return_ea = int(terminal_return_ea)
    terminal_exact_eas = tuple(
        sorted(
            {
                *route.target_identity.exact_instruction_eas,
                terminal_ea,
                exact_return_ea,
            }
        )
    )
    terminal_identity = StableBlockIdentity.from_intervals(
        (
            *route.target_identity.native_ranges.intervals,
            NativeEaInterval(terminal_ea, terminal_ea + 1),
            NativeEaInterval(exact_return_ea, exact_return_ea + 1),
        ),
        native_key=state.native_key,
        exact_instruction_eas=terminal_exact_eas,
    )
    return capture_identity, terminal_identity


def _capture_terminal_return_carrier_requests(
    state: ResolverSessionState,
    function_ea: int,
    requests: tuple[TerminalReturnCarrierRequest, ...],
) -> int:
    """Capture pending terminal carriers into lifecycle-owned portable evidence."""
    import ida_hexrays  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    from d810.hexrays.mutation.detached_handler_island import (
        capture_terminal_return_carrier_evidence,
    )

    existing_requests = {
        carrier.request for carrier in state.portable_evidence.terminal_return_carriers
    }
    captured = []
    for request in requests:
        if request in existing_requests:
            continue
        terminal_return_ea = _native_return_epilogue_instruction_ea(
            int(request.terminal_target_ea)
        )
        if terminal_return_ea is None:
            logger.info(
                "terminal return-carrier capture abstained: source=0x%X "
                "target=0x%X reason=target_not_epilogue",
                int(request.source_handler_ea),
                int(request.terminal_target_ea),
            )
            continue
        identities = _terminal_return_carrier_capture_identities(
            state,
            request,
            terminal_return_ea=int(terminal_return_ea),
        )
        if identities is None:
            logger.info(
                "terminal return-carrier capture abstained: source=0x%X "
                "target=0x%X reason=no_unique_state_route_identity",
                int(request.source_handler_ea),
                int(request.terminal_target_ea),
            )
            continue
        capture_identity, terminal_identity = identities
        source_end_ea = _block_end(int(request.source_handler_ea))
        if int(source_end_ea) <= int(request.source_handler_ea):
            continue
        ranges = ida_hexrays.mba_ranges_t()
        ranges.ranges.push_back(
            idaapi.range_t(
                int(request.source_handler_ea),
                int(source_end_ea),
            )
        )
        failure = ida_hexrays.hexrays_failure_t()
        try:
            snippet = ida_hexrays.gen_microcode(
                ranges,
                failure,
                None,
                int(ida_hexrays.DECOMP_NO_WAIT),
                ida_hexrays.MMAT_LOCOPT,
            )
        except Exception:
            logger.info(
                "terminal return-carrier LOCOPT generation failed: "
                "source=0x%X end=0x%X",
                int(request.source_handler_ea),
                int(source_end_ea),
                exc_info=True,
            )
            snippet = None
        evidence = (
            None
            if snippet is None
            else capture_terminal_return_carrier_evidence(
                function_ea,
                request,
                snippet,
                capture_identity=capture_identity,
                terminal_identity=terminal_identity,
                terminal_return_ea=int(terminal_return_ea),
            )
        )
        if evidence is None:
            logger.info(
                "terminal return-carrier capture abstained: source=0x%X "
                "target=0x%X state=0x%X reason=no_unique_portable_evidence",
                int(request.source_handler_ea),
                int(request.terminal_target_ea),
                int(request.state_constant) & _MASK32,
            )
            continue
        captured.append(evidence)
        logger.info(
            "terminal return-carrier evidence captured: func=0x%X source=0x%X "
            "target=0x%X state=0x%X blocks=%d",
            function_ea,
            int(request.source_handler_ea),
            int(request.terminal_target_ea),
            int(request.state_constant) & _MASK32,
            int(snippet.qty),
        )
    if captured:
        _merge_terminal_return_carriers(state, tuple(captured))
    return len(captured)


def prepare_terminal_return_carrier_evidence(state: ResolverSessionState) -> int:
    """Consume pending carrier requests into portable session evidence."""
    resolution = state.portable_evidence.computed_goto_resolution
    if not isinstance(resolution, ComputedGotoResolution):
        return 0
    key = int(resolution.function_ea)
    resolver_evidence = state.native_preanalysis.resolver_evidence
    requests = (
        ()
        if resolver_evidence is None
        else resolver_evidence.terminal_return_carrier_requests
    )
    if not requests or state.snippet_capture_active:
        return 0
    if not state.begin_snippet_capture(key):
        return 0
    try:
        return _capture_terminal_return_carrier_requests(state, key, requests)
    finally:
        state.finish_snippet_capture()


def _capture_preopt_union_terminal_return_carriers(
    state: ResolverSessionState,
    *,
    function_ea: int,
    mba: object,
    transfers: tuple[MaterializedIndirectTransfer, ...],
) -> int:
    """Capture exact terminal carriers while the pristine union MBA is live."""
    state_var_reg = unique_materialized_state_register(transfers)
    if state_var_reg is None:
        return 0
    terminal_return_eas_by_target: dict[int, int] = {}
    for transfer in transfers:
        if (
            transfer.resolver_kind != "static_handler_entry_route"
            or transfer.selector_state_var_reg is None
            or int(transfer.selector_state_var_reg) != int(state_var_reg)
            or transfer.selector_state_constant is None
            or len(transfer.target_eas) != 1
        ):
            continue
        terminal_target_ea = int(transfer.target_eas[0])
        terminal_return_ea = _native_return_epilogue_instruction_ea(terminal_target_ea)
        if terminal_return_ea is not None:
            terminal_return_eas_by_target[terminal_target_ea] = int(terminal_return_ea)
    terminal_target_eas = tuple(sorted(terminal_return_eas_by_target))
    if not terminal_target_eas:
        return 0

    write_eas_by_state: dict[int, list[int]] = {}
    for route in state.portable_evidence.state_write_routes:
        if int(route.state_var_reg) != int(state_var_reg):
            continue
        write_eas_by_state.setdefault(
            int(route.state_constant) & _MASK32,
            [],
        ).append(int(route.source_write_ea))
    requests = plan_terminal_return_carrier_requests_from_state_writes(
        transfers,
        write_eas_by_state,
        terminal_target_eas,
        state_var_reg=int(state_var_reg),
    )
    if requests:
        state.native_preanalysis.merge_terminal_return_carrier_requests(
            state.native_key,
            requests,
        )

    from d810.hexrays.mutation.detached_handler_island import (
        capture_terminal_return_carrier_evidence,
    )

    captured = []
    for request in requests:
        terminal_return_ea = terminal_return_eas_by_target.get(
            int(request.terminal_target_ea)
        )
        if terminal_return_ea is None:
            continue
        identities = _terminal_return_carrier_capture_identities(
            state,
            request,
            terminal_return_ea=int(terminal_return_ea),
        )
        if identities is None:
            continue
        capture_identity, terminal_identity = identities
        evidence = capture_terminal_return_carrier_evidence(
            int(function_ea),
            request,
            mba,
            capture_identity=capture_identity,
            terminal_identity=terminal_identity,
            terminal_return_ea=int(terminal_return_ea),
        )
        if evidence is not None:
            captured.append(evidence)
    if not captured:
        return 0
    _merge_terminal_return_carriers(state, tuple(captured))
    logger.info(
        "PREOPT union captured portable terminal return carriers: %s",
        [
            (
                hex(int(evidence.request.source_handler_ea)),
                hex(int(evidence.request.terminal_target_ea)),
                hex(int(evidence.request.state_constant)),
            )
            for evidence in captured
        ],
    )
    return len(captured)


def _unique_native_register_indirect_exit(
    ranges: tuple[tuple[int, int], ...],
) -> tuple[int, int] | None:
    """Return one native range start and its unique ``jmp reg`` exit."""
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    exits: set[tuple[int, int]] = set()
    insn = ida_ua.insn_t()
    for start_ea, end_ea in ranges:
        ea = int(start_ea)
        while ea < int(end_ea):
            size = int(ida_ua.decode_insn(insn, ea))
            if size <= 0:
                break
            if (idaapi.print_insn_mnem(ea) or "").lower() == "jmp" and insn.ops[
                0
            ].type == idaapi.o_reg:
                exits.add((int(start_ea), ea))
            ea += size
    return next(iter(exits)) if len(exits) == 1 else None


def _plan_detached_resolver_cut_boundary_ports(
    transfers: tuple[MaterializedIndirectTransfer, ...],
    *,
    target_ea: int,
    ranges: tuple[tuple[int, int], ...],
    exit_finder=None,
):
    """Bind one imported handler's unique indirect exit to its proven router."""
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
        make_resolver_cut_boundary_port,
    )

    if exit_finder is None:
        exit_finder = _unique_native_register_indirect_exit
    candidates = {
        int(transfer.dispatcher_entry_ea)
        for transfer in transfers
        if transfer.resolver_kind == "static_equality_candidate"
        and transfer.dispatcher_entry_ea is not None
        and len(transfer.target_eas) == 1
        and int(transfer.target_eas[0]) == int(target_ea)
    }
    native_exit = exit_finder(ranges)
    if len(candidates) != 1 or native_exit is None:
        return ()
    source_block_ea, source_instruction_ea = native_exit
    return (
        make_resolver_cut_boundary_port(
            source_block_ea=int(source_block_ea),
            source_instruction_ea=int(source_instruction_ea),
            target_ea=next(iter(candidates)),
            source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
            target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            provenance="static_equality_candidate_dispatcher_cut",
        ),
    )


def get_prepared_preopt_union_closure(
    state: ResolverSessionState,
) -> PreoptUnionPreparationResult | None:
    """Return this lifecycle session's published PREOPT union preparation."""
    prepared = state.portable_evidence.preopt_union_preparation
    return prepared if isinstance(prepared, PreoptUnionPreparationResult) else None


def _preopt_union_abstention(
    function_ea: int,
    *reasons: str,
) -> PreoptUnionPreparationResult:
    result = PreoptUnionPreparationResult(
        function_ea=int(function_ea),
        prepared=False,
        published=False,
        abstention_reasons=tuple(str(reason) for reason in reasons),
    )
    logger.info(
        "PREOPT union preparation abstained: func=0x%X reasons=%s",
        int(function_ea),
        result.abstention_reasons,
    )
    return result


def _preopt_resolver_cut_eas(
    resolution: ComputedGotoResolution,
    transfers: Sequence[MaterializedIndirectTransfer] = (),
) -> tuple[int, ...]:
    """Keep only native indirect sites not replaced by a two-arm byte patch."""
    return tuple(
        sorted(
            {
                *(
                    int(source_ea)
                    for source_ea, target_eas in resolution.jmp_targets.items()
                    if len({int(target_ea) for target_ea in target_eas}) == 1
                ),
                *(
                    int(transfer.source_jmp_ea)
                    for transfer in transfers
                    if transfer.resolver_kind == "static_handler_exit_route"
                    and len(transfer.target_eas) == 1
                ),
            }
        )
    )


def _preopt_union_internal_successor_eas(
    closure: NativeSemanticClosure,
) -> dict[int, int]:
    """Return unique frontend resolver cuts whose endpoints share the union.

    PREOPT represents an unresolved indirect tail with a synthetic empty
    successor.  Rebinding that sentinel is safe only when one native
    instruction has exactly one resolver-proven target and the target has an
    owned stable-EA entry in the same closure.  Final state-machine routes are
    semantic-lowering evidence and must not enter frontend normalization.
    """
    included = {int(entry_ea) for entry_ea in closure.included_block_eas}
    targets_by_instruction: dict[int, set[int]] = {}
    for edge in closure.proven_import_boundary_edges:
        if edge.source_instruction_ea is None:
            continue
        targets_by_instruction.setdefault(
            int(edge.source_instruction_ea),
            set(),
        ).add(int(edge.target_ea))
    return {
        instruction_ea: next(iter(target_eas))
        for instruction_ea, target_eas in targets_by_instruction.items()
        if len(target_eas) == 1 and next(iter(target_eas)) in included
    }


def _enrich_preopt_union_route_ranges(
    resolution: ComputedGotoResolution,
    transfers: tuple[MaterializedIndirectTransfer, ...],
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Attach stable native ownership to EA-keyed handler routes.

    Multiple proofs may route the same state to the same native handler.  Once
    one proof owns that target's native corridor, reuse its portable ranges for
    an otherwise range-less duplicate.  Re-deriving ownership from a later,
    already-mutated native CFG can incorrectly absorb the dispatcher.  If
    existing proofs conflict, preserve the missing claim so downstream binding
    abstains instead of manufacturing a third identity.
    """
    missing_targets = {
        int(transfer.target_eas[0])
        for transfer in transfers
        if transfer.resolver_kind == "static_handler_entry_route"
        and len(transfer.target_eas) == 1
        and not transfer.owned_native_ranges
    }
    if not missing_targets:
        return transfers
    envelope_end = (
        max(
            (
                int(ea)
                for ea in (
                    *resolution.reachable_eas,
                    *resolution.block_entries,
                )
            ),
            default=int(resolution.function_ea),
        )
        + 0x100
    )
    existing_ranges_by_target: dict[int, set[tuple[tuple[int, int], ...]]] = {}
    for transfer in transfers:
        if (
            transfer.resolver_kind != "static_handler_entry_route"
            or len(transfer.target_eas) != 1
            or not transfer.owned_native_ranges
        ):
            continue
        target_ea = int(transfer.target_eas[0])
        existing_ranges_by_target.setdefault(target_ea, set()).add(
            tuple(
                (int(start_ea), int(end_ea))
                for start_ea, end_ea in transfer.owned_native_ranges
            )
        )

    ranges_by_target: dict[int, tuple[tuple[int, int], ...]] = {}
    for target_ea in sorted(missing_targets):
        existing_claims = existing_ranges_by_target.get(target_ea, set())
        if len(existing_claims) == 1:
            ranges_by_target[target_ea] = next(iter(existing_claims))
            continue
        if existing_claims:
            continue
        ranges_by_target[target_ea] = merge_detached_snippet_ranges(
            _native_residual_fragment_ranges(
                target_ea,
                envelope_start_ea=int(resolution.function_ea),
                envelope_end_ea=int(envelope_end),
                max_blocks=128,
                max_bytes=max(
                    0x100,
                    int(envelope_end) - int(resolution.function_ea),
                ),
                require_indirect=False,
            )
        )
    return tuple(
        (
            replace(
                transfer,
                owned_native_ranges=ranges_by_target.get(
                    int(transfer.target_eas[0]),
                    (),
                ),
            )
            if transfer.resolver_kind == "static_handler_entry_route"
            and len(transfer.target_eas) == 1
            and not transfer.owned_native_ranges
            else transfer
        )
        for transfer in transfers
    )


def _plan_frontend_normalization_union_source(
    resolution: ComputedGotoResolution,
    *,
    transfers: Sequence[MaterializedIndirectTransfer],
    contextual_patch_plans: Sequence[ComputedGotoPatchPlan] = (),
) -> _FrontendNormalizationUnionSource | None:
    """Build the detached closure directly from the portable transfer ledger."""
    key = int(resolution.function_ea)
    selected_contextual_plans = tuple(
        sorted(
            set(contextual_patch_plans),
            key=lambda plan: (
                int(plan.block_entry),
                int(plan.patch_start),
                int(plan.jmp_ea),
            ),
        )
    )
    if any(
        plan not in resolution.contextual_patch_plans
        for plan in selected_contextual_plans
    ):
        logger.info(
            "frontend normalization source abstained: func=0x%X "
            "reason=foreign_contextual_patch_plan",
            key,
        )
        return None
    resolver_targets_by_source = {
        int(source_ea): tuple(sorted({int(target_ea) for target_ea in target_eas}))
        for source_ea, target_eas in resolution.jmp_targets.items()
        if target_eas
    }
    plan_targets_by_source = {
        int(plan.jmp_ea): tuple(
            sorted({int(target_ea) for target_ea in plan.target_eas})
        )
        for plan in resolution.patch_plans
        if plan.target_eas
    }
    if (
        not resolver_targets_by_source
        or plan_targets_by_source != resolver_targets_by_source
    ):
        logger.info(
            "frontend normalization source abstained: func=0x%X "
            "reason=incomplete_transfer_ledger resolver_sites=%s proof_sites=%s",
            key,
            tuple(hex(ea) for ea in sorted(resolver_targets_by_source)),
            tuple(hex(ea) for ea in sorted(plan_targets_by_source)),
        )
        return None
    function = ida_funcs.get_func(key)
    if function is None:
        logger.info(
            "frontend normalization source abstained: func=0x%X "
            "reason=function_not_found",
            key,
        )
        return None
    handler_region = plan_preopt_union_region(transfers)
    if handler_region.abstentions:
        logger.info(
            "frontend normalization source abstained: func=0x%X "
            "reason=handler_seed_ownership rows=%s",
            key,
            tuple(
                (hex(int(row.target_ea)), row.reason.value)
                for row in handler_region.abstentions
            ),
        )
        return None
    handler_ranges_by_entry = {
        int(seed_ea): tuple(
            NativeRange(int(start_ea), int(end_ea))
            for start_ea, end_ea in native_ranges
        )
        for seed_ea, native_ranges in handler_region.seed_native_ranges
    }
    if any(
        sum(
            int(native_range.start_ea) <= int(seed_ea) < int(native_range.end_ea)
            for native_range in native_ranges
        )
        != 1
        for seed_ea, native_ranges in handler_ranges_by_entry.items()
    ):
        logger.info(
            "frontend normalization source abstained: func=0x%X "
            "reason=handler_seed_outside_owned_range",
            key,
        )
        return None
    handler_entry_eas = tuple(sorted(handler_ranges_by_entry))

    contextual_source_entry_eas = tuple(
        sorted({int(plan.block_entry) for plan in selected_contextual_plans})
    )
    source_entry_eas = tuple(
        sorted(
            {
                *(int(plan.block_entry) for plan in resolution.patch_plans),
                *contextual_source_entry_eas,
            }
        )
    )
    contextual_target_eas = tuple(
        sorted(
            {
                int(target_ea)
                for plan in selected_contextual_plans
                for target_ea in plan.target_eas
            }
        )
    )
    target_eas = tuple(
        sorted(
            {
                int(target_ea)
                for targets in resolver_targets_by_source.values()
                for target_ea in targets
            }
            | {int(target_ea) for target_ea in contextual_target_eas}
        )
    )
    cfg_result = build_native_semantic_cfg(
        function,
        live_native_eas=frozenset(),
        seed_eas=tuple(
            dict.fromkeys((key, *source_entry_eas, *target_eas, *handler_entry_eas))
        ),
        resolver_cut_eas=tuple(sorted(resolver_targets_by_source)),
        resolver_proven_unmarked_entry_eas=(
            *source_entry_eas,
            *target_eas,
            *handler_entry_eas,
        ),
        resolver_target_eas_by_source=resolver_targets_by_source,
    )
    if cfg_result.abstentions:
        logger.info(
            "frontend normalization source abstained: func=0x%X "
            "reason=native_cfg_abstention rows=%s",
            key,
            tuple(
                (
                    abstention.reason.value,
                    hex(int(abstention.entry_ea)),
                    hex(int(abstention.cursor_ea)),
                )
                for abstention in cfg_result.abstentions
            ),
        )
        return None

    seed_provenance_rows = {
        **{
            (int(entry_ea), "computed_transfer_source"): ()
            for entry_ea in source_entry_eas
        },
        **{
            (int(entry_ea), "contextual_computed_transfer_source"): ()
            for entry_ea in contextual_source_entry_eas
        },
        **{(int(entry_ea), "computed_transfer_target"): () for entry_ea in target_eas},
        **{
            (int(entry_ea), "contextual_computed_transfer_target"): ()
            for entry_ea in contextual_target_eas
        },
        **{
            (int(entry_ea), "static_handler_entry_route"): native_ranges
            for entry_ea, native_ranges in handler_ranges_by_entry.items()
        },
    }
    seed_provenance = tuple(
        ResolverProvenHandlerEntry(
            entry_ea=int(entry_ea),
            provenance=provenance,
            owned_native_ranges=owned_native_ranges,
        )
        for (
            entry_ea,
            provenance,
        ), owned_native_ranges in sorted(
            seed_provenance_rows.items(),
            key=lambda item: (int(item[0][0]), str(item[0][1])),
        )
    )
    closure = plan_native_semantic_closure(
        cfg_result.cfg,
        seed_provenance,
    )
    required_entries = frozenset((*source_entry_eas, *target_eas, *handler_entry_eas))
    missing_entries = required_entries - set(closure.included_block_eas)
    if closure.abstentions or missing_entries or not closure.native_ranges:
        logger.info(
            "frontend normalization source abstained: func=0x%X "
            "reason=semantic_closure_abstention rows=%s missing=%s",
            key,
            tuple(
                (
                    abstention.reason.value,
                    (
                        None
                        if abstention.source_block_ea is None
                        else hex(int(abstention.source_block_ea))
                    ),
                    (
                        None
                        if abstention.target_ea is None
                        else hex(int(abstention.target_ea))
                    ),
                )
                for abstention in closure.abstentions
            ),
            tuple(hex(ea) for ea in sorted(missing_entries)),
        )
        return None

    normalized_ranges = tuple(
        (int(native_range.start_ea), int(native_range.end_ea))
        for native_range in closure.native_ranges
    )
    region = PreoptUnionRegionPlan(
        seed_eas=target_eas,
        seed_native_ranges=tuple(
            (int(target_ea), normalized_ranges) for target_ea in target_eas
        ),
        primary_seed_ea=int(target_eas[0]),
        native_ranges=normalized_ranges,
        abstentions=(),
    )
    return _FrontendNormalizationUnionSource(
        region=region,
        cfg=cfg_result.cfg,
        closure=closure,
    )


def _capture_prepatch_preopt_union_source(
    state: ResolverSessionState,
    resolution: ComputedGotoResolution,
    transfers: tuple[MaterializedIndirectTransfer, ...],
) -> bool:
    """Capture one detached source union from portable computed-transfer proof."""
    key = int(resolution.function_ea)
    prepatch_source = state.portable_evidence.prepatch_preopt_union_source
    if prepatch_source is not None or state.snippet_capture_active:
        return prepatch_source is not None

    def abstain(reason: str, detail: object = ()) -> bool:
        logger.info(
            "PREOPT prepatch source abstained: func=0x%X reason=%s detail=%s",
            key,
            reason,
            detail,
        )
        return False

    enriched = _enrich_preopt_union_route_ranges(resolution, transfers)
    _discover_static_state_write_routes(state, resolution, enriched)
    source_plan = _plan_frontend_normalization_union_source(
        resolution,
        transfers=enriched,
        contextual_patch_plans=(
            state.portable_evidence.promoted_contextual_patch_plans
        ),
    )
    if source_plan is None:
        return abstain("portable_union_source")
    region = source_plan.region
    native_cfg = source_plan.cfg
    closure = source_plan.closure
    capture_boundary_ports = DetachedSnippetBoundaryPorts((), ())

    normalized_ranges = tuple(
        (int(native_range.start_ea), int(native_range.end_ea))
        for native_range in closure.native_ranges
    )
    terminal_return_entry_eas = tuple(
        int(entry_ea)
        for entry_ea in closure.included_block_eas
        if native_cfg.blocks_by_ea[int(entry_ea)].terminal is NativeTerminalKind.RETURN
    )
    required_generation_entry_eas = tuple(
        dict.fromkeys((*region.seed_eas, *terminal_return_entry_eas))
    )
    generation_ranges = _preopt_generation_ranges_with_entry_prefix(
        key,
        tuple(
            (int(native_range.start_ea), int(native_range.end_ea))
            for native_range in plan_native_generation_ranges(
                closure,
                required_entry_eas=required_generation_entry_eas,
            )
        ),
    )
    source_entry_eas = tuple(
        dict.fromkeys(int(plan.block_entry) for plan in resolution.patch_plans)
    )
    logger.info(
        "frontend normalization source ranges: func=0x%X sources=%s seeds=%s "
        "blocks=%s owned=%s generated=%s",
        key,
        tuple(hex(int(source_ea)) for source_ea in source_entry_eas),
        tuple(hex(int(seed_ea)) for seed_ea in region.seed_eas),
        tuple(hex(int(entry_ea)) for entry_ea in closure.included_block_eas),
        tuple(
            (hex(int(start_ea)), hex(int(end_ea)))
            for start_ea, end_ea in normalized_ranges
        ),
        tuple(
            (hex(int(start_ea)), hex(int(end_ea)))
            for start_ea, end_ea in generation_ranges
        ),
    )
    ranges = ida_hexrays.mba_ranges_t()
    for start_ea, end_ea in generation_ranges:
        ranges.ranges.push_back(idaapi.range_t(start_ea, end_ea))
    failure = ida_hexrays.hexrays_failure_t()
    if not state.begin_snippet_capture(key):
        return False
    try:
        preopt_mba = _generate_microcode_without_d810(
            ida_hexrays.gen_microcode,
            ranges,
            failure,
            None,
            int(ida_hexrays.DECOMP_NO_WAIT | ida_hexrays.DECOMP_ALL_BLKS),
            int(ida_hexrays.MMAT_PREOPTIMIZED),
        )
        if preopt_mba is None:
            return abstain("preopt_generation_failed", failure.desc())
        preopt_mba.build_graph()
        _capture_preopt_entry_bridge_evidence(state, preopt_mba)
        authoritative_stack_offsets = _static_stack_carrier_frame_offset_overrides(
            resolution.conditional_state_choices,
            consumer_load_eas_by_displacement=(
                _static_stack_carrier_consumer_load_eas(resolution)
            ),
            native_stack_frame_offsets_by_ea=dict(
                resolution.native_stack_frame_offsets
            ),
        )
        if not capture_preopt_union_snippet_template(
            key,
            int(region.primary_seed_ea),
            preopt_mba,
            normalized_ranges,
            boundary_ports=capture_boundary_ports,
            owned_block_entry_eas=tuple(closure.included_block_eas),
            terminal_return_entry_eas=terminal_return_entry_eas,
            resolver_proven_internal_successor_eas=(
                _preopt_union_internal_successor_eas(closure)
            ),
            native_stack_frame_offsets_by_ea=dict(
                resolution.native_stack_frame_offsets
            ),
            authoritative_stack_frame_offsets_by_ea=(authoritative_stack_offsets),
        ):
            return abstain("preopt_capture_failed")
        _capture_preopt_union_terminal_return_carriers(
            state,
            function_ea=key,
            mba=preopt_mba,
            transfers=enriched,
        )
    except Exception:
        logger.info(
            "PREOPT prepatch source capture failed: func=0x%X ranges=%s",
            key,
            generation_ranges,
            exc_info=True,
        )
        return False
    finally:
        state.finish_snippet_capture()

    entry_consumer_routes = _project_preopt_entry_consumer_routes(
        state.portable_evidence.preopt_entry_bridges,
        enriched,
        consumer_load_eas_by_displacement=(
            _static_stack_carrier_consumer_load_eas(resolution)
        ),
        native_cfg=native_cfg,
    )
    published_transfers = tuple(dict.fromkeys((*enriched, *entry_consumer_routes)))
    source = _PrepatchPreoptUnionSource(
        primary_seed_ea=int(region.primary_seed_ea),
        seed_eas=tuple(int(seed_ea) for seed_ea in region.seed_eas),
        seed_native_ranges=tuple(region.seed_native_ranges),
        native_ranges=normalized_ranges,
        imported_block_entry_eas=tuple(closure.included_block_eas),
        cfg=native_cfg,
        closure=closure,
    )
    _merge_native_facts(
        state,
        native_cfg=source.cfg,
        semantic_closure=source.closure,
        transfers=published_transfers,
    )
    state.native_preanalysis.merge_entry_consumer_routes(
        state.native_key,
        entry_consumer_routes,
    )
    state.native_preanalysis.set_prepatch_preopt_union_source(
        state.native_key,
        source,
    )
    logger.info(
        "PREOPT prepatch source captured: func=0x%X primary=0x%X "
        "seeds=%s ranges=%s owned_entries=%s",
        key,
        int(region.primary_seed_ea),
        [hex(int(seed_ea)) for seed_ea in region.seed_eas],
        [(hex(start_ea), hex(end_ea)) for start_ea, end_ea in normalized_ranges],
        [hex(int(entry_ea)) for entry_ea in closure.included_block_eas],
    )
    return True


def _preopt_generation_ranges_with_entry_prefix(
    function_ea: int,
    generation_ranges: tuple[tuple[int, int], ...],
) -> tuple[tuple[int, int], ...]:
    """Generate the pristine entry corridor without importing it into union."""
    normalized = tuple(
        sorted(
            set(
                (int(start_ea), int(end_ea))
                for start_ea, end_ea in generation_ranges
                if int(end_ea) > int(start_ea)
            )
        )
    )
    if not normalized:
        return ()
    first_start = int(normalized[0][0])
    entry_ea = int(function_ea)
    if entry_ea >= first_start:
        return normalized
    return ((entry_ea, first_start), *normalized)


def _static_prepatch_union_source_transfers(
    resolution: ComputedGotoResolution,
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Recover source routes while every native computed goto is still intact."""
    equality_envelope_end = (
        max(
            (int(ea) for ea in (*resolution.reachable_eas, *resolution.block_entries)),
            default=int(resolution.function_ea),
        )
        + 0x100
    )
    native_rows = _native_equality_state_rows(
        int(resolution.function_ea),
        envelope_end_ea=equality_envelope_end,
    )
    static_transfers = _static_materialized_transfers(resolution)
    static_handler_entry_routes = _recover_static_fixpoint_handler_entry_routes(
        resolution,
        static_transfers,
    )
    native_handler_entry_routes = _recover_prepatch_handler_entry_routes(
        resolution,
        native_rows,
    )
    handler_entry_routes = (
        *static_handler_entry_routes,
        *native_handler_entry_routes,
    )
    static_handler_exit_routes = _recover_prepatch_handler_exit_routes(
        resolution,
        static_transfers,
        handler_entry_routes,
    )
    return _static_materialized_transfer_batch(
        resolution,
        static_transfers=static_transfers,
        equality_transfers=(),
        static_handler_entry_routes=static_handler_entry_routes,
        native_handler_entry_routes=native_handler_entry_routes,
        static_handler_exit_routes=static_handler_exit_routes,
    )


def _preopt_union_boundary_ports(
    closure,
    *,
    live_native_eas: frozenset[int],
    transfers: tuple[MaterializedIndirectTransfer, ...] = (),
    live_mba: object | None = None,
    native_cfg: NativeCfg | None = None,
    entry_consumer_port_diagnostic: dict[str, object] | None = None,
) -> DetachedSnippetBoundaryPorts | None:
    """Convert exact resolver cuts to the existing atomic port contract."""
    imported_entry_eas = {int(entry_ea) for entry_ea in closure.included_block_eas}
    edges_by_source: dict[tuple[int, int], list[object]] = {}
    for edge in closure.proven_import_boundary_edges:
        rejection_reason = None
        if edge.kind is not NativeEdgeKind.INDIRECT:
            rejection_reason = f"edge_kind:{edge.kind.value}"
        elif edge.source_instruction_ea is None:
            rejection_reason = "missing_source_instruction"
        elif int(edge.source_ea) not in imported_entry_eas:
            rejection_reason = "source_not_imported"
        target_ea = int(edge.target_ea)
        target_is_imported = target_ea in imported_entry_eas
        target_is_live = target_ea in live_native_eas
        if not target_is_imported and not target_is_live:
            rejection_reason = "target_neither_imported_nor_live"
        if rejection_reason is not None:
            logger.info(
                "PREOPT union boundary rejected: reason=%s source=0x%X "
                "instruction=%s target=0x%X imported=%s live=%s",
                rejection_reason,
                int(edge.source_ea),
                (
                    "none"
                    if edge.source_instruction_ea is None
                    else f"0x{int(edge.source_instruction_ea):X}"
                ),
                target_ea,
                target_is_imported,
                target_is_live,
            )
            return None
        assert edge.source_instruction_ea is not None
        edges_by_source.setdefault(
            (int(edge.source_ea), int(edge.source_instruction_ea)),
            [],
        ).append(edge)

    def target_owner(target_ea: int) -> DetachedSnippetBoundaryPortOwner | None:
        if int(target_ea) in imported_entry_eas:
            return DetachedSnippetBoundaryPortOwner.IMPORTED
        if int(target_ea) in live_native_eas:
            return DetachedSnippetBoundaryPortOwner.LIVE
        return None

    def conditional_port(
        transfer: MaterializedIndirectTransfer,
        *,
        source_owner: DetachedSnippetBoundaryPortOwner,
        source_block_ea: int | None = None,
        predicate_ea: int | None = None,
        predicate_true_is_taken: bool | None = None,
    ) -> DetachedSnippetConditionalBoundaryPort | None:
        if (
            transfer.condition_code is None
            or transfer.true_target_ea is None
            or transfer.false_target_ea is None
            or transfer.selector_state_var_reg is None
            or transfer.selector_compare_constant is None
        ):
            return None
        true_target_ea = int(transfer.true_target_ea)
        false_target_ea = int(transfer.false_target_ea)
        true_owner = target_owner(true_target_ea)
        false_owner = target_owner(false_target_ea)
        if true_owner is None or false_owner is None:
            return None
        if predicate_true_is_taken is False:
            taken_target_ea = false_target_ea
            fallthrough_target_ea = true_target_ea
            taken_owner = false_owner
            fallthrough_owner = true_owner
        else:
            taken_target_ea = true_target_ea
            fallthrough_target_ea = false_target_ea
            taken_owner = true_owner
            fallthrough_owner = false_owner
        terminal_target_eas = {
            int(target_ea)
            for target_ea in (true_target_ea, false_target_ea)
            for block in (
                (
                    None
                    if native_cfg is None
                    else native_cfg.blocks_by_ea.get(int(target_ea))
                ),
            )
            if block is not None and block.terminal is NativeTerminalKind.RETURN
        }
        equality_target_ea = (
            true_target_ea
            if int(transfer.condition_code) == 4
            else (false_target_ea if int(transfer.condition_code) == 5 else None)
        )
        terminal_return_boundary = bool(
            len(terminal_target_eas) == 1
            and equality_target_ea is not None
            and equality_target_ea in terminal_target_eas
        )
        terminal_state = int(transfer.selector_compare_constant) & _MASK32
        return DetachedSnippetConditionalBoundaryPort(
            source_block_ea=(
                int(transfer.source_block_ea)
                if source_block_ea is None
                else int(source_block_ea)
            ),
            predicate_ea=(
                int(transfer.source_jmp_ea)
                if predicate_ea is None
                else int(predicate_ea)
            ),
            old_taken_target_ea=None,
            old_fallthrough_target_ea=None,
            taken_target_ea=taken_target_ea,
            fallthrough_target_ea=fallthrough_target_ea,
            state_register=(
                int(transfer.selector_state_var_reg)
                if terminal_return_boundary
                else None
            ),
            taken_state=(
                terminal_state
                if terminal_return_boundary and taken_target_ea in terminal_target_eas
                else None
            ),
            fallthrough_state=(
                terminal_state
                if terminal_return_boundary
                and fallthrough_target_ea in terminal_target_eas
                else None
            ),
            source_owner=source_owner,
            taken_target_owner=taken_owner,
            fallthrough_target_owner=fallthrough_owner,
            resolver_kind=(
                "preopt_terminal_return_boundary"
                if terminal_return_boundary
                else "resolver_proven_register_compare_cut"
            ),
            predicate_size=4,
            condition_code=int(transfer.condition_code),
            predicate_register=int(transfer.selector_state_var_reg),
            predicate_constant=(int(transfer.selector_compare_constant) & _MASK32),
            predicate_true_is_taken=predicate_true_is_taken,
        )

    direct_ports: list[DetachedSnippetDirectBoundaryPort] = []
    conditional_ports: list[DetachedSnippetConditionalBoundaryPort] = []
    for (source_ea, source_instruction_ea), edges in sorted(edges_by_source.items()):
        target_eas = {int(edge.target_ea) for edge in edges}
        conditional_candidates = tuple(
            transfer
            for transfer in transfers
            if int(transfer.source_block_ea) == source_ea
            and int(transfer.source_jmp_ea) == source_instruction_ea
            and transfer.condition_code is not None
            and transfer.true_target_ea is not None
            and transfer.false_target_ea is not None
            and transfer.selector_state_var_reg is not None
            and transfer.selector_compare_constant is not None
            and {
                int(transfer.true_target_ea),
                int(transfer.false_target_ea),
            }
            == target_eas
        )
        if len(target_eas) == 2 and len(conditional_candidates) == 1:
            port = conditional_port(
                conditional_candidates[0],
                source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
            )
            if port is None:
                return None
            conditional_ports.append(port)
            continue
        if len(target_eas) != 1:
            logger.info(
                "PREOPT union boundary rejected: reason=unresolved_multitarget_cut "
                "source=0x%X instruction=0x%X targets=%s candidates=%d",
                source_ea,
                source_instruction_ea,
                [hex(target_ea) for target_ea in sorted(target_eas)],
                len(conditional_candidates),
            )
            return None
        target_ea = next(iter(target_eas))
        owner = target_owner(target_ea)
        if owner is None:
            return None
        handler_exit_candidates = tuple(
            transfer
            for transfer in transfers
            if transfer.resolver_kind == "static_handler_exit_route"
            and int(transfer.source_jmp_ea) == source_instruction_ea
            and transfer.target_eas == (target_ea,)
        )
        if (
            len(handler_exit_candidates) == 1
            and handler_exit_candidates[0].dispatcher_envelope_target_eas
        ):
            handler_exit = handler_exit_candidates[0]
            direct_ports.append(
                DetachedSnippetDirectBoundaryPort(
                    source_block_ea=source_ea,
                    source_instruction_ea=source_instruction_ea,
                    endpoint_block_ea=source_ea,
                    old_successor_eas=(),
                    target_ea=target_ea,
                    state_register=handler_exit.selector_state_var_reg,
                    state_constant=handler_exit.selector_state_constant,
                    source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                    endpoint_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                    target_owner=owner,
                    delivery_mode="terminal_goto",
                    resolver_kind="static_handler_exit_route",
                    source_replaces_dispatcher_envelope=True,
                )
            )
        else:
            direct_ports.append(
                make_resolver_cut_boundary_port(
                    source_block_ea=source_ea,
                    source_instruction_ea=source_instruction_ea,
                    target_ea=target_ea,
                    source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                    target_owner=owner,
                    provenance=(edges[0].provenance or "resolver_proven_native_cut"),
                )
            )
    portable_terminal_candidates: dict[
        tuple[int, int],
        list[MaterializedIndirectTransfer],
    ] = {}
    for transfer in transfers:
        if (
            (int(transfer.source_block_ea), int(transfer.source_jmp_ea))
            in edges_by_source
            or int(transfer.source_block_ea) in imported_entry_eas
            or transfer.materialized_predicate_ea is None
            or transfer.condition_code is None
            or transfer.true_target_ea is None
            or transfer.false_target_ea is None
            or transfer.selector_state_var_reg is None
            or transfer.selector_compare_constant is None
            or target_owner(int(transfer.true_target_ea)) is None
            or target_owner(int(transfer.false_target_ea)) is None
        ):
            continue
        source_key = (
            int(transfer.source_block_ea),
            int(transfer.materialized_predicate_ea),
        )
        candidate_port = conditional_port(
            transfer,
            source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            source_block_ea=source_key[0],
            predicate_ea=source_key[1],
            predicate_true_is_taken=True,
        )
        if (
            candidate_port is not None
            and candidate_port.resolver_kind == "preopt_terminal_return_boundary"
        ):
            portable_terminal_candidates.setdefault(source_key, []).append(transfer)
    for source_key, candidates in sorted(portable_terminal_candidates.items()):
        if len(candidates) != 1:
            logger.info(
                "PREOPT union boundary rejected: "
                "reason=ambiguous_portable_terminal_source source=0x%X "
                "instruction=0x%X candidates=%d",
                source_key[0],
                source_key[1],
                len(candidates),
            )
            return None
        port = conditional_port(
            candidates[0],
            source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            source_block_ea=source_key[0],
            predicate_ea=source_key[1],
            predicate_true_is_taken=True,
        )
        if port is None:
            return None
        conditional_ports.append(port)
    live_conditional_ports = _preopt_live_conditional_bridge_boundary_ports(
        transfers,
        live_mba=live_mba,
        live_native_eas=live_native_eas,
        imported_entry_eas=frozenset(imported_entry_eas),
        native_cfg=native_cfg,
    )
    if live_conditional_ports is None:
        return None
    conditional_ports.extend(live_conditional_ports)
    conditional_ports = list(
        _without_replaced_imported_dispatcher_ports(
            tuple(conditional_ports),
            transfers,
            native_cfg=native_cfg,
            diagnostic=entry_consumer_port_diagnostic,
        )
    )
    try:
        return normalize_detached_snippet_boundary_ports(
            tuple(direct_ports),
            tuple(conditional_ports),
        )
    except ValueError as exc:
        logger.info("PREOPT union boundary normalization rejected: %s", exc)
        return None


def _live_block_instruction_eas(block: object) -> tuple[int, ...]:
    instruction = block.head
    result: list[int] = []
    while instruction is not None:
        ea = int(instruction.ea)
        if 0 < ea < 0xFFFFFFFFFFFFFFFF:
            result.append(ea)
        if instruction is block.tail or instruction == block.tail:
            break
        instruction = instruction.next
    return tuple(dict.fromkeys(result))


def _find_unique_live_predicate_block(mba: object, predicate_ea: int) -> object | None:
    """Select the jcond owner when CMOV lowering reuses its EA for a copy."""
    matches = tuple(
        block
        for serial in range(int(mba.qty))
        for block in (mba.get_mblock(serial),)
        if block is not None
        and block.tail is not None
        and int(block.tail.ea) == int(predicate_ea)
        and ida_hexrays.is_mcode_jcond(int(block.tail.opcode))
    )
    return matches[0] if len(matches) == 1 else None


def _preopt_live_conditional_bridge_boundary_ports(
    transfers: tuple[MaterializedIndirectTransfer, ...],
    *,
    live_mba: object | None = None,
    live_native_eas: frozenset[int],
    imported_entry_eas: frozenset[int],
    native_cfg: NativeCfg | None = None,
) -> tuple[DetachedSnippetConditionalBoundaryPort, ...] | None:
    """Project a complete live predicate and both exact state routes to PREOPT.

    The source is deliberately not required to survive in the MBA used for
    preparation.  A later fresh PREOPT import must bind the predicate by its
    stable native EA before applying the port.  Both state-to-handler arms must
    independently exist as residual-route evidence, so this projection cannot
    invent an initial state or infer a return from an unmatched state.
    """
    residual_state_targets = {
        (
            int(transfer.selector_state_constant) & _MASK32,
            int(transfer.target_eas[0]),
        )
        for transfer in transfers
        if transfer.resolver_kind == "residual_state_route_evidence"
        and transfer.selector_state_constant is not None
        and len(transfer.target_eas) == 1
    }
    live_predicate_proofs: dict[int, tuple[object | None, bool | None]] = {}

    def exact_live_predicate_proof(
        transfer: MaterializedIndirectTransfer,
    ) -> tuple[object | None, bool | None]:
        transfer_key = id(transfer)
        cached = live_predicate_proofs.get(transfer_key)
        if cached is not None:
            return cached
        predicate_ea = int(transfer.source_jmp_ea)
        live_source = (
            None
            if live_mba is None
            else _find_unique_live_predicate_block(live_mba, predicate_ea)
        )
        if live_source is None:
            proof = (None, None)
        else:
            is_flag_only = bool(
                transfer.resolver_kind == "conditional_handler_bridge"
                and transfer.predicate_preserve_live
                and transfer.predicate_register is None
                and transfer.predicate_compare_register is None
            )
            orientation = exact_live_predicate_true_is_taken(
                live_source,
                predicate_ea=predicate_ea,
                condition_code=int(transfer.condition_code),
                predicate_register=(
                    None if is_flag_only else transfer.predicate_register
                ),
                predicate_size=None if is_flag_only else transfer.predicate_size,
                predicate_constant=(
                    None
                    if is_flag_only
                    or (
                        transfer.resolver_kind
                        == "static_conditional_state_choice_bridge"
                        and transfer.predicate_register is None
                        and transfer.predicate_size is None
                    )
                    else (
                        0
                        if transfer.predicate_compare_constant is None
                        else int(transfer.predicate_compare_constant)
                    )
                ),
            )
            proof = (
                live_source,
                orientation if orientation in (True, False) else None,
            )
        live_predicate_proofs[transfer_key] = proof
        return proof

    eligible_live_bridge_semantics_by_source: dict[
        int,
        set[frozenset[tuple[int, int]]],
    ] = {}
    for transfer in transfers:
        if (
            transfer.resolver_kind != "conditional_handler_bridge"
            or transfer.condition_code not in {2, 3, 4, 5, 6, 7, 12, 13, 14, 15}
            or transfer.predicate_true_state is None
            or transfer.predicate_false_state is None
            or transfer.true_target_ea is None
            or transfer.false_target_ea is None
            or transfer.predicate_compare_register is not None
            or (
                not (
                    transfer.predicate_preserve_live
                    and transfer.predicate_register is None
                )
                and (
                    transfer.predicate_register is None
                    or transfer.predicate_size is None
                    or int(transfer.predicate_size) <= 0
                )
            )
        ):
            continue
        live_source = (
            None
            if live_mba is None
            else _find_unique_live_predicate_block(
                live_mba,
                int(transfer.source_jmp_ea),
            )
        )
        if live_source is None:
            continue
        if transfer.predicate_preserve_live:
            _live_source, live_orientation = exact_live_predicate_proof(transfer)
            if live_orientation not in (True, False):
                continue
        else:
            true_state = int(transfer.predicate_true_state) & _MASK32
            false_state = int(transfer.predicate_false_state) & _MASK32
            if (
                transfer.predicate_true_is_taken not in (True, False)
                or (true_state, int(transfer.true_target_ea))
                not in residual_state_targets
                or (false_state, int(transfer.false_target_ea))
                not in residual_state_targets
            ):
                continue
        eligible_live_bridge_semantics_by_source.setdefault(
            int(transfer.source_jmp_ea),
            set(),
        ).add(
            frozenset(
                {
                    (
                        int(transfer.predicate_true_state) & _MASK32,
                        int(transfer.true_target_ea),
                    ),
                    (
                        int(transfer.predicate_false_state) & _MASK32,
                        int(transfer.false_target_ea),
                    ),
                }
            )
        )

    def target_owner(
        target_ea: int,
    ) -> DetachedSnippetBoundaryPortOwner | None:
        if int(target_ea) in imported_entry_eas:
            return DetachedSnippetBoundaryPortOwner.IMPORTED
        if int(target_ea) in live_native_eas:
            return DetachedSnippetBoundaryPortOwner.LIVE
        return None

    candidates: dict[tuple[int, int], set[DetachedSnippetConditionalBoundaryPort]] = {}
    for transfer in transfers:
        is_static_state_choice = (
            transfer.resolver_kind == "static_conditional_state_choice_bridge"
        )
        is_exact_live_bridge = bool(
            transfer.resolver_kind == "conditional_handler_bridge"
            and transfer.predicate_preserve_live
        )
        is_flag_only_live_bridge = bool(
            is_exact_live_bridge
            and transfer.predicate_register is None
            and transfer.predicate_compare_register is None
        )
        if (
            transfer.resolver_kind
            not in {
                "conditional_handler_bridge",
                "static_conditional_state_choice_bridge",
            }
            or transfer.condition_code not in {2, 3, 4, 5, 6, 7, 12, 13, 14, 15}
            or transfer.true_target_ea is None
            or transfer.false_target_ea is None
            or transfer.predicate_true_state is None
            or transfer.predicate_false_state is None
            or transfer.predicate_compare_register is not None
            or (
                not is_static_state_choice
                and not is_flag_only_live_bridge
                and (
                    transfer.predicate_register is None
                    or transfer.predicate_size is None
                    or int(transfer.predicate_size) <= 0
                )
            )
        ):
            continue
        if is_static_state_choice:
            static_semantics = frozenset(
                {
                    (
                        int(transfer.predicate_true_state) & _MASK32,
                        int(transfer.true_target_ea),
                    ),
                    (
                        int(transfer.predicate_false_state) & _MASK32,
                        int(transfer.false_target_ea),
                    ),
                }
            )
            if static_semantics in eligible_live_bridge_semantics_by_source.get(
                int(transfer.source_jmp_ea),
                set(),
            ):
                continue
        true_target_ea = int(transfer.true_target_ea)
        false_target_ea = int(transfer.false_target_ea)
        true_state = int(transfer.predicate_true_state) & _MASK32
        false_state = int(transfer.predicate_false_state) & _MASK32
        if (
            true_target_ea == false_target_ea
            or true_state == false_state
            or (
                not is_static_state_choice
                and not is_exact_live_bridge
                and (
                    (true_state, true_target_ea) not in residual_state_targets
                    or (false_state, false_target_ea) not in residual_state_targets
                )
            )
        ):
            continue
        true_owner = target_owner(true_target_ea)
        false_owner = target_owner(false_target_ea)
        if (
            true_owner is None
            or false_owner is None
            or DetachedSnippetBoundaryPortOwner.IMPORTED
            not in {true_owner, false_owner}
        ):
            continue
        predicate_ea = int(transfer.source_jmp_ea)
        source_block_ea = int(transfer.source_block_ea)
        predicate_true_is_taken = transfer.predicate_true_is_taken
        if is_static_state_choice or is_exact_live_bridge:
            live_source, live_predicate_orientation = exact_live_predicate_proof(
                transfer
            )
            native_static_predicate_proven = False
            if (
                live_source is None
                and is_static_state_choice
                and predicate_true_is_taken in (True, False)
                and native_cfg is not None
            ):
                native_predicate_blocks = tuple(
                    block
                    for block in native_cfg.blocks_by_ea.values()
                    if int(block.start_ea) <= predicate_ea < int(block.end_ea)
                )
                if len(native_predicate_blocks) == 1:
                    native_predicate = native_predicate_blocks[0]
                    native_taken_edges = tuple(
                        edge
                        for edge in native_predicate.outgoing_edges
                        if edge.kind is NativeEdgeKind.CONDITIONAL_TRUE
                        and edge.target_ea is not None
                        and edge.source_instruction_ea is not None
                        and int(edge.source_instruction_ea) == predicate_ea
                    )
                    native_fallthrough_edges = tuple(
                        edge
                        for edge in native_predicate.outgoing_edges
                        if edge.kind is NativeEdgeKind.CONDITIONAL_FALSE
                        and edge.target_ea is not None
                        and edge.source_instruction_ea is not None
                        and int(edge.source_instruction_ea) == predicate_ea
                    )
                    complete_native_fork = bool(
                        len(native_taken_edges) == 1
                        and len(native_fallthrough_edges) == 1
                        and int(native_taken_edges[0].target_ea)
                        != int(native_fallthrough_edges[0].target_ea)
                    )
                    one_way_native_shape = bool(
                        len(native_predicate.outgoing_edges) == 1
                        and native_predicate.outgoing_edges[0].kind
                        is NativeEdgeKind.DIRECT_JUMP
                        and native_predicate.outgoing_edges[0].target_ea is not None
                        and (
                            native_predicate.outgoing_edges[0].source_instruction_ea
                            is None
                            or int(
                                native_predicate.outgoing_edges[0].source_instruction_ea
                            )
                            == predicate_ea
                        )
                    )
                    # IDA's native flow graph may omit an unreferenced
                    # fallthrough even though isolated PREOPT generation still
                    # retains the exact jcc.  Portable state-choice evidence
                    # supplies the semantic arms; the template importer must
                    # still revalidate the exact predicate and both successors
                    # before applying the atomic mutation.
                    native_static_predicate_proven = bool(
                        complete_native_fork or one_way_native_shape
                    )
            if live_source is None and not native_static_predicate_proven:
                logger.info(
                    "PREOPT exact conditional choice abstained: "
                    "source=0x%X compare=%s predicate=0x%X reason=live_predicate",
                    source_block_ea,
                    (
                        "none"
                        if not transfer.materialized_anchor_eas
                        else f"0x{int(transfer.materialized_anchor_eas[0]):X}"
                    ),
                    predicate_ea,
                )
                continue
            if live_source is not None:
                predicate_true_is_taken = live_predicate_orientation
            if predicate_true_is_taken not in (True, False):
                logger.info(
                    "PREOPT exact conditional choice abstained: "
                    "source=%s predicate=0x%X reason=orientation",
                    (
                        f"blk{int(live_source.serial)}@0x{int(live_source.start):X}"
                        if live_source is not None
                        else f"native@0x{source_block_ea:X}"
                    ),
                    predicate_ea,
                )
                continue
        if predicate_true_is_taken not in (True, False):
            continue
        native_source = None
        if native_cfg is not None:
            exact_source = native_cfg.blocks_by_ea.get(source_block_ea)
            if exact_source is not None and (
                int(exact_source.start_ea) <= predicate_ea < int(exact_source.end_ea)
            ):
                native_source = exact_source
            else:
                native_sources = tuple(
                    block
                    for block in native_cfg.blocks_by_ea.values()
                    if int(block.start_ea) <= predicate_ea < int(block.end_ea)
                )
                if len(native_sources) == 1:
                    native_source = native_sources[0]
                    source_block_ea = int(native_source.start_ea)
        if predicate_ea <= 0 or source_block_ea <= 0:
            continue
        if source_block_ea in imported_entry_eas:
            source_owner = DetachedSnippetBoundaryPortOwner.IMPORTED
        elif source_block_ea in live_native_eas:
            source_owner = DetachedSnippetBoundaryPortOwner.LIVE
        else:
            continue
        old_taken_target_ea = None
        old_fallthrough_target_ea = None
        old_taken_target_owner = None
        old_fallthrough_target_owner = None
        if native_source is not None:
            old_taken_edges = tuple(
                edge
                for edge in native_source.outgoing_edges
                if edge.kind is NativeEdgeKind.CONDITIONAL_TRUE
                and edge.target_ea is not None
                and (
                    edge.source_instruction_ea is None
                    or int(edge.source_instruction_ea) == predicate_ea
                )
            )
            old_fallthrough_edges = tuple(
                edge
                for edge in native_source.outgoing_edges
                if edge.kind is NativeEdgeKind.CONDITIONAL_FALSE
                and edge.target_ea is not None
                and (
                    edge.source_instruction_ea is None
                    or int(edge.source_instruction_ea) == predicate_ea
                )
            )
            has_native_conditional = bool(old_taken_edges or old_fallthrough_edges)
            if has_native_conditional:
                if len(old_taken_edges) != 1 or len(old_fallthrough_edges) != 1:
                    continue
                old_taken_target_ea = int(old_taken_edges[0].target_ea)
                old_fallthrough_target_ea = int(old_fallthrough_edges[0].target_ea)
                old_taken_target_owner = target_owner(old_taken_target_ea)
                old_fallthrough_target_owner = target_owner(old_fallthrough_target_ea)
                if (
                    old_taken_target_owner is None
                    or old_fallthrough_target_owner is None
                ):
                    continue
        if bool(predicate_true_is_taken):
            taken_state = true_state
            taken_target_ea = true_target_ea
            taken_owner = true_owner
            fallthrough_state = false_state
            fallthrough_target_ea = false_target_ea
            fallthrough_owner = false_owner
        else:
            taken_state = false_state
            taken_target_ea = false_target_ea
            taken_owner = false_owner
            fallthrough_state = true_state
            fallthrough_target_ea = true_target_ea
            fallthrough_owner = true_owner
        port = DetachedSnippetConditionalBoundaryPort(
            source_block_ea=source_block_ea,
            predicate_ea=predicate_ea,
            old_taken_target_ea=old_taken_target_ea,
            old_fallthrough_target_ea=old_fallthrough_target_ea,
            taken_target_ea=taken_target_ea,
            fallthrough_target_ea=fallthrough_target_ea,
            state_register=(
                int(transfer.selector_state_var_reg)
                if transfer.selector_state_var_reg is not None
                else None
            ),
            taken_state=taken_state,
            fallthrough_state=fallthrough_state,
            source_owner=source_owner,
            taken_target_owner=taken_owner,
            fallthrough_target_owner=fallthrough_owner,
            resolver_kind=(
                "resolver_proven_static_conditional_state_choice"
                if is_static_state_choice
                else "resolver_proven_live_conditional_bridge"
            ),
            old_taken_target_owner=old_taken_target_owner,
            old_fallthrough_target_owner=old_fallthrough_target_owner,
            logical_source_anchor_ea=(
                int(transfer.materialized_anchor_eas[0])
                if is_static_state_choice and transfer.materialized_anchor_eas
                else predicate_ea
            ),
            predicate_size=(
                None if is_flag_only_live_bridge else transfer.predicate_size
            ),
            condition_code=int(transfer.condition_code),
            predicate_register=(
                None if is_flag_only_live_bridge else transfer.predicate_register
            ),
            predicate_constant=(
                None
                if is_flag_only_live_bridge
                or (
                    is_static_state_choice
                    and transfer.predicate_register is None
                    and transfer.predicate_size is None
                )
                else (
                    0
                    if transfer.predicate_compare_constant is None
                    else int(transfer.predicate_compare_constant) & _MASK32
                )
            ),
            predicate_true_is_taken=bool(predicate_true_is_taken),
        )
        if is_static_state_choice or is_exact_live_bridge:
            logger.info(
                "PREOPT exact conditional choice port: "
                "source=0x%X compare=0x%X predicate=0x%X "
                "taken_state=0x%X taken_target=0x%X "
                "fallthrough_state=0x%X fallthrough_target=0x%X",
                source_block_ea,
                (
                    int(transfer.materialized_anchor_eas[0])
                    if transfer.materialized_anchor_eas
                    else predicate_ea
                ),
                predicate_ea,
                taken_state,
                taken_target_ea,
                fallthrough_state,
                fallthrough_target_ea,
            )
        candidates.setdefault((source_block_ea, predicate_ea), set()).add(port)
    coalesced_candidates: dict[
        tuple[int, int],
        set[DetachedSnippetConditionalBoundaryPort],
    ] = {}
    for source_key, source_ports in candidates.items():
        semantically_equivalent: dict[
            DetachedSnippetConditionalBoundaryPort,
            set[DetachedSnippetConditionalBoundaryPort],
        ] = {}
        for port in source_ports:
            semantic_route = replace(
                port,
                predicate_register=None,
                predicate_size=None,
                predicate_constant=None,
            )
            semantically_equivalent.setdefault(semantic_route, set()).add(port)
        coalesced_ports: set[DetachedSnippetConditionalBoundaryPort] = set()
        for equivalent_ports in semantically_equivalent.values():
            explicit_ports = {
                port
                for port in equivalent_ports
                if any(
                    value is not None
                    for value in (
                        port.predicate_register,
                        port.predicate_size,
                        port.predicate_constant,
                    )
                )
            }
            explicit_shapes = {
                (
                    port.predicate_register,
                    port.predicate_size,
                    port.predicate_constant,
                )
                for port in explicit_ports
            }
            if len(explicit_shapes) > 1:
                coalesced_ports.update(explicit_ports)
                continue
            preferred_ports = explicit_ports or equivalent_ports
            coalesced_ports.add(min(preferred_ports, key=repr))
        coalesced_candidates[source_key] = coalesced_ports
    candidates = coalesced_candidates
    conflicting = {key: ports for key, ports in candidates.items() if len(ports) != 1}
    if conflicting:
        for (source_block_ea, predicate_ea), ports in sorted(conflicting.items()):
            logger.info(
                "PREOPT conditional boundary abstained: "
                "source=0x%X predicate=0x%X reason=conflicting_ports ports=%s",
                source_block_ea,
                predicate_ea,
                tuple(
                    sorted(
                        [
                            (
                                port.resolver_kind,
                                int(port.taken_state),
                                int(port.taken_target_ea),
                                int(port.fallthrough_state),
                                int(port.fallthrough_target_ea),
                                port.predicate_register,
                                port.predicate_size,
                                port.predicate_constant,
                                int(port.condition_code),
                                bool(port.predicate_true_is_taken),
                                port.logical_source_anchor_ea,
                            )
                            for port in ports
                        ],
                        key=repr,
                    )
                ),
            )
        return None
    return tuple(next(iter(ports)) for _source, ports in sorted(candidates.items()))


def _merge_preopt_union_boundary_ports(
    previous: DetachedSnippetBoundaryPorts,
    current: DetachedSnippetBoundaryPorts,
) -> DetachedSnippetBoundaryPorts:
    """Keep resolver-proven ports monotonic across optimized-MBA refreshes.

    Applying a live-to-imported boundary port can remove its source route from
    the next CALLS MBA.  Absence in that rewritten snapshot is not evidence
    that the earlier resolver proof became invalid, so refresh may add ports
    but must not erase them.  A newly-proven conditional may, however,
    explicitly replace the bootstrap direct edge at the same stable source and
    terminal anchor.  Keeping both would mutate one source twice in the same
    atomic batch.  The normalizer still rejects every other contradictory proof
    for the same stable native-EA source.
    """
    conditional_replacements = {
        (
            int(port.logical_source_anchor_ea),
            port.logical_source_owner or port.source_owner,
        )
        for port in current.conditional
        if port.logical_source_anchor_ea is not None
        and port.old_taken_target_ea is None
        and port.old_fallthrough_target_ea is None
    }
    direct = tuple(
        port
        for port in previous.direct + current.direct
        if (
            int(port.source_instruction_ea),
            port.source_owner,
        )
        not in conditional_replacements
    )
    previous_conditional_by_source = {
        (
            int(port.source_block_ea),
            int(port.predicate_ea),
            port.source_owner,
        ): port
        for port in previous.conditional
    }

    def same_static_choice_route(
        baseline: DetachedSnippetConditionalBoundaryPort,
        refreshed: DetachedSnippetConditionalBoundaryPort,
    ) -> bool:
        if (
            baseline.resolver_kind != "resolver_proven_static_conditional_state_choice"
            or refreshed.resolver_kind != baseline.resolver_kind
        ):
            return False
        if baseline.predicate_true_is_taken not in (True, False) or (
            refreshed.predicate_true_is_taken not in (True, False)
        ):
            return False

        def logical_arm_order(
            port: DetachedSnippetConditionalBoundaryPort,
        ) -> DetachedSnippetConditionalBoundaryPort:
            if port.predicate_true_is_taken:
                return port
            return replace(
                port,
                old_taken_target_ea=port.old_fallthrough_target_ea,
                old_fallthrough_target_ea=port.old_taken_target_ea,
                taken_target_ea=port.fallthrough_target_ea,
                fallthrough_target_ea=port.taken_target_ea,
                taken_state=port.fallthrough_state,
                fallthrough_state=port.taken_state,
                taken_target_owner=port.fallthrough_target_owner,
                fallthrough_target_owner=port.taken_target_owner,
                old_taken_target_owner=port.old_fallthrough_target_owner,
                old_fallthrough_target_owner=port.old_taken_target_owner,
            )

        maturity_local_shape = {
            "predicate_size": None,
            "condition_code": None,
            "predicate_register": None,
            "predicate_constant": None,
            "predicate_true_is_taken": None,
        }
        return replace(
            logical_arm_order(baseline),
            **maturity_local_shape,
        ) == replace(
            logical_arm_order(refreshed),
            **maturity_local_shape,
        )

    current_conditional = tuple(
        port
        for port in current.conditional
        if not (
            (
                baseline := previous_conditional_by_source.get(
                    (
                        int(port.source_block_ea),
                        int(port.predicate_ea),
                        port.source_owner,
                    )
                )
            )
            is not None
            and same_static_choice_route(baseline, port)
        )
    )
    conditional = previous.conditional + current_conditional
    try:
        return normalize_detached_snippet_boundary_ports(direct, conditional)
    except ValueError:
        for port in current_conditional:
            source = (
                int(port.source_block_ea),
                int(port.predicate_ea),
                port.source_owner,
            )
            baseline = previous_conditional_by_source.get(source)
            if baseline is not None and baseline != port:
                logger.info(
                    "PREOPT union refresh conditional conflict: previous=%r current=%r",
                    baseline,
                    port,
                )
        raise


def _refresh_preopt_union_boundary_ports(
    previous: DetachedSnippetBoundaryPorts,
    current: DetachedSnippetBoundaryPorts,
    *,
    replacement_transfers: tuple[MaterializedIndirectTransfer, ...],
    native_cfg: NativeCfg | None,
    diagnostic: dict[str, object] | None = None,
) -> DetachedSnippetBoundaryPorts:
    """Merge monotonic proofs, then apply current fragment supersessions."""
    merged = _merge_preopt_union_boundary_ports(previous, current)
    return DetachedSnippetBoundaryPorts(
        direct=merged.direct,
        conditional=_without_replaced_imported_dispatcher_ports(
            merged.conditional,
            replacement_transfers,
            native_cfg=native_cfg,
            diagnostic=diagnostic,
        ),
    )


def prepare_preopt_union_closure(
    state: ResolverSessionState,
    *,
    live_mba: object,
    refresh_existing: bool = False,
    refresh_baseline_boundary_ports: DetachedSnippetBoundaryPorts | None = None,
) -> PreoptUnionPreparationResult:
    """Prepare one resolver-proven native closure for PREOPT import."""
    resolution = state.portable_evidence.computed_goto_resolution
    if not isinstance(resolution, ComputedGotoResolution):
        return _preopt_union_abstention(0, "missing_session_resolution")
    key = int(resolution.function_ea)
    cached = state.portable_evidence.preopt_union_preparation
    if isinstance(cached, PreoptUnionPreparationResult):
        return replace(cached, published=False)
    if (
        resolution.arch != "x86"
        or not is_computed_goto_materialized(state)
        or state.snippet_capture_active
    ):
        return _preopt_union_abstention(key, "profile_not_eligible")

    prepatch_source = state.portable_evidence.prepatch_preopt_union_source
    if prepatch_source is not None and not isinstance(
        prepatch_source, _PrepatchPreoptUnionSource
    ):
        return _preopt_union_abstention(key, "invalid_prepatch_source")
    imported_origins = dict(imported_detached_snippet_instruction_origins(live_mba))
    transfers = tuple(
        _canonicalize_imported_transfer_eas(transfer, imported_origins)
        for transfer in state.materialized_transfers
    )
    recovered_routes = tuple(
        transfer
        for transfer in _recover_static_handler_entry_route_transfers(transfers)
        if transfer not in transfers
    )
    if recovered_routes:
        transfers = transfers + recovered_routes
    transfers = _enrich_preopt_union_route_ranges(resolution, transfers)
    live_conditional_bridges = recover_conditional_handler_bridge_transfers_from_mba(
        transfers,
        live_mba,
        imported_predicate_eas=frozenset(imported_origins),
        imported_instruction_origins=imported_origins,
        native_cfg=(None if prepatch_source is None else prepatch_source.cfg),
    )
    logger.info(
        "PREOPT live conditional bridge recovery: func=0x%X rows=%s",
        key,
        [
            (
                f"0x{int(transfer.source_block_ea):X}",
                f"0x{int(transfer.source_jmp_ea):X}",
                tuple(f"0x{int(ea):X}" for ea in transfer.target_eas),
                transfer.predicate_register,
                transfer.predicate_size,
                transfer.predicate_compare_constant,
                transfer.predicate_true_is_taken,
            )
            for transfer in live_conditional_bridges
        ],
    )
    if live_conditional_bridges:
        transfers = transfers + tuple(
            transfer
            for transfer in live_conditional_bridges
            if transfer not in transfers
        )
    entry_bridge_transfers = _preopt_entry_bridge_transfers(
        state.portable_evidence.preopt_entry_bridges,
        transfers,
    )
    if entry_bridge_transfers:
        transfers = transfers + tuple(
            transfer for transfer in entry_bridge_transfers if transfer not in transfers
        )
    stack_carrier_consumer_load_eas = _static_stack_carrier_consumer_load_eas(
        resolution
    )
    entry_consumer_routes = _bind_preopt_entry_bridge_consumers(
        entry_bridge_transfers,
        consumer_load_eas_by_displacement=stack_carrier_consumer_load_eas,
    )
    if entry_consumer_routes:
        transfers = (
            tuple(
                transfer
                for transfer in transfers
                if transfer not in entry_bridge_transfers
            )
            + entry_consumer_routes
        )
    region = (
        PreoptUnionRegionPlan(
            seed_eas=prepatch_source.seed_eas,
            seed_native_ranges=prepatch_source.seed_native_ranges,
            primary_seed_ea=prepatch_source.primary_seed_ea,
            native_ranges=prepatch_source.native_ranges,
            abstentions=(),
        )
        if prepatch_source is not None
        else plan_preopt_union_region(transfers)
    )
    if region.abstentions:
        return _preopt_union_abstention(
            key,
            *(abstention.reason.value for abstention in region.abstentions),
        )
    if region.primary_seed_ea is None or not region.native_ranges:
        return _preopt_union_abstention(key, "no_union_seed")

    live_native_eas = _live_mba_native_eas(
        live_mba,
        imported_instruction_origins=(
            () if refresh_existing else tuple(imported_origins.items())
        ),
    )
    prepatch_source_matches_region = (
        prepatch_source is not None
        and int(prepatch_source.primary_seed_ea) == int(region.primary_seed_ea)
        and prepatch_source.seed_eas
        == tuple(int(seed_ea) for seed_ea in region.seed_eas)
    )
    if refresh_existing:
        if not prepatch_source_matches_region:
            return _preopt_union_abstention(key, "missing_prepatch_refresh_source")
    else:
        region = select_missing_preopt_union_region(region, live_native_eas)
        if region.primary_seed_ea is None or not region.native_ranges:
            return _preopt_union_abstention(key, "no_missing_union_seed")

    function = ida_funcs.get_func(key)
    if function is None:
        return _preopt_union_abstention(key, "function_not_found")
    resolver_targets_by_source = _resolver_targets_by_source(transfers)
    residual_route_source_eas = tuple(
        sorted(
            {
                int(transfer.source_block_ea)
                for transfer in transfers
                if transfer.resolver_kind == "residual_state_route_evidence"
                and len(transfer.target_eas) == 1
                and int(transfer.target_eas[0]) in region.seed_eas
            }
        )
    )
    use_prepatch_source = prepatch_source_matches_region and prepatch_source is not None
    if use_prepatch_source:
        native_cfg = prepatch_source.cfg
        closure = prepatch_source.closure
    else:
        cfg_result = build_native_semantic_cfg(
            function,
            live_native_eas=live_native_eas,
            seed_eas=tuple(
                dict.fromkeys((key, *region.seed_eas, *residual_route_source_eas))
            ),
            resolver_cut_eas=_preopt_resolver_cut_eas(resolution, transfers),
            resolver_proven_unmarked_entry_eas=region.seed_eas,
            resolver_target_eas_by_source={
                source_ea: tuple(sorted(target_eas))
                for source_ea, target_eas in resolver_targets_by_source.items()
            },
        )
        if cfg_result.abstentions:
            logger.info(
                "PREOPT union native-CFG decode abstentions: func=0x%X rows=%s",
                key,
                [
                    (
                        abstention.reason.value,
                        hex(int(abstention.entry_ea)),
                        hex(int(abstention.cursor_ea)),
                        (
                            None
                            if abstention.owner_func_ea is None
                            else hex(int(abstention.owner_func_ea))
                        ),
                    )
                    for abstention in cfg_result.abstentions
                ],
            )
            return _preopt_union_abstention(
                key,
                *(abstention.reason.value for abstention in cfg_result.abstentions),
            )
        native_cfg = cfg_result.cfg
        closure = plan_native_semantic_closure(
            native_cfg,
            tuple(
                ResolverProvenHandlerEntry(
                    entry_ea=int(seed_ea),
                    provenance="static_handler_entry_route",
                )
                for seed_ea in region.seed_eas
            ),
            import_boundary_target_eas=live_native_eas,
        )
        if closure.abstentions or not closure.native_ranges:
            if closure.abstentions:
                logger.info(
                    "PREOPT union semantic-closure abstentions: func=0x%X rows=%s",
                    key,
                    [
                        (
                            abstention.reason.value,
                            (
                                None
                                if abstention.source_block_ea is None
                                else hex(int(abstention.source_block_ea))
                            ),
                            (
                                None
                                if abstention.target_ea is None
                                else hex(int(abstention.target_ea))
                            ),
                            (
                                None
                                if abstention.dependency_ea is None
                                else hex(int(abstention.dependency_ea))
                            ),
                        )
                        for abstention in closure.abstentions
                    ],
                )
            return _preopt_union_abstention(
                key,
                *(abstention.reason.value for abstention in closure.abstentions),
                *(() if closure.native_ranges else ("empty_native_closure",)),
            )
    owned_entry_consumer_routes = _bind_preopt_entry_consumer_owned_ranges(
        entry_consumer_routes,
        native_cfg=native_cfg,
    )
    if owned_entry_consumer_routes:
        transfers = tuple(
            next(
                (
                    owned
                    for original, owned in zip(
                        entry_consumer_routes,
                        owned_entry_consumer_routes,
                    )
                    if transfer == original
                ),
                transfer,
            )
            for transfer in transfers
        )
        entry_consumer_routes = owned_entry_consumer_routes
    effective_closure = closure
    entry_consumer_port_diagnostic: dict[str, object] = {}
    boundary_ports = _preopt_union_boundary_ports(
        effective_closure,
        live_native_eas=live_native_eas,
        transfers=transfers,
        live_mba=live_mba,
        native_cfg=native_cfg,
        entry_consumer_port_diagnostic=entry_consumer_port_diagnostic,
    )
    if boundary_ports is None:
        return _preopt_union_abstention(key, "incomplete_boundary_topology")
    if refresh_existing and refresh_baseline_boundary_ports is not None:
        try:
            boundary_ports = _refresh_preopt_union_boundary_ports(
                refresh_baseline_boundary_ports,
                boundary_ports,
                replacement_transfers=transfers,
                native_cfg=native_cfg,
                diagnostic=entry_consumer_port_diagnostic,
            )
        except ValueError as exc:
            logger.info(
                "PREOPT union refresh rejected conflicting boundary proof: "
                "func=0x%X reason=%s",
                key,
                exc,
            )
            return _preopt_union_abstention(
                key,
                "conflicting_refresh_boundary_ports",
            )

    normalized_ranges = (
        prepatch_source.native_ranges
        if use_prepatch_source
        else tuple(
            (int(native_range.start_ea), int(native_range.end_ea))
            for native_range in closure.native_ranges
        )
    )
    terminal_return_entry_eas = tuple(
        int(entry_ea)
        for entry_ea in effective_closure.included_block_eas
        if int(entry_ea) in native_cfg.blocks_by_ea
        and native_cfg.blocks_by_ea[int(entry_ea)].terminal is NativeTerminalKind.RETURN
    )
    generation_ranges = tuple(
        (int(native_range.start_ea), int(native_range.end_ea))
        for native_range in plan_native_generation_ranges(
            effective_closure,
            required_entry_eas=terminal_return_entry_eas,
        )
    )
    logger.info(
        "PREOPT union semantic closure: func=0x%X seeds=%s live=%s "
        "blocks=%s ranges=%s generation_ranges=%s boundary_edges=%s",
        key,
        [hex(int(seed_ea)) for seed_ea in region.seed_eas],
        [hex(int(ea)) for ea in sorted(live_native_eas)],
        [
            (
                hex(int(entry_ea)),
                hex(int(native_cfg.blocks_by_ea[int(entry_ea)].end_ea)),
                native_cfg.blocks_by_ea[int(entry_ea)].terminal.value,
                [
                    (
                        edge.kind.value,
                        None if edge.target_ea is None else hex(int(edge.target_ea)),
                        edge.resolver_proven,
                        (
                            None
                            if edge.source_instruction_ea is None
                            else hex(int(edge.source_instruction_ea))
                        ),
                    )
                    for edge in native_cfg.blocks_by_ea[int(entry_ea)].outgoing_edges
                ],
            )
            for entry_ea in effective_closure.included_block_eas
            if int(entry_ea) in native_cfg.blocks_by_ea
        ],
        [(hex(start_ea), hex(end_ea)) for start_ea, end_ea in normalized_ranges],
        [(hex(start_ea), hex(end_ea)) for start_ea, end_ea in generation_ranges],
        [
            (
                hex(int(edge.source_ea)),
                (
                    None
                    if edge.source_instruction_ea is None
                    else hex(int(edge.source_instruction_ea))
                ),
                edge.kind.value,
                hex(int(edge.target_ea)),
            )
            for edge in effective_closure.proven_import_boundary_edges
        ],
    )
    result = PreoptUnionPreparationResult(
        function_ea=key,
        prepared=True,
        published=True,
        primary_seed_ea=int(region.primary_seed_ea),
        seed_eas=tuple(int(seed_ea) for seed_ea in region.seed_eas),
        native_ranges=normalized_ranges,
        imported_block_entry_eas=tuple(effective_closure.included_block_eas),
        entry_consumer_port_diagnostic=tuple(entry_consumer_port_diagnostic.items()),
    )

    def generate(maturity: int):
        ranges = ida_hexrays.mba_ranges_t()
        for start_ea, end_ea in generation_ranges:
            ranges.ranges.push_back(idaapi.range_t(int(start_ea), int(end_ea)))
        failure = ida_hexrays.hexrays_failure_t()
        generated_mba = _generate_microcode_without_d810(
            ida_hexrays.gen_microcode,
            ranges,
            failure,
            None,
            int(ida_hexrays.DECOMP_NO_WAIT | ida_hexrays.DECOMP_ALL_BLKS),
            int(maturity),
        )
        if generated_mba is None:
            logger.info(
                "PREOPT union generation returned no MBA: func=0x%X "
                "maturity=%s ranges=%s failure=%s",
                key,
                maturity_to_string(int(maturity)),
                [
                    (hex(start_ea), hex(end_ea))
                    for start_ea, end_ea in generation_ranges
                ],
                failure.desc(),
            )
        return generated_mba

    prepatch_source_bound = (
        use_prepatch_source
        and bind_preopt_union_snippet_boundary_ports(
            key,
            int(region.primary_seed_ea),
            boundary_ports,
        )
    )
    if prepatch_source_bound:
        logger.info(
            "PREOPT union bound prepatch source: func=0x%X primary=0x%X",
            key,
            int(region.primary_seed_ea),
        )
    elif refresh_existing and use_prepatch_source:
        return _preopt_union_abstention(key, "prepatch_refresh_bind_failed")
    else:
        if not state.begin_snippet_capture(key):
            return _preopt_union_abstention(key, "snippet_capture_active")
        try:
            try:
                preopt_mba = generate(int(ida_hexrays.MMAT_PREOPTIMIZED))
            except Exception:
                logger.info(
                    "PREOPT union generation failed: func=0x%X ranges=%s",
                    key,
                    generation_ranges,
                    exc_info=True,
                )
                preopt_mba = None
            if preopt_mba is None:
                return _preopt_union_abstention(key, "preopt_generation_failed")
            preopt_mba.build_graph()
            captured = capture_preopt_union_snippet_template(
                key,
                int(region.primary_seed_ea),
                preopt_mba,
                normalized_ranges,
                boundary_ports=boundary_ports,
                owned_block_entry_eas=tuple(effective_closure.included_block_eas),
                terminal_return_entry_eas=terminal_return_entry_eas,
                resolver_proven_internal_successor_eas=(
                    _preopt_union_internal_successor_eas(effective_closure)
                ),
            )
            if not captured:
                return _preopt_union_abstention(
                    key,
                    "preopt_union_capture_failed",
                )
        finally:
            state.finish_snippet_capture()

    state_var_reg = unique_materialized_state_register(transfers)
    if state_var_reg is not None:
        state.native_preanalysis.merge_terminal_return_carrier_requests(
            state.native_key,
            plan_terminal_return_carrier_requests_from_native_routes(
                transfers,
                boundary_ports.direct,
                state_var_reg=int(state_var_reg),
            ),
        )
    _merge_native_facts(
        state,
        native_cfg=native_cfg,
        semantic_closure=effective_closure,
        transfers=transfers,
        boundary_ports=boundary_ports,
    )
    state.native_preanalysis.merge_entry_consumer_routes(
        state.native_key,
        entry_consumer_routes,
    )
    state.native_preanalysis.set_preopt_union_preparation(
        state.native_key,
        result,
    )
    logger.info(
        "PREOPT union prepared: func=0x%X primary=0x%X seeds=%s "
        "ranges=%s owned_entries=%s direct_ports=%d conditional_ports=%d",
        key,
        int(region.primary_seed_ea),
        [hex(int(seed_ea)) for seed_ea in region.seed_eas],
        [(hex(start_ea), hex(end_ea)) for start_ea, end_ea in normalized_ranges],
        [hex(int(entry_ea)) for entry_ea in closure.included_block_eas],
        len(boundary_ports.direct),
        len(boundary_ports.conditional),
    )
    return result


def _refresh_preopt_union_from_calls_evidence(
    state: ResolverSessionState,
    mba: object,
) -> bool:
    """Rebind the pristine PREOPT template for a newer CALLS evidence epoch."""

    resolution = state.portable_evidence.computed_goto_resolution
    if not isinstance(resolution, ComputedGotoResolution):
        return False
    key = int(resolution.function_ea)
    previous = state.portable_evidence.preopt_union_preparation
    state.native_preanalysis.set_preopt_union_preparation(state.native_key, None)
    if not isinstance(previous, PreoptUnionPreparationResult) or not previous.prepared:
        if isinstance(previous, PreoptUnionPreparationResult):
            state.native_preanalysis.set_preopt_union_preparation(
                state.native_key,
                previous,
            )
        return False
    try:
        refreshed = prepare_preopt_union_closure(
            state,
            live_mba=mba,
            refresh_existing=True,
            refresh_baseline_boundary_ports=state.boundary_ports,
        )
    except Exception:
        state.native_preanalysis.set_preopt_union_preparation(
            state.native_key,
            previous,
        )
        logger.warning(
            "PREOPT union refresh failed; restored previous authority: "
            "func=0x%X evidence_generation=%d",
            key,
            int(state.evidence_generation),
            exc_info=True,
        )
        return False
    if not refreshed.prepared:
        state.native_preanalysis.set_preopt_union_preparation(
            state.native_key,
            previous,
        )
        return False
    # The portable port set can remain byte-for-byte identical while CALLS
    # publishes newer session evidence consumed by downstream routing.  A
    # successful refresh still requires a fresh GENERATED/PREOPT pass so that
    # the new evidence generation, rather than the old live MBA, is bound.
    state.pending_preopt_reimport = True
    return True


def prepare_detached_handler_snippets(
    state: ResolverSessionState,
    *,
    live_mba: object | None = None,
) -> int:
    """Generate and cache resolver-proven detached handlers outside callbacks.

    This entry point must be called between top-level decompilations.  It uses
    explicit native ranges to obtain isolated microcode, then stores
    function-frame-normalized templates for the next top-level MBA.  PREOPT
    union semantic closure is the only production path.
    """
    resolution = state.portable_evidence.computed_goto_resolution
    if (
        not isinstance(resolution, ComputedGotoResolution)
        or state.snippet_capture_active
    ):
        return 0
    key = int(resolution.function_ea)
    transfers = state.materialized_transfers
    handler_entry_routes = tuple(
        transfer
        for transfer in _recover_static_handler_entry_route_transfers(transfers)
        if transfer not in transfers
    )
    if handler_entry_routes:
        _merge_materialized_transfers(state, handler_entry_routes)
        transfers = state.materialized_transfers
    if state.pending_preopt_reimport:
        state.pending_preopt_reimport = False
        logger.info(
            "PREOPT union reimport scheduled: func=0x%X reason=calls_evidence_refresh",
            key,
        )
        return 1
    prepatch_source = state.portable_evidence.prepatch_preopt_union_source
    if resolution.patch_plans and prepatch_source is None:
        source_transfers = (
            _static_prepatch_union_source_transfers(resolution)
            if resolution.arch == "x86"
            else ()
        )
        source_captured = _capture_prepatch_preopt_union_source(
            state,
            resolution,
            source_transfers,
        )
        if not source_captured:
            logger.info(
                "computed-goto portable frontend capture abstained: "
                "func=0x%X source_captured=%s",
                key,
                source_captured,
            )
            return 0
        logger.info(
            "computed-goto portable frontend evidence captured: func=0x%X "
            "sites=%d evidence_generation=%d",
            key,
            resolution.site_count,
            int(state.evidence_generation),
        )
        return 1
    if live_mba is not None:
        try:
            union_preparation = prepare_preopt_union_closure(
                state,
                live_mba=live_mba,
            )
        except Exception:
            logger.warning(
                "PREOPT union preparation failed open: func=0x%X",
                key,
                exc_info=True,
            )
        else:
            if union_preparation.prepared and union_preparation.published:
                return 1
    logger.info(
        "detached snippet preparation abstained: func=0x%X "
        "reason=preopt_union_not_prepared",
        key,
    )
    return 0


def is_computed_goto_materialized(state: ResolverSessionState) -> bool:
    """Return whether this lifecycle session owns computed-goto materialization."""
    return state.is_materialized


def _zero_arg_call_type_is_proven(
    *,
    profile_owned: bool,
    direct_call: bool,
    has_operand_type: bool,
    has_callee_type: bool,
    guessed_arg_count: int | None,
    callee_argsize: int | None,
    first_fastcall_register_accesses: tuple[str | None, str | None],
) -> bool:
    """Accept a no-argument prototype only when every proof source agrees."""
    return (
        profile_owned
        and direct_call
        and not has_operand_type
        and not has_callee_type
        and guessed_arg_count == 0
        and callee_argsize == 0
        and first_fastcall_register_accesses == ("write", "write")
    )


_EXACT_NATIVE_CALLINFO_REENTRY_KINDS = frozenset(
    {"static_fixpoint", "detached_static_fixpoint"}
)


def _proven_callinfo_reentry_eas(
    resolution: ComputedGotoResolution,
    transfers: Sequence[MaterializedIndirectTransfer],
) -> frozenset[int]:
    """Return computed transfers proven strongly enough for ABI evidence."""
    reentry_eas = {
        int(source_ea)
        for source_ea, targets in resolution.jmp_targets.items()
        if targets
    }
    reentry_eas.update(
        int(transfer.source_jmp_ea)
        for transfer in transfers
        if transfer.target_eas
        and transfer.resolver_kind in _EXACT_NATIVE_CALLINFO_REENTRY_KINDS
    )
    return frozenset(reentry_eas)


def _resolver_state_from_decision(decision: dict) -> ResolverSessionState | None:
    """Return the lifecycle-owned resolver state supplied by a hook decision."""
    session = decision.get("session")
    if session is None:
        return None
    try:
        return resolver_session_state(session)
    except (TypeError, ValueError):
        logger.debug(
            "resolver callback has no compatible lifecycle session", exc_info=True
        )
        return None


def _callinfo_profile_resolution(
    state: ResolverSessionState,
    function_ea: int,
    call_ea: int,
) -> tuple[int, ComputedGotoResolution | None]:
    """Resolve callback-local callinfo through this session's native profile."""
    key = int(function_ea)
    resolution = state.portable_evidence.computed_goto_resolution
    if not isinstance(resolution, ComputedGotoResolution):
        return key, None
    profile_key = int(resolution.function_ea)
    if key == profile_key:
        return profile_key, resolution
    if state.snippet_capture_active and state.snippet_capture_profile_ea == profile_key:
        return profile_key, resolution
    return key, None


def _first_x86_fastcall_register_accesses(
    callee_ea: int,
) -> tuple[str | None, str | None]:
    """Return the first CX/DX access kinds in the native callee fragment."""
    import ida_idp  # type: ignore[import-untyped]
    import ida_ua  # type: ignore[import-untyped]
    import idautils  # type: ignore[import-untyped]

    families = ({"cx", "ecx"}, {"dx", "edx"})
    first: list[str | None] = [None, None]
    register_names = ida_idp.ph_get_regnames()
    for ea in idautils.FuncItems(int(callee_ea)):
        instruction = ida_ua.insn_t()
        if ida_ua.decode_insn(instruction, int(ea)) <= 0:
            continue
        accesses = ida_idp.reg_accesses_t()
        if ida_idp.ph_get_reg_accesses(accesses, instruction, 0) < 0:
            continue
        for access in accesses:
            register_name = str(register_names[int(access.regnum)]).lower()
            for index, family in enumerate(families):
                if first[index] is not None or register_name not in family:
                    continue
                access_type = int(access.access_type)
                first[index] = (
                    "read"
                    if access_type & int(ida_idp.READ_ACCESS)
                    else "write"
                    if access_type == int(ida_idp.WRITE_ACCESS)
                    else None
                )
        if all(kind is not None for kind in first):
            break
    return first[0], first[1]


def _capture_range_instruction_eas(mba: object) -> tuple[int, ...]:
    """Return native code heads owned by an isolated capture MBA."""
    import ida_bytes  # type: ignore[import-untyped]
    import idautils  # type: ignore[import-untyped]

    instruction_eas: set[int] = set()
    ranges = mba.mbr.ranges
    for index in range(int(ranges.size())):
        native_range = ranges[index]
        for ea in idautils.Heads(
            int(native_range.start_ea),
            int(native_range.end_ea),
        ):
            if ida_bytes.is_code(ida_bytes.get_flags(int(ea))):
                instruction_eas.add(int(ea))
    return tuple(sorted(instruction_eas))


def _on_stkpnts(
    *,
    function_ea: int,
    mba: object,
    stack_points: object,
    decision: dict,
) -> None:
    """Project native SP facts onto resolver-owned imported instructions."""
    import ida_frame  # type: ignore[import-untyped]
    import ida_funcs  # type: ignore[import-untyped]

    state = _resolver_state_from_decision(decision)
    if state is None:
        return
    resolution = state.portable_evidence.computed_goto_resolution
    if (
        not isinstance(resolution, ComputedGotoResolution)
        or resolution.arch != "x86"
        or _upsert_stkpnt is None
    ):
        return
    capture_active = state.snippet_capture_active
    key = int(resolution.function_ea)
    function = ida_funcs.get_func(key)
    if function is None:
        return

    if capture_active:
        native_ea_by_live_ea = {
            int(native_ea): int(native_ea)
            for native_ea in _capture_range_instruction_eas(mba)
        }
    else:
        detached_call_spd_by_ea = dict(detached_preopt_call_stack_points(key))
        native_ea_by_live_ea = {
            int(imported_ea): int(native_ea)
            for imported_ea, native_ea in (
                last_imported_detached_snippet_instruction_origins(key)
            )
        }
        native_ea_by_live_ea.update(
            {
                int(call_ea): int(call_ea)
                for call_ea in (
                    *detached_callinfo_template_eas(key),
                    *detached_call_spd_by_ea,
                )
            }
        )
        native_ea_by_live_ea.update(
            {
                int(imported_ea): int(native_ea)
                for imported_ea, native_ea in (
                    imported_detached_snippet_instruction_origins(mba)
                )
            }
        )
    projected: list[tuple[int, int, int]] = []
    diagnostic_points: list[dict[str, object]] = []
    detached_call_spd_by_ea = (
        {} if capture_active else dict(detached_preopt_call_stack_points(key))
    )
    for live_ea, native_ea in sorted(native_ea_by_live_ea.items()):
        try:
            native_spd = int(ida_frame.get_spd(function, int(native_ea)))
            route_call_delta = detached_call_spd_by_ea.get(int(native_ea))
            canonical_spd: int | None = None
            if route_call_delta is None:
                spd = native_spd
            else:
                # hxe_stkpnts runs before this MBA's frame fields are populated.
                # The native function already owns the authoritative frame size.
                canonical_spd = -(
                    int(getattr(function, "frsize")) + int(getattr(function, "frregs"))
                )
                resolved_spd = project_detached_call_stack_point(
                    native_spd=native_spd,
                    canonical_spd=canonical_spd,
                    route_call_delta=int(route_call_delta),
                )
                if resolved_spd is None:
                    diagnostic_points.append(
                        {
                            "live_ea": hex(int(live_ea)),
                            "native_ea": hex(int(native_ea)),
                            "native_spd": int(native_spd),
                            "canonical_spd": int(canonical_spd),
                            "route_call_delta": int(route_call_delta),
                            "applied_spd": None,
                            "outcome": "abstained",
                            "reason": "conflicting_stack_evidence",
                        }
                    )
                    continue
                spd = int(resolved_spd)
            _upsert_stkpnt(stack_points, int(live_ea), spd)
        except Exception:
            logger.debug(
                "computed-goto stack-point projection failed: "
                "func=0x%X live=0x%X native=0x%X",
                key,
                int(live_ea),
                int(native_ea),
                exc_info=True,
            )
            continue
        projected.append((int(live_ea), int(native_ea), spd))
        diagnostic_points.append(
            {
                "live_ea": hex(int(live_ea)),
                "native_ea": hex(int(native_ea)),
                "native_spd": int(native_spd),
                "canonical_spd": (
                    None if canonical_spd is None else int(canonical_spd)
                ),
                "route_call_delta": (
                    None if route_call_delta is None else int(route_call_delta)
                ),
                "applied_spd": int(spd),
                "outcome": "applied",
                "reason": "native_spd" if route_call_delta is None else "merged",
            }
        )
    if not diagnostic_points:
        return
    if projected:
        decision["stack_points_modified"] = len(projected)
    session = decision.get("session")
    session_id = getattr(session, "identity_key", None)
    if session_id is not None:
        maturity = getattr(mba, "maturity", None)
        emit_diagnostic(
            LifecycleEventObserved(
                session_id=str(session_id),
                func_ea=key,
                event_kind="stack_point_projection",
                provider="hexrays",
                maturity=(
                    None if maturity is None else maturity_to_string(int(maturity))
                ),
                phase="hxe_stkpnts",
                evidence_generation=int(state.evidence_generation),
                mba_generation_before=int(
                    getattr(session, "current_mba_generation", 0)
                ),
                mba_generation_after=int(getattr(session, "current_mba_generation", 0)),
                summary=(
                    f"projected {len(projected)} stack points; "
                    f"abstained {len(diagnostic_points) - len(projected)}"
                ),
                payload={
                    "capture_active": bool(capture_active),
                    "points": diagnostic_points,
                },
            )
        )
    if not projected:
        return
    logger.info(
        "computed-goto stack provenance projected: func=0x%X points=%d "
        "capture=%s native_calls=%s route_call_spds=%s",
        key,
        len(projected),
        capture_active,
        [hex(int(ea)) for ea in detached_callinfo_template_eas(key)],
        [
            (hex(int(call_ea)), int(spd))
            for call_ea, spd in sorted(detached_call_spd_by_ea.items())
        ],
    )


def _on_build_callinfo(
    *,
    function_ea: int,
    block: object,
    call_type: object,
    decision: dict,
) -> None:
    """Stabilize narrowly proven call prototypes for this profile."""
    import ida_funcs  # type: ignore[import-untyped]
    import ida_hexrays  # type: ignore[import-untyped]
    import ida_nalt  # type: ignore[import-untyped]
    import ida_typeinf  # type: ignore[import-untyped]

    tail = block.tail
    if tail is None:
        return
    state = _resolver_state_from_decision(decision)
    if state is None:
        return
    if state.native_preanalysis.has_pending_generated_restart:
        # A call-info callback can discover exact detached route evidence after
        # PREOPT has already published the current generation.  Once that
        # evidence stages a controller-owned restart, all later call-info
        # callbacks belong to the obsolete live MBA and must not extend it.
        return
    imported_origins = dict(imported_detached_snippet_instruction_origins(block.mba))
    call_ea = int(imported_origins.get(int(tail.ea), int(tail.ea)))
    key, resolution = _callinfo_profile_resolution(state, function_ea, call_ea)
    profile_owned = resolution is not None and resolution.arch == "x86"
    direct_call = int(tail.opcode) == int(ida_hexrays.m_call) and int(tail.l.t) == int(
        ida_hexrays.mop_v
    )
    indirect_call = int(tail.opcode) == int(ida_hexrays.m_icall)
    if not profile_owned or (not direct_call and not indirect_call):
        return

    owns_live_profile_mba = int(function_ea) == int(key)
    if (
        owns_live_profile_mba
        and not state.snippet_capture_active
        and _copy_mcallinfo is not None
    ):
        route_callinfo = prepare_detached_callinfo_template(
            key,
            call_ea,
            tail,
            block.mba,
            copy_callinfo=_copy_mcallinfo,
        )
        if route_callinfo is not None:
            decision["callinfo"] = route_callinfo
            logger.info(
                "computed-goto route callinfo restored: func=0x%X "
                "call=0x%X args=%d call_spd=%d stkargs_top=%d",
                key,
                call_ea,
                len(route_callinfo.args),
                int(route_callinfo.call_spd),
                int(route_callinfo.stkargs_top),
            )
            return

    operand_type = ida_typeinf.tinfo_t()
    has_operand_type = bool(ida_nalt.get_op_tinfo(operand_type, call_ea, 0))

    if indirect_call:
        if has_operand_type:
            return
        resolver_evidence = state.native_preanalysis.resolver_evidence
        cached_proof = (
            None
            if resolver_evidence is None
            else dict(resolver_evidence.call_abi_proofs).get(call_ea)
        )
        if cached_proof is not None and apply_three_argument_stdcall_type(
            call_type,
            cached_proof,
        ):
            prepared_callinfo = build_three_argument_stdcall_callinfo(
                block,
                call_type,
                cached_proof,
            )
            if prepared_callinfo is not None:
                decision["callinfo"] = prepared_callinfo
                logger.info(
                    "computed-goto indirect call proof reused: "
                    "func=0x%X call=0x%X cc=stdcall args=%d stack_bytes=%d",
                    key,
                    call_ea,
                    int(cached_proof.argument_count),
                    int(cached_proof.stack_argument_bytes),
                )
                return
        recorded_transfers = state.materialized_transfers
        proven_reentry_eas = _proven_callinfo_reentry_eas(
            resolution,
            recorded_transfers,
        )
        if not proven_reentry_eas:
            return
        no_stack_adjustment = native_corridor_has_no_stack_adjustment(
            call_ea,
            proven_reentry_eas,
        )
        if no_stack_adjustment is None:
            local_transfers = _detached_static_terminal_transfers(
                resolution,
                (int(block.start),),
                entry_context_transfers=recorded_transfers,
            )
            if local_transfers:
                calls_evidence_changed = _merge_materialized_transfers(
                    state,
                    local_transfers,
                )
                published_generation = state.native_preanalysis.normalization_published_postvalidated_generation
                if (
                    calls_evidence_changed
                    and owns_live_profile_mba
                    and not state.snippet_capture_active
                    and published_generation is not None
                    and int(published_generation) < int(state.evidence_generation)
                ):
                    state.native_preanalysis.request_generated_restart(
                        evidence_family="materialized_transfers",
                        reason=("CALLS discovered detached local transfer evidence"),
                    )
                combined_transfers = state.materialized_transfers
                proven_reentry_eas = _proven_callinfo_reentry_eas(
                    resolution,
                    combined_transfers,
                )
                no_stack_adjustment = native_corridor_has_no_stack_adjustment(
                    call_ea,
                    proven_reentry_eas,
                )
        evidence = collect_three_argument_callee_purged_evidence(
            block,
            proven_reentry_eas=proven_reentry_eas,
            has_authoritative_type=has_operand_type,
            call_stack_deficit=native_call_stack_deficit(block, call_ea),
            caller_stack_adjustment=(0 if no_stack_adjustment is True else None),
            word_size=4,
        )
        proof = prove_three_argument_callee_purged_call(evidence)
        if proof is None or not apply_three_argument_stdcall_type(
            call_type,
            proof,
        ):
            return
        prepared_callinfo = build_three_argument_stdcall_callinfo(
            block,
            call_type,
            proof,
        )
        if prepared_callinfo is None:
            return
        state.native_preanalysis.merge_call_abi_proof(
            state.native_key,
            call_ea=call_ea,
            proof=proof,
        )
        decision["callinfo"] = prepared_callinfo
        logger.info(
            "computed-goto indirect call prototype stabilized: "
            "func=0x%X call=0x%X cc=stdcall args=%d stack_bytes=%d",
            key,
            call_ea,
            int(proof.argument_count),
            int(proof.stack_argument_bytes),
        )
        return

    callee_ea = int(tail.l.g)
    callee_type = ida_typeinf.tinfo_t()
    has_callee_type = bool(ida_nalt.get_tinfo(callee_type, callee_ea))
    guessed_type = ida_typeinf.tinfo_t()
    guess_result = int(ida_typeinf.guess_tinfo(guessed_type, callee_ea))
    guessed_details = ida_typeinf.func_type_data_t()
    guessed_arg_count = (
        len(guessed_details)
        if guess_result > 0
        and guessed_type.is_func()
        and guessed_type.get_func_details(guessed_details)
        else None
    )
    callee = ida_funcs.get_func(callee_ea)
    callee_argsize = int(callee.argsize) if callee is not None else None
    first_accesses = _first_x86_fastcall_register_accesses(callee_ea)
    if not _zero_arg_call_type_is_proven(
        profile_owned=profile_owned,
        direct_call=direct_call,
        has_operand_type=has_operand_type,
        has_callee_type=has_callee_type,
        guessed_arg_count=guessed_arg_count,
        callee_argsize=callee_argsize,
        first_fastcall_register_accesses=first_accesses,
    ):
        return

    ida_typeinf.copy_tinfo_t(call_type, guessed_type)
    logger.info(
        "computed-goto call prototype stabilized: func=0x%X call=0x%X "
        "callee=0x%X args=0 first_fastcall_accesses=%s",
        key,
        call_ea,
        callee_ea,
        first_accesses,
    )


_MAX_MATERIALIZATION_ROUNDS = 16


def _bootstrap_native_replay_inputs(
    transfers: Sequence[MaterializedIndirectTransfer],
) -> tuple[dict[int, int], dict[int, dict[int, int]], frozenset[int]]:
    """Project portable resolver proof into safe native-bootstrap replay seeds.

    Function-wide values may seed every replay, but per-corridor snapshots are
    deliberately indexed by their native block-entry EA.  The concrete native
    resolver refills a snapshot only after control reaches that entry, so a
    path-local value cannot leak into a different entry corridor.  Conflicting
    facts abstain per register rather than selecting a producer order.
    """
    context_candidates: dict[int, set[int]] = {}
    snapshots: dict[int, dict[int, set[int]]] = {}
    dispatch_anchor_eas: set[int] = set()
    for transfer in transfers:
        for mreg, value in transfer.context_register_values:
            context_candidates.setdefault(int(mreg), set()).add(int(value))
        if int(transfer.source_block_ea) > 0:
            by_mreg = snapshots.setdefault(int(transfer.source_block_ea), {})
            for mreg, value in transfer.source_register_values:
                by_mreg.setdefault(int(mreg), set()).add(int(value))
        for snapshot_ea, register_values in transfer.corridor_register_snapshots:
            by_mreg = snapshots.setdefault(int(snapshot_ea), {})
            for mreg, value in register_values:
                by_mreg.setdefault(int(mreg), set()).add(int(value))
        dispatch_anchor_eas.update(
            int(anchor_ea) for anchor_ea in transfer.materialized_anchor_eas
        )
    context_mregs = {
        mreg: next(iter(values))
        for mreg, values in context_candidates.items()
        if len(values) == 1
    }
    snapshots_by_ea = {
        snapshot_ea: {
            mreg: next(iter(values))
            for mreg, values in by_mreg.items()
            if len(values) == 1
        }
        for snapshot_ea, by_mreg in snapshots.items()
    }
    return context_mregs, snapshots_by_ea, frozenset(dispatch_anchor_eas)


class NativeEntryBootstrapSeed(NamedTuple):
    """Portable proof at the first direct jump in the native entry corridor."""

    source_anchor_ea: int
    direct_target_ea: int
    state_mreg: int
    state_constant: int


def _native_entry_bootstrap_seeds(
    function_ea: int,
    selector_mregs: frozenset[int],
    *,
    max_instructions: int = 1024,
) -> tuple[NativeEntryBootstrapSeed, ...]:
    """Find constant selector values reaching the first direct entry jump.

    This deliberately follows only the native fallthrough corridor.  Calls
    invalidate ABI caller-clobbered facts and then preserve fallthrough.  A
    conditional transfer, indirect jump, undecodable instruction, or unknown
    write to a selector makes the proof abstain.  The returned source and target
    are native instruction EAs, never maturity-local block identifiers.
    """
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    values: dict[int, int] = {}
    instruction = ida_ua.insn_t()
    ea = int(function_ea)
    for _step in range(int(max_instructions)):
        length = int(ida_ua.decode_insn(instruction, ea))
        if length <= 0:
            return ()
        mnemonic = (idaapi.print_insn_mnem(ea) or "").lower()
        destination = instruction.ops[0]
        if destination.type == idaapi.o_reg and mnemonic not in {
            "call",
            "cmp",
            "push",
            "test",
        }:
            destination_mreg = _native_register_mreg(_sv_reg_name(destination))
            if destination_mreg in selector_mregs:
                source = instruction.ops[1]
                if mnemonic == "mov" and source.type == idaapi.o_imm:
                    values[int(destination_mreg)] = int(source.value) & _MASK32
                else:
                    values.pop(int(destination_mreg), None)
        if mnemonic == "call":
            # A native call returns to this fallthrough corridor.  Preserve
            # callee-saved selector facts and invalidate only ABI
            # caller-clobbered registers; a later selector assignment remains
            # exact portable evidence.
            for register_name in _SV_CALLER_CLOBBERED:
                caller_mreg = _native_register_mreg(register_name)
                if caller_mreg is not None:
                    values.pop(int(caller_mreg), None)
        if mnemonic == "jmp":
            if instruction.ops[0].type not in (idaapi.o_near, idaapi.o_far):
                return ()
            direct_target_ea = int(instruction.ops[0].addr)
            return tuple(
                NativeEntryBootstrapSeed(
                    source_anchor_ea=int(ea),
                    direct_target_ea=direct_target_ea,
                    state_mreg=int(selector_mreg),
                    state_constant=int(state),
                )
                for selector_mreg, state in sorted(values.items())
            )
        if mnemonic in _SV_JCC_MNEMS or mnemonic in ("ret", "retn", "retf"):
            return ()
        ea += length
    return ()


def discover_static_native_bootstrap_routes(
    function_ea: int,
    state: ResolverSessionState,
) -> bool:
    """Publish serial-free entry routes during manager-owned native preflight.

    Static resolution supplies the selector registers, register snapshots, and
    the set of proven native block entries.  The native entry scan supplies a
    constant selector and exact target at the first direct jump.  A target
    already proven as a native block entry is accepted directly; otherwise,
    concrete corridor replay must reach a known entry before publication.
    """
    resolution = state.portable_evidence.computed_goto_resolution
    if not isinstance(resolution, ComputedGotoResolution):
        logger.debug(
            "native preflight bootstrap abstain: func=0x%X reason=no_resolution",
            int(function_ea),
        )
        return False
    transfers = state.materialized_transfers
    selector_mregs = frozenset(
        int(transfer.selector_state_var_reg)
        for transfer in transfers
        if transfer.selector_state_var_reg is not None
    )
    if not selector_mregs:
        logger.debug(
            "native preflight bootstrap abstain: func=0x%X reason=no_selectors "
            "transfers=%d",
            int(function_ea),
            len(transfers),
        )
        return False
    seeds = _native_entry_bootstrap_seeds(int(function_ea), selector_mregs)
    if not seeds:
        logger.debug(
            "native preflight bootstrap abstain: func=0x%X reason=no_entry_seed "
            "selectors=%s",
            int(function_ea),
            sorted(selector_mregs),
        )
        return False

    known_entries = {
        int(entry_ea) for entry_ea in resolution.block_entries if int(entry_ea) > 0
    }
    known_entries.update(
        int(target_ea)
        for target_eas in resolution.jmp_targets.values()
        for target_ea in target_eas
        if int(target_ea) > 0
    )
    if not known_entries:
        logger.debug(
            "native preflight bootstrap abstain: func=0x%X reason=no_known_entries",
            int(function_ea),
        )
        return False
    context_mregs, register_snapshots_by_ea, dispatch_anchor_eas = (
        _bootstrap_native_replay_inputs(transfers)
    )
    navigation_sources = frozenset(
        int(transfer.source_block_ea)
        for transfer in transfers
        if transfer.resolver_kind == "static_handler_entry_route"
    )
    discovered = False
    for seed in seeds:
        source_anchor_ea = int(seed.source_anchor_ea)
        state_mreg = int(seed.state_mreg)
        state_constant = int(seed.state_constant)
        initial_mregs = dict(context_mregs)
        initial_mregs[state_mreg] = state_constant
        direct_target_ea = int(seed.direct_target_ea)
        if (
            direct_target_ea in known_entries
            and source_anchor_ea not in navigation_sources
        ):
            handler_anchor_ea: int | None = direct_target_ea
            proof_mode = "direct_target"
        else:
            handler_anchor_ea = _resolve_concrete_dispatch_corridor(
                source_anchor_ea,
                initial_mregs=initial_mregs,
                handler_eas=frozenset(),
                register_snapshots_by_ea=register_snapshots_by_ea,
                dispatch_anchor_eas=dispatch_anchor_eas,
                selector_write_handler_mregs=frozenset({state_mreg}),
                known_block_entry_eas=frozenset(known_entries),
            )
            proof_mode = "corridor_replay"
        logger.debug(
            "native preflight bootstrap replay: func=0x%X source=0x%X "
            "direct_target=0x%X state_mreg=%d state=0x%X target=%s "
            "known=%s proof=%s",
            int(function_ea),
            source_anchor_ea,
            direct_target_ea,
            state_mreg,
            state_constant,
            (None if handler_anchor_ea is None else f"0x{int(handler_anchor_ea):X}"),
            handler_anchor_ea in known_entries,
            proof_mode,
        )
        if (
            handler_anchor_ea is None
            or not isinstance(handler_anchor_ea, int)
            or int(handler_anchor_ea) not in known_entries
        ):
            continue
        discovered = (
            state.native_preanalysis.discover_static_native_bootstrap_route(
                state.native_key,
                source_anchor_ea=int(source_anchor_ea),
                state_constant=int(state_constant),
                handler_anchor_ea=int(handler_anchor_ea),
            )
            or discovered
        )
        logger.debug(
            "native preflight bootstrap: func=0x%X source=0x%X "
            "state_mreg=%d state=0x%X handler=0x%X changed=%s",
            int(function_ea),
            int(source_anchor_ea),
            int(state_mreg),
            int(state_constant),
            int(handler_anchor_ea),
            discovered,
        )
    return discovered


def _static_native_handler_entry_eas(
    flow_graph: FlowGraph,
    dispatcher_blocks: frozenset[int],
) -> frozenset[int]:
    """Return current native block entries outside a recovered dispatcher.

    Native corridor replay may traverse several materialized dispatcher hops.
    A target becomes a handler candidate only when its current MBA block is
    outside the dispatcher region; no inferred table continuation is accepted
    as a handler boundary.
    """
    return frozenset(
        int(block.start_ea)
        for serial, block in flow_graph.blocks.items()
        if int(serial) not in dispatcher_blocks and int(block.start_ea) > 0
    )


def _discover_static_native_bootstrap_routes(
    *,
    mba: object,
    decision: Mapping[str, object],
    state: ResolverSessionState,
) -> bool:
    """Publish entry bootstrap evidence before the one flowchart redo.

    The resolver has just materialized native computed-goto targets.  Re-lift
    the *current* MBA solely to obtain native EA identities for the entry
    source; the portable evidence retains neither this lift nor its serials.
    A detached static handler is intentionally represented by its singleton
    native entry and must bind uniquely after PREOPT regeneration.
    """
    from d810.analyses.control_flow.dispatcher_recovery import recover_dispatcher
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.hexrays.mutation.ir_translator import lift

    logger.debug(
        "static bootstrap discovery: func=0x%X phase=lift",
        int(getattr(mba, "entry_ea", 0)),
    )
    graph = lift(mba)
    logger.debug(
        "static bootstrap discovery: func=0x%X phase=recover_dispatcher blocks=%d",
        int(getattr(mba, "entry_ea", 0)),
        len(graph.blocks),
    )
    recovery = recover_dispatcher(
        graph,
        None,
        materialized_indirect_transfers=state.materialized_transfers,
    )
    dispatcher_map = recovery.dispatch_map
    if dispatcher_map is None:
        return False
    logger.debug(
        "static bootstrap discovery: func=0x%X phase=resolve_candidates "
        "dispatcher_state_mreg=%s",
        int(getattr(mba, "entry_ea", 0)),
        recovery.state_var_reg,
    )
    handler_eas = _static_native_handler_entry_eas(
        graph,
        frozenset(int(serial) for serial in dispatcher_map.dispatcher_blocks),
    )
    if not handler_eas:
        return False

    context_mregs, register_snapshots_by_ea, dispatch_anchor_eas = (
        _bootstrap_native_replay_inputs(state.materialized_transfers)
    )

    def resolve_native_route(
        source_anchor_ea: int,
        state_var_reg: int,
        state_constant: int,
    ) -> int | None:
        if recovery.state_var_reg is not None and int(state_var_reg) != int(
            recovery.state_var_reg
        ):
            return None
        initial_mregs = dict(context_mregs)
        initial_mregs[int(state_var_reg)] = int(state_constant)
        target = _resolve_concrete_dispatch_corridor(
            int(source_anchor_ea),
            initial_mregs=initial_mregs,
            handler_eas=handler_eas,
            register_snapshots_by_ea=register_snapshots_by_ea,
            dispatch_anchor_eas=dispatch_anchor_eas,
        )
        return None if target is None else int(target)

    candidates = _static_native_bootstrap_route_candidates(
        graph,
        state.materialized_transfers,
        native_route_resolver=resolve_native_route,
    )
    logger.debug(
        "static bootstrap discovery: func=0x%X candidates=%s transfers=%d",
        int(getattr(mba, "entry_ea", 0)),
        [
            (hex(int(source_ea)), hex(int(state_value)), hex(int(handler_ea)))
            for source_ea, state_value, handler_ea in candidates
        ],
        len(state.materialized_transfers),
    )
    if not candidates:
        return False
    session = decision.get("session")
    session_id = (
        session.identity_key
        if isinstance(session, ResolverLifecycleSession)
        else "resolver-bootstrap"
    )
    index = MbaBlockIdentityIndex.from_flow_graph(
        generation=0,
        native_key=state.native_key,
        evidence_generation=state.evidence_generation,
        flow_graph=graph,
        session_id=session_id,
    )
    state.bind_current_mba(index)
    discovered = False
    for source_anchor_ea, state_constant, handler_anchor_ea in candidates:
        discovered = (
            state.native_preanalysis.discover_static_native_bootstrap_route(
                state.native_key,
                source_anchor_ea=int(source_anchor_ea),
                state_constant=int(state_constant),
                handler_anchor_ea=int(handler_anchor_ea),
            )
            or discovered
        )
    return discovered


def _on_flowchart_preanalysis(*, function_ea: int, mba: object, decision: dict) -> None:
    """Flowchart-preanalysis seam handler.

    Runs BEFORE Hex-Rays builds ``qflow_chart``: publish portable computed-goto
    evidence and request a rebuild only for later evidence generations.
    Fail-open: a failure here must never gate the decompile.
    """
    key = int(function_ea)
    state = _resolver_state_from_decision(decision)
    if state is None or state.snippet_capture_active:
        return
    if state.native_preanalysis.consume_generated_restart():
        request_hexrays_redo(
            decision,
            "computed_goto_calls_evidence_rebind",
            function_ea=key,
            evidence_generation=state.evidence_generation,
        )
        return
    if state.materialized:
        return
    try:
        if state.materialization is not None:
            resolution = state.portable_evidence.computed_goto_resolution
            if (
                isinstance(resolution, ComputedGotoResolution)
                and resolution.arch == "x86"
                and resolution.patch_plans
                and state.portable_evidence.prepatch_preopt_union_source is None
            ):
                return
            if (
                discover_static_native_bootstrap_routes(key, state)
                and state.native_preanalysis.request_controlled_redo()
            ):
                request_hexrays_redo(
                    decision,
                    "computed_goto_bootstrap_route",
                    function_ea=key,
                    evidence_generation=state.evidence_generation,
                )
            return
        if not _has_unresolved_computed_goto(key):
            return
        resolution = _resolve_computed_goto_resolution(key)
        if resolution is None or not resolution.jmp_targets:
            return
        if not resolution.patch_plans:
            return
        state.begin_materialization(resolution)
        logger.info(
            "computed-goto portable evidence staged: func=0x%X "
            "sites=%d targets=%d reachable=%d arch=%s "
            "authority=frontend_fragment",
            key,
            resolution.site_count,
            resolution.target_count,
            len(resolution.reachable_eas),
            resolution.arch,
        )
        return
    except Exception:
        logger.debug("computed-goto handler failed for 0x%X", key, exc_info=True)


def _on_calls_done_preanalysis(
    *,
    function_ea: int,
    mba: object,
    decision: dict,
) -> None:
    """Advance one staged materialization round over the live CALLS MBA."""
    key = int(function_ea)
    state = _resolver_state_from_decision(decision)
    if state is None or state.snippet_capture_active:
        return
    if state.native_preanalysis.has_pending_generated_restart:
        # Hex-Rays may emit CALLS more than once before control returns to the
        # top-level decompile owner.  Once this generated MBA has requested a
        # restart, later callbacks observe an obsolete graph and must not add
        # maturity-local block starts or synthetic instruction identities to
        # the portable session evidence.
        return
    try:
        from d810.hexrays.mutation.detached_handler_island import (
            imported_detached_snippet_instruction_origins,
        )

        imported_origins = dict(imported_detached_snippet_instruction_origins(mba))
        imported_predicate_eas = frozenset(imported_origins)

        def request_generated_restart(reason: str, **details: object) -> bool:
            if not state.native_preanalysis.request_generated_restart(
                evidence_family="calls_evidence",
                reason=f"CALLS staged {reason} for PREOPT",
            ):
                return False
            decision["defer_generated_restart"] = True
            request_hexrays_redo(
                decision,
                reason,
                function_ea=key,
                **details,
            )
            return True

        def merge_calls_evidence() -> bool:
            changed = False
            transfers = state.materialized_transfers
            handler_evidence = _recover_condition_chain_handler_transfers_from_mba(
                transfers,
                mba,
            )
            if handler_evidence:
                changed = (
                    _merge_materialized_transfers(state, handler_evidence) or changed
                )
                transfers = state.materialized_transfers
            bridge_kwargs = {
                "imported_predicate_eas": imported_predicate_eas,
            }
            if imported_origins:
                bridge_kwargs["imported_instruction_origins"] = imported_origins
            prepatch_source = state.portable_evidence.prepatch_preopt_union_source
            if isinstance(prepatch_source, _PrepatchPreoptUnionSource):
                bridge_kwargs["native_cfg"] = prepatch_source.cfg
            conditional_bridges = recover_conditional_handler_bridge_transfers_from_mba(
                transfers, mba, **bridge_kwargs
            )
            if conditional_bridges:
                changed = (
                    _merge_materialized_transfers(state, conditional_bridges) or changed
                )
            return changed

        if state.materialized:
            calls_evidence_changed = merge_calls_evidence()
            if not calls_evidence_changed:
                return
            request_generated_restart(
                "computed_goto_calls_evidence",
                evidence_generation=state.evidence_generation,
            )
            _refresh_preopt_union_from_calls_evidence(state, mba)
            return

        materialization = state.materialization
        if materialization is None:
            return

        transfers = state.materialized_transfers
        kept_blocks = _keep_static_equality_route_blocks(mba, transfers)
        produced = _recover_static_equality_route_transfers_from_mba(
            materialization.resolution,
            transfers,
            mba,
        )
        if produced:
            _merge_materialized_transfers(state, produced)
            transfers = state.materialized_transfers

        calls_evidence_changed = merge_calls_evidence()
        transfers = state.materialized_transfers

        # Manager preflight normally publishes this before the first MBA.  A
        # direct hook-driven decompile may reach CALLS without that preflight;
        # rerun the same serial-free native proof as the generic fallback.
        if discover_static_native_bootstrap_routes(
            key, state
        ) and request_generated_restart(
            "computed_goto_bootstrap_route",
            evidence_generation=state.evidence_generation,
        ):
            return

        bridge_kwargs = {"imported_predicate_eas": imported_predicate_eas}
        if imported_origins:
            bridge_kwargs["imported_instruction_origins"] = imported_origins
        prepatch_source = state.portable_evidence.prepatch_preopt_union_source
        if isinstance(prepatch_source, _PrepatchPreoptUnionSource):
            bridge_kwargs["native_cfg"] = prepatch_source.cfg
        imported_conditional_bridges = (
            recover_conditional_handler_bridge_transfers_from_mba(
                transfers, mba, **bridge_kwargs
            )
        )
        if imported_conditional_bridges:
            calls_evidence_changed = (
                _merge_materialized_transfers(state, imported_conditional_bridges)
                or calls_evidence_changed
            )
            transfers = state.materialized_transfers

        if calls_evidence_changed:
            materialization.rounds += 1
            request_generated_restart(
                "computed_goto_calls_evidence",
                materialized_count=len(imported_conditional_bridges),
                round=int(materialization.rounds),
            )
            _refresh_preopt_union_from_calls_evidence(state, mba)
            return

        logger.info(
            "computed-goto evidence fixed point: func=0x%X static=%d equality_routes=%d kept=%d",
            key,
            len(transfers),
            len(produced),
            int(kept_blocks),
        )
        state.complete_materialization()
    except Exception:
        logger.debug("computed-goto handler failed for 0x%X", key, exc_info=True)


def install() -> None:
    """Register the computed-goto resolver on the flowchart preanalysis seam."""
    register_flowchart_preanalysis_handler(_HANDLER_NAME, _on_flowchart_preanalysis)
    register_calls_done_preanalysis_handler(
        _CALLS_HANDLER_NAME,
        _on_calls_done_preanalysis,
    )
    register_callinfo_preanalysis_handler(
        _CALLINFO_HANDLER_NAME,
        _on_build_callinfo,
    )
    register_stkpnts_preanalysis_handler(
        _STKPNTS_HANDLER_NAME,
        _on_stkpnts,
    )


def uninstall() -> None:
    unregister_flowchart_preanalysis_handler(_HANDLER_NAME)
    unregister_calls_done_preanalysis_handler(_CALLS_HANDLER_NAME)
    unregister_callinfo_preanalysis_handler(_CALLINFO_HANDLER_NAME)
    unregister_stkpnts_preanalysis_handler(_STKPNTS_HANDLER_NAME)


__all__ = [
    "ComputedGotoResolution",
    "PreoptUnionPreparationResult",
    "is_computed_goto_materialized",
    "resolve_computed_gotos",
    "resolve_computed_gotos_static",
    "stage_computed_goto_preanalysis",
    "prepare_detached_handler_snippets",
    "prepare_requested_detached_call_companions",
    "prepare_preopt_union_closure",
    "get_prepared_preopt_union_closure",
    "prepare_terminal_return_carrier_evidence",
    "capture_detached_route_callinfo_templates",
    "recover_conditional_handler_bridge_transfers_from_mba",
    "install",
    "uninstall",
]

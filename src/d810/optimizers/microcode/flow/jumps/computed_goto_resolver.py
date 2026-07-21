"""Resolve register-computed goto dispatchers that IDA's switch recogniser cannot
crack, by EXECUTING them with d810's concolic engine and materialising the
discovered handler targets on the flowchart-preanalysis seam so Hex-Rays forms
the real CFG.

Motivating shape: a control-flow-flattened
state machine whose dispatcher nodes select the next block with a *cmov/setcc
pointer-select plus additive key* --

    lea rcx, cell_a ; lea rdx, cell_b ; cmp ebx, K ; cmovne rcx, rdx
    mov rax, [rcx] ; add rax, KEY ; jmp rax

There is no indexed jump table, so IDA leaves ``jmp reg`` unresolved and the
handler blocks fall out of the function graph -- Hex-Rays then returns a
truncated/None decompile. This generalises the Tigress indirect-label path
(:mod:`d810.hexrays.preanalysis.indirect_jump_discovery` /
:mod:`~d810.hexrays.preanalysis.indirect_jump_labels`) from an indexed qword
pointer-table to arbitrary computed gotos.

Resolution has two strategies, tried in order:

*Concolic execution* (the fixture's x64 cmov-pointer-select shape).
:meth:`EmulationOracle.trace_corridor` runs the dispatcher from the function
entry and records every executed instruction; the instruction that runs
immediately after a ``jmp reg`` is one of its targets. A flattened state machine
re-enters its dispatcher once per state, so a single trace enumerates every
reachable handler *and* both arms of each 2-way select. Input-dependent branches
that one concrete run cannot reach are covered by supplying extra register/stack
seeds (``initial_seeds``); the discovered target sets are merged across seeds.

*Static const-prop fixpoint* (:func:`resolve_computed_gotos_static`, x86 only;
the setcc+shl+indexed-table+KEY binary-search shape).
A from-entry corridor trace can **fault at instruction 0** when the
prologue writes an unmapped stack and reads unseeded arguments, so the
binary-search dispatcher state is never established -- measured 0/190). A
monotone forward-dataflow fixpoint that JOINs register value-sets at merges
resolves every reachable ``jmp reg`` *without* executing (an unknown read is
Top, not a fault). It is the fallback when concolic finds nothing.

Delivery is a BYTE-PATCH: each ``cmp state,K; cmov; jmp reg`` is rewritten to an
explicit ``cmp state,K; j<cc> true; jmp false``. This is load-bearing: an earlier
cref-based delivery gave a topologically-complete CFG but a *semantically broken*
MBA -- crefs make ``jmp reg`` a multi-target goto yet decouple the condition from
its target, so ``mba-simplify`` strips the now-dead ``cmp``/``cmov`` and collapses
the chain to a single comparison (verified via a full MMAT_CALLS microcode dump).
The explicit ``j<cc>`` preserves the condition, so the block lifts to the
``cmp state,K; jz handler`` equality/range chain the CFF unflattener recovers.

The materialised function is also marked via
:func:`~d810.hexrays.preanalysis.indirect_jump_labels.mark_indirect_dispatcher`
so the unflattener routes recovery to ``MMAT_CALLS`` -- the maturity at which the
equality chain is still intact (GLBOPT1 constant-folds it away). Runs on the
flowchart-preanalysis seam (before Hex-Rays builds ``qflow_chart``) and requests
a Hex-Rays rebuild so the rewritten CFG is picked up.
"""

from __future__ import annotations

import collections
import itertools
import struct
from dataclasses import dataclass, field, replace

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
    StackCallAbiProof,
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
    select_unique_block_native_ea,
)
from d810.analyses.control_flow.native_semantic_closure import (
    NativeCfg,
    NativeEdgeKind,
    NativeSemanticClosure,
    NativeTerminalKind,
    ResolverProvenHandlerEntry,
    plan_native_generation_ranges,
    plan_native_semantic_closure,
)
from d810.analyses.control_flow.native_preanalysis_session import (
    BootstrapRouteBindingEvidence,
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
    predicate_arm_reaches_ea,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
    MaterializedStateRoute,
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
from d810.analyses.value_flow.state_write_anchor import StateWriteAnchorFactCollector
from d810.core.logging import getLogger
from d810.ir.flowgraph import (
    BlockKind,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    OperandKind,
)
from d810.hexrays.preanalysis.flowchart_preanalysis import (
    register_flowchart_preanalysis_handler,
    request_hexrays_redo,
    unregister_flowchart_preanalysis_handler,
)
from d810.hexrays.preanalysis.calls_done_preanalysis import (
    register_calls_done_preanalysis_handler,
    unregister_calls_done_preanalysis_handler,
)
from d810.hexrays.preanalysis.preopt_preanalysis import (
    register_preopt_preanalysis_handler,
    unregister_preopt_preanalysis_handler,
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
    capture_preopt_union_snippet_template,
    detached_callinfo_template_eas,
    detached_preopt_call_stack_points,
    exact_live_predicate_true_is_taken,
    imported_detached_snippet_instruction_origins,
    last_imported_detached_snippet_instruction_origins,
    native_stack_frame_offsets_for_ranges,
    preopt_union_import_in_progress,
    prepare_detached_callinfo_template,
)
from d810.hexrays.preanalysis.indirect_jump_labels import (
    create_dispatcher_target_instructions,
)
from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
    ResolverSessionState,
    resolver_session_state,
)

_PatchPlan = ComputedGotoPatchPlan
_PrepatchPreoptUnionSource = PrepatchPreoptUnionSource


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
_PREOPT_HANDLER_NAME = "computed_goto_resolver.preopt_bootstrap"
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


def _unique_equality_state_targets(
    rows: Sequence[tuple[str, int, int]],
    state_register_name: str,
) -> dict[int, int]:
    """Return only unambiguous equality-leaf targets for one state register."""
    candidates: dict[int, set[int]] = {}
    for register_name, state_constant, target_ea in rows:
        if str(register_name) != str(state_register_name):
            continue
        candidates.setdefault(int(state_constant) & _MASK32, set()).add(int(target_ea))
    return {
        state: next(iter(targets))
        for state, targets in candidates.items()
        if len(targets) == 1
    }


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


def _build_residual_state_route_evidence(
    flow_graph: FlowGraph,
    plans: Sequence[tuple[int, int, int]],
    *,
    state_write_sites: Mapping[tuple[int, int], int],
    state_var_reg: int,
    existing_transfers: Sequence[MaterializedIndirectTransfer],
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Publish exact logical routes for every microcode-proven state plan.

    The live CALLS fixpoint proves the source state write and resolver target,
    independently of whether native byte delivery is also possible.  The
    evidence lets a later LOCOPT MBA bind imported microcode roots without
    inferring from the byte patch or replacing an intervening predicate.
    """
    existing = {
        (
            int(transfer.source_block_ea),
            int(transfer.source_jmp_ea),
            int(transfer.selector_state_constant) & _MASK32,
            int(transfer.target_eas[0]),
        )
        for transfer in existing_transfers
        if transfer.resolver_kind == "residual_state_route_evidence"
        and transfer.selector_state_constant is not None
        and len(transfer.target_eas) == 1
    }
    candidates: set[tuple[int, int, int, int]] = set()
    for source_serial, state_constant, target_ea in plans:
        state = int(state_constant) & _MASK32
        target = int(target_ea)
        write_ea = state_write_sites.get((int(source_serial), state))
        source = flow_graph.get_block(int(source_serial))
        if write_ea is None or source is None or int(source.start_ea) <= 0:
            continue
        candidate = (
            int(source.start_ea),
            int(write_ea),
            state,
            target,
        )
        if candidate not in existing:
            candidates.add(candidate)

    return tuple(
        MaterializedIndirectTransfer(
            source_jmp_ea=write_ea,
            source_block_ea=source_ea,
            materialized_anchor_eas=(),
            target_eas=(target_ea,),
            selector_state_var_reg=int(state_var_reg),
            selector_state_constant=state_constant,
            resolver_kind="residual_state_route_evidence",
        )
        for source_ea, write_ea, state_constant, target_ea in sorted(candidates)
    )


def _plan_residual_state_route_patches(
    flow_graph: FlowGraph,
    transitions: Sequence[object],
    *,
    dispatcher_entry_serial: int,
    state_targets: Mapping[int, int],
) -> tuple[tuple[int, int, int], ...]:
    """Select proven one-way router misses that can activate detached tails."""
    dispatcher_entry = int(dispatcher_entry_serial)
    plans: set[tuple[int, int, int]] = set()
    for transition in transitions:
        state = transition.next_state
        if (
            state is None
            or not transition.is_return
            or transition.via_block is not None
        ):
            continue
        state_constant = int(state) & _MASK32
        target_ea = state_targets.get(state_constant)
        if target_ea is None:
            continue
        source_serial = int(transition.write_block)
        source = flow_graph.get_block(source_serial)
        if source is None or tuple(int(succ) for succ in source.succs) != (
            dispatcher_entry,
        ):
            continue
        plans.add((source_serial, state_constant, int(target_ea)))
    return tuple(sorted(plans))


def _plan_unseen_residual_state_route_patches(
    flow_graph: FlowGraph,
    transitions: Sequence[object],
    *,
    state_targets: Mapping[int, int],
) -> tuple[tuple[int, int, int], ...]:
    """Plan state routes whose native equality target is absent from the MBA.

    At ``hxe_calls_done`` the comparison tree has not yet been normalized to a
    single dispatcher back-edge, so block-number topology is not authoritative.
    The safe invariant is instead that microcode proves the state write while
    the native equality leaf names a target EA that the live MBA does not
    contain.  Delivery merely makes that missing fragment reachable; its own
    indirect transfer must still be proven in a later microcode round.
    """
    live_eas = {
        int(ea)
        for block in flow_graph.blocks.values()
        for ea in (
            int(block.start_ea),
            *(int(insn.ea) for insn in block.insn_snapshots),
        )
    }
    plans: set[tuple[int, int, int]] = set()
    for transition in transitions:
        next_state = transition.next_state
        if next_state is None:
            continue
        state = int(next_state) & _MASK32
        target_ea = state_targets.get(state)
        if target_ea is None or int(target_ea) in live_eas:
            continue
        if flow_graph.get_block(int(transition.write_block)) is None:
            continue
        plans.add((int(transition.write_block), state, int(target_ea)))
    return tuple(sorted(plans))


def _plan_misrouted_exact_state_route_patches(
    flow_graph: FlowGraph,
    transitions: Sequence[object],
    *,
    state_routes: Mapping[int, tuple[int, int | None]],
    state_write_sites: Mapping[tuple[int, int], int],
) -> tuple[tuple[int, int, int], ...]:
    """Override a coarse BST interval only when an exact live leaf disagrees."""
    plans: set[tuple[int, int, int]] = set()
    for transition in transitions:
        next_state = transition.next_state
        if next_state is None:
            continue
        state = int(next_state) & _MASK32
        if (int(transition.write_block), state) not in state_write_sites:
            continue
        route = state_routes.get(state)
        if route is None:
            continue
        target_ea, next_target_ea = route
        exact_handler = find_unique_target_entry_block(
            flow_graph,
            int(target_ea),
            next_target_ea,
        )
        if exact_handler is None:
            continue
        if (
            transition.target_handler is not None
            and int(transition.target_handler) == int(exact_handler)
            and not transition.is_return
        ):
            continue
        if flow_graph.get_block(int(transition.write_block)) is None:
            continue
        plans.add((int(transition.write_block), state, int(target_ea)))
    return tuple(sorted(plans))


def _plan_exact_state_write_route_patches(
    flow_graph: FlowGraph,
    *,
    state_routes: Mapping[int, tuple[int, int | None]],
    state_write_sites: Mapping[tuple[int, int], int],
) -> tuple[tuple[int, int, int], ...]:
    """Plan every exact resolver route backed by a real live state write."""
    plans: set[tuple[int, int, int]] = set()
    for (source_serial, state_constant), _write_ea in state_write_sites.items():
        route = state_routes.get(int(state_constant) & _MASK32)
        if route is None or flow_graph.get_block(int(source_serial)) is None:
            continue
        target_ea, _next_target_ea = route
        plans.add(
            (
                int(source_serial),
                int(state_constant) & _MASK32,
                int(target_ea),
            )
        )
    return tuple(sorted(plans))


def _exact_register_state_write_sites(
    flow_graph: FlowGraph,
    *,
    state_var_reg: int,
    maturity: int,
) -> dict[tuple[int, int], int]:
    """Map unambiguous live register-state writes to their native anchors."""
    candidates: dict[tuple[int, int], set[int]] = {}
    observations = StateWriteAnchorFactCollector().collect(
        flow_graph,
        func_ea=int(flow_graph.func_ea),
        maturity=int(maturity),
        phase="pre_d810",
    )
    for observation in observations:
        payload = observation.payload
        if payload.get("state_var_reg") != int(state_var_reg):
            continue
        block_serial = int(payload["block_serial"])
        state_constant = int(payload["state_const"]) & _MASK32
        block = flow_graph.get_block(block_serial)
        if block is None:
            continue
        instruction_ea = _native_register_immediate_write_near_block(
            block,
            state_var_reg=int(state_var_reg),
            state_constant=state_constant,
        )
        if instruction_ea is None:
            continue
        candidates.setdefault((block_serial, state_constant), set()).add(instruction_ea)
    return {
        key: next(iter(sites)) for key, sites in candidates.items() if len(sites) == 1
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


def _native_register_immediate_write_matches(
    instruction_ea: int,
    *,
    state_var_reg: int,
    state_constant: int,
) -> bool:
    """Validate that a microcode write anchor still names the same native mov."""
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, int(instruction_ea)) <= 0:
        return False
    destination_mreg = None
    if insn.ops[0].type == idaapi.o_reg:
        destination_mreg = _native_register_mreg(_sv_reg_name(insn.ops[0]) or "")
    immediate = int(insn.ops[1].value) if insn.ops[1].type == idaapi.o_imm else None
    return _state_write_values_match(
        mnemonic=idaapi.print_insn_mnem(int(instruction_ea)) or "",
        destination_mreg=destination_mreg,
        immediate=immediate,
        state_var_reg=int(state_var_reg),
        state_constant=int(state_constant),
    )


def _native_register_immediate_write_near_block(
    block: object,
    *,
    state_var_reg: int,
    state_constant: int,
    radius: int = 0x10,
) -> int | None:
    """Locate one exact native write near EAs represented by a live block."""
    import idautils  # type: ignore[import-untyped]

    represented_eas = {int(block.start_ea)}
    represented_eas.update(int(insn.ea) for insn in block.insn_snapshots)
    candidates: set[int] = set()
    for anchor_ea in represented_eas:
        start_ea = max(0, int(anchor_ea) - int(radius))
        end_ea = int(anchor_ea) + int(radius) + 1
        for instruction_ea in idautils.Heads(start_ea, end_ea):
            if _native_register_immediate_write_matches(
                int(instruction_ea),
                state_var_reg=int(state_var_reg),
                state_constant=int(state_constant),
            ):
                candidates.add(int(instruction_ea))
    return next(iter(candidates)) if len(candidates) == 1 else None


def _plan_all_residual_state_route_patches(
    flow_graph: FlowGraph,
    transitions: Sequence[object],
    *,
    dispatcher_entry_serial: int,
    state_targets: Mapping[int, int],
    state_routes: Mapping[int, tuple[int, int | None]] | None = None,
    state_write_sites: Mapping[tuple[int, int], int] | None = None,
) -> tuple[tuple[int, int, int], ...]:
    """Union terminal router misses with routed states whose leaf is detached."""
    plans = set(
        _plan_residual_state_route_patches(
            flow_graph,
            transitions,
            dispatcher_entry_serial=int(dispatcher_entry_serial),
            state_targets=state_targets,
        )
    )
    plans.update(
        _plan_unseen_residual_state_route_patches(
            flow_graph,
            transitions,
            state_targets=state_targets,
        )
    )
    if state_routes and state_write_sites:
        plans.update(
            _plan_exact_state_write_route_patches(
                flow_graph,
                state_routes=state_routes,
                state_write_sites=state_write_sites,
            )
        )
        plans.update(
            _plan_misrouted_exact_state_route_patches(
                flow_graph,
                transitions,
                state_routes=state_routes,
                state_write_sites=state_write_sites,
            )
        )
    if state_write_sites is not None:
        plans = {
            plan
            for plan in plans
            if (int(plan[0]), int(plan[1]) & _MASK32) in state_write_sites
        }
    return tuple(sorted(plans))


def _partition_residual_route_branches(
    branch_targets: Mapping[int, set[tuple[int, int, int]]],
    protected_conditional_eas: frozenset[int],
) -> tuple[
    dict[int, set[tuple[int, int, int]]],
    dict[int, set[tuple[int, int, int]]],
]:
    """Split live conditional predicates from byte-patchable route sites."""
    protected = {
        int(ea): set(facts)
        for ea, facts in branch_targets.items()
        if int(ea) in protected_conditional_eas
    }
    patchable = {
        int(ea): set(facts)
        for ea, facts in branch_targets.items()
        if int(ea) not in protected_conditional_eas
    }
    return protected, patchable


def _residual_predicate_inherited_states(
    flow_graph: FlowGraph,
    plans: Sequence[tuple[int, int, int]],
    *,
    state_write_sites: Mapping[tuple[int, int], int],
) -> dict[int, int]:
    """Bind an exact state write to a following live predicate in its block.

    A residual route can write the dispatcher state immediately before a real
    payload predicate.  Hex-Rays may split the write from the predicate's
    successor arms, so the generic predicate recognizer cannot infer the
    inherited arm state from those successors alone.  The state-route plan and
    exact write EA already prove that value; retain it only when the same
    snapshot block contains one matching write before its conditional tail.
    """
    candidates: dict[int, set[int]] = {}
    for source_serial, state_constant, _target_ea in plans:
        state = int(state_constant) & _MASK32
        write_ea = state_write_sites.get((int(source_serial), state))
        source = flow_graph.get_block(int(source_serial))
        if write_ea is None or source is None or len(source.insn_snapshots) < 2:
            continue
        predicate = source.insn_snapshots[-1]
        if not predicate.is_conditional_jump or int(predicate.ea) <= 0:
            continue
        write_positions = tuple(
            index
            for index, instruction in enumerate(source.insn_snapshots[:-1])
            if int(instruction.ea) == int(write_ea)
        )
        if len(write_positions) != 1:
            continue
        candidates.setdefault(int(predicate.ea), set()).add(state)
    return {
        predicate_ea: next(iter(states))
        for predicate_ea, states in candidates.items()
        if len(states) == 1
    }


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
        or predicate_register is None
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
        predicate_register=int(predicate_register),
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
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Recover exact compare/CMOV state choices before byte materialization.

    Only a register-vs-immediate compare followed by flag-neutral instructions
    and a CMOV with two singleton values qualifies.  The selected constants are
    evidence only; a later stage must map both through the dispatcher.
    """
    import ida_ua  # type: ignore[import-untyped]

    choices: set[MaterializedIndirectTransfer] = set()
    for block_entry, block_state in sorted(entry_state.items()):
        state = dict(block_state)
        pending_compare: tuple[int, int, int, bool] | None = None
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
                        (int(right.value) & _MASK32 if mnemonic == "cmp" else 0),
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
            ida_ua.create_insn(ea)
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
        if mnem == "cmp":
            left, right = insn.ops[0], insn.ops[1]
            if left.type == idaapi.o_reg and right.type == idaapi.o_imm:
                selector = {
                    "selector_register_name": _sv_reg_name(left),
                    "selector_compare_constant": int(right.value) & _MASK32,
                    "selector_state_on_left": True,
                }
            elif left.type == idaapi.o_imm and right.type == idaapi.o_reg:
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
        elif mnem in _SV_CMOV_MNEMS and insn.ops[0].type == idaapi.o_reg:
            dst = _sv_reg_name(insn.ops[0])
            state_t[dst] = _sv_resolve_source(
                insn.ops[1], state_t, is_lea=False
            )  # taken: dst=src
            # not-taken: dst unchanged
            info = {"ea": ea, "cc": _select_cc_nibble(ea, length)}
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
            if selector is not None:
                info.update(selector)
        else:
            _sv_process_writer(mnem, insn, state_f)
            _sv_process_writer(mnem, insn, state_t)
            if mnem not in _SV_FLAG_SAFE_RELOC:
                selector = None
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
                taken_target, taken_state = taken_result
                fallthrough_target, fallthrough_state = fallthrough_result
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
                        taken_resolved_target_ea=taken_target,
                        fallthrough_resolved_target_ea=fallthrough_target,
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
    if not resolved_sites:
        return None

    all_targets: set[int] = set()
    for tgts in resolved_sites.values():
        all_targets.update(tgts)
    forbidden = all_targets | set(entry_state)
    plans, skipped = _bake_patch_plans(
        resolved_sites, block_entry_of, entry_state, forbidden
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
    return ComputedGotoResolution(
        function_ea=int(function_ea),
        jmp_targets={
            int(k): tuple(int(t) for t in v) for k, v in resolved_sites.items()
        },
        reachable_eas=reachable,
        arch=arch,
        executed_insns=steps,
        seeds_run=0,
        stop_reasons=("static_fixpoint", f"unresolved={len(unresolved_sites)}"),
        patch_plans=tuple(plans),
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
        conditional_state_choices=tuple(
            sorted(
                {
                    *_static_conditional_state_choices(entry_state),
                    *_static_branch_state_choices(entry_state),
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


def _native_target_is_return_epilogue(
    target_ea: int,
    *,
    max_instructions: int = 8,
) -> bool:
    """Prove a short x86 frame-teardown corridor ending in ``ret``.

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
            return False
        mnemonic = (idaapi.print_insn_mnem(ea) or "").lower()
        if mnemonic in {"ret", "retn", "retf"}:
            return saw_teardown
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
                return False
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
                return False
            saw_teardown = True
        elif mnemonic == "add":
            if (
                insn.ops[0].type != idaapi.o_reg
                or _sv_reg_name(insn.ops[0]) != "esp"
                or insn.ops[1].type != idaapi.o_imm
            ):
                return False
            saw_teardown = True
        elif mnemonic != "nop":
            return False
        ea += length
    return False


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


def _residual_fragment_ranges(
    resolution: ComputedGotoResolution,
) -> tuple[tuple[int, int], ...]:
    """Form bounded snippet ranges from orphan IDA code within resolver evidence.

    This is structural discovery only: code-item flags delimit candidates; their
    semantics are accepted solely by the live microcode proof adapter.
    """
    import ida_bytes  # type: ignore[import-untyped]
    import ida_funcs  # type: ignore[import-untyped]

    envelope_start = int(resolution.function_ea)
    envelope_end = (
        max(
            (int(ea) for ea in (*resolution.reachable_eas, *resolution.block_entries)),
            default=envelope_start,
        )
        + 0x100
    )
    starts: list[tuple[int, int]] = []
    ea = envelope_start
    max_candidates = 512
    max_bytes = 0x100
    while ea < envelope_end and len(starts) < max_candidates:
        try:
            head = int(ida_bytes.get_item_head(ea))
            flags = ida_bytes.get_flags(head)
            if (
                head != ea
                or not ida_bytes.is_code(flags)
                or ida_funcs.get_func(head) is not None
            ):
                ea += 1
                continue
            end = min(int(ida_bytes.get_item_end(head)) + max_bytes, envelope_end)
            starts.append((head, end))
            ea = max(head + 1, int(ida_bytes.get_item_end(head)))
        except Exception:
            ea += 1
    return tuple(starts)


def _materialize_residual_fragments(
    resolution: ComputedGotoResolution,
    *,
    extra_starts: Sequence[int] = (),
) -> tuple[int, tuple[MaterializedIndirectTransfer, ...]]:
    """Prove and deliver bounded orphan snippets after normal static delivery."""
    import ida_auto  # type: ignore[import-untyped]
    import ida_bytes  # type: ignore[import-untyped]
    import ida_funcs  # type: ignore[import-untyped]
    import ida_hexrays  # type: ignore[import-untyped]
    import ida_segment  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    from d810.backends.hexrays.evidence.residual_indirect_transfer import (
        recognize_residual_indirect_transfer,
    )

    context = _residual_context_mregs(resolution.function_context_register_values)
    if not context:
        return (0, ())
    envelope_start = int(resolution.function_ea)
    envelope_end = (
        max(
            (int(ea) for ea in (*resolution.reachable_eas, *resolution.block_entries)),
            default=envelope_start,
        )
        + 0x100
    )
    evidence_by_branch: dict[int, object] = {}
    candidate_ranges = set(_residual_fragment_ranges(resolution))
    candidate_ranges.update(
        (
            int(start),
            min(int(start) + 0x100, int(envelope_end)),
        )
        for start in extra_starts
        if int(envelope_start) <= int(start) < int(envelope_end)
    )
    for start, end in sorted(candidate_ranges):
        ranges = ida_hexrays.mba_ranges_t()
        ranges.ranges.push_back(idaapi.range_t(int(start), int(end)))
        failure = ida_hexrays.hexrays_failure_t()
        try:
            mba = ida_hexrays.gen_microcode(
                ranges,
                failure,
                None,
                ida_hexrays.DECOMP_NO_WAIT,
                ida_hexrays.MMAT_LOCOPT,
            )
            if mba is None:
                logger.info("residual state-route: CALLS generation returned None")
                continue
            evidence = recognize_residual_indirect_transfer(
                mba, context, envelope_start, envelope_end
            )
        except Exception:
            continue
        if evidence is not None:
            evidence_by_branch.setdefault(int(evidence.conditional_branch_ea), evidence)

    transfers: list[MaterializedIndirectTransfer] = []
    new_heads: list[int] = []
    for evidence in evidence_by_branch.values():
        branch = int(evidence.conditional_branch_ea)
        end = int(evidence.terminal_indirect_transfer_end_ea)
        body = _encode_two_way_branch(
            branch_ea=branch,
            condition_code=int(evidence.proof.condition_code),
            true_target_ea=int(evidence.proof.true_target_ea),
            false_target_ea=int(evidence.proof.false_target_ea),
        )
        if end - branch < len(body):
            continue
        ida_bytes.patch_bytes(branch, body + b"\x90" * (end - branch - len(body)))
        ida_bytes.del_items(branch, ida_bytes.DELIT_EXPAND, end - branch)
        for head in (branch, branch + 6):
            idaapi.create_insn(head)
            new_heads.append(head)
        transfers.append(
            MaterializedIndirectTransfer(
                source_jmp_ea=int(evidence.terminal_indirect_transfer_ea),
                source_block_ea=int(evidence.candidate.fragment_start_ea),
                materialized_anchor_eas=(branch, branch + 6),
                target_eas=(
                    int(evidence.proof.true_target_ea),
                    int(evidence.proof.false_target_ea),
                ),
                condition_code=int(evidence.proof.condition_code),
                true_target_ea=int(evidence.proof.true_target_ea),
                false_target_ea=int(evidence.proof.false_target_ea),
                selector_state_constant=evidence.selector_state_constant,
                resolver_kind="residual_microcode",
                materialized_region_end_ea=end,
            )
        )
    if not transfers:
        return (0, ())
    seg = ida_segment.getseg(int(resolution.function_ea))
    if seg is not None:
        ida_auto.plan_and_wait(seg.start_ea, seg.end_ea)
    func = ida_funcs.get_func(int(resolution.function_ea))
    if func is not None:
        for transfer in transfers:
            for ea in (*transfer.target_eas, *transfer.materialized_anchor_eas):
                if ida_funcs.get_func(int(ea)) is None:
                    ida_funcs.append_func_tail(func, int(ea), _block_end(int(ea)))
        ida_funcs.reanalyze_function(func)
    if seg is not None:
        ida_auto.plan_and_wait(seg.start_ea, seg.end_ea)
    return (len(transfers), tuple(transfers))


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


def _native_equality_state_target_rows(
    function_ea: int,
    *,
    envelope_end_ea: int | None = None,
) -> tuple[tuple[str, int, int], ...]:
    """Return the compatibility projection used by native target planners."""
    return tuple(
        (
            row.register_name,
            int(row.state_constant),
            int(row.direct_target_ea),
        )
        for row in _native_equality_state_rows(
            int(function_ea),
            envelope_end_ea=envelope_end_ea,
        )
    )


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


def _materialize_static_equality_fragments(
    resolution: ComputedGotoResolution,
    *,
    native_rows: tuple[_NativeEqualityRow, ...] | None = None,
    native_setcc_routes: tuple[tuple[_NativeEqualityRow, int, int], ...] = (),
    native_setcc_match_register_values: (
        Mapping[
            _NativeEqualityRow,
            tuple[tuple[str, int], ...],
        ]
        | None
    ) = None,
) -> tuple[int, tuple[MaterializedIndirectTransfer, ...]]:
    """Resolve and byte-materialize detached equality-leaf computed gotos.

    Each candidate is a bounded ``selector-init; cmp state,K; jcc; ...; jmp
    reg`` fragment.  Concrete replay is run twice with matching/non-matching
    selector values and stops at the first indirect target.  The delivery keeps
    the original condition as ``jcc true; jmp false`` so the next MBA sees the
    complete logical CFG.
    """
    import ida_auto  # type: ignore[import-untyped]
    import ida_bytes  # type: ignore[import-untyped]
    import ida_funcs  # type: ignore[import-untyped]
    import ida_segment  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    envelope_end = (
        max(
            (int(ea) for ea in (*resolution.reachable_eas, *resolution.block_entries)),
            default=int(resolution.function_ea),
        )
        + 0x100
    )
    context_mregs = _dispatcher_replay_context_mregs(resolution)
    if context_mregs is None:
        context_mregs = {}
    facts_by_branch: dict[
        int,
        set[
            tuple[
                _NativeEqualityRow,
                int,
                int,
                tuple[tuple[str, int], ...],
            ]
        ],
    ] = {}
    route_candidates: list[MaterializedIndirectTransfer] = []
    setcc_replay_facts: dict[_NativeEqualityRow, set[tuple[int, int]]] = {}
    for replay_row, match_target, nonmatch_target in native_setcc_routes:
        setcc_replay_facts.setdefault(replay_row, set()).add(
            (int(match_target), int(nonmatch_target))
        )
    rows = native_rows
    if rows is None:
        rows = _native_equality_state_rows(
            int(resolution.function_ea),
            envelope_end_ea=envelope_end,
        )
    for row in rows:
        state_var_reg = _native_register_mreg(row.register_name)
        if state_var_reg is None:
            continue
        if row.selector_kind == "setcc":
            matching_plans = tuple(
                plan
                for plan in resolution.patch_plans
                if int(plan.jmp_ea) == int(row.terminal_jmp_ea)
            )
            if len(matching_plans) <= 1:
                replay_facts = setcc_replay_facts.get(row, set())
                replay_match_target_ea = None
                replay_nonmatch_target_ea = None
                if len(replay_facts) == 1:
                    replay_match_target_ea, replay_nonmatch_target_ea = next(
                        iter(replay_facts)
                    )
                route_candidate = _static_equality_route_candidate(
                    row,
                    matching_plans[0] if matching_plans else None,
                    state_var_reg=int(state_var_reg),
                    context_mregs=context_mregs,
                    replay_match_target_ea=replay_match_target_ea,
                    replay_nonmatch_target_ea=replay_nonmatch_target_ea,
                    match_target_register_values=(
                        native_setcc_match_register_values.get(row, ())
                        if native_setcc_match_register_values is not None
                        else ()
                    ),
                )
                if route_candidate is not None:
                    route_candidates.append(route_candidate)
            continue
        entry_mregs = _corridor_entry_mregs(resolution, int(row.block_entry_ea))
        if entry_mregs is None:
            continue
        match_mregs = dict(entry_mregs)
        match_mregs[int(state_var_reg)] = int(row.state_constant)
        nonmatch_mregs = dict(entry_mregs)
        nonmatch_mregs[int(state_var_reg)] = int(row.state_constant) ^ 1
        match_result = _resolve_concrete_dispatch_corridor(
            int(row.block_entry_ea),
            initial_mregs=match_mregs,
            handler_eas=frozenset(),
            return_first_indirect_target=True,
            return_first_indirect_result=True,
        )
        nonmatch_result = _resolve_concrete_dispatch_corridor(
            int(row.block_entry_ea),
            initial_mregs=nonmatch_mregs,
            handler_eas=frozenset(),
            return_first_indirect_target=True,
            return_first_indirect_result=True,
        )
        if not isinstance(match_result, _ConcreteDispatchResult) or not isinstance(
            nonmatch_result,
            _ConcreteDispatchResult,
        ):
            continue
        match_target = int(match_result.target_ea)
        nonmatch_target = int(nonmatch_result.target_ea)
        common_target_register_values = _common_concrete_register_values(
            match_result.register_values,
            nonmatch_result.register_values,
        )
        if not _native_equality_selector_is_materializable(row.selector_kind):
            continue
        if row.condition_code == 4:
            true_target, false_target = int(match_target), int(nonmatch_target)
        elif row.condition_code == 5:
            true_target, false_target = int(nonmatch_target), int(match_target)
        else:
            continue
        facts_by_branch.setdefault(int(row.branch_ea), set()).add(
            (
                row,
                true_target,
                false_target,
                common_target_register_values,
            )
        )

    transfers: list[MaterializedIndirectTransfer] = []
    target_eas: set[int] = set()
    for branch_ea, facts in sorted(facts_by_branch.items()):
        if len(facts) != 1:
            continue
        row, true_target, false_target, target_register_values = next(iter(facts))
        body = _encode_two_way_branch(
            branch_ea=int(branch_ea),
            condition_code=int(row.condition_code),
            true_target_ea=int(true_target),
            false_target_ea=int(false_target),
        )
        region_size = int(row.terminal_end_ea) - int(branch_ea)
        if region_size < len(body):
            continue
        ida_bytes.patch_bytes(
            int(branch_ea),
            body + b"\x90" * (region_size - len(body)),
        )
        ida_bytes.del_items(
            int(branch_ea),
            ida_bytes.DELIT_EXPAND,
            region_size,
        )
        for head_ea in (int(branch_ea), int(branch_ea) + 6):
            idaapi.create_insn(head_ea)
        targets = tuple(dict.fromkeys((int(true_target), int(false_target))))
        target_eas.update(targets)
        transfers.append(
            MaterializedIndirectTransfer(
                source_jmp_ea=int(row.terminal_jmp_ea),
                source_block_ea=int(row.block_entry_ea),
                materialized_anchor_eas=(int(branch_ea), int(branch_ea) + 6),
                target_eas=targets,
                condition_code=int(row.condition_code),
                true_target_ea=int(true_target),
                false_target_ea=int(false_target),
                selector_state_var_reg=_native_register_mreg(row.register_name),
                selector_compare_constant=int(row.state_constant),
                selector_state_on_left=True,
                context_register_values=tuple(sorted(context_mregs.items())),
                target_register_values=tuple(
                    sorted(_residual_context_mregs(target_register_values).items())
                ),
                resolver_kind="static_equality_fixpoint",
                materialized_region_end_ea=int(row.terminal_end_ea),
            )
        )
    dispatcher_fallback_eas = _static_equality_dispatcher_fallback_eas(tuple(transfers))
    for row, match_target, nonmatch_target in native_setcc_routes:
        proven_match_targets = {
            int(candidate.target_eas[0])
            for candidate in route_candidates
            if candidate.selector_state_constant == int(row.state_constant)
            and int(candidate.source_jmp_ea) == int(row.terminal_jmp_ea)
            and len(candidate.target_eas) == 1
        }
        if len(proven_match_targets) != 1:
            continue
        delivery_targets = _setcc_equality_delivery_targets(
            row,
            match_target_ea=int(match_target),
            nonmatch_target_ea=int(nonmatch_target),
            proven_match_target_ea=next(iter(proven_match_targets)),
            dispatcher_fallback_eas=dispatcher_fallback_eas,
        )
        if delivery_targets is None:
            continue
        true_target, false_target = delivery_targets
        body = _encode_two_way_branch(
            branch_ea=int(row.branch_ea),
            condition_code=int(row.condition_code),
            true_target_ea=int(true_target),
            false_target_ea=int(false_target),
        )
        region_size = int(row.terminal_end_ea) - int(row.branch_ea)
        if region_size < len(body):
            continue
        ida_bytes.patch_bytes(
            int(row.branch_ea),
            body + b"\x90" * (region_size - len(body)),
        )
        ida_bytes.del_items(
            int(row.branch_ea),
            ida_bytes.DELIT_EXPAND,
            region_size,
        )
        for head_ea in (int(row.branch_ea), int(row.branch_ea) + 6):
            idaapi.create_insn(head_ea)
        targets = tuple(dict.fromkeys((int(true_target), int(false_target))))
        target_eas.update(targets)
        transfers.append(
            MaterializedIndirectTransfer(
                source_jmp_ea=int(row.terminal_jmp_ea),
                source_block_ea=int(row.block_entry_ea),
                materialized_anchor_eas=(
                    int(row.branch_ea),
                    int(row.branch_ea) + 6,
                ),
                target_eas=targets,
                condition_code=int(row.condition_code),
                true_target_ea=int(true_target),
                false_target_ea=int(false_target),
                selector_state_var_reg=_native_register_mreg(row.register_name),
                selector_compare_constant=int(row.state_constant),
                selector_state_on_left=True,
                context_register_values=tuple(sorted(context_mregs.items())),
                resolver_kind="static_equality_fixpoint",
                materialized_region_end_ea=int(row.terminal_end_ea),
            )
        )
    all_transfers = tuple((*transfers, *route_candidates))
    if not all_transfers:
        return (0, ())

    function = ida_funcs.get_func(int(resolution.function_ea))
    if function is not None:
        for start_ea, end_ea in _equality_fragment_owned_ranges(
            all_transfers,
            block_end=_block_end,
        ):
            _claim_exact_function_tail_range(
                function,
                int(start_ea),
                int(end_ea),
                get_function=ida_funcs.get_func,
                append_function_tail=ida_funcs.append_func_tail,
                delete_function=ida_funcs.del_func,
            )
    segment = ida_segment.getseg(int(resolution.function_ea))
    if segment is not None:
        ida_auto.plan_and_wait(segment.start_ea, segment.end_ea)
    function = ida_funcs.get_func(int(resolution.function_ea))
    if function is not None:
        ida_funcs.reanalyze_function(function)
    logger.info(
        "computed-goto equality materialization: candidates=%d materialized=%d route_candidates=%d targets=%d",
        len(facts_by_branch),
        len(transfers),
        len(route_candidates),
        len(target_eas),
    )
    return len(transfers), all_transfers


def _select_register_indirect_patch_region(
    instructions: Sequence[tuple[int, int, str, bool, bool]],
) -> tuple[int, int] | None:
    """Select a bounded register-only target-computation chain for direct E9 delivery."""
    for terminal_index in range(len(instructions) - 1, -1, -1):
        terminal_start, terminal_end, _mnemonic, _dest_reg, indirect = instructions[
            terminal_index
        ]
        if not indirect:
            continue
        patch_start = int(terminal_start)
        for index in range(terminal_index - 1, -1, -1):
            start_ea, end_ea, mnemonic, dest_is_register, _ = instructions[index]
            if int(end_ea) != patch_start:
                break
            if mnemonic not in _SV_CHAIN_MNEMS or not dest_is_register:
                break
            patch_start = int(start_ea)
        region_size = int(terminal_end) - patch_start
        if region_size >= 5:
            return patch_start, region_size
    return None


def _choose_dispatch_patch_region(
    direct_candidates: Sequence[tuple[int, int]],
    decoded: Sequence[tuple[int, int, str, bool, bool]],
) -> tuple[int, int] | None:
    """Prefer the terminal indirect chain so preceding predicates survive."""
    indirect = _select_register_indirect_patch_region(decoded)
    if indirect is not None:
        return indirect
    return max(direct_candidates) if direct_candidates else None


def _native_dispatch_branch_site(
    block: object,
    *,
    after_ea: int | None = None,
    require_indirect: bool = False,
) -> tuple[int, int] | None:
    """Return a post-write direct branch or safe indirect patch region."""
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]
    import idautils  # type: ignore[import-untyped]

    instruction_eas = [int(insn.ea) for insn in block.insn_snapshots]
    start_ea = min([int(block.start_ea), *instruction_eas])
    if after_ea is not None:
        start_ea = max(start_ea, int(after_ea))
    end_ea = max([int(block.start_ea), *instruction_eas]) + 0x10
    candidates: list[tuple[int, int]] = []
    decoded: list[tuple[int, int, str, bool, bool]] = []
    for ea in idautils.Heads(start_ea, end_ea):
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, int(ea))
        mnemonic = idaapi.print_insn_mnem(int(ea)) if size > 0 else ""
        if size > 0:
            decoded.append(
                (
                    int(ea),
                    int(ea) + int(size),
                    str(mnemonic),
                    insn.ops[0].type == idaapi.o_reg,
                    mnemonic == "jmp" and insn.ops[0].type == idaapi.o_reg,
                )
            )
        if (
            size >= 5
            and (mnemonic in _SV_JCC_MNEMS or mnemonic == "jmp")
            and insn.ops[0].type in {idaapi.o_near, idaapi.o_far}
        ):
            candidates.append((int(ea), int(size)))
    if require_indirect:
        return _select_register_indirect_patch_region(tuple(decoded))
    return _choose_dispatch_patch_region(tuple(candidates), tuple(decoded))


def _native_post_state_write_indirect_site(
    write_ea: int,
    *,
    max_instructions: int = 32,
    materialized_anchor_eas: frozenset[int] = frozenset(),
) -> tuple[int, int] | None:
    """Find the proven fallthrough dispatch delivery after a state write.

    A still-live ``jmp reg`` is accepted through its bounded register chain. A
    direct ``jmp`` is accepted only when static computed-goto materialization
    already recorded its EA as an anchor. Intervening conditional branches are
    payload control flow and are never selected.
    """
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    decoded: list[tuple[int, int, str, bool, bool]] = []
    cursor = int(write_ea)
    for _ in range(int(max_instructions)):
        insn = ida_ua.insn_t()
        size = int(ida_ua.decode_insn(insn, cursor))
        if size <= 0:
            return None
        mnemonic = (idaapi.print_insn_mnem(cursor) or "").lower()
        indirect = mnemonic == "jmp" and insn.ops[0].type == idaapi.o_reg
        decoded.append(
            (
                cursor,
                cursor + size,
                mnemonic,
                insn.ops[0].type == idaapi.o_reg,
                indirect,
            )
        )
        if indirect:
            return _select_register_indirect_patch_region(tuple(decoded))
        if mnemonic in {"ret", "retn", "retf", "call"}:
            return None
        if mnemonic == "jmp" and insn.ops[0].type in {idaapi.o_near, idaapi.o_far}:
            if cursor in materialized_anchor_eas and size >= 5:
                return (cursor, size)
            return None
        cursor += size
    return None


def _native_residual_route_patch_site(
    write_ea: int,
    *,
    materialized_anchor_eas: frozenset[int],
) -> tuple[int, int] | None:
    """Select only the terminal register-indirect delivery after a state write.

    A direct conditional between the state write and the indirect dispatch can
    be payload control flow (for example, a loop-bound guard).  Replacing that
    conditional with the resolved state target erases the opposite arm.  The
    residual-route materializer therefore patches only a bounded fallthrough
    register-target chain and abstains when no such terminal transfer exists.
    """
    return _native_post_state_write_indirect_site(
        int(write_ea),
        materialized_anchor_eas=materialized_anchor_eas,
    )


def _residual_patch_site_is_path_local(
    flow_graph: FlowGraph,
    *,
    source_serial: int,
    patch_ea: int,
    max_blocks: int = 32,
) -> bool:
    """Whether a residual delivery site belongs only to one state-write path.

    Native dispatcher target-computation blocks are commonly shared joins.  A
    state write on one predecessor does not authorize rewriting such a join,
    because another predecessor may reach it with a different state value.
    Accept the patch site only when its unique microcode owner is the write
    block itself or a single-predecessor corridor leading back to that block.
    """
    owners = tuple(
        block
        for block in flow_graph.blocks.values()
        if int(block.start_ea) == int(patch_ea)
        or any(
            int(instruction.ea) == int(patch_ea) for instruction in block.insn_snapshots
        )
    )
    if len(owners) != 1:
        return False

    current_serial = int(owners[0].serial)
    source = int(source_serial)
    seen: set[int] = set()
    while current_serial != source and len(seen) < int(max_blocks):
        if current_serial in seen:
            return False
        seen.add(current_serial)
        current = flow_graph.get_block(current_serial)
        if current is None or len(current.preds) != 1:
            return False
        current_serial = int(current.preds[0])
    return current_serial == source


def _native_predicate_reaches_route_site(
    predicate_ea: int,
    route_ea: int,
    *,
    max_instructions: int = 64,
    max_span: int = 0x100,
) -> bool:
    """Prove that a residual delivery site is in one local predicate arm.

    This is topology evidence only.  State and target identity are checked by
    the caller.  Calls, returns, indirect jumps, undecodable bytes, and paths
    outside the bounded native corridor abstain.
    """
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    predicate = int(predicate_ea)
    target = int(route_ea)
    if predicate == target:
        return True
    if abs(target - predicate) > int(max_span):
        return False
    lower = min(predicate, target) - 0x10
    upper = max(predicate, target) + 0x10
    pending = collections.deque([predicate])
    seen: set[int] = set()
    insn = ida_ua.insn_t()
    while pending and len(seen) < int(max_instructions):
        ea = int(pending.popleft())
        if ea == target:
            return True
        if ea in seen or not (lower <= ea < upper):
            continue
        seen.add(ea)
        size = int(ida_ua.decode_insn(insn, ea))
        if size <= 0:
            continue
        next_ea = ea + size
        mnemonic = (idaapi.print_insn_mnem(ea) or "").lower()
        if mnemonic in {"ret", "retn", "retf", "int", "call"}:
            continue
        if mnemonic == "jmp":
            if insn.ops[0].type in {idaapi.o_near, idaapi.o_far}:
                pending.append(int(insn.ops[0].addr))
            continue
        if mnemonic in _SV_JCC_MNEMS:
            if insn.ops[0].type in {idaapi.o_near, idaapi.o_far}:
                pending.append(int(insn.ops[0].addr))
            pending.append(next_ea)
            continue
        pending.append(next_ea)
    return False


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


def _materialize_residual_state_routes(
    resolution: ComputedGotoResolution,
    transfers: tuple[MaterializedIndirectTransfer, ...],
    *,
    max_rounds: int = 6,
) -> tuple[int, tuple[MaterializedIndirectTransfer, ...]]:
    """Activate detached equality targets from microcode-proven state writes.

    This is profile-gated by the static x86 computed-goto resolution, a
    register-resident condition-chain dispatcher, and a one-way microcode edge
    back to that dispatcher.  Native equality rows provide only the target EA;
    microcode remains authoritative for state identity and the patch site.
    """
    import ida_auto  # type: ignore[import-untyped]
    import ida_bytes  # type: ignore[import-untyped]
    import ida_funcs  # type: ignore[import-untyped]
    import ida_hexrays  # type: ignore[import-untyped]
    import ida_segment  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    from d810.analyses.control_flow.dispatcher_recovery import recover_dispatcher
    from d810.analyses.control_flow.minimal_state_recovery import (
        recover_state_write_transitions_via_partitioned_fixpoint,
    )
    from d810.backends.hexrays.evidence.condition_chain_analysis import (
        analyze_condition_chain_dispatcher,
    )
    from d810.hexrays.mutation.ir_translator import lift

    if resolution.arch != "x86" or not resolution.patch_plans:
        return (0, ())
    func = ida_funcs.get_func(int(resolution.function_ea))
    if func is None:
        return (0, ())

    envelope_end = (
        max(
            (int(ea) for ea in (*resolution.reachable_eas, *resolution.block_entries)),
            default=int(resolution.function_ea),
        )
        + 0x100
    )
    native_rows = _native_equality_state_target_rows(
        int(resolution.function_ea),
        envelope_end_ea=envelope_end,
    )
    delivered_branches: set[int] = set()
    produced: list[MaterializedIndirectTransfer] = []
    delivered_count = 0
    active_transfers = list(transfers)

    for _round in range(int(max_rounds)):
        failure = ida_hexrays.hexrays_failure_t()
        try:
            mba = ida_hexrays.gen_microcode(
                ida_hexrays.mba_ranges_t(func),
                failure,
                None,
                ida_hexrays.DECOMP_NO_WAIT,
                ida_hexrays.MMAT_CALLS,
            )
            if mba is None:
                continue
            graph = lift(mba)
            recovery = recover_dispatcher(
                graph,
                None,
                materialized_indirect_transfers=tuple(active_transfers),
            )
            if (
                recovery.dispatch_map is None
                or recovery.dispatcher_block_serial is None
                or recovery.state_var_reg is None
            ):
                logger.info(
                    "residual state-route: dispatcher recovery incomplete "
                    "map=%s entry=%s reg=%s",
                    recovery.dispatch_map is not None,
                    recovery.dispatcher_block_serial,
                    recovery.state_var_reg,
                )
                break
            range_evidence = analyze_condition_chain_dispatcher(
                mba,
                int(recovery.dispatcher_block_serial),
                None,
                state_var_reg=int(recovery.state_var_reg),
            )
            dispatcher = range_evidence.dispatcher
            if dispatcher is None:
                logger.info("residual state-route: no condition-chain dispatcher")
                break
            state_register_name = next(
                (
                    name
                    for name in _SV_REG_NAMES.values()
                    if _native_register_mreg(name) == int(recovery.state_var_reg)
                ),
                None,
            )
            if state_register_name is None:
                logger.info(
                    "residual state-route: no native register for mreg=%s",
                    recovery.state_var_reg,
                )
                break
            state_targets = _unique_static_equality_handler_targets(
                tuple(active_transfers),
                int(recovery.state_var_reg),
            )
            if not state_targets:
                state_targets = _unique_equality_state_targets(
                    native_rows,
                    state_register_name,
                )
            transitions = recover_state_write_transitions_via_partitioned_fixpoint(
                graph,
                dispatcher,
                None,
                dispatcher_entry_serial=int(recovery.dispatcher_block_serial),
                include_multi_entry_back_edges=True,
                state_var_reg=int(recovery.state_var_reg),
            )
            plans = _plan_all_residual_state_route_patches(
                graph,
                transitions,
                dispatcher_entry_serial=int(recovery.dispatcher_block_serial),
                state_targets=state_targets,
            )
            logger.info(
                "residual state-route: rows=%d targets=%d transitions=%d plans=%d",
                len(native_rows),
                len(state_targets),
                len(transitions),
                len(plans),
            )
        except Exception as exc:
            logger.info("residual state-route recovery failed: %r", exc)
            break

        branch_targets: dict[int, set[tuple[int, int, int]]] = {}
        for source_serial, state_constant, target_ea in plans:
            source = graph.get_block(int(source_serial))
            site = _native_dispatch_branch_site(source) if source is not None else None
            if (
                site is None
                or int(site[0]) in delivered_branches
                or not _residual_patch_site_is_path_local(
                    graph,
                    source_serial=int(source_serial),
                    patch_ea=int(site[0]),
                )
            ):
                continue
            branch_targets.setdefault(int(site[0]), set()).add(
                (int(site[1]), int(state_constant), int(target_ea))
            )

        delivered_targets: list[int] = []
        round_transfers: list[MaterializedIndirectTransfer] = []
        for branch_ea, facts in sorted(branch_targets.items()):
            if len(facts) != 1:
                continue
            branch_size, state_constant, target_ea = next(iter(facts))
            body = b"\xe9" + struct.pack("<i", int(target_ea) - (int(branch_ea) + 5))
            if int(branch_size) < len(body):
                continue
            body += b"\x90" * (int(branch_size) - len(body))
            ida_bytes.patch_bytes(int(branch_ea), body)
            ida_bytes.del_items(
                int(branch_ea), ida_bytes.DELIT_EXPAND, int(branch_size)
            )
            idaapi.create_insn(int(branch_ea))
            delivered_branches.add(int(branch_ea))
            delivered_targets.append(int(target_ea))
            round_transfers.append(
                MaterializedIndirectTransfer(
                    source_jmp_ea=int(branch_ea),
                    source_block_ea=int(branch_ea),
                    materialized_anchor_eas=(int(branch_ea),),
                    target_eas=(int(target_ea),),
                    selector_state_constant=int(state_constant),
                    resolver_kind="residual_state_route",
                )
            )
        if not round_transfers:
            break

        delivered_count += len(round_transfers)
        produced.extend(round_transfers)
        active_transfers.extend(round_transfers)
        func = ida_funcs.get_func(int(resolution.function_ea))
        if func is not None:
            owned_ranges = {
                (int(target_ea), _block_end(int(target_ea)))
                for target_ea in delivered_targets
            }
            owned_ranges.update(
                _equality_fragment_owned_ranges(
                    _exact_equality_fragment_transfers(tuple(active_transfers)),
                    block_end=_block_end,
                )
            )
            for range_start, range_end in sorted(owned_ranges):
                _claim_exact_function_tail_range(
                    func,
                    int(range_start),
                    int(range_end),
                    get_function=ida_funcs.get_func,
                    append_function_tail=ida_funcs.append_func_tail,
                    delete_function=ida_funcs.del_func,
                )
        segment = ida_segment.getseg(int(resolution.function_ea))
        if segment is not None:
            ida_auto.plan_and_wait(segment.start_ea, segment.end_ea)
        func = ida_funcs.get_func(int(resolution.function_ea))
        if func is not None:
            ida_funcs.reanalyze_function(func)
        if segment is not None:
            ida_auto.plan_and_wait(segment.start_ea, segment.end_ea)

        fragment_count, fragment_transfers = _materialize_residual_fragments(
            resolution,
            extra_starts=tuple(delivered_targets),
        )
        delivered_count += int(fragment_count)
        produced.extend(fragment_transfers)
        active_transfers.extend(fragment_transfers)
        func = ida_funcs.get_func(int(resolution.function_ea))
        if func is None:
            break

    return delivered_count, tuple(produced)


def _materialize_residual_state_routes_from_mba(
    resolution: ComputedGotoResolution,
    transfers: tuple[MaterializedIndirectTransfer, ...],
    mba: object,
) -> tuple[int, tuple[MaterializedIndirectTransfer, ...]]:
    """One non-reentrant residual-state delivery round over the live MBA."""
    import ida_auto  # type: ignore[import-untyped]
    import ida_bytes  # type: ignore[import-untyped]
    import ida_funcs  # type: ignore[import-untyped]
    import ida_segment  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    from d810.analyses.control_flow.dispatcher_recovery import recover_dispatcher
    from d810.analyses.control_flow.minimal_state_recovery import (
        recover_state_write_transitions_via_partitioned_fixpoint,
    )
    from d810.backends.hexrays.evidence.condition_chain_analysis import (
        analyze_condition_chain_dispatcher,
    )
    from d810.backends.hexrays.evidence.residual_entry_bridge import (
        recognize_conditional_handler_bridges,
    )
    from d810.hexrays.mutation.ir_translator import lift

    if resolution.arch != "x86" or not resolution.patch_plans:
        return (0, ())
    envelope_end = (
        max(
            (int(ea) for ea in (*resolution.reachable_eas, *resolution.block_entries)),
            default=int(resolution.function_ea),
        )
        + 0x100
    )
    try:
        graph = lift(mba)
        recovery = recover_dispatcher(
            graph,
            None,
            materialized_indirect_transfers=transfers,
        )
        if (
            recovery.dispatch_map is None
            or recovery.dispatcher_block_serial is None
            or recovery.state_var_reg is None
        ):
            logger.info(
                "live residual state-route unavailable: blocks=%d map=%s entry=%s reg=%s",
                len(graph.blocks),
                recovery.dispatch_map is not None,
                recovery.dispatcher_block_serial,
                recovery.state_var_reg,
            )
            return (0, ())
        range_evidence = analyze_condition_chain_dispatcher(
            mba,
            int(recovery.dispatcher_block_serial),
            None,
            state_var_reg=int(recovery.state_var_reg),
        )
        if range_evidence.dispatcher is None:
            logger.info(
                "live residual state-route has no condition-chain dispatcher: entry=%d",
                int(recovery.dispatcher_block_serial),
            )
            return (0, ())
        state_register_name = next(
            (
                name
                for name in _SV_REG_NAMES.values()
                if _native_register_mreg(name) == int(recovery.state_var_reg)
            ),
            None,
        )
        if state_register_name is None:
            return (0, ())
        transitions = recover_state_write_transitions_via_partitioned_fixpoint(
            graph,
            range_evidence.dispatcher,
            None,
            dispatcher_entry_serial=int(recovery.dispatcher_block_serial),
            include_multi_entry_back_edges=True,
            state_var_reg=int(recovery.state_var_reg),
        )
        state_routes = _unique_static_equality_handler_routes(
            transfers,
            int(recovery.state_var_reg),
        )
        state_targets = {
            state: target for state, (target, _bound) in state_routes.items()
        }
        state_write_sites = _exact_register_state_write_sites(
            graph,
            state_var_reg=int(recovery.state_var_reg),
            maturity=int(mba.maturity),
        )
        if not state_targets:
            state_targets = _unique_equality_state_targets(
                _native_equality_state_target_rows(
                    int(resolution.function_ea),
                    envelope_end_ea=envelope_end,
                ),
                state_register_name,
            )
        plans = _plan_all_residual_state_route_patches(
            graph,
            transitions,
            dispatcher_entry_serial=int(recovery.dispatcher_block_serial),
            state_targets=state_targets,
            state_routes=state_routes,
            state_write_sites=state_write_sites,
        )
        inherited_states_by_predicate_ea = _residual_predicate_inherited_states(
            graph,
            plans,
            state_write_sites=state_write_sites,
        )
        logger.info(
            "live residual state-route: blocks=%d entry=%d reg=%d transitions=%d plans=%d",
            len(graph.blocks),
            int(recovery.dispatcher_block_serial),
            int(recovery.state_var_reg),
            len(transitions),
            len(plans),
        )
        if not plans:
            candidates = [
                (
                    int(transition.write_block),
                    hex(int(transition.next_state)),
                    transition.target_handler,
                    bool(transition.is_return),
                    transition.via_block,
                    tuple(
                        int(serial)
                        for serial in graph.blocks[int(transition.write_block)].succs
                    ),
                    hex(int(graph.blocks[int(transition.write_block)].start_ea)),
                )
                for transition in transitions
                if transition.next_state is not None
            ]
            logger.info(
                "live residual state-route candidates: count=%d sample=%s",
                len(candidates),
                candidates[:8],
            )
    except Exception:
        logger.debug("live residual state-route recovery failed", exc_info=True)
        return (0, ())

    branch_targets: dict[int, set[tuple[int, int, int]]] = {}
    try:
        conditional_state_targets = dict(state_targets)
        for state, handler_serial in recovery.dispatch_map.state_to_handler().items():
            handler_block = graph.get_block(int(handler_serial))
            if handler_block is not None and int(handler_block.start_ea) > 0:
                conditional_state_targets.setdefault(
                    int(state) & _MASK32,
                    int(handler_block.start_ea),
                )
        conditional_rows = recognize_conditional_handler_bridges(
            mba,
            state_register=int(recovery.state_var_reg),
            state_targets=conditional_state_targets,
            inherited_states_by_predicate_ea=(inherited_states_by_predicate_ea),
        )
    except Exception:
        logger.warning(
            "live residual state-route conditional recognition failed",
            exc_info=True,
        )
        conditional_rows = ()
    delivered_branch_eas = {
        int(anchor_ea)
        for transfer in transfers
        if transfer.resolver_kind == "residual_state_route"
        for anchor_ea in transfer.materialized_anchor_eas
    }
    materialized_dispatch_anchor_eas = frozenset(
        int(anchor_ea)
        for transfer in transfers
        if transfer.resolver_kind == "static_fixpoint" and len(transfer.target_eas) == 1
        for anchor_ea in transfer.materialized_anchor_eas
    )
    for source_serial, state_constant, target_ea in plans:
        source = graph.get_block(int(source_serial))
        write_ea = state_write_sites.get(
            (int(source_serial), int(state_constant) & _MASK32)
        )
        site = (
            _native_residual_route_patch_site(
                write_ea,
                materialized_anchor_eas=materialized_dispatch_anchor_eas,
            )
            if source is not None and write_ea is not None
            else None
        )
        if site is None or not _residual_patch_site_is_path_local(
            graph,
            source_serial=int(source_serial),
            patch_ea=int(site[0]),
        ):
            continue
        elif int(site[0]) not in delivered_branch_eas:
            branch_targets.setdefault(int(site[0]), set()).add(
                (int(site[1]), int(state_constant), int(target_ea))
            )

    protected_conditional_eas = frozenset(
        int(row.predicate_ea)
        for row in conditional_rows
        if int(row.predicate_ea) in branch_targets
    )

    protected_branches, patchable_branches = _partition_residual_route_branches(
        branch_targets,
        protected_conditional_eas,
    )
    produced = list(
        _build_residual_state_route_evidence(
            graph,
            tuple(plans),
            state_write_sites=state_write_sites,
            state_var_reg=int(recovery.state_var_reg),
            existing_transfers=transfers,
        )
    )
    delivered_targets = [
        int(transfer.target_eas[0])
        for transfer in produced
        if len(transfer.target_eas) == 1
    ]
    for branch_ea, facts in sorted(protected_branches.items()):
        if len(facts) != 1:
            continue
        _branch_size, state_constant, target_ea = next(iter(facts))
        delivered_targets.append(int(target_ea))
        produced.append(
            MaterializedIndirectTransfer(
                source_jmp_ea=int(branch_ea),
                source_block_ea=int(branch_ea),
                materialized_anchor_eas=(int(branch_ea),),
                target_eas=(int(target_ea),),
                selector_state_var_reg=int(recovery.state_var_reg),
                selector_state_constant=int(state_constant),
                resolver_kind="residual_state_route",
            )
        )
    for branch_ea, facts in sorted(patchable_branches.items()):
        if len(facts) != 1:
            continue
        branch_size, state_constant, target_ea = next(iter(facts))
        body = b"\xe9" + struct.pack("<i", int(target_ea) - (int(branch_ea) + 5))
        if int(branch_size) < len(body):
            continue
        body += b"\x90" * (int(branch_size) - len(body))
        ida_bytes.patch_bytes(int(branch_ea), body)
        ida_bytes.del_items(int(branch_ea), ida_bytes.DELIT_EXPAND, int(branch_size))
        idaapi.create_insn(int(branch_ea))
        delivered_targets.append(int(target_ea))
        produced.append(
            MaterializedIndirectTransfer(
                source_jmp_ea=int(branch_ea),
                source_block_ea=int(branch_ea),
                materialized_anchor_eas=(int(branch_ea),),
                target_eas=(int(target_ea),),
                selector_state_var_reg=int(recovery.state_var_reg),
                selector_state_constant=int(state_constant),
                resolver_kind="residual_state_route",
            )
        )
    conditional_bridges = recover_conditional_handler_bridge_transfers_from_mba(
        transfers + tuple(produced),
        mba,
        inherited_states_by_predicate_ea=inherited_states_by_predicate_ea,
    )
    produced.extend(conditional_bridges)
    if not produced:
        return (0, ())

    logger.info(
        "live residual state-route preserved conditionals: %s",
        [
            hex(int(transfer.source_jmp_ea))
            for transfer in produced
            if int(transfer.source_jmp_ea) in protected_conditional_eas
        ],
    )

    func = ida_funcs.get_func(int(resolution.function_ea))
    if func is not None:
        owned_ranges: set[tuple[int, int]] = set()
        for target_ea in delivered_targets:
            ranges = _native_residual_fragment_ranges(
                int(target_ea),
                envelope_start_ea=int(resolution.function_ea),
                envelope_end_ea=int(envelope_end),
            )
            if not ranges:
                ranges = ((int(target_ea), _block_end(int(target_ea))),)
            owned_ranges.update(ranges)
        owned_ranges.update(
            _equality_fragment_owned_ranges(
                _exact_equality_fragment_transfers(transfers),
                block_end=_block_end,
            )
        )
        for range_start, range_end in sorted(owned_ranges):
            _claim_exact_function_tail_range(
                func,
                int(range_start),
                int(range_end),
                get_function=ida_funcs.get_func,
                append_function_tail=ida_funcs.append_func_tail,
                delete_function=ida_funcs.del_func,
            )
    segment = ida_segment.getseg(int(resolution.function_ea))
    if segment is not None:
        ida_auto.plan_and_wait(segment.start_ea, segment.end_ea)
    func = ida_funcs.get_func(int(resolution.function_ea))
    if func is not None:
        ida_funcs.reanalyze_function(func)
    if segment is not None:
        ida_auto.plan_and_wait(segment.start_ea, segment.end_ea)
    return len(produced), tuple(produced)


def _materialize_residual_fragment_from_mba(
    resolution: ComputedGotoResolution,
    mba: object,
) -> tuple[int, tuple[MaterializedIndirectTransfer, ...]]:
    """Deliver one residual indirect fragment proven by the live MBA.

    Flowchart preanalysis is already running inside Hex-Rays microcode
    generation, so recursively calling ``gen_microcode`` here is invalid.  A
    single delivery followed by ``MERR_REDO`` lets Hex-Rays rebuild the MBA and
    expose the next fragment without re-entrancy.
    """
    import ida_auto  # type: ignore[import-untyped]
    import ida_bytes  # type: ignore[import-untyped]
    import ida_funcs  # type: ignore[import-untyped]
    import ida_segment  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    from d810.backends.hexrays.evidence.residual_indirect_transfer import (
        recognize_residual_indirect_transfer,
    )

    context = _residual_context_mregs(resolution.function_context_register_values)
    if not context:
        return (0, ())
    envelope_start = int(resolution.function_ea)
    envelope_end = (
        max(
            (int(ea) for ea in (*resolution.reachable_eas, *resolution.block_entries)),
            default=envelope_start,
        )
        + 0x100
    )
    try:
        evidence = recognize_residual_indirect_transfer(
            mba,
            context,
            envelope_start,
            envelope_end,
        )
    except Exception:
        logger.debug("live residual-fragment recognition failed", exc_info=True)
        return (0, ())
    if evidence is None:
        try:
            block_count = int(mba.qty)
        except Exception:
            block_count = -1
        logger.info(
            "live residual-fragment: no proof in %d blocks",
            block_count,
        )
        return (0, ())

    branch_ea = int(evidence.conditional_branch_ea)
    region_end_ea = int(evidence.terminal_indirect_transfer_end_ea)
    body = _encode_two_way_branch(
        branch_ea=branch_ea,
        condition_code=int(evidence.proof.condition_code),
        true_target_ea=int(evidence.proof.true_target_ea),
        false_target_ea=int(evidence.proof.false_target_ea),
    )
    if region_end_ea - branch_ea < len(body):
        return (0, ())

    ida_bytes.patch_bytes(
        branch_ea,
        body + b"\x90" * (region_end_ea - branch_ea - len(body)),
    )
    ida_bytes.del_items(
        branch_ea,
        ida_bytes.DELIT_EXPAND,
        region_end_ea - branch_ea,
    )
    for head_ea in (branch_ea, branch_ea + 6):
        idaapi.create_insn(head_ea)

    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=int(evidence.terminal_indirect_transfer_ea),
        source_block_ea=int(evidence.candidate.fragment_start_ea),
        materialized_anchor_eas=(branch_ea, branch_ea + 6),
        target_eas=(
            int(evidence.proof.true_target_ea),
            int(evidence.proof.false_target_ea),
        ),
        condition_code=int(evidence.proof.condition_code),
        true_target_ea=int(evidence.proof.true_target_ea),
        false_target_ea=int(evidence.proof.false_target_ea),
        selector_state_constant=evidence.selector_state_constant,
        resolver_kind="residual_microcode",
    )
    function = ida_funcs.get_func(int(resolution.function_ea))
    if function is not None:
        for target_ea in (*transfer.target_eas, *transfer.materialized_anchor_eas):
            if ida_funcs.get_func(int(target_ea)) is None:
                ida_funcs.append_func_tail(
                    function,
                    int(target_ea),
                    _block_end(int(target_ea)),
                )
        ida_funcs.reanalyze_function(function)
    segment = ida_segment.getseg(int(resolution.function_ea))
    if segment is not None:
        ida_auto.plan_and_wait(segment.start_ea, segment.end_ea)
    return (1, (transfer,))


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


def _materialize_residual_entry_bridge(
    resolution: ComputedGotoResolution,
    transfers: tuple[MaterializedIndirectTransfer, ...],
    mba: object,
) -> tuple[int, tuple[MaterializedIndirectTransfer, ...]]:
    """Materialize one proven prologue-to-residual entry bridge, or abstain.

    This is a structural profile gate for the x86 comparison-tree topology.  It
    consumes no loader names or native semantic scans: every predicate, state
    value, dispatcher path edge, and target comes from live microcode or an
    immutable resolver transfer record.
    """
    if resolution.arch != "x86" or not resolution.patch_plans:
        return (0, ())
    import ida_auto  # type: ignore[import-untyped]
    import ida_bytes  # type: ignore[import-untyped]
    import ida_funcs  # type: ignore[import-untyped]
    import ida_hexrays  # type: ignore[import-untyped]
    import ida_segment  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    from d810.analyses.control_flow.dispatcher_recovery import recover_dispatcher
    from d810.analyses.control_flow.residual_entry_bridge import (
        plan_residual_entry_bridge,
    )
    from d810.backends.hexrays.evidence.residual_entry_bridge import (
        recognize_residual_entry_bridge,
        recover_initial_state_write,
        recover_state_routing_nodes,
    )
    from d810.hexrays.mutation.ir_translator import lift

    def _abstain(reason: str) -> tuple[int, tuple[MaterializedIndirectTransfer, ...]]:
        logger.info("residual entry bridge abstained: %s", reason)
        return (0, ())

    try:
        evidence = recognize_residual_entry_bridge(mba)
        if evidence is None:
            return _abstain("no_live_entry_evidence")
        graph = lift(mba)
        recovery = recover_dispatcher(
            graph, None, materialized_indirect_transfers=transfers
        )
        dmap = recovery.dispatch_map
        if dmap is None or recovery.state_var_reg is None:
            return _abstain("dispatcher_recovery_incomplete")
        routing_nodes = recover_state_routing_nodes(
            mba,
            state_register=int(recovery.state_var_reg),
            after_ea=int(evidence.source_store_ea),
            before_ea=int(evidence.source_store_ea) + 0x100,
            transfers=transfers,
        )
        if not routing_nodes:
            return _abstain("no_state_routing_nodes")
        initial_state = recover_initial_state_write(
            mba,
            state_register=int(recovery.state_var_reg),
            after_ea=int(evidence.source_store_ea),
            before_ea=min(node.source_block_ea for node in routing_nodes),
        )
        if initial_state is None:
            return _abstain("no_initial_state_write")
        handler_serial = dmap.resolve_target(int(evidence.taken_state_constant))
        handler = (
            graph.get_block(handler_serial) if handler_serial is not None else None
        )
        if handler is None:
            return _abstain("taken_state_has_no_live_handler")
        residual_target = _exact_equality_native_target(
            transfers,
            int(evidence.fallthrough_state_constant),
        )
        if residual_target is None:
            return _abstain("fallthrough_state_has_no_exact_target")
        plan = plan_residual_entry_bridge(
            evidence=evidence,
            initial_state=initial_state,
            routing_nodes=routing_nodes,
            live_state_targets={
                int(evidence.taken_state_constant): int(handler.start_ea)
            },
            residual_state_targets={
                int(evidence.fallthrough_state_constant): int(residual_target)
            },
            required_patch_size=11,
        )
        if plan is None:
            return _abstain("portable_bridge_plan_rejected")
        logger.info(
            "residual entry bridge candidate: predicate=0x%X store=0x%X "
            "anchor=0x%X taken=0x%X fallthrough=0x%X",
            int(evidence.predicate_ea),
            int(evidence.source_store_ea),
            int(plan.anchor_ea),
            int(plan.true_target_ea),
            int(plan.false_target_ea),
        )
        trampoline = _native_entry_bridge_trampoline(
            predicate_ea=int(evidence.predicate_ea),
            source_store_ea=int(evidence.source_store_ea),
            routing_start_ea=min(node.source_block_ea for node in routing_nodes),
            dispatcher_anchor_ea=int(plan.anchor_ea),
            required_cave_size=11,
        )
        if trampoline is None:
            return _abstain("native_trampoline_not_found")
        entry_ea, entry_size, cave_ea, cave_size = trampoline
        entry_body = _encode_direct_jump(entry_ea, entry_size, cave_ea)
        processor_register = int(ida_hexrays.mreg2reg(int(recovery.state_var_reg), 4))
        state_write = _encode_x86_register_immediate32(
            processor_register,
            int(evidence.taken_state_constant),
        )
        inverted_condition = int(plan.condition_code) ^ 1
        residual_target = int(plan.false_target_ea)
        conditional_residual = (
            b"\x0f"
            + bytes((0x80 | inverted_condition,))
            + struct.pack("<i", residual_target - (cave_ea + 6))
        )
        bridge_body = conditional_residual + (state_write or b"")
        if (
            entry_body is None
            or state_write is None
            or len(bridge_body) != cave_size
            or cave_ea + cave_size != int(plan.anchor_ea)
        ):
            return _abstain("native_bridge_encoding_rejected")

        # Expose both proven targets as function-owned blocks before rebuilding
        # the prologue CFG.  The residual arm can be detached from Hex-Rays'
        # original function chunks even though the static resolver proved it.
        func = ida_funcs.get_func(int(resolution.function_ea))
        if func is None:
            return _abstain("function_not_found")
        for target_ea in (int(plan.anchor_ea), residual_target):
            if ida_funcs.get_func(target_ea) is None:
                ida_funcs.append_func_tail(func, target_ea, _block_end(target_ea))

        ida_bytes.patch_bytes(entry_ea, entry_body)
        ida_bytes.patch_bytes(
            cave_ea,
            bridge_body + b"\x90" * (cave_size - len(bridge_body)),
        )
        ida_bytes.del_items(entry_ea, ida_bytes.DELIT_EXPAND, entry_size)
        ida_bytes.del_items(cave_ea, ida_bytes.DELIT_EXPAND, cave_size)
        for head in (entry_ea, cave_ea, cave_ea + 6):
            idaapi.create_insn(head)
        segment = ida_segment.getseg(int(resolution.function_ea))
        if segment is not None:
            ida_auto.plan_and_wait(segment.start_ea, segment.end_ea)
        ida_funcs.reanalyze_function(func)
        if segment is not None:
            ida_auto.plan_and_wait(segment.start_ea, segment.end_ea)
        return (
            1,
            (
                MaterializedIndirectTransfer(
                    source_jmp_ea=entry_ea,
                    source_block_ea=entry_ea,
                    materialized_anchor_eas=(
                        entry_ea,
                        cave_ea,
                        cave_ea + 6,
                    ),
                    target_eas=(residual_target, int(plan.anchor_ea)),
                    condition_code=inverted_condition,
                    true_target_ea=residual_target,
                    false_target_ea=int(plan.anchor_ea),
                    resolver_kind="residual_entry_bridge",
                    materialized_region_end_ea=cave_ea + cave_size,
                ),
            ),
        )
    except Exception:
        logger.debug("residual entry bridge failed", exc_info=True)
        return (0, ())


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


def _materialize_static(
    resolution: ComputedGotoResolution,
    state: ResolverSessionState,
) -> int:
    """Apply pre-baked patch plans, then re-derive the function and absorb the
    now-reachable orphan blocks. Mirrors the proven spike sequence:
    patch -> del_items -> plan_and_wait -> reanalyze -> absorb -> plan_and_wait.
    Returns the number of sites patched."""
    import ida_auto  # type: ignore[import-untyped]
    import ida_bytes  # type: ignore[import-untyped]
    import ida_funcs  # type: ignore[import-untyped]
    import ida_segment  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    func = ida_funcs.get_func(int(resolution.function_ea))
    if func is None or not resolution.patch_plans:
        return 0

    # Snapshot native equality selectors before patch decoding invalidates
    # detached instruction heads.  The rows remain provenance only; setcc
    # targets still require unique live-microcode validation at CALLS.
    equality_envelope_end = (
        max(
            (int(ea) for ea in (*resolution.reachable_eas, *resolution.block_entries)),
            default=int(resolution.function_ea),
        )
        + 0x100
    )
    native_equality_rows = _native_equality_state_rows(
        int(resolution.function_ea),
        envelope_end_ea=equality_envelope_end,
    )
    native_setcc_match_register_values: dict[
        _NativeEqualityRow,
        tuple[tuple[str, int], ...],
    ] = {}
    native_setcc_routes = _resolve_native_setcc_route_facts(
        resolution,
        native_equality_rows,
        match_register_values_by_row=native_setcc_match_register_values,
    )
    logger.info(
        "computed-goto native setcc replay: rows=%d facts=%s",
        sum(row.selector_kind == "setcc" for row in native_equality_rows),
        [
            (
                hex(int(row.branch_ea)),
                hex(int(row.terminal_jmp_ea)),
                hex(int(row.state_constant) & _MASK32),
                hex(int(match_target)),
                hex(int(nonmatch_target)),
            )
            for row, match_target, nonmatch_target in native_setcc_routes
        ],
    )
    native_handler_entry_routes = _recover_prepatch_handler_entry_routes(
        resolution,
        native_equality_rows,
    )
    static_transfers = _static_materialized_transfers(resolution)
    static_choice_handler_entry_routes = _recover_static_choice_handler_entry_routes(
        resolution,
        static_transfers
        + native_handler_entry_routes
        + resolution.conditional_state_choices,
    )
    static_handler_entry_routes = _recover_static_fixpoint_handler_entry_routes(
        resolution,
        static_transfers,
    )
    handler_entry_routes = (
        *static_handler_entry_routes,
        *native_handler_entry_routes,
        *static_choice_handler_entry_routes,
    )
    static_handler_exit_routes = _recover_prepatch_handler_exit_routes(
        resolution,
        static_transfers,
        handler_entry_routes,
    )
    # 1) apply every byte patch, then re-decode each rewritten region in place.
    new_block_eas: list[int] = []
    for plan in resolution.patch_plans:
        ida_bytes.patch_bytes(plan.patch_start, plan.patch_bytes)
        new_block_eas.extend(plan.new_block_eas)
    for plan in resolution.patch_plans:
        ida_bytes.del_items(
            plan.block_entry, ida_bytes.DELIT_EXPAND, plan.region_end - plan.block_entry
        )
    for plan in resolution.patch_plans:
        for head in plan.insn_heads:
            idaapi.create_insn(int(head))

    # Claim detached equality fragments and handlers before the first global
    # analysis pass. Otherwise IDA may promote a proven handler to a standalone
    # function, excluding it from the flattened parent's CALLS MBA.
    state.indirect_dispatcher_materialized = True
    equality_count, equality_transfers = _materialize_static_equality_fragments(
        resolution,
        native_rows=native_equality_rows,
        native_setcc_routes=native_setcc_routes,
        native_setcc_match_register_values=(native_setcc_match_register_values),
    )

    seg = ida_segment.getseg(int(resolution.function_ea))
    if seg is not None:
        ida_auto.plan_and_wait(seg.start_ea, seg.end_ea)

    # 2) reanalyze with the dispatcher profile already active so the CFF
    #    unflattener routes recovery to MMAT_CALLS.
    func = ida_funcs.get_func(int(resolution.function_ea))
    if func is not None:
        ida_funcs.reanalyze_function(func)
    if seg is not None:
        ida_auto.plan_and_wait(seg.start_ea, seg.end_ea)

    # 3) absorb every discovered block (and each new jcc/jmp leader) that IDA did
    #    not fold into the function on its own.
    func = ida_funcs.get_func(int(resolution.function_ea))
    absorb = _static_absorb_eas(
        resolution,
        new_block_eas=new_block_eas,
    )
    for ea in absorb:
        if func is None:
            break
        end_ea = _block_end(int(ea))
        if end_ea <= int(ea):
            continue
        _claim_exact_function_tail_range(
            func,
            int(ea),
            int(end_ea),
            get_function=ida_funcs.get_func,
            append_function_tail=ida_funcs.append_func_tail,
            delete_function=ida_funcs.del_func,
        )

    func = ida_funcs.get_func(int(resolution.function_ea))
    if func is not None:
        ida_funcs.reanalyze_function(func)
    if seg is not None:
        ida_auto.plan_and_wait(seg.start_ea, seg.end_ea)
    _merge_materialized_transfers(
        state,
        (
            *resolution.conditional_state_choices,
            *_static_materialized_transfer_batch(
                resolution,
                static_transfers=static_transfers,
                equality_transfers=equality_transfers,
                static_handler_entry_routes=(
                    *static_handler_entry_routes,
                    *static_choice_handler_entry_routes,
                ),
                native_handler_entry_routes=native_handler_entry_routes,
                static_handler_exit_routes=static_handler_exit_routes,
            ),
        ),
    )
    return len(resolution.patch_plans) + int(equality_count)


# --------------------------------------------------------------------------- #
# delivery (Tigress cref recipe -- effective only on the preanalysis seam)    #
# --------------------------------------------------------------------------- #
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
            cmp_end = ea + length
        elif mnem.startswith("cmov"):
            cmov = (insn.ops[0].reg, insn.ops[1].reg)
            cc = _select_cc_nibble(ea, length)
        elif mnem == "add" and insn.ops[1].type == idaapi.o_imm:
            key = int(insn.ops[1].value) & mask
        ea += length

    if cmov is None or cc is None or key is None or cmp_end is None:
        return None
    dst, src = cmov
    cell_false, cell_true = lea_cell.get(dst), lea_cell.get(src)
    if cell_false is None or cell_true is None:
        return None
    return {
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
        if mnem in ("jmp", "retn", "ret", "retf", "int") or mnem.startswith("j"):
            return ea
        ea = prev


def deliver_by_byte_patch(resolution: ComputedGotoResolution) -> int:
    """Rewrite each cmov/setcc computed goto into an explicit ``j<cc> true; jmp
    false``. Unlike crefs, this PRESERVES the branch condition, so the block
    lifts to the ``cmp state,K; jz handler`` equality/range chain that
    ``recover_dispatcher`` needs (crefs decouple condition from target, and
    mba-simplify then strips the dead cmp/cmov, collapsing the chain). Returns
    the list of newly-created unconditional-jmp EAs (so the caller can pull them
    into the function)."""
    import ida_bytes  # type: ignore[import-untyped]
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    text = _text_segment(resolution.function_ea)
    if text is None:
        return []
    text_start = text[0]
    new_jmp_eas: list[int] = []
    insn = ida_ua.insn_t()

    def _apply(
        patch_start: int, region_end: int, body: bytes, insn_heads: tuple[int, ...]
    ) -> None:
        ida_bytes.patch_bytes(
            patch_start, body + b"\x90" * (region_end - patch_start - len(body))
        )
        # re-decode the rewritten region so IDA sees the new jcc/jmp instructions
        ida_bytes.del_items(
            patch_start, ida_bytes.DELIT_EXPAND, region_end - patch_start
        )
        for head in insn_heads:
            idaapi.create_insn(int(head))

    for jmp_ea, targets in resolution.jmp_targets.items():
        jlen = ida_ua.decode_insn(insn, int(jmp_ea))
        if jlen <= 0:
            continue
        region_end = int(jmp_ea) + jlen
        if len(targets) == 1:
            body = b"\xe9" + _pack_i32(int(targets[0]) - (int(jmp_ea) + 5))
            if region_end - int(jmp_ea) >= len(body):
                _apply(int(jmp_ea), region_end, body, (int(jmp_ea),))
                new_jmp_eas.append(int(jmp_ea))
            continue
        if len(targets) != 2:
            continue
        info = _analyze_select_block(
            int(jmp_ea), _block_start_of(int(jmp_ea), text_start), resolution.arch
        )
        if info is None:
            continue
        cmp_end = info["cmp_end"]
        jcc_end = cmp_end + 6
        jmp_end = jcc_end + 5
        body = (
            bytes([0x0F, 0x80 + (info["cc"] & 0x0F)])
            + _pack_i32(info["target_true"] - jcc_end)
            + b"\xe9"
            + _pack_i32(info["target_false"] - jmp_end)
        )
        if region_end - cmp_end < len(body):
            continue
        _apply(cmp_end, region_end, body, (cmp_end, jcc_end))
        # the E9 jmp at jcc_end is a NEW instruction (not in the concolic trace's
        # original EAs); return it so the caller pulls it into the function.
        new_jmp_eas.append(int(jcc_end))
    return new_jmp_eas


def _pack_i32(v: int) -> bytes:
    import struct

    return struct.pack("<i", ((int(v) + 0x80000000) & 0xFFFFFFFF) - 0x80000000)


def materialize_computed_gotos(
    resolution: ComputedGotoResolution,
    *,
    state: ResolverSessionState,
) -> int:
    """Create the handler blocks + jump edges for a resolution. Returns the
    number of ``jmp reg`` sites materialised. MUST run on the flowchart seam.

    Delivery is BYTE-PATCH (``deliver_by_byte_patch``): each cmov/setcc computed
    goto is rewritten to an explicit ``j<cc> true; jmp false``. This preserves
    the branch condition, so the block lifts to the ``cmp state,K; jz handler``
    equality/range chain the CFF unflattener recovers. (Crefs were tried and
    REJECTED: they make the jump a multi-target goto but decouple condition from
    target, so mba-simplify strips the dead cmp/cmov and collapses the chain --
    verified via a full CALLS microcode dump.)
    """
    import ida_auto  # type: ignore[import-untyped]
    import ida_funcs  # type: ignore[import-untyped]
    import ida_segment  # type: ignore[import-untyped]

    # Static x86 fixpoint path carries pre-baked patch plans + the full block set.
    if resolution.patch_plans:
        return _materialize_static(resolution, state)

    func = ida_funcs.get_func(int(resolution.function_ea))
    if func is None:
        return 0

    # 1) rewrite the computed gotos to explicit conditional/unconditional jumps
    #    (deliver_by_byte_patch re-decodes each rewritten region in place).
    new_jmp_eas = deliver_by_byte_patch(resolution)
    if not new_jmp_eas:
        return 0
    patched = len(new_jmp_eas)

    # 2) ensure every discovered handler is a code head, re-analyze the region so
    #    IDA follows the new explicit jumps, then pull orphaned blocks -- including
    #    the newly-created jmp instructions -- into the function.
    reachable = tuple(resolution.reachable_eas) + tuple(new_jmp_eas)
    create_dispatcher_target_instructions(resolution.reachable_eas)
    seg = ida_segment.getseg(int(resolution.function_ea))
    if seg is not None:
        ida_auto.plan_and_wait(seg.start_ea, seg.end_ea)
    func = ida_funcs.get_func(int(resolution.function_ea))
    for ea in reachable:
        if func is not None and ida_funcs.get_func(ea) is None:
            ida_funcs.append_func_tail(func, ea, _block_end(ea))

    # Mark this as a materialized register-indirect dispatcher so the CFF
    # unflattener routes recovery to MMAT_CALLS -- the maturity at which the
    # `cmp state, const; jz handler` equality chain is still intact. GLBOPT1
    # constant-folds the chain away, so a GLBOPT1-only recovery reads map_rows=0.
    state.indirect_dispatcher_materialized = True

    if seg is not None:
        ida_funcs.reanalyze_function(ida_funcs.get_func(int(resolution.function_ea)))
        ida_auto.plan_and_wait(seg.start_ea, seg.end_ea)
    return patched


# --------------------------------------------------------------------------- #
# preanalysis handler + registration                                          #
# --------------------------------------------------------------------------- #
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
    if resolution is None or not resolution.jmp_targets:
        static = resolve_computed_gotos_static(int(function_ea))
        if static is not None:
            resolution = static
    if resolution is None:
        return None
    if resolution.patch_plans:
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


def resolve_and_materialize(
    function_ea: int,
    *,
    state: ResolverSessionState,
    **kwargs: object,
) -> ComputedGotoResolution | None:
    """Resolve one computed goto and immediately apply its byte delivery.

    The flowchart hook stages static x86 plans through the between-decompile
    preparer so their PREOPT source can be captured first.  This public helper
    retains immediate delivery for explicit callers and non-static profiles.
    """
    resolution = _resolve_computed_goto_resolution(function_ea, **kwargs)
    if resolution is None:
        return None
    materialised = materialize_computed_gotos(resolution, state=state)
    logger.info(
        "computed-goto: func=0x%x sites=%d targets=%d materialised=%d reachable=%d arch=%s",
        int(function_ea),
        resolution.site_count,
        resolution.target_count,
        materialised,
        len(resolution.reachable_eas),
        resolution.arch,
    )
    return resolution


def stage_computed_goto_preanalysis(
    function_ea: int,
    *,
    state: ResolverSessionState,
    **kwargs: object,
) -> ComputedGotoResolution | None:
    """Resolve computed-goto evidence while preserving static PREOPT input.

    Static x86 plans must retain the original native bytes until the
    between-decompile preparer has captured their prepatch MBA.  Other
    resolver profiles have no detached PREOPT source to preserve and can be
    delivered immediately.
    """
    resolution = _resolve_computed_goto_resolution(function_ea, **kwargs)
    if resolution is None or not resolution.jmp_targets:
        return None

    state.begin_materialization(resolution)
    if resolution.arch == "x86" and resolution.patch_plans:
        state.pending_prepatch_materialization = resolution
        logger.info(
            "computed-goto staged: func=0x%x sites=%d targets=%d "
            "reachable=%d arch=%s",
            int(function_ea),
            resolution.site_count,
            resolution.target_count,
            len(resolution.reachable_eas),
            resolution.arch,
        )
        return resolution

    materialised = materialize_computed_gotos(resolution, state=state)
    logger.info(
        "computed-goto: func=0x%x sites=%d targets=%d materialised=%d reachable=%d arch=%s",
        int(function_ea),
        resolution.site_count,
        resolution.target_count,
        materialised,
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


def _capture_terminal_return_carrier_requests(
    function_ea: int,
    requests: tuple[TerminalReturnCarrierRequest, ...],
) -> int:
    """Capture pending terminal carriers independently of snippet topology."""
    import ida_hexrays  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    from d810.hexrays.mutation.detached_handler_island import (
        capture_terminal_return_carrier_template,
        has_terminal_return_carrier_template,
    )

    captured = 0
    for request in requests:
        if has_terminal_return_carrier_template(function_ea, request):
            continue
        if not _native_target_is_return_epilogue(int(request.terminal_target_ea)):
            logger.info(
                "terminal return-carrier capture abstained: source=0x%X "
                "target=0x%X reason=target_not_epilogue",
                int(request.source_handler_ea),
                int(request.terminal_target_ea),
            )
            continue
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
        if snippet is None or not capture_terminal_return_carrier_template(
            function_ea,
            request,
            snippet,
        ):
            logger.info(
                "terminal return-carrier capture abstained: source=0x%X "
                "target=0x%X state=0x%X reason=no_unique_template",
                int(request.source_handler_ea),
                int(request.terminal_target_ea),
                int(request.state_constant) & _MASK32,
            )
            continue
        captured += 1
        logger.info(
            "terminal return-carrier captured: func=0x%X source=0x%X "
            "target=0x%X state=0x%X blocks=%d",
            function_ea,
            int(request.source_handler_ea),
            int(request.terminal_target_ea),
            int(request.state_constant) & _MASK32,
            int(snippet.qty),
        )
    return captured


def prepare_terminal_return_carrier_templates(state: ResolverSessionState) -> int:
    """Consume pending CALLS carrier evidence between decompilations."""
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
        return _capture_terminal_return_carrier_requests(key, requests)
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
    terminal_target_eas = tuple(
        sorted(
            {
                int(transfer.target_eas[0])
                for transfer in transfers
                if transfer.resolver_kind == "static_handler_entry_route"
                and transfer.selector_state_var_reg is not None
                and int(transfer.selector_state_var_reg) == int(state_var_reg)
                and transfer.selector_state_constant is not None
                and len(transfer.target_eas) == 1
                and _native_target_is_return_epilogue(int(transfer.target_eas[0]))
            }
        )
    )
    if not terminal_target_eas:
        return 0

    from d810.hexrays.mutation.detached_handler_island import (
        capture_terminal_return_carrier_template,
    )
    from d810.hexrays.mutation.ir_translator import lift

    flow_graph = lift(mba)
    write_sites = _exact_register_state_write_sites(
        flow_graph,
        state_var_reg=int(state_var_reg),
        maturity=int(mba.maturity),
    )
    write_eas_by_state: dict[int, list[int]] = {}
    for (_serial, state_constant), write_ea in write_sites.items():
        write_eas_by_state.setdefault(int(state_constant), []).append(int(write_ea))
    requests = plan_terminal_return_carrier_requests_from_state_writes(
        transfers,
        write_eas_by_state,
        terminal_target_eas,
        state_var_reg=int(state_var_reg),
    )
    captured_requests = tuple(
        request
        for request in requests
        if capture_terminal_return_carrier_template(
            int(function_ea),
            request,
            mba,
        )
    )
    if not captured_requests:
        return 0
    state.native_preanalysis.merge_terminal_return_carrier_requests(
        state.native_key,
        captured_requests,
    )
    logger.info(
        "PREOPT union captured terminal return carriers: %s",
        [
            (
                hex(int(request.source_handler_ea)),
                hex(int(request.terminal_target_ea)),
                hex(int(request.state_constant)),
            )
            for request in captured_requests
        ],
    )
    return len(captured_requests)


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
    """Return unique resolver-cut edges whose endpoints share the union.

    PREOPT represents an unresolved indirect tail with a synthetic empty
    successor.  Rebinding that sentinel is safe only when one native
    instruction has exactly one resolver-proven target and the target has an
    owned stable-EA entry in the same closure.
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
    existing_ranges_by_target: dict[
        int, set[tuple[tuple[int, int], ...]]
    ] = {}
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


def _capture_prepatch_preopt_union_source(
    state: ResolverSessionState,
    resolution: ComputedGotoResolution,
    transfers: tuple[MaterializedIndirectTransfer, ...],
) -> bool:
    """Capture one source union before byte delivery can detach its handlers.

    Boundary ownership is intentionally not bound here.  The first live
    top-level MBA supplies that evidence later through
    :func:`prepare_preopt_union_closure`.
    """
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
    region = plan_preopt_union_region(enriched)
    if region.abstentions or region.primary_seed_ea is None or not region.native_ranges:
        return abstain(
            "no_complete_union_region",
            tuple(
                (hex(int(row.target_ea)), row.reason.value)
                for row in region.abstentions
            ),
        )
    function = ida_funcs.get_func(key)
    if function is None:
        return abstain("function_not_found")

    resolver_targets_by_source = _resolver_targets_by_source(enriched)
    cfg_result = build_native_semantic_cfg(
        function,
        live_native_eas=frozenset(),
        seed_eas=tuple(dict.fromkeys((key, *region.seed_eas))),
        resolver_cut_eas=tuple(
            sorted(
                {
                    *(int(source_ea) for source_ea in resolution.jmp_targets),
                    *(
                        int(transfer.source_jmp_ea)
                        for transfer in enriched
                        if transfer.resolver_kind == "static_handler_exit_route"
                    ),
                }
            )
        ),
        resolver_proven_unmarked_entry_eas=region.seed_eas,
        resolver_target_eas_by_source={
            source_ea: tuple(sorted(target_eas))
            for source_ea, target_eas in resolver_targets_by_source.items()
        },
    )
    if cfg_result.abstentions:
        return abstain(
            "native_cfg_abstention",
            tuple(
                (
                    row.reason.value,
                    hex(int(row.entry_ea)),
                    hex(int(row.cursor_ea)),
                )
                for row in cfg_result.abstentions
            ),
        )
    closure_seed_eas = tuple(
        sorted(
            set(int(seed_ea) for seed_ea in region.seed_eas)
            | {
                int(target_ea)
                for target_eas in resolver_targets_by_source.values()
                for target_ea in target_eas
                if int(target_ea) in cfg_result.cfg.blocks_by_ea
            }
        )
    )
    closure = plan_native_semantic_closure(
        cfg_result.cfg,
        tuple(
            ResolverProvenHandlerEntry(
                entry_ea=int(seed_ea),
                provenance=(
                    "static_handler_entry_route"
                    if int(seed_ea) in region.seed_eas
                    else "resolver_proven_dispatch_target"
                ),
            )
            for seed_ea in closure_seed_eas
        ),
    )
    if closure.abstentions or not closure.native_ranges:
        return abstain(
            "semantic_closure_abstention",
            tuple(
                (
                    row.reason.value,
                    (
                        None
                        if row.source_block_ea is None
                        else hex(int(row.source_block_ea))
                    ),
                    None if row.target_ea is None else hex(int(row.target_ea)),
                )
                for row in closure.abstentions
            ),
        )

    normalized_ranges = tuple(
        (int(native_range.start_ea), int(native_range.end_ea))
        for native_range in closure.native_ranges
    )
    terminal_return_entry_eas = tuple(
        int(entry_ea)
        for entry_ea in closure.included_block_eas
        if cfg_result.cfg.blocks_by_ea[int(entry_ea)].terminal
        is NativeTerminalKind.RETURN
    )
    generation_ranges = tuple(
        (int(native_range.start_ea), int(native_range.end_ea))
        for native_range in plan_native_generation_ranges(
            closure,
            required_entry_eas=terminal_return_entry_eas,
        )
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

    source = _PrepatchPreoptUnionSource(
        primary_seed_ea=int(region.primary_seed_ea),
        seed_eas=tuple(int(seed_ea) for seed_ea in region.seed_eas),
        seed_native_ranges=tuple(region.seed_native_ranges),
        native_ranges=normalized_ranges,
        imported_block_entry_eas=tuple(closure.included_block_eas),
        cfg=cfg_result.cfg,
        closure=closure,
    )
    _merge_native_facts(
        state,
        native_cfg=source.cfg,
        semantic_closure=source.closure,
        transfers=enriched,
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
    imported_seed_eas: tuple[int, ...] = (),
    stack_carrier_consumer_load_eas_by_displacement: (
        Mapping[int, Sequence[int]] | None
    ) = None,
    native_stack_frame_offsets_by_ea: Mapping[int, tuple[int, ...]] | None = None,
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
            transfer = conditional_candidates[0]
            assert transfer.true_target_ea is not None
            assert transfer.false_target_ea is not None
            assert transfer.selector_state_var_reg is not None
            assert transfer.selector_compare_constant is not None
            assert transfer.condition_code is not None
            true_target_ea = int(transfer.true_target_ea)
            false_target_ea = int(transfer.false_target_ea)
            true_owner = target_owner(true_target_ea)
            false_owner = target_owner(false_target_ea)
            if true_owner is None or false_owner is None:
                return None
            conditional_ports.append(
                DetachedSnippetConditionalBoundaryPort(
                    source_block_ea=source_ea,
                    predicate_ea=source_instruction_ea,
                    old_taken_target_ea=None,
                    old_fallthrough_target_ea=None,
                    taken_target_ea=true_target_ea,
                    fallthrough_target_ea=false_target_ea,
                    state_register=None,
                    taken_state=None,
                    fallthrough_state=None,
                    source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                    taken_target_owner=true_owner,
                    fallthrough_target_owner=false_owner,
                    resolver_kind="resolver_proven_register_compare_cut",
                    predicate_size=4,
                    condition_code=int(transfer.condition_code),
                    predicate_register=int(transfer.selector_state_var_reg),
                    predicate_constant=(
                        int(transfer.selector_compare_constant) & _MASK32
                    ),
                )
            )
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
    conditional_bridges = tuple(
        transfer
        for transfer in transfers
        if transfer.resolver_kind == "conditional_handler_bridge"
        and transfer.predicate_true_state is not None
        and transfer.predicate_false_state is not None
        and transfer.true_target_ea is not None
        and transfer.false_target_ea is not None
    )

    def consumed_by_conditional_bridge(
        transfer: MaterializedIndirectTransfer,
    ) -> bool:
        if (
            live_mba is None
            or transfer.resolver_kind != "residual_state_route_evidence"
            or transfer.selector_state_constant is None
            or len(transfer.target_eas) != 1
        ):
            return False
        state_target = (
            int(transfer.selector_state_constant) & _MASK32,
            int(transfer.target_eas[0]),
        )
        route_ea = int(transfer.source_jmp_ea)
        for bridge in conditional_bridges:
            bridge_arms = {
                (
                    int(bridge.predicate_true_state) & _MASK32,
                    int(bridge.true_target_ea),
                ),
                (
                    int(bridge.predicate_false_state) & _MASK32,
                    int(bridge.false_target_ea),
                ),
            }
            if state_target not in bridge_arms:
                continue
            if (
                bridge.predicate_predecessor_ea is not None
                and route_ea == int(bridge.predicate_predecessor_ea)
            ) or predicate_arm_reaches_ea(
                live_mba,
                predicate_ea=int(bridge.source_jmp_ea),
                route_ea=route_ea,
            ):
                return True
        return False

    remaining_transfers = tuple(
        transfer
        for transfer in transfers
        if not consumed_by_conditional_bridge(transfer)
    )
    live_entry_ports = _preopt_live_residual_route_boundary_ports(
        remaining_transfers,
        live_mba=live_mba,
        live_native_eas=live_native_eas,
        imported_entry_eas=frozenset(imported_entry_eas),
        native_cfg=native_cfg,
    )
    if live_entry_ports is None:
        return None
    direct_ports.extend(live_entry_ports)
    composed_direct_ports, entry_choice_ports = (
        _compose_preopt_stack_carried_entry_choice_ports(
            transfers,
            tuple(direct_ports),
            live_native_eas=live_native_eas,
            imported_entry_eas=frozenset(imported_entry_eas),
            native_cfg=native_cfg,
            consumer_load_eas_by_displacement=(
                {}
                if stack_carrier_consumer_load_eas_by_displacement is None
                else stack_carrier_consumer_load_eas_by_displacement
            ),
            native_stack_frame_offsets_by_ea=(
                {}
                if native_stack_frame_offsets_by_ea is None
                else native_stack_frame_offsets_by_ea
            ),
            existing_conditional_ports=tuple(conditional_ports),
        )
    )
    direct_ports = list(composed_direct_ports)
    conditional_ports.extend(entry_choice_ports)
    conditional_ports = list(
        _compose_preopt_stack_carrier_router_ports(
            transfers,
            tuple(conditional_ports),
            imported_entry_eas=frozenset(imported_entry_eas),
            live_native_eas=live_native_eas,
            native_cfg=native_cfg,
            consumer_load_eas_by_displacement=(
                {}
                if stack_carrier_consumer_load_eas_by_displacement is None
                else stack_carrier_consumer_load_eas_by_displacement
            ),
            native_stack_frame_offsets_by_ea=(
                {}
                if native_stack_frame_offsets_by_ea is None
                else native_stack_frame_offsets_by_ea
            ),
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
    live_bridge_semantics_by_source: dict[
        int,
        set[frozenset[tuple[int, int]]],
    ] = {}
    for transfer in transfers:
        if (
            transfer.resolver_kind != "conditional_handler_bridge"
            or transfer.predicate_true_state is None
            or transfer.predicate_false_state is None
            or transfer.true_target_ea is None
            or transfer.false_target_ea is None
        ):
            continue
        live_bridge_semantics_by_source.setdefault(
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
            if static_semantics in live_bridge_semantics_by_source.get(
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
        if is_static_state_choice:
            if live_mba is None:
                continue
            live_source = _find_unique_live_predicate_block(
                live_mba,
                predicate_ea,
            )
            if live_source is None:
                logger.info(
                    "PREOPT static conditional choice abstained: "
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
            predicate_true_is_taken = exact_live_predicate_true_is_taken(
                live_source,
                predicate_ea=predicate_ea,
                condition_code=int(transfer.condition_code),
                predicate_register=transfer.predicate_register,
                predicate_size=transfer.predicate_size,
                predicate_constant=(
                    None
                    if is_static_state_choice
                    and transfer.predicate_register is None
                    and transfer.predicate_size is None
                    else (
                        0
                        if transfer.predicate_compare_constant is None
                        else int(transfer.predicate_compare_constant)
                    )
                ),
            )
            if predicate_true_is_taken not in (True, False):
                logger.info(
                    "PREOPT static conditional choice abstained: "
                    "source=blk%d@0x%X predicate=0x%X reason=orientation",
                    int(live_source.serial),
                    int(live_source.start),
                    predicate_ea,
                )
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
            predicate_size=transfer.predicate_size,
            condition_code=int(transfer.condition_code),
            predicate_register=transfer.predicate_register,
            predicate_constant=(
                None
                if is_static_state_choice
                and transfer.predicate_register is None
                and transfer.predicate_size is None
                else (
                    0
                    if transfer.predicate_compare_constant is None
                    else int(transfer.predicate_compare_constant) & _MASK32
                )
            ),
            predicate_true_is_taken=bool(predicate_true_is_taken),
        )
        if is_static_state_choice:
            logger.info(
                "PREOPT static conditional choice port: "
                "source=0x%X compare=0x%X predicate=0x%X "
                "taken_state=0x%X taken_target=0x%X "
                "fallthrough_state=0x%X fallthrough_target=0x%X",
                source_block_ea,
                int(transfer.materialized_anchor_eas[0]),
                predicate_ea,
                taken_state,
                taken_target_ea,
                fallthrough_state,
                fallthrough_target_ea,
            )
        candidates.setdefault((source_block_ea, predicate_ea), set()).add(port)
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
                    )
                ),
            )
        return None
    return tuple(next(iter(ports)) for _source, ports in sorted(candidates.items()))


def _preopt_live_residual_route_boundary_ports(
    transfers: tuple[MaterializedIndirectTransfer, ...],
    *,
    live_mba: object | None,
    live_native_eas: frozenset[int],
    imported_entry_eas: frozenset[int],
    native_cfg: NativeCfg | None,
) -> tuple[DetachedSnippetDirectBoundaryPort, ...] | None:
    """Bind a proven live one-way state tail to its imported handler.

    A state choice may occur in an earlier two-way block and reconverge before
    the actual dispatcher state write.  Only the one-way post-dominator that
    contains an exact residual state-write anchor may cross into the imported
    union.  Its sole old successor must remain a recovered dispatcher router.
    """
    if live_mba is None or native_cfg is None:
        return ()
    dispatcher_router_eas = {
        int(router_ea)
        for transfer in transfers
        for router_ea in transfer.dispatcher_router_eas
    }
    rejections: list[tuple[str, int, int]] = []
    candidates: list[tuple[int, DetachedSnippetDirectBoundaryPort]] = []

    def live_candidate(
        transfer: MaterializedIndirectTransfer,
        source_write_ea: int,
        target_ea: int,
    ) -> DetachedSnippetDirectBoundaryPort | None:
        source_matches = tuple(
            block
            for serial in range(int(live_mba.qty))
            for block in (live_mba.get_mblock(serial),)
            if block is not None
            and int(block.start) <= source_write_ea < int(block.end)
        )
        if len(source_matches) != 1:
            return None
        represented = source_matches[0]
        represented_eas = _live_block_instruction_eas(represented)
        represented_entry_ea = select_unique_block_native_ea(
            int(represented.start),
            represented_eas,
        )
        successor_serials = tuple(int(serial) for serial in represented.succset)
        if represented_entry_ea is None or len(successor_serials) != 1:
            return None
        old_successor = live_mba.get_mblock(successor_serials[0])
        if old_successor is None:
            return None
        old_successor_ea = select_unique_block_native_ea(
            int(old_successor.start),
            _live_block_instruction_eas(old_successor),
        )
        if (
            old_successor_ea is None
            or int(old_successor_ea) not in dispatcher_router_eas
            or int(represented_entry_ea) not in live_native_eas
        ):
            return None
        source_instruction_ea = int(represented.tail.ea)
        if source_instruction_ea <= 0:
            source_instruction_ea = source_write_ea
        return DetachedSnippetDirectBoundaryPort(
            source_block_ea=int(represented_entry_ea),
            source_instruction_ea=source_instruction_ea,
            endpoint_block_ea=int(represented_entry_ea),
            old_successor_eas=(int(old_successor_ea),),
            target_ea=target_ea,
            state_register=int(transfer.selector_state_var_reg),
            state_constant=int(transfer.selector_state_constant) & _MASK32,
            source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            endpoint_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
            delivery_mode="redirect_edge",
            resolver_kind=transfer.resolver_kind,
            old_successor_owners=(DetachedSnippetBoundaryPortOwner.LIVE,),
        )

    for transfer in transfers:
        if (
            transfer.resolver_kind != "residual_state_route_evidence"
            or transfer.selector_state_var_reg is None
            or transfer.selector_state_constant is None
            or len(transfer.target_eas) != 1
        ):
            continue
        source_write_ea = int(transfer.source_jmp_ea)
        source_block_ea = int(transfer.source_block_ea)
        target_ea = int(transfer.target_eas[0])
        if target_ea not in imported_entry_eas:
            rejections.append(("target_ownership", source_write_ea, target_ea))
            continue
        native_matches = tuple(
            block
            for block in native_cfg.blocks_by_ea.values()
            if int(block.start_ea) <= source_write_ea < int(block.end_ea)
        )
        exact_native_source = native_cfg.blocks_by_ea.get(source_block_ea)
        if exact_native_source is not None and (
            int(exact_native_source.start_ea)
            <= source_write_ea
            < int(exact_native_source.end_ea)
        ):
            native_source = exact_native_source
        else:
            if len(native_matches) != 1:
                port = live_candidate(transfer, source_write_ea, target_ea)
                if port is not None:
                    candidates.append((source_write_ea, port))
                    continue
                rejections.append(("native_range_owner", source_write_ea, target_ea))
                continue
            (native_source,) = native_matches
        if len(native_source.outgoing_edges) != 1:
            rejections.append(("native_edge_count", source_write_ea, target_ea))
            continue
        edge = native_source.outgoing_edges[0]
        compatible_terminal_eas = {
            int(candidate_edge.source_instruction_ea)
            for candidate_block in native_matches
            if len(candidate_block.outgoing_edges) == 1
            for candidate_edge in candidate_block.outgoing_edges
            if candidate_edge.kind is edge.kind
            and candidate_edge.target_ea == edge.target_ea
            and candidate_edge.source_instruction_ea is not None
        }
        if len(compatible_terminal_eas) == 1:
            edge = replace(
                edge,
                source_instruction_ea=next(iter(compatible_terminal_eas)),
            )
        elif len(compatible_terminal_eas) > 1:
            rejections.append(("native_terminal_conflict", source_write_ea, target_ea))
            continue
        if (
            edge.kind not in {NativeEdgeKind.DIRECT_JUMP, NativeEdgeKind.FALLTHROUGH}
            or edge.target_ea is None
            or edge.source_instruction_ea is None
            or int(edge.target_ea) not in dispatcher_router_eas
        ):
            edge_target = (
                "none" if edge.target_ea is None else f"0x{int(edge.target_ea):X}"
            )
            edge_source = (
                "none"
                if edge.source_instruction_ea is None
                else f"0x{int(edge.source_instruction_ea):X}"
            )
            rejections.append(
                (
                    "native_router_edge:"
                    f"{edge.kind.value}:{edge_source}:{edge_target}",
                    source_write_ea,
                    target_ea,
                )
            )
            continue
        source_instruction_ea = int(edge.source_instruction_ea)
        old_successor_ea = int(edge.target_ea)
        native_source_entry_ea = int(native_source.start_ea)
        if native_source_entry_ea in imported_entry_eas:
            old_successor_owner = (
                DetachedSnippetBoundaryPortOwner.IMPORTED
                if old_successor_ea in imported_entry_eas
                else (
                    DetachedSnippetBoundaryPortOwner.LIVE
                    if old_successor_ea in live_native_eas
                    else None
                )
            )
            if old_successor_owner is None:
                rejections.append(
                    ("imported_old_successor_owner", source_write_ea, target_ea)
                )
                continue
            candidates.append(
                (
                    source_write_ea,
                    DetachedSnippetDirectBoundaryPort(
                        source_block_ea=native_source_entry_ea,
                        source_instruction_ea=source_instruction_ea,
                        endpoint_block_ea=native_source_entry_ea,
                        old_successor_eas=(old_successor_ea,),
                        target_ea=target_ea,
                        state_register=int(transfer.selector_state_var_reg),
                        state_constant=(
                            int(transfer.selector_state_constant) & _MASK32
                        ),
                        source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                        endpoint_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                        target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                        delivery_mode="redirect_edge",
                        resolver_kind=transfer.resolver_kind,
                        old_successor_owners=(old_successor_owner,),
                    ),
                )
            )
            continue
        source_matches = tuple(
            block
            for serial in range(int(live_mba.qty))
            for block in (live_mba.get_mblock(serial),)
            if block is not None
            and int(block.start) <= source_write_ea < int(block.end)
        )
        if len(source_matches) != 1:
            logger.info(
                "PREOPT live residual-route range lookup: "
                "write=0x%X source_block=0x%X target=0x%X matches=%s blocks=%s",
                source_write_ea,
                source_block_ea,
                target_ea,
                tuple(int(block.serial) for block in source_matches),
                tuple(
                    (
                        int(block.serial),
                        int(block.start),
                        int(block.end),
                        _live_block_instruction_eas(block),
                    )
                    for serial in range(int(live_mba.qty))
                    for block in (live_mba.get_mblock(serial),)
                    if block is not None
                ),
            )
            rejections.append(("live_range_owner", source_write_ea, target_ea))
            continue
        represented = source_matches[0]
        represented_eas = _live_block_instruction_eas(represented)
        represented_entry_ea = select_unique_block_native_ea(
            int(represented.start),
            represented_eas,
        )
        if (
            represented_entry_ea is None
            or int(represented_entry_ea) not in live_native_eas
            or source_instruction_ea not in represented_eas
        ):
            rejections.append(("live_terminal_anchor", source_write_ea, target_ea))
            continue
        candidates.append(
            (
                source_write_ea,
                DetachedSnippetDirectBoundaryPort(
                    source_block_ea=source_block_ea,
                    source_instruction_ea=source_instruction_ea,
                    endpoint_block_ea=source_instruction_ea,
                    old_successor_eas=(old_successor_ea,),
                    target_ea=target_ea,
                    state_register=int(transfer.selector_state_var_reg),
                    state_constant=(int(transfer.selector_state_constant) & _MASK32),
                    source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
                    endpoint_owner=DetachedSnippetBoundaryPortOwner.LIVE,
                    target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                    delivery_mode="redirect_edge",
                    resolver_kind=transfer.resolver_kind,
                    old_successor_owners=(DetachedSnippetBoundaryPortOwner.LIVE,),
                ),
            )
        )
    if rejections:
        logger.info(
            "PREOPT live residual-route boundary candidates: routers=%s "
            "accepted=%s rejected=%s",
            [hex(ea) for ea in sorted(dispatcher_router_eas)],
            [
                (
                    hex(proof_write_ea),
                    hex(int(port.source_block_ea)),
                    hex(int(port.source_instruction_ea)),
                    hex(int(port.target_ea)),
                )
                for proof_write_ea, port in candidates
            ],
            [
                (reason, hex(source_write_ea), hex(target_ea))
                for reason, source_write_ea, target_ea in rejections
            ],
        )
    latest_by_terminal: dict[
        tuple[int, int],
        tuple[int, set[DetachedSnippetDirectBoundaryPort]],
    ] = {}
    for proof_write_ea, port in candidates:
        terminal_key = (
            int(port.source_instruction_ea),
            int(port.old_successor_eas[0]),
        )
        previous = latest_by_terminal.get(terminal_key)
        if previous is None or proof_write_ea > previous[0]:
            latest_by_terminal[terminal_key] = (proof_write_ea, {port})
        elif proof_write_ea == previous[0]:
            previous[1].add(port)
    if any(len(ports) != 1 for _write_ea, ports in latest_by_terminal.values()):
        return None
    selected_candidates = tuple(
        next(iter(ports)) for _write_ea, ports in latest_by_terminal.values()
    )
    by_source: dict[tuple[int, int], set[DetachedSnippetDirectBoundaryPort]] = {}
    for port in selected_candidates:
        by_source.setdefault(
            (int(port.source_block_ea), int(port.source_instruction_ea)),
            set(),
        ).add(port)
    if any(len(ports) != 1 for ports in by_source.values()):
        return None
    return tuple(
        sorted(
            (next(iter(ports)) for ports in by_source.values()),
            key=lambda port: (
                int(port.source_instruction_ea),
                int(port.target_ea),
            ),
        )
    )


def _compose_preopt_stack_carrier_router_ports(
    transfers: tuple[MaterializedIndirectTransfer, ...],
    conditional_ports: tuple[DetachedSnippetConditionalBoundaryPort, ...],
    *,
    imported_entry_eas: frozenset[int],
    live_native_eas: frozenset[int],
    native_cfg: NativeCfg | None,
    consumer_load_eas_by_displacement: Mapping[int, Sequence[int]],
    native_stack_frame_offsets_by_ea: Mapping[int, tuple[int, ...]] | None = None,
) -> tuple[DetachedSnippetConditionalBoundaryPort, ...]:
    """Retain nested prologue predicates selected through stack routers.

    A static state choice can route to a handler that merely loads another
    prologue-selected state from a stack cell and re-enters the dispatcher.
    The resolver already proves both facts before import: which predicate
    filled the cell and which imported native block consumes it.  Connect the
    outer arm to that exact live predicate instead of the synthetic router.

    The result is a small resolver-proven decision tree made from the existing
    binary conditional-port contract.  Missing or ambiguous choices, consumer
    ownership, predicate ports, or cycles preserve the original ports.
    """
    if native_cfg is None or not conditional_ports:
        return conditional_ports

    choices_by_displacement: dict[int, list[MaterializedIndirectTransfer]] = {}
    for transfer in transfers:
        if (
            transfer.resolver_kind != "static_stack_carried_state_choice"
            or transfer.state_carrier_stack_displacement is None
            or transfer.predicate_true_state is None
            or transfer.predicate_false_state is None
            or transfer.true_target_ea is None
            or transfer.false_target_ea is None
        ):
            continue
        displacement = int(transfer.state_carrier_stack_displacement) & _MASK32
        choices_by_displacement.setdefault(displacement, []).append(transfer)

    unique_choice_by_displacement = {
        displacement: choices[0]
        for displacement, choices in choices_by_displacement.items()
        if len(choices) == 1
    }

    def port_matches_choice(
        port: DetachedSnippetConditionalBoundaryPort,
        choice: MaterializedIndirectTransfer,
    ) -> bool:
        assert choice.predicate_true_state is not None
        assert choice.predicate_false_state is not None
        assert choice.true_target_ea is not None
        assert choice.false_target_ea is not None
        return (
            int(port.predicate_ea) == int(choice.source_jmp_ea)
            and port.source_owner is DetachedSnippetBoundaryPortOwner.LIVE
            and port.taken_state is not None
            and port.fallthrough_state is not None
            and {
                int(port.taken_state) & _MASK32,
                int(port.fallthrough_state) & _MASK32,
            }
            == {
                int(choice.predicate_true_state) & _MASK32,
                int(choice.predicate_false_state) & _MASK32,
            }
            and {
                int(port.taken_target_ea),
                int(port.fallthrough_target_ea),
            }
            == {
                int(choice.true_target_ea),
                int(choice.false_target_ea),
            }
        )

    def imported_owner_entry(ea: int) -> int | None:
        matches = {
            int(entry_ea)
            for entry_ea in imported_entry_eas
            for block in (native_cfg.blocks_by_ea.get(int(entry_ea)),)
            if block is not None and int(block.start_ea) <= int(ea) < int(block.end_ea)
        }
        if not matches and int(ea) in imported_entry_eas:
            matches.add(int(ea))
        return next(iter(matches)) if len(matches) == 1 else None

    displacements_by_consumer_entry: dict[int, set[int]] = {}
    for displacement, load_eas in consumer_load_eas_by_displacement.items():
        for load_ea in load_eas:
            owner_entry = imported_owner_entry(int(load_ea))
            if owner_entry is not None:
                displacements_by_consumer_entry.setdefault(owner_entry, set()).add(
                    int(displacement) & _MASK32
                )

    def target_owner(target_ea: int) -> DetachedSnippetBoundaryPortOwner | None:
        if int(target_ea) in imported_entry_eas:
            return DetachedSnippetBoundaryPortOwner.IMPORTED
        if int(target_ea) in live_native_eas:
            return DetachedSnippetBoundaryPortOwner.LIVE
        return None

    def is_expansion_source(
        port: DetachedSnippetConditionalBoundaryPort,
    ) -> bool:
        """Expand native predicates, never a previously relocated choice."""
        return port.logical_source_anchor_ea is None or int(
            port.logical_source_anchor_ea
        ) == int(port.predicate_ea)

    expansion_sources = tuple(
        port for port in conditional_ports if is_expansion_source(port)
    )

    referenced_displacements = {
        displacement
        for port in expansion_sources
        for target_ea, target_owner in (
            (port.taken_target_ea, port.taken_target_owner),
            (port.fallthrough_target_ea, port.fallthrough_target_owner),
        )
        if target_owner is DetachedSnippetBoundaryPortOwner.IMPORTED
        for consumer_entry in (imported_owner_entry(int(target_ea)),)
        if consumer_entry is not None
        for displacement in displacements_by_consumer_entry.get(consumer_entry, set())
    }
    frame_offsets = (
        {}
        if native_stack_frame_offsets_by_ea is None
        else native_stack_frame_offsets_by_ea
    )
    generated_nested_ports: list[DetachedSnippetConditionalBoundaryPort] = []
    nested_port_by_displacement: dict[int, DetachedSnippetConditionalBoundaryPort] = {}
    for displacement, choice in unique_choice_by_displacement.items():
        matches = tuple(
            port for port in conditional_ports if port_matches_choice(port, choice)
        )
        if len(matches) == 1 and int(matches[0].predicate_ea) in live_native_eas:
            nested_port_by_displacement[displacement] = matches[0]
            continue
        if displacement not in referenced_displacements or matches:
            continue
        assert choice.state_carrier_store_ea is not None
        store_offsets = frame_offsets.get(int(choice.state_carrier_store_ea), ())
        load_eas = tuple(
            dict.fromkeys(
                int(load_ea)
                for load_ea in consumer_load_eas_by_displacement.get(displacement, ())
                if imported_owner_entry(int(load_ea)) is not None
            )
        )
        true_owner = target_owner(int(choice.true_target_ea))
        false_owner = target_owner(int(choice.false_target_ea))
        if (
            len(store_offsets) != 1
            or len(load_eas) != 1
            or choice.selector_state_var_reg is None
            or choice.predicate_size is None
            or int(choice.predicate_size) <= 0
            or true_owner is None
            or false_owner is None
        ):
            continue
        generated = DetachedSnippetConditionalBoundaryPort(
            source_block_ea=int(choice.source_block_ea),
            predicate_ea=int(choice.source_jmp_ea),
            old_taken_target_ea=None,
            old_fallthrough_target_ea=None,
            taken_target_ea=int(choice.true_target_ea),
            fallthrough_target_ea=int(choice.false_target_ea),
            state_register=int(choice.selector_state_var_reg),
            taken_state=int(choice.predicate_true_state) & _MASK32,
            fallthrough_state=int(choice.predicate_false_state) & _MASK32,
            source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            taken_target_owner=true_owner,
            fallthrough_target_owner=false_owner,
            resolver_kind=("resolver_proven_static_stack_carried_router_choice"),
            logical_source_anchor_ea=load_eas[0],
            logical_source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
            predicate_ida_stkoff=int(store_offsets[0]),
            predicate_stack_value=(int(choice.predicate_true_state) & _MASK32),
            predicate_size=int(choice.predicate_size),
            condition_code=choice.condition_code,
            predicate_register=choice.predicate_register,
            predicate_constant=choice.predicate_compare_constant,
            predicate_true_is_taken=True,
            logical_source_replaces_dispatcher_envelope=True,
        )
        generated_nested_ports.append(generated)
        nested_port_by_displacement[displacement] = generated

    dependencies: dict[int, set[int]] = {}
    rewrites: dict[
        int,
        tuple[
            int | None,
            DetachedSnippetConditionalBoundaryPort | None,
            int | None,
            DetachedSnippetConditionalBoundaryPort | None,
        ],
    ] = {}
    for port in conditional_ports:
        arm_rows: list[
            tuple[int | None, DetachedSnippetConditionalBoundaryPort | None]
        ] = []
        for target_ea, target_owner in (
            (port.taken_target_ea, port.taken_target_owner),
            (port.fallthrough_target_ea, port.fallthrough_target_owner),
        ):
            nested_port = None
            displacement = None
            if (
                is_expansion_source(port)
                and target_owner is DetachedSnippetBoundaryPortOwner.IMPORTED
            ):
                consumer_entry = imported_owner_entry(int(target_ea))
                candidates = (
                    set()
                    if consumer_entry is None
                    else displacements_by_consumer_entry.get(consumer_entry, set())
                )
                if len(candidates) == 1:
                    displacement = next(iter(candidates))
                    candidate_port = nested_port_by_displacement.get(displacement)
                    if candidate_port is not None and int(
                        candidate_port.predicate_ea
                    ) != int(port.predicate_ea):
                        nested_port = candidate_port
                        dependencies.setdefault(int(port.predicate_ea), set()).add(
                            int(candidate_port.predicate_ea)
                        )
            arm_rows.append((displacement, nested_port))
        rewrites[int(port.predicate_ea)] = (
            arm_rows[0][0],
            arm_rows[0][1],
            arm_rows[1][0],
            arm_rows[1][1],
        )

    visiting: set[int] = set()
    visited: set[int] = set()

    def has_cycle(predicate_ea: int) -> bool:
        if predicate_ea in visiting:
            return True
        if predicate_ea in visited:
            return False
        visiting.add(predicate_ea)
        cyclic = any(
            has_cycle(successor) for successor in dependencies.get(predicate_ea, set())
        )
        visiting.remove(predicate_ea)
        visited.add(predicate_ea)
        return cyclic

    if any(has_cycle(predicate_ea) for predicate_ea in dependencies):
        logger.info("PREOPT stack-carrier router expansion abstained: cycle")
        return conditional_ports

    result: list[DetachedSnippetConditionalBoundaryPort] = []
    expanded_rows: list[tuple[str, str, str]] = []
    for port in conditional_ports:
        (
            _taken_displacement,
            taken_nested,
            _fallthrough_displacement,
            fallthrough_nested,
        ) = rewrites[int(port.predicate_ea)]
        rewritten = replace(
            port,
            taken_target_ea=(
                int(port.taken_target_ea)
                if taken_nested is None
                else int(taken_nested.predicate_ea)
            ),
            taken_target_owner=(
                port.taken_target_owner
                if taken_nested is None
                else DetachedSnippetBoundaryPortOwner.LIVE
            ),
            taken_target_is_boundary_source=taken_nested is not None,
            fallthrough_target_ea=(
                int(port.fallthrough_target_ea)
                if fallthrough_nested is None
                else int(fallthrough_nested.predicate_ea)
            ),
            fallthrough_target_owner=(
                port.fallthrough_target_owner
                if fallthrough_nested is None
                else DetachedSnippetBoundaryPortOwner.LIVE
            ),
            fallthrough_target_is_boundary_source=(fallthrough_nested is not None),
        )
        result.append(rewritten)
        if taken_nested is not None:
            expanded_rows.append(
                (
                    f"0x{int(port.predicate_ea):X}",
                    "taken",
                    f"0x{int(taken_nested.predicate_ea):X}",
                )
            )
        if fallthrough_nested is not None:
            expanded_rows.append(
                (
                    f"0x{int(port.predicate_ea):X}",
                    "fallthrough",
                    f"0x{int(fallthrough_nested.predicate_ea):X}",
                )
            )
    result.extend(generated_nested_ports)
    if expanded_rows:
        logger.info("PREOPT stack-carrier router expansion: rows=%s", expanded_rows)
    return tuple(result)


def _compose_preopt_stack_carried_entry_choice_ports(
    transfers: tuple[MaterializedIndirectTransfer, ...],
    direct_ports: tuple[DetachedSnippetDirectBoundaryPort, ...],
    *,
    live_native_eas: frozenset[int],
    imported_entry_eas: frozenset[int],
    native_cfg: NativeCfg | None,
    consumer_load_eas_by_displacement: Mapping[int, Sequence[int]],
    native_stack_frame_offsets_by_ea: Mapping[int, tuple[int, ...]],
    existing_conditional_ports: tuple[DetachedSnippetConditionalBoundaryPort, ...] = (),
) -> tuple[
    tuple[DetachedSnippetDirectBoundaryPort, ...],
    tuple[DetachedSnippetConditionalBoundaryPort, ...],
]:
    """Replace one proven bootstrap route with its carried two-state choice.

    The original compare/CMOV may be far earlier than the live edge into a
    detached bootstrap handler.  The static resolver already proves that the
    CMOV stores exactly one of two dispatcher states in one native stack cell
    and independently maps both states to handlers.  Retain the original
    predicate EA as proof provenance, but name the later direct-port terminal
    as the logical control-transfer anchor.  Reconstructing the stack-cell
    condition there preserves every intervening prologue side effect before
    branching to the two handlers.

    Every identity is native-EA based.  Missing or ambiguous stores, consumers,
    entry routes, offsets, or target owners leave the original direct port
    untouched.
    """
    if native_cfg is None:
        return direct_ports, ()

    choices_by_displacement: dict[int, list[MaterializedIndirectTransfer]] = {}
    for transfer in transfers:
        if (
            transfer.resolver_kind != "static_stack_carried_state_choice"
            or transfer.state_carrier_store_ea is None
            or transfer.state_carrier_stack_displacement is None
            or transfer.predicate_true_state is None
            or transfer.predicate_false_state is None
            or transfer.true_target_ea is None
            or transfer.false_target_ea is None
            or transfer.selector_state_var_reg is None
            or transfer.predicate_size is None
            or int(transfer.predicate_size) <= 0
        ):
            continue
        displacement = int(transfer.state_carrier_stack_displacement) & _MASK32
        choices_by_displacement.setdefault(displacement, []).append(transfer)

    def target_owner(target_ea: int) -> DetachedSnippetBoundaryPortOwner | None:
        if int(target_ea) in imported_entry_eas:
            return DetachedSnippetBoundaryPortOwner.IMPORTED
        if int(target_ea) in live_native_eas:
            return DetachedSnippetBoundaryPortOwner.LIVE
        return None

    candidate_rows: dict[
        DetachedSnippetDirectBoundaryPort,
        set[DetachedSnippetConditionalBoundaryPort],
    ] = {}
    for displacement, choices in sorted(choices_by_displacement.items()):
        if len(choices) != 1:
            continue
        (choice,) = choices
        choice_states = {
            int(choice.predicate_true_state) & _MASK32,
            int(choice.predicate_false_state) & _MASK32,
        }
        choice_targets = {
            int(choice.true_target_ea),
            int(choice.false_target_ea),
        }
        if any(
            int(port.predicate_ea) == int(choice.source_jmp_ea)
            and port.taken_state is not None
            and port.fallthrough_state is not None
            and {
                int(port.taken_state) & _MASK32,
                int(port.fallthrough_state) & _MASK32,
            }
            == choice_states
            and (
                {
                    int(port.taken_target_ea),
                    int(port.fallthrough_target_ea),
                }
                == choice_targets
                or port.taken_target_is_boundary_source
                or port.fallthrough_target_is_boundary_source
            )
            for port in existing_conditional_ports
        ):
            # The live prologue predicate is already the complete two-arm
            # boundary. Do not rediscover a synthetic boundary from its later
            # stack consumer.
            continue
        consumer_entries: set[int] = set()
        consumer_ambiguous = False
        for load_ea in consumer_load_eas_by_displacement.get(displacement, ()):
            owners = {
                int(entry_ea)
                for entry_ea in imported_entry_eas
                for block in (native_cfg.blocks_by_ea.get(int(entry_ea)),)
                if block is not None
                and int(block.start_ea) <= int(load_ea) < int(block.end_ea)
            }
            if len(owners) != 1:
                consumer_ambiguous = True
                break
            consumer_entries.update(owners)
        if consumer_ambiguous or len(consumer_entries) != 1:
            continue
        (consumer_entry_ea,) = consumer_entries
        matching_direct_ports = tuple(
            port
            for port in direct_ports
            if port.source_owner is DetachedSnippetBoundaryPortOwner.LIVE
            and port.endpoint_owner is DetachedSnippetBoundaryPortOwner.LIVE
            and port.target_owner is DetachedSnippetBoundaryPortOwner.IMPORTED
            and port.delivery_mode == "redirect_edge"
            and int(port.target_ea) == consumer_entry_ea
        )
        if len(matching_direct_ports) != 1:
            continue
        (direct_port,) = matching_direct_ports
        predicate_blocks = tuple(
            block
            for block in native_cfg.blocks_by_ea.values()
            if int(block.start_ea) <= int(choice.source_jmp_ea) < int(block.end_ea)
        )
        if len(predicate_blocks) != 1:
            continue
        predicate_source_ea = int(predicate_blocks[0].start_ea)
        assert choice.state_carrier_store_ea is not None
        store_offsets = native_stack_frame_offsets_by_ea.get(
            int(choice.state_carrier_store_ea),
            (),
        )
        if len(store_offsets) != 1:
            continue
        assert choice.predicate_true_state is not None
        assert choice.predicate_false_state is not None
        assert choice.true_target_ea is not None
        assert choice.false_target_ea is not None
        true_state = int(choice.predicate_true_state) & _MASK32
        false_state = int(choice.predicate_false_state) & _MASK32
        true_target_ea = int(choice.true_target_ea)
        false_target_ea = int(choice.false_target_ea)
        true_owner = target_owner(true_target_ea)
        false_owner = target_owner(false_target_ea)
        if (
            true_state == false_state
            or true_target_ea == false_target_ea
            or true_owner is None
            or false_owner is None
            or DetachedSnippetBoundaryPortOwner.IMPORTED
            not in {true_owner, false_owner}
        ):
            continue
        candidate_rows.setdefault(direct_port, set()).add(
            DetachedSnippetConditionalBoundaryPort(
                source_block_ea=predicate_source_ea,
                predicate_ea=int(choice.source_jmp_ea),
                old_taken_target_ea=None,
                old_fallthrough_target_ea=None,
                taken_target_ea=true_target_ea,
                fallthrough_target_ea=false_target_ea,
                state_register=int(choice.selector_state_var_reg),
                taken_state=true_state,
                fallthrough_state=false_state,
                source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
                taken_target_owner=true_owner,
                fallthrough_target_owner=false_owner,
                resolver_kind=("resolver_proven_static_stack_carried_entry_choice"),
                logical_source_anchor_ea=int(direct_port.source_instruction_ea),
                predicate_ida_stkoff=int(store_offsets[0]),
                predicate_stack_value=true_state,
                predicate_size=int(choice.predicate_size),
                condition_code=choice.condition_code,
                predicate_register=choice.predicate_register,
                predicate_constant=choice.predicate_compare_constant,
                predicate_true_is_taken=True,
            )
        )

    selected = {
        direct_port: next(iter(ports))
        for direct_port, ports in candidate_rows.items()
        if len(ports) == 1
    }
    if selected:
        logger.info(
            "PREOPT stack-carried entry choices: rows=%s",
            [
                (
                    f"0x{int(direct_port.source_block_ea):X}",
                    f"0x{int(direct_port.source_instruction_ea):X}",
                    f"0x{int(direct_port.target_ea):X}",
                    f"0x{int(port.predicate_ea):X}",
                    f"0x{int(port.taken_state):X}",
                    f"0x{int(port.taken_target_ea):X}",
                    f"0x{int(port.fallthrough_state):X}",
                    f"0x{int(port.fallthrough_target_ea):X}",
                )
                for direct_port, port in sorted(
                    selected.items(),
                    key=lambda row: int(row[0].source_instruction_ea),
                )
            ],
        )
    return (
        tuple(port for port in direct_ports if port not in selected),
        tuple(
            port
            for _direct, port in sorted(
                selected.items(),
                key=lambda row: int(row[0].source_instruction_ea),
            )
        ),
    )


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
        maturity_local_shape = {
            "predicate_size": None,
            "condition_code": None,
            "predicate_register": None,
            "predicate_constant": None,
            "predicate_true_is_taken": None,
        }
        return replace(baseline, **maturity_local_shape) == replace(
            refreshed,
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
                    "PREOPT union refresh conditional conflict: "
                    "previous=%r current=%r",
                    baseline,
                    port,
                )
        raise


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
    prepatch_source = state.portable_evidence.prepatch_preopt_union_source
    if prepatch_source is not None and not isinstance(
        prepatch_source, _PrepatchPreoptUnionSource
    ):
        return _preopt_union_abstention(key, "invalid_prepatch_source")
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
                    "PREOPT union semantic-closure abstentions: " "func=0x%X rows=%s",
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
    effective_closure = closure
    boundary_ports = _preopt_union_boundary_ports(
        effective_closure,
        live_native_eas=live_native_eas,
        transfers=transfers,
        live_mba=live_mba,
        native_cfg=native_cfg,
        imported_seed_eas=tuple(int(ea) for ea in region.seed_eas),
        stack_carrier_consumer_load_eas_by_displacement=(
            _static_stack_carrier_consumer_load_eas(resolution)
        ),
        native_stack_frame_offsets_by_ea=dict(resolution.native_stack_frame_offsets),
    )
    if boundary_ports is None:
        return _preopt_union_abstention(key, "incomplete_boundary_topology")
    if refresh_existing and refresh_baseline_boundary_ports is not None:
        try:
            boundary_ports = _merge_preopt_union_boundary_ports(
                refresh_baseline_boundary_ports,
                boundary_ports,
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
    refreshed = prepare_preopt_union_closure(
        state,
        live_mba=mba,
        refresh_existing=True,
        refresh_baseline_boundary_ports=state.boundary_ports,
    )
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
    import ida_hexrays  # type: ignore[import-untyped]

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
    pending = state.pending_prepatch_materialization
    if isinstance(pending, ComputedGotoResolution):
        source_captured = _capture_prepatch_preopt_union_source(
            state,
            pending,
            _static_prepatch_union_source_transfers(pending),
        )
        materialized = materialize_computed_gotos(pending, state=state)
        if materialized <= 0:
            logger.info(
                "computed-goto staged delivery abstained: func=0x%X "
                "source_captured=%s",
                key,
                source_captured,
            )
            return 0
        state.pending_prepatch_materialization = None
        logger.info(
            "computed-goto staged delivery materialized: func=0x%X "
            "sites=%d source_captured=%s",
            key,
            materialized,
            source_captured,
        )

        if live_mba is not None:
            try:
                union_preparation = prepare_preopt_union_closure(
                    state,
                    live_mba=live_mba,
                )
            except Exception:
                logger.warning(
                    "PREOPT union preparation from prepatch live MBA failed "
                    "open: func=0x%X",
                    key,
                    exc_info=True,
                )
            else:
                if union_preparation.prepared and union_preparation.published:
                    return 1

        staged_cfunc = None
        for attempt in range(2):
            ida_hexrays.clear_cached_cfuncs()
            staged_cfunc = ida_hexrays.decompile(key)
            if staged_cfunc is not None:
                break
            logger.info(
                "computed-goto staged live decompile retry: func=0x%X " "attempt=%d",
                key,
                attempt + 1,
            )
        if staged_cfunc is not None:
            union_preparation = prepare_preopt_union_closure(
                state,
                live_mba=staged_cfunc.mba,
            )
            if union_preparation.prepared and union_preparation.published:
                return 1
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


def _entry_bridge_ready(
    *,
    entry_bridge_materialized: bool,
    state_route_rounds: int,
) -> bool:
    """Require one route-materialization round before bridging the prologue."""
    return not entry_bridge_materialized and int(state_route_rounds) > 0


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
                    else "write" if access_type == int(ida_idp.WRITE_ACCESS) else None
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
    detached_call_spd_by_ea = (
        {} if capture_active else dict(detached_preopt_call_stack_points(key))
    )
    for live_ea, native_ea in sorted(native_ea_by_live_ea.items()):
        try:
            native_spd = int(ida_frame.get_spd(function, int(native_ea)))
            route_call_delta = detached_call_spd_by_ea.get(int(native_ea))
            # Captured push depth is relative to the detached route entry;
            # hxe_stkpnts consumes absolute function-frame coordinates.
            spd = (
                native_spd
                if route_call_delta is None
                else native_spd + int(route_call_delta)
            )
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
    if not projected:
        return
    decision["stack_points_modified"] = len(projected)
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
                _merge_materialized_transfers(state, local_transfers)
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


def _on_preopt_bootstrap_route(
    *,
    function_ea: int,
    mba: object,
    decision: dict,
) -> None:
    """Rebind and route static bootstrap evidence through the live MBA gateway."""
    state = _resolver_state_from_decision(decision)
    if state is None:
        logger.debug(
            "PREOPT bootstrap abstain: func=0x%X reason=no_session_state",
            int(function_ea),
        )
        return
    if (
        state.snippet_capture_active
        or state.preopt_union_import_active
        or preopt_union_import_in_progress(mba)
        or int(getattr(mba, "entry_ea", int(function_ea)) or int(function_ea))
        != int(function_ea)
    ):
        return
    if (
        not state.native_preanalysis.needs_preopt_binding()
        and not state.native_preanalysis.needs_bootstrap_route_binding()
    ):
        logger.debug(
            "PREOPT bootstrap abstain: func=0x%X reason=no_pending_binding "
            "evidence_generation=%d bound_generation=%s routes=%d",
            int(function_ea),
            int(state.evidence_generation),
            state.native_preanalysis.bound_preopt_generation,
            len(state.native_preanalysis.bootstrap_routes),
        )
        return
    index = state.identity_index
    gateway = decision.get("mutation_gateway")
    if index is None or gateway is None:
        logger.debug(
            "PREOPT bootstrap abstain: func=0x%X reason=missing_live_port "
            "index=%s gateway=%s routes=%d",
            int(function_ea),
            index is not None,
            gateway is not None,
            len(state.native_preanalysis.bootstrap_routes),
        )
        return

    import ida_hexrays  # type: ignore[import-untyped]

    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier
    from d810.ir.block_identity import (
        NativeEaInterval,
        RebindStatus,
        StableBlockIdentity,
    )

    redirect_routes = []
    terminal_routes = []
    already_routed = []
    bootstrap_bindings = {}

    details = decision.get("details")
    preparation = get_prepared_preopt_union_closure(state)
    union_prepared = bool(
        preparation is not None
        and preparation.prepared
        and preparation.published
        and int(preparation.function_ea) == int(function_ea)
        and preparation.primary_seed_ea is not None
    )
    union_imported = bool(
        isinstance(details, dict)
        and union_prepared
        and int(details.get("preopt_union_root_ea", -1))
        == int(preparation.primary_seed_ea)
    )

    def live_range_identity(block, anchor_ea: int):
        start_ea = int(getattr(block, "start", 0) or 0)
        end_ea = int(getattr(block, "end", 0) or 0)
        anchor = int(anchor_ea)
        if start_ea <= 0 or end_ea <= start_ea or not start_ea <= anchor < end_ea:
            return None
        return StableBlockIdentity.from_intervals(
            (NativeEaInterval(start_ea, end_ea),),
            native_key=state.native_key,
        )

    for evidence in sorted(
        state.native_preanalysis.bootstrap_routes.values(),
        key=lambda route: (
            int(route.source_anchor_ea),
            int(route.state),
            int(route.handler_anchor_ea),
        ),
    ):
        rebound = state.rebind_bootstrap_route(
            source_identity=evidence.source_identity,
            state=int(evidence.state),
            prefer_imported_handler=union_imported,
        )
        if rebound is None:
            source_result = index.rebind_identity(evidence.source_identity)
            handler_result = index.rebind_imported_identity(evidence.handler_identity)
            if not union_imported or handler_result.status is RebindStatus.MISSING:
                handler_result = index.rebind_identity(evidence.handler_identity)
            logger.debug(
                "PREOPT bootstrap rebind abstain: func=0x%X source=0x%X "
                "state=0x%X handler=0x%X source_status=%s handler_status=%s "
                "mba_entry=0x%X blocks=%d identities=%d snippet_capture=%s",
                int(function_ea),
                int(evidence.source_anchor_ea),
                int(evidence.state),
                int(evidence.handler_anchor_ea),
                source_result.status.value,
                handler_result.status.value,
                int(getattr(mba, "entry_ea", 0) or 0),
                int(getattr(mba, "qty", 0) or 0),
                len(index.serials_by_identity),
                bool(state.snippet_capture_active),
            )
            continue
        source = mba.get_mblock(int(rebound.source.serial))
        handler = mba.get_mblock(int(rebound.handler.serial))
        if source is None or handler is None:
            logger.debug(
                "PREOPT bootstrap live-block abstain: func=0x%X source=0x%X "
                "handler=0x%X source_serial=%d handler_serial=%d "
                "source_present=%s handler_present=%s",
                int(function_ea),
                int(evidence.source_anchor_ea),
                int(evidence.handler_anchor_ea),
                int(rebound.source.serial),
                int(rebound.handler.serial),
                source is not None,
                handler is not None,
            )
            continue
        tail = source.tail
        source_nsucc = int(source.nsucc())
        if (
            tail is None
            or int(tail.ea) != int(evidence.source_anchor_ea)
            or int(tail.opcode) != int(ida_hexrays.m_goto)
            or source_nsucc not in (0, 1)
        ):
            logger.debug(
                "PREOPT bootstrap source-shape abstain: func=0x%X "
                "source=0x%X source_serial=%d block_start=0x%X tail_ea=%s "
                "tail_opcode=%s nsucc=%d succs=%s",
                int(function_ea),
                int(evidence.source_anchor_ea),
                int(source.serial),
                int(getattr(source, "start", 0) or 0),
                None if tail is None else f"0x{int(tail.ea):X}",
                None if tail is None else int(tail.opcode),
                source_nsucc,
                tuple(int(source.succ(i)) for i in range(source_nsucc)),
            )
            continue
        source_binding_identity = live_range_identity(
            source,
            int(evidence.source_anchor_ea),
        )
        handler_binding_identity = live_range_identity(
            handler,
            int(evidence.handler_anchor_ea),
        )
        if source_binding_identity is None or handler_binding_identity is None:
            logger.debug(
                "PREOPT bootstrap binding abstain: func=0x%X source=0x%X "
                "handler=0x%X source_range=[0x%X,0x%X) "
                "handler_range=[0x%X,0x%X)",
                int(function_ea),
                int(evidence.source_anchor_ea),
                int(evidence.handler_anchor_ea),
                int(getattr(source, "start", 0) or 0),
                int(getattr(source, "end", 0) or 0),
                int(getattr(handler, "start", 0) or 0),
                int(getattr(handler, "end", 0) or 0),
            )
        else:
            bootstrap_bindings[evidence.key] = BootstrapRouteBindingEvidence(
                route=evidence,
                source_identity=source_binding_identity,
                handler_identity=handler_binding_identity,
                evidence_generation=int(state.evidence_generation),
            )
        if source_nsucc == 0:
            terminal_routes.append(rebound)
        elif int(source.succ(0)) == int(rebound.handler.serial):
            already_routed.append(rebound)
        else:
            redirect_routes.append(rebound)

    # The union importer owns its internal conditional boundary ports, but it
    # cannot own a bootstrap edge whose source remains in the caller's live
    # MBA.  Continue rebinding bootstrap routes through the session gateway;
    # only suppress the conditional work that the importer already applied.
    conditional_candidates: dict[int, set[tuple[int, int, bool]]] = {}
    for transfer in () if union_prepared else state.materialized_transfers:
        if (
            transfer.resolver_kind != "static_conditional_state_choice_bridge"
            or not transfer.predicate_preserve_live
            or transfer.predicate_true_is_taken is None
            or transfer.true_target_ea is None
            or transfer.false_target_ea is None
        ):
            continue
        true_is_taken = bool(transfer.predicate_true_is_taken)
        taken_target_ea = int(
            transfer.true_target_ea if true_is_taken else transfer.false_target_ea
        )
        fallthrough_target_ea = int(
            transfer.false_target_ea if true_is_taken else transfer.true_target_ea
        )
        conditional_candidates.setdefault(
            int(transfer.source_jmp_ea),
            set(),
        ).add((taken_target_ea, fallthrough_target_ea, true_is_taken))

    conditional_pending = []
    conditional_already = []
    conditional_materialize = []
    for source_ea, proofs in sorted(conditional_candidates.items()):
        if len(proofs) != 1:
            continue
        taken_target_ea, fallthrough_target_ea, true_is_taken = next(iter(proofs))
        source_identity = StableBlockIdentity.from_intervals(
            (NativeEaInterval(int(source_ea), int(source_ea) + 1),),
            native_key=index.native_key,
        )
        taken_identity = StableBlockIdentity.from_intervals(
            (NativeEaInterval(int(taken_target_ea), int(taken_target_ea) + 1),),
            native_key=index.native_key,
        )
        fallthrough_identity = StableBlockIdentity.from_intervals(
            (
                NativeEaInterval(
                    int(fallthrough_target_ea),
                    int(fallthrough_target_ea) + 1,
                ),
            ),
            native_key=index.native_key,
        )
        source_result = index.rebind_identity(source_identity)
        taken_result = index.rebind_identity(taken_identity)
        fallthrough_result = index.rebind_identity(fallthrough_identity)
        if (
            source_result.block is None
            or taken_result.block is None
            or fallthrough_result.block is None
        ):
            logger.debug(
                "PREOPT static conditional rebind abstain: func=0x%X "
                "predicate=0x%X taken=0x%X fallthrough=0x%X "
                "source_status=%s taken_status=%s fallthrough_status=%s",
                int(function_ea),
                int(source_ea),
                int(taken_target_ea),
                int(fallthrough_target_ea),
                source_result.status.value,
                taken_result.status.value,
                fallthrough_result.status.value,
            )
            continue
        source = mba.get_mblock(int(source_result.block.serial))
        taken_target = mba.get_mblock(int(taken_result.block.serial))
        fallthrough_target = mba.get_mblock(int(fallthrough_result.block.serial))
        if source is None or taken_target is None or fallthrough_target is None:
            continue
        tail = source.tail
        successors = tuple(
            int(source.succ(index)) for index in range(int(source.nsucc()))
        )
        has_block_target = bool(
            tail is not None
            and getattr(tail, "d", None) is not None
            and int(tail.d.t) == int(ida_hexrays.mop_b)
            and tail.d.b is not None
        )
        taken = int(tail.d.b) if has_block_target else None
        source_matches_predicate = tail is not None and bool(
            int(tail.ea) == int(source_ea)
            and ida_hexrays.is_mcode_jcond(int(tail.opcode))
        )
        generated_zero_way = bool(
            source_matches_predicate
            and len(successors) == 0
            and getattr(tail, "d", None) is not None
            and int(tail.d.t) == int(ida_hexrays.mop_v)
        )
        live_two_way = bool(
            source_matches_predicate
            and len(successors) == 2
            and taken is not None
            and int(taken) in successors
        )
        if generated_zero_way:
            conditional_materialize.append(
                (
                    int(source_ea),
                    int(taken_target_ea),
                    int(fallthrough_target_ea),
                    source_result.block,
                    taken_result.block,
                    fallthrough_result.block,
                )
            )
            continue
        if not live_two_way:
            logger.debug(
                "PREOPT static conditional source-shape abstain: func=0x%X "
                "predicate=0x%X source_serial=%d taken_target=0x%X "
                "fallthrough_target=0x%X tail_ea=%s "
                "opcode=%s taken=%s successors=%s true_is_taken=%s "
                "maturity=%s ltype=%s rtype=%s dtype=%s text=%s",
                int(function_ea),
                int(source_ea),
                int(source_result.block.serial),
                int(taken_target_ea),
                int(fallthrough_target_ea),
                None if tail is None else f"0x{int(tail.ea):X}",
                None if tail is None else int(tail.opcode),
                taken,
                successors,
                bool(true_is_taken),
                int(getattr(mba, "maturity", -1)),
                None if tail is None else int(tail.l.t),
                None if tail is None else int(tail.r.t),
                None if tail is None else int(tail.d.t),
                None if tail is None else str(tail),
            )
            continue
        rebound = (
            int(source_ea),
            int(taken_target_ea),
            source_result.block,
            taken_result.block,
            int(taken),
        )
        if int(taken) == int(taken_result.block.serial):
            conditional_already.append(rebound)
        else:
            conditional_pending.append(rebound)

    pending_routes = (*terminal_routes, *redirect_routes)
    if (
        not pending_routes
        and not already_routed
        and not conditional_pending
        and not conditional_already
        and not conditional_materialize
    ):
        if union_imported and not state.native_preanalysis.bootstrap_routes:
            state.native_preanalysis.mark_preopt_bound()
        return
    pending_source_serials = [
        *(int(route.source.serial) for route in pending_routes),
        *(int(route[2].serial) for route in conditional_pending),
        *(int(route[3].serial) for route in conditional_materialize),
    ]
    if len(set(pending_source_serials)) != len(pending_source_serials):
        return

    applied = 0
    if pending_routes or conditional_pending or conditional_materialize:
        modifier = DeferredGraphModifier(mba, mutation_gateway=gateway)
        for route in terminal_routes:
            source = mba.get_mblock(int(route.source.serial))
            handler = mba.get_mblock(int(route.handler.serial))
            if (
                source is None
                or handler is None
                or not modifier.restore_pruned_direct_now(source, handler)
            ):
                return
            applied += 1
        for route in redirect_routes:
            modifier.queue_goto_change(
                block_serial=int(route.source.serial),
                new_target=int(route.handler.serial),
                description=(
                    "rebound static bootstrap route "
                    f"source@0x{route.evidence.source_anchor_ea:X} "
                    f"state=0x{route.evidence.state:X} "
                    f"handler@0x{route.evidence.handler_anchor_ea:X}"
                ),
                rule_priority=100,
            )
        for (
            source_ea,
            target_ea,
            source_bound,
            target_bound,
            old_taken,
        ) in conditional_pending:
            modifier.queue_conditional_target_change(
                block_serial=int(source_bound.serial),
                new_target=int(target_bound.serial),
                old_target=int(old_taken),
                description=(
                    "rebound static conditional taken route "
                    f"predicate@0x{source_ea:X} target@0x{target_ea:X}"
                ),
            )
        for (
            source_ea,
            taken_target_ea,
            fallthrough_target_ea,
            source_bound,
            taken_bound,
            fallthrough_bound,
        ) in conditional_materialize:
            modifier.queue_materialize_zero_way_conditional(
                source_serial=int(source_bound.serial),
                predicate_ea=int(source_ea),
                taken_target_serial=int(taken_bound.serial),
                fallthrough_target_serial=int(fallthrough_bound.serial),
                description=(
                    "materialize rebound generated conditional "
                    f"predicate@0x{source_ea:X} "
                    f"taken@0x{taken_target_ea:X} "
                    f"fallthrough@0x{fallthrough_target_ea:X}"
                ),
                rule_priority=100,
            )
        deferred_applied = (
            modifier.apply(transactional=True, staged_atomic=True)
            if (redirect_routes or conditional_pending or conditional_materialize)
            else 0
        )
        expected_applied = (
            len(redirect_routes)
            + len(conditional_pending)
            + len(conditional_materialize)
        )
        if deferred_applied != expected_applied:
            return
        applied += deferred_applied
        decision["microcode_modified"] = True

    rebound_all = (*already_routed, *pending_routes)
    for route in rebound_all:
        newly_rebound = state.native_preanalysis.mark_bootstrap_route_rebound(
            route.evidence
        )
        binding = bootstrap_bindings.get(route.evidence.key)
        if binding is not None:
            state.native_preanalysis.record_bootstrap_route_binding(
                state.native_key,
                binding,
            )
        if not newly_rebound:
            continue
        logger.info(
            "PREOPT_BOOTSTRAP_ROUTE func=0x%X source=0x%X state=0x%X "
            "handler=0x%X evidence_generation=%d applied=%s",
            int(function_ea),
            int(route.evidence.source_anchor_ea),
            int(route.evidence.state),
            int(route.evidence.handler_anchor_ea),
            int(state.evidence_generation),
            bool(route in pending_routes),
        )
    for (
        source_ea,
        target_ea,
        source_bound,
        target_bound,
        _old_taken,
    ) in (*conditional_already, *conditional_pending):
        logger.info(
            "PREOPT_STATIC_CONDITIONAL_ROUTE func=0x%X predicate=0x%X "
            "source_serial=%d handler=0x%X handler_serial=%d "
            "evidence_generation=%d applied=%s",
            int(function_ea),
            int(source_ea),
            int(source_bound.serial),
            int(target_ea),
            int(target_bound.serial),
            int(state.evidence_generation),
            bool(
                any(
                    int(pending[0]) == int(source_ea) for pending in conditional_pending
                )
            ),
        )
    for (
        source_ea,
        taken_target_ea,
        fallthrough_target_ea,
        source_bound,
        taken_bound,
        fallthrough_bound,
    ) in conditional_materialize:
        logger.info(
            "PREOPT_STATIC_CONDITIONAL_ROUTE func=0x%X predicate=0x%X "
            "source_serial=%d taken_handler=0x%X taken_serial=%d "
            "fallthrough_handler=0x%X fallthrough_serial=%d "
            "evidence_generation=%d applied=True",
            int(function_ea),
            int(source_ea),
            int(source_bound.serial),
            int(taken_target_ea),
            int(taken_bound.serial),
            int(fallthrough_target_ea),
            int(fallthrough_bound.serial),
            int(state.evidence_generation),
        )
    if (
        rebound_all
        or conditional_already
        or conditional_pending
        or conditional_materialize
    ):
        state.native_preanalysis.mark_preopt_bound()


def _on_flowchart_preanalysis(*, function_ea: int, mba: object, decision: dict) -> None:
    """Flowchart-preanalysis seam handler.

    Runs BEFORE Hex-Rays builds ``qflow_chart``: resolve the computed gotos,
    materialise the handler edges, and request a Hex-Rays rebuild so the new
    crefs are picked up. Fail-open: a failure here must never gate the decompile.
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
            if state.pending_prepatch_materialization is not None:
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
        state.begin_materialization(resolution)
        if resolution.arch == "x86" and resolution.patch_plans:
            state.pending_prepatch_materialization = resolution
            logger.info(
                "computed-goto static delivery staged: func=0x%X "
                "sites=%d targets=%d reason=prepatch_preopt_capture",
                key,
                resolution.site_count,
                resolution.target_count,
            )
            return
        materialised = materialize_computed_gotos(resolution, state=state)
        logger.info(
            "computed-goto: func=0x%x sites=%d targets=%d materialised=%d "
            "reachable=%d arch=%s",
            key,
            resolution.site_count,
            resolution.target_count,
            materialised,
            len(resolution.reachable_eas),
            resolution.arch,
        )
        discover_static_native_bootstrap_routes(key, state)
        if not state.native_preanalysis.request_controlled_redo():
            return
        request_hexrays_redo(
            decision,
            "computed_goto_materialized",
            function_ea=key,
            site_count=resolution.site_count,
            target_count=resolution.target_count,
            round=0,
        )
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
            if not state.native_preanalysis.request_generated_restart():
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
            if _refresh_preopt_union_from_calls_evidence(
                state,
                mba,
            ) and request_generated_restart(
                "computed_goto_preopt_template_refreshed",
                evidence_generation=state.evidence_generation,
            ):
                return
            if state.native_preanalysis.request_controlled_redo():
                request_hexrays_redo(
                    decision,
                    "computed_goto_calls_evidence",
                    function_ea=key,
                    evidence_generation=state.evidence_generation,
                )
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

        if _entry_bridge_ready(
            entry_bridge_materialized=materialization.entry_bridge_materialized,
            state_route_rounds=materialization.state_route_rounds,
        ):
            bridge_count, bridge_transfers = _materialize_residual_entry_bridge(
                materialization.resolution,
                transfers,
                mba,
            )
            if bridge_count:
                materialization.entry_bridge_materialized = True
                _merge_materialized_transfers(state, bridge_transfers)
                materialization.rounds += 1
                request_hexrays_redo(
                    decision,
                    "computed_goto_residual_entry_bridge",
                    function_ea=key,
                    materialized_count=int(bridge_count),
                    round=int(materialization.rounds),
                )
                return

        route_count, route_transfers = _materialize_residual_state_routes_from_mba(
            materialization.resolution,
            transfers,
            mba,
        )
        if route_count:
            _merge_materialized_transfers(state, route_transfers)
            route_evidence = state.materialized_transfers
            try:
                conditional_bridges = (
                    recover_conditional_handler_bridge_transfers_from_mba(
                        route_evidence,
                        mba,
                        imported_predicate_eas=imported_predicate_eas,
                        imported_instruction_origins=imported_origins,
                    )
                )
            except Exception:
                logger.info(
                    "conditional bridge enrichment failed after route commit: "
                    "func=0x%X routes=%d",
                    key,
                    len(route_transfers),
                    exc_info=True,
                )
                conditional_bridges = ()
            if conditional_bridges:
                _merge_materialized_transfers(state, conditional_bridges)
            materialization.state_route_rounds += 1
            materialization.rounds += 1
            if _refresh_preopt_union_from_calls_evidence(state, mba):
                request_generated_restart(
                    "computed_goto_preopt_template_refreshed",
                    materialized_count=int(route_count),
                    round=int(materialization.rounds),
                )
                return
            request_hexrays_redo(
                decision,
                "computed_goto_residual_state_route",
                function_ea=key,
                materialized_count=int(route_count),
                round=int(materialization.rounds),
            )
            return

        if calls_evidence_changed and _refresh_preopt_union_from_calls_evidence(
            state, mba
        ):
            materialization.rounds += 1
            request_generated_restart(
                "computed_goto_preopt_template_refreshed",
                materialized_count=len(imported_conditional_bridges),
                round=int(materialization.rounds),
            )
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
    register_preopt_preanalysis_handler(
        _PREOPT_HANDLER_NAME,
        _on_preopt_bootstrap_route,
    )
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
    unregister_preopt_preanalysis_handler(_PREOPT_HANDLER_NAME)
    unregister_calls_done_preanalysis_handler(_CALLS_HANDLER_NAME)
    unregister_callinfo_preanalysis_handler(_CALLINFO_HANDLER_NAME)
    unregister_stkpnts_preanalysis_handler(_STKPNTS_HANDLER_NAME)


__all__ = [
    "ComputedGotoResolution",
    "PreoptUnionPreparationResult",
    "is_computed_goto_materialized",
    "resolve_computed_gotos",
    "resolve_computed_gotos_static",
    "materialize_computed_gotos",
    "resolve_and_materialize",
    "stage_computed_goto_preanalysis",
    "prepare_detached_handler_snippets",
    "prepare_preopt_union_closure",
    "get_prepared_preopt_union_closure",
    "prepare_terminal_return_carrier_templates",
    "capture_detached_route_callinfo_templates",
    "recover_conditional_handler_bridge_transfers_from_mba",
    "install",
    "uninstall",
]

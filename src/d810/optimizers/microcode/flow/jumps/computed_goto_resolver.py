"""Resolve register-computed goto dispatchers that IDA's switch recogniser cannot
crack, by EXECUTING them with d810's concolic engine and materialising the
discovered handler targets on the flowchart-preanalysis seam so Hex-Rays forms
the real CFG.

Motivating shape (Rhadamanthys loader ``sub_40A560``): a control-flow-flattened
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
the real Rhadamanthys loader's setcc+shl+indexed-table+KEY binary-search shape).
A from-entry corridor trace **faults at instruction 0** on the real loader (the
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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from d810.core.typing import NamedTuple

from d810.backends.emulation.common import CorridorEventKind
from d810.backends.emulation.oracle import EmulationOracle
from d810.core.logging import getLogger
from d810.hexrays.preanalysis.flowchart_preanalysis import (
    register_flowchart_preanalysis_handler,
    request_hexrays_redo,
    unregister_flowchart_preanalysis_handler,
)
from d810.hexrays.preanalysis.indirect_jump_labels import (
    create_dispatcher_target_instructions,
    mark_indirect_dispatcher,
)

logger = getLogger("D810.hexrays.preanalysis.computed_goto")

_HANDLER_NAME = "computed_goto_resolver"
#: Cap on emulated instructions for one corridor trace (a flattened state machine
#: with N states * M handler instructions; generous headroom, fail-open on hit).
_DEFAULT_MAX_INSTRUCTIONS = 20000
#: Scratch stack window mapped for the corridor emulation (well away from image).
_STACK_BASE = 0x00F00000
_STACK_SIZE = 0x00040000
_STACK_TOP = _STACK_BASE + _STACK_SIZE // 2


@dataclass(frozen=True)
class ComputedGotoResolution:
    """Targets discovered for a function's register-computed ``jmp reg`` sites."""

    function_ea: int
    jmp_targets: Mapping[int, tuple[int, ...]]
    reachable_eas: tuple[int, ...]
    arch: str
    executed_insns: int
    seeds_run: int
    stop_reasons: tuple[str, ...] = field(default_factory=tuple)
    #: Pre-baked byte patches (static x86 fixpoint path only; empty for concolic).
    patch_plans: tuple["_PatchPlan", ...] = field(default_factory=tuple)
    #: Every block leader discovered by the static fixpoint (orphan-absorb set).
    block_entries: tuple[int, ...] = field(default_factory=tuple)

    @property
    def site_count(self) -> int:
        return len(self.jmp_targets)

    @property
    def target_count(self) -> int:
        return sum(len(v) for v in self.jmp_targets.values())


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
# The concolic corridor trace faults at instruction 0 on the real             #
# Rhadamanthys loader ``sub_40A560``: the prologue writes an unmapped stack    #
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
_SV_REG_NAMES = {0: "eax", 1: "ecx", 2: "edx", 3: "ebx", 4: "esp", 5: "ebp", 6: "esi", 7: "edi"}
_SV_CALLER_CLOBBERED = ("eax", "ecx", "edx")
_SV_SHIFT_MNEMS = {"shl", "sal", "shr"}
_SV_CMOV_MNEMS = {
    "cmovz", "cmovnz", "cmove", "cmovne", "cmovl", "cmovle", "cmovg", "cmovge",
    "cmova", "cmovae", "cmovb", "cmovbe", "cmovs", "cmovns", "cmovo", "cmovno",
    "cmovp", "cmovnp", "cmovpe", "cmovpo",
}
_SV_JCC_MNEMS = {
    "jz", "jnz", "je", "jne", "jl", "jle", "jg", "jge", "ja", "jae", "jb",
    "jbe", "js", "jns", "jo", "jno", "jp", "jnp", "jcxz", "jecxz",
}
#: instructions whose bytes are safe to overwrite when redirecting a jmp reg
#: (the address-computation chain + the setcc/shift/select that feed it).
_SV_CHAIN_MNEMS = {"mov", "lea", "add", "sub", "xor", "and", "or", "shl", "sal", "shr"}
#: instructions safe to RELOCATE verbatim (position-independent, flag-neutral).
_SV_FLAG_SAFE_RELOC = {"mov", "lea", "push", "pop", "nop", "movzx", "movsx"}


class _PatchPlan(NamedTuple):
    """A pre-baked condition-preserving byte-patch for one computed-goto site."""

    jmp_ea: int
    block_entry: int
    patch_start: int
    patch_bytes: bytes  # E9 / 0F8x rewrite, NOP-padded to region_end
    region_end: int
    insn_heads: tuple[int, ...]  # create_insn heads after del_items
    new_block_eas: tuple[int, ...]  # newly-created jcc/jmp leaders to absorb


def _sv_reg_name(op) -> str | None:
    return _SV_REG_NAMES.get(op.reg)


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
    if op0.type != idaapi.o_reg:
        return
    dst = _sv_reg_name(op0)
    if dst is None:
        return
    if mnem == "mov":
        state[dst] = _sv_resolve_source(insn.ops[1], state, is_lea=False)
    elif mnem == "lea":
        state[dst] = _sv_resolve_source(insn.ops[1], state, is_lea=True)
    elif mnem == "add":
        state[dst] = _sv_combine(state.get(dst), _sv_resolve_source(insn.ops[1], state, is_lea=False), lambda a, b: a + b)
    elif mnem == "sub":
        state[dst] = _sv_combine(state.get(dst), _sv_resolve_source(insn.ops[1], state, is_lea=False), lambda a, b: a - b)
    elif mnem == "xor":
        op1 = insn.ops[1]
        if op1.type == idaapi.o_reg and op1.reg == op0.reg:
            state[dst] = _sv_singleton(0)
        else:
            state[dst] = _sv_combine(state.get(dst), _sv_resolve_source(op1, state, is_lea=False), lambda a, b: a ^ b)
    elif mnem == "and":
        state[dst] = _sv_combine(state.get(dst), _sv_resolve_source(insn.ops[1], state, is_lea=False), lambda a, b: a & b)
    elif mnem == "or":
        state[dst] = _sv_combine(state.get(dst), _sv_resolve_source(insn.ops[1], state, is_lea=False), lambda a, b: a | b)
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
                    out.add((v << s) & _MASK32 if mnem in ("shl", "sal") else (v >> s) & _MASK32)
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


def _static_resolver_fixpoint(function_ea: int) -> tuple[dict, dict, dict, dict, int]:
    """Monotone forward-dataflow fixpoint from *function_ea* that JOINs register
    value-sets at merges. Returns
    ``(entry_state, resolved_sites, unresolved_sites, block_entry_of, steps)``
    where ``resolved_sites`` maps each ``jmp reg`` EA to its sorted target list."""
    import ida_ua  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]

    entry_state: dict[int, dict] = {int(function_ea): {}}
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
    insn = ida_ua.insn_t()
    ea = int(block_entry)
    while ea <= int(jmp_ea):
        length = ida_ua.decode_insn(insn, ea)
        if length <= 0:
            return None
        mnem = idaapi.print_insn_mnem(ea)
        if ea == int(jmp_ea):
            break
        if mnem == "call":
            for c in _SV_CALLER_CLOBBERED:
                state_f[c] = None
                state_t[c] = None
        elif mnem in _SV_CMOV_MNEMS and insn.ops[0].type == idaapi.o_reg:
            dst = _sv_reg_name(insn.ops[0])
            state_t[dst] = _sv_resolve_source(insn.ops[1], state_t, is_lea=False)  # taken: dst=src
            # not-taken: dst unchanged
            info = {"ea": ea, "cc": _select_cc_nibble(ea, length)}
        elif mnem.startswith("set") and len(mnem) > 3 and insn.ops[0].type == idaapi.o_reg:
            dst = _sv_reg_name(insn.ops[0])
            old_t = state_t.get(dst)
            old_f = state_f.get(dst)
            base_t = (next(iter(old_t)) & 0xFFFFFF00) if old_t and len(old_t) == 1 else 0
            base_f = (next(iter(old_f)) & 0xFFFFFF00) if old_f and len(old_f) == 1 else 0
            state_t[dst] = _sv_singleton(base_t | 1)  # taken: al = 1
            state_f[dst] = _sv_singleton(base_f | 0)  # not-taken: al = 0
            info = {"ea": ea, "cc": _select_cc_nibble(ea, length)}
        else:
            _sv_process_writer(mnem, insn, state_f)
            _sv_process_writer(mnem, insn, state_t)
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


def _extend_for_padding(region_end: int, needed_extra: int, forbidden_starts: set[int]) -> int:
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
                    region_len += _extend_for_padding(region_end, 5 - region_len, forbidden_starts)
                if region_len < 5:
                    skipped.append((jmp_ea, 1, "no room (uncond)"))
                    continue
                rel = targets[0] - (patch_start + 5)
                body = b"\xE9" + struct.pack("<i", rel)
                body += b"\x90" * (region_len - len(body))
                plans.append(_PatchPlan(
                    jmp_ea=jmp_ea, block_entry=block_entry, patch_start=patch_start,
                    patch_bytes=body, region_end=patch_start + region_len,
                    insn_heads=(patch_start,), new_block_eas=(patch_start,),
                ))
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
                    split = max(_last_reg_writer_end(block_entry, jmp_ea, jmp_reg), patch_start)
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
                        + bytes([0x0F, 0x80 + (info["cc"] & 0xF)]) + struct.pack("<i", info["true"] - jcc_end)
                        + b"\xE9" + struct.pack("<i", info["false"] - jmp_end)
                    )
                    region_len = region_end - patch_start
                    if region_len < len(body):
                        region_len += _extend_for_padding(region_end, len(body) - region_len, forbidden_starts)
                    if region_len < len(body):
                        fail_reason = f"no room (need {len(body)} have {region_end - patch_start})"
                        continue
                    body += b"\x90" * (region_len - len(body))
                    plans.append(_PatchPlan(
                        jmp_ea=jmp_ea, block_entry=block_entry, patch_start=patch_start,
                        patch_bytes=body, region_end=patch_start + region_len,
                        insn_heads=(patch_start, jcc_start, jcc_end),
                        # the E9 at jcc_end is a NEW instruction (not in any trace);
                        # both jcc and its E9 fall-through must be pulled into the func.
                        new_block_eas=(jcc_start, jcc_end),
                    ))
                    done = True
                    break
                if not done:
                    skipped.append((jmp_ea, 2, fail_reason))
            else:
                skipped.append((jmp_ea, len(targets), f"{len(targets)}-way (needs N-way delivery)"))
        except Exception as exc:  # noqa: BLE001
            skipped.append((jmp_ea, len(targets), f"exception: {exc!r}"))
    return plans, skipped


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

    entry_state, resolved_sites, unresolved_sites, block_entry_of, steps = _static_resolver_fixpoint(function_ea)
    if not resolved_sites:
        return None

    all_targets: set[int] = set()
    for tgts in resolved_sites.values():
        all_targets.update(tgts)
    forbidden = all_targets | set(entry_state)
    plans, skipped = _bake_patch_plans(resolved_sites, block_entry_of, entry_state, forbidden)
    if skipped:
        logger.info(
            "computed-goto(static): %d/%d sites patched; %d skipped: %s",
            len(plans), len(resolved_sites), len(skipped),
            ", ".join(f"0x{ea:x}:{n}way:{r}" for ea, n, r in skipped[:12]),
        )
    if not plans:
        return None

    reachable = tuple(sorted(set(entry_state) | all_targets))
    return ComputedGotoResolution(
        function_ea=int(function_ea),
        jmp_targets={int(k): tuple(int(t) for t in v) for k, v in resolved_sites.items()},
        reachable_eas=reachable,
        arch=arch,
        executed_insns=steps,
        seeds_run=0,
        stop_reasons=("static_fixpoint", f"unresolved={len(unresolved_sites)}"),
        patch_plans=tuple(plans),
        block_entries=tuple(sorted(set(entry_state))),
    )


def _materialize_static(resolution: ComputedGotoResolution) -> int:
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

    # 1) apply every byte patch, then re-decode each rewritten region in place.
    new_block_eas: list[int] = []
    for plan in resolution.patch_plans:
        ida_bytes.patch_bytes(plan.patch_start, plan.patch_bytes)
        new_block_eas.extend(plan.new_block_eas)
    for plan in resolution.patch_plans:
        ida_bytes.del_items(plan.block_entry, ida_bytes.DELIT_EXPAND, plan.region_end - plan.block_entry)
    for plan in resolution.patch_plans:
        for head in plan.insn_heads:
            idaapi.create_insn(int(head))

    seg = ida_segment.getseg(int(resolution.function_ea))
    if seg is not None:
        ida_auto.plan_and_wait(seg.start_ea, seg.end_ea)

    # 2) mark BEFORE reanalyze so the CFF unflattener routes recovery to MMAT_CALLS.
    mark_indirect_dispatcher(int(resolution.function_ea))

    func = ida_funcs.get_func(int(resolution.function_ea))
    if func is not None:
        ida_funcs.reanalyze_function(func)
    if seg is not None:
        ida_auto.plan_and_wait(seg.start_ea, seg.end_ea)

    # 3) absorb every discovered block (and each new jcc/jmp leader) that IDA did
    #    not fold into the function on its own.
    func = ida_funcs.get_func(int(resolution.function_ea))
    absorb = sorted(set(resolution.block_entries) | set(new_block_eas) | set(resolution.reachable_eas))
    for ea in absorb:
        if func is not None and ida_funcs.get_func(int(ea)) is None:
            ida_funcs.append_func_tail(func, int(ea), _block_end(int(ea)))

    func = ida_funcs.get_func(int(resolution.function_ea))
    if func is not None:
        ida_funcs.reanalyze_function(func)
    if seg is not None:
        ida_auto.plan_and_wait(seg.start_ea, seg.end_ea)
    return len(resolution.patch_plans)


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
        if mnem == "lea" and insn.ops[0].type == idaapi.o_reg and insn.ops[1].type in (idaapi.o_mem, idaapi.o_displ):
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
        "target_false": (getptr(cell_false) + key) & mask,  # cc false → dst keeps its lea
        "target_true": (getptr(cell_true) + key) & mask,    # cc true  → dst = src
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

    def _apply(patch_start: int, region_end: int, body: bytes, insn_heads: tuple[int, ...]) -> None:
        ida_bytes.patch_bytes(patch_start, body + b"\x90" * (region_end - patch_start - len(body)))
        # re-decode the rewritten region so IDA sees the new jcc/jmp instructions
        ida_bytes.del_items(patch_start, ida_bytes.DELIT_EXPAND, region_end - patch_start)
        for head in insn_heads:
            idaapi.create_insn(int(head))

    for jmp_ea, targets in resolution.jmp_targets.items():
        jlen = ida_ua.decode_insn(insn, int(jmp_ea))
        if jlen <= 0:
            continue
        region_end = int(jmp_ea) + jlen
        if len(targets) == 1:
            body = b"\xE9" + _pack_i32(int(targets[0]) - (int(jmp_ea) + 5))
            if region_end - int(jmp_ea) >= len(body):
                _apply(int(jmp_ea), region_end, body, (int(jmp_ea),))
                new_jmp_eas.append(int(jmp_ea))
            continue
        if len(targets) != 2:
            continue
        info = _analyze_select_block(int(jmp_ea), _block_start_of(int(jmp_ea), text_start), resolution.arch)
        if info is None:
            continue
        cmp_end = info["cmp_end"]
        jcc_end = cmp_end + 6
        jmp_end = jcc_end + 5
        body = (bytes([0x0F, 0x80 + (info["cc"] & 0x0F)]) + _pack_i32(info["target_true"] - jcc_end)
                + b"\xE9" + _pack_i32(info["target_false"] - jmp_end))
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


def materialize_computed_gotos(resolution: ComputedGotoResolution) -> int:
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
    import ida_bytes  # type: ignore[import-untyped]
    import ida_funcs  # type: ignore[import-untyped]
    import ida_segment  # type: ignore[import-untyped]

    # Static x86 fixpoint path carries pre-baked patch plans + the full block set.
    if resolution.patch_plans:
        return _materialize_static(resolution)

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
    mark_indirect_dispatcher(int(resolution.function_ea))

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


def resolve_and_materialize(function_ea: int, **kwargs: object) -> ComputedGotoResolution | None:
    """Full pipeline for one function: resolve then materialise. Concolic
    execution is tried first (the fixture's cmov-pointer-select shape); when it
    finds nothing -- e.g. an x86 loader whose prologue the from-entry trace
    cannot execute -- the static const-prop fixpoint is the fallback. Returns the
    resolution (or None if nothing to do)."""
    resolution = resolve_computed_gotos(int(function_ea), **kwargs)  # type: ignore[arg-type]
    if resolution is None or not resolution.jmp_targets:
        static = resolve_computed_gotos_static(int(function_ea))
        if static is not None:
            resolution = static
    if resolution is None:
        return None
    materialised = materialize_computed_gotos(resolution)
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


#: EAs already materialised in this registration (materialise once per function).
_MATERIALIZED_EAS: set[int] = set()


def _on_flowchart_preanalysis(*, function_ea: int, mba: object, decision: dict) -> None:
    """Flowchart-preanalysis seam handler.

    Runs BEFORE Hex-Rays builds ``qflow_chart``: resolve the computed gotos,
    materialise the handler edges, and request a Hex-Rays rebuild so the new
    crefs are picked up. Fail-open: a failure here must never gate the decompile.
    """
    key = int(function_ea)
    if key in _MATERIALIZED_EAS:
        return
    try:
        if not _has_unresolved_computed_goto(key):
            return
        _MATERIALIZED_EAS.add(key)
        resolution = resolve_and_materialize(key)
        if resolution is None or not resolution.jmp_targets:
            return
        request_hexrays_redo(
            decision,
            "computed_goto_materialized",
            function_ea=key,
            site_count=resolution.site_count,
            target_count=resolution.target_count,
        )
    except Exception:
        logger.debug("computed-goto handler failed for 0x%X", key, exc_info=True)


def install() -> None:
    """Register the computed-goto resolver on the flowchart preanalysis seam."""
    _MATERIALIZED_EAS.clear()
    register_flowchart_preanalysis_handler(_HANDLER_NAME, _on_flowchart_preanalysis)


def uninstall() -> None:
    _MATERIALIZED_EAS.clear()
    unregister_flowchart_preanalysis_handler(_HANDLER_NAME)


__all__ = [
    "ComputedGotoResolution",
    "resolve_computed_gotos",
    "resolve_computed_gotos_static",
    "materialize_computed_gotos",
    "resolve_and_materialize",
    "install",
    "uninstall",
]

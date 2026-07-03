"""Single-trip loop-peel: IDA-facing fact extraction (Hex-Rays microcode).

The RECOGNIZER.  For each natural-loop back-edge it enumerates -- by EXACT
def-use / loop-membership / dominance analysis, never a heuristic -- the facts
the proven gate needs, then delegates the decision to
``single_trip_loop.prove_single_trip``.

Lives in ``d810.evaluator.hexrays_microcode`` (the IDA-coupled layer, next to
``chains.py``): it needs live microcode + DU chains, so it cannot sit in the
portable ``d810.analyses`` layer.  The pure proof gate + fact model DO live in
``d810.analyses.control_flow.single_trip_loop`` (IDA-free, unit-tested).

Every precondition is a count, a dominance check, or a discharged proof:

* guard = the header exit-test operand (register or stack var);
* CONTINUE predicate = the header comparison, oriented by which successor lies
  inside the natural loop;
* **P1** (sole in-loop constant recurrence): the guard has exactly ONE reaching
  def inside the loop and it assigns a constant; the entry value is a single
  constant too;
* **P2** (unconditional recurrence): that in-loop def *dominates the latch*, so
  every back-edge traversal writes it before the header re-test.

If any precondition fails, the recognizer ABSTAINS -- it never peels on suspicion.
"""
from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.analyses.control_flow.dominator import DominatorTree, compute_dom_tree
from d810.analyses.control_flow.single_trip_loop import (
    CmpKind,
    LoopFacts,
    PeelVerdict,
    prove_single_trip,
)
from d810.core.logging import getLogger
from d810.evaluator.hexrays_microcode.chains import (
    find_reaching_defs_for_reg,
    find_reaching_defs_for_stkvar,
)

logger = getLogger(__name__)

# Conditional-jump opcode -> CONTINUE comparison assuming the JUMP-TAKEN edge
# (succset[1]) is the one that stays in the loop.  Orientation is corrected in
# ``extract_single_trip_facts`` when the fall-through edge is the loop edge.
_JCC_CMP = {
    ida_hexrays.m_jz: CmpKind.EQ,
    ida_hexrays.m_jnz: CmpKind.NE,
    ida_hexrays.m_jae: CmpKind.UGE,
    ida_hexrays.m_jb: CmpKind.ULT,
    ida_hexrays.m_ja: CmpKind.UGT,
    ida_hexrays.m_jbe: CmpKind.ULE,
    ida_hexrays.m_jg: CmpKind.SGT,
    ida_hexrays.m_jge: CmpKind.SGE,
    ida_hexrays.m_jl: CmpKind.SLT,
    ida_hexrays.m_jle: CmpKind.SLE,
}

_NEGATE = {
    CmpKind.EQ: CmpKind.NE,
    CmpKind.NE: CmpKind.EQ,
    CmpKind.ULT: CmpKind.UGE,
    CmpKind.UGE: CmpKind.ULT,
    CmpKind.UGT: CmpKind.ULE,
    CmpKind.ULE: CmpKind.UGT,
    CmpKind.SLT: CmpKind.SGE,
    CmpKind.SGE: CmpKind.SLT,
    CmpKind.SGT: CmpKind.SLE,
    CmpKind.SLE: CmpKind.SGT,
}


@dataclass(frozen=True)
class PeelCandidate:
    """A recognized loop and the gate's verdict on peeling it."""

    header: int
    latch: int
    verdict: PeelVerdict


def _successors_map(mba) -> dict[int, list[int]]:
    return {
        i: list(mba.get_mblock(i).succset)
        for i in range(mba.qty)
        if mba.get_mblock(i) is not None
    }


def _back_edges(mba, dom: DominatorTree) -> list[tuple[int, int]]:
    """Retreating edges ``(u, v)`` where ``v`` dominates ``u`` (natural-loop
    back-edges in a reducible CFG -- the same criterion the structurer uses)."""
    edges: list[tuple[int, int]] = []
    for u in range(mba.qty):
        blk = mba.get_mblock(u)
        if blk is None:
            continue
        for v in list(blk.succset):
            if dom.dominates(v, u):
                edges.append((u, v))
    return sorted(edges)


def _natural_loop_nodes(mba, latch: int, header: int) -> set[int]:
    """Nodes of the natural loop of back-edge ``latch -> header``:
    the header plus every node reaching the latch without crossing the header."""
    loop = {header, latch}
    stack = [latch]
    while stack:
        n = stack.pop()
        blk = mba.get_mblock(n)
        if blk is None:
            continue
        for p in list(blk.predset):
            if p not in loop:
                loop.add(p)
                stack.append(p)
    return loop


def _guard_locator(tail):
    """Return ``('reg', mreg, size) | ('stk', stkoff, size) | None`` for the
    header exit-test guard operand (``tail.l``)."""
    l = tail.l
    if l is None:
        return None
    if l.t == ida_hexrays.mop_r:
        return ("reg", l.r, l.size)
    if l.t == ida_hexrays.mop_S and l.s is not None:
        return ("stk", l.s.off, l.size)
    return None


def _const_assigned_by(mba, defsite) -> int | None:
    """The constant a DefSite's instruction assigns, or None if not a const def."""
    blk = mba.get_mblock(defsite.block_serial)
    if blk is None:
        return None
    ins = blk.head
    while ins is not None:
        if ins.ea == defsite.ins_ea and ins.opcode == defsite.ins_opcode:
            if ins.l is not None and ins.l.t == ida_hexrays.mop_n:
                return ins.l.nnn.value
            return None
        ins = ins.next
    return None


def extract_single_trip_facts(
    mba, latch: int, header: int, dom: DominatorTree | None = None
) -> LoopFacts | None:
    """Enumerate ``LoopFacts`` for the back-edge ``latch -> header``, or abstain.

    Abstains (``None``) unless the header is a keyable 2-way comparison guard and
    both preconditions P1 (sole in-loop constant recurrence + single constant
    entry) and P2 (in-loop def dominates the latch) hold.
    """
    hblk = mba.get_mblock(header)
    if hblk is None or hblk.type != ida_hexrays.BLT_2WAY:
        return None
    tail = hblk.tail
    if tail is None:
        return None
    base_cmp = _JCC_CMP.get(tail.opcode)
    if base_cmp is None:
        return None  # nested/opaque condition (e.g. m_jcnd) -> abstain
    imm = tail.r
    if imm is None or imm.t != ida_hexrays.mop_n:
        return None
    loc = _guard_locator(tail)
    if loc is None:
        return None
    kind, ident, size = loc

    succ = list(hblk.succset)
    if len(succ) != 2:
        return None
    fallthrough, taken = succ[0], succ[1]
    loop_nodes = _natural_loop_nodes(mba, latch, header)
    if taken in loop_nodes and fallthrough not in loop_nodes:
        continue_cmp = base_cmp
    elif fallthrough in loop_nodes and taken not in loop_nodes:
        continue_cmp = _NEGATE[base_cmp]
    else:
        return None  # not a clean single-exit loop guard -> abstain

    if kind == "reg":
        defs = find_reaching_defs_for_reg(mba, header, ident, size)
    else:
        defs = find_reaching_defs_for_stkvar(mba, header, ident, size)
    if not defs:
        return None

    # P1: exactly one in-loop def (a constant) + a single constant entry def.
    inloop_defs = [d for d in defs if d.block_serial in loop_nodes]
    entry_defs = [d for d in defs if d.block_serial not in loop_nodes]
    if len(inloop_defs) != 1 or not entry_defs:
        return None
    c1 = _const_assigned_by(mba, inloop_defs[0])
    if c1 is None:
        return None
    entry_consts = {_const_assigned_by(mba, d) for d in entry_defs}
    if None in entry_consts or len(entry_consts) != 1:
        return None
    c0 = next(iter(entry_consts))

    if dom is None:
        dom = compute_dom_tree(_successors_map(mba), 0)
    # Genuine natural-loop back-edge: the header must dominate the latch.  This
    # makes the recognizer safe to call on any (latch, target) pair -- it
    # abstains unless latch->header is a real loop back-edge.
    if not dom.dominates(header, latch):
        return None
    # P2: the in-loop def must DOMINATE the latch, so every back-edge traversal
    # writes c1 before re-testing the header (guard == c1 on the back-edge).
    if not dom.dominates(inloop_defs[0].block_serial, latch):
        return None

    return LoopFacts(
        guard_size=size,
        entry_const=c0,
        inloop_const=c1,
        continue_cmp=continue_cmp,
        continue_imm=imm.nnn.value,
    )


def recognize_single_trip(
    mba, latch: int, header: int, dom: DominatorTree | None = None
) -> PeelCandidate | None:
    """Extract facts for one back-edge and run the proven gate (or abstain)."""
    facts = extract_single_trip_facts(mba, latch, header, dom=dom)
    if facts is None:
        return None
    return PeelCandidate(header=header, latch=latch, verdict=prove_single_trip(facts))


def find_single_trip_peels(mba) -> list[PeelCandidate]:
    """All natural loops whose single-trip peel is PROVEN sound."""
    dom = compute_dom_tree(_successors_map(mba), 0)
    out: list[PeelCandidate] = []
    for latch, header in _back_edges(mba, dom):
        cand = recognize_single_trip(mba, latch, header, dom=dom)
        if cand is not None and cand.verdict.proved:
            out.append(cand)
    return out


__all__ = [
    "PeelCandidate",
    "extract_single_trip_facts",
    "recognize_single_trip",
    "find_single_trip_peels",
]

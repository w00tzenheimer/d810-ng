"""Live Hex-Rays adapter for the return-carrier corruption proof (llr-ytow).

Builds the three injected facts the backend-neutral proof core
(:mod:`d810.analyses.value_flow.return_carrier_corruption`) needs, from a live
``ida_hexrays.mba_t`` at ``MMAT_GLBOPT1``:

* **carrier blocks** -- blocks with a full-width ``rax`` definition whose value
  is directly derived from a stack slot / arg-derived value (``mop_S`` /
  ``mop_a``): the genuine return carriers (the counter ``*v17+1``,
  ``a5+0xD0``, ...).
* **DU-chain use count** of a candidate ``mov #imm, <rax>{n}`` -- counted as the
  number of *other* operands across the whole MBA whose value number equals the
  def's ``{n}`` (Pillar 1: zero == no computational use).
* **strict dominators** of each candidate's block (Pillar 2, via
  :func:`compute_dom_tree`).

This module is READ-ONLY: it returns the proven-droppable sites. The mutation
(NOP) is a thin wrapper applied by the GLBOPT hook once a site is proven, so
the fact-building can be validated independently of any MBA edit.

In IDA microcode ``al`` / ``ax`` / ``eax`` / ``rax`` share one micro-register
(``mr_rax``) and differ only by ``mop_t.size``; a write with ``size == 8`` is a
full overwrite, ``size < 8`` a partial (low-byte) write -- matching the proof
core's ``is_partial`` flag.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.control_flow.dominator import compute_dom_tree
from d810.analyses.value_flow.return_carrier_corruption import (
    CarrierCorruptionProof,
    KeepReason,
    ReturnRegDef,
    prove_return_const_droppable,
)
from d810.core.logging import getLogger

logger = getLogger("D810.return_carrier_corruption")

try:
    import ida_hexrays

    IDA_AVAILABLE = True
except ImportError:  # pragma: no cover - unit envs have no IDA
    IDA_AVAILABLE = False

__all__ = ["CandidateSite", "find_droppable_return_const_corruptions"]


@dataclass(frozen=True, slots=True)
class CandidateSite:
    """A proven-droppable return-register constant write."""

    block_serial: int
    insn_ea: int
    proof: CarrierCorruptionProof


def _rax_mreg() -> int | None:
    """Resolve the ``rax`` micro-register number, or ``None`` if unavailable."""
    # ``mr_first + reg`` numbering is arch-specific; reg2mreg maps the IDA
    # processor register to its mreg. R_ax (index 0 on x86/x64) -> rax mreg.
    try:
        return ida_hexrays.reg2mreg(0)  # R_ax
    except Exception:  # pragma: no cover - depends on live IDA
        mr_rax = getattr(ida_hexrays, "mr_rax", None)
        return int(mr_rax) if mr_rax is not None else None


def _iter_operands(insn):
    """Yield every leaf ``mop_t`` referenced by *insn*.

    The boolean marks only the instruction's top-level destination slot. Do
    not rely on ``mop is ins.d`` for this distinction: SWIG property access can
    hand back fresh proxy objects.
    """
    stack = [(insn.l, False), (insn.r, False), (insn.d, True)]
    while stack:
        mop, is_top_dest = stack.pop()
        if mop is None:
            continue
        yield mop, is_top_dest
        # descend into sub-instructions / operand pairs so register reads
        # nested inside expressions are counted as uses.
        sub = getattr(mop, "d", None)
        if mop.t == ida_hexrays.mop_d and sub is not None:
            stack.extend([(sub.l, False), (sub.r, False), (sub.d, False)])
        elif mop.t == ida_hexrays.mop_a and getattr(mop, "a", None) is not None:
            stack.append((mop.a, False))


def _count_valnum_uses(mba, rax_mreg: int, valnum: int, def_ea: int) -> int:
    """Count operands across the MBA that READ ``rax{valnum}`` (Pillar 1).

    Only register *reads* count: an operand is a use when it appears anywhere
    other than as the destination ``insn.d`` of the defining instruction.
    """
    uses = 0
    for bi in range(mba.qty):
        blk = mba.get_mblock(bi)
        ins = blk.head
        while ins is not None:
            for mop, is_top_dest in _iter_operands(ins):
                if (
                    mop.t == ida_hexrays.mop_r
                    and mop.r == rax_mreg
                    and getattr(mop, "valnum", -1) == valnum
                    and not (is_top_dest and ins.ea == def_ea)
                ):
                    uses += 1
            ins = ins.next
    return uses


def _is_literal_operand(mop) -> bool:
    return mop is not None and mop.t == ida_hexrays.mop_n


def _is_simple_stack_or_arg_source(mop) -> bool:
    """Return whether *mop* is a direct carrier source.

    Accept direct stack/arg operands and the GLBOPT shape for memory carriers:
    ``ldx ds, %slot`` wrapped as a ``mop_d`` source. Reject larger folded
    arithmetic trees that merely mention stack locals.
    """
    if mop is None:
        return False
    if mop.t in (ida_hexrays.mop_S, ida_hexrays.mop_a):
        return True
    sub = getattr(mop, "d", None)
    if (
        mop.t == ida_hexrays.mop_d
        and sub is not None
        and sub.opcode == getattr(ida_hexrays, "m_ldx", object())
    ):
        return _is_simple_stack_or_arg_source(sub.l) or _is_simple_stack_or_arg_source(
            sub.r
        )
    return False


def _is_carrier_source(insn) -> bool:
    """A full-rax def is a carrier when it directly computes a return value
    from stack/arg storage, not when it is a call/load or literal result."""
    if insn.opcode == ida_hexrays.m_mov:
        return _is_simple_stack_or_arg_source(insn.l)
    if insn.opcode == getattr(ida_hexrays, "m_add", object()):
        return (
            _is_simple_stack_or_arg_source(insn.l)
            and _is_literal_operand(insn.r)
        ) or (
            _is_literal_operand(insn.l)
            and _is_simple_stack_or_arg_source(insn.r)
        )
    return False


def find_droppable_return_const_corruptions(mba) -> list[CandidateSite]:
    """Return the proven-droppable ``mov #imm, <rax>`` corruptions in *mba*.

    Read-only. Applies the two-pillar proof to every literal write of the
    return register; returns only the sites where both pillars hold.
    """
    if not IDA_AVAILABLE or mba is None:
        return []
    rax = _rax_mreg()
    if rax is None:
        return []

    # --- carrier blocks: full-rax defs sourced from a stack/arg value ---
    carrier_blocks: set[int] = set()
    candidates: list[tuple[ReturnRegDef, int]] = []  # (def, insn_ea)
    reg_defs = 0
    const_reg_defs = 0
    seen_regs: set[int] = set()
    for bi in range(mba.qty):
        blk = mba.get_mblock(bi)
        ins = blk.head
        while ins is not None:
            d = ins.d
            if d is not None and d.t == ida_hexrays.mop_r:
                reg_defs += 1
                seen_regs.add(int(d.r))
                if (
                    ins.opcode == ida_hexrays.m_mov
                    and ins.l is not None
                    and ins.l.t == ida_hexrays.mop_n
                ):
                    const_reg_defs += 1
            if d is not None and d.t == ida_hexrays.mop_r and d.r == rax:
                full = d.size == 8
                if full and _is_carrier_source(ins):
                    carrier_blocks.add(bi)
                if (
                    ins.opcode == ida_hexrays.m_mov
                    and ins.l is not None
                    and ins.l.t == ida_hexrays.mop_n
                ):
                    candidates.append(
                        (
                            ReturnRegDef(
                                block=bi,
                                ea=ins.ea,
                                ssa=int(getattr(d, "valnum", 0)) or None,
                                is_const=True,
                                is_partial=(d.size != 8),
                                const_value=int(ins.l.nnn.value),
                            ),
                            ins.ea,
                        )
                    )
            ins = ins.next

    if logger.debug_on:
        logger.debug(
            "return-carrier corruption scan: maturity=%s rax_mreg=%s "
            "reg_defs=%d const_reg_defs=%d candidates=%d carriers=%s "
            "seen_regs=%s",
            getattr(mba, "maturity", None),
            rax,
            reg_defs,
            const_reg_defs,
            len(candidates),
            sorted(carrier_blocks),
            sorted(seen_regs),
        )

    if not candidates:
        return []

    # --- topology + dominators ---
    successors: dict[int, list[int]] = {}
    for bi in range(mba.qty):
        blk = mba.get_mblock(bi)
        succ = blk.succset
        successors[bi] = [int(s) for s in succ] if succ is not None else []
    dom = compute_dom_tree(successors, entry=0)

    # --- prove each candidate ---
    sites: list[CandidateSite] = []
    for target, insn_ea in candidates:
        if target.ssa is None:
            continue
        uses = _count_valnum_uses(mba, rax, target.ssa, insn_ea)
        strict = dom.dominators_of(target.block) - {target.block}
        result = prove_return_const_droppable(
            target,
            du_chain_uses=uses,
            carrier_blocks=carrier_blocks,
            strict_dominators=strict,
        )
        if isinstance(result, CarrierCorruptionProof):
            sites.append(CandidateSite(target.block, insn_ea, result))
            logger.info("return-carrier corruption proven droppable: %s", result.reason)
        elif logger.debug_on:
            _, reason = result  # type: ignore[misc]
            logger.debug(
                "keep %#x @blk%d: %s", target.const_value, target.block, reason.value
            )
    return sites

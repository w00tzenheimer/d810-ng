"""Sparse Conditional Constant Propagation (SCCP) -- Algorithm 3.

Gold-standard compiler constant propagation combining a constant lattice
with CFG reachability analysis.  Uses IDA's DU chains (``mba.get_du``)
for SSA-like use-def information.

**Status: DORMANT** -- not wired into the emulator or any pass.  Created
as a skeleton for future activation.

The lattice is: ``BOTTOM`` (unknown) < ``Const(v)`` < ``TOP`` (overdefined).
Two worklists drive the analysis:

* **CFG worklist** -- edges ``(from_blk, to_blk)`` that become executable.
* **SSA worklist** -- ``mop_key`` values whose lattice entry changed, so
  downstream uses must be re-evaluated.

References:
    Wegman & Zadeck, "Constant Propagation with Conditional Branches", 1991.
    docs/plans/2026-03-16-emulator-cross-block-resolution.md  (Algorithm 3)
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from enum import Enum, auto

from d810.core.logging import getLogger

logger = getLogger(__name__)

# ---------------------------------------------------------------------------
# Lattice
# ---------------------------------------------------------------------------

class _LatticeKind(Enum):
    BOTTOM = auto()   # Not yet known
    CONST = auto()    # Known constant
    TOP = auto()      # Overdefined (multiple distinct values)


@dataclass(frozen=True, slots=True)
class LatticeValue:
    kind: _LatticeKind
    value: int | None = None  # Only meaningful when kind == CONST


BOTTOM = LatticeValue(_LatticeKind.BOTTOM)
TOP = LatticeValue(_LatticeKind.TOP)


def _const(v: int) -> LatticeValue:
    return LatticeValue(_LatticeKind.CONST, v)


def _meet(a: LatticeValue, b: LatticeValue) -> LatticeValue:
    """Lattice meet: BOTTOM /\\ x = x, TOP /\\ x = TOP, Const(a) /\\ Const(b) = TOP if a!=b."""
    if a.kind is _LatticeKind.BOTTOM:
        return b
    if b.kind is _LatticeKind.BOTTOM:
        return a
    if a.kind is _LatticeKind.TOP or b.kind is _LatticeKind.TOP:
        return TOP
    # Both CONST
    if a.value == b.value:
        return a
    return TOP


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

_MAX_CFG_ITERATIONS = 2000
_MAX_SSA_ITERATIONS = 2000
_MAX_BLOCKS = 500


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_sccp(mba: object) -> dict[tuple, int | None]:
    """Run Sparse Conditional Constant Propagation on the MBA.

    Returns mapping from ``mop_key`` to constant value, or ``None`` for
    variables that are ``TOP`` (overdefined) or ``BOTTOM`` (unresolved).

    Args:
        mba: An ``ida_hexrays.mba_t`` instance (typed as ``object`` to
            avoid a hard import dependency on IDA at module level).

    Returns:
        ``{mop_key: int | None}`` -- constant for resolved variables,
        ``None`` for overdefined / unresolved.
    """
    try:
        import ida_hexrays  # noqa: F811
    except ImportError:
        return {}

    try:
        return _run_sccp_impl(mba, ida_hexrays)
    except Exception as exc:
        logger.warning("sccp: top-level failure: %s", exc)
        return {}


def _run_sccp_impl(
    mba: object,
    ida_hexrays: object,
) -> dict[tuple, int | None]:
    """Core SCCP implementation."""
    from d810.hexrays.expr.p_ast import get_mop_key

    qty: int = mba.qty  # type: ignore[attr-defined]
    if qty > _MAX_BLOCKS:
        logger.info("sccp: skipping (%d blocks > %d limit)", qty, _MAX_BLOCKS)
        return {}

    # ------------------------------------------------------------------ init
    lattice: dict[tuple, LatticeValue] = defaultdict(lambda: BOTTOM)
    executable: set[tuple[int, int]] = set()

    cfg_worklist: deque[tuple[int, int]] = deque()
    ssa_worklist: deque[tuple] = deque()  # mop_keys whose value changed

    # Seed: entry block's outgoing edges
    entry_blk = mba.get_mblock(0)  # type: ignore[attr-defined]
    if entry_blk is None:
        return {}
    for i in range(entry_blk.nsucc()):  # type: ignore[attr-defined]
        cfg_worklist.append((0, entry_blk.succ(i)))  # type: ignore[attr-defined]

    # ------------------------------------------------------------------ main
    cfg_iters = 0
    ssa_iters = 0

    while cfg_worklist or ssa_worklist:
        # ---- CFG worklist ----
        while cfg_worklist and cfg_iters < _MAX_CFG_ITERATIONS:
            cfg_iters += 1
            from_blk, to_blk = cfg_worklist.popleft()
            if (from_blk, to_blk) in executable:
                continue
            executable.add((from_blk, to_blk))

            blk = mba.get_mblock(to_blk)  # type: ignore[attr-defined]
            if blk is None:
                continue

            # Evaluate all instructions in the block
            ins = blk.head  # type: ignore[attr-defined]
            while ins is not None:
                _evaluate_insn(ins, lattice, ssa_worklist, get_mop_key, ida_hexrays)
                ins = ins.next  # type: ignore[attr-defined]

            # Add successor edges
            for i in range(blk.nsucc()):  # type: ignore[attr-defined]
                succ = blk.succ(i)  # type: ignore[attr-defined]
                if (to_blk, succ) not in executable:
                    cfg_worklist.append((to_blk, succ))

        # ---- SSA worklist ----
        while ssa_worklist and ssa_iters < _MAX_SSA_ITERATIONS:
            ssa_iters += 1
            changed_key = ssa_worklist.popleft()

            # TODO: Find all USE sites of changed_key via mba.get_du(GC_REGS_AND_STKVARS)
            # For each use site in an executable block, re-evaluate the instruction.
            # If the instruction's destination lattice value changes, add it to ssa_worklist.
            #
            # Skeleton:
            #   use_blocks = _find_use_blocks(mba, changed_key, ida_hexrays)
            #   for use_blk_serial in use_blocks:
            #       if not _block_is_executable(use_blk_serial, executable):
            #           continue
            #       blk = mba.get_mblock(use_blk_serial)
            #       ins = blk.head
            #       while ins is not None:
            #           if _uses_variable(ins, changed_key, get_mop_key, ida_hexrays):
            #               _evaluate_insn(ins, lattice, ssa_worklist, get_mop_key, ida_hexrays)
            #               # If dest changed and is a conditional branch, update cfg_worklist
            #               if _is_conditional_branch(ins, ida_hexrays):
            #                   _update_cfg_edges(ins, lattice, cfg_worklist, blk, ida_hexrays)
            #           ins = ins.next
            pass  # SSA propagation not yet implemented

    # ------------------------------------------------------------------ extract
    result: dict[tuple, int | None] = {}
    for key, lv in lattice.items():
        if lv.kind is _LatticeKind.CONST:
            result[key] = lv.value
        else:
            result[key] = None
    return result


# ---------------------------------------------------------------------------
# Instruction evaluation
# ---------------------------------------------------------------------------

def _evaluate_insn(
    ins: object,
    lattice: dict[tuple, LatticeValue],
    ssa_worklist: deque[tuple],
    get_mop_key: object,
    ida_hexrays: object,
) -> None:
    """Evaluate a single instruction and update the lattice.

    If the destination's lattice value changes, append its key to *ssa_worklist*.
    """
    d = ins.d  # type: ignore[attr-defined]
    if d is None:
        return
    if d.t == ida_hexrays.mop_z:  # type: ignore[attr-defined]
        return  # No destination (e.g. conditional jumps write flags, not a variable)

    try:
        dest_key = get_mop_key(d)  # type: ignore[misc]
    except Exception:
        return

    old_val = lattice[dest_key]

    # Compute new value from source operands
    new_val = _eval_sources(ins, lattice, get_mop_key, ida_hexrays)

    # Monotone update: value can only go up (BOTTOM -> Const -> TOP)
    merged = _meet(old_val, new_val)
    if merged != old_val:
        lattice[dest_key] = merged
        ssa_worklist.append(dest_key)


def _eval_sources(
    ins: object,
    lattice: dict[tuple, LatticeValue],
    get_mop_key: object,
    ida_hexrays: object,
) -> LatticeValue:
    """Evaluate an instruction given current lattice values for operands.

    Returns the resulting LatticeValue for the destination.
    """
    # Resolve source operand lattice values
    l_mop = ins.l  # type: ignore[attr-defined]
    r_mop = ins.r  # type: ignore[attr-defined]

    lv = _resolve_operand(l_mop, lattice, get_mop_key, ida_hexrays) if l_mop is not None else None
    # For unary ops, r is not used
    rv = _resolve_operand(r_mop, lattice, get_mop_key, ida_hexrays) if r_mop is not None else None

    # If left source is BOTTOM, result is BOTTOM (not yet known)
    if lv is not None and lv.kind is _LatticeKind.BOTTOM:
        return BOTTOM
    # If left source is TOP, result is TOP (overdefined)
    if lv is not None and lv.kind is _LatticeKind.TOP:
        return TOP

    # For binary ops, check right operand too
    opcode = ins.opcode  # type: ignore[attr-defined]
    if rv is not None:
        if rv.kind is _LatticeKind.BOTTOM:
            return BOTTOM
        if rv.kind is _LatticeKind.TOP:
            return TOP

    # All sources are Const (or immediate) -- evaluate the operation
    # TODO: Bridge to demand_eval._eval_with_constants or implement inline
    # For now, delegate to the arithmetic evaluator from demand_eval
    try:
        _demand = __import__(
            "d810.evaluator.hexrays_microcode.demand_eval",
            fromlist=["_eval_with_constants"],
        )
        # Build a minimal memo dict from lattice const values
        memo: dict[tuple, int | None] = {}
        for src_mop in [l_mop, r_mop]:
            if src_mop is None:
                continue
            if src_mop.t == ida_hexrays.mop_n:  # type: ignore[attr-defined]
                continue  # _eval_with_constants reads immediates directly
            try:
                src_key = get_mop_key(src_mop)  # type: ignore[misc]
            except Exception:
                return TOP
            src_lv = lattice.get(src_key, BOTTOM)
            if src_lv.kind is _LatticeKind.CONST:
                memo[src_key] = src_lv.value
            else:
                return BOTTOM if src_lv.kind is _LatticeKind.BOTTOM else TOP

        result = _demand._eval_with_constants(ins, memo)
        if result is not None:
            return _const(result)
        return TOP
    except Exception:
        return TOP


def _resolve_operand(
    mop: object,
    lattice: dict[tuple, LatticeValue],
    get_mop_key: object,
    ida_hexrays: object,
) -> LatticeValue | None:
    """Resolve a source operand to a LatticeValue."""
    if mop is None:
        return None
    t = mop.t  # type: ignore[attr-defined]
    if t == ida_hexrays.mop_n:  # type: ignore[attr-defined]
        nnn = mop.nnn  # type: ignore[attr-defined]
        val = nnn.value if nnn is not None else 0
        return _const(val)
    if t in (ida_hexrays.mop_r, ida_hexrays.mop_S):  # type: ignore[attr-defined]
        try:
            key = get_mop_key(mop)  # type: ignore[misc]
        except Exception:
            return TOP
        return lattice.get(key, BOTTOM)
    # Unsupported operand type -> overdefined
    return TOP


# ---------------------------------------------------------------------------
# Helpers (stubs for future implementation)
# ---------------------------------------------------------------------------

def _find_use_blocks(
    mba: object,
    mop_key: tuple,
    ida_hexrays: object,
) -> list[int]:
    """Find all block serials that USE a variable identified by mop_key.

    TODO: Use ``mba.get_du(GC_REGS_AND_STKVARS)`` to find use sites.
    The DU chains provide ``block_chains_t`` per block with reg and stkvar
    chain accessors.
    """
    return []  # Stub


def _block_is_executable(blk_serial: int, executable: set[tuple[int, int]]) -> bool:
    """Check if any incoming edge to blk_serial is in the executable set."""
    return any(to == blk_serial for _, to in executable)


def _uses_variable(
    ins: object,
    mop_key: tuple,
    get_mop_key: object,
    ida_hexrays: object,
) -> bool:
    """Check if an instruction uses a variable identified by mop_key.

    TODO: Inspect ins.l, ins.r, and sub-operands for matching mop_key.
    """
    return False  # Stub


def _is_conditional_branch(ins: object, ida_hexrays: object) -> bool:
    """Check if an instruction is a conditional branch."""
    opcode = ins.opcode  # type: ignore[attr-defined]
    return opcode in (
        ida_hexrays.m_jcnd,  # type: ignore[attr-defined]
        ida_hexrays.m_jnz,  # type: ignore[attr-defined]
        ida_hexrays.m_jz,  # type: ignore[attr-defined]
        ida_hexrays.m_jae,  # type: ignore[attr-defined]
        ida_hexrays.m_jb,  # type: ignore[attr-defined]
        ida_hexrays.m_ja,  # type: ignore[attr-defined]
        ida_hexrays.m_jbe,  # type: ignore[attr-defined]
        ida_hexrays.m_jg,  # type: ignore[attr-defined]
        ida_hexrays.m_jge,  # type: ignore[attr-defined]
        ida_hexrays.m_jl,  # type: ignore[attr-defined]
        ida_hexrays.m_jle,  # type: ignore[attr-defined]
    )


def _update_cfg_edges(
    ins: object,
    lattice: dict[tuple, LatticeValue],
    cfg_worklist: deque[tuple[int, int]],
    blk: object,
    ida_hexrays: object,
) -> None:
    """If a conditional branch resolves to a constant, add only the taken edge.

    TODO: Evaluate the branch condition from the lattice. If the condition
    is Const(0), add only the fall-through edge. If Const(nonzero), add
    only the taken edge. If TOP/BOTTOM, add both edges (conservative).
    """
    pass  # Stub

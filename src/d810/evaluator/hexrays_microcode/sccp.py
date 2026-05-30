"""Sparse Conditional Constant Propagation (SCCP) -- Algorithm 3.

Gold-standard compiler constant propagation combining a constant lattice
with CFG reachability analysis.  Uses IDA's DU chains (``mba.get_du``)
for SSA-like use-def information.

**Status: DORMANT** -- not wired into the emulator or any pass.  Created
as a complete solver for future activation.

The lattice is: ``BOTTOM`` (unknown) < ``Const(v, sz)`` < ``TOP`` (overdefined).
Two worklists drive the analysis:

* **CFG worklist** -- edges ``(from_blk, to_blk)`` that become executable.
* **SSA worklist** -- ``mop_key`` values whose lattice entry changed, so
  downstream uses must be re-evaluated.

References:
    Wegman & Zadeck, "Constant Propagation with Conditional Branches", 1991.
    LLVM SparsePropagation.h
    docs/plans/2026-03-16-emulator-cross-block-resolution.md  (Algorithm 3)
"""
from __future__ import annotations

from collections import defaultdict, deque

from d810.ir.lattice import BOTTOM, TOP, Const, LatticeValue, lattice_meet
from d810.core.logging import getLogger
from d810.core.typing import Any

logger = getLogger(__name__)

# ---------------------------------------------------------------------------
# Type aliases (re-export canonical lattice types under SCCP-local names)
# ---------------------------------------------------------------------------

LatticeVal = LatticeValue
MopKey = tuple  # from get_mop_key
CfgEdge = tuple[int, int]  # (from_serial, to_serial)


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

_MAX_BLOCKS = 500

# ---------------------------------------------------------------------------
# Internal opcode sets (lazily initialized to avoid module-level IDA import)
# ---------------------------------------------------------------------------

_UNARY_OPCODES: frozenset[int] | None = None
_BINARY_OPCODES: frozenset[int] | None = None
_CMP_OPCODES: frozenset[int] | None = None
_COND_BRANCH_OPCODES: frozenset[int] | None = None


def _init_opcode_sets(hx: Any) -> None:
    """Lazily populate opcode classification sets."""
    global _UNARY_OPCODES, _BINARY_OPCODES, _CMP_OPCODES, _COND_BRANCH_OPCODES

    if _UNARY_OPCODES is not None:
        return

    _UNARY_OPCODES = frozenset([
        hx.m_mov, hx.m_neg, hx.m_lnot, hx.m_bnot,
        hx.m_xds, hx.m_xdu, hx.m_low, hx.m_high,
    ])

    _BINARY_OPCODES = frozenset([
        hx.m_add, hx.m_sub, hx.m_mul,
        hx.m_udiv, hx.m_sdiv, hx.m_umod, hx.m_smod,
        hx.m_or, hx.m_and, hx.m_xor,
        hx.m_shl, hx.m_shr, hx.m_sar,
    ])

    _CMP_OPCODES = frozenset([
        hx.m_setz, hx.m_setnz, hx.m_setae, hx.m_setb,
        hx.m_seta, hx.m_setbe, hx.m_setg, hx.m_setge,
        hx.m_setl, hx.m_setle,
    ])

    _COND_BRANCH_OPCODES = frozenset([
        hx.m_jcnd, hx.m_jnz, hx.m_jz,
        hx.m_jae, hx.m_jb, hx.m_ja, hx.m_jbe,
        hx.m_jg, hx.m_jge, hx.m_jl, hx.m_jle,
    ])


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


# ---------------------------------------------------------------------------
# Core solver
# ---------------------------------------------------------------------------


def _run_sccp_impl(
    mba: object,
    hx: Any,
) -> dict[tuple, int | None]:
    """Core SCCP implementation.

    1. Initialize: all variables = BOTTOM, entry block edges executable.
    2. Main loop: drain CFG worklist then SSA worklist until both empty.
    3. visit_cfg_edge: mark edge executable; if block newly reachable,
       visit all its instructions.
    4. visit_ssa_edge: re-evaluate instructions that use the changed variable.
    5. eval_phi: for passthru variables, meet values from executable preds.
    6. eval_insn: evaluate instruction, update dest lattice value.
    7. eval_branch: if condition is Const, only add taken successor.
    8. update_value: on lattice change, add all DU uses to SSA worklist.
    """
    from d810.hexrays.expr.p_ast import get_mop_key
    from d810.core.bits import (
        AND_TABLE,
        get_add_cf,
        get_add_of,
        get_parity_flag,
        get_sub_of,
        signed_to_unsigned,
        unsigned_to_signed,
    )

    _init_opcode_sets(hx)
    assert _UNARY_OPCODES is not None  # guaranteed by _init_opcode_sets

    qty: int = mba.qty  # type: ignore[attr-defined]
    if qty > _MAX_BLOCKS:
        logger.info("sccp: skipping (%d blocks > %d limit)", qty, _MAX_BLOCKS)
        return {}

    max_iterations = qty * 10

    # ------------------------------------------------------------------ state
    lattice: dict[MopKey, LatticeVal] = defaultdict(lambda: BOTTOM)
    executable: set[CfgEdge] = set()
    block_visited: set[int] = set()  # blocks whose instructions were evaluated

    cfg_wl: deque[CfgEdge] = deque()
    ssa_wl: deque[MopKey] = deque()

    # Build DU chains once up front.
    du_index = _build_du_index(mba, hx, qty, get_mop_key)

    # ------------------------------------------------------------------ seed
    # Entry block (serial 0) is always executable.
    entry_blk = mba.get_mblock(0)  # type: ignore[attr-defined]
    if entry_blk is None:
        return {}

    # Seed: a virtual edge (-1, 0) to mark the entry block reachable.
    cfg_wl.append((-1, 0))

    # -------------------------------------------------------------- helpers

    def _resolve_operand(mop: Any) -> LatticeVal:
        """Resolve a source operand to its lattice value."""
        if mop is None:
            return TOP
        t = mop.t
        if t == hx.mop_n:
            nnn = mop.nnn
            val = nnn.value if nnn is not None else 0
            return Const(val, mop.size)
        if t in (hx.mop_r, hx.mop_S):
            try:
                key = get_mop_key(mop)
            except Exception:
                return TOP
            return lattice[key]
        # mop_d (nested instruction result), mop_v (global), etc. -> TOP
        return TOP

    def _mask(size: int) -> int:
        return AND_TABLE.get(size, AND_TABLE[8])

    def _short_circuit(opcode: int, lv: LatticeVal, rv: LatticeVal, dest_size: int) -> LatticeVal | None:
        """Apply short-circuit evaluation rules from Rust SCCP.

        Returns a LatticeVal if the result can be determined without both
        operands being Const, or None to fall through to normal evaluation.
        """
        mask = _mask(dest_size)

        # x * 0 = 0 (either side)
        if opcode == hx.m_mul:
            zero = Const(0, dest_size)
            if isinstance(lv, Const) and lv.value == 0:
                return zero
            if isinstance(rv, Const) and rv.value == 0:
                return zero

        # x & 0 = 0 (either side)
        if opcode == hx.m_and:
            zero = Const(0, dest_size)
            if isinstance(lv, Const) and lv.value == 0:
                return zero
            if isinstance(rv, Const) and rv.value == 0:
                return zero

        # x | all_ones = all_ones (either side)
        if opcode == hx.m_or:
            if isinstance(lv, Const) and lv.value == mask:
                return Const(mask, dest_size)
            if isinstance(rv, Const) and rv.value == mask:
                return Const(mask, dest_size)

        return None

    def _eval_insn_value(ins: Any) -> LatticeVal:
        """Evaluate one instruction and return the lattice value for dest."""
        opcode = ins.opcode
        d = ins.d
        if d is None or d.t == hx.mop_z:
            return TOP

        dest_size = d.size
        if dest_size <= 0:
            return TOP

        mask = _mask(dest_size)

        l_mop = ins.l
        r_mop = ins.r

        lv = _resolve_operand(l_mop)
        rv = _resolve_operand(r_mop) if r_mop is not None else None

        # ---- Unary opcodes ----
        if opcode in _UNARY_OPCODES:
            if lv is BOTTOM:
                return BOTTOM
            if lv is TOP:
                return TOP
            assert isinstance(lv, Const)
            v = lv.value
            ls = l_mop.size if l_mop is not None else dest_size

            if opcode == hx.m_mov:
                return Const(v & mask, dest_size)
            if opcode == hx.m_neg:
                return Const((-v) & mask, dest_size)
            if opcode == hx.m_lnot:
                return Const(int(v == 0) & mask, dest_size)
            if opcode == hx.m_bnot:
                return Const((v ^ mask) & mask, dest_size)
            if opcode == hx.m_xds:
                left_signed = unsigned_to_signed(v, ls)
                return Const(signed_to_unsigned(left_signed, dest_size) & mask, dest_size)
            if opcode == hx.m_xdu:
                return Const(v & mask, dest_size)
            if opcode == hx.m_low:
                return Const(v & mask, dest_size)
            if opcode == hx.m_high:
                shift_bits = dest_size * 8 if dest_size else 0
                return Const((v >> shift_bits) & mask, dest_size)
            return TOP

        # ---- Binary / comparison opcodes ----
        if opcode in _BINARY_OPCODES or opcode in _CMP_OPCODES:
            if rv is None:
                return TOP

            # Short-circuit evaluation (Rust SCCP rules)
            sc = _short_circuit(opcode, lv, rv, dest_size)
            if sc is not None:
                return sc

            # If either operand is BOTTOM, result is BOTTOM (unless short-circuited above)
            if lv is BOTTOM or rv is BOTTOM:
                return BOTTOM
            # If either operand is TOP, result is TOP
            if lv is TOP or rv is TOP:
                return TOP

            assert isinstance(lv, Const) and isinstance(rv, Const)
            a = lv.value
            b = rv.value
            ls = l_mop.size if l_mop is not None else dest_size
            rs = r_mop.size if r_mop is not None else dest_size

            result: int | None = None

            # Binary arithmetic
            if opcode == hx.m_add:
                result = (a + b) & mask
            elif opcode == hx.m_sub:
                result = (a - b) & mask
            elif opcode == hx.m_mul:
                result = (a * b) & mask
            elif opcode == hx.m_udiv:
                result = (a // b) & mask if b != 0 else None
            elif opcode == hx.m_sdiv:
                if b == 0:
                    result = None
                else:
                    la = unsigned_to_signed(a, ls)
                    rb = unsigned_to_signed(b, rs)
                    if rb == 0:
                        result = None
                    else:
                        q = (abs(la) // abs(rb)) * (-1 if (la < 0) ^ (rb < 0) else 1)
                        result = signed_to_unsigned(q, dest_size) & mask
            elif opcode == hx.m_umod:
                result = (a % b) & mask if b != 0 else None
            elif opcode == hx.m_smod:
                if b == 0:
                    result = None
                else:
                    la = unsigned_to_signed(a, ls)
                    rb = unsigned_to_signed(b, rs)
                    if rb == 0:
                        result = None
                    else:
                        q = (abs(la) // abs(rb)) * (-1 if (la < 0) ^ (rb < 0) else 1)
                        result = signed_to_unsigned(la - (q * rb), dest_size) & mask
            elif opcode == hx.m_or:
                result = (a | b) & mask
            elif opcode == hx.m_and:
                result = (a & b) & mask
            elif opcode == hx.m_xor:
                result = (a ^ b) & mask
            elif opcode == hx.m_shl:
                result = (a << b) & mask
            elif opcode == hx.m_shr:
                result = (a >> b) & mask
            elif opcode == hx.m_sar:
                result = signed_to_unsigned(unsigned_to_signed(a, ls) >> b, dest_size) & mask

            # Comparison ops
            elif opcode == hx.m_setz:
                result = (1 if a == b else 0) & mask
            elif opcode == hx.m_setnz:
                result = (1 if a != b else 0) & mask
            elif opcode == hx.m_setae:
                result = (1 if a >= b else 0) & mask
            elif opcode == hx.m_setb:
                result = (1 if a < b else 0) & mask
            elif opcode == hx.m_seta:
                result = (1 if a > b else 0) & mask
            elif opcode == hx.m_setbe:
                result = (1 if a <= b else 0) & mask
            elif opcode == hx.m_setg:
                result = (1 if unsigned_to_signed(a, ls) > unsigned_to_signed(b, rs) else 0) & mask
            elif opcode == hx.m_setge:
                result = (1 if unsigned_to_signed(a, ls) >= unsigned_to_signed(b, rs) else 0) & mask
            elif opcode == hx.m_setl:
                result = (1 if unsigned_to_signed(a, ls) < unsigned_to_signed(b, rs) else 0) & mask
            elif opcode == hx.m_setle:
                result = (1 if unsigned_to_signed(a, ls) <= unsigned_to_signed(b, rs) else 0) & mask

            if result is not None:
                return Const(result, dest_size)
            return TOP

        # ---- Conditional branches (m_jz, m_jnz, etc.) ----
        # These write to the dest operand as a side-effect in some maturity
        # levels (condition result), but more importantly we handle branching
        # separately via _eval_branch.  For the dest lattice, treat as TOP.
        if opcode in _COND_BRANCH_OPCODES:
            return TOP

        # Unknown/side-effecting opcode -> TOP
        return TOP

    def _eval_branch(ins: Any, blk: Any) -> None:
        """Evaluate branch instruction and add appropriate successor edges.

        If the branch condition resolves to a Const, add only the taken
        (or fall-through) edge.  Otherwise add both successors.
        """
        opcode = ins.opcode
        blk_serial: int = blk.serial

        if opcode == hx.m_goto:
            # Unconditional goto -- single successor.
            for i in range(blk.nsucc()):
                s = blk.succ(i)
                if (blk_serial, s) not in executable:
                    cfg_wl.append((blk_serial, s))
            return

        if opcode not in _COND_BRANCH_OPCODES:
            # Non-branching tail -- add all successors.
            for i in range(blk.nsucc()):
                s = blk.succ(i)
                if (blk_serial, s) not in executable:
                    cfg_wl.append((blk_serial, s))
            return

        # Conditional branch: try to resolve condition.
        cond_val = _eval_condition(ins)

        if cond_val is BOTTOM:
            # Condition not yet known -- don't add any edges yet.
            # They will be added when the condition's dependencies resolve.
            return

        if cond_val is TOP:
            # Overdefined -- both branches feasible.
            for i in range(blk.nsucc()):
                s = blk.succ(i)
                if (blk_serial, s) not in executable:
                    cfg_wl.append((blk_serial, s))
            return

        # Condition is Const: determine taken vs fall-through.
        assert isinstance(cond_val, Const)
        nsucc = blk.nsucc()
        if nsucc < 2:
            # Degenerate: only one successor, add it.
            for i in range(nsucc):
                s = blk.succ(i)
                if (blk_serial, s) not in executable:
                    cfg_wl.append((blk_serial, s))
            return

        # IDA convention: succ(0) = fall-through, succ(1) = taken branch.
        fall_through = blk.succ(0)
        taken = blk.succ(1)

        if cond_val.value != 0:
            # Condition is true -> taken branch only.
            if (blk_serial, taken) not in executable:
                cfg_wl.append((blk_serial, taken))
        else:
            # Condition is false -> fall-through only.
            if (blk_serial, fall_through) not in executable:
                cfg_wl.append((blk_serial, fall_through))

    def _eval_condition(ins: Any) -> LatticeVal:
        """Evaluate the condition of a conditional branch instruction.

        For m_jcnd: condition is in ins.l (nested instruction result).
        For m_jz/m_jnz/m_jae/etc.: compare ins.l vs ins.r.
        """
        opcode = ins.opcode

        if opcode == hx.m_jcnd:
            # m_jcnd condition is in ins.l
            return _resolve_operand(ins.l)

        # Binary conditional jumps: compare l vs r.
        lv = _resolve_operand(ins.l)
        rv = _resolve_operand(ins.r)

        if lv is BOTTOM or rv is BOTTOM:
            return BOTTOM
        if lv is TOP or rv is TOP:
            return TOP

        assert isinstance(lv, Const) and isinstance(rv, Const)
        a = lv.value
        b = rv.value
        ls = ins.l.size if ins.l is not None else 4
        rs = ins.r.size if ins.r is not None else 4

        result: int | None = None
        if opcode == hx.m_jz:
            result = 1 if a == b else 0
        elif opcode == hx.m_jnz:
            result = 1 if a != b else 0
        elif opcode == hx.m_jae:
            result = 1 if a >= b else 0
        elif opcode == hx.m_jb:
            result = 1 if a < b else 0
        elif opcode == hx.m_ja:
            result = 1 if a > b else 0
        elif opcode == hx.m_jbe:
            result = 1 if a <= b else 0
        elif opcode == hx.m_jg:
            result = 1 if unsigned_to_signed(a, ls) > unsigned_to_signed(b, rs) else 0
        elif opcode == hx.m_jge:
            result = 1 if unsigned_to_signed(a, ls) >= unsigned_to_signed(b, rs) else 0
        elif opcode == hx.m_jl:
            result = 1 if unsigned_to_signed(a, ls) < unsigned_to_signed(b, rs) else 0
        elif opcode == hx.m_jle:
            result = 1 if unsigned_to_signed(a, ls) <= unsigned_to_signed(b, rs) else 0

        if result is not None:
            return Const(result, 1)
        return TOP

    def _update_lattice(dest_key: MopKey, new_val: LatticeVal, ins_ea: int = 0) -> bool:
        """Monotone lattice update.  Returns True if value changed."""
        old_val = lattice[dest_key]
        merged = lattice_meet(old_val, new_val)
        if merged is old_val or merged == old_val:
            return False
        lattice[dest_key] = merged
        if logger.debug_on and isinstance(merged, Const):
            logger.debug(
                "SCCP-LATTICE: key=%s -> Const(0x%x, %d) from_ea=0x%x",
                dest_key, merged.value, merged.size, ins_ea,
            )
        return True

    def _visit_insn(ins: Any, blk_serial: int) -> None:
        """Visit a single instruction: eval, update lattice, propagate."""
        d = ins.d
        if d is None or d.t == hx.mop_z:
            return

        try:
            dest_key = get_mop_key(d)
        except Exception:
            return

        new_val = _eval_insn_value(ins)
        if _update_lattice(dest_key, new_val, ins_ea=ins.ea):
            # Value changed -- add all uses to SSA worklist.
            ssa_wl.append(dest_key)

    def _visit_block(blk_serial: int) -> None:
        """Visit all instructions in a block."""
        blk = mba.get_mblock(blk_serial)  # type: ignore[attr-defined]
        if blk is None:
            return

        ins = blk.head
        while ins is not None:
            _visit_insn(ins, blk_serial)
            ins = ins.next

        # Evaluate branch at the tail to determine successor edges.
        tail = blk.tail
        if tail is not None:
            _eval_branch(tail, blk)
        else:
            # No tail instruction -- add all successors.
            for i in range(blk.nsucc()):
                s = blk.succ(i)
                if (blk_serial, s) not in executable:
                    cfg_wl.append((blk_serial, s))

    def _block_is_executable(blk_serial: int) -> bool:
        """Check if any incoming edge to blk_serial is executable."""
        return blk_serial in block_visited

    # ------------------------------------------------------------------ main loop
    iteration = 0

    while (cfg_wl or ssa_wl) and iteration < max_iterations:
        iteration += 1

        # ---- CFG worklist: process one edge ----
        if cfg_wl:
            from_blk, to_blk = cfg_wl.popleft()
            edge = (from_blk, to_blk)

            if edge in executable:
                continue

            executable.add(edge)

            first_visit = to_blk not in block_visited
            block_visited.add(to_blk)

            if first_visit:
                # Block newly reachable: visit all instructions.
                _visit_block(to_blk)
            else:
                # Block already visited but new edge arrived.
                # Re-evaluate phi-like variables at block entry
                # (values from new predecessor may change lattice).
                _revisit_phi_inputs(mba, hx, to_blk, lattice, ssa_wl, get_mop_key)

            continue

        # ---- SSA worklist: process one variable change ----
        if ssa_wl:
            changed_key = ssa_wl.popleft()

            # Find all USE sites of changed_key via DU index.
            use_sites = du_index.get(changed_key, [])

            for use_blk_serial, use_ea in use_sites:
                if not _block_is_executable(use_blk_serial):
                    continue

                blk = mba.get_mblock(use_blk_serial)  # type: ignore[attr-defined]
                if blk is None:
                    continue

                # Re-evaluate all instructions in the block that use this variable.
                ins = blk.head
                while ins is not None:
                    if _insn_uses_key(ins, changed_key, get_mop_key, hx):
                        _visit_insn(ins, use_blk_serial)
                    ins = ins.next

                # If the tail is a conditional branch and it uses the changed var,
                # re-evaluate branch edges.
                tail = blk.tail
                if tail is not None and tail.opcode in _COND_BRANCH_OPCODES:
                    if _insn_uses_key(tail, changed_key, get_mop_key, hx):
                        _eval_branch(tail, blk)

    if iteration >= max_iterations:
        logger.info("sccp: hit iteration limit (%d)", max_iterations)

    # ------------------------------------------------------------------ extract
    result: dict[tuple, int | None] = {}
    for key, lv in lattice.items():
        if isinstance(lv, Const):
            result[key] = lv.value
        else:
            result[key] = None
    return result


# ---------------------------------------------------------------------------
# DU index builder
# ---------------------------------------------------------------------------


def _build_du_index(
    mba: Any,
    hx: Any,
    qty: int,
    get_mop_key: Any,
) -> dict[MopKey, list[tuple[int, int]]]:
    """Build a mapping: mop_key -> list of (blk_serial, insn_ea) use sites.

    Walks every instruction in the MBA and records which mop_keys appear
    as source operands.  This is a lightweight alternative to IDA's DU chains
    that works without requiring ``mba.build_graph()`` (which may not be
    available at all maturity levels).
    """
    index: dict[MopKey, list[tuple[int, int]]] = defaultdict(list)

    for blk_idx in range(qty):
        blk = mba.get_mblock(blk_idx)  # type: ignore[attr-defined]
        if blk is None:
            continue

        ins = blk.head
        while ins is not None:
            _collect_source_keys(ins, blk_idx, ins.ea, index, get_mop_key, hx)
            ins = ins.next

    return dict(index)


def _collect_source_keys(
    ins: Any,
    blk_serial: int,
    ea: int,
    index: dict[MopKey, list[tuple[int, int]]],
    get_mop_key: Any,
    hx: Any,
) -> None:
    """Record all source mop_keys in an instruction into the DU index."""
    for mop in _iter_source_mops(ins, hx):
        try:
            key = get_mop_key(mop)
        except Exception:
            continue
        index[key].append((blk_serial, ea))


def _iter_source_mops(ins: Any, hx: Any) -> list[Any]:
    """Return a list of source operands from an instruction."""
    result: list[Any] = []
    if ins.l is not None and ins.l.t != hx.mop_z:
        result.append(ins.l)
    if ins.r is not None and ins.r.t != hx.mop_z:
        result.append(ins.r)
    return result


# ---------------------------------------------------------------------------
# Instruction source matching
# ---------------------------------------------------------------------------


def _insn_uses_key(
    ins: Any,
    key: MopKey,
    get_mop_key: Any,
    hx: Any,
) -> bool:
    """Check if an instruction reads a variable identified by mop_key."""
    for mop in _iter_source_mops(ins, hx):
        try:
            if get_mop_key(mop) == key:
                return True
        except Exception:
            continue
    return False


# ---------------------------------------------------------------------------
# PHI-like re-evaluation on new executable edge
# ---------------------------------------------------------------------------


def _revisit_phi_inputs(
    mba: Any,
    hx: Any,
    blk_serial: int,
    lattice: dict[MopKey, LatticeVal],
    ssa_wl: deque[MopKey],
    get_mop_key: Any,
) -> None:
    """When a new edge into *blk_serial* becomes executable, re-evaluate
    all instructions in the block whose source operands may have new values
    flowing in from the newly-executable predecessor.

    Without explicit PHI nodes we conservatively re-visit the entire block.
    """
    blk = mba.get_mblock(blk_serial)  # type: ignore[attr-defined]
    if blk is None:
        return

    ins = blk.head
    while ins is not None:
        d = ins.d
        if d is not None and d.t != hx.mop_z:
            try:
                dest_key = get_mop_key(d)
            except Exception:
                ins = ins.next
                continue

            # Re-add to SSA worklist so downstream uses get re-evaluated.
            ssa_wl.append(dest_key)
        ins = ins.next


# ---------------------------------------------------------------------------
# Module-level exports
# ---------------------------------------------------------------------------

__all__ = [
    "LatticeVal",
    "MopKey",
    "CfgEdge",
    "run_sccp",
]

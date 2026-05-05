"""Loop-bound-writer detection used by path-tail and shared-group guards.

Identifies the OLLVM-style ``m_xdu (X & K), %B`` (or ``m_and X, K, %B``)
pattern where ``B`` is a stkvar bound that participates in a loop test
of shape ``m_jnz/m_jz (counter + small_const), B``.  When a CFG mutation
(redirect, duplicate-and-redirect, etc.) routes the bound writer through
a fresh predecessor topology, IDA's MMAT_GLBOPT1 finalization
forward-substitutes the unique writer into the loop test and erases the
counter side, producing a non-progressing inner do-while.

Used by the path-tail planner *and* the shared-group reconstruction
planner.  The detector itself is identical; only the wiring differs.
Returns ``None`` on any failure so the surrounding code can keep its
existing fast-path semantics.
"""
from __future__ import annotations

from dataclasses import dataclass

# Loop-bound mask values seen on OLLVM-style flattened functions where the
# bound expression is ``(state & mask)`` with mask in
# {0x1F, 0x3E, 0x3F, 0x7F}.  Kept narrow on purpose: any broader set
# risks suppressing legitimate state-transition redirects.
_LOOP_BOUND_MASKS: frozenset[int] = frozenset({0x1F, 0x3E, 0x3F, 0x7F})

# Counter-advance deltas: ``counter + small_const`` where ``small_const``
# is an offset matching common index/byte/word/qword stride patterns.
_COUNTER_ADVANCE_DELTAS: frozenset[int] = frozenset({1, 2, 4, 8})


@dataclass(frozen=True, slots=True)
class LoopBoundWriterDiagnostic:
    """Verdict from the loop-bound-writer detector.

    Populated only when all four conjunctive conditions hold for the
    candidate's source block:

    1. The source block contains a unique writer to a stkvar ``B``.
    2. The writer expression is ``(X & K)`` (or ``m_xdu(X & K)``) with
       ``K`` in :data:`_LOOP_BOUND_MASKS`.
    3. Some block in the function reads ``B`` via ``m_jnz`` / ``m_jz``.
    4. The other operand of that loop test has counter-advance shape
       (``counter_stkvar + small_const`` with the const in
       :data:`_COUNTER_ADVANCE_DELTAS`).
    """

    bound_stkoff: int
    bound_writer_ea: int
    loop_test_ea: int
    counter_stkoff: int


def _safe_int_attr(obj, attr: str, default: int = -1) -> int:
    try:
        return int(getattr(obj, attr))
    except (AttributeError, TypeError, ValueError):
        return default


def _iter_block_insns(blk):
    insn = getattr(blk, "head", None)
    while insn is not None:
        yield insn
        insn = getattr(insn, "next", None)


def _extract_const_mask_from_binop(sub_insn, *, mop_n: int) -> int | None:
    """Return the constant operand of a 2-operand sub-instruction whose
    other operand is non-const, or ``None``."""
    l = getattr(sub_insn, "l", None)
    r = getattr(sub_insn, "r", None)
    if l is None or r is None:
        return None
    try:
        lt = int(l.t)
        rt = int(r.t)
    except (AttributeError, TypeError):
        return None
    if rt == mop_n and lt != mop_n:
        try:
            return int(r.nnn.value) & 0xFFFFFFFFFFFFFFFF
        except (AttributeError, TypeError):
            return None
    if lt == mop_n and rt != mop_n:
        try:
            return int(l.nnn.value) & 0xFFFFFFFFFFFFFFFF
        except (AttributeError, TypeError):
            return None
    return None


def _detect_constant_mask_writer(
    insn,
    *,
    m_xdu: int,
    m_and: int,
    mop_n: int,
    mop_S: int,
    mop_d: int,
) -> int | None:
    """If ``insn`` writes a stkvar with a constant-mask expression
    ``(X & K)`` where ``K`` is a recognized loop-bound mask, return the
    destination stkoff; else ``None``.

    Two shapes are accepted:

    * ``m_xdu(mop_d(m_and X K)), %B``  -- mask-and-extend.
    * ``m_and X K, %B``                -- direct mask write.
    """
    op = _safe_int_attr(insn, "opcode")
    d = getattr(insn, "d", None)
    if d is None:
        return None
    try:
        if int(d.t) != mop_S:
            return None
        dest_stkoff = int(d.s.off)
    except (AttributeError, TypeError):
        return None

    if op == m_xdu:
        l = getattr(insn, "l", None)
        if l is None:
            return None
        try:
            if int(l.t) != mop_d:
                return None
        except (AttributeError, TypeError):
            return None
        sub = getattr(l, "d", None)
        if sub is None or _safe_int_attr(sub, "opcode") != m_and:
            return None
        mask = _extract_const_mask_from_binop(sub, mop_n=mop_n)
        if mask is None or mask not in _LOOP_BOUND_MASKS:
            return None
        return dest_stkoff

    if op == m_and:
        mask = _extract_const_mask_from_binop(insn, mop_n=mop_n)
        if mask is None or mask not in _LOOP_BOUND_MASKS:
            return None
        return dest_stkoff

    return None


def _operand_reads_stkoff(
    mop,
    target_stkoff: int,
    *,
    mop_S: int,
    mop_d: int,
    m_xdu: int,
) -> bool:
    """True iff ``mop`` reads stkoff ``target_stkoff`` -- either
    directly as ``mop_S`` or wrapped in ``m_xdu`` inside a ``mop_d``."""
    if mop is None:
        return False
    try:
        t = int(mop.t)
    except (AttributeError, TypeError):
        return False
    if t == mop_S:
        try:
            return int(mop.s.off) == int(target_stkoff)
        except (AttributeError, TypeError):
            return False
    if t == mop_d:
        sub = getattr(mop, "d", None)
        if sub is None or _safe_int_attr(sub, "opcode") != m_xdu:
            return False
        l = getattr(sub, "l", None)
        if l is None:
            return False
        try:
            if int(l.t) != mop_S:
                return False
            return int(l.s.off) == int(target_stkoff)
        except (AttributeError, TypeError):
            return False
    return False


def _extract_counter_advance(
    mop,
    *,
    mop_n: int,
    mop_S: int,
    mop_d: int,
    m_add: int,
) -> int | None:
    """If ``mop`` is ``m_add(stkvar, small_const)`` (in either order),
    return the stkoff of the counter; else ``None``."""
    if mop is None:
        return None
    try:
        if int(mop.t) != mop_d:
            return None
    except (AttributeError, TypeError):
        return None
    sub = getattr(mop, "d", None)
    if sub is None or _safe_int_attr(sub, "opcode") != m_add:
        return None
    l = getattr(sub, "l", None)
    r = getattr(sub, "r", None)
    if l is None or r is None:
        return None
    try:
        lt = int(l.t)
        rt = int(r.t)
    except (AttributeError, TypeError):
        return None
    counter_stkoff: int | None = None
    delta: int | None = None
    if lt == mop_S and rt == mop_n:
        try:
            counter_stkoff = int(l.s.off)
            delta = int(r.nnn.value) & 0xFFFFFFFFFFFFFFFF
        except (AttributeError, TypeError):
            return None
    elif lt == mop_n and rt == mop_S:
        try:
            counter_stkoff = int(r.s.off)
            delta = int(l.nnn.value) & 0xFFFFFFFFFFFFFFFF
        except (AttributeError, TypeError):
            return None
    if counter_stkoff is None or delta is None:
        return None
    if delta not in _COUNTER_ADVANCE_DELTAS:
        return None
    return counter_stkoff


def detect_loop_bound_writer_redirect(
    mba,
    source_block_serial: int,
) -> LoopBoundWriterDiagnostic | None:
    """Inspect ``mba`` and return a diagnostic iff the source block
    matches the loop-bound-writer pattern (all four conjunctive
    conditions hold).  Read-only; returns ``None`` on any failure.

    The four conditions are documented on
    :class:`LoopBoundWriterDiagnostic`.  The detector is intentionally
    narrow -- the guard exists to suppress one specific OLLVM-driven
    redirect that lets IDA's GLBOPT1 fold the inner-loop bound away.
    Anything broader risks regressing legitimate state-transition
    redirects.
    """
    if mba is None:
        return None
    try:
        import ida_hexrays
    except ImportError:
        return None

    m_xdu = getattr(ida_hexrays, "m_xdu", -1)
    m_and = getattr(ida_hexrays, "m_and", -1)
    m_jnz = getattr(ida_hexrays, "m_jnz", -1)
    m_jz = getattr(ida_hexrays, "m_jz", -1)
    m_add = getattr(ida_hexrays, "m_add", -1)
    mop_n = getattr(ida_hexrays, "mop_n", -1)
    mop_S = getattr(ida_hexrays, "mop_S", -1)
    mop_d = getattr(ida_hexrays, "mop_d", -1)

    qty = _safe_int_attr(mba, "qty", 0)
    if qty <= 0:
        return None

    try:
        source_blk = mba.get_mblock(int(source_block_serial))
    except Exception:
        return None
    if source_blk is None:
        return None

    # Conditions (1) + (2): exactly one constant-mask writer in the
    # source block and at most one such writer site for that stkvar
    # across the whole function.
    bound_stkoff: int | None = None
    bound_writer_ea: int | None = None
    for insn in _iter_block_insns(source_blk):
        candidate = _detect_constant_mask_writer(
            insn,
            m_xdu=m_xdu,
            m_and=m_and,
            mop_n=mop_n,
            mop_S=mop_S,
            mop_d=mop_d,
        )
        if candidate is None:
            continue
        if bound_stkoff is not None:
            return None  # multiple constant-mask writes in the source block
        bound_stkoff = candidate
        bound_writer_ea = _safe_int_attr(insn, "ea")
    if bound_stkoff is None or bound_writer_ea is None or bound_writer_ea < 0:
        return None

    # Verify uniqueness across the whole function: no other block writes B.
    src_serial_int = int(source_block_serial)
    for i in range(qty):
        if i == src_serial_int:
            continue
        try:
            blk = mba.get_mblock(i)
        except Exception:
            continue
        if blk is None:
            continue
        for ins in _iter_block_insns(blk):
            d = getattr(ins, "d", None)
            if d is None:
                continue
            try:
                if int(d.t) == mop_S and int(d.s.off) == bound_stkoff:
                    return None  # another writer to B exists
            except (AttributeError, TypeError):
                continue

    # Conditions (3) + (4): some block reads B via m_jnz/m_jz, with the
    # other operand having ``counter + small_const`` shape.
    for i in range(qty):
        try:
            blk = mba.get_mblock(i)
        except Exception:
            continue
        if blk is None:
            continue
        for ins in _iter_block_insns(blk):
            op = _safe_int_attr(ins, "opcode")
            if op != m_jnz and op != m_jz:
                continue
            a = getattr(ins, "l", None)
            b = getattr(ins, "r", None)
            if a is None or b is None:
                continue
            a_is_b = _operand_reads_stkoff(
                a, bound_stkoff, mop_S=mop_S, mop_d=mop_d, m_xdu=m_xdu,
            )
            b_is_b = _operand_reads_stkoff(
                b, bound_stkoff, mop_S=mop_S, mop_d=mop_d, m_xdu=m_xdu,
            )
            other = None
            if a_is_b and not b_is_b:
                other = b
            elif b_is_b and not a_is_b:
                other = a
            if other is None:
                continue
            counter_stkoff = _extract_counter_advance(
                other, mop_n=mop_n, mop_S=mop_S, mop_d=mop_d, m_add=m_add,
            )
            if counter_stkoff is None:
                continue
            loop_test_ea = _safe_int_attr(ins, "ea")
            if loop_test_ea < 0:
                continue
            return LoopBoundWriterDiagnostic(
                bound_stkoff=int(bound_stkoff),
                bound_writer_ea=int(bound_writer_ea),
                loop_test_ea=int(loop_test_ea),
                counter_stkoff=int(counter_stkoff),
            )

    return None


__all__ = [
    "detect_loop_bound_writer_redirect",
    "LoopBoundWriterDiagnostic",
]

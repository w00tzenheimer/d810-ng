"""Loop-carried induction guards (bound writer + counter writeback tail).

Two related detectors that protect inner loops on OLLVM-style flattened
functions from CFG rewrites that would orphan the loop's induction
chain:

* :func:`detect_loop_bound_writer_redirect` -- the *bound* writer.  When
  a mutation routes the unique ``m_xdu (X & K), %B`` writer through a
  fresh predecessor topology, IDA's MMAT_GLBOPT1 finalization
  forward-substitutes the writer into the loop test and erases the
  counter side, producing a non-progressing inner do-while.

* :func:`detect_loop_counter_writeback_tail` -- the *counter* writeback
  tail.  When a CFG redirect bypasses or orphans the block that commits
  the counter advance (``m_mov temp -> counter_stkvar`` where
  ``counter_stkvar`` participates in the loop test as
  ``counter + small_const``), IDA's DCE drops the writeback during
  finalization and the loop test never updates -- same observable
  symptom (non-progressing do-while), different root cause.

Both detectors are read-only and return ``None`` on any failure so the
surrounding code can keep its existing fast-path semantics.

This module also exposes :func:`collect_const_var_refs_in_block`, a
neutral helper that returns the set of ``%var_NNN`` *name tokens*
(matching the format used by ``ReturnCarrierFact.payload
['upstream_writer_var_refs']``) that the given block writes via the
canonical ``m_mov #const, %var_NNN`` shape.  It exists here because the
existing fakes/conventions for this file cover the same opcode/mop
surface.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from d810.cfg.flowgraph import InsnKind, OperandKind

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


def _insn_kind(insn: object) -> InsnKind:
    kind = getattr(insn, "kind", InsnKind.UNKNOWN)
    return kind if isinstance(kind, InsnKind) else InsnKind.UNKNOWN


def _operand_kind(mop: object | None) -> OperandKind:
    if mop is None:
        return OperandKind.EMPTY
    kind = getattr(mop, "kind", OperandKind.UNKNOWN)
    return kind if isinstance(kind, OperandKind) else OperandKind.UNKNOWN


def _operand_stkoff(mop: object | None) -> int | None:
    if _operand_kind(mop) != OperandKind.STACK:
        return None
    for attr_path in (("stkoff",), ("s", "off")):
        cur = mop
        try:
            for attr in attr_path:
                cur = getattr(cur, attr)
            return int(cur)
        except (AttributeError, TypeError, ValueError):
            continue
    return None


def _operand_const_value(mop: object | None) -> int | None:
    if _operand_kind(mop) != OperandKind.NUMBER:
        return None
    for attr_path in (("value",), ("nnn", "value")):
        cur = mop
        try:
            for attr in attr_path:
                cur = getattr(cur, attr)
            return int(cur) & 0xFFFFFFFFFFFFFFFF
        except (AttributeError, TypeError, ValueError):
            continue
    return None


def _iter_block_insns(blk):
    insn = getattr(blk, "head", None)
    while insn is not None:
        yield insn
        insn = getattr(insn, "next", None)


def _extract_const_mask_from_binop(sub_insn) -> int | None:
    """Return the constant operand of a 2-operand sub-instruction whose
    other operand is non-const, or ``None``."""
    l = getattr(sub_insn, "l", None)
    r = getattr(sub_insn, "r", None)
    if l is None or r is None:
        return None
    l_const = _operand_const_value(l)
    r_const = _operand_const_value(r)
    if r_const is not None and l_const is None:
        return r_const
    if l_const is not None and r_const is None:
        return l_const
    return None


def _detect_constant_mask_writer(insn) -> int | None:
    """If ``insn`` writes a stkvar with a constant-mask expression
    ``(X & K)`` where ``K`` is a recognized loop-bound mask, return the
    destination stkoff; else ``None``.

    Two shapes are accepted:

    * ``m_xdu(mop_d(m_and X K)), %B``  -- mask-and-extend.
    * ``m_and X K, %B``                -- direct mask write.
    """
    d = getattr(insn, "d", None)
    dest_stkoff = _operand_stkoff(d)
    if dest_stkoff is None:
        return None

    if _insn_kind(insn) == InsnKind.XDU:
        l = getattr(insn, "l", None)
        if _operand_kind(l) != OperandKind.SUBINSN:
            return None
        sub = getattr(l, "d", None)
        if sub is None or _insn_kind(sub) != InsnKind.AND:
            return None
        mask = _extract_const_mask_from_binop(sub)
        if mask is None or mask not in _LOOP_BOUND_MASKS:
            return None
        return dest_stkoff

    if _insn_kind(insn) == InsnKind.AND:
        mask = _extract_const_mask_from_binop(insn)
        if mask is None or mask not in _LOOP_BOUND_MASKS:
            return None
        return dest_stkoff

    return None


def _operand_reads_stkoff(
    mop,
    target_stkoff: int,
) -> bool:
    """True iff ``mop`` reads stkoff ``target_stkoff`` -- either
    directly as ``mop_S`` or wrapped in ``m_xdu`` inside a ``mop_d``."""
    if mop is None:
        return False
    if _operand_kind(mop) == OperandKind.STACK:
        return _operand_stkoff(mop) == int(target_stkoff)
    if _operand_kind(mop) == OperandKind.SUBINSN:
        sub = getattr(mop, "d", None)
        if sub is None or _insn_kind(sub) != InsnKind.XDU:
            return False
        l = getattr(sub, "l", None)
        return _operand_stkoff(l) == int(target_stkoff)
    return False


def _extract_counter_advance(mop) -> int | None:
    """If ``mop`` is ``m_add(stkvar, small_const)`` (in either order),
    return the stkoff of the counter; else ``None``."""
    if mop is None:
        return None
    if _operand_kind(mop) != OperandKind.SUBINSN:
        return None
    sub = getattr(mop, "d", None)
    if sub is None or _insn_kind(sub) != InsnKind.ADD:
        return None
    l = getattr(sub, "l", None)
    r = getattr(sub, "r", None)
    if l is None or r is None:
        return None
    counter_stkoff: int | None = None
    delta: int | None = None
    l_stkoff = _operand_stkoff(l)
    r_stkoff = _operand_stkoff(r)
    l_const = _operand_const_value(l)
    r_const = _operand_const_value(r)
    if l_stkoff is not None and r_const is not None:
        counter_stkoff = l_stkoff
        delta = r_const
    elif l_const is not None and r_stkoff is not None:
        counter_stkoff = r_stkoff
        delta = l_const
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
        candidate = _detect_constant_mask_writer(insn)
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
            if _operand_stkoff(d) == bound_stkoff:
                return None  # another writer to B exists

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
            if _insn_kind(ins) != InsnKind.EQUALITY_JUMP:
                continue
            a = getattr(ins, "l", None)
            b = getattr(ins, "r", None)
            if a is None or b is None:
                continue
            a_is_b = _operand_reads_stkoff(a, bound_stkoff)
            b_is_b = _operand_reads_stkoff(b, bound_stkoff)
            other = None
            if a_is_b and not b_is_b:
                other = b
            elif b_is_b and not a_is_b:
                other = a
            if other is None:
                continue
            counter_stkoff = _extract_counter_advance(other)
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


@dataclass(frozen=True, slots=True)
class LoopCounterWritebackDiagnostic:
    """Verdict from the loop-counter writeback-tail detector.

    Populated only when all four conjunctive conditions hold for the
    candidate tail block:

    1. The candidate block contains an ``m_mov src -> mop_S(K)`` where
       ``src`` is a temp/stkvar (not a constant) -- i.e. the writeback
       commits some loop-carried temp into stkoff ``K``.
    2. Some block in the function reads ``K`` via ``m_jnz`` / ``m_jz``
       with the *other* operand of the test having shape
       ``K + small_const`` (delta in :data:`_COUNTER_ADVANCE_DELTAS`)
       -- i.e. ``K`` is the counter consumed in a loop test.
    3. Some block in the function emits ``m_add mop_S(K), small_const ->
       <temp>`` -- the counter advance compute that feeds the writeback.
    4. The other operand of the loop test is a stkvar (the loop bound).

    When this diagnostic is non-None, any CFG redirect that bypasses or
    orphans the tail block will sever the loop-carried induction chain
    and IDA's MMAT_GLBOPT1 DCE will drop the writeback.  The guard
    rejects such redirects so the writeback survives.
    """

    tail_block_serial: int
    counter_stkoff: int
    bound_stkoff: int
    loop_test_ea: int
    advance_ea: int


def _operand_is_constant(mop) -> bool:
    return _operand_kind(mop) == OperandKind.NUMBER


def _operand_temp_or_stkvar_kind(mop) -> bool:
    return _operand_kind(mop) in {OperandKind.LVAR, OperandKind.STACK}


def _find_writeback_to_stkvar(blk) -> int | None:
    """If ``blk`` contains an ``m_mov src -> mop_S(K)`` whose ``src`` is
    a temp/stkvar (NOT a constant), return ``K``; else ``None``.

    The constant-source check distinguishes a counter writeback from a
    counter reset (``mov #0, %counter``) and from an unrelated stkvar
    initialisation.
    """
    for insn in _iter_block_insns(blk):
        if _insn_kind(insn) != InsnKind.MOV:
            continue
        d = getattr(insn, "d", None)
        l = getattr(insn, "l", None)
        dest_stkoff = _operand_stkoff(d)
        if dest_stkoff is None or l is None:
            continue
        if _operand_is_constant(l):
            continue
        if not _operand_temp_or_stkvar_kind(l):
            continue
        return int(dest_stkoff)
    return None


def _is_counter_advance_add(
    insn,
    counter_stkoff: int,
) -> bool:
    """True iff ``insn`` is ``m_add mop_S(counter_stkoff) + small_const``
    (in either operand order) where the constant delta is in
    :data:`_COUNTER_ADVANCE_DELTAS`."""
    l = getattr(insn, "l", None)
    r = getattr(insn, "r", None)
    if l is None or r is None:
        return False
    l_stkoff = _operand_stkoff(l)
    r_stkoff = _operand_stkoff(r)
    l_const = _operand_const_value(l)
    r_const = _operand_const_value(r)
    if l_stkoff == counter_stkoff and r_const is not None:
        return r_const in _COUNTER_ADVANCE_DELTAS
    if r_stkoff == counter_stkoff and l_const is not None:
        return l_const in _COUNTER_ADVANCE_DELTAS
    return False


def detect_loop_counter_writeback_tail(
    mba,
    tail_block_serial: int,
) -> LoopCounterWritebackDiagnostic | None:
    """Inspect ``mba`` and return a diagnostic iff ``tail_block_serial``
    is the writeback tail of a loop-carried counter (all four
    conjunctive conditions hold).  Read-only; returns ``None`` on any
    failure.

    The four conditions are documented on
    :class:`LoopCounterWritebackDiagnostic`.  The detector is
    intentionally narrow -- the guard exists to suppress one specific
    OLLVM-driven cascade that orphans the counter writeback block,
    causing IDA to DCE the unique counter advance commit and produce a
    non-progressing inner do-while.
    """
    if mba is None:
        return None

    qty = _safe_int_attr(mba, "qty", 0)
    if qty <= 0:
        return None

    try:
        tail_blk = mba.get_mblock(int(tail_block_serial))
    except Exception:
        return None
    if tail_blk is None:
        return None

    # Condition (1): tail block has an m_mov writeback to some stkoff K
    # whose source is a temp/stkvar (loop-carried), not a constant.
    counter_stkoff = _find_writeback_to_stkvar(tail_blk)
    if counter_stkoff is None:
        return None

    # Conditions (2) + (4): some block reads K via m_jnz/m_jz with the
    # other operand having ``K + small_const`` shape, and the test's
    # other operand is a stkvar (the loop bound).
    loop_test_ea: int | None = None
    bound_stkoff: int | None = None
    for i in range(qty):
        try:
            blk = mba.get_mblock(i)
        except Exception:
            continue
        if blk is None:
            continue
        for ins in _iter_block_insns(blk):
            if _insn_kind(ins) != InsnKind.EQUALITY_JUMP:
                continue
            a = getattr(ins, "l", None)
            b = getattr(ins, "r", None)
            if a is None or b is None:
                continue
            adv_a = _extract_counter_advance(a)
            adv_b = _extract_counter_advance(b)
            other = None
            if adv_a == counter_stkoff and adv_b != counter_stkoff:
                other = b
            elif adv_b == counter_stkoff and adv_a != counter_stkoff:
                other = a
            if other is None:
                continue
            bound_stkoff = _operand_stkoff(other)
            if bound_stkoff is None:
                continue
            ea = _safe_int_attr(ins, "ea")
            if ea < 0:
                continue
            loop_test_ea = ea
            break
        if loop_test_ea is not None:
            break
    if loop_test_ea is None or bound_stkoff is None:
        return None

    # Condition (3): some block emits m_add mop_S(counter_stkoff) +
    # small_const (the advance compute that feeds the writeback).
    advance_ea: int | None = None
    for i in range(qty):
        try:
            blk = mba.get_mblock(i)
        except Exception:
            continue
        if blk is None:
            continue
        for ins in _iter_block_insns(blk):
            if _insn_kind(ins) != InsnKind.ADD:
                continue
            if not _is_counter_advance_add(ins, counter_stkoff):
                continue
            ea = _safe_int_attr(ins, "ea")
            if ea < 0:
                continue
            advance_ea = ea
            break
        if advance_ea is not None:
            break
    if advance_ea is None:
        return None

    return LoopCounterWritebackDiagnostic(
        tail_block_serial=int(tail_block_serial),
        counter_stkoff=int(counter_stkoff),
        bound_stkoff=int(bound_stkoff),
        loop_test_ea=int(loop_test_ea),
        advance_ea=int(advance_ea),
    )


# Match ``%var_NNN`` references in microcode dstr text.  Mirrors the
# pattern used by ``ReturnCarrierFactCollector._extract_var_refs`` so
# the result of :func:`collect_const_var_refs_in_block` can be
# intersected directly with the
# ``ReturnCarrierFact.payload["upstream_writer_var_refs"]`` payload.
_VAR_REF_RE = re.compile(r"%var_([0-9A-Fa-f]+)")


def collect_const_var_refs_in_block(mba, block_serial: int) -> frozenset[str]:
    """Return the set of ``%var_NNN`` name tokens written via
    ``m_mov #const, %var_NNN`` in the given block.

    Names are parsed from the destination operand's ``dstr`` (the
    textual rendering used by the IDA microcode dump) rather than from
    raw ``mop_S.s.off``.  This matches the format stored in
    ``ReturnCarrierFact.payload["upstream_writer_var_refs"]``, so the
    two sets can be intersected without an additional translation step.

    The walk is read-only and returns an empty set on any failure
    (missing block, missing instructions, bad opcodes, parse errors).
    """
    if mba is None:
        return frozenset()
    try:
        serial = int(block_serial)
        qty = int(getattr(mba, "qty", 0))
    except (TypeError, ValueError):
        return frozenset()
    if serial < 0 or serial >= qty:
        return frozenset()
    try:
        blk = mba.get_mblock(serial)
    except Exception:
        return frozenset()
    if blk is None:
        return frozenset()

    found: set[str] = set()
    for insn in _iter_block_insns(blk):
        if _insn_kind(insn) != InsnKind.MOV:
            continue
        l = getattr(insn, "l", None)
        d = getattr(insn, "d", None)
        if l is None or d is None:
            continue
        if _operand_kind(l) != OperandKind.NUMBER or _operand_kind(d) != OperandKind.STACK:
            continue
        # Parse %var_NNN from the destination's dstr so the result
        # matches the ReturnCarrierFact upstream_writer_var_refs format.
        dstr_method = getattr(d, "dstr", None)
        text: str | None = None
        if callable(dstr_method):
            try:
                text = dstr_method()
            except Exception:
                text = None
        elif isinstance(dstr_method, str):
            text = dstr_method
        if not text:
            insn_dstr = getattr(insn, "dstr", None)
            if callable(insn_dstr):
                try:
                    text = insn_dstr()
                except Exception:
                    text = None
            elif isinstance(insn_dstr, str):
                text = insn_dstr
        if text:
            for match in _VAR_REF_RE.finditer(text):
                found.add(match.group(1).lower())
    return frozenset(found)


__all__ = [
    "collect_const_var_refs_in_block",
    "detect_loop_bound_writer_redirect",
    "detect_loop_counter_writeback_tail",
    "LoopBoundWriterDiagnostic",
    "LoopCounterWritebackDiagnostic",
]

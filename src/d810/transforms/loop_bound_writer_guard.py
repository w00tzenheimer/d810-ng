"""Loop-carried induction guard (counter writeback tail) + helpers.

Protects inner loops on OLLVM-style flattened functions from CFG
rewrites that would orphan the loop's induction chain:

* :func:`detect_loop_counter_writeback_tail` -- the *counter* writeback
  tail.  When a CFG redirect bypasses or orphans the block that commits
  the counter advance (``m_mov temp -> counter_stkvar`` where
  ``counter_stkvar`` participates in the loop test as
  ``counter + small_const``), IDA's DCE drops the writeback during
  finalization and the loop test never updates, producing a
  non-progressing inner do-while.

The detector is read-only and returns ``None`` on any failure so the
surrounding code can keep its existing fast-path semantics.  It consumes
a portable :class:`~d810.ir.flowgraph.FlowGraph` snapshot lifted once by
the caller (no live ``mba`` dependency).

This module also exposes :func:`collect_const_var_refs_in_block`, a
neutral helper that returns portable stack-storage identity keys
(``S<offset>``) written via the canonical ``m_mov #const, stack`` shape.
It exists here because the existing fakes/conventions for this file cover the
same opcode/mop surface.

:class:`LoopBoundWriterDiagnostic` is retained (exported, no producer in
this module) only because :mod:`d810.transforms.path_tail_modification_planning`
still types a decision field with it.

llr-0s2n -- canonical Instruction port.  The three structural helpers no
longer navigate raw ``InsnSnapshot``/``MopSnapshot`` operand slots
(``.l`` / ``.r`` / ``.d`` and their ``.s.off`` / ``.nnn.value`` children).
Each :class:`~d810.ir.flowgraph.InsnSnapshot` is projected through
``project_instruction`` to the canonical
:class:`~d810.ir.instructions.Instruction`, and operand identity is read off
``Instruction.inputs`` / ``Instruction.result`` (``Varnode`` storage
identity), ``Instruction.operation``, and the shallow per-slot
``Instruction.input_exprs`` projection.  The buried counter-advance operand
(a one-level ``SUBINSN`` wrapping ``m_add(stkvar, small_const)``) is matched
as the depth-1 ``input_exprs[slot]`` expression ``Add(Move(StackSlot),
Const)`` -- exactly the single nesting level the former ``mop -> mop.d ->
sub.l/sub.r`` walk inspected.  The deep ``operand_expr_fragments`` walk is
deliberately NOT used here: matching it would broaden detection past that one
level.  The accepted classifier parameters are retained for caller
compatibility; the canonical projection already carries the semantic kind, so
they are no longer consulted on the projected path.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from d810.ir.expressions import Add, Const, ExprRef, Move
from d810.ir.flowgraph import BlockSnapshot, InsnKind, InsnSnapshot, OperandKind
from d810.ir.instructions import Instruction
from d810.ir.insn_projection import project_instruction
from d810.ir.locations import StackSlot
from d810.ir.semantics import ValueOpKind
from d810.ir.value_refs import DefinitionRef
from d810.ir.varnode import Space, Varnode
from d810.analyses.value_flow.induction_carrier import (
    _canonical_operands,
    _const_value_from_varnode,
    _stkoff_from_varnode,
)

# Counter-advance deltas: ``counter + small_const`` where ``small_const``
# is an offset matching common index/byte/word/qword stride patterns.
_COUNTER_ADVANCE_DELTAS: frozenset[int] = frozenset({1, 2, 4, 8})

# Source storage spaces accepted as a loop-carried writeback source: a
# temp/lvar/stack value (NOT a constant).  Mirrors the former
# ``OperandKind in {LVAR, STACK}`` gate -- ``OperandKind.LVAR`` projects to
# ``Space.LVAR`` and ``OperandKind.STACK`` to ``Space.STACK``.
_WRITEBACK_SOURCE_SPACES: frozenset[Space] = frozenset({Space.LVAR, Space.STACK})


@dataclass(frozen=True, slots=True)
class LoopBoundWriterDiagnostic:
    """Verdict from the loop-bound-writer detector.

    Populated only when all four conjunctive conditions hold for the
    candidate's source block:

    1. The source block contains a unique writer to a stkvar ``B``.
    2. The writer expression is ``(X & K)`` (or ``m_xdu(X & K)``) with
       ``K`` a narrow loop-bound mask (``0x1F``/``0x3E``/``0x3F``/``0x7F``).
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


InsnKindClassifier = Callable[[object], InsnKind | None]
OperandKindClassifier = Callable[[object], OperandKind | None]


def _project(insn: object) -> Instruction | None:
    """Project a portable ``InsnSnapshot`` to a canonical ``Instruction``.

    Returns ``None`` for any block-instruction object that is not a portable
    ``InsnSnapshot`` (the canonical projection has no meaning for it).
    """
    if not isinstance(insn, InsnSnapshot):
        return None
    try:
        return project_instruction(insn)
    except Exception:
        return None


def _iter_block_instructions(blk):
    """Yield each block instruction projected to a canonical ``Instruction``."""
    if isinstance(blk, BlockSnapshot):
        snapshots = blk.iter_insns()
    else:
        snapshots = ()
        insn = getattr(blk, "head", None)
        chain = []
        while insn is not None:
            chain.append(insn)
            insn = getattr(insn, "next", None)
        snapshots = tuple(chain)
    for insn in snapshots:
        instruction = _project(insn)
        if instruction is not None:
            yield instruction


def _input_expr(instruction: Instruction, slot: int) -> ExprRef | None:
    exprs = instruction.input_exprs
    return exprs[slot] if slot < len(exprs) else None


def _snapshot_kind(instruction: Instruction) -> InsnKind:
    """Portable backend-neutral kind of the canonical ``Instruction``.

    The canonical ``operation`` enum collapses ``EQUALITY_JUMP`` (``m_jnz`` /
    ``m_jz``) and ``COND_JUMP`` (``m_jcnd``) into a single
    ``ControlTransferKind.CONDITIONAL_BRANCH``; the projection preserves the
    distinguishing ``InsnKind`` in provenance attrs, so the loop-test gate can
    stay ``EQUALITY_JUMP``-only as before."""
    raw = instruction.attrs.get("snapshot_kind")
    if raw is None:
        return InsnKind.UNKNOWN
    try:
        return InsnKind(raw)
    except ValueError:
        return InsnKind.UNKNOWN


def _move_stkoff(expr: ExprRef | None) -> int | None:
    """Stack-slot offset of a portable ``Move(StackSlot)`` leaf, else ``None``."""
    if not isinstance(expr, Move):
        return None
    source = expr.source
    if not isinstance(source, DefinitionRef):
        return None
    location = source.location
    return int(location.offset) if isinstance(location, StackSlot) else None


def _const_value(expr: ExprRef | None) -> int | None:
    """Numeric value of a portable ``Const`` leaf, else ``None``."""
    return int(expr.value) if isinstance(expr, Const) else None


def _extract_counter_advance(operand_expr: ExprRef | None) -> int | None:
    """If ``operand_expr`` is ``m_add(stkvar, small_const)`` (either order),
    return the stkoff of the counter; else ``None``.

    ``operand_expr`` is the depth-1 ``Instruction.input_exprs[slot]``
    projection of the top-level operand -- exactly the single nesting level
    the former ``mop -> mop.d -> sub.l/sub.r`` walk inspected (a ``SUBINSN``
    wrapping ``m_add`` whose two operands are leaf stack/const operands)."""
    if not isinstance(operand_expr, Add):
        return None
    left, right = operand_expr.left, operand_expr.right
    l_stkoff = _move_stkoff(left)
    r_stkoff = _move_stkoff(right)
    l_const = _const_value(left)
    r_const = _const_value(right)
    counter_stkoff: int | None = None
    delta: int | None = None
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


def _find_writeback_to_stkvar(blk) -> int | None:
    """If ``blk`` contains an ``m_mov src -> mop_S(K)`` whose ``src`` is
    a temp/stkvar (NOT a constant), return ``K``; else ``None``.

    The constant-source check distinguishes a counter writeback from a
    counter reset (``mov #0, %counter``) and from an unrelated stkvar
    initialisation.  Read off the canonical ``Instruction``: the dest is the
    ``result`` ``Varnode`` (a stack slot), the source is ``inputs[0]`` (a
    non-``CONST`` ``Varnode`` in stack/lvar storage).
    """
    for instruction in _iter_block_instructions(blk):
        if instruction.operation is not ValueOpKind.MOVE:
            continue
        dest, src, _ = _canonical_operands(instruction)
        dest_stkoff = _stkoff_from_varnode(dest)
        if dest_stkoff is None or not isinstance(src, Varnode):
            continue
        if src.space is Space.CONST:
            continue
        if src.space not in _WRITEBACK_SOURCE_SPACES:
            continue
        return int(dest_stkoff)
    return None


def _is_counter_advance_add(
    instruction: Instruction,
    counter_stkoff: int,
) -> bool:
    """True iff ``instruction`` is ``m_add mop_S(counter_stkoff) + small_const``
    (in either operand order) where the constant delta is in
    :data:`_COUNTER_ADVANCE_DELTAS`.

    Reads the two top-level source operands off ``Instruction.inputs`` --
    the canonical projection of the former ``insn.l`` / ``insn.r`` slots."""
    _, left, right = _canonical_operands(instruction)
    l_stkoff = _stkoff_from_varnode(left)
    r_stkoff = _stkoff_from_varnode(right)
    l_const = _const_value_from_varnode(left)
    r_const = _const_value_from_varnode(right)
    if l_stkoff == counter_stkoff and r_const is not None:
        return r_const in _COUNTER_ADVANCE_DELTAS
    if r_stkoff == counter_stkoff and l_const is not None:
        return l_const in _COUNTER_ADVANCE_DELTAS
    return False


def detect_loop_counter_writeback_tail(
    flow_graph,
    tail_block_serial: int,
    *,
    insn_kind_classifier: InsnKindClassifier | None = None,
    operand_kind_classifier: OperandKindClassifier | None = None,
) -> LoopCounterWritebackDiagnostic | None:
    """Inspect ``flow_graph`` and return a diagnostic iff
    ``tail_block_serial`` is the writeback tail of a loop-carried
    counter (all four conjunctive conditions hold).  Read-only; returns
    ``None`` on any failure.

    Consumes a portable :class:`~d810.ir.flowgraph.FlowGraph` snapshot
    (lifted once by the caller) rather than a live ``mba`` -- block
    lookup is ``flow_graph.get_block(serial)`` and the existence scans
    walk ``flow_graph.blocks`` in ascending-serial order (matching the
    former ``range(mba.qty)`` traversal).

    The four conditions are documented on
    :class:`LoopCounterWritebackDiagnostic`.  The detector is
    intentionally narrow -- the guard exists to suppress one specific
    OLLVM-driven cascade that orphans the counter writeback block,
    causing IDA to DCE the unique counter advance commit and produce a
    non-progressing inner do-while.

    ``insn_kind_classifier`` / ``operand_kind_classifier`` are accepted for
    caller compatibility; the canonical ``Instruction`` projection carries the
    semantic kind, so they are no longer consulted.
    """
    if flow_graph is None:
        return None

    try:
        tail_blk = flow_graph.get_block(int(tail_block_serial))
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
    for _serial in sorted(flow_graph.blocks):
        blk = flow_graph.blocks[_serial]
        for ins in _iter_block_instructions(blk):
            if _snapshot_kind(ins) is not InsnKind.EQUALITY_JUMP:
                continue
            # The loop test compares two top-level operands (slot 0 == ``l``,
            # slot 1 == ``r``).  ``input_exprs`` is the depth-1 per-slot
            # projection, so a SUBINSN-Add operand and a plain stkvar operand
            # stay aligned to their slot -- unlike ``inputs``, which flattens
            # nested SUBINSN children into additional positions.
            expr_a = _input_expr(ins, 0)
            expr_b = _input_expr(ins, 1)
            adv_a = _extract_counter_advance(expr_a)
            adv_b = _extract_counter_advance(expr_b)
            other_expr = None
            if adv_a == counter_stkoff and adv_b != counter_stkoff:
                other_expr = expr_b
            elif adv_b == counter_stkoff and adv_a != counter_stkoff:
                other_expr = expr_a
            if other_expr is None:
                continue
            bound_stkoff = _move_stkoff(other_expr)
            if bound_stkoff is None:
                continue
            ea = _safe_int_attr(_InstructionEa(ins), "ea")
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
    for _serial in sorted(flow_graph.blocks):
        blk = flow_graph.blocks[_serial]
        for ins in _iter_block_instructions(blk):
            if ins.operation is not ValueOpKind.ADD:
                continue
            if not _is_counter_advance_add(ins, counter_stkoff):
                continue
            ea = _safe_int_attr(_InstructionEa(ins), "ea")
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


class _InstructionEa:
    """Thin EA adapter so ``_safe_int_attr`` reads the canonical EA.

    The former code read ``ins.ea`` off the raw snapshot; the canonical
    ``Instruction`` carries its EA in provenance attrs.  This exposes it under
    the ``ea`` attribute name the existing ``_safe_int_attr`` helper expects,
    preserving the ``ea < 0`` reject path byte-for-byte.
    """

    __slots__ = ("ea",)

    def __init__(self, instruction: Instruction) -> None:
        raw = instruction.attrs.get("ea")
        self.ea = int(raw) if raw is not None else -1


def collect_const_var_refs_in_block(
    flow_graph,
    block_serial: int,
    *,
    insn_kind_classifier: InsnKindClassifier | None = None,
    operand_kind_classifier: OperandKindClassifier | None = None,
) -> frozenset[str]:
    """Return storage identity keys written via ``m_mov #const, stack``.

    The key format matches
    ``ReturnCarrierFact.payload["upstream_writer_source_storage_keys"]``.
    This helper reads the destination stack offset from the portable
    :class:`~d810.ir.flowgraph.FlowGraph` snapshot rather than parsing
    rendered ``%var`` names from ``dstr``.

    The walk is read-only and returns an empty set on any failure
    (missing graph, missing block, missing instructions, bad opcodes,
    parse errors).

    ``insn_kind_classifier`` / ``operand_kind_classifier`` are accepted for
    caller compatibility; the canonical ``Instruction`` projection carries the
    semantic kind, so they are no longer consulted.
    """
    if flow_graph is None:
        return frozenset()
    try:
        serial = int(block_serial)
    except (TypeError, ValueError):
        return frozenset()
    if serial < 0:
        return frozenset()
    try:
        blk = flow_graph.get_block(serial)
    except Exception:
        return frozenset()
    if blk is None:
        return frozenset()

    found: set[str] = set()
    for instruction in _iter_block_instructions(blk):
        if instruction.operation is not ValueOpKind.MOVE:
            continue
        dest, src, _ = _canonical_operands(instruction)
        if not isinstance(src, Varnode) or src.space is not Space.CONST:
            continue
        stkoff = _stkoff_from_varnode(dest)
        if stkoff is not None:
            found.add(f"S{int(stkoff)}".lower())
    return frozenset(found)


__all__ = [
    "collect_const_var_refs_in_block",
    "detect_loop_counter_writeback_tail",
    "LoopBoundWriterDiagnostic",
    "LoopCounterWritebackDiagnostic",
]

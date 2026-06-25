"""Folded loop-guard fact collector (ticket llr-pydd).

Hex-Rays folds the constant-trip-count loop guard of a counted accumulation
loop (``for (i = 0; i < N; i++) acc += f(i)``) to a constant ``je`` and DCEs
the body arm BEFORE the unflatten recovery maturity (MMAT_CALLS for the Tigress
INDIRECT profile).  The induction counter and the numeric bound ``N`` survive
only at the earlier MMAT_LOCOPT maturity (a dead ``(%counter - #N)`` compare
and the orphaned body-state write), so this collector observes them there and
records one ``FoldedLoopGuardFact`` per detected guard.

The fact carries everything the unflatten emitter needs to re-materialize the guard
as an explicit ``if (counter < N)`` 2-way branch at the later maturity (where
the live counter stack slot is stable but the comparison and the body arm are
gone):

* ``guard_ea``            -- start EA of the guard handler block.
* ``counter_stkoff/size`` -- the induction stack slot (cross-maturity stable).
* ``bound``               -- the numeric trip-count bound ``N``.
* ``signed``              -- compare signedness (``True`` => ``setl``).
* ``body_state``          -- state const the dropped (TRUE/body) arm wrote.
* ``exit_state``          -- state const the surviving (FALSE/exit) arm wrote.

Observability-only: the collector never modifies microcode and never feeds
planning except through the typed fact a consumer chooses to read.  The earlier
LOCOPT facts carry forward into the CALLS view via the lifecycle's
maturity-rank filter, so the unflatten CALLS run can read this LOCOPT fact directly.

llr-3b41 S11 -- canonical-only.  A collector-local iterator routes a meta-rich
:class:`~d810.ir.flowgraph.FlowGraph` block (the only shape a production fact
target ever is) through ``InstructionProjection.from_block``, and an offline
diag row carrying a parseable ``meta`` operand tree through the SAME canonical
:func:`~d810.ir.insn_projection.project_diag_instruction` projection.  Flat
operands (``dest_stkoff`` / ``src_*``) are read off the canonical record; the
nested operand SUBTREE (``src_l_mop`` / ``src_r_mop``) is taken from the SOURCE
``InsnSnapshot.l`` / ``.r`` (FlowGraph) or :func:`parse_diag_meta_operand`
(diag) ``MopSnapshot`` and walked through the canonical
:func:`~d810.ir.insn_projection.iter_operand_exprs` API.  The meta-less flat
fallback was removed (S11) -- it was unreachable by any real source once every
production fact target became a canonical ``FlowGraph``.

**EMBRACE gain (S6, the first port where it bites):** the nested-sub guard
detection (Shape 2 below) reads ``src_l_mop`` / ``src_r_mop``.  Pre-S6 those
fields were populated ONLY by the now-deleted legacy flat path, which was
``None`` on every real source -- so Shape 2 was effectively dead on FlowGraph
blocks AND operand-tree diag rows.  Routing meta-rich sources through the source
``MopSnapshot`` now lets a buried ``(counter - #N)`` guard inside an
``m_xdu`` / ``m_jge`` tree be detected on those sources for the first time -- a
strict improvement.  The FlowGraph path already exposed nested structure in the
canonical projection, so its flat-shape output stays byte-identical; only the
nested-sub recovery is newly reachable.  Meta-less rows stay byte-identical.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from d810.capabilities.source_lifter import select_lifter
from d810.core.typing import Any, Iterable
from d810.ir.expressions import Const, ExprRef, Move, Sub, ValueOpKind
from d810.ir.flowgraph import MopSnapshot
from d810.ir.instructions import Instruction
from d810.ir.insn_projection import (
    InstructionProjection,
    _diag_meta_payload,
    iter_operand_exprs,
    parse_diag_meta_operand,
    project_diag_instruction,
)
from d810.ir.locations import RegisterLocation, StackSlot
from d810.ir.maturity import LOCAL_FACT_COLLECTION_IR_MATURITIES
from d810.ir.semantics import PredicateKind
from d810.ir.value_refs import DefinitionRef
from d810.analyses.fact_collection_context import (
    FactCollectionContext,
    coerce_fact_collection_context,
    fact_provider_label,
)
from d810.analyses.value_flow.induction_carrier import (
    _canonical_opcode_name,
    _canonical_operands,
    _classify_induction_update,
    _const_value_from_varnode,
    _operation_of_view,
    _reg_from_varnode,
    _size_from_varnode,
    _stkoff_from_varnode,
    _value_op_from_instruction,
)
from d810.analyses.value_flow.state_write_anchor import (
    _block_start_ea_lookup,
    _block_succs,
    _is_state_const_write,
)
from d810.analyses.value_flow.model import FactObservation


# LOCOPT is the load-bearing maturity (the guard is folded by CALLS), but
# observing at every state-machine maturity is harmless: later maturities
# simply find no folded guard once the loop is gone.
_TARGET_MATURITIES = LOCAL_FACT_COLLECTION_IR_MATURITIES

_SIGNED_GUARD_PREDICATES = frozenset(
    {
        PredicateKind.SLT,
        PredicateKind.SLE,
        PredicateKind.SGT,
        PredicateKind.SGE,
    }
)
_UNSIGNED_GUARD_PREDICATES = frozenset(
    {
        PredicateKind.ULT,
        PredicateKind.ULE,
        PredicateKind.UGT,
        PredicateKind.UGE,
    }
)
_BURIED_SUB_HOST_OPERATIONS = frozenset({ValueOpKind.ZEXT, ValueOpKind.SEXT})


def _predicate_kind_of(instruction: Instruction) -> PredicateKind | None:
    """Return the compare predicate of a canonical ``Instruction``.

    A bare set* materialization (``setl`` etc.) carries its ``PredicateKind`` as
    ``Instruction.operation`` (no control transfer); a conditional branch
    carries it in ``Instruction.control.predicate``.  This reads whichever is
    present.
    """
    operation = instruction.operation
    if isinstance(operation, PredicateKind):
        return operation
    control = instruction.control
    return control.predicate if control is not None else None


@dataclass(frozen=True)
class _FoldedGuardInsn:
    """Uniform semantic view consumed by folded_loop_guard's classifiers.

    Built from a canonical :class:`~d810.ir.instructions.Instruction` (plus its
    source operand ``MopSnapshot`` subtrees).  Exposes ONLY the
    fields folded_loop_guard reads:

    * flat operands -- ``dest_stkoff`` / ``dest_size`` / ``dest_reg`` /
      ``src_l_stkoff`` / ``src_l_reg`` / ``src_l_value`` / ``src_r_stkoff`` /
      ``src_r_reg`` / ``src_r_value`` -- for the induction-var enumeration, the
      flat top-level guard (Shape 1) and the state-const-write recovery;
    * semantics -- ``operation`` / ``opcode_name`` / ``predicate_kind``;
    * nested operand subtrees -- ``src_l_mop`` / ``src_r_mop`` -- for the buried
      ``(counter - #N)`` guard (Shape 2);
    * identity/evidence -- ``block_serial`` / ``insn_index`` / ``ea`` / ``dstr``.

    The shared classifier helpers (``_classify_induction_update`` /
    ``_operation_of_view`` / ``_is_state_const_write``) duck-type over this
    record's attribute names unchanged.
    """

    block_serial: int
    insn_index: int
    ea: int | None
    opcode_name: str
    dstr: str
    operation: ValueOpKind | None
    predicate_kind: PredicateKind | None
    dest_stkoff: int | None
    dest_size: int | None
    dest_reg: int | None
    src_l_stkoff: int | None
    src_l_reg: int | None
    src_l_value: int | None
    src_r_stkoff: int | None
    src_r_reg: int | None
    src_r_value: int | None
    src_l_mop: MopSnapshot | None
    src_r_mop: MopSnapshot | None

    @classmethod
    def from_canonical(
        cls,
        *,
        block_serial: int,
        index: int,
        instruction: Instruction,
        src_l_mop: MopSnapshot | None,
        src_r_mop: MopSnapshot | None,
    ) -> "_FoldedGuardInsn":
        dest, left, right = _canonical_operands(instruction)
        attrs = instruction.attrs
        ea_raw = attrs.get("ea")
        return cls(
            block_serial=int(block_serial),
            insn_index=int(index),
            ea=int(ea_raw) if ea_raw is not None else None,
            opcode_name=_canonical_opcode_name(instruction),
            dstr=str(attrs.get("display_text") or ""),
            operation=_value_op_from_instruction(instruction),
            predicate_kind=_predicate_kind_of(instruction),
            dest_stkoff=_stkoff_from_varnode(dest),
            dest_size=_size_from_varnode(dest),
            dest_reg=_reg_from_varnode(dest),
            src_l_stkoff=_stkoff_from_varnode(left),
            src_l_reg=_reg_from_varnode(left),
            src_l_value=_const_value_from_varnode(left),
            src_r_stkoff=_stkoff_from_varnode(right),
            src_r_reg=_reg_from_varnode(right),
            src_r_value=_const_value_from_varnode(right),
            src_l_mop=src_l_mop,
            src_r_mop=src_r_mop,
        )


def _iter_folded_guard_insns(target: Any) -> Iterable[_FoldedGuardInsn]:
    """Yield folded_loop_guard's semantic record for every instruction.

    Canonical-only (llr-3b41 S11): a meta-rich FlowGraph block is projected via
    ``InstructionProjection.from_block`` (with the source operand
    ``MopSnapshot`` subtrees attached for the nested-sub walker); an offline
    diag row carrying a ``meta`` operand tree is lifted via
    ``project_diag_instruction`` (with the ``l`` / ``r`` operand subtrees parsed
    from ``meta``).  The meta-less flat fallback was removed -- it was
    unreachable by any real source once every production fact target became a
    canonical ``FlowGraph``.  A registered live
    :class:`~d810.capabilities.source_lifter.SourceLifter` lifts a backend
    source to a portable flow graph first.
    """
    lifter = select_lifter(target)
    if lifter is not None:
        target = lifter.lift(target)

    blocks = getattr(target, "blocks", target)
    block_iter = blocks.values() if isinstance(blocks, Mapping) else blocks

    for blk in block_iter:
        block_serial = int(getattr(blk, "serial"))
        insn_snapshots = getattr(blk, "insn_snapshots", None)
        if insn_snapshots is not None:
            instructions = InstructionProjection.from_block(blk)
            for index, instruction in enumerate(instructions):
                source = (
                    insn_snapshots[index]
                    if index < len(insn_snapshots)
                    else None
                )
                yield _FoldedGuardInsn.from_canonical(
                    block_serial=block_serial,
                    index=index,
                    instruction=instruction,
                    src_l_mop=getattr(source, "l", None),
                    src_r_mop=getattr(source, "r", None),
                )
            continue
        for index, insn in enumerate(getattr(blk, "instructions", ())):
            meta = _diag_meta_payload(insn)
            yield _FoldedGuardInsn.from_canonical(
                block_serial=block_serial,
                index=int(getattr(insn, "index", index)),
                instruction=project_diag_instruction(insn),
                src_l_mop=parse_diag_meta_operand(meta.get("l")),
                src_r_mop=parse_diag_meta_operand(meta.get("r")),
            )


def _block_preds(target: Any, block_serial: int) -> tuple[int, ...]:
    blocks = getattr(target, "blocks", target)
    block_iter = blocks.values() if isinstance(blocks, Mapping) else blocks
    for blk in block_iter:
        try:
            if int(getattr(blk, "serial")) == int(block_serial):
                raw = getattr(blk, "preds", ()) or ()
                return tuple(int(p) for p in raw)
        except (TypeError, ValueError):
            continue
    return ()


@dataclass(frozen=True, slots=True)
class _InductionVar:
    """An induction counter bound by microcode-operand identity.

    Exactly one of ``stkoff`` / ``reg`` is set: ``stkoff`` for a stack-slot
    counter, ``reg`` for a register-resident counter.  ``size`` is the operand
    width in bytes.
    """

    size: int
    stkoff: int | None = None
    reg: int | None = None

    @property
    def is_reg(self) -> bool:
        return self.reg is not None

    def matches_operand(
        self, *, stkoff: int | None, reg: int | None
    ) -> bool:
        """True iff the given operand identity is this induction var."""
        if self.stkoff is not None:
            return stkoff is not None and int(stkoff) == int(self.stkoff)
        if self.reg is not None:
            return reg is not None and int(reg) == int(self.reg)
        return False


def _induction_vars(
    instructions: tuple[_FoldedGuardInsn, ...],
) -> tuple[_InductionVar, ...]:
    """Collect every ``+1``/``-1`` self-update as a stack- or register-keyed
    induction var (one entry per distinct counter identity)."""
    by_stkoff: dict[int, _InductionVar] = {}
    by_reg: dict[int, _InductionVar] = {}
    for insn in instructions:
        update = _classify_induction_update(insn)
        if update is None:
            continue
        if abs(int(update.step)) != 1:
            continue
        if insn.dest_stkoff is not None:
            stkoff = int(insn.dest_stkoff)
            size = int(insn.dest_size or 4)
            by_stkoff.setdefault(stkoff, _InductionVar(size=size, stkoff=stkoff))
        elif insn.dest_reg is not None:
            reg = int(insn.dest_reg)
            size = int(insn.dest_size or 4)
            by_reg.setdefault(reg, _InductionVar(size=size, reg=reg))
    return tuple(by_stkoff.values()) + tuple(by_reg.values())


def _state_const(insn: _FoldedGuardInsn, canonical_stkoff: int | None) -> int | None:
    if not _is_state_const_write(insn):
        return None
    if canonical_stkoff is not None and int(insn.dest_stkoff or -1) != canonical_stkoff:
        return None
    return int(insn.src_l_value or 0) & 0xFFFFFFFF


def _canonical_state_stkoff(
    instructions: tuple[_FoldedGuardInsn, ...],
) -> int | None:
    from collections import Counter

    counter: Counter[int] = Counter()
    for insn in instructions:
        if _is_state_const_write(insn) and insn.dest_stkoff is not None:
            counter[int(insn.dest_stkoff)] += 1
    if not counter:
        return None
    top, n = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[0]
    return int(top) if n >= 2 else None


class FoldedLoopGuardFactCollector:
    """Observe folded counted-loop guards before their body arm is DCE'd."""

    name = "FoldedLoopGuardFactCollector"
    fact_kinds = frozenset({"FoldedLoopGuardFact"})
    maturities = _TARGET_MATURITIES

    def collect(
        self,
        target: Any,
        *,
        context: FactCollectionContext | None = None,
        func_ea: int | None = None,
        phase: str = "pre_d810",
        **legacy_fields: Any,
    ) -> tuple[FactObservation, ...]:
        context = coerce_fact_collection_context(
            context,
            func_ea=func_ea,
            phase=phase,
            legacy_fields=legacy_fields,
        )
        phase = context.phase
        maturity_text = fact_provider_label(context)
        instructions = tuple(_iter_folded_guard_insns(target))
        if not instructions:
            return ()

        induction = _induction_vars(instructions)
        if not induction:
            return ()
        canonical_stkoff = _canonical_state_stkoff(instructions)
        if canonical_stkoff is None:
            return ()

        by_block: dict[int, list[_FoldedGuardInsn]] = {}
        for insn in instructions:
            by_block.setdefault(int(insn.block_serial), []).append(insn)
        for items in by_block.values():
            items.sort(key=lambda i: int(i.insn_index))

        block_start_ea = _block_start_ea_lookup(target)

        observations: list[FactObservation] = []
        for guard_serial, block_insns in by_block.items():
            counter = self._guard_counter(block_insns, induction)
            if counter is None:
                continue
            counter_var, bound, signed = counter
            arms = self._guard_arms(
                target, guard_serial, by_block, canonical_stkoff
            )
            if arms is None:
                continue
            body_state, exit_state = arms
            guard_ea = block_start_ea.get(int(guard_serial))
            if guard_ea is None:
                continue

            counter_id = (
                f"reg=0x{counter_var.reg:x}"
                if counter_var.is_reg
                else f"stkoff=0x{counter_var.stkoff:x}"
            )
            semantic_key = (
                f"folded_loop_guard:guard_ea=0x{int(guard_ea):x}:"
                f"counter_{counter_id}:bound=0x{bound:x}"
            )
            payload: dict[str, Any] = {
                "guard_block_serial": int(guard_serial),
                "guard_ea": int(guard_ea),
                "guard_ea_hex": f"0x{int(guard_ea) & 0xFFFFFFFFFFFFFFFF:016x}",
                "counter_stkoff": (
                    int(counter_var.stkoff)
                    if counter_var.stkoff is not None
                    else None
                ),
                "counter_stkoff_hex": (
                    f"0x{counter_var.stkoff:x}"
                    if counter_var.stkoff is not None
                    else None
                ),
                "counter_reg": (
                    int(counter_var.reg) if counter_var.reg is not None else None
                ),
                "counter_reg_hex": (
                    f"0x{counter_var.reg:x}"
                    if counter_var.reg is not None
                    else None
                ),
                "counter_size": int(counter_var.size),
                "bound": int(bound),
                "bound_hex": f"0x{int(bound):x}",
                "signed": bool(signed),
                "body_state": int(body_state),
                "body_state_hex": f"0x{int(body_state):08x}",
                "exit_state": int(exit_state),
                "exit_state_hex": f"0x{int(exit_state):08x}",
            }
            observations.append(
                FactObservation(
                    fact_id=semantic_key,
                    kind="FoldedLoopGuardFact",
                    semantic_key=semantic_key,
                    maturity=maturity_text,
                    phase=phase,
                    confidence=0.8,
                    source_block=int(guard_serial),
                    source_ea=int(guard_ea),
                    block_fingerprint=f"folded_guard:blk[{int(guard_serial)}]",
                    mop_signature=(
                        f"folded_loop_guard:counter@{counter_id}"
                        f"<0x{int(bound):x}->body=0x{int(body_state):08x}/"
                        f"exit=0x{int(exit_state):08x}"
                    ),
                    payload=payload,
                    evidence=tuple(
                        i.dstr for i in block_insns if i.dstr
                    )[:4],
                )
            )
        return tuple(observations)

    @staticmethod
    def _guard_counter(
        block_insns: list[_FoldedGuardInsn],
        induction: tuple[_InductionVar, ...],
    ) -> tuple[_InductionVar, int, bool] | None:
        """Return ``(counter, bound, signed)`` for a folded induction compare.

        Detection is portable-IR based and works at any nesting depth.  Two
        shapes are recognised:

        1. Flat top-level compare/subtract where one operand identity matches a
           known induction var (stack slot or register) and the other operand
           is a constant.  Compare signedness comes from ``PredicateKind``; the
           sign-bit subtract form is represented by ``ValueOpKind.SUB`` and
           defaults to signed.

        2. Nested ``(induction-var - #N)`` subtract buried inside a portable
           extend operation or compare predicate tree.  The collector consumes
           projected ``ExprRef`` fragments to find a binary ``Sub`` node whose
           one child leaf is a known induction var and the other is a constant.
        """
        # Shape 1: flat top-level operand match (non-nested case).
        for insn in block_insns:
            signed = FoldedLoopGuardFactCollector._flat_guard_signedness(insn)
            if signed is None:
                continue
            match = FoldedLoopGuardFactCollector._match_counter_bound(
                insn, induction
            )
            if match is None:
                continue
            counter, bound = match
            return counter, bound, signed

        # Shape 2: nested ``(induction-var - #N)`` buried in an operand tree.
        for insn in block_insns:
            signed = FoldedLoopGuardFactCollector._nested_sub_signedness(insn)
            if signed is None:
                continue
            match = FoldedLoopGuardFactCollector._match_buried_sub(
                insn, induction
            )
            if match is None:
                continue
            counter, bound = match
            return counter, bound, signed
        return None

    @staticmethod
    def _flat_guard_signedness(insn: _FoldedGuardInsn) -> bool | None:
        """Return compare signedness for a semantic flat guard candidate."""
        predicate = insn.predicate_kind
        if predicate in _UNSIGNED_GUARD_PREDICATES:
            return False
        if predicate in _SIGNED_GUARD_PREDICATES:
            return True
        if _operation_of_view(insn) is ValueOpKind.SUB:
            return True
        return None

    @staticmethod
    def _nested_sub_signedness(insn: _FoldedGuardInsn) -> bool | None:
        """Return compare signedness for a semantic buried-subtract host."""
        predicate = insn.predicate_kind
        if predicate in _UNSIGNED_GUARD_PREDICATES:
            return False
        if predicate in _SIGNED_GUARD_PREDICATES:
            return True
        if _operation_of_view(insn) in _BURIED_SUB_HOST_OPERATIONS:
            return True
        return None

    @staticmethod
    def _match_buried_sub(
        insn: _FoldedGuardInsn,
        induction: tuple[_InductionVar, ...],
    ) -> tuple[_InductionVar, int] | None:
        """Walk the operand subtree of ``insn`` for a buried ``(counter - #N)``.

        The structured operand snapshots are projected into ``ExprRef``
        fragments by the IR layer.  Unsupported vendor wrappers remain
        provenance-only there, but supported child expressions below them still
        reach this analysis as portable expression nodes.
        """
        for root in (insn.src_l_mop, insn.src_r_mop):
            for expr in iter_operand_exprs(root):
                match = FoldedLoopGuardFactCollector._match_sub_expr(
                    expr, induction
                )
                if match is not None:
                    return match
        return None

    @staticmethod
    def _match_sub_expr(
        expr: ExprRef,
        induction: tuple[_InductionVar, ...],
    ) -> tuple[_InductionVar, int] | None:
        """Match an ``ExprRef`` subtract as ``(counter - #N)``."""
        if not isinstance(expr, Sub):
            return None
        return FoldedLoopGuardFactCollector._pair_counter_const_expr(
            expr.left, expr.right, induction
        )

    @staticmethod
    def _expr_identity(expr: ExprRef) -> tuple[int | None, int | None]:
        """Return ``(stkoff, reg)`` identity for a portable expression leaf."""
        if not isinstance(expr, Move):
            return None, None
        source = expr.source
        if not isinstance(source, DefinitionRef):
            return None, None
        location = source.location
        if isinstance(location, StackSlot):
            return int(location.offset), None
        if isinstance(location, RegisterLocation):
            return None, int(location.register_id)
        return None, None

    @staticmethod
    def _expr_const(expr: ExprRef) -> int | None:
        """Return the numeric value of a portable constant leaf, else None."""
        return int(expr.value) if isinstance(expr, Const) else None

    @staticmethod
    def _pair_counter_const_expr(
        left: ExprRef,
        right: ExprRef,
        induction: tuple[_InductionVar, ...],
    ) -> tuple[_InductionVar, int] | None:
        """Match a ``Sub`` node's children as ``(induction-var, const)``.

        For an ``(i - N)`` sign-bit guard the induction var is the minuend
        (left) and the bound is the subtrahend (right); the swapped order is
        also accepted defensively.  Returns ``(counter, bound)`` with a
        positive bound, else ``None``.
        """
        left_stk, left_reg = FoldedLoopGuardFactCollector._expr_identity(left)
        right_stk, right_reg = FoldedLoopGuardFactCollector._expr_identity(right)
        left_const = FoldedLoopGuardFactCollector._expr_const(left)
        right_const = FoldedLoopGuardFactCollector._expr_const(right)
        for var in induction:
            if var.matches_operand(stkoff=left_stk, reg=left_reg) and right_const:
                if right_const > 0:
                    return var, int(right_const)
            if var.matches_operand(stkoff=right_stk, reg=right_reg) and left_const:
                if left_const > 0:
                    return var, int(left_const)
        return None

    @staticmethod
    def _match_counter_bound(
        insn: _FoldedGuardInsn,
        induction: tuple[_InductionVar, ...],
    ) -> tuple[_InductionVar, int] | None:
        """Match ``(induction-var, const)`` in either operand order.

        Returns ``(counter, bound)`` when one operand is a known induction var
        and the other is a positive numeric constant; else ``None``.
        """
        left_const = insn.src_l_value
        right_const = insn.src_r_value
        for var in induction:
            # induction var on the LEFT, constant on the RIGHT
            if (
                var.matches_operand(stkoff=insn.src_l_stkoff, reg=insn.src_l_reg)
                and right_const is not None
            ):
                bound = int(right_const)
                if bound > 0:
                    return var, bound
            # induction var on the RIGHT, constant on the LEFT (swapped order)
            if (
                var.matches_operand(stkoff=insn.src_r_stkoff, reg=insn.src_r_reg)
                and left_const is not None
            ):
                bound = int(left_const)
                if bound > 0:
                    return var, bound
        return None

    @staticmethod
    def _guard_arms(
        target: Any,
        guard_serial: int,
        by_block: dict[int, list[_FoldedGuardInsn]],
        canonical_stkoff: int,
    ) -> tuple[int, int] | None:
        """Recover ``(body_state, exit_state)`` for the folded guard.

        The surviving (FALSE/exit) arm is the guard's live successor that writes
        a state const.  The dropped (TRUE/body) arm is an orphaned sibling block
        (no preds) whose state-write converges to the SAME join the exit arm
        reaches.  This survives at LOCOPT because the body arm is orphaned, not
        yet swept.
        """
        exit_arm = FoldedLoopGuardFactCollector._arm_state_block(
            target, guard_serial, by_block, canonical_stkoff
        )
        if exit_arm is None:
            return None
        exit_block, exit_state = exit_arm
        join_candidates = set(_block_succs(target, exit_block))
        for serial, block_insns in by_block.items():
            if serial in (guard_serial, exit_block):
                continue
            if _block_preds(target, serial):
                continue  # not orphaned
            body_state = next(
                (
                    s
                    for s in (
                        _state_const(i, canonical_stkoff) for i in block_insns
                    )
                    if s is not None
                ),
                None,
            )
            if body_state is None or body_state == exit_state:
                continue
            if not (set(_block_succs(target, serial)) & join_candidates):
                continue
            return int(body_state), int(exit_state)
        return None

    @staticmethod
    def _arm_state_block(
        target: Any,
        guard_serial: int,
        by_block: dict[int, list[_FoldedGuardInsn]],
        canonical_stkoff: int,
    ) -> tuple[int, int] | None:
        """Return the guard's live successor that writes a state const."""
        for succ in _block_succs(target, guard_serial):
            block_insns = by_block.get(int(succ), [])
            state = next(
                (
                    s
                    for s in (
                        _state_const(i, canonical_stkoff) for i in block_insns
                    )
                    if s is not None
                ),
                None,
            )
            if state is not None:
                return int(succ), int(state)
        return None


__all__ = ["FoldedLoopGuardFactCollector"]

"""Folded loop-guard fact collector (ticket llr-pydd).

Hex-Rays folds the constant-trip-count loop guard of a counted accumulation
loop (``for (i = 0; i < N; i++) acc += f(i)``) to a constant ``je`` and DCEs
the body arm BEFORE the §1a recovery maturity (MMAT_CALLS for the Tigress
INDIRECT profile).  The induction counter and the numeric bound ``N`` survive
only at the earlier MMAT_LOCOPT maturity (a dead ``(%counter - #N)`` compare
and the orphaned body-state write), so this collector observes them there and
records one ``FoldedLoopGuardFact`` per detected guard.

The fact carries everything the §1a emitter needs to re-materialize the guard
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
maturity-rank filter, so the §1a CALLS run can read this LOCOPT fact directly.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from d810.core.typing import Any
from d810.ir.flowgraph import InsnKind, OperandKind
from d810.analyses.value_flow.induction_carrier import (
    _MATURITY_VALUES,
    _InstructionView,
    _classify_induction_update,
    _iter_instruction_views,
    _maturity_name,
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
_TARGET_MATURITIES = frozenset({
    _MATURITY_VALUES["MMAT_PREOPTIMIZED"],
    _MATURITY_VALUES["MMAT_LOCOPT"],
})

# Opcode names that hold a ``counter <cmp> bound`` predicate over a structured
# (induction-var, const) operand pair.  Both the diag ``m_*`` names and the
# portable ``InsnKind.value`` lowercase aliases are accepted so the operand
# match works on either fact-target path.
#
# ``m_sub`` is the sign-bit form: a folded ``i < N`` guard materializes the
# predicate as ``(i - N) < 0`` (a dead subtract whose result feeds a sign test),
# so matching ``m_sub`` over (induction-var, const) covers the Tigress shape.
# A direct ``m_setl``/``m_jl`` over (counter, #N) is the same operand match.
_SUB_GUARD_OPCODES = frozenset({"m_sub", "sub", "op_13"})

# Signed less/greater comparison families => render ``setl``.
_SIGNED_CMP_OPCODES = frozenset({
    "m_setl", "m_setle", "m_setg", "m_setge",
    "m_jl", "m_jle", "m_jg", "m_jge",
})
# Unsigned below/above comparison families => render ``setb``.
_UNSIGNED_CMP_OPCODES = frozenset({
    "m_setb", "m_setbe", "m_seta", "m_setae",
    "m_jb", "m_jbe", "m_ja", "m_jae",
})

# All compare/set/jump opcodes whose (counter, const) operand pair anchors a
# folded guard, plus the sign-bit subtract form.
_GUARD_CMP_OPCODES = _SIGNED_CMP_OPCODES | _UNSIGNED_CMP_OPCODES | _SUB_GUARD_OPCODES

# Widen/extend and compare opcodes that, in a FOLDED ``i < N`` guard, do NOT
# carry the ``(counter - bound)`` pair as a flat top-level operand: the
# subtract is a sub-node BURIED inside an ``m_xdu`` widen or an ``m_jge``
# sign-bit predicate tree (the real Tigress LOCOPT shape, e.g.
# ``xdu (%var - #0x64)`` / ``jge ((bnot(%var - #0x64) | ...) & ...), #0``).
# These anchor the OPERAND-TREE walk in ``_guard_counter``; the buried SUB
# child is the signed ``(i - N) < 0`` idiom regardless of the host opcode.
_TREE_HOST_OPCODES = frozenset({
    "m_xdu", "xdu", "op_9",
    "m_xds", "xds",
    "m_jge", "m_jg", "m_jle", "m_jl",
    "m_jae", "m_ja", "m_jbe", "m_jb",
    "m_setl", "m_setle", "m_setg", "m_setge",
    "m_setb", "m_setbe", "m_seta", "m_setae",
})

# Opcodes whose buried-subtract sign-bit form renders as an UNSIGNED compare.
_UNSIGNED_TREE_HOST_OPCODES = frozenset({
    "m_jae", "m_ja", "m_jbe", "m_jb",
    "m_setb", "m_setbe", "m_seta", "m_setae",
})


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
    instructions: tuple[_InstructionView, ...],
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


def _state_const(insn: _InstructionView, canonical_stkoff: int | None) -> int | None:
    if not _is_state_const_write(insn):
        return None
    if canonical_stkoff is not None and int(insn.dest_stkoff or -1) != canonical_stkoff:
        return None
    return int(insn.src_l_value or 0) & 0xFFFFFFFF


def _canonical_state_stkoff(
    instructions: tuple[_InstructionView, ...],
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
        func_ea: int,
        maturity: int,
        phase: str,
    ) -> tuple[FactObservation, ...]:
        maturity_text = _maturity_name(maturity)
        instructions = tuple(_iter_instruction_views(target))
        if not instructions:
            return ()

        induction = _induction_vars(instructions)
        if not induction:
            return ()
        canonical_stkoff = _canonical_state_stkoff(instructions)
        if canonical_stkoff is None:
            return ()

        by_block: dict[int, list[_InstructionView]] = {}
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
        block_insns: list[_InstructionView],
        induction: tuple[_InductionVar, ...],
    ) -> tuple[_InductionVar, int, bool] | None:
        """Return ``(counter, bound, signed)`` for a folded induction compare.

        Detection is microcode-OPERAND based, not text based, and works at
        ANY nesting depth.  Two shapes are recognised:

        1. FLAT top-level compare/subtract (``_GUARD_CMP_OPCODES``) where ONE
           operand identity matches a known induction var (stack slot OR
           register) and the OTHER operand is a constant; both operand orders
           handled.  ``signed`` from the opcode.

        2. NESTED ``(induction-var - #N)`` subtract buried inside an
           ``m_xdu`` widen or an ``m_jge`` / ``m_setl`` sign-bit predicate
           tree (``_TREE_HOST_OPCODES``).  The real Tigress LOCOPT shape:
           ``xdu (%var_1E0 - #0x64)`` / ``jge ((bnot(%var_1D0 - #0x64) | ...)
           & ...), #0``.  The collector walks the structured operand SUBTREE
           (``MopSnapshot.sub_kind`` / ``sub_l`` / ``sub_r``) to find a binary
           ``SUB`` node whose one child leaf is a known induction var and the
           other is a constant.  This is the signed ``(i - N) < 0`` idiom.
        """
        # Shape 1: flat top-level operand match (non-nested case).
        for insn in block_insns:
            if insn.opcode_name not in _GUARD_CMP_OPCODES:
                continue
            match = FoldedLoopGuardFactCollector._match_counter_bound(
                insn, induction
            )
            if match is None:
                continue
            counter, bound = match
            signed = FoldedLoopGuardFactCollector._opcode_signedness(
                insn.opcode_name
            )
            return counter, bound, signed

        # Shape 2: nested ``(induction-var - #N)`` buried in an operand tree.
        for insn in block_insns:
            if insn.opcode_name not in _TREE_HOST_OPCODES:
                continue
            match = FoldedLoopGuardFactCollector._match_buried_sub(
                insn, induction
            )
            if match is None:
                continue
            counter, bound = match
            signed = insn.opcode_name not in _UNSIGNED_TREE_HOST_OPCODES
            return counter, bound, signed
        return None

    @staticmethod
    def _match_buried_sub(
        insn: _InstructionView,
        induction: tuple[_InductionVar, ...],
    ) -> tuple[_InductionVar, int] | None:
        """Walk the operand subtree of ``insn`` for a buried ``(counter - #N)``.

        Recurses the structured ``MopSnapshot`` subtree carried by the
        instruction (``src_l_mop`` / ``src_r_mop``) to find a binary ``SUB``
        sub-operation whose one child leaf is a known induction var and the
        other child is a positive numeric constant.  Returns ``(counter,
        bound)`` for the first match, else ``None``.
        """
        for root in (insn.src_l_mop, insn.src_r_mop):
            match = FoldedLoopGuardFactCollector._walk_for_sub(root, induction)
            if match is not None:
                return match
        return None

    @staticmethod
    def _walk_for_sub(
        mop: Any,
        induction: tuple[_InductionVar, ...],
    ) -> tuple[_InductionVar, int] | None:
        """Depth-first search a ``MopSnapshot`` tree for ``(counter - #N)``.

        A node is a nested sub-operation when ``sub_kind`` is set; its operand
        children are ``sub_l`` / ``sub_r``.  When the node is a ``SUB`` whose
        children pair a known induction-var leaf with a positive constant, the
        match is returned; otherwise the search recurses into the children.
        """
        if mop is None:
            return None
        sub_kind = getattr(mop, "sub_kind", None)
        sub_l = getattr(mop, "sub_l", None)
        sub_r = getattr(mop, "sub_r", None)
        if sub_kind is InsnKind.SUB:
            match = FoldedLoopGuardFactCollector._pair_counter_const(
                sub_l, sub_r, induction
            )
            if match is not None:
                return match
        for child in (sub_l, sub_r):
            match = FoldedLoopGuardFactCollector._walk_for_sub(child, induction)
            if match is not None:
                return match
        return None

    @staticmethod
    def _leaf_identity(mop: Any) -> tuple[int | None, int | None]:
        """Return ``(stkoff, reg)`` operand identity for a ``MopSnapshot`` leaf."""
        if mop is None:
            return None, None
        kind = getattr(mop, "kind", None)
        if kind is OperandKind.STACK:
            stkoff = getattr(mop, "stkoff", None)
            return (int(stkoff) if stkoff is not None else None), None
        if kind is OperandKind.REGISTER:
            reg = getattr(mop, "reg", None)
            return None, (int(reg) if reg is not None else None)
        return None, None

    @staticmethod
    def _leaf_const(mop: Any) -> int | None:
        """Return the numeric value of a ``MopSnapshot`` constant leaf, else None."""
        if mop is None:
            return None
        if getattr(mop, "kind", None) is OperandKind.NUMBER:
            value = getattr(mop, "value", None)
            return int(value) if value is not None else None
        return None

    @staticmethod
    def _pair_counter_const(
        left: Any,
        right: Any,
        induction: tuple[_InductionVar, ...],
    ) -> tuple[_InductionVar, int] | None:
        """Match a ``SUB`` node's children as ``(induction-var, const)``.

        For an ``(i - N)`` sign-bit guard the induction var is the minuend
        (left) and the bound is the subtrahend (right); the swapped order is
        also accepted defensively.  Returns ``(counter, bound)`` with a
        positive bound, else ``None``.
        """
        left_stk, left_reg = FoldedLoopGuardFactCollector._leaf_identity(left)
        right_stk, right_reg = FoldedLoopGuardFactCollector._leaf_identity(right)
        left_const = FoldedLoopGuardFactCollector._leaf_const(left)
        right_const = FoldedLoopGuardFactCollector._leaf_const(right)
        for var in induction:
            if var.matches_operand(stkoff=left_stk, reg=left_reg) and right_const:
                if right_const > 0:
                    return var, int(right_const)
            if var.matches_operand(stkoff=right_stk, reg=right_reg) and left_const:
                if left_const > 0:
                    return var, int(left_const)
        return None

    @staticmethod
    def _opcode_signedness(opcode_name: str) -> bool:
        """Derive compare signedness from the opcode (defaults to signed for the
        ``m_sub`` sign-bit form)."""
        if opcode_name in _UNSIGNED_CMP_OPCODES:
            return False
        return True

    @staticmethod
    def _match_counter_bound(
        insn: _InstructionView,
        induction: tuple[_InductionVar, ...],
    ) -> tuple[_InductionVar, int] | None:
        """Match ``(induction-var, const)`` in either operand order.

        Returns ``(counter, bound)`` when one operand is a known induction var
        and the other is a positive numeric constant; else ``None``.
        """
        left_const = insn.src_l_value if insn.src_l_type in (None, "mop_n") else None
        right_const = insn.src_r_value if insn.src_r_type in (None, "mop_n") else None
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
        by_block: dict[int, list[_InstructionView]],
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
        by_block: dict[int, list[_InstructionView]],
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

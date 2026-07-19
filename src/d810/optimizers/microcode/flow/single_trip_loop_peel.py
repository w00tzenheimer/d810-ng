"""Single-trip loop peel -- the EMIT (FlowOptimizationRule).

Consumes loops PROVEN (Z3) to execute exactly once and rewrites the CFG so the
loop becomes straight-line: the latch's back-edge is redirected to the loop
exit, breaking the cycle.  IDA's own const-prop/DCE then folds the now-constant
header guard and removes the induction variable -- we restore the true
structural fact and let the decompiler's own analysis finish (recover, don't
fight).

Layering: this is the only piece that mutates the CFG, so it lives in the
``optimizers`` layer.  The PROOF gate is the portable
``d810.analyses.control_flow.single_trip_loop``; the recognizer is
``d810.evaluator.hexrays_microcode.single_trip_loop_extract``.

Emit preconditions (beyond the proven gate), both checked on the live blocks:

* **P3 (pure-test header)**: the header's only instruction is its conditional
  jump (``head is tail``).  The eliminated second header visit therefore ran
  nothing but the branch, so skipping it preserves semantics.
* **P4 (goto latch)**: the latch is a 1-way block ending in ``goto header``, so
  the redirect is a ``BLOCK_GOTO_CHANGE`` (which never coerces a 2-way block
  into a goto).

If either fails, the rule ABSTAINS.
"""
from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.core.logging import getLogger
from d810.evaluator.hexrays_microcode.single_trip_loop_extract import (
    PeelCandidate,
    recognize_single_trip,
)
from d810.hexrays.mutation.cfg_verify import safe_verify
from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier
from d810.optimizers.microcode.flow.handler import FlowOptimizationRule

logger = getLogger(__name__)


@dataclass(frozen=True)
class PeelPlan:
    """A validated plan to peel one proven single-trip loop."""

    header: int
    latch: int
    exit_succ: int


def _loop_nodes(mba, latch: int, header: int) -> set[int]:
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


def plan_single_trip_peel(mba, candidate: PeelCandidate) -> PeelPlan | None:
    """Validate the emit preconditions P3/P4 and resolve the loop exit."""
    header, latch = candidate.header, candidate.latch
    hblk = mba.get_mblock(header)
    lblk = mba.get_mblock(latch)
    if hblk is None or lblk is None:
        logger.debug("peel plan abstain: missing block header=%s latch=%s", header, latch)
        return None
    # P3: header is a pure-test block -- exactly one instruction (the cond jump).
    # NB compare by list structure, NOT ``head is tail``: SWIG returns a fresh
    # proxy object per property access, so identity is always False.
    if hblk.head is None or hblk.head.next is not None:
        n = 0
        ins = hblk.head
        while ins is not None:
            n += 1
            ins = ins.next
        logger.debug("peel plan abstain P3: header %d not pure-test (ninsn=%d)", header, n)
        return None
    # P4: latch is a 1-way goto whose sole successor is the header.
    if (
        lblk.nsucc() != 1
        or lblk.tail is None
        or lblk.tail.opcode != ida_hexrays.m_goto
        or lblk.succ(0) != header
    ):
        logger.debug(
            "peel plan abstain P4: latch %d not goto->header (nsucc=%d tailop=%s succ0=%s)",
            latch,
            lblk.nsucc(),
            (lblk.tail.opcode if lblk.tail is not None else None),
            (lblk.succ(0) if lblk.nsucc() >= 1 else None),
        )
        return None
    # Exit successor = the header successor NOT inside the loop (must be unique).
    loop_nodes = _loop_nodes(mba, latch, header)
    exits = [s for s in list(hblk.succset) if s not in loop_nodes]
    if len(exits) != 1:
        logger.debug(
            "peel plan abstain: exits=%s loop_nodes=%s succs=%s",
            exits,
            sorted(loop_nodes),
            list(hblk.succset),
        )
        return None
    logger.debug(
        "peel plan OK: header=%d latch=%d exit=%d", header, latch, exits[0]
    )
    return PeelPlan(header=header, latch=latch, exit_succ=exits[0])


def peel_single_trip_loop(
    mba,
    candidate: PeelCandidate,
    *,
    modifier_factory=DeferredGraphModifier,
) -> bool:
    """Apply the peel for one proven candidate.  Returns True if the CFG changed.

    Redirects the latch's back-edge to the loop exit, breaking the cycle.
    """
    plan = plan_single_trip_peel(mba, candidate)
    if plan is None:
        return False

    modifier = modifier_factory(mba)
    modifier.queue_goto_change(
        int(plan.latch),
        int(plan.exit_succ),
        description=(
            f"single-trip peel: latch {plan.latch} back-edge -> exit "
            f"{plan.exit_succ} (header {plan.header})"
        ),
        rule_priority=100,  # proven constant analysis
    )
    applied = modifier.apply(defer_post_apply_maintenance=True)
    logger.debug(
        "peel apply: latch %d -> exit %d applied=%d",
        plan.latch,
        plan.exit_succ,
        applied,
    )
    if applied <= 0:
        return False
    safe_verify(
        mba,
        f"after single-trip peel latch {plan.latch} -> exit {plan.exit_succ}",
        logger_func=logger.error,
    )
    return True


class SingleTripLoopPeelRule(FlowOptimizationRule):
    """Peel loops proven to run exactly once into straight-line code."""

    NAME = "SingleTripLoopPeel"
    DESCRIPTION = (
        "Peel loops PROVEN (Z3) to run exactly once into straight-line code by "
        "redirecting the back-edge to the loop exit; IDA then folds the guard."
    )
    USES_DEFERRED_CFG = True

    def optimize(self, blk) -> int:
        mba = blk.mba
        if mba is None or blk.nsucc() != 1:
            return 0
        tail = blk.tail
        if tail is None or tail.opcode != ida_hexrays.m_goto:
            return 0
        header = blk.succ(0)
        hblk = mba.get_mblock(header)
        if hblk is not None and hblk.tail is not None:
            gl = hblk.tail.l
            logger.debug(
                "SingleTripLoopPeel probe: latch=%d header=%d hdr_op=%s "
                "guard_t=%s guard_size=%s",
                blk.serial,
                header,
                hblk.tail.opcode,
                (gl.t if gl is not None else None),
                (gl.size if gl is not None else None),
            )
        candidate = recognize_single_trip(mba, blk.serial, header)
        if candidate is None:
            logger.debug(
                "SingleTripLoopPeel: latch=%d header=%d recognizer ABSTAINED",
                blk.serial,
                header,
            )
            return 0
        if not candidate.verdict.proved:
            logger.debug(
                "SingleTripLoopPeel: latch=%d not proved (%s)",
                blk.serial,
                candidate.verdict.reason,
            )
            return 0
        if peel_single_trip_loop(
            mba,
            candidate,
            modifier_factory=self.new_deferred_modifier,
        ):
            logger.info(
                "SingleTripLoopPeel: latch %d -> header %d peeled (%s)",
                blk.serial,
                header,
                candidate.verdict.reason,
            )
            return 1
        return 0


__all__ = [
    "PeelPlan",
    "plan_single_trip_peel",
    "peel_single_trip_loop",
    "SingleTripLoopPeelRule",
]

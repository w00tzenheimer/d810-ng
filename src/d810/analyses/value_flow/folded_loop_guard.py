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

import re
from collections.abc import Mapping
from dataclasses import dataclass

from d810.core.typing import Any
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

# ``(%var_1E0.4-#0x64.4)`` -- counter token, optional SSA suffix, then the
# numeric bound.  The subtraction is how the sign-bit ``i < N`` predicate is
# materialized (``(i - N) < 0``); a folded guard leaves it as dead code.
_COUNTER_BOUND_RE = re.compile(
    r"%var_([0-9A-Fa-f]+)\.(\d+)(?:\{[^}]*\})?-#0x([0-9A-Fa-f]+)\."
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
    stkoff: int
    size: int


def _induction_vars_by_stkoff(
    instructions: tuple[_InstructionView, ...],
) -> dict[int, _InductionVar]:
    """Map ``dest_stkoff -> _InductionVar`` for every ``+1``/``-1`` self-update."""
    found: dict[int, _InductionVar] = {}
    for insn in instructions:
        update = _classify_induction_update(insn)
        if update is None:
            continue
        if abs(int(update.step)) != 1:
            continue
        stkoff = int(insn.dest_stkoff)
        size = int(insn.dest_size or 4)
        found.setdefault(stkoff, _InductionVar(stkoff, size))
    return found


def _counter_stkoff_for_token(
    token_hex: str,
    induction_vars: dict[int, _InductionVar],
) -> _InductionVar | None:
    """Resolve a ``%var_<HEX>`` guard-compare token to its induction slot.

    The ``var_<HEX>`` display name's hex suffix is the *frame* offset, which is
    not the microcode ``stkoff``; rather than parse the (binary-specific) frame
    map, we accept the guard token only when EXACTLY one induction var exists
    (the common counted-loop shape) and bind to it, or fall back to matching the
    token's stkoff directly when the display offset happens to equal it.
    """
    if len(induction_vars) == 1:
        return next(iter(induction_vars.values()))
    try:
        candidate = int(token_hex, 16)
    except ValueError:
        return None
    return induction_vars.get(candidate)


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

        induction = _induction_vars_by_stkoff(instructions)
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
            counter_var, bound = counter
            arms = self._guard_arms(
                target, guard_serial, by_block, canonical_stkoff
            )
            if arms is None:
                continue
            body_state, exit_state = arms
            guard_ea = block_start_ea.get(int(guard_serial))
            if guard_ea is None:
                continue

            semantic_key = (
                f"folded_loop_guard:guard_ea=0x{int(guard_ea):x}:"
                f"counter_stkoff=0x{counter_var.stkoff:x}:bound=0x{bound:x}"
            )
            payload: dict[str, Any] = {
                "guard_block_serial": int(guard_serial),
                "guard_ea": int(guard_ea),
                "guard_ea_hex": f"0x{int(guard_ea) & 0xFFFFFFFFFFFFFFFF:016x}",
                "counter_stkoff": int(counter_var.stkoff),
                "counter_stkoff_hex": f"0x{counter_var.stkoff:x}",
                "counter_size": int(counter_var.size),
                "bound": int(bound),
                "bound_hex": f"0x{int(bound):x}",
                "signed": True,
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
                        f"folded_loop_guard:counter@0x{counter_var.stkoff:x}"
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
        induction: dict[int, _InductionVar],
    ) -> tuple[_InductionVar, int] | None:
        """Return ``(counter, bound)`` if the block holds a folded ``(i - N)``
        induction compare, else ``None``."""
        for insn in block_insns:
            match = _COUNTER_BOUND_RE.search(str(insn.dstr or ""))
            if match is None:
                continue
            counter = _counter_stkoff_for_token(match.group(1), induction)
            if counter is None:
                continue
            try:
                bound = int(match.group(3), 16)
            except ValueError:
                continue
            if bound <= 0:
                continue
            return counter, bound
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

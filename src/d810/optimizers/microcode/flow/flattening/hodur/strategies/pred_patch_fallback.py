"""PredPatchFallbackStrategy — MopTracker-based predecessor patching.

For dispatcher predecessors where direct linearization couldn't resolve the
state value, this fallback strategy traces state values backward using
MopTracker.  If a unique state is inferred, it proposes a GOTO_REDIRECT.
If multiple predecessors disagree, it may propose BLOCK_DUPLICATE.

Corresponds to ``HodurUnflattener._resolve_and_patch`` and
``_infer_unique_state_at_block_end``.
"""
from __future__ import annotations

import ida_hexrays
from d810.core.typing import TYPE_CHECKING

from d810.core import logging
from d810.optimizers.microcode.flow.flattening.hodur.analysis import (
    HODUR_STATE_CHECK_OPCODES,
    HodurStateMachineDetector,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_FALLBACK,
    BenefitMetrics,
    EditType,
    OwnershipScope,
    PlanFragment,
    ProposedEdit,
)
from d810.hexrays.utils.tracker import MopTracker
from d810.optimizers.microcode.flow.flattening.utils import get_all_possibles_values

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger("D810.hodur.strategy.pred_patch_fallback")

__all__ = ["PredPatchFallbackStrategy"]

# MopTracker limits (matching HodurUnflattener constants)
_MOP_TRACKER_MAX_NB_BLOCK = 20
_MOP_TRACKER_MAX_NB_PATH = 15


class PredPatchFallbackStrategy:
    """Propose GOTO_REDIRECT or BLOCK_DUPLICATE edits for remaining dispatcher preds.

    After direct linearization, some blocks still point to dispatcher check
    blocks.  This strategy uses MopTracker backward tracing to identify the
    state value at the predecessor and proposes the appropriate redirect.

    Prerequisites: ``direct_handler_linearization`` must have run so that
    already-resolved blocks are not re-processed.
    """

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "pred_patch_fallback"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_FALLBACK

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        """Return True when a state machine with handlers is present.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if the snapshot describes a state machine that may have
            unresolved predecessor edges.
        """
        sm = snapshot.state_machine
        if sm is None:
            return False
        handlers = getattr(sm, "handlers", None)
        state_var = getattr(sm, "state_var", None)
        return bool(handlers) and state_var is not None

    # ------------------------------------------------------------------
    # Private helper: resolve chain target (ported from HodurUnflattener)
    # ------------------------------------------------------------------

    def _resolve_conditional_chain_target(
        self,
        mba: object,
        start_block: int,
        state_value: int,
        hodur_state_check_opcodes: list,
        detector_cls: object,
    ) -> int | None:
        """Follow conditional-chain comparisons for a concrete state until a leaf block.

        Port of HodurUnflattener._resolve_conditional_chain_target.
        """
        visited: set[int] = set()
        current = start_block

        for _ in range(mba.qty):
            if current in visited:
                return None
            visited.add(current)

            blk = mba.get_mblock(current)
            if blk.tail is None or blk.tail.opcode not in hodur_state_check_opcodes:
                return current
            check_info = detector_cls._extract_check_constant_and_opcode(blk.tail)
            if check_info is None:
                return current
            check_opcode, check_const, check_size = check_info

            jump_target, fallthrough = (
                detector_cls._get_jump_and_fallthrough_targets(blk)
            )
            if jump_target is None or fallthrough is None:
                return None

            jump_taken = detector_cls._is_jump_taken_for_state(
                check_opcode,
                int(state_value),
                check_const,
                check_size,
            )
            if jump_taken is None:
                return None

            current = jump_target if jump_taken else fallthrough

        return None

    # ------------------------------------------------------------------
    # plan() — full port of _resolve_and_patch
    # ------------------------------------------------------------------

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        """Produce a PlanFragment for predecessor-based patching.

        Full port of HodurUnflattener._resolve_and_patch.

        For each state check block, if we can determine what state the predecessor
        always has, we can bypass the check and go directly to the appropriate handler.

        Patching strategy (same as FixPredecessorOfConditionalJumpBlock):
        1. Propose BLOCK_DUPLICATE for the check block
        2. Propose CONVERT_TO_GOTO to make the duplicate unconditionally go to target
        3. Propose GOTO_REDIRECT to redirect the predecessor to the duplicate

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            A PlanFragment with GOTO_REDIRECT or BLOCK_DUPLICATE edits, or
            None when no unresolved predecessors exist.
        """
        if not self.is_applicable(snapshot):
            return None

        mba = snapshot.mba
        sm = snapshot.state_machine
        if mba is None or sm is None:
            return None

        handlers = getattr(sm, "handlers", {}) or {}
        state_var = getattr(sm, "state_var", None)

        if not handlers or state_var is None:
            return None

        edits: list[ProposedEdit] = []
        owned_blocks: set[int] = set()
        nb_changes = 0

        # Collect all patches to apply (to avoid modifying while iterating)
        # patches_fall_through: list of (pred_blk_serial, check_blk_serial, fall_through_serial)
        # patches_jump_taken:   list of (pred_blk_serial, check_blk_serial, jump_target_serial)
        patches_fall_through: list[tuple[int, int, int]] = []
        patches_jump_taken: list[tuple[int, int, int]] = []
        # Track conditional predecessors already queued to avoid duplicate patches
        conditional_preds_patched: set[int] = set()

        # For each state check block
        for state_val, handler in handlers.items():
            check_blk = mba.get_mblock(handler.check_block)
            if check_blk is None:
                continue

            logger.debug(
                "Analyzing state check block %d for state %s",
                handler.check_block,
                hex(state_val),
            )

            # For each predecessor of the check block
            pred_list = list(check_blk.predset)
            for pred_serial in pred_list:
                pred_blk = mba.get_mblock(pred_serial)
                if pred_blk is None:
                    continue

                # Use backward tracking to determine what state value the predecessor has
                tracker = MopTracker(
                    [state_var],
                    max_nb_block=_MOP_TRACKER_MAX_NB_BLOCK,
                    max_path=_MOP_TRACKER_MAX_NB_PATH,
                )
                tracker.reset()

                histories = tracker.search_backward(pred_blk, pred_blk.tail)
                values = get_all_possibles_values(histories, [state_var])
                flat_values = [v[0] for v in values if v[0] is not None]

                if not flat_values:
                    logger.debug(
                        "  Pred %d: could not determine state value", pred_serial
                    )
                    continue

                unique_values = set(flat_values)
                if len(unique_values) > 1:
                    logger.debug(
                        "  Pred %d: multiple possible state values: %s",
                        pred_serial,
                        [hex(v) for v in unique_values],
                    )
                    if (
                        len(unique_values) == 2
                        and pred_serial not in conditional_preds_patched
                    ):
                        # Attempt conditional transition resolution:
                        # The predecessor is a 2-way block where each path sets a
                        # different state value.  Walk the check-block chain for each
                        # value and, if both resolve to a valid handler block, propose
                        # BLOCK_DUPLICATE edits to redirect the two successor edges.
                        val_list = list(unique_values)
                        handler_targets = [
                            self._resolve_conditional_chain_target(
                                mba,
                                handler.check_block,
                                v,
                                HODUR_STATE_CHECK_OPCODES,
                                HodurStateMachineDetector,
                            )
                            for v in val_list
                        ]

                        if None not in handler_targets and pred_blk.nsucc() == 2:
                            check_opcode = (
                                check_blk.tail.opcode if check_blk.tail else None
                            )
                            if (
                                check_blk.tail is not None
                                and check_opcode in HODUR_STATE_CHECK_OPCODES
                            ):
                                # Determine which resolved handler corresponds to the
                                # jump-taken vs fall-through edge of pred_blk by using
                                # the check block's comparison against state_val.
                                all_resolved = True
                                for idx, v in enumerate(val_list):
                                    jt_for_v = HodurStateMachineDetector._is_jump_taken_for_state(
                                        check_opcode,
                                        int(v),
                                        int(state_val),
                                        check_blk.tail.r.size,
                                    )
                                    if jt_for_v is None:
                                        all_resolved = False
                                        break
                                    h_tgt = handler_targets[idx]
                                    if jt_for_v:
                                        patches_jump_taken.append(
                                            (pred_serial, handler.check_block, h_tgt)
                                        )
                                    else:
                                        patches_fall_through.append(
                                            (pred_serial, handler.check_block, h_tgt)
                                        )
                                if all_resolved:
                                    logger.debug(
                                        "Conditional fork at pred %d: values %s -> handlers %s",
                                        pred_serial,
                                        [hex(v) for v in val_list],
                                        [hex(h) for h in handler_targets],
                                    )
                                    conditional_preds_patched.add(pred_serial)
                    continue

                pred_state = flat_values[0]
                logger.debug(
                    "  Pred %d: state value is %s", pred_serial, hex(pred_state)
                )

                check_opcode = check_blk.tail.opcode if check_blk.tail else None
                if (
                    check_blk.tail is None
                    or check_opcode not in HODUR_STATE_CHECK_OPCODES
                ):
                    continue

                jump_target, fall_through = (
                    HodurStateMachineDetector._get_jump_and_fallthrough_targets(
                        check_blk
                    )
                )
                if jump_target is None or fall_through is None:
                    continue

                jump_taken = HodurStateMachineDetector._is_jump_taken_for_state(
                    check_opcode,
                    int(pred_state),
                    int(state_val),
                    check_blk.tail.r.size,
                )
                if jump_taken is None:
                    continue

                if jump_taken:
                    logger.info(
                        "Patching pred %d -> skip check %d -> jump target %d",
                        pred_serial,
                        handler.check_block,
                        jump_target,
                    )
                    patches_jump_taken.append((pred_serial, handler.check_block, jump_target))
                else:
                    logger.info(
                        "Patching pred %d -> skip check %d -> fall through %d",
                        pred_serial,
                        handler.check_block,
                        fall_through,
                    )
                    patches_fall_through.append((pred_serial, handler.check_block, fall_through))

        # Emit ProposedEdits for fall-through patches (jump never taken)
        for pred_serial, check_serial, fall_through in patches_fall_through:
            # BLOCK_DUPLICATE: duplicate check_serial, then make new block go to fall_through,
            # then redirect pred to new block.
            edits.append(
                ProposedEdit(
                    edit_type=EditType.BLOCK_DUPLICATE,
                    source_block=check_serial,
                    target_block=fall_through,
                    metadata={
                        "pred_serial": pred_serial,
                        "patch_kind": "fall_through",
                        "strategy": self.name,
                        "description": "pred_patch: pred %d -> dup check %d -> %d"
                        % (pred_serial, check_serial, fall_through),
                    },
                )
            )
            owned_blocks.add(pred_serial)
            owned_blocks.add(check_serial)
            nb_changes += 1

        # Emit ProposedEdits for jump-taken patches
        for pred_serial, check_serial, jump_target in patches_jump_taken:
            edits.append(
                ProposedEdit(
                    edit_type=EditType.BLOCK_DUPLICATE,
                    source_block=check_serial,
                    target_block=jump_target,
                    metadata={
                        "pred_serial": pred_serial,
                        "patch_kind": "jump_taken",
                        "strategy": self.name,
                        "description": "pred_patch: pred %d -> dup check %d -> %d"
                        % (pred_serial, check_serial, jump_target),
                    },
                )
            )
            owned_blocks.add(pred_serial)
            owned_blocks.add(check_serial)
            nb_changes += 1

        if not edits:
            return None

        ownership = OwnershipScope(
            blocks=frozenset(owned_blocks),
            edges=frozenset(),
            transitions=frozenset(),
        )
        benefit = BenefitMetrics(
            handlers_resolved=0,
            transitions_resolved=nb_changes,
            blocks_freed=0,
            conflict_density=0.3,  # may overlap with direct strategy's block claims
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            proposed_edits=edits,
            ownership=ownership,
            prerequisites=["direct_handler_linearization"],
            expected_benefit=benefit,
            risk_score=0.35,
        )

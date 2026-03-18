"""Backward dispatcher-predecessor resolution strategy.

Resolves TAIL_CHASE_FAILED handler exits by using MopTracker to backward-walk
from each dispatcher predecessor and resolve the state variable value, then
looking up the target handler via the IntervalDispatcher.

This runs on the PRE-APPLY MBA where state var writes are still intact
(before NOP'ing). Post-apply, the writes are NOP'd and block structure
changes due to trampolines.
"""
from __future__ import annotations

from d810.core import logging
from d810.core.typing import TYPE_CHECKING
from d810.cfg.graph_modification import DuplicateAndRedirect
from d810.optimizers.microcode.flow.flattening.hodur._helpers import blk_label
from d810.optimizers.microcode.flow.flattening.hodur._modification_bridge import (
    ModificationBuilder,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_DIRECT,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.recon.flow.bst_model import (
    resolve_redirectable_handler_target,
)

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.hodur.snapshot import AnalysisSnapshot

logger = logging.getLogger("D810.hodur.strategy.backward_pred_resolution")

__all__ = ["BackwardPredResolutionStrategy"]


def _nop_value_lookup(
    pred_blk,
    pred_serial: int,
    nop_state_values: dict[int, int],
    bst_result: "BSTAnalysisResult",
    mba: object,
) -> int | None:
    """Resolve a dispatcher predecessor via NOP'd state value lookup.

    When a block wrote a state constant that was NOP'd by the LFG strategy,
    we can look up the original constant value and resolve the target handler
    via the BST dispatcher.

    Also checks predecessors of pred_serial, because trampolines (block
    copies) may not have the NOP'd value directly, but their predecessor
    (the original block) does.

    Args:
        pred_blk: ``ida_hexrays.mblock_t`` dispatcher predecessor block.
        pred_serial: Block serial of the dispatcher predecessor.
        nop_state_values: Mapping of block_serial to NOP'd constant value.
        bst_result: BST analysis result containing the IntervalDispatcher.
        mba: The mba_t object for blk_label logging.

    Returns:
        Handler block serial if resolved, or ``None``.
    """
    # Direct lookup on the predecessor itself.
    nop_value = nop_state_values.get(pred_serial)
    if nop_value is None:
        # Check predecessors -- the NOP'd block might be a pred of this
        # trampoline (e.g., blk[269] is a copy of blk[123], NOP was on 123).
        try:
            for pi in range(pred_blk.npred()):
                pred_of_pred = pred_blk.pred(pi)
                nop_value = nop_state_values.get(pred_of_pred)
                if nop_value is not None:
                    break
        except Exception:
            pass

    if nop_value is None:
        return None

    dispatcher = getattr(bst_result, "dispatcher", None)
    if dispatcher is None:
        return None

    target = dispatcher.lookup(nop_value)
    if target is not None and target != pred_serial:
        logger.info(
            "BACKWARD_PRED: %s resolved via NOP'd value 0x%X -> %s",
            blk_label(mba, pred_serial),
            nop_value,
            blk_label(mba, target),
        )
        return target
    return None


def _valrange_probe_fallback(
    pred_blk,
    state_var,
    bst_result: "BSTAnalysisResult",
) -> int | None:
    """Attempt to resolve a dispatcher predecessor via IDA valrange probing.

    When MopTracker backward-walk fails to find a concrete state constant,
    this fallback queries IDA's value-range analysis on the state variable
    at ``pred_blk`` and probes the IntervalDispatcher's rows to find a
    unique matching handler target.

    Args:
        pred_blk: ``ida_hexrays.mblock_t`` dispatcher predecessor block.
        state_var: ``ida_hexrays.mop_t`` (mop_S) for the state variable.
        bst_result: BST analysis result containing the IntervalDispatcher.

    Returns:
        Handler block serial if exactly one target matches, or ``None``.
    """
    dispatcher = getattr(bst_result, "dispatcher", None)
    if dispatcher is None:
        return None
    try:
        import ida_hexrays
        stkoff = state_var.s.off
    except Exception:
        return None
    from d810.evaluator.hexrays_microcode.valranges import (
        resolve_state_via_valrange_probe,
    )
    return resolve_state_via_valrange_probe(
        pred_blk, stkoff, dispatcher, pred_blk.tail,
    )


class BackwardPredResolutionStrategy:
    """Resolve unresolved handler exits via backward dispatcher-pred walk.

    For each non-BST predecessor of the dispatcher block, use MopTracker
    to backward-walk and resolve the state variable value.  If the value
    can be resolved, perform a BST lookup to determine the target handler
    and emit a ``RedirectGoto`` modification.

    Family: ``FAMILY_DIRECT`` -- runs after primary direct strategies.
    Risk: LOW-MEDIUM -- read-only backward walk + BST lookup, no speculation.
    """

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "backward_pred_resolution"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_DIRECT

    def is_applicable(self, snapshot: "AnalysisSnapshot") -> bool:
        """Return True when a BST result and dispatcher serial are present.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if the snapshot has a BST result with a valid dispatcher serial.
        """
        return (
            snapshot.bst_result is not None
            and snapshot.bst_dispatcher_serial >= 0
        )

    def plan(
        self, snapshot: "AnalysisSnapshot",
    ) -> PlanFragment | list[PlanFragment] | None:
        """Produce PlanFragments for backward-pred-based exit resolution.

        For each non-BST predecessor of the dispatcher block, use MopTracker
        to backward-walk and resolve the state variable value, then emit a
        redirect if BST lookup succeeds.

        Single-target ``RedirectGoto`` modifications are placed in a separate
        fragment from multi-target ``DuplicateAndRedirect`` modifications so
        that a failure in the latter does not abort the former.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            One or two PlanFragments (single-target first, multi-target
            second), or None when no exits could be resolved.
        """
        import ida_hexrays

        from d810.evaluator.hexrays_microcode.tracker import MopTracker

        mba = snapshot.mba
        bst_result = snapshot.bst_result
        dispatcher_serial = snapshot.bst_dispatcher_serial
        bst_node_blocks = bst_result.bst_node_blocks
        bst_serials = set(bst_node_blocks) | {dispatcher_serial}

        # Get state var mop (must be mop_S)
        state_var = getattr(snapshot.state_machine, "state_var", None)
        if state_var is None or state_var.t != ida_hexrays.mop_S:
            return None

        disp_blk = mba.get_mblock(dispatcher_serial)
        if disp_blk is None:
            return None

        # Build set of blocks already handled by LFG transitions.
        # On the first pass, resolved_transitions is empty, so we also
        # check the state machine's transition list directly -- these are
        # the from_block serials that LFG's direct_handler_linearization
        # will redirect.  Emitting duplicates causes GATE_FAILED.
        lfg_handled: set[int] = set()
        sm = snapshot.state_machine
        if sm is not None:
            for trans in sm.transitions:
                if trans.from_block is not None:
                    lfg_handled.add(trans.from_block)

        # Also include blocks whose transitions were explicitly resolved
        # by earlier strategies (belt-and-suspenders for later passes).
        resolved_trans = snapshot.resolved_transitions
        if resolved_trans and sm is not None:
            for t in sm.transitions:
                key = (t.from_state, t.to_state)
                if key in resolved_trans:
                    lfg_handled.add(t.from_block)

        # LFG also redirects blocks discovered via exit state resolution
        # (BFS from handler entries) and BST default block discovery (DFS
        # forward evaluation).  These redirect sources are NOT in
        # sm.transitions, so the filter above misses them.  Any dispatcher
        # predecessor inside a handler's block set will be reached by
        # LFG's forward evaluation — add all handler-owned blocks to the
        # exclusion set to prevent duplicate redirects that cause
        # CFG_50860_SUCC_MISMATCH.
        if sm is not None:
            for handler in sm.handlers.values():
                lfg_handled.add(handler.check_block)
                for blk_serial in handler.handler_blocks:
                    lfg_handled.add(blk_serial)

        # LFG's _resolve_exit_states performs BFS from handler entries for
        # EXIT states (handlers with no outgoing transition) and redirects
        # any block it discovers that writes a state constant.  These
        # BFS-discovered blocks may NOT appear in handler_blocks (e.g.
        # blk[48] for handler 0x6D207773).  Replicate the EXIT state
        # identification and BFS to exclude those blocks.
        if sm is not None and bst_result is not None:
            handler_state_map = getattr(bst_result, "handler_state_map", None) or {}
            if handler_state_map:
                # Inverted map: state_value -> handler entry serial
                state_to_entry: dict[int, int] = {
                    v: k for k, v in handler_state_map.items()
                }
                states_with_outgoing: set[int] = {
                    t.from_state for t in sm.transitions
                    if t.from_state is not None
                }
                for state_val, handler in sm.handlers.items():
                    if state_val in states_with_outgoing:
                        continue
                    # This is an EXIT state — LFG will BFS from its entry.
                    correct_entry = state_to_entry.get(state_val)
                    if correct_entry is None:
                        _exit_dispatcher = getattr(bst_result, "dispatcher", None)
                        if _exit_dispatcher is not None:
                            correct_entry = _exit_dispatcher.lookup(state_val)
                    if correct_entry is None:
                        continue
                    # BFS from correct_entry (mirrors LFG depth=6)
                    bfs_visited: set[int] = set()
                    bfs_queue: list[tuple[int, int]] = [(correct_entry, 0)]
                    while bfs_queue:
                        blk_serial, depth = bfs_queue.pop(0)
                        if blk_serial in bfs_visited:
                            continue
                        bfs_visited.add(blk_serial)
                        if blk_serial in bst_serials:
                            continue
                        try:
                            blk = mba.get_mblock(blk_serial)
                        except (AttributeError, IndexError):
                            continue
                        if blk is None:
                            continue
                        if depth < 6:
                            try:
                                for si in range(blk.nsucc()):
                                    succ_s = blk.succ(si)
                                    if succ_s not in bfs_visited:
                                        bfs_queue.append((succ_s, depth + 1))
                            except Exception:
                                pass
                    lfg_handled.update(bfs_visited)

        builder = ModificationBuilder.from_snapshot(snapshot)
        modifications = []
        owned_blocks: set[int] = set()

        # Build augmented exits set (shared across all histories).
        # If the forward terminal proof discovers an exit state for one
        # predecessor, subsequent predecessors with the same state value
        # are filtered by the augmented set without re-running the BFS.
        augmented_exits: set[int] = set()

        # Count non-BST dispatcher preds for the log summary
        total_preds = sum(
            1 for pi in range(disp_blk.npred())
            if disp_blk.pred(pi) not in bst_serials
        )
        skipped = sum(
            1 for pi in range(disp_blk.npred())
            if disp_blk.pred(pi) not in bst_serials
            and disp_blk.pred(pi) in lfg_handled
        )
        remaining = total_preds - skipped
        if skipped:
            logger.info(
                "BACKWARD_PRED: skipping %d LFG-handled predecessors, "
                "processing %d remaining",
                skipped, remaining,
            )

        # Iterate dispatcher predecessors
        for pi in range(disp_blk.npred()):
            pred_serial = disp_blk.pred(pi)
            if pred_serial in bst_serials:
                continue

            # EXPERIMENT: lfg_handled guard disabled — let backward_pred
            # process all dispatcher predecessors, including those in
            # handler block sets. NOPs are OFF so state writes survive.
            # if pred_serial in lfg_handled:
            #     continue

            pred_blk = mba.get_mblock(pred_serial)
            if pred_blk is None or pred_blk.nsucc() != 1:
                continue

            # Only redirect blocks still pointing at the dispatcher.
            # If the successor is already something else (redirected by
            # an earlier strategy in the same decompilation pass), emitting
            # a second redirect would create a duplicate-successor
            # violation (CFG_50860_SUCC_MISMATCH).
            if pred_blk.succ(0) != dispatcher_serial:
                continue

            # Use MopTracker to backward-walk and resolve the state var value
            MopTracker.reset()
            tracker = MopTracker([state_var], max_nb_block=10, max_path=50)
            try:
                histories = tracker.search_backward(pred_blk, pred_blk.tail)
            except Exception:
                logger.debug(
                    "BACKWARD_PRED: %s MopTracker search_backward failed",
                    blk_label(mba, pred_serial),
                )
                continue

            # Collect ALL resolved targets across histories.
            # When a block has multiple predecessors, different paths may
            # write different state values.  We must only redirect when
            # every resolved path agrees on the same target handler.
            resolved_targets: set[int] = set()
            resolved_values: list[tuple[int, int]] = []
            for history in histories:
                value = history.get_mop_constant_value(state_var)
                if value is not None:
                    target = resolve_redirectable_handler_target(
                        bst_result, value,
                        augmented_exits=augmented_exits,
                        mba=mba,
                        dispatcher_serial=dispatcher_serial,
                    )
                    if target is None and value not in bst_result.exits:
                        logger.debug(
                            "BACKWARD_PRED: %s state=0x%X skipped "
                            "(terminal handler — forward proof)",
                            blk_label(mba, pred_serial), value,
                        )
                    if target is not None:
                        resolved_targets.add(target)
                        resolved_values.append((value, target))

            if len(resolved_targets) == 1:
                # All paths agree on the same target — safe to redirect
                target = next(iter(resolved_targets))
                mod = builder.goto_redirect(
                    source_block=pred_serial, target_block=target,
                )
                if mod is not None:
                    modifications.append(mod)
                    owned_blocks.add(pred_serial)
                    logger.info(
                        "BACKWARD_PRED: %s MopTracker resolved state=0x%X "
                        "-> handler %s (%d paths agree)",
                        blk_label(mba, pred_serial), resolved_values[0][0],
                        blk_label(mba, target),
                        len(resolved_values),
                    )
            elif len(resolved_targets) > 1:
                # Paths disagree — duplicate the block per predecessor arm.
                # Build per-predecessor target mapping by matching each
                # history's path against pred_serial's predecessors.
                per_pred_targets: list[tuple[int, int]] = []
                seen_preds: set[int] = set()

                for history in histories:
                    value = history.get_mop_constant_value(state_var)
                    if value is None:
                        continue
                    target = resolve_redirectable_handler_target(
                        bst_result, value,
                        augmented_exits=augmented_exits,
                        mba=mba,
                        dispatcher_serial=dispatcher_serial,
                    )
                    if target is None:
                        continue

                    # The history's path traces back through predecessors.
                    # The first block in the path is the furthest predecessor.
                    # We need the IMMEDIATE predecessor of pred_serial (the
                    # dispatcher predecessor being duplicated).
                    # Check pred_serial's predecessors and match against
                    # history path.
                    for arm_idx in range(pred_blk.npred()):
                        arm_serial = pred_blk.pred(arm_idx)
                        if arm_serial in seen_preds:
                            continue
                        if history.contains_block_serial(arm_serial):
                            per_pred_targets.append((arm_serial, target))
                            seen_preds.add(arm_serial)
                            break

                if len(per_pred_targets) >= 2:
                    mod = builder.duplicate_and_redirect(
                        source_block=pred_serial,
                        per_pred_targets=per_pred_targets,
                    )
                    modifications.append(mod)
                    owned_blocks.add(pred_serial)
                    logger.info(
                        "BACKWARD_PRED: %s DUPLICATE_AND_REDIRECT: %s",
                        blk_label(mba, pred_serial),
                        [(f"pred={p} -> {blk_label(mba, t)}") for p, t in per_pred_targets],
                    )
                else:
                    # Per-arm mapping failed — try NOP'd value, then valrange
                    nop_target = _nop_value_lookup(
                        pred_blk, pred_serial,
                        snapshot.nop_state_values, bst_result, mba,
                    )
                    if nop_target is not None:
                        mod = builder.goto_redirect(
                            source_block=pred_serial,
                            target_block=nop_target,
                        )
                        if mod is not None:
                            modifications.append(mod)
                            owned_blocks.add(pred_serial)
                    else:
                        vr_target = _valrange_probe_fallback(
                            pred_blk, state_var, bst_result,
                        )
                        if vr_target is not None and vr_target != pred_serial:
                            mod = builder.goto_redirect(
                                source_block=pred_serial,
                                target_block=vr_target,
                            )
                            if mod is not None:
                                modifications.append(mod)
                                owned_blocks.add(pred_serial)
                                logger.info(
                                    "BACKWARD_PRED: %s multi-target resolved "
                                    "via valrange probe -> %s",
                                    blk_label(mba, pred_serial),
                                    blk_label(mba, vr_target),
                                )
                        else:
                            logger.info(
                                "BACKWARD_PRED: %s MULTI-TARGET but couldn't "
                                "map %d targets to predecessors",
                                blk_label(mba, pred_serial), len(resolved_targets),
                            )
            else:
                # MopTracker failed — try NOP'd value lookup first, then
                # valrange probe as final fallback.
                nop_target = _nop_value_lookup(
                    pred_blk, pred_serial,
                    snapshot.nop_state_values, bst_result, mba,
                )
                if nop_target is not None:
                    mod = builder.goto_redirect(
                        source_block=pred_serial,
                        target_block=nop_target,
                    )
                    if mod is not None:
                        modifications.append(mod)
                        owned_blocks.add(pred_serial)
                else:
                    # NOP'd value lookup failed — try valrange probe
                    vr_target = _valrange_probe_fallback(
                        pred_blk, state_var, bst_result,
                    )
                    if vr_target is not None and vr_target != pred_serial:
                        mod = builder.goto_redirect(
                            source_block=pred_serial,
                            target_block=vr_target,
                        )
                        if mod is not None:
                            modifications.append(mod)
                            owned_blocks.add(pred_serial)
                            if vr_target in bst_result.exits:
                                logger.info(
                                    "BACKWARD_PRED: %s resolved via "
                                    "valrange probe -> exit handler %s",
                                    blk_label(mba, pred_serial),
                                    blk_label(mba, vr_target),
                                )
                            else:
                                logger.info(
                                    "BACKWARD_PRED: %s resolved via "
                                    "valrange probe -> handler %s",
                                    blk_label(mba, pred_serial),
                                    blk_label(mba, vr_target),
                                )
                    elif len(histories) > 0:
                        logger.debug(
                            "BACKWARD_PRED: %s %d histories, none resolved",
                            blk_label(mba, pred_serial), len(histories),
                        )
                    else:
                        logger.debug(
                            "BACKWARD_PRED: %s 0 histories",
                            blk_label(mba, pred_serial),
                        )

        if not modifications:
            return None

        logger.info(
            "BACKWARD_PRED: resolved %d dispatcher predecessors",
            len(modifications),
        )

        # Split: single-target RedirectGoto vs multi-target DuplicateAndRedirect
        single_target_mods = [
            m for m in modifications
            if not isinstance(m, DuplicateAndRedirect)
        ]
        multi_target_mods = [
            m for m in modifications
            if isinstance(m, DuplicateAndRedirect)
        ]

        fragments: list[PlanFragment] = []

        if single_target_mods:
            fragments.append(PlanFragment(
                strategy_name=self.name,
                family=self.family,
                modifications=single_target_mods,
                ownership=OwnershipScope(
                    blocks=frozenset(),
                    edges=frozenset(),
                    transitions=frozenset(),
                ),
                prerequisites=["direct_handler_linearization"],
                expected_benefit=BenefitMetrics(
                    handlers_resolved=0,
                    transitions_resolved=len(single_target_mods),
                    blocks_freed=0,
                    conflict_density=0.0,
                ),
                risk_score=0.3,
                metadata={"safeguard_min_required": 1},
            ))

        if multi_target_mods:
            fragments.append(PlanFragment(
                strategy_name=self.name,
                family=self.family,
                modifications=multi_target_mods,
                ownership=OwnershipScope(
                    blocks=frozenset(),
                    edges=frozenset(),
                    transitions=frozenset(),
                ),
                prerequisites=["direct_handler_linearization"],
                expected_benefit=BenefitMetrics(
                    handlers_resolved=0,
                    transitions_resolved=len(multi_target_mods),
                    blocks_freed=0,
                    conflict_density=0.0,
                ),
                risk_score=0.4,
                metadata={"safeguard_min_required": 1},
            ))

        if len(fragments) == 1:
            return fragments[0]
        return fragments

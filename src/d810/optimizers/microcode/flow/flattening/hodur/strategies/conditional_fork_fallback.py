"""ConditionalForkFallbackStrategy — resolve 2-way conditional state forks.

When a block has two outgoing edges and each arm writes a different state value,
this strategy walks the BST check chain to determine which handler each arm
targets.  It proposes CONVERT_TO_GOTO or CONDITIONAL_REDIRECT edits for each arm.

Corresponds to ``HodurUnflattener._resolve_conditional_forks_via_predecessors``,
``_find_conditional_predecessor``, ``_resolve_conditional_chain_target``,
``_emulate_chain_exit``, ``_collect_ladder_use_before_def``, and
``_get_successor_into_dispatcher``.
"""
from __future__ import annotations

import ida_hexrays
from d810.core.typing import TYPE_CHECKING

from d810.core import logging
from d810.hexrays.utils.hexrays_helpers import (
    append_mop_if_not_in_list,
    equal_mops_ignore_size,
    get_mop_index,
)
from d810.evaluator.hexrays_microcode.tracker import (
    InstructionDefUseCollector,
    remove_segment_registers,
)
from d810.evaluator.hexrays_microcode.emulator import (
    MicroCodeEnvironment,
    MicroCodeInterpreter,
)
from d810.optimizers.microcode.flow.flattening.hodur.analysis import (
    HODUR_STATE_CHECK_OPCODES,
    HodurStateMachineDetector,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_FALLBACK,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.recon.flow.def_search import resolve_mop_via_predecessors
from d810.optimizers.microcode.flow.flattening.hodur._modification_bridge import (
    ModificationBuilder,
)
if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger("D810.hodur.strategy.conditional_fork_fallback")

__all__ = ["ConditionalForkFallbackStrategy"]


class ConditionalForkFallbackStrategy:
    """Propose CONDITIONAL_REDIRECT edits for conditional state fork blocks.

    When a single block (from_block) drives two distinct state transitions,
    the dispatcher check chain must be walked for each state value to find
    the corresponding handler entry.  The executor then rewires both edges.

    Prerequisites: ``direct_handler_linearization`` must have run to ensure
    the main transition set is established before conditional forks are
    attempted.
    """

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "conditional_fork_fallback"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_FALLBACK

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        """Return True when conditional transitions exist in the state machine.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if any transition is marked conditional.
        """
        sm = snapshot.state_machine
        if sm is None:
            return False
        transitions = getattr(sm, "transitions", None) or []
        return any(getattr(t, "is_conditional", False) for t in transitions)

    # ------------------------------------------------------------------
    # Private helpers (ported from HodurUnflattener)
    # ------------------------------------------------------------------

    def _find_conditional_predecessor(self, mba: object, start_block: int) -> int | None:
        """Walk backward along single-predecessor chains to find a 2-way block.

        Only follows single-predecessor paths (npred()==1) to avoid crossing
        dispatcher boundaries. Returns the serial of the first 2-way conditional
        block found, or None.

        Port of HodurUnflattener._find_conditional_predecessor.
        """
        current = start_block
        visited: set[int] = {current}
        max_depth = mba.qty  # Safety bound

        for _ in range(max_depth):
            blk = mba.get_mblock(current)
            if blk.npred() != 1:
                return None  # Multi-predecessor — bail

            pred_serial = blk.predset[0]
            if pred_serial in visited:
                return None  # Cycle

            pred_blk = mba.get_mblock(pred_serial)
            if (
                pred_blk.nsucc() == 2
                and pred_blk.tail
                and pred_blk.tail.opcode
                in (
                    ida_hexrays.m_jcnd,
                    ida_hexrays.m_jnz,
                    ida_hexrays.m_jz,
                    ida_hexrays.m_jae,
                    ida_hexrays.m_jb,
                    ida_hexrays.m_ja,
                    ida_hexrays.m_jbe,
                    ida_hexrays.m_jg,
                    ida_hexrays.m_jge,
                    ida_hexrays.m_jl,
                    ida_hexrays.m_jle,
                )
            ):
                return pred_serial

            visited.add(pred_serial)
            current = pred_serial

        return None

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

    def _collect_ladder_use_before_def(
        self,
        mba: object,
        dispatcher_set: set[int],
        entry_serial: int,
    ) -> list:
        """Collect all mops used-before-defined in the ladder (dispatcher) blocks.

        Port of HodurUnflattener._collect_ladder_use_before_def.
        """
        use_list: list = []
        def_list: list = []
        use_before_def: list = []

        # Find all reachable blocks within dispatcher_set starting from entry_serial
        reachable: set[int] = set()
        queue = [entry_serial]
        while queue:
            curr = queue.pop(0)
            if curr in reachable or curr not in dispatcher_set:
                continue
            reachable.add(curr)
            blk = mba.get_mblock(curr)
            if blk:
                for succ in blk.succset:
                    queue.append(succ)

        # Process reachable blocks in topological order (serial order)
        for serial in sorted(reachable):
            blk = mba.get_mblock(serial)
            if blk is None:
                continue
            cur_ins = blk.head
            while cur_ins is not None:
                collector = InstructionDefUseCollector()
                cur_ins.for_all_ops(collector)
                cleaned = remove_segment_registers(collector.unresolved_ins_mops)
                for mop_used in cleaned + list(collector.memory_unresolved_ins_mops):
                    append_mop_if_not_in_list(mop_used, use_list)
                    if get_mop_index(mop_used, def_list) == -1:
                        append_mop_if_not_in_list(mop_used, use_before_def)
                for mop_def in collector.target_mops:
                    append_mop_if_not_in_list(mop_def, def_list)
                cur_ins = cur_ins.next

        return [
            m for m in use_before_def if m.t in (ida_hexrays.mop_r, ida_hexrays.mop_S)
        ]

    def _get_successor_into_dispatcher(
        self,
        from_block: object,
        dispatcher_set: set[int],
        mba: object,
    ) -> int | None:
        """Return the successor that enters or stays in the dispatcher set.

        Port of HodurUnflattener._get_successor_into_dispatcher.
        """
        succs = list(from_block.succset)
        if not succs:
            return None
        if from_block.nsucc() == 1:
            return succs[0]
        if from_block.nsucc() == 2:
            in_disp = [s for s in succs if s in dispatcher_set]
            if in_disp:
                return in_disp[0]
            for s in succs:
                succ_blk = mba.get_mblock(s)
                if succ_blk is None:
                    continue
                for s2 in succ_blk.succset:
                    if s2 in dispatcher_set:
                        return s
            return None
        return succs[0] if succs else None

    def _emulate_chain_exit(
        self,
        mba: object,
        entry_block_serial: int,
        state_value: int,
        state_var: object,
        dispatcher_set: set[int],
        use_before_def: list,
        from_block_serial: int,
        max_instructions: int = 5000,
    ) -> int | None:
        """Emulate from entry_block with env built from local definitions until
        we exit the dispatcher set. Returns the block serial we land in, or None on failure.

        Port of HodurUnflattener._emulate_chain_exit.
        """
        cur_blk = mba.get_mblock(entry_block_serial)
        if cur_blk is None:
            return None

        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        env = MicroCodeEnvironment()
        try:
            env.define(state_var, int(state_value))
        except Exception:
            return None

        from_blk = mba.get_mblock(from_block_serial)
        if from_blk is None:
            return None

        for mop in use_before_def:
            if state_var is not None and equal_mops_ignore_size(mop, state_var):
                continue
            ast = resolve_mop_via_predecessors(mop, from_blk, from_blk.tail)
            if ast is None or not hasattr(ast, "value") or ast.value is None:
                return None
            try:
                env.define(mop, int(ast.value))
            except Exception:
                return None

        cur_ins = cur_blk.head
        visited: set[int] = set()
        nb_emulated = 0

        while cur_blk is not None:
            if cur_ins is None:
                cur_ins = cur_blk.head
            if cur_ins is None:
                return None
            if cur_blk.serial in visited:
                return None
            visited.add(cur_blk.serial)

            is_ok = interpreter.eval_instruction(
                cur_blk, cur_ins, env, raise_exception=False
            )
            if not is_ok:
                return None
            nb_emulated += 1
            if nb_emulated >= max_instructions:
                return None

            next_blk = env.next_blk
            next_ins = env.next_ins
            if next_blk is None:
                return None
            if next_blk.serial not in dispatcher_set:
                return next_blk.serial
            cur_blk = next_blk
            cur_ins = next_ins

        return None

    # ------------------------------------------------------------------
    # plan()
    # ------------------------------------------------------------------

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        """Produce a PlanFragment for conditional fork resolution.

        Full port of HodurUnflattener._resolve_conditional_forks_via_predecessors.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            A PlanFragment with CONDITIONAL_REDIRECT edits for each conditional
            fork, or None when no conditional transitions exist.
        """
        if not self.is_applicable(snapshot):
            return None

        mba = snapshot.mba
        sm = snapshot.state_machine
        if mba is None or sm is None:
            return None

        transitions = getattr(sm, "transitions", []) or []

        # Build dispatcher_set + state_var for emulation fallback
        dispatcher_set: set[int] = set()
        for h in (getattr(sm, "handlers", None) or {}).values():
            cb = getattr(h, "check_block", None)
            if cb is not None:
                dispatcher_set.add(cb)

        state_var = getattr(sm, "state_var", None)

        # Group conditional transitions by from_block.
        conditional_groups: dict[int, list] = {}
        for t in transitions:
            if not getattr(t, "is_conditional", False):
                continue
            from_block = getattr(t, "from_block", None)
            if from_block is None:
                continue
            conditional_groups.setdefault(from_block, []).append(t)

        builder = ModificationBuilder.from_snapshot(snapshot)
        modifications: list = []
        owned_blocks: set[int] = set()
        owned_transitions: set[tuple[int, int]] = set()
        resolved = 0

        for from_blk_serial, group_transitions in conditional_groups.items():
            unique_states = list({getattr(t, "to_state", None) for t in group_transitions})
            if len(unique_states) != 2:
                continue

            # Walk backward from from_block looking for a 2-way conditional block
            cond_block = self._find_conditional_predecessor(mba, from_blk_serial)
            if cond_block is None:
                if logger.debug_on:
                    logger.debug(
                        "No conditional predecessor found for block %d",
                        from_blk_serial,
                    )
                continue

            # Resolve which target block each state leads to through the chain
            state_a, state_b = unique_states[0], unique_states[1]
            target_a = self._resolve_conditional_chain_target(
                mba, cond_block, state_a, HODUR_STATE_CHECK_OPCODES, HodurStateMachineDetector
            )
            target_b = self._resolve_conditional_chain_target(
                mba, cond_block, state_b, HODUR_STATE_CHECK_OPCODES, HodurStateMachineDetector
            )

            if target_a is None or target_b is None:
                # Static walk hit a loop; try emulation fallback
                if dispatcher_set and state_var is not None:
                    use_before_def = self._collect_ladder_use_before_def(
                        mba, dispatcher_set, cond_block
                    )
                    from_blk = mba.get_mblock(from_blk_serial)
                    ladder_entry = (
                        self._get_successor_into_dispatcher(from_blk, dispatcher_set, mba)
                        if from_blk is not None
                        else None
                    )
                    if ladder_entry is not None:
                        try:
                            if target_a is None:
                                target_a = self._emulate_chain_exit(
                                    mba,
                                    ladder_entry,
                                    int(state_a),
                                    state_var,
                                    dispatcher_set,
                                    use_before_def,
                                    from_blk_serial,
                                )
                            if target_b is None:
                                target_b = self._emulate_chain_exit(
                                    mba,
                                    ladder_entry,
                                    int(state_b),
                                    state_var,
                                    dispatcher_set,
                                    use_before_def,
                                    from_blk_serial,
                                )
                        except Exception:
                            pass
                if target_a is None or target_b is None:
                    if logger.debug_on:
                        logger.debug(
                            "Chain resolution failed for block %d states 0x%x/0x%x",
                            from_blk_serial,
                            state_a,
                            state_b,
                        )
                    continue

            # Determine jcc taken/fallthrough mapping using the check block comparison
            cond_blk = mba.get_mblock(cond_block)
            if (
                cond_blk is None
                or cond_blk.tail is None
                or cond_blk.tail.opcode not in HODUR_STATE_CHECK_OPCODES
            ):
                continue

            check_info = HodurStateMachineDetector._extract_check_constant_and_opcode(
                cond_blk.tail
            )
            if check_info is None:
                continue
            check_opcode, check_const, check_size = check_info

            jt_a = HodurStateMachineDetector._is_jump_taken_for_state(
                check_opcode,
                int(state_a),
                check_const,
                check_size,
            )
            if jt_a is None:
                continue

            taken_target = target_a if jt_a else target_b
            fall_target = target_b if jt_a else target_a

            # Emit CONDITIONAL_REDIRECT: source_block is from_blk_serial (the handler
            # exit block); metadata carries the reference block (cond_block) and targets.
            modifications.append(
                builder.conditional_redirect(
                    source_block=from_blk_serial,
                    conditional_target=taken_target,
                    fallthrough_target=fall_target,
                    ref_block=cond_block,
                )
            )
            owned_blocks.add(from_blk_serial)
            resolved += 1

            if logger.debug_on:
                logger.debug(
                    "Resolved conditional fork at block %d: "
                    "taken->%d, fall->%d (states 0x%x/0x%x)",
                    cond_block,
                    taken_target,
                    fall_target,
                    state_a,
                    state_b,
                )

            # Record transitions as owned.
            for t in group_transitions:
                from_s = getattr(t, "from_state", None)
                to_s = getattr(t, "to_state", None)
                if from_s is not None and to_s is not None:
                    owned_transitions.add((from_s, to_s))

        if not modifications:
            return None

        ownership = OwnershipScope(
            blocks=frozenset(owned_blocks),
            edges=frozenset(),
            transitions=frozenset(owned_transitions),
        )
        benefit = BenefitMetrics(
            handlers_resolved=0,
            transitions_resolved=resolved,
            blocks_freed=0,
            conflict_density=0.2,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=modifications,
            ownership=ownership,
            prerequisites=["direct_handler_linearization"],
            expected_benefit=benefit,
            risk_score=0.3,
        )

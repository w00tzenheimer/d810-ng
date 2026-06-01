"""DispatcherTrampolineSkipStrategy -- skip residual trampoline gotos to BST.

After HCC linearization, a small set of blocks may still tail-jump to the BST
root. Those blocks typically look like::

    [<state-write> i = #<state_const>]
    goto BST_ROOT

Since the BST resolves the state value to a deterministic handler block, we can
short-circuit the trampoline: rewrite the tail goto to point directly at the
BST-resolved target.  We DO NOT NOP the state write -- only the goto
destination changes.  The state write becomes dead code (no longer read by
anything reachable) and IDA's dataflow optimizer collapses it.

Family: ``FAMILY_CLEANUP`` -- runs after HCC and other reconstruction passes.
Default behavior
----------------
Trampoline skip is opt-in.  Enable it with
``D810_HODUR_ENABLE_TRAMPOLINE_SKIP=1`` for targeted archaeology or regression
isolation.  ``D810_HODUR_DISABLE_TRAMPOLINE_SKIP=1`` remains accepted as an
explicit off switch.

Risk: LOW -- only emits ``RedirectGoto`` for 1-way trampoline blocks whose
new_target was deterministically resolved by walking the BST.
"""
from __future__ import annotations

import os

import ida_hexrays

from d810.core import logging
from d810.core.typing import TYPE_CHECKING
from d810.ir.flowgraph import InsnKind, OperandKind
from d810.transforms.loop_bound_writer_guard import collect_const_var_refs_in_block
from d810.transforms.modification_builder import ModificationBuilder
from d810.transforms.residual_target_resolution import (
    BstConditionalTail,
    BstGotoTail,
    resolve_dispatcher_trampoline_skip_candidate,
    walk_bst_dispatcher,
)
from d810.backends.hexrays.evidence.analysis import (
    HodurStateMachineDetector,
)
from d810.transforms.plan_fragment import (
    FAMILY_CLEANUP,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)

if TYPE_CHECKING:
    from d810.transforms.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger(
    "D810.hodur.strategy.dispatcher_trampoline_skip", logging.DEBUG
)

__all__ = ["DispatcherTrampolineSkipStrategy"]

_GATE_ENV_ENABLE = "D810_HODUR_ENABLE_TRAMPOLINE_SKIP"
_GATE_ENV_DISABLE = "D810_HODUR_DISABLE_TRAMPOLINE_SKIP"

# Conditional opcodes the BST cascade may use to discriminate state values.
_BST_COND_OPCODES: frozenset[int] = frozenset({
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
})


class DispatcherTrampolineSkipStrategy:
    """Redirect [state-write,] goto BST_ROOT trampolines to BST-resolved targets.

    Family: ``FAMILY_CLEANUP`` -- last in pipeline.
    """

    @property
    def name(self) -> str:
        return "dispatcher_trampoline_skip"

    @property
    def family(self) -> str:
        return FAMILY_CLEANUP

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        if os.environ.get(_GATE_ENV_DISABLE, "").strip() == "1":
            return False
        if os.environ.get(_GATE_ENV_ENABLE, "").strip() != "1":
            return False
        if snapshot.mba is None:
            return False
        if snapshot.bst_dispatcher_serial < 0:
            return False
        if snapshot.bst_result is None:
            return False
        return True

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        if not self.is_applicable(snapshot):
            return None

        mba = snapshot.mba
        bst_root_serial = int(snapshot.bst_dispatcher_serial)
        bst_result = snapshot.bst_result
        bst_node_blocks = set(getattr(bst_result, "bst_node_blocks", {}) or {})
        # Always treat the root itself as a BST block, even if not in node map.
        bst_node_blocks.add(bst_root_serial)

        state_var_stkoff = self._resolve_state_var_stkoff(snapshot)
        if state_var_stkoff is None:
            logger.info(
                "DispatcherTrampolineSkip: no state-var stkoff; skipping"
            )
            return None

        builder = ModificationBuilder.from_snapshot(snapshot)
        modifications: list = []
        owned_blocks: set[int] = set()
        skip_count: int = 0
        skipped_return_carrier_const_feed: int = 0
        skipped_direct_use_def_veto: int = 0
        cumulative_view = getattr(snapshot, "cumulative_planner_view", None)

        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            if blk is None:
                continue
            serial = int(blk.serial)
            goto_target = self._goto_target(blk)
            direct_use_def_veto = (
                cumulative_view is not None
                and callable(
                    getattr(cumulative_view, "is_direct_use_def_vetoed", None)
                )
                and cumulative_view.is_direct_use_def_vetoed(serial)
            )
            decision = resolve_dispatcher_trampoline_skip_candidate(
                source_block=serial,
                bst_root=bst_root_serial,
                bst_blocks=bst_node_blocks,
                nsucc=int(blk.nsucc()),
                goto_target=goto_target,
                direct_use_def_veto=direct_use_def_veto,
                state_value_fn=lambda blk=blk: self._find_last_state_write_constant(
                    blk,
                    state_var_stkoff,
                ),
                target_for_state_fn=lambda state_value: self._walk_bst(
                    mba,
                    bst_root_serial,
                    bst_node_blocks,
                    state_value,
                ),
                target_exists_fn=lambda target_serial: (
                    0 <= int(target_serial) < int(mba.qty)
                    and mba.get_mblock(int(target_serial)) is not None
                ),
                block_count=int(mba.qty),
            )
            if (
                decision.rejection_reason == "direct_use_def_veto"
            ):
                logger.info(
                    "RECON_REDIRECT_REJECTED_PRIOR_USE_DEF_VETO "
                    "source=blk[%d] old_target=blk[%d]",
                    serial,
                    bst_root_serial,
                )
                skipped_direct_use_def_veto += 1
                continue
            if not decision.is_admitted:
                continue
            target_serial = int(decision.target_block)
            state_value = int(decision.state_value)

            modification = builder.goto_redirect(
                source_block=serial,
                target_block=target_serial,
                old_target=bst_root_serial,
            )

            # Return-carrier const-feed gate.  Only fact-rooted, never
            # heuristic.  ``bst_root_serial`` is, by construction, the
            # redirect's old_target (the dispatcher root state-flow node), so
            # the user's "old_target is dispatcher/root state-flow" condition
            # is auto-satisfied here.
            fact_view = getattr(snapshot, "diagnostic_fact_view", None)
            should_reject = False
            if fact_view is not None:
                sites = fact_view.return_carrier_sites_for_block(target_serial)
                if sites:
                    introduced = collect_const_var_refs_in_block(
                        mba,
                        serial,
                        insn_kind_classifier=self._hexrays_insn_kind,
                        operand_kind_classifier=self._hexrays_operand_kind,
                    )
                    if introduced:
                        for site in sites:
                            fact_refs = frozenset(
                                str(ref).lower()
                                for ref in (site.payload or {}).get(
                                    "upstream_writer_var_refs", ()
                                )
                            )
                            overlap = introduced & fact_refs
                            if overlap:
                                logger.info(
                                    "RECON_REDIRECT_REJECTED_RETURN_CARRIER_CONST_FEED "
                                    "source=blk[%d] target=blk[%d] old_target=blk[%d] "
                                    "fact_id=%s overlap=%s "
                                    "upstream_writer_ea=0x%x upstream_writer_block=%s",
                                    serial,
                                    target_serial,
                                    bst_root_serial,
                                    site.fact_id,
                                    sorted(overlap),
                                    int(
                                        (site.payload or {}).get(
                                            "upstream_writer_ea"
                                        )
                                        or 0
                                    ),
                                    (site.payload or {}).get(
                                        "upstream_writer_block_serial"
                                    ),
                                )
                                should_reject = True
                                break
            if should_reject:
                skipped_return_carrier_const_feed += 1
                continue

            modifications.append(modification)
            owned_blocks.add(serial)
            skip_count += 1
            logger.info(
                "trampoline skip: blk[%d] state=0x%X -> blk[%d]",
                serial,
                state_value & 0xFFFFFFFFFFFFFFFF,
                target_serial,
            )

        logger.info(
            "DispatcherTrampolineSkip: %d trampolines redirected",
            skip_count,
        )
        logger.info(
            "DispatcherTrampolineSkip: skipped %d redirects rejected by "
            "return-carrier const-feed gate",
            skipped_return_carrier_const_feed,
        )
        logger.info(
            "DispatcherTrampolineSkip: skipped %d redirects rejected by "
            "prior direct use-def vetoes",
            skipped_direct_use_def_veto,
        )

        if not modifications:
            return None

        ownership = OwnershipScope(
            blocks=frozenset(owned_blocks),
            edges=frozenset(),
            transitions=frozenset(),
        )
        benefit = BenefitMetrics(
            handlers_resolved=0,
            transitions_resolved=skip_count,
            blocks_freed=0,
            conflict_density=0.0,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=modifications,
            ownership=ownership,
            prerequisites=["linearized_flow_graph", "handler_chain_composer"],
            expected_benefit=benefit,
            risk_score=0.15,
            metadata={
                "safeguard_min_required": 1,
                "allow_prerequisite_block_overlap": True,
                "execution_policy": "trampoline_skip",
            },
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_state_var_stkoff(snapshot: AnalysisSnapshot) -> int | None:
        """Best-effort state-var stack-offset resolution."""
        detector = getattr(snapshot, "detector", None)
        if detector is not None:
            try:
                from d810.analyses.control_flow.transition_builder import (
                    _get_state_var_stkoff,
                )

                off = _get_state_var_stkoff(detector)
                if off is not None:
                    return int(off)
            except Exception:
                pass
        sm = getattr(snapshot, "state_machine", None)
        if sm is not None and getattr(sm, "state_var", None) is not None:
            try:
                sv = sm.state_var
                if sv.t == ida_hexrays.mop_S:
                    return int(sv.s.off)
            except Exception:
                pass
        return None

    @staticmethod
    def _find_last_state_write_constant(
        blk: object, state_var_stkoff: int
    ) -> int | None:
        """Scan blk.tail backwards for `m_mov #const, state_var`.

        Returns the constant value, or ``None`` if no such write is found in
        the block.  The walk is bounded; we only need a write that is
        textually at (or near) the tail of the block since that's what the
        forward state-eval would compute.
        """
        insn = getattr(blk, "tail", None)
        # Skip the trailing m_goto itself.
        if insn is not None and insn.opcode == ida_hexrays.m_goto:
            insn = insn.prev
        walk_limit = 16
        walked = 0
        while insn is not None and walked < walk_limit:
            if (
                insn.opcode == ida_hexrays.m_mov
                and insn.l is not None
                and insn.l.t == ida_hexrays.mop_n
                and insn.d is not None
                and insn.d.t == ida_hexrays.mop_S
                and insn.d.s is not None
                and int(insn.d.s.off) == int(state_var_stkoff)
            ):
                try:
                    return int(insn.l.nnn.value)
                except Exception:
                    return None
            insn = insn.prev
            walked += 1
        return None

    @staticmethod
    def _hexrays_insn_kind(insn: object) -> InsnKind | None:
        try:
            opcode = int(getattr(insn, "opcode"))
        except (TypeError, ValueError):
            return None
        if opcode == int(ida_hexrays.m_mov):
            return InsnKind.MOV
        return None

    @staticmethod
    def _hexrays_operand_kind(mop: object) -> OperandKind | None:
        try:
            operand_type = int(getattr(mop, "t"))
        except (TypeError, ValueError):
            return None
        if operand_type == int(ida_hexrays.mop_n):
            return OperandKind.NUMBER
        if operand_type == int(ida_hexrays.mop_S):
            return OperandKind.STACK
        return None

    @staticmethod
    def _goto_target(blk: object) -> int | None:
        tail = getattr(blk, "tail", None)
        if tail is None or tail.opcode != ida_hexrays.m_goto:
            return None
        target = getattr(tail, "l", None)
        if target is None or target.t != ida_hexrays.mop_b:
            return None
        return int(target.b)

    @staticmethod
    def _walk_bst(
        mba: object,
        root: int,
        bst_blocks: set[int],
        state_value: int,
    ) -> int | None:
        """Walk the BST cascade for ``state_value`` until landing in a
        non-BST block.

        Each BST block is either a 1-way passthrough (``m_goto``) or a 2-way
        comparison (``m_j*``) on the state variable against an immediate.  We
        evaluate the comparison using the known state value and follow the
        taken / fall-through edge.  Returns the first non-BST block reached,
        or ``None`` if the walk hit an unrecognized block.
        """
        return walk_bst_dispatcher(
            root=int(root),
            bst_blocks=bst_blocks,
            state_value=int(state_value),
            tail_for_block_fn=lambda serial: DispatcherTrampolineSkipStrategy._bst_tail_view(
                mba,
                serial,
            ),
            is_conditional_taken_fn=HodurStateMachineDetector._is_jump_taken_for_state,
        )

    @staticmethod
    def _bst_tail_view(
        mba: object,
        serial: int,
    ) -> BstGotoTail | BstConditionalTail | None:
        blk = mba.get_mblock(int(serial))
        if blk is None:
            return None
        tail = blk.tail
        if tail is None:
            return None
        opcode = tail.opcode
        if opcode == ida_hexrays.m_goto:
            target = tail.l
            if target is None or target.t != ida_hexrays.mop_b:
                return None
            return BstGotoTail(target=int(target.b))
        if opcode not in _BST_COND_OPCODES:
            return None
        rhs = tail.r
        taken_target = tail.d
        if (
            rhs is None
            or rhs.t != ida_hexrays.mop_n
            or taken_target is None
            or taken_target.t != ida_hexrays.mop_b
        ):
            return None
        try:
            rhs_value = int(rhs.nnn.value)
            rhs_size = int(rhs.size) if rhs.size > 0 else 4
        except Exception:
            return None
        return BstConditionalTail(
            opcode=int(opcode),
            rhs_value=rhs_value,
            rhs_size=rhs_size,
            taken_target=int(taken_target.b),
            successors=tuple(int(blk.succ(index)) for index in range(blk.nsucc())),
        )

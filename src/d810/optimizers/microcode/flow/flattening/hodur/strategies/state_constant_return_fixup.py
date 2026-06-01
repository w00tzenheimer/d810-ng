"""StateConstantReturnFixupStrategy -- NOP leaked state constants in return paths.

After Hodur linearization, some return-path blocks still contain
``m_mov rax = #<state_const>`` instructions that overwrite the correct return
value with a stale dispatcher constant.  This strategy identifies such
instructions by matching their immediate source operand against the set of
known state constants, and emits ``NopInstruction`` modifications to remove
them.  IDA's own dataflow optimizer then propagates the correct reaching
definition into the return slot.

Family: ``FAMILY_CLEANUP`` -- runs after all other strategies.
Prerequisites: ``["linearized_flow_graph"]`` -- the active DAG-driven
linearizer must already have resolved handler transitions.
"""
from __future__ import annotations

from d810.core import logging
from d810.core.typing import TYPE_CHECKING
from d810.transforms.modification_builder import (
    ModificationBuilder,
)
from d810.transforms.state_var_cleanup import collect_state_constants
from d810.evaluator.hexrays_microcode.return_cleanup_backend import (
    HexRaysReturnCleanupEvidenceBackend,
)
from d810.transforms.plan_fragment import (
    FAMILY_CLEANUP,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.analyses.control_flow.exit_transition_discovery import (
    resolve_state_var_stkoff,
)

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger("D810.hodur.strategy.state_const_return_fixup")

__all__ = ["StateConstantReturnFixupStrategy"]

_RETURN_CLEANUP_BACKEND = HexRaysReturnCleanupEvidenceBackend()


class StateConstantReturnFixupStrategy:
    """NOP ``m_mov rax = #<state_const>`` in BLT_STOP predecessor blocks.

    After linearization, handler bodies correctly compute the return value,
    but residual OLLVM dispatcher glue may overwrite ``rax`` with a stale
    state constant just before the return.  Removing the overwrite lets IDA
    propagate the correct reaching definition.

    Family: ``FAMILY_CLEANUP`` -- last in pipeline.
    Risk: LOW -- only NOPs instructions whose source is a known state constant.
    """

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "state_constant_return_fixup"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_CLEANUP

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        """Return True when known state constants exist.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if there are known state constants to match against.
        """
        return bool(self._collect_state_constants(snapshot))

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        """Produce a PlanFragment with NOP edits for leaked state constant writes.

        Scans predecessor blocks of BLT_STOP for ``m_mov`` instructions that
        write a known state constant into ``rax`` or a return stack variable,
        and emits ``NopInstruction`` modifications for each.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            A PlanFragment with NOP modifications, or ``None`` when no leaked
            state constants were found.
        """
        mba = snapshot.mba
        if mba is None:
            return None

        known_consts = self._collect_state_constants(snapshot)
        if not known_consts:
            return None

        state_var_stkoff = resolve_state_var_stkoff(
            detector=getattr(snapshot, "detector", None),
            state_var=getattr(getattr(snapshot, "state_machine", None), "state_var", None),
        )
        evidence = _RETURN_CLEANUP_BACKEND.collect_return_cleanup_evidence(
            mba,
            known_state_constants=known_consts,
            state_var_stkoff=state_var_stkoff,
        )
        if evidence.stop_serial is None:
            logger.info(
                "StateConstReturnFixup: no BLT_STOP block found"
            )
            return None

        builder = ModificationBuilder.from_snapshot(snapshot)
        modifications: list = []
        owned_blocks: set[int] = set()
        seen_sites: set[tuple[int, int]] = set()
        nop_count = 0
        for cleanup_site in evidence.sites:
            site = (int(cleanup_site.block_serial), int(cleanup_site.insn_ea))
            if site in seen_sites:
                continue
            modifications.append(
                builder.nop_instruction(
                    source_block=cleanup_site.block_serial,
                    instruction_ea=cleanup_site.insn_ea,
                )
            )
            seen_sites.add(site)
            owned_blocks.add(cleanup_site.block_serial)
            nop_count += 1
            if cleanup_site.reason == "synthetic_return_feeder":
                logger.info(
                    "StateConstReturnFixup: NOP synthetic return feeder"
                    " at blk[%d]:0x%x feeding mux blk[%d]",
                    cleanup_site.block_serial,
                    cleanup_site.insn_ea,
                    cleanup_site.mux_block_serial if cleanup_site.mux_block_serial is not None else -1,
                )
            elif cleanup_site.reason == "state_const_mov":
                logger.info(
                    "StateConstReturnFixup: NOP m_mov #0x%x at"
                    " blk[%d]:0x%x",
                    cleanup_site.observed_state if cleanup_site.observed_state is not None else 0,
                    cleanup_site.block_serial,
                    cleanup_site.insn_ea,
                )
            else:
                logger.info(
                    "StateConstReturnFixup: NOP cleanup site reason=%s"
                    " at blk[%d]:0x%x",
                    cleanup_site.reason,
                    cleanup_site.block_serial,
                    cleanup_site.insn_ea,
                )

        logger.info(
            "StateConstReturnFixup: %d instructions NOPed across %d"
            " BLT_STOP predecessors",
            nop_count,
            evidence.stop_pred_count,
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
            transitions_resolved=0,
            blocks_freed=0,
            conflict_density=0.0,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=modifications,
            ownership=ownership,
            prerequisites=["linearized_flow_graph"],
            expected_benefit=benefit,
            risk_score=0.1,
            metadata={
                "safeguard_min_required": 1,
                # This cleanup intentionally stacks on top of the DAG
                # linearizer's block ownership: it NOPs leaked return-slot
                # feeders inside already-linearized handler blocks and does not
                # compete for CFG edges or state transitions.
                "allow_prerequisite_block_overlap": True,
                # NOPing stale state-var → return-slot feeders temporarily
                # creates undefined-use (INTERR 50846) that IDA resolves at
                # later maturities via its own dataflow optimizer.
                "execution_policy": "nop_cleanup_relaxed",
            },
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_state_constants(snapshot: AnalysisSnapshot) -> set[int]:
        """Collect all known state constants from snapshot and BST result.

        Merges ``snapshot.state_constants`` with values from
        ``bst_result.handler_state_map`` and ``bst_result.handler_range_map``.

        Args:
            snapshot: Immutable analysis snapshot.

        Returns:
            Set of integer state constant values.
        """
        return set(collect_state_constants(snapshot.state_constants, snapshot.bst_result))

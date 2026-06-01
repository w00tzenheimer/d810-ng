"""DeadStateVariableEliminationStrategy -- NOP reads of the dead state variable.

After Hodur linearization, the OLLVM dispatcher state variable is semantically
dead.  DirectLinearization already NOPs state variable **writes** (``m_mov
#CONST, state_var``).  However, downstream **reads** of the state variable
survive -- for example, ``m_xdu %var_8.8 = %var_7BC.4`` instructions that
widen the dead state variable into a return slot.

This strategy identifies remaining read sites through a backend evidence
adapter and emits backend-neutral ``NopInstructions`` modifications. Hodur owns
the cleanup policy and graph intent; the Hex-Rays adapter owns live DU chains,
operands, opcodes, gutted-block checks, value ranges, and reaching-def guards.

Family: ``FAMILY_CLEANUP`` -- runs after all other strategies.
Prerequisites: ``["state_write_reconstruction"]`` -- the reconstruction pass
must already have rewritten the semantic handoffs before stale state-variable
reads are removed.
"""
from __future__ import annotations

from d810.core import logging
from d810.core.typing import TYPE_CHECKING
from d810.transforms.modification_builder import (
    ModificationBuilder,
)
from d810.transforms.state_var_cleanup import collect_state_constants
from d810.evaluator.hexrays_microcode.dead_state_variable_backend import (
    HexRaysDeadStateVariableEvidenceBackend,
    StateVariableRef,
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

logger = logging.getLogger("D810.hodur.strategy.dead_state_var_elim")

__all__ = ["DeadStateVariableEliminationStrategy"]

_DEAD_STATE_BACKEND = HexRaysDeadStateVariableEvidenceBackend()


class DeadStateVariableEliminationStrategy:
    """NOP remaining reads of the dead state variable after linearization."""

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "dead_state_variable_elimination"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_CLEANUP

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        """Return True when a known state-machine state variable exists."""
        sm = snapshot.state_machine
        if sm is None:
            return False
        if not getattr(sm, "handlers", None):
            return False
        return self._resolve_state_variable(snapshot) is not None

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        """Produce a PlanFragment with NOP edits for dead state-variable reads."""
        if not self.is_applicable(snapshot):
            return None

        mba = snapshot.mba
        if mba is None:
            return None

        state_variable = self._resolve_state_variable(snapshot)
        if state_variable is None:
            return None

        state_constants = self._collect_state_constants(snapshot)
        bst_result = getattr(snapshot, "bst_result", None)
        bst_node_blocks = frozenset(
            int(block)
            for block in (getattr(bst_result, "bst_node_blocks", set()) or set())
        )
        evidence = _DEAD_STATE_BACKEND.collect_dead_state_read_cleanup_evidence(
            mba,
            state_variable=state_variable,
            known_state_constants=state_constants,
            bst_node_blocks=bst_node_blocks,
        )

        if evidence.use_site_count == 0:
            logger.info(
                "DeadStateVarElim: no read sites found for state_var stkoff=0x%x",
                state_variable.stkoff,
            )
            return None

        builder = ModificationBuilder.from_snapshot(snapshot)
        modifications: list = []
        owned_blocks: set[int] = set()

        for cleanup_site in evidence.sites:
            modifications.append(
                builder.nop_instruction(
                    source_block=cleanup_site.block_serial,
                    instruction_ea=cleanup_site.insn_ea,
                )
            )
            owned_blocks.add(cleanup_site.block_serial)
            logger.debug(
                "DeadStateVarElim: NOP read site blk[%d] ea=0x%x opcode=%s",
                cleanup_site.block_serial,
                cleanup_site.insn_ea,
                cleanup_site.opcode_name,
            )

        logger.info(
            "DeadStateVarElim: %d/%d use sites NOPed for state_var stkoff=0x%x",
            len(modifications),
            evidence.use_site_count,
            state_variable.stkoff,
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
            prerequisites=["state_write_reconstruction"],
            expected_benefit=benefit,
            risk_score=0.1,
            metadata={"safeguard_min_required": 1},
        )

    @staticmethod
    def _resolve_state_variable(snapshot: AnalysisSnapshot) -> StateVariableRef | None:
        return _DEAD_STATE_BACKEND.resolve_state_variable(
            detector=getattr(snapshot, "detector", None),
            state_var=getattr(
                getattr(snapshot, "state_machine", None),
                "state_var",
                None,
            ),
        )

    @staticmethod
    def _collect_state_constants(snapshot: AnalysisSnapshot) -> frozenset[int]:
        """Collect all known state constants from the snapshot and BST result."""
        return collect_state_constants(snapshot.state_constants, snapshot.bst_result)

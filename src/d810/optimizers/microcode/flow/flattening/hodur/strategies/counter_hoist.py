"""CounterHoistStrategy -- promote fused load-add-store induction operands.

OLLVM-flattened byte loops express induction as a single fused instruction
where the load is embedded as a sub-instruction (mop_d) of an arithmetic op::

    add  [ds.2:v54.8].8, v62.8, v30.8   ; m_add l=mop_d(m_ldx ds, v54), r=v62
    stx  v30 -> [ds.2:v54.8]            ; m_stx storing back to the same addr

IDA's MMAT_LVARS DCE eliminates the load (and therefore the increment) because
the m_ldx only appears as a sub-operand. The pseudocode loses the
``*ptr += step`` semantic and the do-while body looks like a stuck counter.

This strategy detects the pattern at MMAT_GLBOPT1 and queues
:class:`PromoteOperandToScalar` modifications that hoist the embedded m_ldx
into its own instruction with a fresh kreg destination, restoring an
explicit def-use chain that survives DCE.

Family: ``FAMILY_CLEANUP`` -- runs after HCC, and after optional
trampoline-skip when that experiment is enabled.

Default behavior
----------------
Default-on. Disable for archaeology / regression isolation with
``D810_HODUR_DISABLE_COUNTER_HOIST=1`` or
``D810_HODUR_ENABLE_COUNTER_HOIST=0``.

Risk: LOW -- the rewrite is semantically equivalent (same value computed,
same memory write); only the def-use shape changes.
"""
from __future__ import annotations

import os

from d810.capabilities.providers import get_microcode_evidence
from d810.core import logging
from d810.core.typing import TYPE_CHECKING
from d810.transforms.modification_builder import ModificationBuilder
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    FAMILY_CLEANUP,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger(
    "D810.hodur.strategy.counter_hoist", logging.DEBUG
)

__all__ = ["CounterHoistStrategy"]

_GATE_ENV_ENABLE = "D810_HODUR_ENABLE_COUNTER_HOIST"
_GATE_ENV_DISABLE = "D810_HODUR_DISABLE_COUNTER_HOIST"


class CounterHoistStrategy:
    """Promote fused load-add-store induction operands to standalone insns.

    Family: ``FAMILY_CLEANUP``.
    """

    @property
    def name(self) -> str:
        return "counter_hoist"

    @property
    def family(self) -> str:
        return FAMILY_CLEANUP

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        if os.environ.get(_GATE_ENV_DISABLE, "").strip() == "1":
            return False
        if os.environ.get(_GATE_ENV_ENABLE, "").strip() == "0":
            return False
        return snapshot.mba is not None

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        if not self.is_applicable(snapshot):
            return None

        mba = snapshot.mba
        builder = ModificationBuilder.from_snapshot(snapshot)
        modifications: list = []
        owned_blocks: set[int] = set()
        match_count = 0

        # Live ``minsn_t``/``mop_t`` detection runs in the backend seam, which
        # returns matched (block_serial, side, host_ea, host_opcode) tuples in
        # the same nested block-then-instruction order this loop used to scan.
        candidates = get_microcode_evidence().find_counter_hoist_candidates(mba)
        for block_serial, side, host_ea, host_opcode in candidates:
            modifications.append(
                builder.promote_operand_to_scalar(
                    source_block=block_serial,
                    host_ea=host_ea,
                    host_opcode=host_opcode,
                    operand_side=side,
                )
            )
            owned_blocks.add(block_serial)
            match_count += 1
            logger.info(
                "counter_hoist: queued promote at blk[%d]@0x%x "
                "opcode=%d side=%s",
                block_serial,
                host_ea,
                host_opcode,
                side,
            )

        logger.info(
            "CounterHoist: %d load-arith-store sites queued for promotion",
            match_count,
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
            prerequisites=["handler_chain_composer"],
            expected_benefit=benefit,
            risk_score=0.10,
            metadata={
                "safeguard_min_required": 1,
                "allow_prerequisite_block_overlap": True,
                "execution_policy": "counter_hoist",
            },
        )

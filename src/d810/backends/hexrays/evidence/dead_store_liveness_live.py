"""Hex-Rays composition root for portable GLBOPT2 dead-store liveness."""

from __future__ import annotations

from d810.backends.hexrays.evidence.instruction_value_flow_live import (
    build_live_instruction_flow,
)
from d810.evaluator.hexrays_microcode.dead_store_liveness import (
    HexRaysDeadStoreLivenessBackend as _PortableDeadStoreLivenessEvaluator,
)
from d810.core.observability import emit, has_subscribers
from d810.core.observability_events import DeadStoreRejectionObserved
from d810.hexrays.ir_maturity import maturity_to_name

__all__ = ["HexRaysDeadStoreLivenessBackend"]


class HexRaysDeadStoreLivenessBackend(_PortableDeadStoreLivenessEvaluator):
    """Bind the portable DSE evaluator to live Hex-Rays instruction facts."""

    def __init__(self) -> None:
        super().__init__(build_live_instruction_flow)

    def collect(self, mba: object):
        evidence = super().collect(mba)
        if not has_subscribers(DeadStoreRejectionObserved):
            return evidence
        func_ea = int(getattr(mba, "entry_ea", 0) or 0)
        maturity = maturity_to_name(int(getattr(mba, "maturity", -1)))
        for rejection in evidence.rejections:
            emit(
                DeadStoreRejectionObserved(
                    func_ea=func_ea,
                    maturity=maturity,
                    strategy="dead_store_elimination",
                    authoritative=bool(evidence.authoritative),
                    block_serial=int(rejection.block_serial),
                    block_start_ea=int(rejection.block_start_ea),
                    insn_ea=int(rejection.insn_ea),
                    ordinal=int(rejection.ordinal),
                    opcode=int(rejection.opcode),
                    destination_kind=rejection.destination_kind,
                    destination_id=rejection.destination_id,
                    destination_width=int(rejection.destination_width),
                    reason=rejection.reason.value,
                    detail=rejection.detail,
                    use_block_serial=rejection.use_block_serial,
                    use_block_start_ea=rejection.use_block_start_ea,
                    use_insn_ea=rejection.use_insn_ea,
                    use_ordinal=rejection.use_ordinal,
                    use_opcode=rejection.use_opcode,
                    use_operand_path=rejection.use_operand_path,
                    use_kind=rejection.use_kind,
                )
            )
        return evidence

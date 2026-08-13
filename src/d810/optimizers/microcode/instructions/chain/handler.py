import abc
import time

import ida_hexrays

from d810.backends.mba.hexrays_island import lower_hexrays_island
from d810.hexrays.ir.minsn_utils import minsn_to_ast
from d810.mba.provider_outcome import (
    MbaProviderKind,
    MbaProviderOutcome,
    ProviderOutcomeStatus,
)
from d810.optimizers.microcode.instructions.handler import (
    InstructionOptimizationRule,
    InstructionOptimizer,
)


class ChainSimplificationRule(InstructionOptimizationRule):
    CATEGORY = "Chain Optimization"

    def __init__(self) -> None:
        super().__init__()
        self._attempt_started: float | None = None
        self._last_provider_outcome: MbaProviderOutcome | None = None

    def _begin_chain_attempt(self) -> None:
        """Reset observation state; the existing chain algebra remains untouched."""

        self._attempt_started = time.monotonic()
        self._last_provider_outcome = None

    @staticmethod
    def _chain_arity(mop, opcode: int) -> int:
        if mop is None or getattr(mop, "t", None) != ida_hexrays.mop_d:
            return 1
        nested = getattr(mop, "d", None)
        if nested is None or getattr(nested, "opcode", None) != opcode:
            return 1
        return ChainSimplificationRule._chain_arity(nested.l, opcode) + ChainSimplificationRule._chain_arity(nested.r, opcode)

    def _publish_chain_result(self, ins, new_ins, *, opcode: int) -> None:
        """Publish one structural-chain outcome without changing emission order."""

        if new_ins is None:
            return
        elapsed_ms = 0.0
        if self._attempt_started is not None:
            elapsed_ms = max(0.0, (time.monotonic() - self._attempt_started) * 1000.0)
        try:
            input_ast = minsn_to_ast(ins)
            output_ast = minsn_to_ast(new_ins)
            destination_size = int(ins.d.size)
            lowering = lower_hexrays_island(input_ast, destination_size=destination_size)
            if input_ast is None or output_ast is None or lowering.term is None:
                raise ValueError("native chain island profile unavailable")
            input_cost = (lowering.profile.operator_count, lowering.profile.total_node_count)
            output_lowering = lower_hexrays_island(output_ast, destination_size=destination_size)
            if output_lowering.term is None:
                raise ValueError("native chain output profile unavailable")
            self._last_provider_outcome = MbaProviderOutcome(
                provider=MbaProviderKind.STRUCTURAL_CHAIN,
                status=ProviderOutcomeStatus.APPLIED,
                fingerprint=lowering.profile.fingerprint,
                input_cost=input_cost,
                output_cost=(
                    output_lowering.profile.operator_count,
                    output_lowering.profile.total_node_count,
                ),
                elapsed_ms=elapsed_ms,
                metadata={
                    "chain_opcode": int(opcode),
                    "flattened_arity": self._chain_arity(ins.l, opcode)
                    + self._chain_arity(ins.r, opcode),
                    "rules_attempted": 1,
                    "rules_applied": 1,
                },
            )
        except Exception:
            self._last_provider_outcome = MbaProviderOutcome(
                provider=MbaProviderKind.STRUCTURAL_CHAIN,
                status=ProviderOutcomeStatus.RECONSTRUCTION_FAILED,
                fingerprint="profile_unavailable",
                elapsed_ms=elapsed_ms,
                refusal_reason="profile_unavailable",
                metadata={
                    "chain_opcode": int(opcode),
                    "rules_attempted": 1,
                    "rules_applied": 1,
                },
            )

    def execution_metadata(self) -> dict[str, object]:
        outcome = self._last_provider_outcome
        return {} if outcome is None else {"mba_provider_outcome": outcome.to_dict()}

    @abc.abstractmethod
    def check_and_replace(self, blk, ins):
        """Return a replacement instruction if the rule matches, otherwise None."""


class ChainOptimizer(InstructionOptimizer):
    RULE_CLASSES = [ChainSimplificationRule]

    def __init__(self, maturities, stats, log_dir=None):
        super().__init__(maturities, stats, log_dir)
        # Only consider binary associative ops chains
        self._allowed_root_opcodes = {
            ida_hexrays.m_xor,
            ida_hexrays.m_and,
            ida_hexrays.m_or,
            ida_hexrays.m_add,
            ida_hexrays.m_sub,
        }

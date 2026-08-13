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
        self.provider_outcome_history: list[MbaProviderOutcome] = []
        self._attempt_outcome_index: int | None = None

    def _begin_chain_attempt(self) -> None:
        """Reset observation state; the existing chain algebra remains untouched."""

        self._attempt_started = time.monotonic()
        self._last_provider_outcome = None
        self._attempt_outcome_index = None

    def _publish_provider_outcome(self, outcome: MbaProviderOutcome) -> None:
        self._last_provider_outcome = outcome
        if self._attempt_outcome_index is None:
            self.provider_outcome_history.append(outcome)
            self._attempt_outcome_index = len(self.provider_outcome_history) - 1
        else:
            self.provider_outcome_history[self._attempt_outcome_index] = outcome

    @staticmethod
    def _chain_arity(mop, opcode: int) -> int:
        if mop is None or getattr(mop, "t", None) != ida_hexrays.mop_d:
            return 1
        nested = getattr(mop, "d", None)
        if nested is None or getattr(nested, "opcode", None) != opcode:
            return 1
        return ChainSimplificationRule._chain_arity(nested.l, opcode) + ChainSimplificationRule._chain_arity(nested.r, opcode)

    @staticmethod
    def _arithmetic_arity(mop) -> int:
        """Count operands exactly as ``ArithmeticChainSimplification.add_mop``."""

        if mop is None or getattr(mop, "t", None) != ida_hexrays.mop_d:
            return 1
        nested = getattr(mop, "d", None)
        opcode = getattr(nested, "opcode", None)
        if opcode in (ida_hexrays.m_add, ida_hexrays.m_sub):
            return (
                ChainSimplificationRule._arithmetic_arity(nested.l)
                + ChainSimplificationRule._arithmetic_arity(nested.r)
            )
        if opcode == ida_hexrays.m_neg:
            return ChainSimplificationRule._arithmetic_arity(nested.l)
        return 1

    @classmethod
    def _flattened_arity(cls, ins, opcode: int) -> int:
        if opcode in (ida_hexrays.m_add, ida_hexrays.m_sub):
            return cls._arithmetic_arity(ins.l) + cls._arithmetic_arity(ins.r)
        return cls._chain_arity(ins.l, opcode) + cls._chain_arity(ins.r, opcode)

    def _publish_chain_result(self, ins, new_ins, *, opcode: int) -> None:
        """Publish one structural-chain outcome without changing emission order."""

        elapsed_ms = 0.0
        if self._attempt_started is not None:
            elapsed_ms = max(0.0, (time.monotonic() - self._attempt_started) * 1000.0)
        try:
            input_ast = minsn_to_ast(ins)
            destination_size = int(ins.d.size)
            lowering = lower_hexrays_island(input_ast, destination_size=destination_size)
            if input_ast is None or lowering.term is None:
                raise ValueError("native chain island profile unavailable")
            input_cost = (lowering.profile.operator_count, lowering.profile.total_node_count)
            if new_ins is None:
                self._publish_provider_outcome(MbaProviderOutcome(
                    provider=MbaProviderKind.STRUCTURAL_CHAIN,
                    status=ProviderOutcomeStatus.UNCHANGED,
                    fingerprint=lowering.profile.fingerprint,
                    input_cost=input_cost,
                    elapsed_ms=elapsed_ms,
                    refusal_reason="no_match",
                    metadata={
                        "chain_opcode": int(opcode),
                        "flattened_arity": self._flattened_arity(ins, opcode),
                        "rules_attempted": 1,
                        "rules_applied": 0,
                    },
                ))
                return
            output_ast = minsn_to_ast(new_ins)
            if output_ast is None:
                raise ValueError("native chain output profile unavailable")
            output_lowering = lower_hexrays_island(output_ast, destination_size=destination_size)
            if output_lowering.term is None:
                raise ValueError("native chain output profile unavailable")
            self._publish_provider_outcome(MbaProviderOutcome(
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
                    "flattened_arity": self._flattened_arity(ins, opcode),
                    "rules_attempted": 1,
                    "rules_applied": 1,
                },
            ))
        except Exception:
            self._publish_provider_outcome(MbaProviderOutcome(
                provider=MbaProviderKind.STRUCTURAL_CHAIN,
                status=ProviderOutcomeStatus.RECONSTRUCTION_FAILED,
                fingerprint="profile_unavailable",
                elapsed_ms=elapsed_ms,
                refusal_reason="profile_unavailable",
                metadata={
                    "chain_opcode": int(opcode),
                    "rules_attempted": 1,
                    "rules_applied": int(new_ins is not None),
                },
            ))

    def _publish_chain_error(self, ins, *, opcode: int, exc: RuntimeError) -> None:
        """Record a simplifier exception while preserving its existing control flow."""

        elapsed_ms = 0.0
        if self._attempt_started is not None:
            elapsed_ms = max(0.0, (time.monotonic() - self._attempt_started) * 1000.0)
        input_cost = None
        fingerprint = "profile_unavailable"
        try:
            input_ast = minsn_to_ast(ins)
            lowering = lower_hexrays_island(
                input_ast,
                destination_size=int(ins.d.size),
            )
            if input_ast is not None and lowering.term is not None:
                fingerprint = lowering.profile.fingerprint
                input_cost = (
                    lowering.profile.operator_count,
                    lowering.profile.total_node_count,
                )
        except Exception:
            pass
        self._publish_provider_outcome(MbaProviderOutcome(
            provider=MbaProviderKind.STRUCTURAL_CHAIN,
            status=ProviderOutcomeStatus.ERROR,
            fingerprint=fingerprint,
            input_cost=input_cost,
            elapsed_ms=elapsed_ms,
            refusal_reason=type(exc).__name__,
            metadata={
                "chain_opcode": int(opcode),
                "rules_attempted": 1,
                "rules_applied": 0,
                "error_class": type(exc).__name__,
                "error_message": str(exc),
            },
        ))

    def _run_chain_attempt(self, ins, *, opcode: int, simplify):
        """Observe chain failures but retain the former raised exception behavior."""

        try:
            new_ins = simplify()
        except RuntimeError as exc:
            self._publish_chain_error(ins, opcode=opcode, exc=exc)
            raise
        self._publish_chain_result(ins, new_ins, opcode=opcode)
        return new_ins

    def execution_metadata(self) -> dict[str, object]:
        outcome = self._last_provider_outcome
        return {} if outcome is None else {"mba_provider_outcome": outcome.to_dict()}

    def provider_outcomes(self) -> tuple[MbaProviderOutcome, ...]:
        """Return one final outcome for each structural-chain attempt."""

        return tuple(self.provider_outcome_history)

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

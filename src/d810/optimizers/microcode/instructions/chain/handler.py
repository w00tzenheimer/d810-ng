import abc
import time
from dataclasses import replace

import ida_hexrays

from d810.backends.mba.native_mba_term_view import NativeMbaTermView
from d810.mba.provider_outcome import (
    MbaProviderKind,
    MbaProviderOutcome,
    ProviderOutcomeStatus,
)
from d810.mba.provider_history import ProviderOutcomeHistory
from d810.mba.native_corpus_capture import native_profile_metadata
from d810.optimizers.microcode.instructions.handler import (
    InstructionOptimizationRule,
    InstructionOptimizer,
)


class ChainSimplificationRule(InstructionOptimizationRule):
    CATEGORY = "Chain Optimization"
    PORTFOLIO_TIER = "fast"

    def __init__(self) -> None:
        super().__init__()
        self._attempt_started: float | None = None
        self._last_provider_outcome: MbaProviderOutcome | None = None
        self.provider_outcome_history = ProviderOutcomeHistory[MbaProviderOutcome]()
        self._attempt_outcome_index: int | None = None
        self._provider_outcome_capture_depth = 0

    def _begin_chain_attempt(self) -> None:
        """Reset observation state; the existing chain algebra remains untouched."""

        self._attempt_started = time.monotonic()
        self._last_provider_outcome = None
        self._attempt_outcome_index = None

    def _publish_provider_outcome(self, outcome: MbaProviderOutcome) -> None:
        self._last_provider_outcome = outcome
        if not self._provider_outcome_capture_enabled():
            return
        if self._attempt_outcome_index is None:
            self._attempt_outcome_index = self.provider_outcome_history.append(outcome)
        else:
            self.provider_outcome_history.replace(self._attempt_outcome_index, outcome)

    def _provider_outcome_capture_enabled(self) -> bool:
        return self._provider_outcome_capture_depth > 0

    def begin_provider_outcome_capture(self) -> None:
        if not self._provider_outcome_capture_enabled():
            self.provider_outcome_history.clear()
        self._provider_outcome_capture_depth += 1

    def end_provider_outcome_capture(self) -> None:
        if self._provider_outcome_capture_depth <= 0:
            raise RuntimeError("provider outcome capture was not active")
        self._provider_outcome_capture_depth -= 1

    @staticmethod
    def _native_profile_metadata(profile) -> dict[str, object]:
        """Attach capture evidence only for complete native lowering profiles."""

        try:
            return {"native_profile": native_profile_metadata(profile)}
        except (AttributeError, TypeError, ValueError):
            return {}

    @staticmethod
    def _chain_arity(mop, opcode: int) -> int:
        if mop is None or getattr(mop, "t", None) != ida_hexrays.mop_d:
            return 1
        nested = getattr(mop, "d", None)
        if nested is None or getattr(nested, "opcode", None) != opcode:
            return 1
        return ChainSimplificationRule._chain_arity(
            nested.l, opcode
        ) + ChainSimplificationRule._chain_arity(nested.r, opcode)

    @staticmethod
    def _arithmetic_arity(mop) -> int:
        """Count operands exactly as ``ArithmeticChainSimplification.add_mop``."""

        if mop is None or getattr(mop, "t", None) != ida_hexrays.mop_d:
            return 1
        nested = getattr(mop, "d", None)
        opcode = getattr(nested, "opcode", None)
        if opcode in (ida_hexrays.m_add, ida_hexrays.m_sub):
            return ChainSimplificationRule._arithmetic_arity(
                nested.l
            ) + ChainSimplificationRule._arithmetic_arity(nested.r)
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

        # A nonmatch has no rule-fired statistics or execution metadata to
        # publish.  Native corpus capture is the sole consumer of unchanged
        # provider rows, so avoid constructing and canonicalizing a complete
        # native MBA view on the normal hot path when capture is inactive.
        if new_ins is None and not self._provider_outcome_capture_enabled():
            self._last_provider_outcome = None
            self._attempt_outcome_index = None
            return

        elapsed_ms = 0.0
        if self._attempt_started is not None:
            elapsed_ms = max(0.0, (time.monotonic() - self._attempt_started) * 1000.0)
        try:
            input_profile = self._read_native_chain_profile(ins)
            if input_profile is None:
                raise ValueError("native chain island profile unavailable")
            input_cost = (
                input_profile.operator_count,
                input_profile.total_node_count,
            )
            native_metadata = self._native_profile_metadata(input_profile)
            if new_ins is None:
                self._publish_provider_outcome(
                    MbaProviderOutcome(
                        provider=MbaProviderKind.STRUCTURAL_CHAIN,
                        status=ProviderOutcomeStatus.UNCHANGED,
                        fingerprint=input_profile.fingerprint,
                        input_cost=input_cost,
                        elapsed_ms=elapsed_ms,
                        refusal_reason="no_match",
                        metadata={
                            **native_metadata,
                            "chain_opcode": int(opcode),
                            "flattened_arity": self._flattened_arity(ins, opcode),
                            "rules_attempted": 1,
                            "rules_applied": 0,
                        },
                    )
                )
                return
            output_profile = self._read_native_chain_profile(new_ins)
            if output_profile is None:
                raise ValueError("native chain output profile unavailable")
            self._publish_provider_outcome(
                MbaProviderOutcome(
                    provider=MbaProviderKind.STRUCTURAL_CHAIN,
                    status=ProviderOutcomeStatus.IMPROVED,
                    fingerprint=input_profile.fingerprint,
                    input_cost=input_cost,
                    output_cost=(
                        output_profile.operator_count,
                        output_profile.total_node_count,
                    ),
                    elapsed_ms=elapsed_ms,
                    metadata={
                        **native_metadata,
                        "chain_opcode": int(opcode),
                        "flattened_arity": self._flattened_arity(ins, opcode),
                        "rules_attempted": 1,
                        "rules_applied": 1,
                    },
                )
            )
        except Exception:
            self._publish_provider_outcome(
                MbaProviderOutcome(
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
                )
            )

    def _publish_chain_error(self, ins, *, opcode: int, exc: RuntimeError) -> None:
        """Record a simplifier exception while preserving its existing control flow."""

        elapsed_ms = 0.0
        if self._attempt_started is not None:
            elapsed_ms = max(0.0, (time.monotonic() - self._attempt_started) * 1000.0)
        input_cost = None
        fingerprint = "profile_unavailable"
        try:
            profile = self._read_native_chain_profile(ins)
            if profile is not None:
                fingerprint = profile.fingerprint
                input_cost = (
                    profile.operator_count,
                    profile.total_node_count,
                )
        except Exception:
            pass
        self._publish_provider_outcome(
            MbaProviderOutcome(
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
            )
        )

    @staticmethod
    def _read_native_chain_profile(ins):
        """Return the shared direct native profile without constructing an AST."""

        destination = getattr(ins, "d", None)
        destination_size = getattr(destination, "size", None)
        if type(destination_size) is not int:
            return None
        result = NativeMbaTermView.from_instruction(
            ins, destination_size=destination_size
        )
        return result.profile if result.view is not None else None

    def _finalize_candidate_outcome(
        self, *, accepted: bool, reason: str | None = None
    ) -> None:
        """Upgrade only the candidate that survived the outer optinsn guards."""

        outcome = self._last_provider_outcome
        if outcome is None or outcome.status is not ProviderOutcomeStatus.IMPROVED:
            return
        metadata = dict(outcome.metadata or {})
        metadata["mutation_outcome"] = "accepted" if accepted else "rejected"
        if reason is not None:
            metadata["mutation_rejection_reason"] = reason
        self._publish_provider_outcome(
            replace(
                outcome,
                status=(
                    ProviderOutcomeStatus.APPLIED
                    if accepted
                    else ProviderOutcomeStatus.IMPROVED
                ),
                refusal_reason=None if accepted else reason,
                metadata=metadata,
            )
        )

    def record_mutation_accepted(self) -> None:
        self._finalize_candidate_outcome(accepted=True)

    def record_mutation_rejected(self, reason: str) -> None:
        self._finalize_candidate_outcome(accepted=False, reason=reason)

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

        return self.provider_outcome_history.outcomes()

    def provider_outcome_cursor(self) -> int:
        """Return a capture cursor for the bounded structural-chain history."""

        return self.provider_outcome_history.cursor

    def provider_outcomes_since(self, cursor: int) -> tuple[MbaProviderOutcome, ...]:
        """Return one exact retained capture delta or fail closed on eviction."""

        return self.provider_outcome_history.since(cursor)

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

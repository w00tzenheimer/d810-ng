import abc
from d810.core import typing

import ida_hexrays

from d810.backends.ast.z3_proof_policy import Z3ProofPolicy
from d810.core.observability import emit as emit_observation
from d810.core.observability_events import Z3PredicateProofObserved
from d810.hexrays.expr.ast import AstNode, AstNodeProtocol
from d810.optimizers.microcode.instructions.handler import (
    GenericPatternRule,
    InstructionOptimizer,
)


class Z3Rule(GenericPatternRule):
    """Base class for Z3-based optimization rules.

    Z3 rules can prove properties about expressions (e.g., always zero, always equal)
    using Z3 theorem proving. They have access to the current block and instruction
    context for backward tracking of register/stack variable definitions.
    """

    CATEGORY = "Z3 Simplification"
    PROOF_TRANSFORM_ID: str | None = None

    def __init__(self):
        super().__init__()
        # Context for backward tracking (set during check_and_replace)
        self._current_blk: ida_hexrays.mblock_t | None = None
        self._current_ins: ida_hexrays.minsn_t | None = None
        self._z3_proof_policy = Z3ProofPolicy()

    def configure(self, kwargs) -> None:
        """Configure maturity and an independent policy for generic predicates."""
        config = dict(kwargs or {})
        policy = self._z3_proof_policy
        if self.PROOF_TRANSFORM_ID is not None:
            max_expression_nodes = config.pop("max_expression_nodes", 256)
            proof_timeout_ms = config.pop("proof_timeout_ms", 50)
            try:
                policy = Z3ProofPolicy(
                    max_expression_nodes=max_expression_nodes,
                    proof_timeout_ms=proof_timeout_ms,
                )
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"{self.PROOF_TRANSFORM_ID} has an invalid Z3 proof policy: {exc}"
                ) from exc
        super().configure(config)
        self._z3_proof_policy = policy

    @property
    def z3_proof_policy(self) -> Z3ProofPolicy:
        """Return the immutable policy configured for this rule."""
        return self._z3_proof_policy

    def observe_z3_proof(self, operation: str, result: object) -> None:
        """Publish one typed proof receipt without affecting rule matching."""
        status = getattr(getattr(result, "status", None), "value", None)
        if status is None:
            status = str(getattr(result, "status", "abstained"))
        reason = getattr(getattr(result, "reason", None), "value", None)
        if reason is None:
            raw_reason = getattr(result, "reason", None)
            reason = raw_reason if isinstance(raw_reason, str) else None
        if status == "abstained" and not reason:
            # A malformed fake/backend result must still produce a valid
            # abstention receipt; conclusive results intentionally retain the
            # typed API's ``None`` reason.
            reason = "proof_abstained"
        mba = getattr(self._current_blk, "mba", None)
        func_ea = int(getattr(mba, "entry_ea", 0) or 0)
        emit_observation(
            Z3PredicateProofObserved(
                func_ea=func_ea,
                transform_id=str(self.PROOF_TRANSFORM_ID or self.name),
                operation=str(operation),
                max_expression_nodes=self._z3_proof_policy.max_expression_nodes,
                proof_timeout_ms=self._z3_proof_policy.proof_timeout_ms,
                observed_expression_nodes=getattr(
                    result, "observed_expression_nodes", None
                ),
                elapsed_ms=float(getattr(result, "elapsed_ms", 0.0)),
                status=str(status),
                reason=reason,
            )
        )

    @property
    @abc.abstractmethod
    def PATTERN(self) -> AstNode:
        """Return the pattern to match."""

    @property
    @abc.abstractmethod
    def REPLACEMENT_PATTERN(self) -> AstNode:
        """Return the replacement pattern."""

    @typing.override
    def check_and_replace(
        self, blk: ida_hexrays.mblock_t, instruction: ida_hexrays.minsn_t
    ) -> ida_hexrays.minsn_t | None:
        """Override to store context for backward tracking."""
        # Store context so check_candidate can access blk/ins for MopTracker
        self._current_blk = blk
        self._current_ins = instruction
        try:
            return super().check_and_replace(blk, instruction)
        finally:
            # Clear context after use
            self._current_blk = None
            self._current_ins = None


class Z3Optimizer(InstructionOptimizer):
    RULE_CLASSES = [Z3Rule]

    def __init__(self, maturities, stats, log_dir=None):
        super().__init__(maturities, stats, log_dir)
        self._allowed_root_opcodes: set[int] = set()
        # Track if any rule has no PATTERN (pattern-less rules match any opcode)
        self._has_patternless_rule: bool = False

    def add_rule(self, rule: Z3Rule) -> bool:  # type: ignore[override]
        ok = super().add_rule(rule)
        if not ok:
            return False
        try:
            pat = rule.PATTERN
            if pat is None:
                # Rule has no PATTERN - it uses custom check_and_replace logic
                # and can match any opcode, so disable the pre-filter entirely
                # by clearing _allowed_root_opcodes (also checked by base class)
                self._has_patternless_rule = True
                self._allowed_root_opcodes.clear()
            # Use Protocol for hot-reload safety
            elif (
                isinstance(pat, AstNodeProtocol) and pat.opcode is not None
            ):  # Only add to filter if we haven't disabled it
                if not self._has_patternless_rule:
                    self._allowed_root_opcodes.add(int(pat.opcode))
        except Exception:
            pass
        return True

    def get_optimized_instruction(
        self,
        blk: ida_hexrays.mblock_t,
        ins: ida_hexrays.minsn_t,
        *,
        allowed_rule_names: frozenset[str] | None = None,
        scheduled_rule_names: frozenset[str] | None = None,
    ):  # type: ignore[override]
        # The opcode pre-filter is now handled by clearing _allowed_root_opcodes
        # when a patternless rule is added, which also disables the base class filter.
        return super().get_optimized_instruction(
            blk,
            ins,
            allowed_rule_names=allowed_rule_names,
            scheduled_rule_names=scheduled_rule_names,
        )

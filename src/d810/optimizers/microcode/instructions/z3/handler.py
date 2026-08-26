import abc
import functools
from d810.core import typing

import ida_hexrays

from d810.backends.ast.z3_proof_policy import Z3ProofPolicy
from d810.backends.ast.z3 import Z3MopProver
from d810.analyses.value_flow.call_return_value import refine_call_result
from d810.core.observability import emit as emit_observation
from d810.core.observability_events import Z3PredicateProofObserved
from d810.core.z3_proof import Z3ProofAbstentionReason, Z3ProofStatus
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
        self._definition_search_ins: ida_hexrays.minsn_t | None = None
        self._z3_proof_policy = Z3ProofPolicy()
        self._validated_fact_view = None

    @property
    def validated_fact_view(self):
        """Return the callback-local validated fact view, if any."""
        return self._validated_fact_view

    def bind_validated_fact_view(self, view) -> None:
        """Bind or clear the callback-local fact view."""
        self._validated_fact_view = view

    def make_z3_mop_prover(self, *, prover_cls=None) -> Z3MopProver:
        """Construct a prover carrying this rule's transient context."""
        refiner = None
        if self.validated_fact_view is not None:
            refiner = functools.partial(
                refine_call_result,
                view=self.validated_fact_view,
            )
        constructor = Z3MopProver if prover_cls is None else prover_cls
        kwargs = {
            "blk": self._current_blk,
            "ins": self.definition_search_ins,
            "policy": self.z3_proof_policy,
        }
        if refiner is not None:
            kwargs["call_result_refiner"] = refiner
        return constructor(
            **kwargs,
        )

    def configure(self, kwargs) -> None:
        """Configure maturity and an independent policy for generic predicates."""
        config = dict(kwargs or {})
        policy = self._z3_proof_policy
        if self.PROOF_TRANSFORM_ID is not None:
            default_policy = Z3ProofPolicy()
            max_expression_nodes = config.pop(
                "max_expression_nodes", default_policy.max_expression_nodes
            )
            proof_timeout_ms = config.pop(
                "proof_timeout_ms", default_policy.proof_timeout_ms
            )
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

    @property
    def definition_search_ins(self) -> ida_hexrays.minsn_t | None:
        """Return the owner instruction used for contextual def-use lookup."""
        if self._definition_search_ins is not None:
            return self._definition_search_ins
        # Keep direct rule tests and legacy callers safe while the transient
        # context is not bound by ``check_and_replace``.
        return self._current_ins

    def observe_z3_proof(self, operation: str, result: object) -> bool:
        """Publish a valid proof receipt, rejecting malformed results."""
        try:
            status = getattr(result, "status", None)
            reason = getattr(result, "reason", None)
        except Exception:
            return False
        if type(status) is not Z3ProofStatus:
            return False
        if status is Z3ProofStatus.ABSTAINED:
            if type(reason) is not Z3ProofAbstentionReason:
                return False
        elif reason is not None:
            return False
        try:
            mba = getattr(self._current_blk, "mba", None)
            func_ea = int(getattr(mba, "entry_ea", 0) or 0)
            event = Z3PredicateProofObserved(
                func_ea=func_ea,
                transform_id=str(self.PROOF_TRANSFORM_ID or self.name),
                operation=str(operation),
                max_expression_nodes=self._z3_proof_policy.max_expression_nodes,
                proof_timeout_ms=self._z3_proof_policy.proof_timeout_ms,
                observed_expression_nodes=getattr(
                    result, "observed_expression_nodes", None
                ),
                elapsed_ms=float(getattr(result, "elapsed_ms", 0.0)),
                status=status,
                reason=reason,
            )
        except (AttributeError, TypeError, ValueError):
            return False
        emit_observation(event)
        return True

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
        self,
        blk: ida_hexrays.mblock_t,
        instruction: ida_hexrays.minsn_t,
        *,
        contextual_anchor_ins: ida_hexrays.minsn_t | None = None,
    ) -> ida_hexrays.minsn_t | None:
        """Override to store context for backward tracking."""
        # Store context so check_candidate can access blk/ins for MopTracker
        self._current_blk = blk
        self._current_ins = instruction
        self._definition_search_ins = (
            instruction if contextual_anchor_ins is None else contextual_anchor_ins
        )
        try:
            return super().check_and_replace(blk, instruction)
        finally:
            # Clear context after use
            self._current_blk = None
            self._current_ins = None
            self._definition_search_ins = None

    @typing.override
    def check_and_replace_with_context(
        self,
        blk: ida_hexrays.mblock_t,
        instruction: ida_hexrays.minsn_t,
        *,
        contextual_anchor_ins: ida_hexrays.minsn_t | None = None,
    ) -> ida_hexrays.minsn_t | None:
        return self.check_and_replace(
            blk,
            instruction,
            contextual_anchor_ins=contextual_anchor_ins,
        )


class Z3Optimizer(InstructionOptimizer):
    RULE_CLASSES = [Z3Rule]

    def __init__(self, maturities, stats, log_dir=None):
        super().__init__(maturities, stats, log_dir)
        self._allowed_root_opcodes: set[int] = set()
        # Track if any rule has no PATTERN (pattern-less rules match any opcode)
        self._has_patternless_rule: bool = False
        self._validated_fact_view = None

    def bind_validated_fact_view(self, view) -> None:
        """Bind a callback-local view to all current and future rules."""
        self._validated_fact_view = view
        for rule in self.rules:
            binder = getattr(rule, "bind_validated_fact_view", None)
            if callable(binder):
                binder(view)

    def add_rule(self, rule: Z3Rule) -> bool:  # type: ignore[override]
        ok = super().add_rule(rule)
        if not ok:
            return False
        binder = getattr(rule, "bind_validated_fact_view", None)
        if callable(binder):
            binder(self._validated_fact_view)
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

    def reset_rules(self) -> None:
        super().reset_rules()
        self._allowed_root_opcodes.clear()
        self._has_patternless_rule = False

    def get_optimized_instruction(
        self,
        blk: ida_hexrays.mblock_t,
        ins: ida_hexrays.minsn_t,
        *,
        contextual_anchor_ins: ida_hexrays.minsn_t | None = None,
        allowed_rule_names: frozenset[str] | None = None,
        scheduled_rule_names: frozenset[str] | None = None,
    ):  # type: ignore[override]
        # The opcode pre-filter is now handled by clearing _allowed_root_opcodes
        # when a patternless rule is added, which also disables the base class filter.
        return super().get_optimized_instruction(
            blk,
            ins,
            contextual_anchor_ins=contextual_anchor_ins,
            allowed_rule_names=allowed_rule_names,
            scheduled_rule_names=scheduled_rule_names,
        )

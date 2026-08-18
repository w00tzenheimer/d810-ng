from __future__ import annotations

import abc

import ida_hexrays

from d810.core import Registrant, getLogger, typing
from d810.errors import D810Exception
from d810.hexrays.expr.ast import AstNode
from d810.hexrays.ir.minsn_utils import minsn_to_ast
from d810.hexrays.utils.hexrays_formatters import format_minsn_t, maturity_to_string
from d810.ir.maturity import IRMaturity
from d810.optimizers.microcode.handler import OptimizationRule
from d810.passes.scheduler import RunLater

if typing.TYPE_CHECKING:
    from d810.core import OptimizationStatistics

d810_logger = getLogger("d810")
optimizer_logger = getLogger("d810.optimizer")


class InstructionOptimizationRule(OptimizationRule, Registrant, abc.ABC):
    """Base class for *instruction*-level optimizations.

    This class is now marked as *abstract* so that it is skipped when
    collecting concrete rules for presentation in the GUI.
    """

    CATEGORY = "Instruction"

    def __init__(self):
        super().__init__()
        self.maturities = []
        self._run_later_requests: list[RunLater] = []

    def run_later(self, at: IRMaturity, reason: str = "") -> None:
        """Request that this rule run again at a later maturity."""
        self._run_later_requests.append(RunLater(at=at, reason=reason))

    def drain_run_later_requests(self) -> tuple[RunLater, ...]:
        """Return and clear this rule's queued run-later requests."""
        if not self._run_later_requests:
            return ()
        requests = tuple(self._run_later_requests)
        self._run_later_requests.clear()
        return requests

    def execution_metadata(self) -> dict[str, typing.Any]:
        """Return metadata for the most recent successful replacement."""
        return {}

    def record_mutation_accepted(self) -> None:
        """Finalize telemetry after the outer optinsn owner accepts a candidate.

        Rule implementations that emit provider outcomes use this hook to
        upgrade a discovered strict improvement to an applied mutation.  The
        default is intentionally a no-op for legacy instruction rules.
        """

    def record_mutation_rejected(self, reason: str) -> None:
        """Retain a non-applied candidate outcome after an outer safety veto."""

        del reason

    @abc.abstractmethod
    def check_and_replace(self, blk, ins):
        """Return a replacement instruction if the rule matches, otherwise None."""

    def check_and_replace_with_context(
        self,
        blk,
        ins,
        *,
        contextual_anchor_ins: ida_hexrays.minsn_t | None = None,
    ):
        """Run the rule with an optional owner instruction for nested context.

        Most instruction rules only inspect the candidate instruction itself, so
        they retain the legacy ``check_and_replace`` call.  Context-sensitive
        rules may override this hook to distinguish the nested candidate being
        rewritten from the top-level instruction that owns its def-use context.
        """
        del contextual_anchor_ins
        return self.check_and_replace(blk, ins)


class GenericPatternRule(InstructionOptimizationRule):
    PATTERNS: list[AstNode] | None = None

    def __init__(self):
        super().__init__()
        self.pattern_candidates = [self.PATTERN] if self.PATTERN is not None else []
        if self.PATTERNS is not None:
            self.pattern_candidates += self.PATTERNS

    @abc.abstractmethod
    def check_candidate(self, candidate: AstNode) -> bool:
        """Return True if the candidate matches the rule, otherwise False."""

    @property
    @abc.abstractmethod
    def PATTERN(self) -> AstNode:
        """Return the pattern to match."""

    @property
    @abc.abstractmethod
    def REPLACEMENT_PATTERN(self) -> AstNode:
        """Return the replacement pattern."""

    def get_valid_candidates(self, instruction: ida_hexrays.minsn_t, stop_early=True):
        valid_candidates = []
        tmp = minsn_to_ast(instruction)
        if tmp is None:
            return []
        for candidate_pattern in self.pattern_candidates:
            if not candidate_pattern:
                continue
            # Use a read-only check first for structural matching (no mops copied)
            if not candidate_pattern.check_pattern_and_copy_mops(tmp, read_only=True):
                continue
            # If the read-only check passes, then we can create a mutable copy
            # and populate mops
            mutable_candidate = candidate_pattern.clone()
            if not mutable_candidate.check_pattern_and_copy_mops(tmp):
                continue
            # Check candidate AFTER mops are populated, since check_candidate
            # may need to access leaf mops (e.g., to check segment permissions)
            if not self.check_candidate(mutable_candidate):
                continue
            valid_candidates.append(mutable_candidate)
            if stop_early:
                return valid_candidates
        return []

    def get_replacement(self, candidate: AstNode) -> ida_hexrays.minsn_t | None:
        # REPLACEMENT_PATTERN is implemented as a @property (or a method
        # masquerading as an attribute) that builds a brand-new AstNode tree
        # every time it is accessed.
        #
        # the issue is `self.REPLACEMENT_PATTERN` creates new nodes *EVERY* time because it
        # is a property. When invoked, it then re-instantiates the objects, so it loses
        # anything that modified it before.
        repl_pat = self.REPLACEMENT_PATTERN
        if not repl_pat:
            if optimizer_logger.debug_on:
                optimizer_logger.debug(
                    "No replacement pattern for rule %s",
                    self.NAME,
                )
            return None
        is_ok = repl_pat.update_leafs_mop(candidate)
        if optimizer_logger.debug_on:
            optimizer_logger.debug(
                "Replacement pattern updated leaf mops OK?: %s",
                is_ok,
            )
        if not is_ok:
            return None
        if not candidate.ea:
            if optimizer_logger.debug_on:
                optimizer_logger.debug(
                    "No EA for candidate %s",
                    candidate,
                )
            return None
        new_ins = repl_pat.create_minsn(candidate.ea, candidate.dst_mop)
        if optimizer_logger.debug_on:
            optimizer_logger.debug(
                "Replacement instruction created: %s",
                format_minsn_t(new_ins),
            )
        return new_ins

    @typing.override
    def check_and_replace(
        self, blk: ida_hexrays.mblock_t, instruction: ida_hexrays.minsn_t
    ) -> ida_hexrays.minsn_t | None:
        valid_candidates = self.get_valid_candidates(instruction, stop_early=True)
        if len(valid_candidates) == 0:
            return None
        new_instruction = self.get_replacement(valid_candidates[0])
        return new_instruction

    @property
    def description(self):
        if self.DESCRIPTION is not None:
            return self.DESCRIPTION
        if (self.PATTERN is None) or (self.REPLACEMENT_PATTERN is None):
            return ""
        self.PATTERN.reset_mops()
        self.REPLACEMENT_PATTERN.reset_mops()
        return "{0} => {1}".format(self.PATTERN, self.REPLACEMENT_PATTERN)


T_Rule = typing.TypeVar("T_Rule", bound=InstructionOptimizationRule)


class _InsertionOrderedRuleSet(typing.Generic[T_Rule]):
    """Deduplicate rules without discarding their registration order."""

    def __init__(self) -> None:
        self._rules: dict[T_Rule, None] = {}

    def add(self, rule: T_Rule) -> None:
        self._rules.setdefault(rule, None)

    def __contains__(self, rule: object) -> bool:
        return rule in self._rules

    def __iter__(self) -> typing.Iterator[T_Rule]:
        return iter(self._rules)

    def __len__(self) -> int:
        return len(self._rules)


class InstructionOptimizer(Registrant, typing.Generic[T_Rule]):
    RULE_CLASSES: list[typing.Type[T_Rule]] = []
    NAME = None

    def __init__(
        self, maturities: list[int], stats: OptimizationStatistics, log_dir=None
    ):
        self.rules = _InsertionOrderedRuleSet[T_Rule]()
        self.maturities = maturities
        self.log_dir = log_dir
        self.cur_maturity = ida_hexrays.MMAT_PREOPTIMIZED
        # Centralized statistics collector injected by the manager
        self.stats = stats
        self._run_later_callback = None
        # The adapter populates this with the rules that closed a rewrite
        # cycle at the current instruction site.  It is deliberately a
        # rule-level quarantine: other rules can still simplify the same
        # instruction after one producer has started churning.
        self._cycle_quarantined_rule_names: frozenset[str] = frozenset()
        self.last_matched_rule_name: str | None = None
        self._pending_replacement_rule: InstructionOptimizationRule | None = None

    def set_run_later_callback(self, callback) -> None:
        self._run_later_callback = callback

    def set_cycle_quarantined_rule_names(
        self,
        rule_names: frozenset[str],
    ) -> None:
        """Set the per-callback rule quarantine supplied by the adapter."""
        self._cycle_quarantined_rule_names = frozenset(rule_names)

    def add_rule(self, rule: T_Rule) -> bool:
        """Add a rule to this optimizer if it matches RULE_CLASSES.

        Rules must inherit from one of the classes in RULE_CLASSES to be accepted.
        This ensures type safety and proper interface compliance.
        """
        # Check if rule inherits from one of RULE_CLASSES
        is_valid_rule_class = False
        for rule_class in self.RULE_CLASSES:
            if isinstance(rule, rule_class):
                is_valid_rule_class = True
                break

        if not is_valid_rule_class:
            return False

        if optimizer_logger.debug_on:
            optimizer_logger.debug("Adding rule %s", rule)
        if len(rule.maturities) == 0:
            rule.maturities = self.maturities
        self.rules.add(rule)
        return True

    def reset_rules(self) -> None:
        """Remove the live rule set before a transactional project swap."""

        self.rules.clear()

    def get_optimized_instruction(
        self,
        blk: ida_hexrays.mblock_t,
        ins: ida_hexrays.minsn_t,
        *,
        contextual_anchor_ins: ida_hexrays.minsn_t | None = None,
        allowed_rule_names: frozenset[str] | None = None,
        scheduled_rule_names: frozenset[str] | None = None,
    ) -> ida_hexrays.minsn_t | None:
        if contextual_anchor_ins is None:
            contextual_anchor_ins = ins
        self.last_matched_rule_name = None
        # uee-b7ze causality test: when ``D810_FENCE_INSN_OPT_AT_GLBOPT1``
        # is set, suppress every instruction-level optimizer (Z3 const
        # opt, PatternOptimizer, egraph rules, etc.) at MMAT_GLBOPT1
        # without touching CFG/HCC mutations.  Diagnostic-only knob:
        # used to attribute the 247->44 block drop between
        # post_bundle_stabilize and maturity_MMAT_GLBOPT1_post_d810
        # to either (a) IDA's native GLBOPT1 cleanup or (b) d810
        # instruction-level mutations making the chain look dead.
        self._pending_replacement_rule = None
        try:
            import os

            _fence_env = os.environ.get("D810_FENCE_INSN_OPT_AT_GLBOPT1", "")
            if _fence_env and blk is not None:
                _maturity = int(blk.mba.maturity)
                if _maturity == int(ida_hexrays.MMAT_GLBOPT1):
                    if not getattr(self, "_fence_logged_glbopt1", False):
                        optimizer_logger.info(
                            "FENCE_INSN_OPT_AT_GLBOPT1 active for %s"
                            " (maturity=%s, env=%r)",
                            type(self).__name__,
                            maturity_to_string(_maturity),
                            _fence_env,
                        )
                        self._fence_logged_glbopt1 = True
                    return None
        except Exception as _exc:
            try:
                optimizer_logger.warning(
                    "FENCE_INSN_OPT_AT_GLBOPT1 check raised: %s",
                    _exc,
                )
            except Exception:
                pass
        # Fast opcode gate for chain rules to avoid work on unrelated instructions
        # Only applies to optimizers whose rules expose a "TARGET_OPCODES" set.
        try:
            target_opcodes = getattr(self, "_allowed_root_opcodes", None)
            if target_opcodes:
                if ins.opcode not in target_opcodes:
                    return None
        except Exception:
            pass
        if blk is not None:
            self.cur_maturity = blk.mba.maturity
        # Optimizer-level maturity gate: skip entire optimizer if current
        # maturity is not in this optimizer's allowed maturities.
        # Per-rule maturity checks (below) provide defense-in-depth.
        scheduled_rule_names = scheduled_rule_names or frozenset()
        if self.cur_maturity not in self.maturities and not scheduled_rule_names:
            return None
        for rule in self.rules:
            rule_name = str(rule.name)
            if rule_name in self._cycle_quarantined_rule_names:
                continue
            if allowed_rule_names is not None and rule_name not in allowed_rule_names:
                continue
            if (
                self.cur_maturity not in rule.maturities
                and rule_name not in scheduled_rule_names
            ):
                continue
            try:
                try:
                    check_with_context = getattr(
                        rule,
                        "check_and_replace_with_context",
                        None,
                    )
                    if callable(check_with_context):
                        new_ins = check_with_context(
                            blk,
                            ins,
                            contextual_anchor_ins=contextual_anchor_ins,
                        )
                    else:
                        new_ins = rule.check_and_replace(blk, ins)
                finally:
                    if self._run_later_callback is not None:
                        self._run_later_callback(rule, self.cur_maturity)
                if new_ins is not None:
                    self.last_matched_rule_name = rule_name
                    optimizer_logger.info(
                        "Rule %s matched in maturity %s:",
                        rule.name,
                        maturity_to_string(self.cur_maturity),
                    )
                    optimizer_logger.info("  orig: %s", format_minsn_t(ins))
                    optimizer_logger.info("  new : %s", format_minsn_t(new_ins))

                    self._pending_replacement_rule = rule
                    return new_ins
            except RuntimeError as e:
                optimizer_logger.error(
                    "Runtime error during rule %s in maturity %s for instruction %s: %s",
                    rule,
                    maturity_to_string(self.cur_maturity),
                    format_minsn_t(ins),
                    e,
                )
            except D810Exception as e:
                optimizer_logger.error(
                    "D810Exception during rule %s in maturity %s for instruction %s: %s",
                    rule,
                    maturity_to_string(self.cur_maturity),
                    format_minsn_t(ins),
                    e,
                )
        return None

    def record_mutation_accepted(self) -> None:
        """Publish a rule firing only after the outer owner accepts the swap."""

        rule = self._pending_replacement_rule
        if rule is not None:
            rule.record_mutation_accepted()
            if self.stats is not None:
                self.stats.record_rule_fired(
                    rule=rule,
                    optimizer=self.name,
                    maturity=self.cur_maturity,
                    **rule.execution_metadata(),
                )
        self._pending_replacement_rule = None

    def record_mutation_rejected(self, reason: str) -> None:
        """Preserve a candidate as non-applied when an outer guard vetoes it."""

        rule = self._pending_replacement_rule
        if rule is not None:
            rule.record_mutation_rejected(reason)
        self._pending_replacement_rule = None

    @property
    def name(self):
        if self.NAME is not None:
            return self.NAME
        return self.__class__.__name__


# Note: VerifiableRule instances are registered in RULE_REGISTRY (d810.mba.rules)
# and injected into PatternOptimizer at construction time by InstructionOptimizerManager.
# This avoids duck typing and keeps the registration explicit.

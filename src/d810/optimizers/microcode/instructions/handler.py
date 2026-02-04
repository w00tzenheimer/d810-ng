from __future__ import annotations

import abc
import typing

import ida_hexrays

from d810.core import Registrant, getLogger, typing
from d810.errors import D810Exception
from d810.expr.ast import AstNode, minsn_to_ast
from d810.hexrays.hexrays_formatters import format_minsn_t, maturity_to_string
from d810.optimizers.microcode.handler import OptimizationRule

if typing.TYPE_CHECKING:
    from d810.core import OptimizationStatistics

d810_logger = getLogger("D810")
optimizer_logger = getLogger("D810.optimizer")


class InstructionOptimizationRule(OptimizationRule, Registrant, abc.ABC):
    """Base class for *instruction*-level optimizations.

    This class is now marked as *abstract* so that it is skipped when
    collecting concrete rules for presentation in the GUI.
    """

    def __init__(self):
        super().__init__()
        self.maturities = []

    @abc.abstractmethod
    def check_and_replace(self, blk, ins):
        """Return a replacement instruction if the rule matches, otherwise None."""


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


class InstructionOptimizer(Registrant, typing.Generic[T_Rule]):
    RULE_CLASSES: list[typing.Type[T_Rule]] = []
    NAME = None

    def __init__(
        self, maturities: list[int], stats: OptimizationStatistics, log_dir=None
    ):
        self.rules: set[T_Rule] = set()
        self.maturities = maturities
        self.log_dir = log_dir
        self.cur_maturity = ida_hexrays.MMAT_PREOPTIMIZED
        # Centralized statistics collector injected by the manager
        self.stats = stats

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

    def get_optimized_instruction(
        self, blk: ida_hexrays.mblock_t, ins: ida_hexrays.minsn_t
    ) -> ida_hexrays.minsn_t | None:
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
        # This was commented out in the original code,
        # and it looks like the entire instruction optimizer can be skipped
        # if the maturity level isn't desired for this specific optimizer.
        # TODO: we should check to see if this is still relevant?
        # if self.cur_maturity not in self.maturities:
        #     return None
        for rule in self.rules:
            if self.cur_maturity not in rule.maturities:
                continue
            try:
                new_ins = rule.check_and_replace(blk, ins)
                if new_ins is not None:
                    if self.stats is not None:
                        # Use new API with actual rule object
                        self.stats.record_rule_fired(
                            rule=rule,
                            optimizer=self.name,
                            maturity=self.cur_maturity,
                        )
                    optimizer_logger.info(
                        "Rule %s matched in maturity %s:",
                        rule.name,
                        maturity_to_string(self.cur_maturity),
                    )
                    optimizer_logger.info("  orig: %s", format_minsn_t(ins))
                    optimizer_logger.info("  new : %s", format_minsn_t(new_ins))

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

    @property
    def name(self):
        if self.NAME is not None:
            return self.NAME
        return self.__class__.__name__


# Note: VerifiableRule instances are registered in RULE_REGISTRY (d810.mba.rules)
# and injected into PatternOptimizer at construction time by InstructionOptimizerManager.
# This avoids duck typing and keeps the registration explicit.

import abc
import dataclasses
import itertools
import os
import time
from collections import Counter
from d810.core import typing

import ida_hexrays

from d810.core import getLogger
from d810.core.settings import get_settings
from d810.hexrays.expr.ast import AstBase, AstNode, AstNodeProtocol
from d810.hexrays.ir.minsn_utils import minsn_to_ast
from d810.hexrays.utils.hexrays_formatters import format_minsn_t
from d810.mba.extension_api import CanonicalFallbackError
from d810.mba.ac_matching import (
    check_canonical_feasibility,
    prepare_canonical_candidate_facts,
)
from d810.mba.provider_outcome import RawMatcherWorkReceipt
from d810.optimizers.microcode.instructions.handler import (
    GenericPatternRule,
    InstructionOptimizationRule,
    InstructionOptimizer,
)

# Pattern engine dispatcher (PR1) - normalized Cython/Python gate
from d810.optimizers.microcode.instructions.pattern_matching.engine import (
    BindingsProxy,
    MatchBindings,
    OpcodeIndexedStorage as _IndexedStorage,
    match_pattern_nomut as _match_nomut,
    get_engine_info,
)

optimizer_logger = getLogger("d810.optimizer")
pattern_search_logger = getLogger("d810.pattern_search")
_CANONICAL_FALLBACK_COMPARISON_BUDGET = 256

if typing.TYPE_CHECKING:
    from d810.core import OptimizationStatistics
    from d810.backends.mba.ida import IDAPatternAdapter


@dataclasses.dataclass
class CompiledRuleView:
    """Cached compiled state for an optimizer's rule set.

    This dataclass represents the compiled view of all active rules,
    including opcode filters and pattern storage. It includes a generation
    counter to detect when invalidation is needed.

    Attributes:
        generation: Monotonically increasing counter incremented on each mutation.
        allowed_opcodes: Frozenset of opcodes used by registered patterns.
        rule_count: Number of rules in the compiled view.
        compiled_at: Timestamp (time.monotonic()) when view was created.
    """

    generation: int
    allowed_opcodes: frozenset[int]
    rule_count: int
    compiled_at: float  # time.monotonic()


class PatternMatchingRule(GenericPatternRule):
    CATEGORY = "Pattern Matching"
    FUZZ_PATTERN: bool = True

    def __init__(self):
        super().__init__()
        self.fuzz_pattern = self.FUZZ_PATTERN

    def configure(self, fuzz_pattern=None, **kwargs):
        super().configure(kwargs)
        if fuzz_pattern is not None:
            self.fuzz_pattern = fuzz_pattern
        self._generate_pattern_candidates()
        if pattern_search_logger.debug_on:
            pattern_search_logger.debug(
                "Rule %s configured with %s patterns",
                self.__class__.__name__,
                len(self.pattern_candidates),
            )

    @property
    @abc.abstractmethod
    def PATTERN(self) -> AstNode:
        """Return the pattern to match."""

    @property
    @abc.abstractmethod
    def REPLACEMENT_PATTERN(self) -> AstNode:
        """Return the replacement pattern."""

    def _generate_pattern_candidates(self):
        self.fuzz_pattern = self.FUZZ_PATTERN
        if self.PATTERN is not None:
            self.PATTERN.reset_mops()
        if not self.fuzz_pattern and self.PATTERN is not None:
            self.pattern_candidates = [self.PATTERN]
        else:
            self.pattern_candidates = ast_generator(self.PATTERN)
        if self.PATTERNS is not None:
            self.pattern_candidates += list(self.PATTERNS)

    def check_pattern_and_replace(self, candidate_pattern: AstNode, test_ast: AstNode):
        if optimizer_logger.debug_on:
            optimizer_logger.debug(
                " 1. Checking pattern: %s against %s",
                candidate_pattern.get_pattern(),
                test_ast.get_pattern(),
            )
        if not candidate_pattern.check_pattern_and_copy_mops(test_ast):
            return None
        if optimizer_logger.debug_on:
            optimizer_logger.debug(
                " 2. Pattern matched: %s",
                candidate_pattern.get_pattern(),
            )
        if not self.check_candidate(candidate_pattern):
            return None
        if optimizer_logger.debug_on:
            optimizer_logger.debug(
                " 3. Candidate check passed: %s",
                candidate_pattern.get_pattern(),
            )
        new_instruction = self.get_replacement(candidate_pattern)
        if optimizer_logger.debug_on:
            optimizer_logger.debug(
                " 4. Replacement: %s",
                None if new_instruction is None else new_instruction,
            )
        return new_instruction

    def check_candidate(self, candidate: AstNode):
        return True

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self.PATTERN)} -> {repr(self.REPLACEMENT_PATTERN)})"


@dataclasses.dataclass
class RulePatternInfo:
    rule: InstructionOptimizationRule
    pattern: AstBase


# Frozenset for fast wildcard lookup in compatible() check
_WILDCARDS = frozenset(("L", "C", "N"))

# For signature_generator: only "L" and "N" should NOT generate variations.
# Constants "C" MUST generate "L" variations so patterns with "L" can match instructions with "C".
_SIG_GEN_TERMINALS = frozenset(("L", "N"))


def signature_generator(ref_sig: tuple[str, ...]) -> typing.Iterator[tuple[str, ...]]:
    """Generate all possible wildcard variations of a signature tuple."""
    for i, x in enumerate(ref_sig):
        if x not in _SIG_GEN_TERMINALS:
            for sig_suffix in signature_generator(ref_sig[i + 1 :]):
                yield ref_sig[:i] + ("L",) + sig_suffix
    yield ref_sig


class PatternStorage(object):
    # The PatternStorage object is used to store patterns associated to rules
    # A PatternStorage contains a dictionary (next_layer_patterns) where:
    #  - keys are the signature of a pattern at a specific depth (tuples for fast hashing)
    #  - values are PatternStorage object for the next depth
    # Additionally, it stores the rule objects which are resolved for the PatternStorage depth
    def __init__(self, depth=1):
        self.depth = depth
        # Use tuple keys directly for O(1) lookup without string operations
        self.next_layer_patterns: dict[tuple[str, ...], PatternStorage] = {}
        self.rule_resolved: list[RulePatternInfo] = []

    def add_pattern_for_rule(self, pattern: AstBase, rule: InstructionOptimizationRule):
        sig_list = pattern.get_depth_signature(self.depth)
        sig_tuple = tuple(sig_list)
        # A registered child already proves this signature is nonterminal.
        child = self.next_layer_patterns.get(sig_tuple)
        if child is not None:
            child.add_pattern_for_rule(pattern, rule)
        elif sig_tuple.count("N") == len(sig_tuple):
            # Preserve all([]) while avoiding Python generator resumes.
            self.rule_resolved.append(RulePatternInfo(rule, pattern))
        else:
            child = PatternStorage(self.depth + 1)
            self.next_layer_patterns[sig_tuple] = child
            child.add_pattern_for_rule(pattern, rule)

    @staticmethod
    def layer_signature_to_key(sig: list[str]) -> tuple[str, ...]:
        """Convert signature list to tuple key (for compatibility)."""
        return tuple(sig)

    # @staticmethod
    # def is_layer_signature_compatible(
    #     instruction_signature: str, pattern_signature: str
    # ) -> bool:
    #     if instruction_signature == pattern_signature:
    #         return True
    #     instruction_node_list = instruction_signature.split(",")
    #     pattern_node_list = pattern_signature.split(",")
    #     for ins_node_sig, pattern_node_sig in zip(
    #         instruction_node_list, pattern_node_list
    #     ):
    #         if (
    #             pattern_node_sig not in ["L", "C", "N"]
    #             and ins_node_sig != pattern_node_sig
    #         ):
    #             return False
    #     return True

    @staticmethod
    def compatible(inst_sig: tuple[str, ...], pat_sig: tuple[str, ...]) -> bool:
        """Check if instruction signature is compatible with pattern signature."""
        for i, p in zip(inst_sig, pat_sig):
            if p not in _WILDCARDS and i != p:
                return False
        return True

    def get_matching_rule_pattern_info(self, pattern: AstBase) -> list[RulePatternInfo]:
        if pattern_search_logger.debug_on:
            pattern_search_logger.debug("Searching for %s", pattern)
        return self.explore_one_level(pattern, 1)

    def explore_one_level(
        self, searched_pattern: AstBase, cur_level: int
    ) -> list[RulePatternInfo]:
        # We need to check if searched_pattern is in self.next_layer_patterns
        # Easy solution: try/except self.next_layer_patterns[searched_pattern]
        # Problem is that known patterns may not exactly match the microcode instruction, e.g.
        #   -> Pattern layer 3 signature is ("L", "N", "15", "L")
        #   -> Multiple instruction can match that: ("L", "N", "15", "L"), ("C", "N", "15", "L"), etc.
        # This piece of code handles that efficiently using tuple keys
        if not self.next_layer_patterns:
            return []

        sig_list = searched_pattern.get_depth_signature(cur_level)
        searched_sig = tuple(sig_list)

        # Count non-wildcard elements to determine number of variations
        non_wildcard_count = sum(1 for x in searched_sig if x not in _WILDCARDS)
        nb_possible_signature = 1 << non_wildcard_count  # 2 ** non_wildcard_count

        if pattern_search_logger.debug_on:
            pattern_search_logger.debug(
                "  Layer %d: %s -> %d variations (storage has %d signatures)",
                cur_level,
                searched_sig,
                nb_possible_signature,
                len(self.next_layer_patterns),
            )

        matched_rule_pattern_info: list[RulePatternInfo] = []

        if nb_possible_signature < len(self.next_layer_patterns):
            # Method 1: Generate all possible wildcard variations and look them up
            if pattern_search_logger.debug_on:
                pattern_search_logger.debug(
                    "  => Using method 1 (signature generation)"
                )
            for possible_sig in signature_generator(searched_sig):
                pattern_storage = self.next_layer_patterns.get(possible_sig)
                if pattern_storage is not None:
                    if pattern_search_logger.debug_on:
                        pattern_search_logger.debug(
                            "    Compatible signature: %s -> resolved: %s",
                            possible_sig,
                            pattern_storage.rule_resolved,
                        )
                    matched_rule_pattern_info.extend(pattern_storage.rule_resolved)
                    matched_rule_pattern_info.extend(
                        pattern_storage.explore_one_level(
                            searched_pattern, cur_level + 1
                        )
                    )
        else:
            # Method 2: Iterate through stored patterns and check compatibility
            if pattern_search_logger.debug_on:
                pattern_search_logger.debug("  => Using method 2 (linear scan)")
            for pat_sig, pattern_storage in self.next_layer_patterns.items():
                if self.compatible(searched_sig, pat_sig):
                    if pattern_search_logger.debug_on:
                        pattern_search_logger.debug(
                            "    Compatible signature: %s -> resolved: %s",
                            pat_sig,
                            pattern_storage.rule_resolved,
                        )
                    matched_rule_pattern_info.extend(pattern_storage.rule_resolved)
                    matched_rule_pattern_info.extend(
                        pattern_storage.explore_one_level(
                            searched_pattern, cur_level + 1
                        )
                    )

        return matched_rule_pattern_info


class PatternOptimizer(InstructionOptimizer):
    # The main idea of PatternOptimizer is to generate/store all possible patterns associated to all known rules in a $
    # dictionary-like object (PatternStorage) when the plugin is loaded.
    # => it means that we generate a very large number of patterns
    #
    # At runtime, we transform the microcode instruction in a list of keys that we search in the PatternStorage object
    # to speed up the checks
    # => we don't want to test all patterns, so we use the PatternStorage object to (quickly) get the patterns
    # which have the same shape as the microcode instruction

    RULE_CLASSES = [PatternMatchingRule]

    def __init__(
        self,
        maturities,
        stats: "OptimizationStatistics",
        log_dir=None,
        verifiable_rules: list | None = None,
    ):
        super().__init__(maturities, stats, log_dir=log_dir)
        self.pattern_storage = PatternStorage(depth=1)
        # Fast-path filter: restrict AST building to instructions whose opcode
        # appears as the root opcode of at least one registered rule pattern.
        # This avoids paying the cost of minsn_to_ast() for obviously
        # incompatible instructions.
        self._allowed_root_opcodes: set[int] = set()

        # PR2: Opcode-indexed storage (new storage backend)
        self._indexed_storage = _IndexedStorage()

        # Certified DSL adapters keep their declared pattern in the normal raw
        # stores. Their canonical templates are indexed separately and are
        # consulted after that rule's raw candidates miss, before later rules.
        self._canonical_fallback_rules_by_root_shape: dict[
            tuple[str, int, int], list[InstructionOptimizationRule]
        ] = {}
        # Includes traditional rules as well as DSL adapters. Catalogue IDs
        # alone cannot represent priority across these two populations.
        self._rule_registration_order: dict[int, int] = {}
        self._canonical_fallback_registration_order: list[InstructionOptimizationRule] = []

        # PR2: Feature flag for rollback to legacy PatternStorage
        # Default is to use the new indexed storage; users can set
        # D810_LEGACY_STORAGE=1 to rollback if issues arise.
        self._use_legacy_storage = os.environ.get("D810_LEGACY_STORAGE", "0") == "1"
        # Correctness fallback: if indexed lookup yields no candidates, retry
        # with legacy PatternStorage. This catches wildcard-heavy expressions
        # where strict fingerprints can produce false negatives.
        self._use_indexed_legacy_fallback = (
            os.environ.get("D810_INDEXED_LEGACY_FALLBACK", "1") == "1"
        )
        # Bounded OLLVM feasibility experiment. Resolve outside callback loops
        # and retain exact control behavior when the explicit flag is absent.
        self._use_canonical_fallback_feasibility_filter = (
            os.environ.get("D810_CANONICAL_FALLBACK_FEASIBILITY_FILTER", "0")
            == "1"
        )
        self._canonical_fallback_feasibility_counts: Counter[str] = Counter()

        if self._use_legacy_storage:
            optimizer_logger.debug(
                "PatternOptimizer: using legacy PatternStorage (D810_LEGACY_STORAGE=1)"
            )
        else:
            optimizer_logger.debug("PatternOptimizer: using OpcodeIndexedStorage")

        # PR3: Generation counter for invalidation tracking
        self._generation: int = 0
        self._compiled_view: CompiledRuleView | None = None

        # PR4: Non-mutating matching feature flag and reusable bindings
        # Default is OFF (opt-in) pending parity validation; configure through
        # D810Settings so saved preferences and environment precedence agree
        # with the manager's runtime lifecycle.
        self._use_nomut_matching = get_settings().nomut_matching
        self._match_bindings = MatchBindings()

        if self._use_nomut_matching:
            optimizer_logger.debug(
                "PatternOptimizer: using non-mutating pattern matching (runtime setting enabled)"
            )
        else:
            optimizer_logger.debug(
                "PatternOptimizer: using legacy mutating pattern matching (default, nomut is opt-in)"
            )

        # Optional fallback: if direct AST matching fails, try a def-use expanded
        # AST via MopTracker for opcodes where expressions are commonly split into
        # temporaries (e.g. x+y-2*(x&y) lowered as chained sub/add/mul/and).
        self._use_tracker_resolution_fallback = (
            os.environ.get("D810_PATTERN_TRACKER_RESOLVE", "1") == "1"
        )
        self._trace_tracker_resolution = (
            os.environ.get("D810_PATTERN_TRACE_TRACKER", "0") == "1"
        )
        self._tracker_resolution_opcodes = {ida_hexrays.m_sub, ida_hexrays.m_add}

        # Register verifiable rules passed at construction time.
        # These rules (from RULE_REGISTRY) implement check_pattern_and_replace
        # and pattern_candidates, bypassing the normal RULE_CLASSES check.
        if verifiable_rules:
            for rule in verifiable_rules:
                self._add_rule_internal(rule)
            optimizer_logger.debug(
                f"PatternOptimizer initialized with {len(self.rules)} rules"
            )
            optimizer_logger.debug(
                f"Allowed root opcodes: {self._allowed_root_opcodes}"
            )

    @property
    def engine_info(self) -> dict:
        """Return diagnostic info about the active pattern engine."""
        return get_engine_info()

    def _get_compiled_view(self) -> CompiledRuleView:
        """Get or rebuild the compiled rule view.

        This method implements the compilation cache. It rebuilds the view
        only when the generation counter has changed (indicating rules were
        added, removed, or configuration changed).

        Returns:
            CompiledRuleView: The current compiled view, either cached or freshly built.
        """
        if (
            self._compiled_view is None
            or self._compiled_view.generation != self._generation
        ):
            self._compiled_view = self._compile_rules()
        return self._compiled_view

    def reset_rules(self) -> None:
        """Clear rules and rebuild dispatch indexes for a project swap."""

        super().reset_rules()
        self.pattern_storage = PatternStorage(depth=1)
        self._indexed_storage = _IndexedStorage()
        self._allowed_root_opcodes = set()
        self._canonical_fallback_rules_by_root_shape = {}
        self._rule_registration_order = {}
        self._canonical_fallback_registration_order = []
        self._generation += 1
        self._compiled_view = None
        self._canonical_fallback_feasibility_counts.clear()

    @property
    def canonical_fallback_feasibility_counts(self) -> dict[str, int]:
        """Return fixed-key experiment work counters without retained terms."""

        return {
            key: int(self._canonical_fallback_feasibility_counts.get(key, 0))
            for key in (
                "candidate_fact_constructions",
                "candidate_fact_operands",
                "template_fact_constructions",
                "template_fact_requirements",
                "predicate_comparisons",
                "rejected_candidates",
                "surviving_candidates",
                "unknown_candidates",
            )
        }

    def _compile_rules(self) -> CompiledRuleView:
        """Build compiled view from current rule set.

        This method is called only when the generation counter changes,
        avoiding redundant recomputation of expensive structures.

        Returns:
            CompiledRuleView: A new compiled view with current generation.
        """
        return CompiledRuleView(
            generation=self._generation,
            allowed_opcodes=frozenset(self._allowed_root_opcodes),
            rule_count=len(self.rules),
            compiled_at=time.monotonic(),
        )

    def invalidate(self) -> None:
        """Explicitly invalidate the compiled view.

        This method increments the generation counter, forcing recompilation
        on the next access. Used by lifecycle events (reload, config changes).
        """
        self._generation += 1

    def _add_rule_internal(self, rule) -> bool:
        """Add a rule to this optimizer (internal helper).

        This method adds the rule and registers its patterns without
        performing any type checking. Used for both traditional rules
        (after RULE_CLASSES check) and verifiable rules (injected at init).
        """
        if optimizer_logger.debug_on:
            optimizer_logger.debug("Adding rule %s", rule.name)
        if len(rule.maturities) == 0:
            rule.maturities = self.maturities
        self.rules.add(rule)
        self._rule_registration_order.setdefault(
            id(rule), len(self._rule_registration_order)
        )

        # Register patterns if the rule has them
        if not hasattr(rule, "pattern_candidates"):
            return True
        try:
            candidates = rule.pattern_candidates
            optimizer_logger.debug(
                f"Rule {rule.name} has {len(candidates)} pattern candidates"
            )
        except Exception as e:
            optimizer_logger.error(f"Rule {rule.name} pattern_candidates failed: {e}")
            return False
        for pattern in candidates:
            if optimizer_logger.debug_on:
                optimizer_logger.debug(
                    "[PatternOptimizer] Adding pattern: %s",
                    str(pattern),
                )

            # Collect root opcode for quick opcode pre-filtering
            try:
                # Use Protocol for hot-reload safety
                if isinstance(pattern, AstNodeProtocol) and pattern.opcode is not None:
                    opcode = int(pattern.opcode)
                    self._allowed_root_opcodes.add(opcode)
            except Exception:
                pass
            # PR2: Register legacy rules to both storages during migration.
            self.pattern_storage.add_pattern_for_rule(pattern, rule)
            self._indexed_storage.add_pattern(pattern, rule)

        if self._canonical_fallback_enabled_for(rule):
            root_shapes = getattr(rule, "canonical_fallback_root_shapes", ())
            if root_shapes and rule not in self._canonical_fallback_registration_order:
                self._canonical_fallback_registration_order.append(rule)
            for root_shape in root_shapes:
                bucket = self._canonical_fallback_rules_by_root_shape.setdefault(
                    tuple(root_shape), []
                )
                if rule not in bucket:
                    bucket.append(rule)
                    bucket.sort(key=self._canonical_fallback_sort_key)

        # Invalidate compiled view after adding rule (PR3)
        self._generation += 1

        return True

    def add_rule(self, rule: "PatternMatchingRule | IDAPatternAdapter"):
        """Add a rule to this optimizer.

        Accepts both traditional PatternMatchingRule instances and
        IDAPatternAdapter instances (VerifiableRule wrappers).
        """
        # Check if this is an IDAPatternAdapter (VerifiableRule wrapper)
        # These bypass the RULE_CLASSES check and use _add_rule_internal directly
        rule_class_name = rule.__class__.__name__
        if rule_class_name == "IDAPatternAdapter":
            self._add_rule_internal(rule)
            # _add_rule_internal already increments generation
            return True

        # For traditional PatternMatchingRule instances, check RULE_CLASSES
        is_ok = super().add_rule(rule)
        if not is_ok:
            return False
        self._rule_registration_order.setdefault(
            id(rule), len(self._rule_registration_order)
        )
        # Register patterns (rule already added to self.rules by super())
        if not hasattr(rule, "pattern_candidates"):
            return True
        for pattern in rule.pattern_candidates:
            if optimizer_logger.debug_on:
                optimizer_logger.debug(
                    "[PatternOptimizer.add_rule] Adding pattern: %s",
                    str(pattern),
                )
            try:
                # Use Protocol for hot-reload safety
                if isinstance(pattern, AstNodeProtocol) and pattern.opcode is not None:
                    opcode = int(pattern.opcode)
                    self._allowed_root_opcodes.add(opcode)
            except Exception:
                pass
            # PR2: Register legacy rules to both storages during migration.
            self.pattern_storage.add_pattern_for_rule(pattern, rule)
            self._indexed_storage.add_pattern(pattern, rule)

        if self._canonical_fallback_enabled_for(rule):
            root_shapes = getattr(rule, "canonical_fallback_root_shapes", ())
            if root_shapes and rule not in self._canonical_fallback_registration_order:
                self._canonical_fallback_registration_order.append(rule)
            for root_shape in root_shapes:
                bucket = self._canonical_fallback_rules_by_root_shape.setdefault(
                    tuple(root_shape), []
                )
                if rule not in bucket:
                    bucket.append(rule)
                    bucket.sort(key=self._canonical_fallback_sort_key)

        # Invalidate compiled view after adding rule (PR3)
        self._generation += 1

        return True

    def get_optimized_instruction(
        self,
        blk: ida_hexrays.mblock_t,
        ins: ida_hexrays.minsn_t,
        *,
        contextual_anchor_ins: ida_hexrays.minsn_t | None = None,
        allowed_rule_names: frozenset[str] | None = None,
        scheduled_rule_names: frozenset[str] | None = None,
        observation_context_factory=None,
    ) -> ida_hexrays.minsn_t | None:
        if contextual_anchor_ins is None:
            contextual_anchor_ins = ins
        self.last_matched_rule_name = None
        self._pending_replacement_rule = None
        self._pending_replacement_context = None
        self._provider_finalized_rules = set()
        if blk is not None:
            self._maybe_flush_rule_match_aggregate(blk.mba.maturity)
            self.cur_maturity = blk.mba.maturity
        # Optimizer-level maturity gate removed: per-rule maturities are checked in the loop below
        # if self.cur_maturity not in self.maturities:
        #     return None
        # Skip this optimizer entirely when no pattern-matching rules are configured.
        # This avoids the (potentially expensive) AST conversion and pattern lookup
        # overhead when the user has not enabled any pattern rules.
        if len(self.rules) == 0:
            if optimizer_logger.debug_on:
                optimizer_logger.debug(
                    "[PatternOptimizer.get_optimized_instruction] No rules configured, skipping"
                )
            return None

        # Opcode pre-filter: if the instruction opcode is never used as a root
        # by any registered rule, there is no point in attempting an AST build.
        # This shortcut has a substantial impact on hot paths.
        try:
            if (
                ins.opcode not in self._allowed_root_opcodes
                and not self._canonical_fallback_rules_by_root_shape
            ):
                return None
        except Exception:
            # If anything goes wrong while reading opcode, fall through to safe path
            pass

        tmp = minsn_to_ast(ins)
        if tmp is None:
            if optimizer_logger.debug_on:
                optimizer_logger.debug(
                    "[PatternOptimizer.get_optimized_instruction] minsn_to_ast failed, skipping"
                )
            return None

        # NOTE: We do NOT canonicalize the input AST here because canonicalization
        # creates synthetic nodes (e.g., negated constants) that lose the mop
        # information needed for pattern matching. Instead, patterns are registered
        # in multiple forms (via ast_generator or equivalent) to match different
        # but mathematically equivalent input structures.

        new_ins = self._try_matches(
            blk,
            ins,
            tmp,
            allowed_rule_names=allowed_rule_names,
            scheduled_rule_names=scheduled_rule_names,
            source_label="direct",
            observation_context_factory=observation_context_factory,
            contextual_anchor_ins=contextual_anchor_ins,
        )
        if new_ins is not None:
            return new_ins

        # Fallback path: reconstruct expression trees from local def-use chains
        # and retry pattern matching once.
        resolved_ast = self._resolve_ast_with_tracker(blk, ins, tmp)
        if resolved_ast is not None and resolved_ast is not tmp:
            new_ins = self._try_matches(
                blk,
                ins,
                resolved_ast,
                allowed_rule_names=allowed_rule_names,
                scheduled_rule_names=scheduled_rule_names,
                source_label="tracker",
                observation_context_factory=observation_context_factory,
                contextual_anchor_ins=contextual_anchor_ins,
            )
            if new_ins is not None:
                return new_ins
        return None

    def _resolve_ast_with_tracker(
        self,
        blk: ida_hexrays.mblock_t,
        ins: ida_hexrays.minsn_t,
        ast: AstBase,
    ) -> AstBase | None:
        if not self._use_tracker_resolution_fallback:
            return None
        if blk is None:
            return None
        if ins.opcode not in self._tracker_resolution_opcodes:
            return None
        # The tracker fallback is deliberately unavailable before LOCOPT. This
        # is a lifecycle boundary for trustworthy native operand/version
        # provenance, not an assertion about when Hex-Rays can build UD/DU
        # chains. At PREOPT a physical register leaf can denote a value that
        # the root instruction has already overwritten; replaying that leaf in
        # a replacement is unsound even when the algebraic pattern itself is
        # valid.
        maturity = getattr(getattr(blk, "mba", None), "maturity", None)
        if maturity is None:
            maturity = getattr(self, "cur_maturity", None)
        try:
            if maturity is None or int(maturity) <= int(ida_hexrays.MMAT_PREOPTIMIZED):
                return None
        except (TypeError, ValueError):
            return None
        try:
            # Reuse the tracker-aware AST resolver already used by Z3 helpers.
            from d810.evaluator.hexrays_microcode.def_search import (
                recursively_resolve_ast,
            )
        except Exception:
            return None
        try:
            resolved = recursively_resolve_ast(
                ast, blk, ins, depth=0, max_depth=6, cache={}
            )
        except Exception:
            return None
        trace_tracker_resolution = bool(
            getattr(self, "_trace_tracker_resolution", False)
        )
        if resolved is None or resolved is ast:
            if trace_tracker_resolution:
                optimizer_logger.debug(
                    "[PatternOptimizer] tracker unresolved for %s",
                    format_minsn_t(ins),
                )
            return None
        if not self._has_usable_tracker_provenance(ins, resolved):
            if trace_tracker_resolution:
                optimizer_logger.debug(
                    "[PatternOptimizer] tracker provenance unavailable for %s; refusing fallback",
                    format_minsn_t(ins),
                )
            return None
        if trace_tracker_resolution:
            optimizer_logger.debug(
                "[PatternOptimizer] tracker resolved %s -> %s",
                format_minsn_t(ins),
                resolved,
            )
        if optimizer_logger.debug_on:
            optimizer_logger.debug(
                "[PatternOptimizer] tracker-resolved AST for %s -> %s",
                format_minsn_t(ins),
                resolved,
            )
        return resolved

    @staticmethod
    def _storage_version(mop: object) -> tuple[tuple[str, int], int] | None:
        """Extract a versioned register/stack identity from a native or snapshot mop.

        ``recursively_resolve_ast`` normally leaves ``MopSnapshot`` instances
        on AST leaves, while the root instruction still carries a live
        ``mop_t``. Keep this duck-typed so both representations are accepted
        without materializing a borrowed mop. Missing value numbers are
        intentionally not treated as equivalent: they are unknown provenance.
        """

        try:
            mop_type = int(getattr(mop, "t"))
        except (AttributeError, TypeError, ValueError):
            return None
        try:
            value_number = int(getattr(mop, "valnum"))
        except (AttributeError, TypeError, ValueError):
            return None
        if value_number <= 0:
            return None

        if mop_type == ida_hexrays.mop_r:
            register = getattr(mop, "r", None)
            if register is None:
                register = getattr(mop, "reg", None)
            try:
                return ("r", int(register)), value_number
            except (TypeError, ValueError):
                return None

        if mop_type == ida_hexrays.mop_S:
            stack_offset = getattr(mop, "stkoff", None)
            if stack_offset is None:
                stack = getattr(mop, "s", None)
                stack_offset = getattr(stack, "off", None)
            try:
                return ("S", int(stack_offset)), value_number
            except (TypeError, ValueError):
                return None

        return None

    @classmethod
    def _has_usable_tracker_provenance(
        cls,
        ins: ida_hexrays.minsn_t,
        resolved: AstBase,
    ) -> bool:
        """Prove that a tracker AST can replay without borrowed-mop aliasing.

        Every non-constant register/stack leaf must carry a positive native
        value number. The rewritten instruction destination must carry one as
        well, and a leaf that aliases that destination must be an explicitly
        older version. This distinguishes a safe LOCOPT+ versioned replacement
        from the PREOPT corruption where a borrowed register is read after it
        has been overwritten.
        """

        destination = cls._storage_version(getattr(ins, "d", None))
        if destination is None:
            return False
        destination_storage, destination_version = destination

        try:
            leaves = resolved.get_leaf_list()
        except Exception:
            return False
        for leaf in leaves:
            mop = getattr(leaf, "mop", None)
            if mop is None:
                # Computed constants are allowed to have no native mop. Any
                # other unbound leaf would make a tracker replacement guess.
                try:
                    if leaf.is_constant():
                        continue
                except Exception:
                    pass
                return False
            try:
                mop_type = int(getattr(mop, "t"))
            except (AttributeError, TypeError, ValueError):
                return False
            if mop_type == ida_hexrays.mop_n:
                continue
            if mop_type not in (ida_hexrays.mop_r, ida_hexrays.mop_S):
                continue

            source = cls._storage_version(mop)
            if source is None:
                return False
            source_storage, source_version = source
            if (
                source_storage == destination_storage
                and source_version >= destination_version
            ):
                return False
        return True

    @staticmethod
    def _canonical_fallback_enabled_for(rule: object) -> bool:
        """Read the explicit fallback flag, with a deprecated compatibility alias."""

        return bool(
            getattr(rule, "canonical_fallback_enabled", False)
            or getattr(rule, "uses_structural_matching", False)
        )

    @staticmethod
    def _canonical_fallback_sort_key(rule: object) -> tuple[int, object]:
        """Keep certified declaration order ahead of deterministic extensions."""

        declaration_index = getattr(rule, "canonical_fallback_declaration_index", None)
        if declaration_index is None:
            declaration_index = getattr(rule, "_certified_catalogue_rule_id", None)
        if type(declaration_index) is int and declaration_index >= 0:
            return (0, declaration_index)
        return (1, str(getattr(rule, "name", type(rule).__name__)))

    def _rule_is_eligible(
        self,
        rule: object,
        *,
        maturity: object,
        allowed_rule_names: frozenset[str] | None,
        scheduled_rule_names: frozenset[str],
    ) -> bool:
        rule_name = str(getattr(rule, "name", ""))
        if rule_name in getattr(
            self,
            "_cycle_quarantined_rule_names",
            frozenset(),
        ):
            return False
        if allowed_rule_names is not None and rule_name not in allowed_rule_names:
            return False
        return bool(
            maturity in getattr(rule, "maturities", ())
            or rule_name in scheduled_rule_names
        )

    @staticmethod
    def _raw_attempt_abstains(rule: object) -> bool:
        """Stop fallback after a typed raw budget/unsupported/error outcome."""

        stop_reason = getattr(rule, "raw_stop_reason", None)
        if getattr(stop_reason, "value", stop_reason) in {
            "raw_budget",
            "raw_unsupported",
        }:
            return True
        outcome = getattr(rule, "_last_provider_outcome", None)
        status = getattr(getattr(outcome, "status", None), "value", None)
        return status in {"error", "over_budget", "unavailable"}

    def _raw_work_backend(self) -> str:
        """Identify the actual raw matcher route for this handler attempt."""

        if self._use_nomut_matching and not self._use_legacy_storage:
            try:
                return str(get_engine_info()["backend"])
            except (KeyError, TypeError, ValueError):
                return "unknown"
        return "legacy_ast"

    def _record_raw_work(
        self,
        rule: object,
        *,
        comparisons: int,
        lazy_swaps: int,
        backend: str,
    ) -> None:
        """Forward observational raw work without affecting matching."""

        record = getattr(rule, "record_raw_match_receipt", None)
        if record is None:
            return
        try:
            record(RawMatcherWorkReceipt(comparisons, lazy_swaps, backend))
        except Exception:
            optimizer_logger.debug(
                "Raw matcher work telemetry failed for %s", rule, exc_info=True
            )

    def _canonical_fallback_rules_for(
        self, root_shape: tuple[str, int, int] | None
    ) -> tuple[InstructionOptimizationRule, ...]:
        if root_shape is None:
            return ()
        return tuple(
            self._canonical_fallback_rules_by_root_shape.get(tuple(root_shape), ())
        )

    def _prepare_canonical_fallback(
        self,
        test_ast: AstBase,
        ins: ida_hexrays.minsn_t,
        *,
        allowed_rule_names: frozenset[str] | None,
        scheduled_rule_names: frozenset[str],
        preparing_rule=None,
    ) -> tuple[object | None, tuple[InstructionOptimizationRule, ...]]:
        """Lower one root and select its certified canonical declaration bucket."""

        if not getattr(self, "_canonical_fallback_rules_by_root_shape", None):
            return None, ()
        if preparing_rule is None:
            preparing_rule = next(
                (
                    rule
                    for rule in self._canonical_fallback_registration_order
                    if self._rule_is_eligible(
                        rule,
                        maturity=self.cur_maturity,
                        allowed_rule_names=allowed_rule_names,
                        scheduled_rule_names=scheduled_rule_names,
                    )
                ),
                None,
            )
        if preparing_rule is None:
            return None, ()
        prepare = getattr(preparing_rule, "prepare_structural_candidate", None)
        if prepare is None:
            return None, (preparing_rule,)
        destination_size = getattr(getattr(ins, "d", None), "size", None)
        try:
            lowering = prepare(test_ast, destination_size=destination_size)
        except Exception:
            return None, (preparing_rule,)
        term = getattr(lowering, "term", None)
        if term is None:
            return lowering, (preparing_rule,)
        from d810.mba.certified_catalogue import root_shape_for_term

        selected = tuple(
            rule
            for rule in self._canonical_fallback_rules_for(root_shape_for_term(term))
            if self._rule_is_eligible(
                rule,
                maturity=self.cur_maturity,
                allowed_rule_names=allowed_rule_names,
                scheduled_rule_names=scheduled_rule_names,
            )
        )
        return lowering, selected

    def _get_candidates(self, ast: AstBase) -> list[RulePatternInfo]:
        if self._use_legacy_storage:
            return self.pattern_storage.get_matching_rule_pattern_info(ast)
        candidates = self._indexed_storage.get_candidates(ast)
        if candidates or not self._use_indexed_legacy_fallback:
            return candidates
        fallback_candidates = self.pattern_storage.get_matching_rule_pattern_info(ast)
        if fallback_candidates and optimizer_logger.debug_on:
            optimizer_logger.debug(
                "[PatternOptimizer] indexed miss, legacy fallback produced %d candidate(s) for %s",
                len(fallback_candidates),
                ast,
            )
        return fallback_candidates

    def _iter_match_schedule(
        self,
        all_matches,
        test_ast,
        ins,
        *,
        allowed_rule_names,
        scheduled_rule_names,
    ):
        """Merge raw candidates with the actual canonical root bucket lazily.

        Registration owns the unique canonical inventory. Until the first
        eligible canonical rule's raw forms miss, there is no lowering. Only
        that lowered root's bucket is then merged with remaining raw candidates;
        matching never scans every width bucket or sorts the whole catalogue.
        """
        inventory = self._canonical_fallback_registration_order
        if not inventory:
            for info in all_matches:
                yield info, None, None, 0
            return

        def eligible(rule):
            return self._rule_is_eligible(
                rule,
                maturity=self.cur_maturity,
                allowed_rule_names=allowed_rule_names,
                scheduled_rule_names=scheduled_rule_names,
            )

        first_canonical = next((rule for rule in inventory if eligible(rule)), None)
        if first_canonical is None:
            for info in all_matches:
                yield info, None, None, 0
            return

        # Rules stay strongly owned by this optimizer. IDs are local occurrence
        # keys, not semantic identities, and reset_rules discards this ordering.
        order = self._rule_registration_order

        def position(rule):
            try:
                return order[id(rule)]
            except KeyError:
                raise RuntimeError("mixed matching requires registered rule order") from None

        first_position = position(first_canonical)
        raw = sorted(
            (info for info in all_matches if eligible(info.rule)),
            key=lambda info: position(info.rule),
        )
        cursor = 0
        while cursor < len(raw) and position(raw[cursor].rule) <= first_position:
            yield raw[cursor], None, None, 0
            cursor += 1

        lowering, fallback_rules = self._prepare_canonical_fallback(
            test_ast,
            ins,
            allowed_rule_names=allowed_rule_names,
            scheduled_rule_names=scheduled_rule_names,
            preparing_rule=first_canonical,
        )
        selected = sorted(
            {id(rule): rule for rule in fallback_rules}.values(), key=position
        )
        for rule in selected:
            while cursor < len(raw) and position(raw[cursor].rule) <= position(rule):
                yield raw[cursor], None, None, 0
                cursor += 1
            yield None, rule, lowering, len(selected)
        while cursor < len(raw):
            yield raw[cursor], None, None, 0
            cursor += 1

    def _try_matches(
        self,
        blk: ida_hexrays.mblock_t,
        ins: ida_hexrays.minsn_t,
        test_ast: AstBase,
        *,
        allowed_rule_names: frozenset[str] | None,
        scheduled_rule_names: frozenset[str] | None,
        source_label: str,
        observation_context_factory=None,
        contextual_anchor_ins=None,
    ) -> ida_hexrays.minsn_t | None:
        if contextual_anchor_ins is None:
            contextual_anchor_ins = ins
        all_matches = self._get_candidates(test_ast)
        match_len = len(all_matches)
        scheduled_rule_names = scheduled_rule_names or frozenset()
        raw_comparisons = 0
        raw_lazy_swaps = 0
        raw_backend = self._raw_work_backend()
        fallback_attempt_count = 0
        remaining_fallback_budget = _CANONICAL_FALLBACK_COMPARISON_BUDGET
        canonical_candidate_facts = None
        canonical_candidate_facts_ready = False
        schedule = self._iter_match_schedule(
            all_matches,
            test_ast,
            ins,
            allowed_rule_names=allowed_rule_names,
            scheduled_rule_names=scheduled_rule_names,
        )
        for i, (
            rule_pattern_info,
            rule,
            structural_lowering,
            fallback_bucket_size,
        ) in enumerate(schedule):
            if rule_pattern_info is not None:
                rule_name = str(rule_pattern_info.rule.name)
                if not self._rule_is_eligible(
                    rule_pattern_info.rule,
                    maturity=self.cur_maturity,
                    allowed_rule_names=allowed_rule_names,
                    scheduled_rule_names=scheduled_rule_names,
                ):
                    continue
                if optimizer_logger.debug_on:
                    optimizer_logger.debug(
                        "[PatternOptimizer.get_optimized_instruction:%s] %s/%s rule_pattern_info: %s",
                        source_label,
                        i + 1,
                        match_len,
                        rule_pattern_info,
                    )
                bind_match_context = getattr(
                    rule_pattern_info.rule,
                    "bind_match_context",
                    None,
                )
                clear_match_context = getattr(
                    rule_pattern_info.rule,
                    "clear_match_context",
                    None,
                )
                attempt_finalized = False
                try:
                    if bind_match_context is not None:
                        bind_match_context(blk, ins)
                    # One receipt entry corresponds to one candidate-pattern
                    # comparison actually started by this handler. Generated
                    # legacy permutations are comparisons, not lazy swaps.
                    raw_comparisons += 1
                    self._record_raw_work(
                        rule_pattern_info.rule,
                        comparisons=1,
                        lazy_swaps=raw_lazy_swaps,
                        backend=raw_backend,
                    )

                    # Task 7 shadow mode remains in force for legacy rules.
                    observe_structural_match = getattr(
                        rule_pattern_info.rule,
                        "observe_structural_match",
                        None,
                    )
                    if (
                        observe_structural_match is not None
                        and not self._canonical_fallback_enabled_for(
                            rule_pattern_info.rule
                        )
                        and os.environ.get("D810_SHADOW_DSL_MATCHING", "0") == "1"
                    ):
                        observe_structural_match(test_ast)

                    # PR4: Non-mutating match path (when enabled and using indexed storage)
                    if self._use_nomut_matching and not self._use_legacy_storage:
                        # Non-mutating match: pattern stays frozen, bindings go to separate object
                        if not _match_nomut(
                            rule_pattern_info.pattern, test_ast, self._match_bindings
                        ):
                            if self._raw_attempt_abstains(rule_pattern_info.rule):
                                return None
                            continue
                        proxy = BindingsProxy(self._match_bindings)
                        if not rule_pattern_info.rule.check_candidate(proxy):
                            if self._raw_attempt_abstains(rule_pattern_info.rule):
                                return None
                            continue
                        record_legacy_match_bindings = getattr(
                            rule_pattern_info.rule,
                            "record_legacy_match_bindings",
                            None,
                        )
                        if record_legacy_match_bindings is not None:
                            record_legacy_match_bindings(
                                rule_pattern_info.pattern,
                                test_ast,
                            )
                        new_ins = rule_pattern_info.rule.get_replacement(proxy)
                        if new_ins is not None:
                            record_bound_replacement_outcome = getattr(
                                rule_pattern_info.rule,
                                "record_bound_replacement_outcome",
                                None,
                            )
                            if record_bound_replacement_outcome is not None:
                                record_bound_replacement_outcome(
                                    rule_pattern_info.rule.REPLACEMENT_PATTERN
                                )
                    else:
                        # Legacy mutating path: pattern gets mop references copied into it
                        new_ins = rule_pattern_info.rule.check_pattern_and_replace(
                            rule_pattern_info.pattern, test_ast
                        )
                    if self._raw_attempt_abstains(rule_pattern_info.rule):
                        return None

                    if new_ins is not None:
                        self._rule_match_aggregate.record(
                            str(rule_pattern_info.rule.name)
                        )
                        if optimizer_logger.debug_on:
                            optimizer_logger.debug(
                                "Rule %s matched in maturity %s:",
                                rule_pattern_info.rule.name,
                                self.cur_maturity,
                            )
                            optimizer_logger.debug("  orig: %s", format_minsn_t(ins))
                            optimizer_logger.debug(
                                "  new : %s",
                                format_minsn_t(new_ins),
                            )
                        self.last_matched_rule_name = str(rule_pattern_info.rule.name)
                        self._set_pending_replacement(
                            rule_pattern_info.rule,
                            blk,
                            contextual_anchor_ins,
                            observation_context_factory,
                        )
                        return new_ins
                except RuntimeError as e:
                    record_attempt_error = getattr(
                        rule_pattern_info.rule,
                        "record_attempt_error",
                        None,
                    )
                    if record_attempt_error is not None:
                        record_attempt_error(e)
                    optimizer_logger.error(
                        "Error during rule %s for instruction %s: %s",
                        rule_pattern_info.rule,
                        format_minsn_t(ins),
                        e,
                        exc_info=True,
                    )
                    self._finalize_provider_rule(
                        rule_pattern_info.rule,
                        blk,
                        contextual_anchor_ins,
                        observation_context_factory,
                        accepted=False,
                        reason="provider_exception",
                    )
                    attempt_finalized = True
                except Exception:
                    self._finalize_provider_rule(
                        rule_pattern_info.rule,
                        blk,
                        contextual_anchor_ins,
                        observation_context_factory,
                        accepted=False,
                        reason="provider_exception",
                    )
                    attempt_finalized = True
                    raise
                finally:
                    try:
                        if self._run_later_callback is not None:
                            self._run_later_callback(
                                rule_pattern_info.rule,
                                self.cur_maturity,
                            )
                    finally:
                        if clear_match_context is not None:
                            clear_match_context()
                    if not attempt_finalized and (
                        getattr(self, "_pending_replacement_rule", None)
                        is not rule_pattern_info.rule
                    ):
                        self._finalize_provider_rule(
                            rule_pattern_info.rule,
                            blk,
                            contextual_anchor_ins,
                            observation_context_factory,
                            accepted=False,
                            reason="provider_terminal",
                        )
                if self._raw_attempt_abstains(rule_pattern_info.rule):
                    return None
                continue

            rule_name = str(rule.name)
            bind_match_context = getattr(rule, "bind_match_context", None)
            bind_structural_match_context = getattr(
                rule,
                "bind_structural_match_context",
                bind_match_context,
            )
            clear_match_context = getattr(rule, "clear_match_context", None)
            fallback_attempt_finalized = False
            try:
                if bind_structural_match_context is not None:
                    bind_structural_match_context(blk, ins)
                # Carry the complete raw work performed for this root into the
                # fallback outcome. A fallback candidate has its own adapter
                # context, so the receipt must cross this boundary explicitly.
                self._record_raw_work(
                    rule,
                    comparisons=raw_comparisons,
                    lazy_swaps=raw_lazy_swaps,
                    backend=raw_backend,
                )
                match_structural_and_replace = getattr(
                    rule,
                    "match_structural_and_replace",
                    None,
                )
                if match_structural_and_replace is None:
                    fallback_attempt_finalized = True
                    continue
                if getattr(
                    self,
                    "_use_canonical_fallback_feasibility_filter",
                    False,
                ):
                    counts = getattr(
                        self, "_canonical_fallback_feasibility_counts", None
                    )
                    if counts is None:
                        counts = Counter()
                        self._canonical_fallback_feasibility_counts = counts
                    if not canonical_candidate_facts_ready:
                        canonical_candidate_facts_ready = True
                        term = getattr(structural_lowering, "term", None)
                        canonical_candidate_facts = prepare_canonical_candidate_facts(
                            term
                        )
                        if canonical_candidate_facts is not None:
                            counts["candidate_fact_constructions"] += 1
                            counts["candidate_fact_operands"] += len(
                                canonical_candidate_facts.ac_operands or ()
                            )
                    template_lookup = getattr(
                        rule, "canonical_feasibility_template_facts", None
                    )
                    template_facts = None
                    template_constructed = False
                    if template_lookup is not None:
                        try:
                            template_facts, template_constructed = template_lookup(
                                getattr(
                                    getattr(canonical_candidate_facts, "root", None),
                                    "width",
                                    0,
                                )
                            )
                        except Exception:
                            optimizer_logger.debug(
                                "Canonical feasibility facts unavailable for %s",
                                rule,
                                exc_info=True,
                            )
                    counts["template_fact_constructions"] += int(
                        template_constructed
                    )
                    if template_constructed and template_facts is not None:
                        counts["template_fact_requirements"] += len(
                            template_facts.ac_requirements or ()
                        )
                    feasibility = check_canonical_feasibility(
                        template_facts, canonical_candidate_facts
                    )
                    counts["predicate_comparisons"] += (
                        feasibility.predicate_comparisons
                    )
                    if not feasibility.known:
                        counts["unknown_candidates"] += 1
                    if not feasibility.survives:
                        counts["rejected_candidates"] += 1
                        record_rejection = getattr(
                            rule,
                            "record_canonical_feasibility_rejection",
                            None,
                        )
                        if record_rejection is not None:
                            record_rejection(
                                bucket_size=fallback_bucket_size,
                                predicate_comparisons=(
                                    feasibility.predicate_comparisons
                                ),
                                lowering=structural_lowering,
                                source_ast=test_ast,
                            )
                        continue
                    counts["surviving_candidates"] += 1
                fallback_attempt_count += 1
                new_ins = match_structural_and_replace(
                    test_ast,
                    bucket_size=fallback_bucket_size,
                    attempted_rule_count=fallback_attempt_count,
                    comparison_budget=remaining_fallback_budget,
                    lowering=structural_lowering,
                    lowering_provided=True,
                )
                consumed = getattr(rule, "canonical_fallback_comparisons", 0)
                if type(consumed) is not int or consumed < 0:
                    raise CanonicalFallbackError(
                        "matcher",
                        ValueError(
                            "canonical fallback reported an invalid comparison count"
                        ),
                    )
                if consumed > remaining_fallback_budget:
                    raise CanonicalFallbackError(
                        "matcher",
                        ValueError(
                            "canonical fallback exceeded the root comparison budget"
                        ),
                    )
                remaining_fallback_budget -= consumed
                if getattr(rule, "canonical_fallback_budget_exhausted", False):
                    return None
                if new_ins is not None:
                    self.last_matched_rule_name = rule_name
                    self._set_pending_replacement(
                        rule,
                        blk,
                        contextual_anchor_ins,
                        observation_context_factory,
                    )
                    return new_ins
                if remaining_fallback_budget == 0:
                    return None
            except CanonicalFallbackError as e:
                record_attempt_error = getattr(rule, "record_attempt_error", None)
                if record_attempt_error is not None:
                    try:
                        record_attempt_error(e)
                    except Exception:
                        optimizer_logger.debug(
                            "Canonical fallback error telemetry failed for %s",
                            rule,
                            exc_info=True,
                        )
                optimizer_logger.error(
                    "Terminal error during canonical fallback rule %s for instruction %s: %s",
                    rule,
                    format_minsn_t(ins),
                    e,
                    exc_info=True,
                )
                self._finalize_provider_rule(
                    rule,
                    blk,
                    contextual_anchor_ins,
                    observation_context_factory,
                    accepted=False,
                    reason="provider_exception",
                )
                fallback_attempt_finalized = True
                return None
            except Exception as e:
                record_attempt_error = getattr(rule, "record_attempt_error", None)
                if record_attempt_error is not None:
                    try:
                        record_attempt_error(e)
                    except Exception:
                        optimizer_logger.debug(
                            "Canonical fallback error telemetry failed for %s",
                            rule,
                            exc_info=True,
                        )
                optimizer_logger.error(
                    "Error during canonical fallback rule %s for instruction %s: %s",
                    rule,
                    format_minsn_t(ins),
                    e,
                    exc_info=True,
                )
                self._finalize_provider_rule(
                    rule,
                    blk,
                    contextual_anchor_ins,
                    observation_context_factory,
                    accepted=False,
                    reason="provider_exception",
                )
                fallback_attempt_finalized = True
                return None
            finally:
                try:
                    if self._run_later_callback is not None:
                        self._run_later_callback(rule, self.cur_maturity)
                finally:
                    if clear_match_context is not None:
                        clear_match_context()
                if not fallback_attempt_finalized and (
                    getattr(self, "_pending_replacement_rule", None) is not rule
                ):
                    self._finalize_provider_rule(
                        rule,
                        blk,
                        contextual_anchor_ins,
                        observation_context_factory,
                        accepted=False,
                        reason="provider_terminal",
                    )
        return None


# AST equivalent pattern generation stuff
# TODO: refactor/clean this


def rec_get_all_binary_subtree_representation(elt_list):
    if len(elt_list) == 1:
        return elt_list
    if len(elt_list) == 2:
        return [elt_list]
    tmp_res = []
    for i in range(1, len(elt_list)):
        left_list = rec_get_all_binary_subtree_representation(elt_list[:i])
        right_list = rec_get_all_binary_subtree_representation(elt_list[i:])
        for left in left_list:
            for right in right_list:
                tmp_res.append([left, right])
    return tmp_res


def rec_get_all_binary_tree_representation(elt_list):
    if len(elt_list) <= 1:
        return elt_list
    tmp = list(itertools.permutations(elt_list))
    tmp2 = []
    for perm_tmp in tmp:
        tmp2 += rec_get_all_binary_subtree_representation(perm_tmp)
    return tmp2


def get_all_binary_tree_representation(all_elt):
    tmp = rec_get_all_binary_tree_representation(all_elt)
    return tmp


def generate_ast(opcode, leafs):
    if isinstance(leafs, AstBase):
        return leafs
    if len(leafs) == 1:
        return leafs[0]
    if len(leafs) == 2:
        return AstNode(
            opcode, generate_ast(opcode, leafs[0]), generate_ast(opcode, leafs[1])
        )


def get_addition_operands(ast_node):
    if not isinstance(ast_node, AstBase) or not ast_node.is_node():
        return [ast_node]
    ast_node = typing.cast(AstNode, ast_node)
    if ast_node.opcode == ida_hexrays.m_add:
        return get_addition_operands(ast_node.left) + get_addition_operands(
            ast_node.right
        )
    elif ast_node.opcode == ida_hexrays.m_sub:
        tmp = get_addition_operands(ast_node.left)
        for aaa in get_addition_operands(ast_node.right):
            tmp.append(AstNode(ida_hexrays.m_neg, aaa))
        return tmp
    else:
        return [ast_node]


def get_opcode_operands(ref_opcode: int, ast_node: AstBase) -> list[AstBase]:
    if not isinstance(ast_node, AstBase) or not ast_node.is_node():
        return [ast_node]
    ast_node = typing.cast(AstNode, ast_node)
    if ast_node.opcode is not None and ast_node.opcode == ref_opcode:
        left = (
            get_opcode_operands(ref_opcode, ast_node.left)
            if ast_node.left is not None
            else []
        )
        right = (
            get_opcode_operands(ref_opcode, ast_node.right)
            if ast_node.right is not None
            else []
        )
        return left + right
    else:
        return [ast_node]


def get_similar_opcode_operands(ast_node: AstNode) -> list[AstNode]:
    if ast_node.opcode is None:
        return [ast_node]
    if ast_node.opcode in [ida_hexrays.m_add, ida_hexrays.m_sub]:
        add_elts = get_addition_operands(ast_node)
        all_add_ordering = get_all_binary_tree_representation(add_elts)
        ast_res = []
        for leaf_ordering in all_add_ordering:
            ast_res.append(generate_ast(ida_hexrays.m_add, leaf_ordering))
        return ast_res
    elif ast_node.opcode in [
        ida_hexrays.m_xor,
        ida_hexrays.m_or,
        ida_hexrays.m_and,
        ida_hexrays.m_mul,
    ]:
        same_elts = get_opcode_operands(int(ast_node.opcode), ast_node)
        all_same_ordering = get_all_binary_tree_representation(same_elts)
        ast_res = []
        for leaf_ordering in all_same_ordering:
            ast_res.append(generate_ast(ast_node.opcode, leaf_ordering))
        return ast_res

    else:
        return [ast_node]


def get_ast_variations_with_add_sub(
    opcode: int, left: AstNode, right: AstNode
) -> list[AstNode]:
    possible_ast = [AstNode(opcode, left, right)]
    if opcode == ida_hexrays.m_add:
        if left.is_node() and right.is_node():
            left = typing.cast(AstNode, left)
            right = typing.cast(AstNode, right)
            if (left.opcode == ida_hexrays.m_neg) and (
                right.opcode == ida_hexrays.m_neg
            ):
                possible_ast.append(
                    AstNode(
                        ida_hexrays.m_neg,
                        AstNode(ida_hexrays.m_add, left.left, right.left),
                    )
                )
        if right.is_node() and (right.opcode == ida_hexrays.m_neg):
            right = typing.cast(AstNode, right)
            possible_ast.append(AstNode(ida_hexrays.m_sub, left, right.left))
    return possible_ast


def ast_generator(ast_node: AstBase | None, excluded_opcodes=None) -> list[AstBase]:
    if ast_node is None:
        return []
    if not ast_node.is_node():
        return [ast_node]
    ast_node = typing.cast(AstNode, ast_node)
    res_ast = []
    excluded_opcodes = excluded_opcodes if excluded_opcodes is not None else []
    if ast_node.opcode not in excluded_opcodes:
        if ast_node.opcode in [ida_hexrays.m_add, ida_hexrays.m_sub]:
            similar_ast_list = get_similar_opcode_operands(ast_node)
            for similar_ast in similar_ast_list:
                sub_ast_left_list = ast_generator(
                    similar_ast.left,
                    excluded_opcodes=[ida_hexrays.m_add, ida_hexrays.m_sub],
                )
                sub_ast_right_list = ast_generator(
                    similar_ast.right,
                    excluded_opcodes=[ida_hexrays.m_add, ida_hexrays.m_sub],
                )
                for sub_ast_left in sub_ast_left_list:
                    for sub_ast_right in sub_ast_right_list:
                        sub_ast_left = typing.cast(AstNode, sub_ast_left)
                        sub_ast_right = typing.cast(AstNode, sub_ast_right)
                        res_ast += get_ast_variations_with_add_sub(
                            ida_hexrays.m_add, sub_ast_left, sub_ast_right
                        )
            return res_ast
        if ast_node.opcode in [
            ida_hexrays.m_xor,
            ida_hexrays.m_or,
            ida_hexrays.m_and,
            ida_hexrays.m_mul,
        ]:
            similar_ast_list = get_similar_opcode_operands(ast_node)
            for similar_ast in similar_ast_list:
                sub_ast_left_list = ast_generator(
                    similar_ast.left, excluded_opcodes=[ast_node.opcode]
                )
                sub_ast_right_list = ast_generator(
                    similar_ast.right, excluded_opcodes=[ast_node.opcode]
                )
                for sub_ast_left in sub_ast_left_list:
                    for sub_ast_right in sub_ast_right_list:
                        sub_ast_left = typing.cast(AstNode, sub_ast_left)
                        sub_ast_right = typing.cast(AstNode, sub_ast_right)
                        if ast_node.opcode is not None:
                            res_ast += get_ast_variations_with_add_sub(
                                int(ast_node.opcode), sub_ast_left, sub_ast_right
                            )
            return res_ast
    if ast_node.opcode not in [
        ida_hexrays.m_add,
        ida_hexrays.m_sub,
        ida_hexrays.m_or,
        ida_hexrays.m_and,
        ida_hexrays.m_mul,
    ]:
        excluded_opcodes = []
    nb_operands = 0
    if ast_node.left is not None:
        nb_operands += 1
    if ast_node.right is not None:
        nb_operands += 1
    if nb_operands == 1:
        sub_ast_list = ast_generator(ast_node.left, excluded_opcodes=excluded_opcodes)
        for sub_ast in sub_ast_list:
            res_ast.append(AstNode(ast_node.opcode, sub_ast))
        return res_ast
    if nb_operands == 2:
        sub_ast_left_list = ast_generator(
            ast_node.left, excluded_opcodes=excluded_opcodes
        )
        sub_ast_right_list = ast_generator(
            ast_node.right, excluded_opcodes=excluded_opcodes
        )
        for sub_ast_left in sub_ast_left_list:
            for sub_ast_right in sub_ast_right_list:
                sub_ast_left = typing.cast(AstNode, sub_ast_left)
                sub_ast_right = typing.cast(AstNode, sub_ast_right)
                if ast_node.opcode is not None:
                    res_ast += get_ast_variations_with_add_sub(
                        int(ast_node.opcode), sub_ast_left, sub_ast_right
                    )
        return res_ast
    return []

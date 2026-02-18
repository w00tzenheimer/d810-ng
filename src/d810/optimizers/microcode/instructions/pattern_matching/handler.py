import abc
import dataclasses
import itertools
import os
import time
from d810.core import typing

import ida_hexrays

from d810.core import getLogger
from d810.expr.ast import AstBase, AstNode, AstNodeProtocol, minsn_to_ast
from d810.hexrays.hexrays_formatters import format_minsn_t
from d810.optimizers.microcode.instructions.handler import (
    GenericPatternRule,
    InstructionOptimizationRule,
    InstructionOptimizer,
)

# Pattern engine dispatcher (PR1) — normalized Cython/Python gate
from d810.optimizers.microcode.instructions.pattern_matching.engine import (
    BindingsProxy,
    MatchBindings,
    OpcodeIndexedStorage as _IndexedStorage,
    match_pattern_nomut as _match_nomut,
    get_engine_info,
    _USING_CYTHON as _ENGINE_CYTHON,
)

optimizer_logger = getLogger("D810.optimizer")
pattern_search_logger = getLogger("D810.pattern_search")

if typing.TYPE_CHECKING:
    from d810.core import OptimizationStatistics
    from d810.mba.backends.ida import IDAPatternAdapter


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
            for sig_suffix in signature_generator(ref_sig[i + 1:]):
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
        # Check if signature is all "N" (terminal case)
        if all(x == "N" for x in sig_tuple):
            self.rule_resolved.append(RulePatternInfo(rule, pattern))
        else:
            if sig_tuple not in self.next_layer_patterns:
                self.next_layer_patterns[sig_tuple] = PatternStorage(self.depth + 1)
            self.next_layer_patterns[sig_tuple].add_pattern_for_rule(pattern, rule)

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

    def explore_one_level(self, searched_pattern: AstBase, cur_level: int) -> list[RulePatternInfo]:
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
                pattern_search_logger.debug("  => Using method 1 (signature generation)")
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
                        pattern_storage.explore_one_level(searched_pattern, cur_level + 1)
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
                        pattern_storage.explore_one_level(searched_pattern, cur_level + 1)
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

        if self._use_legacy_storage:
            optimizer_logger.debug("PatternOptimizer: using legacy PatternStorage (D810_LEGACY_STORAGE=1)")
        else:
            optimizer_logger.debug("PatternOptimizer: using OpcodeIndexedStorage")

        # PR3: Generation counter for invalidation tracking
        self._generation: int = 0
        self._compiled_view: CompiledRuleView | None = None

        # PR4: Non-mutating matching feature flag and reusable bindings
        # Default is OFF (opt-in) pending parity validation; users can set
        # D810_NOMUT_MATCHING=1 to enable experimental non-mutating matching.
        self._use_nomut_matching = os.environ.get("D810_NOMUT_MATCHING", "0") == "1"
        self._match_bindings = MatchBindings()

        if self._use_nomut_matching:
            optimizer_logger.debug("PatternOptimizer: using non-mutating pattern matching (D810_NOMUT_MATCHING=1 opt-in)")
        else:
            optimizer_logger.debug("PatternOptimizer: using legacy mutating pattern matching (default, nomut is opt-in)")

        # Optional fallback: if direct AST matching fails, try a def-use expanded
        # AST via MopTracker for opcodes where expressions are commonly split into
        # temporaries (e.g. x+y-2*(x&y) lowered as chained sub/add/mul/and).
        self._use_tracker_resolution_fallback = (
            os.environ.get("D810_PATTERN_TRACKER_RESOLVE", "1") == "1"
        )
        self._trace_tracker_resolution = (
            os.environ.get("D810_PATTERN_TRACE_TRACKER", "0") == "1"
        )
        self._tracker_resolution_opcodes = {ida_hexrays.m_sub}

        # Register verifiable rules passed at construction time.
        # These rules (from RULE_REGISTRY) implement check_pattern_and_replace
        # and pattern_candidates, bypassing the normal RULE_CLASSES check.
        if verifiable_rules:
            for rule in verifiable_rules:
                self._add_rule_internal(rule)
            optimizer_logger.debug(f"PatternOptimizer initialized with {len(self.rules)} rules")
            optimizer_logger.debug(f"Allowed root opcodes: {self._allowed_root_opcodes}")

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
        if self._compiled_view is None or self._compiled_view.generation != self._generation:
            self._compiled_view = self._compile_rules()
        return self._compiled_view

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

        # Register patterns if the rule has them
        if not hasattr(rule, 'pattern_candidates'):
            return True
        try:
            candidates = rule.pattern_candidates
            optimizer_logger.debug(f"Rule {rule.name} has {len(candidates)} pattern candidates")
        except Exception as e:
            optimizer_logger.error(f"Rule {rule.name} pattern_candidates failed: {e}")
            return False
        for pattern in candidates:
            if optimizer_logger.debug_on:
                optimizer_logger.debug(
                    "[PatternOptimizer] Adding pattern: %s",
                    str(pattern),
                )
            # PR2: Register to both storages during migration
            self.pattern_storage.add_pattern_for_rule(pattern, rule)
            self._indexed_storage.add_pattern(pattern, rule)

            # Collect root opcode for quick opcode pre-filtering
            try:
                # Use Protocol for hot-reload safety
                if isinstance(pattern, AstNodeProtocol) and pattern.opcode is not None:
                    self._allowed_root_opcodes.add(int(pattern.opcode))
            except Exception:
                pass

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
        # Register patterns (rule already added to self.rules by super())
        if not hasattr(rule, 'pattern_candidates'):
            return True
        for pattern in rule.pattern_candidates:
            if optimizer_logger.debug_on:
                optimizer_logger.debug(
                    "[PatternOptimizer.add_rule] Adding pattern: %s",
                    str(pattern),
                )
            # PR2: Register to both storages during migration
            self.pattern_storage.add_pattern_for_rule(pattern, rule)
            self._indexed_storage.add_pattern(pattern, rule)

            try:
                # Use Protocol for hot-reload safety
                if isinstance(pattern, AstNodeProtocol) and pattern.opcode is not None:
                    self._allowed_root_opcodes.add(int(pattern.opcode))
            except Exception:
                pass

        # Invalidate compiled view after adding rule (PR3)
        self._generation += 1

        return True

    def get_optimized_instruction(
        self,
        blk: ida_hexrays.mblock_t,
        ins: ida_hexrays.minsn_t,
        *,
        allowed_rule_names: frozenset[str] | None = None,
    ) -> ida_hexrays.minsn_t | None:
        if blk is not None:
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
            if ins.opcode not in self._allowed_root_opcodes:
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
            ins,
            tmp,
            allowed_rule_names=allowed_rule_names,
            source_label="direct",
        )
        if new_ins is not None:
            return new_ins

        # Fallback path: reconstruct expression trees from local def-use chains
        # and retry pattern matching once.
        resolved_ast = self._resolve_ast_with_tracker(blk, ins, tmp)
        if resolved_ast is not None and resolved_ast is not tmp:
            new_ins = self._try_matches(
                ins,
                resolved_ast,
                allowed_rule_names=allowed_rule_names,
                source_label="tracker",
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
        try:
            # Reuse the tracker-aware AST resolver already used by Z3 helpers.
            from d810.expr.z3_utils import _recursively_resolve_ast
        except Exception:
            return None
        try:
            resolved = _recursively_resolve_ast(ast, blk, ins, depth=0, max_depth=6, cache={})
        except Exception:
            return None
        if resolved is None or resolved is ast:
            if self._trace_tracker_resolution:
                optimizer_logger.info(
                    "[PatternOptimizer] tracker unresolved for %s",
                    format_minsn_t(ins),
                )
            return None
        if self._trace_tracker_resolution:
            optimizer_logger.info(
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

    def _try_matches(
        self,
        ins: ida_hexrays.minsn_t,
        test_ast: AstBase,
        *,
        allowed_rule_names: frozenset[str] | None,
        source_label: str,
    ) -> ida_hexrays.minsn_t | None:
        all_matches = self._get_candidates(test_ast)
        match_len = len(all_matches)
        for i, rule_pattern_info in enumerate(all_matches):
            if (
                allowed_rule_names is not None
                and rule_pattern_info.rule.name not in allowed_rule_names
            ):
                continue
            # Per-rule maturity check (Gate 2)
            if self.cur_maturity not in rule_pattern_info.rule.maturities:
                continue
            if optimizer_logger.debug_on:
                optimizer_logger.debug(
                    "[PatternOptimizer.get_optimized_instruction:%s] %s/%s rule_pattern_info: %s",
                    source_label,
                    i + 1,
                    match_len,
                    rule_pattern_info,
                )
            try:
                # PR4: Non-mutating match path (when enabled and using indexed storage)
                if self._use_nomut_matching and not self._use_legacy_storage:
                    # Non-mutating match: pattern stays frozen, bindings go to separate object
                    if not _match_nomut(
                        rule_pattern_info.pattern, test_ast, self._match_bindings
                    ):
                        continue
                    proxy = BindingsProxy(self._match_bindings)
                    if not rule_pattern_info.rule.check_candidate(proxy):
                        continue
                    new_ins = rule_pattern_info.rule.get_replacement(proxy)
                else:
                    # Legacy mutating path: pattern gets mop references copied into it
                    new_ins = rule_pattern_info.rule.check_pattern_and_replace(
                        rule_pattern_info.pattern, test_ast
                    )

                if new_ins is not None:
                    if optimizer_logger.info_on:
                        optimizer_logger.info(
                            "Rule %s matched in maturity %s:",
                            rule_pattern_info.rule.name,
                            self.cur_maturity,
                        )
                        optimizer_logger.info("  orig: %s", format_minsn_t(ins))
                        optimizer_logger.info(
                            "  new : %s",
                            format_minsn_t(new_ins),
                        )
                    if self.stats is not None:
                        # Use new API with actual rule object
                        self.stats.record_rule_fired(
                            rule=rule_pattern_info.rule,
                            optimizer=self.name,
                            maturity=self.cur_maturity,
                        )

                    return new_ins
            except RuntimeError as e:
                optimizer_logger.error(
                    "Error during rule %s for instruction %s: %s",
                    rule_pattern_info.rule,
                    format_minsn_t(ins),
                    e,
                    exc_info=True,
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
        for l in left_list:
            for r in right_list:
                tmp_res.append([l, r])
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
    elif ast_node.opcode in [ida_hexrays.m_xor, ida_hexrays.m_or, ida_hexrays.m_and, ida_hexrays.m_mul]:
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
            if (left.opcode == ida_hexrays.m_neg) and (right.opcode == ida_hexrays.m_neg):
                possible_ast.append(
                    AstNode(ida_hexrays.m_neg, AstNode(ida_hexrays.m_add, left.left, right.left))
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
                    similar_ast.left, excluded_opcodes=[ida_hexrays.m_add, ida_hexrays.m_sub]
                )
                sub_ast_right_list = ast_generator(
                    similar_ast.right, excluded_opcodes=[ida_hexrays.m_add, ida_hexrays.m_sub]
                )
                for sub_ast_left in sub_ast_left_list:
                    for sub_ast_right in sub_ast_right_list:
                        sub_ast_left = typing.cast(AstNode, sub_ast_left)
                        sub_ast_right = typing.cast(AstNode, sub_ast_right)
                        res_ast += get_ast_variations_with_add_sub(
                            ida_hexrays.m_add, sub_ast_left, sub_ast_right
                        )
            return res_ast
        if ast_node.opcode in [ida_hexrays.m_xor, ida_hexrays.m_or, ida_hexrays.m_and, ida_hexrays.m_mul]:
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
    if ast_node.opcode not in [ida_hexrays.m_add, ida_hexrays.m_sub, ida_hexrays.m_or, ida_hexrays.m_and, ida_hexrays.m_mul]:
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

"""Bounded, proof-gated Egglog MBA instruction rule.

This is intentionally *not* a second global instruction optimizer.  Egglog is
an opt-in peephole rule, so the normal project configuration and execution
scope decide when it may run.  Each candidate gets a fresh e-graph; no facts
or expressions leak between instructions or decompilations.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, replace
from types import MappingProxyType

import ida_hexrays

from d810.backends.mba.egglog_add_rule_compiler import (
    CompiledEgglogRule,
    EgglogAddSpecialization,
    canonical_pattern_catalogue_for_rules,
    compiled_rules_for_families,
    specialize,
)
from d810.backends.mba.egglog_saturation import (
    EgglogFunctionBudget,
    EgglogExtractionBudget,
    EgglogExtractionReceipt,
    EgglogExtractionResult,
    ExtractionSkipReason,
    extraction_receipt_for_lowering,
    extraction_receipt_for_profile,
    extract_bounded_candidate,
    extract_bounded_term,
)
from d810.backends.mba.cross_block_preparation import (
    prepare_ast_with_cross_block_constants,
    prepare_ast_with_def_use_constants,
)
from d810.backends.mba.hexrays_island import (
    lower_hexrays_island,
    rebuild_hexrays_island,
)
from d810.backends.mba.compiled_pattern_catalogue import (
    CanonicalPatternComparisonBudgetExceeded,
    CompiledPatternCatalogue,
)
from d810.backends.mba.native_mba_term_view import (
    NativeMbaTermView,
    semantic_native_leaf_key,
)
from d810.backends.mba.native_z3 import prove_native_ast_equivalence
from d810.backends.mba.native_z3_proof_template import (
    NativeZ3ProofTemplate,
    native_z3_proof_templates_for_rules,
    prove_typed_term_equivalence,
)
from d810.backends.mba.egglog_structural_rules import (
    compile_all_fixed_rotate_rules,
)
from d810.core import getLogger
from d810.hexrays.expr.ast import AstNode
from d810.hexrays.ir_maturity import ir_maturity_to_ida
from d810.hexrays.ir.minsn_utils import minsn_to_ast
from d810.ir.maturity import IRMaturity
from d810.mba.differential_report import egglog_receipt_to_outcome
from d810.mba.performance_timing import (
    EMPTY_MBA_STAGE_TIMINGS,
    MbaStageTimer,
)
from d810.mba.semantic_canonicalization import canonicalize_mba_term
from d810.mba.provider_outcome import MbaProviderOutcome, ProviderOutcomeStatus
from d810.mba.provider_history import ProviderOutcomeHistory
from d810.optimizers.microcode.instructions.peephole.handler import (
    PeepholeSimplificationRule,
)

logger = getLogger(__name__)


def _is_native_instruction(value) -> bool:
    """Return whether *value* is an IDA native instruction object.

    Portable/runtime tests may replace ``ida_hexrays.minsn_t`` with a
    factory function to observe reconstruction ordering.  Calling
    ``isinstance`` with that replacement raises ``TypeError``; keep the
    native-helper fast path type-safe without weakening the portable seam.
    """

    native_type = getattr(ida_hexrays, "minsn_t", None)
    return isinstance(native_type, type) and isinstance(value, native_type)

_ROOT_OPCODE_BY_OPERATION = MappingProxyType(
    {
        "add": ida_hexrays.m_add,
        "and": ida_hexrays.m_and,
        "bnot": ida_hexrays.m_bnot,
        "mul": ida_hexrays.m_mul,
        "neg": ida_hexrays.m_neg,
        "or": ida_hexrays.m_or,
        "sub": ida_hexrays.m_sub,
        "xor": ida_hexrays.m_xor,
    }
)
_SUPPORTED_ROOT_OPCODES = frozenset(_ROOT_OPCODE_BY_OPERATION.values())
_BOOL_OPCODES = frozenset(
    {ida_hexrays.m_and, ida_hexrays.m_or, ida_hexrays.m_xor, ida_hexrays.m_bnot}
)
_ARITH_OPCODES = frozenset(
    {ida_hexrays.m_add, ida_hexrays.m_sub, ida_hexrays.m_mul, ida_hexrays.m_neg}
)
_VALID_SIZES = frozenset({1, 2, 4, 8})
_DEFAULT_FAMILIES = ("add",)
_MAX_NATIVE_Z3_TIMEOUT_MS = 250
_INTERACTIVE_NATIVE_Z3_TIMEOUT_MS = 50
_MAX_PATTERN_COMPARISONS = 256


@dataclass(frozen=True)
class _SelectedRuleCatalogue:
    compiled_rules: tuple[CompiledEgglogRule, ...]


class EgglogOptimizer(PeepholeSimplificationRule):
    """Extract one strictly smaller, proof-gated MBA rewrite with Egglog.

    The default rule set is the certified ADD catalogue. Selection remains
    bounded and deterministic: configured families are indexed by root opcode,
    one fresh per-candidate degree-bounded e-graph discovers eligible results,
    and the lowest-cost native-Z3-proven strict reduction wins with catalogue
    order as the stable tie-breaker. The live ``time_budget_ms=3`` default is a
    safe telemetry/no-op mode and never invokes Egglog; configure above 50 ms
    with enough deterministic-work headroom to admit structurally capped Egglog
    execution. Admitted Rust calls cannot be hard-interrupted, so elapsed time
    remains acceptance telemetry.
    """

    DESCRIPTION = "Bounded Egglog MBA extraction (proof-gated)"
    CATEGORY = "MBA Solving"
    PORTFOLIO_TIER = "residual"

    def __init__(self) -> None:
        super().__init__()
        self.maturities = [ida_hexrays.MMAT_GLBOPT2]
        self.extraction_budget = EgglogExtractionBudget()
        self._publish_budget_attributes(self.extraction_budget)
        self.families = _DEFAULT_FAMILIES
        self.__catalogue = _SelectedRuleCatalogue(())
        self._compiled_rules: tuple[CompiledEgglogRule, ...] = ()
        self._rules_by_root_opcode = MappingProxyType({})
        self._native_pattern_catalogue = CompiledPatternCatalogue.from_rules(())
        self._proof_templates = MappingProxyType({})
        self.native_proof_mode = "legacy"
        self.execution_mode = "interactive"
        self._catalogue_configured = False
        self.last_extraction_receipt: EgglogExtractionReceipt | None = None
        self.last_rule_family: str | None = None
        self.last_rule_provenance: tuple[str, ...] | None = None
        self.last_derivation_trace: (
            tuple[tuple[str, str, tuple[str, ...]], ...] | None
        ) = None
        self.rule_provenance_history = ProviderOutcomeHistory[tuple[str, ...]]()
        self.provider_outcome_history = ProviderOutcomeHistory[MbaProviderOutcome]()
        self._attempt_outcome_index: int | None = None
        self._provider_outcome_capture_depth = 0
        self._last_provider_outcome: MbaProviderOutcome | None = None
        self.cross_block_constant_preparation = False
        self.cross_block_def_use_preparation = False
        self.generic_native_z3_before_certificate = False
        self.function_time_budget_ms: int | None = None
        self._function_budget: EgglogFunctionBudget | None = None
        self.residual_only = False
        self._residual_admitted = False
        self.collect_stage_timings = False
        self.last_stage_timings = EMPTY_MBA_STAGE_TIMINGS
        self._stage_timer: MbaStageTimer | None = None

    def _begin_provider_attempt(self) -> None:
        """Start one observable attempt, independent of whether it mutates."""

        self._attempt_outcome_index = None
        self._last_provider_outcome = None

    def _provider_outcome_capture_enabled(self) -> bool:
        return self._provider_outcome_capture_depth > 0

    def _provider_outcome_history_enabled(self) -> bool:
        """Retain bounded outcomes for explicit captures and timing profiles."""

        return self._provider_outcome_capture_enabled() or self.collect_stage_timings

    def begin_provider_outcome_capture(self) -> None:
        if not self._provider_outcome_capture_enabled():
            self.provider_outcome_history.clear()
        self._provider_outcome_capture_depth += 1

    def end_provider_outcome_capture(self) -> None:
        if self._provider_outcome_capture_depth <= 0:
            raise RuntimeError("provider outcome capture was not active")
        self._provider_outcome_capture_depth -= 1

    def configure(self, kwargs) -> None:
        config = dict(kwargs or {})
        maturity_names = config.pop("maturities", None)
        if "rounds" in config and "saturation_rounds" in config:
            raise ValueError(
                "EgglogOptimizer rounds and saturation_rounds cannot both be set"
            )
        if "rounds" in config:
            config["saturation_rounds"] = config.pop("rounds")
        families = self._validate_families(
            config.get("families", list(_DEFAULT_FAMILIES))
        )
        collect_stage_timings = config.get("collect_stage_timings", False)
        if type(collect_stage_timings) is not bool:
            raise ValueError("EgglogOptimizer collect_stage_timings must be a boolean")
        native_proof_mode = config.get("native_proof_mode", "legacy")
        if native_proof_mode not in {"legacy", "shadow"}:
            raise ValueError(
                "EgglogOptimizer native_proof_mode must be legacy or shadow; "
                "enforced is not rollout-authorized"
            )
        execution_mode = config.get("execution_mode", "interactive")
        if type(execution_mode) is not str or execution_mode not in {
            "interactive",
            "noninteractive",
        }:
            raise ValueError(
                "EgglogOptimizer execution_mode must be interactive or noninteractive"
            )
        super().configure(config)
        if maturity_names is not None:
            try:
                self.maturities = [
                    ir_maturity_to_ida(IRMaturity[str(name)]) for name in maturity_names
                ]
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(
                    "EgglogOptimizer maturities must be IRMaturity names"
                ) from exc
        max_leaves = self.config.get("max_leaves", 2)
        if type(max_leaves) is not int or not 1 <= max_leaves <= 8:
            raise ValueError("EgglogOptimizer max_leaves must be between 1 and 8")
        preparation = self.config.get("cross_block_constant_preparation", False)
        if type(preparation) is not bool:
            raise ValueError(
                "EgglogOptimizer cross_block_constant_preparation must be boolean"
            )
        def_use_preparation = self.config.get("cross_block_def_use_preparation", False)
        if type(def_use_preparation) is not bool:
            raise ValueError(
                "EgglogOptimizer cross_block_def_use_preparation must be boolean"
            )
        generic_native_z3_before_certificate = self.config.get(
            "generic_native_z3_before_certificate", False
        )
        if type(generic_native_z3_before_certificate) is not bool:
            raise ValueError(
                "EgglogOptimizer generic_native_z3_before_certificate must be boolean"
            )
        function_time_budget_ms = self.config.get("function_time_budget_ms")
        if function_time_budget_ms is not None and (
            type(function_time_budget_ms) is not int
            or not 1 <= function_time_budget_ms <= 5_000
        ):
            raise ValueError(
                "EgglogOptimizer function_time_budget_ms must be an integer from 1 to 5000"
            )
        residual_only = self.config.get("residual_only", False)
        if type(residual_only) is not bool:
            raise ValueError("EgglogOptimizer residual_only must be boolean")
        try:
            budget = EgglogExtractionBudget(
                max_leaves=max_leaves,
                max_operator_nodes=self.config.get("max_operator_nodes", 10),
                max_degree=self.config.get("max_degree", 1),
                saturation_rounds=self.config.get("saturation_rounds", 2),
                max_eclasses=self.config.get("max_eclasses", 64),
                max_enodes=self.config.get("max_enodes", 128),
                max_rule_firings=self.config.get("max_rule_firings", 32),
                time_budget_ms=self.config.get("time_budget_ms", 3),
                require_proof=self.config.get("require_proof", True),
            )
        except ValueError as exc:
            if self.config.get("require_proof", True) is not True:
                raise ValueError("EgglogOptimizer native proof is mandatory") from exc
            raise ValueError(f"EgglogOptimizer {exc}") from exc

        if families == ("fixed_rotate",):
            selected_catalogue = _SelectedRuleCatalogue(
                tuple(
                    receipt.compiled_rule
                    for receipt in compile_all_fixed_rotate_rules()
                    if receipt.compiled_rule is not None
                )
            )
        else:
            selected_catalogue = _SelectedRuleCatalogue(
                compiled_rules_for_families(families)
            )
        self.extraction_budget = budget
        self._publish_budget_attributes(budget)
        self.collect_stage_timings = collect_stage_timings
        self.native_proof_mode = native_proof_mode
        self.execution_mode = execution_mode
        self.families = families
        self._catalogue = selected_catalogue
        self.cross_block_constant_preparation = preparation
        self.cross_block_def_use_preparation = def_use_preparation
        self.generic_native_z3_before_certificate = generic_native_z3_before_certificate
        self.function_time_budget_ms = function_time_budget_ms
        self._function_budget = (
            None
            if function_time_budget_ms is None
            else EgglogFunctionBudget(function_time_budget_ms)
        )
        self.residual_only = residual_only
        self._residual_admitted = False

    def _publish_budget_attributes(self, budget: EgglogExtractionBudget) -> None:
        self.max_leaves = budget.max_leaves
        self.max_operator_nodes = budget.max_operator_nodes
        self.max_degree = budget.max_degree
        self.saturation_rounds = budget.saturation_rounds
        self.max_eclasses = budget.max_eclasses
        self.max_enodes = budget.max_enodes
        self.max_rule_firings = budget.max_rule_firings
        self.time_budget_ms = budget.time_budget_ms
        self.require_proof = budget.require_proof
        # Deprecated direct-handler compatibility. Config-v2 emits only the new key.
        self.rounds = budget.saturation_rounds

    @property
    def _catalogue(self):
        return self.__catalogue

    @_catalogue.setter
    def _catalogue(self, catalogue) -> None:
        self.__catalogue = catalogue
        self._compiled_rules = catalogue.compiled_rules
        self._rules_by_root_opcode = self._build_root_opcode_buckets(
            self._compiled_rules
        )
        self._native_pattern_catalogue = canonical_pattern_catalogue_for_rules(
            self._compiled_rules
        )
        self._proof_templates = native_z3_proof_templates_for_rules(
            self._compiled_rules
        )
        self._catalogue_configured = True

    def _ensure_catalogue_configured(self) -> None:
        """Compile the default selection only when a direct handler is used."""
        if not self._catalogue_configured:
            if self.families == ("fixed_rotate",):
                self._catalogue = _SelectedRuleCatalogue(
                    tuple(
                        receipt.compiled_rule
                        for receipt in compile_all_fixed_rotate_rules()
                        if receipt.compiled_rule is not None
                    )
                )
            else:
                self._catalogue = _SelectedRuleCatalogue(
                    compiled_rules_for_families(self.families)
                )

    def check_and_replace(self, blk, ins):
        """Return a replacement only after extraction, shrink, and proof."""
        self.last_rule_family = None
        self.last_rule_provenance = None
        self.last_derivation_trace = None
        self.last_extraction_receipt = None
        self._begin_provider_attempt()
        self._begin_stage_timing()
        try:
            if self.residual_only and not self._residual_admitted:
                return None
            self._begin_stage("root_eligibility")
            try:
                if ins.opcode not in _SUPPORTED_ROOT_OPCODES:
                    self._record_extraction_receipt(
                        EgglogExtractionReceipt(
                            skip_reason=ExtractionSkipReason.NON_MBA_CANDIDATE
                        )
                    )
                    return None
            finally:
                self._finish_stage("root_eligibility")
            return self._check_and_replace(ins, blk=blk)
        except Exception:  # Never leak an exception through Hex-Rays' callback.
            receipt = self.last_extraction_receipt
            self._record_extraction_receipt(
                EgglogExtractionReceipt(skip_reason=ExtractionSkipReason.INTERNAL_ERROR)
                if receipt is None
                else replace(
                    receipt,
                    skip_reason=ExtractionSkipReason.INTERNAL_ERROR,
                )
            )
            logger.exception(
                "egglog MBA extraction failed at %#x", getattr(ins, "ea", 0)
            )
            return None
        finally:
            self._finish_stage_timing()

    def set_residual_admission(self, admitted: bool) -> None:
        """Receive the current callback's fast-path outcome from its owner."""

        self._residual_admitted = bool(admitted)

    def _check_and_replace(self, ins, *, blk=None):
        self.last_rule_family = None
        self.last_rule_provenance = None
        self.last_derivation_trace = None
        self.last_extraction_receipt = None
        self._begin_provider_attempt()
        if ins.d is None or type(getattr(ins.d, "size", None)) is not int:
            self._record_extraction_receipt(
                EgglogExtractionReceipt(
                    skip_reason=ExtractionSkipReason.UNSUPPORTED_WIDTH_SEMANTICS
                )
            )
            return None
        destination_size = int(ins.d.size)
        if (
            self.cross_block_constant_preparation
            or self.cross_block_def_use_preparation
        ):
            return self._check_and_replace_with_prepared_ast(
                ins,
                blk=blk,
                destination_size=destination_size,
            )
        self._begin_stage("native_preflight")
        try:
            native_result = self._read_native_view(ins, destination_size)
            view = native_result.view
            if view is None:
                self._record_extraction_receipt(
                    extraction_receipt_for_profile(
                        native_result.profile,
                        ExtractionSkipReason.UNSUPPORTED_WIDTH_SEMANTICS,
                    )
                )
                return None
            # Retain the direct profile if a later preflight guard raises; the
            # callback converts that failure to internal_error without losing its
            # useful unsafe-input evidence.
            self.last_extraction_receipt = extraction_receipt_for_profile(
                native_result.profile,
                ExtractionSkipReason.INTERNAL_ERROR,
            )
            candidate_skip_reason = self._native_view_skip_reason(native_result.profile)
            if candidate_skip_reason is not None:
                self._record_extraction_receipt(
                    extraction_receipt_for_profile(
                        native_result.profile, candidate_skip_reason
                    )
                )
                return None
            self._ensure_catalogue_configured()
            structural_route = self.families == ("fixed_rotate",)
            matcher_started = (
                time.perf_counter() if self.collect_stage_timings else None
            )
            if structural_route:
                try:
                    structural_matches = (
                        self._native_pattern_catalogue.canonical_applications(
                            view.to_typed_term(),
                            comparison_budget=_MAX_PATTERN_COMPARISONS,
                        )
                    )
                except CanonicalPatternComparisonBudgetExceeded:
                    self._record_extraction_receipt(
                        extraction_receipt_for_profile(
                            native_result.profile,
                            ExtractionSkipReason.CANDIDATE_BUDGET,
                        )
                    )
                    return None
                match_result = None
            else:
                structural_matches = ()
                match_result = self._native_pattern_catalogue.match_root(
                    view, comparison_budget=_MAX_PATTERN_COMPARISONS
                )
            matcher_elapsed_ms = (
                None
                if matcher_started is None
                else (time.perf_counter() - matcher_started) * 1000.0
            )
            if match_result is not None and match_result.comparison_budget_exceeded:
                self._record_extraction_receipt(
                    self._with_native_match_telemetry(
                        extraction_receipt_for_profile(
                            native_result.profile,
                            ExtractionSkipReason.CANDIDATE_BUDGET,
                        ),
                        match_result,
                        elapsed_ms=matcher_elapsed_ms,
                    )
                )
                return None
            matches = () if match_result is None else match_result.matches
            canonical_match_result = None
            if structural_route and not structural_matches:
                self._record_extraction_receipt(
                    extraction_receipt_for_profile(
                        native_result.profile,
                        ExtractionSkipReason.NO_DEGREE_ELIGIBLE_IMPROVEMENT,
                    )
                )
                return None
            if not structural_route and not matches:
                canonical_term = canonicalize_mba_term(view.to_typed_term()).canonical_term
                canonical_match_result = self._native_pattern_catalogue.match_canonical_root(
                    canonical_term,
                    comparison_budget=_MAX_PATTERN_COMPARISONS,
                )
                if canonical_match_result.stop_reason.value == "comparison_budget":
                    self._record_extraction_receipt(
                        self._with_native_match_telemetry(
                            extraction_receipt_for_profile(
                                native_result.profile,
                                ExtractionSkipReason.CANDIDATE_BUDGET,
                            ),
                            canonical_match_result,
                            elapsed_ms=matcher_elapsed_ms,
                        )
                    )
                    return None
                matches = canonical_match_result.matches
                if not matches:
                    self._record_extraction_receipt(
                        self._with_native_match_telemetry(
                            extraction_receipt_for_profile(
                                native_result.profile,
                                ExtractionSkipReason.NO_DEGREE_ELIGIBLE_IMPROVEMENT,
                            ),
                            canonical_match_result,
                            elapsed_ms=matcher_elapsed_ms,
                        )
                    )
                    return None
        finally:
            self._finish_stage("native_preflight")
        extraction_budget = self._candidate_extraction_budget(blk)
        telemetry_match_result = (
            match_result
            if canonical_match_result is None
            else canonical_match_result
        )
        if extraction_budget is None:
            receipt = extraction_receipt_for_profile(
                native_result.profile,
                ExtractionSkipReason.TIME_BUDGET,
            )
            if telemetry_match_result is not None:
                receipt = self._with_native_match_telemetry(
                    receipt,
                    telemetry_match_result,
                    elapsed_ms=matcher_elapsed_ms,
                )
            self._record_extraction_receipt(receipt)
            return None
        candidate_term = view.to_typed_term()
        if structural_route:
            initial_replacements = {}
        elif canonical_match_result is None:
            initial_replacements = {
                id(match.rule): match.bindings.materialize_replacement(match.rule)
                for match in matches
            }
        else:
            initial_replacements = {
                id(match.compiled_pattern.rule): match.compiled_pattern.materialize_replacement(
                    match.bindings
                )
                for match in matches
            }

        self._begin_stage("egglog_extraction")
        try:
            extraction_kwargs = {
                "destination_size": destination_size,
                "profile": native_result.profile,
                "initial_replacements": initial_replacements,
            }
            if extraction_budget != self.extraction_budget:
                extraction_kwargs["budget"] = extraction_budget
            extraction = self._select_native_extraction(
                candidate_term,
                block=blk,
                destination=ins.d,
                **extraction_kwargs,
            )
        finally:
            self._finish_stage("egglog_extraction")
        if telemetry_match_result is not None:
            extraction = replace(
                extraction,
                receipt=self._with_native_match_telemetry(
                    extraction.receipt,
                    telemetry_match_result,
                    elapsed_ms=matcher_elapsed_ms,
                ),
            )
        self._record_extraction_receipt(extraction.receipt)
        replacement_term = extraction.replacement_term
        if replacement_term is None:
            return None
        # AST construction is intentionally deferred until the direct native
        # preflight and Egglog extraction have selected a concrete winner.
        self._begin_stage("ast_construction")
        try:
            ast = minsn_to_ast(ins)
        finally:
            self._finish_stage("ast_construction")
        if ast is None:
            self._record_extraction_receipt(
                replace(
                    extraction.receipt,
                    skip_reason=ExtractionSkipReason.LOWERING_FAILED,
                    derivation_trace=(),
                )
            )
            return None
        lowering = lower_hexrays_island(ast, destination_size=destination_size)
        canonical_candidate_term = canonicalize_mba_term(candidate_term).canonical_term
        if lowering.term is None or lowering.term != canonical_candidate_term:
            self._record_extraction_receipt(
                replace(
                    extraction.receipt,
                    skip_reason=ExtractionSkipReason.LOWERING_FAILED,
                    derivation_trace=(),
                )
            )
            return None
        replacement = rebuild_hexrays_island(
            replacement_term,
            lowering=lowering,
            destination_size=destination_size,
            block=blk,
            destination=ins.d,
        )
        if replacement is None:
            self._record_extraction_receipt(
                replace(
                    extraction.receipt,
                    skip_reason=ExtractionSkipReason.LOWERING_FAILED,
                    derivation_trace=(),
                )
            )
            return None
        if replacement_term.operation not in {"rol", "ror"} and self._node_count(
            replacement
        ) >= self._node_count(ast):
            self._record_extraction_receipt(
                replace(
                    extraction.receipt,
                    skip_reason=ExtractionSkipReason.NO_DEGREE_ELIGIBLE_IMPROVEMENT,
                )
            )
            return None
        selected = extraction.selected_provenance
        if selected is None:
            self._record_extraction_receipt(
                replace(
                    extraction.receipt,
                    skip_reason=ExtractionSkipReason.INTERNAL_ERROR,
                )
            )
            return None
        width = int(ins.d.size) * 8
        self._begin_stage("native_z3")
        try:
            (
                proved,
                template_source,
                fallback_reason,
                template_verdict,
                legacy_verdict,
                template_elapsed_ms,
                legacy_elapsed_ms,
            ) = self._prove_selected_replacement(
                ast,
                replacement,
                original_term=lowering.term,
                replacement_term=replacement_term,
                selected=selected,
                width=width,
            )
        finally:
            self._finish_stage("native_z3")
        if not proved:
            self._record_extraction_receipt(
                replace(
                    extraction.receipt,
                    skip_reason=ExtractionSkipReason.NATIVE_Z3_FAILED,
                    derivation_trace=(),
                    proof_mode=self.native_proof_mode,
                    template_source_name=template_source,
                    template_fallback_reason=fallback_reason,
                    template_proof_verdict=template_verdict,
                    legacy_proof_verdict=legacy_verdict,
                    template_proof_elapsed_ms=template_elapsed_ms,
                    legacy_proof_elapsed_ms=legacy_elapsed_ms,
                )
            )
            return None
        extraction = replace(
            extraction,
            receipt=replace(
                extraction.receipt,
                proof_mode=self.native_proof_mode,
                template_source_name=template_source,
                template_fallback_reason=fallback_reason,
                template_proof_verdict=template_verdict,
                legacy_proof_verdict=legacy_verdict,
                template_proof_elapsed_ms=template_elapsed_ms,
                legacy_proof_elapsed_ms=legacy_elapsed_ms,
            ),
        )
        self._record_extraction_receipt(extraction.receipt)
        self._begin_stage("reconstruction")
        try:
            new_ins = self._create_instruction(replacement, ins)
        finally:
            self._finish_stage("reconstruction")
        if new_ins is None:
            self._record_extraction_receipt(
                replace(
                    extraction.receipt,
                    skip_reason=ExtractionSkipReason.LOWERING_FAILED,
                    derivation_trace=(),
                )
            )
            return None
        family, source_name, aliases = selected
        provenance = (source_name, *aliases)
        self.last_rule_family = family
        self.last_rule_provenance = provenance
        self.last_derivation_trace = extraction.derivation_trace
        self.rule_provenance_history.append(provenance)
        logger.info(
            "egglog MBA rewrite at %#x: family=%s source=%s aliases=%s",
            getattr(ins, "ea", 0),
            family,
            source_name,
            aliases,
        )
        return new_ins

    def _check_and_replace_with_prepared_ast(
        self,
        ins,
        *,
        blk,
        destination_size: int,
    ):
        """Retain the configured cross-block preparation path.

        Native matcher terms deliberately reflect only one instruction.  When
        cross-block constant preparation is explicitly enabled, retain the
        established AST preparation/proof path rather than pretending those
        external constants are available to the local native view.
        """

        self._begin_stage("ast_construction")
        try:
            ast = minsn_to_ast(ins)
        finally:
            self._finish_stage("ast_construction")
        if ast is None:
            self._record_extraction_receipt(
                EgglogExtractionReceipt(skip_reason=ExtractionSkipReason.INTERNAL_ERROR)
            )
            return None
        self._begin_stage("native_preflight")
        try:
            lowering = lower_hexrays_island(ast, destination_size=destination_size)
            self.last_extraction_receipt = extraction_receipt_for_lowering(
                lowering,
                ExtractionSkipReason.INTERNAL_ERROR,
            )
            candidate_skip_reason = self._candidate_skip_reason(ast, ins)
            if candidate_skip_reason is not None:
                self._record_extraction_receipt(
                    extraction_receipt_for_lowering(lowering, candidate_skip_reason)
                )
                return None
            extraction_ast = ast
            known_constants = None
            if (
                self.cross_block_constant_preparation
                and blk is not None
                and getattr(blk, "mba", None) is not None
            ):
                prepared = prepare_ast_with_cross_block_constants(
                    blk.mba, blk, ins, ast
                )
                if prepared is not None:
                    extraction_ast = prepared.ast
                    known_constants = prepared.known_constants
            if (
                known_constants is None
                and self.cross_block_def_use_preparation
                and blk is not None
                and getattr(blk, "mba", None) is not None
            ):
                prepared = prepare_ast_with_def_use_constants(blk.mba, blk, ins, ast)
                if prepared is not None:
                    extraction_ast = prepared.ast
                    known_constants = prepared.known_constants
            extraction_budget = self._candidate_extraction_budget(blk)
            if extraction_budget is None:
                self._record_extraction_receipt(
                    extraction_receipt_for_lowering(
                        lowering, ExtractionSkipReason.TIME_BUDGET
                    )
                )
                return None
        finally:
            self._finish_stage("native_preflight")
        self._begin_stage("egglog_extraction")
        try:
            extraction = self._select_extraction(
                extraction_ast,
                destination_size=destination_size,
                budget=extraction_budget,
            )
        finally:
            self._finish_stage("egglog_extraction")
        self._record_extraction_receipt(extraction.receipt)
        replacement = extraction.replacement_ast
        if replacement is None:
            return None
        if self._node_count(replacement) >= self._node_count(ast):
            self._record_extraction_receipt(
                replace(
                    extraction.receipt,
                    skip_reason=ExtractionSkipReason.NO_DEGREE_ELIGIBLE_IMPROVEMENT,
                )
            )
            return None
        selected = extraction.selected_provenance
        if selected is None:
            self._record_extraction_receipt(
                replace(
                    extraction.receipt, skip_reason=ExtractionSkipReason.INTERNAL_ERROR
                )
            )
            return None
        proof_kwargs: dict[str, object] = {"width": destination_size * 8}
        if known_constants is not None:
            proof_kwargs["known_constants"] = known_constants
        certificate = self._native_proof_certificate(selected[1])
        if certificate is not None:
            proof_kwargs["certificate"] = certificate
            proof_kwargs["generic_native_z3_before_certificate"] = (
                self.generic_native_z3_before_certificate
            )
        self._begin_stage("native_z3")
        try:
            proved = prove_native_ast_equivalence(ast, replacement, **proof_kwargs)
        finally:
            self._finish_stage("native_z3")
        if not proved:
            self._record_extraction_receipt(
                replace(
                    extraction.receipt,
                    skip_reason=ExtractionSkipReason.NATIVE_Z3_FAILED,
                    derivation_trace=(),
                )
            )
            return None
        self._begin_stage("reconstruction")
        try:
            new_ins = self._create_instruction(replacement, ins)
        finally:
            self._finish_stage("reconstruction")
        if new_ins is None:
            self._record_extraction_receipt(
                replace(
                    extraction.receipt,
                    skip_reason=ExtractionSkipReason.LOWERING_FAILED,
                    derivation_trace=(),
                )
            )
            return None
        family, source_name, aliases = selected
        provenance = (source_name, *aliases)
        self.last_rule_family = family
        self.last_rule_provenance = provenance
        self.last_derivation_trace = extraction.derivation_trace
        if self._provider_outcome_history_enabled():
            self.rule_provenance_history.append(provenance)
        return new_ins

    @staticmethod
    def _with_native_match_telemetry(receipt, match_result, *, elapsed_ms):
        """Attach facts from one bounded native matcher invocation.

        This runs after matching only and never influences selection, proof, or
        mutation.  The binding count is the number of concrete live bindings
        retained across declaration-order matches, rather than a count of
        derived constraint values.
        """

        return replace(
            receipt,
            native_matcher_backend=getattr(match_result, "matcher_backend", "python"),
            native_matcher_comparisons=match_result.comparisons,
            native_matcher_lazy_swaps=getattr(
                match_result,
                "lazy_swaps",
                getattr(match_result, "commuted_branches", 0),
            ),
            native_fixed_binding_count=sum(
                len(
                    getattr(
                        match.bindings,
                        "native",
                        getattr(match.bindings, "terms", {}),
                    )
                )
                for match in match_result.matches
            ),
            native_matcher_elapsed_ms=elapsed_ms,
        )

    def _begin_stage_timing(self) -> None:
        self.last_stage_timings = EMPTY_MBA_STAGE_TIMINGS
        self._stage_timer = (
            MbaStageTimer(enabled=True) if self.collect_stage_timings else None
        )

    def _begin_stage(self, name: str) -> None:
        timer = self._stage_timer
        if timer is None:
            return
        try:
            timer.begin(name)
        except Exception:
            self._stage_timer = None

    def _finish_stage(self, name: str) -> None:
        timer = self._stage_timer
        if timer is None:
            return
        try:
            timer.finish(name)
        except Exception:
            self._stage_timer = None

    def _finish_stage_timing(self) -> None:
        timer = self._stage_timer
        self._stage_timer = None
        if timer is None:
            return
        try:
            self.last_stage_timings = timer.freeze()
        except Exception:
            self.last_stage_timings = EMPTY_MBA_STAGE_TIMINGS
            return
        if not self.last_stage_timings.stages:
            return
        outcome = self._last_provider_outcome
        if outcome is None:
            return
        metadata = dict(outcome.metadata or {})
        metadata["stage_timings_ms"] = self.last_stage_timings.as_dict()
        outcome = replace(outcome, metadata=metadata)
        self._last_provider_outcome = outcome
        if self._attempt_outcome_index is not None:
            self.provider_outcome_history.replace(self._attempt_outcome_index, outcome)

    def _record_extraction_receipt(self, receipt: EgglogExtractionReceipt) -> None:
        self.last_extraction_receipt = receipt
        outcome = egglog_receipt_to_outcome(receipt)
        self._last_provider_outcome = outcome
        if self._provider_outcome_history_enabled():
            if self._attempt_outcome_index is None:
                self._attempt_outcome_index = self.provider_outcome_history.append(
                    outcome
                )
            else:
                self.provider_outcome_history.replace(
                    self._attempt_outcome_index, outcome
                )
        skip_reason = (
            receipt.skip_reason.value if receipt.skip_reason is not None else None
        )
        logger.info(
            "egglog MBA extraction receipt: input_cost=%s extracted_cost=%s "
            "degree=%s eclasses=%s enodes=%s rule_firings=%s elapsed_ms=%s "
            "family=%s source=%s aliases=%s island=%s fingerprint=%s blockers=%s skip=%s",
            receipt.input_cost,
            receipt.extracted_cost,
            receipt.degree,
            receipt.eclass_count,
            receipt.enode_count,
            receipt.rule_firings,
            receipt.elapsed_ms,
            receipt.selected_family,
            receipt.selected_source,
            receipt.selected_aliases,
            receipt.island_class,
            receipt.island_fingerprint,
            receipt.blockers,
            skip_reason,
        )

    def provider_outcomes(self) -> tuple[MbaProviderOutcome, ...]:
        """Return one final outcome per attempted Egglog candidate."""

        return self.provider_outcome_history.outcomes()

    def provider_outcome_cursor(self) -> int:
        """Return a capture cursor for the bounded Egglog history."""

        return self.provider_outcome_history.cursor

    def provider_outcomes_since(self, cursor: int) -> tuple[MbaProviderOutcome, ...]:
        """Return one exact retained capture delta or fail closed on eviction."""

        return self.provider_outcome_history.since(cursor)

    def _finalize_candidate_outcome(
        self, *, accepted: bool, reason: str | None = None
    ) -> None:
        """Mark only an outer-accepted candidate as an applied mutation."""

        outcome = self._last_provider_outcome
        if outcome is None:
            return
        if outcome.status is not ProviderOutcomeStatus.IMPROVED:
            return
        metadata = dict(outcome.metadata or {})
        metadata["mutation_outcome"] = "accepted" if accepted else "rejected"
        if reason is not None:
            metadata["mutation_rejection_reason"] = reason
        finalized = replace(
            outcome,
            status=(
                ProviderOutcomeStatus.APPLIED
                if accepted
                else ProviderOutcomeStatus.IMPROVED
            ),
            refusal_reason=None if accepted else reason,
            metadata=metadata,
        )
        self._last_provider_outcome = finalized
        if self._attempt_outcome_index is not None:
            self.provider_outcome_history.replace(
                self._attempt_outcome_index,
                finalized,
            )

    def record_mutation_accepted(self) -> None:
        self._finalize_candidate_outcome(accepted=True)

    def record_mutation_rejected(self, reason: str) -> None:
        self._finalize_candidate_outcome(accepted=False, reason=reason)

    def execution_metadata(self) -> dict[str, object]:
        """Expose the latest extraction receipt and successful provenance."""
        receipt = self.last_extraction_receipt
        if receipt is None:
            return {}
        metadata: dict[str, object] = {
            "input_cost": receipt.input_cost,
            "canonicalizer_version": receipt.canonicalizer_version,
            "canonical_input_cost": receipt.canonical_input_cost,
            "normalization_steps": receipt.normalization_steps,
            "execution_path": receipt.execution_path,
            "cache_status": receipt.cache_status,
            "cache_key": receipt.cache_key,
            "extracted_cost": receipt.extracted_cost,
            "degree": receipt.degree,
            "eclass_count": receipt.eclass_count,
            "enode_count": receipt.enode_count,
            "rule_firings": receipt.rule_firings,
            "elapsed_ms": receipt.elapsed_ms,
            "selected_family": receipt.selected_family,
            "selected_source": receipt.selected_source,
            "selected_aliases": receipt.selected_aliases,
            "skip_reason": (
                receipt.skip_reason.value if receipt.skip_reason is not None else None
            ),
            "island_class": receipt.island_class,
            "island_fingerprint": receipt.island_fingerprint,
            "operator_count": receipt.operator_count,
            "distinct_leaf_count": receipt.distinct_leaf_count,
            "nonlinear_product_count": receipt.nonlinear_product_count,
            "blockers": receipt.blockers,
            "proof_mode": receipt.proof_mode,
            "template_source_name": receipt.template_source_name,
            "template_fallback_reason": receipt.template_fallback_reason,
            "template_proof_verdict": receipt.template_proof_verdict,
            "legacy_proof_verdict": receipt.legacy_proof_verdict,
            "template_proof_elapsed_ms": receipt.template_proof_elapsed_ms,
            "legacy_proof_elapsed_ms": receipt.legacy_proof_elapsed_ms,
            "native_matcher_backend": receipt.native_matcher_backend,
            "native_matcher_comparisons": receipt.native_matcher_comparisons,
            "native_matcher_lazy_swaps": receipt.native_matcher_lazy_swaps,
            "native_fixed_binding_count": receipt.native_fixed_binding_count,
            "native_matcher_elapsed_ms": receipt.native_matcher_elapsed_ms,
        }
        if receipt.selected_source is not None:
            source_names = (receipt.selected_source, *receipt.selected_aliases)
            metadata.update(
                {
                    "source_names": source_names,
                    "source_name": receipt.selected_source,
                    "aliases": receipt.selected_aliases,
                }
            )
        if receipt.selected_family is not None:
            metadata["family"] = receipt.selected_family
        if self.last_stage_timings.stages:
            metadata["stage_timings_ms"] = self.last_stage_timings.as_dict()
        if self.last_derivation_trace is not None:
            metadata["derivation_trace"] = self.last_derivation_trace
        outcome = self.provider_outcome()
        if outcome is not None:
            metadata["mba_provider_outcome"] = outcome.to_dict()
        return metadata

    def provider_outcome(self) -> MbaProviderOutcome | None:
        """Return the latest receipt as portable provider telemetry only.

        Extraction, native proof, and mutation stay unchanged.  This is an
        observation adapter for the common differential report boundary.
        """

        if self._last_provider_outcome is not None:
            return self._last_provider_outcome
        if self.last_extraction_receipt is None:
            return None
        return egglog_receipt_to_outcome(self.last_extraction_receipt)

    def _candidate_extraction_budget(
        self,
        blk,
    ) -> EgglogExtractionBudget | None:
        """Clamp one candidate's admission budget to its live function window."""

        tracker = self._function_budget
        if tracker is None or blk is None:
            return self.extraction_budget
        mba = getattr(blk, "mba", None)
        function_ea = int(getattr(mba, "entry_ea", 0) or 0)
        if mba is None or function_ea <= 0:
            return self.extraction_budget
        remaining_ms = tracker.remaining_ms((function_ea, id(mba)))
        candidate_time_budget_ms = min(
            self.extraction_budget.time_budget_ms, remaining_ms
        )
        if candidate_time_budget_ms < 50:
            return None
        return replace(
            self.extraction_budget,
            time_budget_ms=candidate_time_budget_ms,
        )

    def _select_extraction(
        self,
        ast: AstNode,
        *,
        destination_size: int,
        budget: EgglogExtractionBudget | None = None,
    ) -> EgglogExtractionResult:
        """Run one fresh bounded extraction with the configured rule objects."""
        self._ensure_catalogue_configured()
        return extract_bounded_candidate(
            ast,
            self._compiled_rules,
            self.extraction_budget if budget is None else budget,
            int(destination_size),
            catalogue=self._native_pattern_catalogue,
        )

    def _select_native_extraction(
        self,
        candidate_term,
        *,
        destination_size: int,
        profile,
        initial_replacements,
        block=None,
        destination=None,
        budget: EgglogExtractionBudget | None = None,
    ) -> EgglogExtractionResult:
        """Run bounded extraction after a direct ``minsn_t``/``mop_t`` match."""

        return extract_bounded_term(
            candidate_term,
            self._compiled_rules,
            self.extraction_budget if budget is None else budget,
            destination_size=destination_size,
            profile=profile,
            initial_replacements=initial_replacements,
            catalogue=self._native_pattern_catalogue,
            block=block,
            destination=destination,
        )

    @staticmethod
    def _read_native_view(ins, destination_size: int):
        """Read a callback-local view without AST or IR construction."""

        return NativeMbaTermView.from_instruction(
            ins,
            destination_size=destination_size,
        )

    def _native_proof_certificate(self, source_name: str) -> str | None:
        """Return a configured rule's bounded native proof plan, if any."""

        for rule in self._compiled_rules:
            if rule.source_name == source_name:
                certificate = getattr(rule.rule_type, "EGGLOG_CERTIFICATE_PROVER", None)
                return certificate if type(certificate) is str else None
        return None

    def _select_specialization(
        self, ast: AstNode, *, destination_size: int
    ) -> EgglogAddSpecialization | None:
        """Deprecated compatibility seam; the live handler uses one extraction."""
        self._ensure_catalogue_configured()
        width = int(destination_size) * 8
        best: EgglogAddSpecialization | None = None
        best_cost: int | None = None
        for rule in self._rules_by_root_opcode.get(int(ast.opcode), ()):
            specialization = specialize(
                rule,
                ast,
                destination_size=int(destination_size),
                rounds=self.rounds,
            )
            if specialization is None:
                continue
            if self._node_count(specialization.replacement_ast) >= self._node_count(
                ast
            ):
                continue
            if width not in rule.proof_widths:
                continue
            if not self._prove_ast_equivalence(
                ast, specialization.replacement_ast, width=width
            ):
                continue
            cost = self._node_count(specialization.replacement_ast)
            if best_cost is None or cost < best_cost:
                best = specialization
                best_cost = cost
        return best

    @staticmethod
    def _validate_families(families: object) -> tuple[str, ...]:
        if (
            not isinstance(families, list)
            or not families
            or any(type(value) is not str for value in families)
        ):
            raise ValueError(
                "EgglogOptimizer families must be a nonempty list of names"
            )
        resolved = tuple(families)
        if len(set(resolved)) != len(resolved):
            raise ValueError("EgglogOptimizer families must be unique")
        if "fixed_rotate" in resolved and len(resolved) != 1:
            raise ValueError(
                "EgglogOptimizer families fixed_rotate must be selected alone"
            )
        unsupported = tuple(
            family
            for family in resolved
            if family not in _ROOT_OPCODE_BY_OPERATION and family != "fixed_rotate"
        )
        if unsupported:
            raise ValueError(
                "EgglogOptimizer families must name supported families; got "
                + ", ".join(unsupported)
            )
        return resolved

    def _build_root_opcode_buckets(
        self,
        rules: tuple[CompiledEgglogRule, ...],
    ) -> MappingProxyType:
        buckets: dict[int, list[CompiledEgglogRule]] = {}
        for rule in rules:
            operation = getattr(getattr(rule, "pattern", None), "operation", None)
            if operation is None and self.families == _DEFAULT_FAMILIES:
                # Preserve the private ADD-only test seam used by legacy
                # selection tests whose synthetic rules have no DSL pattern.
                operation = "add"
            opcode = _ROOT_OPCODE_BY_OPERATION.get(operation)
            if opcode is None:
                raise ValueError(
                    f"Egglog rule {rule.source_name} has unsupported root operation "
                    f"{operation!r}"
                )
            buckets.setdefault(opcode, []).append(rule)
        return MappingProxyType(
            {opcode: tuple(bucket) for opcode, bucket in buckets.items()}
        )

    def _is_candidate(self, ast, ins) -> bool:
        return self._candidate_skip_reason(ast, ins) is None

    def _candidate_skip_reason(self, ast, ins) -> ExtractionSkipReason | None:
        if ins.d is None or int(ins.d.size) not in _VALID_SIZES:
            return ExtractionSkipReason.UNSUPPORTED_WIDTH_SEMANTICS
        leaves = ast.get_leaf_list()
        variable_leaves = [leaf for leaf in leaves if not leaf.is_constant()]
        unique_variable_leaves = {
            self._leaf_identity(leaf): leaf for leaf in variable_leaves
        }
        if any(
            int(getattr(leaf.mop, "size", 0)) != int(ins.d.size)
            for leaf in unique_variable_leaves.values()
        ):
            return ExtractionSkipReason.UNSUPPORTED_WIDTH_SEMANTICS
        if not unique_variable_leaves or len(unique_variable_leaves) > self.max_leaves:
            return ExtractionSkipReason.CANDIDATE_BUDGET
        opcodes = self._opcodes(ast)
        if not opcodes or not opcodes <= _SUPPORTED_ROOT_OPCODES:
            return ExtractionSkipReason.NON_MBA_CANDIDATE
        if len(opcodes) > self.max_operator_nodes:
            # The exact operator-node count is checked below; this cheap set-size
            # gate only avoids walking obviously oversized heterogeneous trees.
            return ExtractionSkipReason.CANDIDATE_BUDGET
        if self._operator_node_count(ast) > self.max_operator_nodes:
            return ExtractionSkipReason.CANDIDATE_BUDGET
        return None

    def _native_view_skip_reason(self, profile) -> ExtractionSkipReason | None:
        """Apply the live limits to a direct read-only microcode view."""

        if profile.blockers:
            return ExtractionSkipReason.UNSUPPORTED_WIDTH_SEMANTICS
        if profile.operator_count > self.max_operator_nodes:
            return ExtractionSkipReason.CANDIDATE_BUDGET
        if (
            not profile.distinct_leaf_count
            or profile.distinct_leaf_count > self.max_leaves
        ):
            return ExtractionSkipReason.CANDIDATE_BUDGET
        if not profile.operations:
            return ExtractionSkipReason.NON_MBA_CANDIDATE
        return None

    @staticmethod
    def _operator_node_count(node) -> int:
        if node is None or node.is_leaf():
            return 0
        return (
            1
            + EgglogOptimizer._operator_node_count(node.left)
            + EgglogOptimizer._operator_node_count(node.right)
        )

    @staticmethod
    def _opcodes(node) -> set[int]:
        if node is None or node.is_leaf():
            return set()
        return (
            {int(node.opcode)}
            | EgglogOptimizer._opcodes(node.left)
            | EgglogOptimizer._opcodes(node.right)
        )

    @staticmethod
    def _leaf_identity(leaf) -> int:
        ast_index = getattr(leaf, "ast_index", None)
        return id(leaf) if ast_index is None else int(ast_index)

    @staticmethod
    def _node_count(node) -> int:
        if node is None:
            return 0
        if _is_native_instruction(node):
            return 1
        if node.is_leaf():
            return 1
        return (
            1
            + EgglogOptimizer._node_count(node.left)
            + EgglogOptimizer._node_count(node.right)
        )

    def _prove_selected_replacement(
        self,
        original: AstNode,
        replacement: AstNode,
        *,
        original_term,
        replacement_term,
        selected: tuple[str, str, tuple[str, ...]],
        width: int,
    ) -> tuple[
        bool,
        str | None,
        str | None,
        bool | None,
        bool | None,
        float | None,
        float | None,
    ]:
        """Run the configured template mode without weakening native proof."""

        if selected[0] == "fixed_rotate":
            proved = prove_typed_term_equivalence(original_term, replacement_term)
            return (
                proved,
                selected[1],
                None,
                proved,
                proved,
                None,
                None,
            )

        certificate = self._native_proof_certificate(selected[1])

        def prove_native_ast() -> bool:
            if certificate is not None:
                return prove_native_ast_equivalence(
                    original,
                    replacement,
                    width=width,
                    certificate=certificate,
                    generic_native_z3_before_certificate=(
                        self.generic_native_z3_before_certificate
                    ),
                )
            return self._prove_ast_equivalence(
                original,
                replacement,
                width=width,
                timeout_ms=self._native_z3_timeout_ms(),
            )

        if self.native_proof_mode == "legacy":
            legacy_started = time.perf_counter()
            legacy_proved = prove_native_ast()
            return (
                legacy_proved,
                None,
                None,
                None,
                legacy_proved,
                None,
                (time.perf_counter() - legacy_started) * 1000.0,
            )
        family, source_name, _aliases = selected
        rule = next(
            (
                candidate
                for candidate in self._compiled_rules
                if candidate.family == family and candidate.source_name == source_name
            ),
            None,
        )
        template: NativeZ3ProofTemplate | None = (
            None if rule is None else self._proof_templates.get((id(rule), width))
        )
        template_proved: bool | None = None
        template_elapsed_ms: float | None = None
        fallback_reason: str | None = None
        if template is None:
            fallback_reason = "template_unavailable"
        else:
            validation = template.validate_terms(original_term, replacement_term)
            if validation is None:
                fallback_reason = "shape_mismatch"
            else:
                template_started = time.perf_counter()
                template_proved = template.prove_validation(validation)
                template_elapsed_ms = (time.perf_counter() - template_started) * 1000.0
                if not template_proved:
                    fallback_reason = "template_proof_failed"
        legacy_started = time.perf_counter()
        legacy_proved = prove_native_ast()
        legacy_elapsed_ms = (time.perf_counter() - legacy_started) * 1000.0
        if self.native_proof_mode == "shadow":
            if template_proved is not None and template_proved != legacy_proved:
                return (
                    False,
                    template.source_name if template else None,
                    "shadow_divergence",
                    template_proved,
                    legacy_proved,
                    template_elapsed_ms,
                    legacy_elapsed_ms,
                )
            return (
                legacy_proved,
                template.source_name if template else None,
                fallback_reason,
                template_proved,
                legacy_proved,
                template_elapsed_ms,
                legacy_elapsed_ms,
            )
        if template_proved is True:
            return (
                True,
                template.source_name if template else None,
                None,
                True,
                legacy_proved,
                template_elapsed_ms,
                legacy_elapsed_ms,
            )
        return (
            legacy_proved,
            template.source_name if template else None,
            fallback_reason,
            template_proved,
            legacy_proved,
            template_elapsed_ms,
            legacy_elapsed_ms,
        )

    def _native_z3_timeout_ms(self) -> int:
        """Use the extended native-proof timeout only when explicitly opted in.

        A large extraction budget alone does not alter interactive mutation
        behavior.  Noninteractive corpus/profile configurations may request a
        longer proof, but it remains finitely capped.
        """

        if self.execution_mode == "noninteractive":
            return min(self.time_budget_ms, _MAX_NATIVE_Z3_TIMEOUT_MS)
        return _INTERACTIVE_NATIVE_Z3_TIMEOUT_MS

    @staticmethod
    def _prove_ast_equivalence(
        original: AstNode, replacement: AstNode, *, width: int, timeout_ms: int = 50
    ) -> bool:
        """Prove concrete native AST equivalence at the destination width."""
        if type(timeout_ms) is not int or timeout_ms <= 0:
            return False
        try:
            import z3

            variables = {}

            def visit(node):
                if node is None:
                    raise ValueError("missing AST operand")
                if node.is_leaf():
                    if node.is_constant():
                        return z3.BitVecVal(int(node.value), width)
                    mop = getattr(node, "mop", None)
                    if mop is None:
                        raise ValueError("missing AST leaf operand")
                    key = ("mop", *semantic_native_leaf_key(mop))
                    hash(key)
                    return variables.setdefault(
                        key, z3.BitVec(f"egglog_leaf_{len(variables)}", width)
                    )
                left = visit(node.left)
                right = visit(node.right) if node.right is not None else None
                operations = {
                    ida_hexrays.m_add: lambda: left + right,
                    ida_hexrays.m_sub: lambda: left - right,
                    ida_hexrays.m_mul: lambda: left * right,
                    ida_hexrays.m_and: lambda: left & right,
                    ida_hexrays.m_or: lambda: left | right,
                    ida_hexrays.m_xor: lambda: left ^ right,
                    ida_hexrays.m_neg: lambda: -left,
                    ida_hexrays.m_bnot: lambda: ~left,
                }
                operation = operations.get(node.opcode)
                if operation is None:
                    raise ValueError(f"unsupported AST opcode: {node.opcode}")
                return operation()

            solver = z3.Solver()
            solver.set(timeout=timeout_ms)
            solver.add(visit(original) != visit(replacement))
            return solver.check() == z3.unsat
        except Exception:
            return False

    @staticmethod
    def _create_instruction(replacement: AstNode, original_ins):
        if _is_native_instruction(replacement):
            return replacement
        new_mop = replacement.create_mop(original_ins.ea)
        if new_mop is None:
            return None
        new_ins = ida_hexrays.minsn_t(original_ins.ea)
        new_ins.opcode = ida_hexrays.m_mov
        new_ins.l = new_mop
        new_ins.d = original_ins.d
        return new_ins

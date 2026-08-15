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
    compiled_rules_for_families,
    specialize,
)
from d810.backends.mba.egglog_saturation import (
    EgglogExtractionBudget,
    EgglogExtractionReceipt,
    EgglogExtractionResult,
    ExtractionSkipReason,
    extraction_receipt_for_profile,
    extract_bounded_candidate,
    extract_bounded_term,
)
from d810.backends.mba.hexrays_island import (
    lower_hexrays_island,
    rebuild_hexrays_island,
)
from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue
from d810.backends.mba.native_mba_term_view import NativeMbaTermView
from d810.backends.mba.native_z3_proof_template import (
    NativeZ3ProofTemplate,
    native_z3_proof_templates_for_rules,
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
from d810.mba.typed_term import canonicalize_ac_term
from d810.mba.provider_outcome import MbaProviderOutcome, ProviderOutcomeStatus
from d810.optimizers.microcode.instructions.peephole.handler import (
    PeepholeSimplificationRule,
)

logger = getLogger(__name__)

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
        self.rule_provenance_history: list[tuple[str, ...]] = []
        self.provider_outcome_history: list[MbaProviderOutcome] = []
        self._attempt_outcome_index: int | None = None
        self.collect_stage_timings = False
        self.last_stage_timings = EMPTY_MBA_STAGE_TIMINGS
        self._stage_timer: MbaStageTimer | None = None

    def _begin_provider_attempt(self) -> None:
        """Start one observable attempt, independent of whether it mutates."""

        self._attempt_outcome_index = None

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
        self._native_pattern_catalogue = CompiledPatternCatalogue.from_rules(
            self._compiled_rules
        )
        self._proof_templates = native_z3_proof_templates_for_rules(
            self._compiled_rules
        )
        self._catalogue_configured = True

    def _ensure_catalogue_configured(self) -> None:
        """Compile the default selection only when a direct handler is used."""
        if not self._catalogue_configured:
            self._catalogue = _SelectedRuleCatalogue(
                compiled_rules_for_families(self.families)
            )

    def check_and_replace(self, blk, ins):
        """Return a replacement only after extraction, shrink, and proof."""
        del blk
        self.last_rule_family = None
        self.last_rule_provenance = None
        self.last_derivation_trace = None
        self.last_extraction_receipt = None
        self._begin_provider_attempt()
        self._begin_stage_timing()
        try:
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
            return self._check_and_replace(ins)
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

    def _check_and_replace(self, ins):
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
            matcher_started = (
                time.perf_counter() if self.collect_stage_timings else None
            )
            match_result = self._native_pattern_catalogue.match_root(
                view, comparison_budget=_MAX_PATTERN_COMPARISONS
            )
            matcher_elapsed_ms = (
                None
                if matcher_started is None
                else (time.perf_counter() - matcher_started) * 1000.0
            )
            if match_result.comparison_budget_exceeded:
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
            matches = match_result.matches
            if not matches:
                self._record_extraction_receipt(
                    self._with_native_match_telemetry(
                        extraction_receipt_for_profile(
                            native_result.profile,
                            ExtractionSkipReason.NO_DEGREE_ELIGIBLE_IMPROVEMENT,
                        ),
                        match_result,
                        elapsed_ms=matcher_elapsed_ms,
                    )
                )
                return None
        finally:
            self._finish_stage("native_preflight")
        candidate_term = canonicalize_ac_term(
            (
                view.to_typed_term()
                if match_result.candidate_term is None
                else match_result.candidate_term
            )
        )
        initial_replacements = {
            id(match.rule): match.bindings.materialize_replacement(match.rule)
            for match in matches
        }

        self._begin_stage("egglog_extraction")
        try:
            extraction = self._select_native_extraction(
                candidate_term,
                destination_size=destination_size,
                profile=native_result.profile,
                initial_replacements=initial_replacements,
            )
        finally:
            self._finish_stage("egglog_extraction")
        extraction = replace(
            extraction,
            receipt=self._with_native_match_telemetry(
                extraction.receipt,
                match_result,
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
        if lowering.term is None or lowering.term != candidate_term:
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
            native_matcher_backend=match_result.matcher_backend,
            native_matcher_comparisons=match_result.comparisons,
            native_matcher_lazy_swaps=match_result.lazy_swaps,
            native_fixed_binding_count=sum(
                len(match.bindings.native) for match in match_result.matches
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
        if not self.last_stage_timings.stages or self._attempt_outcome_index is None:
            return
        outcome = self.provider_outcome_history[self._attempt_outcome_index]
        metadata = dict(outcome.metadata or {})
        metadata["stage_timings_ms"] = self.last_stage_timings.as_dict()
        self.provider_outcome_history[self._attempt_outcome_index] = replace(
            outcome,
            metadata=metadata,
        )

    def _record_extraction_receipt(self, receipt: EgglogExtractionReceipt) -> None:
        self.last_extraction_receipt = receipt
        outcome = egglog_receipt_to_outcome(receipt)
        if self._attempt_outcome_index is None:
            self.provider_outcome_history.append(outcome)
            self._attempt_outcome_index = len(self.provider_outcome_history) - 1
        else:
            self.provider_outcome_history[self._attempt_outcome_index] = outcome
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

        return tuple(self.provider_outcome_history)

    def _finalize_candidate_outcome(
        self, *, accepted: bool, reason: str | None = None
    ) -> None:
        """Mark only an outer-accepted candidate as an applied mutation."""

        if self._attempt_outcome_index is None:
            return
        outcome = self.provider_outcome_history[self._attempt_outcome_index]
        if outcome.status is not ProviderOutcomeStatus.IMPROVED:
            return
        metadata = dict(outcome.metadata or {})
        metadata["mutation_outcome"] = "accepted" if accepted else "rejected"
        if reason is not None:
            metadata["mutation_rejection_reason"] = reason
        self.provider_outcome_history[self._attempt_outcome_index] = replace(
            outcome,
            status=(
                ProviderOutcomeStatus.APPLIED
                if accepted
                else ProviderOutcomeStatus.IMPROVED
            ),
            refusal_reason=None if accepted else reason,
            metadata=metadata,
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

        if self._attempt_outcome_index is not None:
            return self.provider_outcome_history[self._attempt_outcome_index]
        if self.last_extraction_receipt is None:
            return None
        return egglog_receipt_to_outcome(self.last_extraction_receipt)

    def _select_extraction(
        self, ast: AstNode, *, destination_size: int
    ) -> EgglogExtractionResult:
        """Run one fresh bounded extraction with the configured rule objects."""
        self._ensure_catalogue_configured()
        return extract_bounded_candidate(
            ast,
            self._compiled_rules,
            self.extraction_budget,
            int(destination_size),
        )

    def _select_native_extraction(
        self,
        candidate_term,
        *,
        destination_size: int,
        profile,
        initial_replacements,
    ) -> EgglogExtractionResult:
        """Run bounded extraction after a direct ``minsn_t``/``mop_t`` match."""

        return extract_bounded_term(
            candidate_term,
            self._compiled_rules,
            self.extraction_budget,
            destination_size=destination_size,
            profile=profile,
            initial_replacements=initial_replacements,
        )

    @staticmethod
    def _read_native_view(ins, destination_size: int):
        """Read a callback-local view without AST or IR construction."""

        return NativeMbaTermView.from_instruction(
            ins,
            destination_size=destination_size,
        )

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
        unsupported = tuple(
            family for family in resolved if family not in _ROOT_OPCODE_BY_OPERATION
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

        if self.native_proof_mode == "legacy":
            legacy_started = time.perf_counter()
            legacy_proved = self._prove_ast_equivalence(
                original,
                replacement,
                width=width,
                timeout_ms=self._native_z3_timeout_ms(),
            )
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
        legacy_proved = self._prove_ast_equivalence(
            original,
            replacement,
            width=width,
            timeout_ms=self._native_z3_timeout_ms(),
        )
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
                    try:
                        hash(mop)
                        key = ("mop", mop)
                    except TypeError:
                        key = ("mop", repr(mop))
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
        new_mop = replacement.create_mop(original_ins.ea)
        if new_mop is None:
            return None
        new_ins = ida_hexrays.minsn_t(original_ins.ea)
        new_ins.opcode = ida_hexrays.m_mov
        new_ins.l = new_mop
        new_ins.d = original_ins.d
        return new_ins

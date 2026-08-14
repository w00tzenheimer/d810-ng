"""Bounded, proof-gated Egglog MBA instruction rule.

This is intentionally *not* a second global instruction optimizer.  Egglog is
an opt-in peephole rule, so the normal project configuration and execution
scope decide when it may run.  Each candidate gets a fresh e-graph; no facts
or expressions leak between instructions or decompilations.
"""

from __future__ import annotations

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
    extraction_receipt_for_lowering,
    extract_bounded_candidate,
)
from d810.backends.mba.hexrays_island import lower_hexrays_island
from d810.backends.mba.native_z3 import prove_native_ast_equivalence
from d810.core import getLogger
from d810.hexrays.expr.ast import AstNode
from d810.hexrays.ir_maturity import ir_maturity_to_ida
from d810.hexrays.ir.minsn_utils import minsn_to_ast
from d810.ir.maturity import IRMaturity
from d810.mba.differential_report import egglog_receipt_to_outcome
from d810.mba.provider_outcome import MbaProviderOutcome, ProviderOutcomeStatus
from d810.mba.provider_history import ProviderOutcomeHistory
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

    def _begin_provider_attempt(self) -> None:
        """Start one observable attempt, independent of whether it mutates."""

        self._attempt_outcome_index = None
        self._last_provider_outcome = None

    def _provider_outcome_capture_enabled(self) -> bool:
        return self._provider_outcome_capture_depth > 0

    def begin_provider_outcome_capture(self) -> None:
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
        if ins.opcode not in _SUPPORTED_ROOT_OPCODES:
            self._record_extraction_receipt(
                EgglogExtractionReceipt(
                    skip_reason=ExtractionSkipReason.NON_MBA_CANDIDATE
                )
            )
            return None
        try:
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

    def _check_and_replace(self, ins):
        self.last_rule_family = None
        self.last_rule_provenance = None
        self.last_derivation_trace = None
        self.last_extraction_receipt = None
        self._begin_provider_attempt()
        ast = minsn_to_ast(ins)
        if ast is None:
            self._record_extraction_receipt(
                EgglogExtractionReceipt(skip_reason=ExtractionSkipReason.INTERNAL_ERROR)
            )
            return None
        lowering = lower_hexrays_island(ast, destination_size=int(ins.d.size))
        # Preserve the candidate profile if a later preflight step raises; the
        # callback guard upgrades only the provider outcome to internal_error.
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

        extraction = self._select_extraction(ast, destination_size=int(ins.d.size))
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
                    extraction.receipt,
                    skip_reason=ExtractionSkipReason.INTERNAL_ERROR,
                )
            )
            return None
        width = int(ins.d.size) * 8
        if not self._prove_ast_equivalence(ast, replacement, width=width):
            self._record_extraction_receipt(
                replace(
                    extraction.receipt,
                    skip_reason=ExtractionSkipReason.NATIVE_Z3_FAILED,
                    derivation_trace=(),
                )
            )
            return None
        new_ins = self._create_instruction(replacement, ins)
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
        if self._provider_outcome_capture_enabled():
            self.rule_provenance_history.append(provenance)
        logger.info(
            "egglog MBA rewrite at %#x: family=%s source=%s aliases=%s",
            getattr(ins, "ea", 0),
            family,
            source_name,
            aliases,
        )
        return new_ins

    def _record_extraction_receipt(self, receipt: EgglogExtractionReceipt) -> None:
        self.last_extraction_receipt = receipt
        outcome = egglog_receipt_to_outcome(receipt)
        self._last_provider_outcome = outcome
        if not self._provider_outcome_capture_enabled():
            return
        if self._attempt_outcome_index is None:
            self._attempt_outcome_index = self.provider_outcome_history.append(outcome)
        else:
            self.provider_outcome_history.replace(self._attempt_outcome_index, outcome)
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

    @staticmethod
    def _prove_ast_equivalence(
        original: AstNode, replacement: AstNode, *, width: int
    ) -> bool:
        """Compatibility facade for the shared native Z3 mutation gate."""

        return prove_native_ast_equivalence(original, replacement, width=width)

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

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
    extract_bounded_candidate,
)
from d810.core import getLogger
from d810.hexrays.expr.ast import AstNode
from d810.hexrays.ir_maturity import ir_maturity_to_ida
from d810.hexrays.ir.minsn_utils import minsn_to_ast
from d810.ir.maturity import IRMaturity
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
    order as the stable tie-breaker.
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
        self.rule_provenance_history: list[tuple[str, ...]] = []

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
        if ins.opcode not in _SUPPORTED_ROOT_OPCODES:
            return None
        try:
            return self._check_and_replace(ins)
        except Exception:  # Never leak an exception through Hex-Rays' callback.
            if self.last_extraction_receipt is not None:
                self._record_extraction_receipt(
                    replace(
                        self.last_extraction_receipt,
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
        self.last_extraction_receipt = None
        ast = minsn_to_ast(ins)
        if ast is None:
            return None
        if not self._is_candidate(ast, ins):
            self._record_extraction_receipt(
                EgglogExtractionReceipt(
                    skip_reason=ExtractionSkipReason.UNSUPPORTED_WIDTH_SEMANTICS
                )
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
                )
            )
            return None
        new_ins = self._create_instruction(replacement, ins)
        if new_ins is None:
            self._record_extraction_receipt(
                replace(
                    extraction.receipt,
                    skip_reason=ExtractionSkipReason.LOWERING_FAILED,
                )
            )
            return None
        family, source_name, aliases = selected
        provenance = (source_name, *aliases)
        self.last_rule_family = family
        self.last_rule_provenance = provenance
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
        skip_reason = (
            receipt.skip_reason.value if receipt.skip_reason is not None else None
        )
        logger.info(
            "egglog MBA extraction receipt: input_cost=%s extracted_cost=%s "
            "degree=%s eclasses=%s enodes=%s rule_firings=%s elapsed_ms=%s "
            "family=%s source=%s aliases=%s skip=%s",
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
            skip_reason,
        )

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
        return metadata

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
        if ins.d is None or int(ins.d.size) not in _VALID_SIZES:
            return False
        leaves = ast.get_leaf_list()
        variable_leaves = [leaf for leaf in leaves if not leaf.is_constant()]
        unique_variable_leaves = {
            self._leaf_identity(leaf): leaf for leaf in variable_leaves
        }
        if not unique_variable_leaves or len(unique_variable_leaves) > self.max_leaves:
            return False
        if any(
            int(getattr(leaf.mop, "size", 0)) != int(ins.d.size)
            for leaf in unique_variable_leaves.values()
        ):
            return False
        opcodes = self._opcodes(ast)
        return bool(opcodes & _BOOL_OPCODES) and bool(opcodes & _ARITH_OPCODES)

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
        """Prove concrete native AST equivalence at the destination width."""
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
            solver.set(timeout=50)
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

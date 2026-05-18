"""Fact-type alias registry used at the diagnostics boundary.

The registry is the single source of truth that maps a canonical value-flow
fact type to:

- the legacy serialized kind names produced by older collectors and
  persisted into diag SQLite snapshots;
- a human-readable display name used by CLI / diagnostic output;
- the industry-standard term (LLVM MemorySSA, angr, SVF, etc.);
- the producer ontology (which collectors emit observations that land in
  this canonical bucket).

Diagnostic readers should call :func:`canonical_fact_type` to translate an
observed ``FactObservation.kind`` row into the canonical surface, while
preserving the original observed kind in the raw snapshot row. This lets
old snapshots remain queryable through canonical names without lossy
rewrites.

During Phase 3 of the value-flow terminology rename the canonical type and
the legacy serialized kind have identical string values (no schema
migration yet). Phase 4 may introduce new canonical values; the alias
registry then carries the legacy strings forward without breaking older
diag SQLite snapshots.
"""
from __future__ import annotations

from dataclasses import dataclass
from d810.core.typing import Mapping

from d810.recon.facts.value_flow.call_effect_summary import (
    CALL_EFFECT_SUMMARY_FACT_TYPE,
)
from d810.recon.facts.value_flow.call_return_value import (
    CALL_RETURN_VALUE_FACT_TYPE,
)
from d810.recon.facts.value_flow.effect_path import EFFECT_PATH_FACT_TYPE
from d810.recon.facts.value_flow.induction_variable import (
    INDUCTION_VARIABLE_FACT_TYPE,
)
from d810.recon.facts.value_flow.loop_predicate_value import (
    LOOP_PREDICATE_VALUE_FACT_TYPE,
)
from d810.recon.facts.value_flow.materialization_point import (
    MATERIALIZATION_POINT_FACT_TYPE,
)
from d810.recon.facts.value_flow.must_alias import MUST_ALIAS_FACT_TYPE
from d810.recon.facts.value_flow.observable_memory_def import (
    OBSERVABLE_MEMORY_DEF_FACT_TYPE,
)
from d810.recon.facts.value_flow.scalar_promotion import (
    SCALAR_PROMOTION_FACT_TYPE,
)
from d810.recon.facts.value_flow.scalar_replacement import (
    SCALAR_REPLACEMENT_FACT_TYPE,
)
from d810.recon.facts.value_flow.state_transition import (
    STATE_TRANSITION_FACT_TYPE,
)
from d810.recon.facts.value_flow.state_write import STATE_WRITE_FACT_TYPE
from d810.recon.facts.value_flow.symbolic_expression import (
    SYMBOLIC_EXPRESSION_FACT_TYPE,
)


@dataclass(frozen=True)
class FactTypeAlias:
    """Canonical-to-legacy mapping for one value-flow fact family.

    The canonical fact type is the public ontology label. The legacy
    kinds tuple lists every serialized ``FactObservation.kind`` value that
    must normalize to this canonical type for diagnostic queries. During
    Phase 3 every alias contains exactly one legacy kind equal to the
    canonical type's current string value.
    """

    canonical_fact_type: str
    legacy_kinds: tuple[str, ...]
    display_name: str
    industry_term: str
    producer_ontology: str


FACT_TYPE_ALIAS_REGISTRY: tuple[FactTypeAlias, ...] = (
    FactTypeAlias(
        canonical_fact_type=OBSERVABLE_MEMORY_DEF_FACT_TYPE,
        legacy_kinds=("ObservableStoreFact",),
        display_name="Observable memory def",
        industry_term="LLVM MemorySSA MemoryDef (externally visible) / angr store action",
        producer_ontology="Hodur TerminalByteEmitter and OLLVM oracle output-store candidates.",
    ),
    FactTypeAlias(
        canonical_fact_type=SCALAR_PROMOTION_FACT_TYPE,
        legacy_kinds=("CarrierStorePromotionFact",),
        display_name="Scalar promotion",
        industry_term="LLVM mem2reg / scalar-promotion",
        producer_ontology="OLLVM accumulator and output-store carrier facts.",
    ),
    FactTypeAlias(
        canonical_fact_type=MUST_ALIAS_FACT_TYPE,
        legacy_kinds=("SameCarrierAliasFact",),
        display_name="Must-alias",
        industry_term="Alias-analysis MustAlias",
        producer_ontology="OLLVM accumulator same-carrier alias proofs.",
    ),
    FactTypeAlias(
        canonical_fact_type=SCALAR_REPLACEMENT_FACT_TYPE,
        legacy_kinds=("LocalStorageScalarizationFact",),
        display_name="Scalar replacement",
        industry_term="LLVM SROA / scalar replacement",
        producer_ontology="OLLVM local-pointer / accumulator carriers with proven local base.",
    ),
    FactTypeAlias(
        canonical_fact_type=SYMBOLIC_EXPRESSION_FACT_TYPE,
        legacy_kinds=("ExpressionCarrierFact",),
        display_name="Symbolic expression",
        industry_term="angr Claripy AST / LLVM SSA value",
        producer_ontology="OLLVM accumulator carrier semantic expression proofs.",
    ),
    FactTypeAlias(
        canonical_fact_type=LOOP_PREDICATE_VALUE_FACT_TYPE,
        legacy_kinds=("LoopPredicateCarrierFact",),
        display_name="Loop-predicate value",
        industry_term="Loop-predicate / loop-bound value",
        producer_ontology="Hodur LoopCarrierFact and OLLVM LOOP_INDEX_CARRIER role.",
    ),
    FactTypeAlias(
        canonical_fact_type=CALL_RETURN_VALUE_FACT_TYPE,
        legacy_kinds=("CallResultCarrierFact",),
        display_name="Call return value",
        industry_term="Call return value (ABI return)",
        producer_ontology="OLLVM PASSWORD_COMPARE_RESULT and similar call-result carriers.",
    ),
    FactTypeAlias(
        canonical_fact_type=INDUCTION_VARIABLE_FACT_TYPE,
        legacy_kinds=("GenericInductionCarrierFact",),
        display_name="Induction variable",
        industry_term="Loop induction variable",
        producer_ontology="Hodur InductionCarrierFact (recurrences and direct copies).",
    ),
    FactTypeAlias(
        canonical_fact_type=MATERIALIZATION_POINT_FACT_TYPE,
        legacy_kinds=("TerminalMaterializationFact",),
        display_name="Materialization point",
        industry_term="Materialization point (return value, output exposure)",
        producer_ontology="Hodur ReturnCarrierFact and ReturnFrontierFact terminals.",
    ),
    FactTypeAlias(
        canonical_fact_type=STATE_WRITE_FACT_TYPE,
        legacy_kinds=("StateVariableWriteFact",),
        display_name="State write",
        industry_term="LLVM MemoryDef / angr store action over FSM state variable",
        producer_ontology="Hodur StateWriteAnchorFact.",
    ),
    FactTypeAlias(
        canonical_fact_type=STATE_TRANSITION_FACT_TYPE,
        legacy_kinds=("StateTransitionCarrierFact",),
        display_name="State transition",
        industry_term="FSM transition edge (or LLVM MemoryPhi at joins)",
        producer_ontology="Hodur StateTransitionAnchorFact.",
    ),
    FactTypeAlias(
        canonical_fact_type=EFFECT_PATH_FACT_TYPE,
        legacy_kinds=("SideEffectCorridorFact",),
        display_name="Effect path",
        industry_term="Effect system / LLVM ModRef path / angr action sequence",
        producer_ontology="Hodur ByteEmitCorridorFact.",
    ),
    FactTypeAlias(
        canonical_fact_type=CALL_EFFECT_SUMMARY_FACT_TYPE,
        legacy_kinds=("CallSideEffectAnchorFact",),
        display_name="Call effect summary",
        industry_term="LLVM ModRef call summary",
        producer_ontology="Hodur CallAnchorFact.",
    ),
)


def _build_canonical_lookup() -> Mapping[str, FactTypeAlias]:
    lookup: dict[str, FactTypeAlias] = {}
    for alias in FACT_TYPE_ALIAS_REGISTRY:
        lookup[alias.canonical_fact_type] = alias
        for legacy in alias.legacy_kinds:
            lookup[legacy] = alias
    return lookup


_CANONICAL_LOOKUP: Mapping[str, FactTypeAlias] = _build_canonical_lookup()


def canonical_fact_type(observed_kind: str) -> str | None:
    """Return the canonical fact type for *observed_kind*, or ``None``.

    *observed_kind* may be either the canonical type or a legacy serialized
    kind from an old diag snapshot. Unknown kinds return ``None`` so the
    caller can preserve the raw value rather than coerce it into the
    canonical surface.
    """

    alias = _CANONICAL_LOOKUP.get(observed_kind)
    return None if alias is None else alias.canonical_fact_type


def legacy_kinds_for(fact_type: str) -> tuple[str, ...]:
    """Return the legacy serialized kinds for *fact_type*.

    Returns an empty tuple when *fact_type* is unknown.
    """

    alias = _CANONICAL_LOOKUP.get(fact_type)
    return () if alias is None else alias.legacy_kinds


def display_name_for(fact_type: str) -> str | None:
    """Return the canonical display name for *fact_type*."""

    alias = _CANONICAL_LOOKUP.get(fact_type)
    return None if alias is None else alias.display_name


def industry_term_for(fact_type: str) -> str | None:
    """Return the industry-standard term description for *fact_type*."""

    alias = _CANONICAL_LOOKUP.get(fact_type)
    return None if alias is None else alias.industry_term


def producer_ontology_for(fact_type: str) -> str | None:
    """Return the producer-ontology description for *fact_type*."""

    alias = _CANONICAL_LOOKUP.get(fact_type)
    return None if alias is None else alias.producer_ontology


def all_canonical_fact_types() -> tuple[str, ...]:
    """Return every canonical fact type known to the registry."""

    return tuple(alias.canonical_fact_type for alias in FACT_TYPE_ALIAS_REGISTRY)


def all_legacy_kinds() -> frozenset[str]:
    """Return every legacy serialized kind known to the registry."""

    return frozenset(
        legacy
        for alias in FACT_TYPE_ALIAS_REGISTRY
        for legacy in alias.legacy_kinds
    )


__all__ = [
    "FACT_TYPE_ALIAS_REGISTRY",
    "FactTypeAlias",
    "all_canonical_fact_types",
    "all_legacy_kinds",
    "canonical_fact_type",
    "display_name_for",
    "industry_term_for",
    "legacy_kinds_for",
    "producer_ontology_for",
]

"""Fact-type schema registry used at the diagnostics boundary.

The registry is the single source of truth that maps observed producer/schema
names onto canonical value-flow fact types.  It exists because D-810 records
both raw source observations (for example ``ReturnCarrierFact``) and projected
value-flow facts. Diagnostic readers should call :func:`canonical_fact_type`
before grouping rows so producer names, previous schema names, and canonical
types land in the same public ontology.

New projected value-flow facts must emit canonical strings directly. This
registry is a schema-normalization boundary, not permission for new projected
rows to keep using carrier-era serialized names.
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
from d810.recon.facts.value_flow.memory_phi import MEMORY_PHI_FACT_TYPE
from d810.recon.facts.value_flow.memory_use import MEMORY_USE_FACT_TYPE
from d810.recon.facts.value_flow.must_alias import MUST_ALIAS_FACT_TYPE
from d810.recon.facts.value_flow.observable_memory_def import (
    OBSERVABLE_MEMORY_DEF_FACT_TYPE,
)
from d810.recon.facts.value_flow.points_to import POINTS_TO_FACT_TYPE
from d810.recon.facts.value_flow.return_value import RETURN_VALUE_FACT_TYPE
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
    """Canonical mapping for one value-flow fact family.

    The canonical fact type is the public ontology label. The accepted
    aliases tuple lists raw producer names and previous schema names that
    should normalize to the canonical type at diagnostic read time.
    """

    canonical_fact_type: str
    accepted_kind_aliases: tuple[str, ...]
    display_name: str
    industry_term: str
    producer_ontology: str

    @property
    def legacy_kinds(self) -> tuple[str, ...]:
        """Compatibility spelling for callers not yet renamed."""

        return self.accepted_kind_aliases


FACT_TYPE_ALIAS_REGISTRY: tuple[FactTypeAlias, ...] = (
    FactTypeAlias(
        canonical_fact_type=OBSERVABLE_MEMORY_DEF_FACT_TYPE,
        accepted_kind_aliases=("ObservableStoreFact", "TerminalByteEmitterFact"),
        display_name="Observable memory def",
        industry_term="LLVM MemorySSA MemoryDef (externally visible) / angr store action",
        producer_ontology="Hodur TerminalByteEmitter and OLLVM oracle output-store candidates.",
    ),
    FactTypeAlias(
        canonical_fact_type=SCALAR_PROMOTION_FACT_TYPE,
        accepted_kind_aliases=("CarrierStorePromotionFact",),
        display_name="Scalar promotion",
        industry_term="LLVM mem2reg / scalar-promotion",
        producer_ontology="OLLVM accumulator and output-store carrier facts.",
    ),
    FactTypeAlias(
        canonical_fact_type=MUST_ALIAS_FACT_TYPE,
        accepted_kind_aliases=("SameCarrierAliasFact",),
        display_name="Must-alias",
        industry_term="Alias-analysis MustAlias",
        producer_ontology="OLLVM accumulator same-carrier alias proofs.",
    ),
    FactTypeAlias(
        canonical_fact_type=SCALAR_REPLACEMENT_FACT_TYPE,
        accepted_kind_aliases=("LocalStorageScalarizationFact",),
        display_name="Scalar replacement",
        industry_term="LLVM SROA / scalar replacement",
        producer_ontology="OLLVM local-pointer / accumulator carriers with proven local base.",
    ),
    FactTypeAlias(
        canonical_fact_type=SYMBOLIC_EXPRESSION_FACT_TYPE,
        accepted_kind_aliases=("ExpressionCarrierFact",),
        display_name="Symbolic expression",
        industry_term="angr Claripy AST / LLVM SSA value",
        producer_ontology="OLLVM accumulator carrier semantic expression proofs.",
    ),
    FactTypeAlias(
        canonical_fact_type=LOOP_PREDICATE_VALUE_FACT_TYPE,
        accepted_kind_aliases=("LoopPredicateCarrierFact", "LoopCarrierFact"),
        display_name="Loop-predicate value",
        industry_term="Loop-predicate / loop-bound value",
        producer_ontology="Hodur LoopCarrierFact and OLLVM LOOP_INDEX_CARRIER role.",
    ),
    FactTypeAlias(
        canonical_fact_type=CALL_RETURN_VALUE_FACT_TYPE,
        accepted_kind_aliases=("CallResultCarrierFact",),
        display_name="Call return value",
        industry_term="Call return value (ABI return)",
        producer_ontology="OLLVM PASSWORD_COMPARE_RESULT and similar call-result carriers.",
    ),
    FactTypeAlias(
        canonical_fact_type=INDUCTION_VARIABLE_FACT_TYPE,
        accepted_kind_aliases=("GenericInductionCarrierFact", "InductionCarrierFact"),
        display_name="Induction variable",
        industry_term="Loop induction variable",
        producer_ontology="Hodur InductionCarrierFact (recurrences and direct copies).",
    ),
    FactTypeAlias(
        canonical_fact_type=MATERIALIZATION_POINT_FACT_TYPE,
        accepted_kind_aliases=("TerminalMaterializationFact", "ReturnCarrierFact", "ReturnFrontierFact"),
        display_name="Materialization point",
        industry_term="Materialization point (return value, output exposure)",
        producer_ontology="Hodur ReturnCarrierFact and ReturnFrontierFact terminals.",
    ),
    FactTypeAlias(
        canonical_fact_type=MEMORY_USE_FACT_TYPE,
        accepted_kind_aliases=("ReturnSlotUseFact", "ReturnCarrierFact"),
        display_name="Memory use",
        industry_term="LLVM MemorySSA MemoryUse / angr memory read action",
        producer_ontology="Hodur ReturnCarrierFact return-slot uses.",
    ),
    FactTypeAlias(
        canonical_fact_type=MEMORY_PHI_FACT_TYPE,
        accepted_kind_aliases=("ReturnFrontierMergeFact", "ReturnFrontierFact"),
        display_name="Memory phi",
        industry_term="LLVM MemorySSA MemoryPhi / memory-version merge",
        producer_ontology="Hodur ReturnFrontierFact carrier convergence.",
    ),
    FactTypeAlias(
        canonical_fact_type=POINTS_TO_FACT_TYPE,
        accepted_kind_aliases=("DestinationPointsToFact", "TerminalByteEmitterFact"),
        display_name="Points-to",
        industry_term="Alias-analysis points-to relation / memory location equivalence",
        producer_ontology="Hodur TerminalByteEmitter destination-buffer expressions.",
    ),
    FactTypeAlias(
        canonical_fact_type=RETURN_VALUE_FACT_TYPE,
        accepted_kind_aliases=("ReturnCarrierFact",),
        display_name="Return value",
        industry_term="ABI return value / SSA return value",
        producer_ontology="Hodur ReturnCarrierFact return-slot value evidence.",
    ),
    FactTypeAlias(
        canonical_fact_type=STATE_WRITE_FACT_TYPE,
        accepted_kind_aliases=("StateVariableWriteFact", "StateWriteAnchorFact"),
        display_name="State write",
        industry_term="LLVM MemoryDef / angr store action over FSM state variable",
        producer_ontology="Hodur StateWriteAnchorFact.",
    ),
    FactTypeAlias(
        canonical_fact_type=STATE_TRANSITION_FACT_TYPE,
        accepted_kind_aliases=("StateTransitionCarrierFact", "StateTransitionAnchorFact"),
        display_name="State transition",
        industry_term="FSM transition edge (or LLVM MemoryPhi at joins)",
        producer_ontology="Hodur StateTransitionAnchorFact.",
    ),
    FactTypeAlias(
        canonical_fact_type=EFFECT_PATH_FACT_TYPE,
        accepted_kind_aliases=("SideEffectCorridorFact", "ByteEmitCorridorFact"),
        display_name="Effect path",
        industry_term="Effect system / LLVM ModRef path / angr action sequence",
        producer_ontology="Hodur ByteEmitCorridorFact.",
    ),
    FactTypeAlias(
        canonical_fact_type=CALL_EFFECT_SUMMARY_FACT_TYPE,
        accepted_kind_aliases=("CallSideEffectAnchorFact", "CallAnchorFact"),
        display_name="Call effect summary",
        industry_term="LLVM ModRef call summary",
        producer_ontology="Hodur CallAnchorFact.",
    ),
)


def _build_canonical_lookup() -> Mapping[str, FactTypeAlias]:
    return {
        alias.canonical_fact_type: alias
        for alias in FACT_TYPE_ALIAS_REGISTRY
    }


def _build_observed_lookup() -> Mapping[str, tuple[FactTypeAlias, ...]]:
    lookup: dict[str, list[FactTypeAlias]] = {}
    for alias in FACT_TYPE_ALIAS_REGISTRY:
        lookup.setdefault(alias.canonical_fact_type, []).append(alias)
        for observed_kind in alias.accepted_kind_aliases:
            lookup.setdefault(observed_kind, []).append(alias)
    return {key: tuple(values) for key, values in lookup.items()}


_CANONICAL_LOOKUP: Mapping[str, FactTypeAlias] = _build_canonical_lookup()
_OBSERVED_LOOKUP: Mapping[str, tuple[FactTypeAlias, ...]] = _build_observed_lookup()


def canonical_fact_type(observed_kind: str) -> str | None:
    """Return the unique canonical fact type for *observed_kind*, or ``None``.

    *observed_kind* may be either the canonical type, a raw producer kind, or
    a previous serialized schema name. Unknown kinds return ``None`` so the
    caller can preserve the raw value rather than coerce it into the canonical
    surface. Producer kinds that project into several canonical families also
    return ``None`` here; use :func:`canonical_fact_types` when a caller wants
    the full set.
    """

    aliases = _OBSERVED_LOOKUP.get(observed_kind, ())
    fact_types = tuple(dict.fromkeys(alias.canonical_fact_type for alias in aliases))
    if len(fact_types) != 1:
        return None
    return fact_types[0]


def canonical_fact_types(observed_kind: str) -> tuple[str, ...]:
    """Return every canonical value-flow type for *observed_kind*."""

    aliases = _OBSERVED_LOOKUP.get(observed_kind, ())
    return tuple(dict.fromkeys(alias.canonical_fact_type for alias in aliases))


def accepted_kind_aliases_for(fact_type: str) -> tuple[str, ...]:
    """Return accepted producer/schema aliases for *fact_type*.

    Returns an empty tuple when *fact_type* is unknown.
    """

    alias = _CANONICAL_LOOKUP.get(fact_type)
    return () if alias is None else alias.accepted_kind_aliases


def legacy_kinds_for(fact_type: str) -> tuple[str, ...]:
    """Compatibility spelling for :func:`accepted_kind_aliases_for`."""

    return accepted_kind_aliases_for(fact_type)


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


def all_accepted_kind_aliases() -> frozenset[str]:
    """Return every accepted producer/schema alias known to the registry."""

    return frozenset(
        observed_kind
        for alias in FACT_TYPE_ALIAS_REGISTRY
        for observed_kind in alias.accepted_kind_aliases
    )


def all_legacy_kinds() -> frozenset[str]:
    """Compatibility spelling for :func:`all_accepted_kind_aliases`."""

    return all_accepted_kind_aliases()


__all__ = [
    "FACT_TYPE_ALIAS_REGISTRY",
    "FactTypeAlias",
    "accepted_kind_aliases_for",
    "all_accepted_kind_aliases",
    "all_canonical_fact_types",
    "all_legacy_kinds",
    "canonical_fact_type",
    "canonical_fact_types",
    "display_name_for",
    "industry_term_for",
    "legacy_kinds_for",
    "producer_ontology_for",
]

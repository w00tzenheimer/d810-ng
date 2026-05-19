"""Canonical value-flow fact surface.

This package is the canonical home for D-810's value-flow fact ontology.
Each module exports a single canonical ``*_FACT_TYPE`` constant; the package
aggregates the full set as :data:`VALUE_FLOW_FACT_TYPES`.

The constants are canonical serialized ``FactObservation.kind`` values.
Observed producer/schema names are normalized through the diagnostics alias
registry. New projected value-flow rows emit canonical types directly.

Glossary: ``.tmp/terminology_rename/inventory.md`` (Phase 0 artifact).
Design plan: ``docs/plans/2026-05-18-value-flow-terminology-rename-design.md``.

Public surface:

- canonical fact-type constants, one per family;
- :data:`VALUE_FLOW_FACT_TYPES`, the frozenset of all canonical types;
- :func:`project_value_flow_facts`, canonical alias for the projection;
- :func:`is_value_flow_fact`, canonical alias for the predicate;
- :func:`production_value_flow_fact`, canonical alias for the
  production-proven predicate;
- :func:`exact_source_identity`, already-neutral helper re-exported here.
"""
from __future__ import annotations

from d810.recon.facts.carrier import (
    exact_source_identity,
    is_generic_carrier_fact as is_value_flow_fact,
    production_carrier_fact as production_value_flow_fact,
    project_carrier_fact_families as project_value_flow_facts,
)
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
from d810.recon.facts.value_flow.alias_registry import (
    FACT_TYPE_ALIAS_REGISTRY,
    FactTypeAlias,
    accepted_kind_aliases_for,
    all_accepted_kind_aliases,
    all_canonical_fact_types,
    all_legacy_kinds,
    canonical_fact_type,
    canonical_fact_types,
    display_name_for,
    industry_term_for,
    legacy_kinds_for,
    producer_ontology_for,
)

VALUE_FLOW_FACT_TYPES = frozenset({
    OBSERVABLE_MEMORY_DEF_FACT_TYPE,
    SCALAR_PROMOTION_FACT_TYPE,
    MUST_ALIAS_FACT_TYPE,
    SCALAR_REPLACEMENT_FACT_TYPE,
    SYMBOLIC_EXPRESSION_FACT_TYPE,
    LOOP_PREDICATE_VALUE_FACT_TYPE,
    CALL_RETURN_VALUE_FACT_TYPE,
    INDUCTION_VARIABLE_FACT_TYPE,
    MATERIALIZATION_POINT_FACT_TYPE,
    MEMORY_PHI_FACT_TYPE,
    MEMORY_USE_FACT_TYPE,
    STATE_WRITE_FACT_TYPE,
    STATE_TRANSITION_FACT_TYPE,
    EFFECT_PATH_FACT_TYPE,
    CALL_EFFECT_SUMMARY_FACT_TYPE,
    POINTS_TO_FACT_TYPE,
    RETURN_VALUE_FACT_TYPE,
})

__all__ = [
    "CALL_EFFECT_SUMMARY_FACT_TYPE",
    "CALL_RETURN_VALUE_FACT_TYPE",
    "EFFECT_PATH_FACT_TYPE",
    "FACT_TYPE_ALIAS_REGISTRY",
    "FactTypeAlias",
    "INDUCTION_VARIABLE_FACT_TYPE",
    "LOOP_PREDICATE_VALUE_FACT_TYPE",
    "MATERIALIZATION_POINT_FACT_TYPE",
    "MEMORY_PHI_FACT_TYPE",
    "MEMORY_USE_FACT_TYPE",
    "MUST_ALIAS_FACT_TYPE",
    "OBSERVABLE_MEMORY_DEF_FACT_TYPE",
    "POINTS_TO_FACT_TYPE",
    "RETURN_VALUE_FACT_TYPE",
    "SCALAR_PROMOTION_FACT_TYPE",
    "SCALAR_REPLACEMENT_FACT_TYPE",
    "STATE_TRANSITION_FACT_TYPE",
    "STATE_WRITE_FACT_TYPE",
    "SYMBOLIC_EXPRESSION_FACT_TYPE",
    "VALUE_FLOW_FACT_TYPES",
    "accepted_kind_aliases_for",
    "all_accepted_kind_aliases",
    "all_canonical_fact_types",
    "all_legacy_kinds",
    "canonical_fact_type",
    "canonical_fact_types",
    "display_name_for",
    "exact_source_identity",
    "industry_term_for",
    "is_value_flow_fact",
    "legacy_kinds_for",
    "producer_ontology_for",
    "production_value_flow_fact",
    "project_value_flow_facts",
]

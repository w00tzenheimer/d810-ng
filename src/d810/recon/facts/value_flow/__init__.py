"""Canonical value-flow fact surface.

This package is the canonical home for D-810's value-flow fact ontology.
Each module exports a single canonical ``*_FACT_TYPE`` constant; the package
aggregates the full set as :data:`VALUE_FLOW_FACT_TYPES`.

During Phase 1 of the value-flow terminology rename, the canonical
constants are aliases for the legacy ``*_FACT_KIND`` constants in
:mod:`d810.recon.facts.carrier`. Phase 4 may introduce new canonical
serialized values backed by a diagnostic alias registry.

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
    STATE_WRITE_FACT_TYPE,
    STATE_TRANSITION_FACT_TYPE,
    EFFECT_PATH_FACT_TYPE,
    CALL_EFFECT_SUMMARY_FACT_TYPE,
})

__all__ = [
    "CALL_EFFECT_SUMMARY_FACT_TYPE",
    "CALL_RETURN_VALUE_FACT_TYPE",
    "EFFECT_PATH_FACT_TYPE",
    "INDUCTION_VARIABLE_FACT_TYPE",
    "LOOP_PREDICATE_VALUE_FACT_TYPE",
    "MATERIALIZATION_POINT_FACT_TYPE",
    "MUST_ALIAS_FACT_TYPE",
    "OBSERVABLE_MEMORY_DEF_FACT_TYPE",
    "SCALAR_PROMOTION_FACT_TYPE",
    "SCALAR_REPLACEMENT_FACT_TYPE",
    "STATE_TRANSITION_FACT_TYPE",
    "STATE_WRITE_FACT_TYPE",
    "SYMBOLIC_EXPRESSION_FACT_TYPE",
    "VALUE_FLOW_FACT_TYPES",
    "exact_source_identity",
    "is_value_flow_fact",
    "production_value_flow_fact",
    "project_value_flow_facts",
]

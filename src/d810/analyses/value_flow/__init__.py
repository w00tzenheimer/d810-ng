"""Portable value-flow facts and analyses (LLVM / LiSA-style).

``d810.analyses.value_flow`` hosts backend-neutral value-flow analyses:
def-use, value ranges, aliasing, recurrence/induction facts, and the
constant-folding / state-write evaluation core relocated out of
``d810.recon.flow``.

Portable-core layer: no live IDA / Hex-Rays imports, no vendor mutation
surfaces.  Live-mba accessors are injected by the Hex-Rays evidence adapter
(``d810.backends.hexrays.evidence``) rather than imported here.

See ``docs/plans/recon-and-cfg-restructuring.md`` (Suggested Landing
Sequence, steps 6-8) and the migration playbook for the relocation slices.
"""

from __future__ import annotations

from d810.analyses.value_flow.observation import FactObservation
from d810.analyses.value_flow.contract_evidence import (
    CONTRACT_EVIDENCE_KEY,
    CONTRACT_EVIDENCE_TOKENS,
    CONTRACT_EVIDENCE_TOKENS_KEY,
    ContractEvidenceToken,
    contract_evidence_payload,
    contract_evidence_tokens,
)
from d810.analyses.value_flow.projection import (
    LIFECYCLE_PRODUCTION_PROVEN,
    exact_source_identity,
    is_value_flow_fact,
    production_value_flow_fact,
    project_value_flow_facts,
)
from d810.analyses.value_flow.call_effect_summary import (
    CALL_EFFECT_SUMMARY_FACT_TYPE,
)
from d810.analyses.value_flow.call_return_value import (
    CALL_RETURN_VALUE_FACT_TYPE,
)
from d810.analyses.value_flow.effect_path import EFFECT_PATH_FACT_TYPE
from d810.analyses.value_flow.induction_variable import (
    INDUCTION_VARIABLE_FACT_TYPE,
)
from d810.analyses.value_flow.loop_predicate_value import (
    LOOP_PREDICATE_VALUE_FACT_TYPE,
)
from d810.analyses.value_flow.materialization_point import (
    MATERIALIZATION_POINT_FACT_TYPE,
)
from d810.analyses.value_flow.may_alias import MAY_ALIAS_FACT_TYPE
from d810.analyses.value_flow.memory_phi import MEMORY_PHI_FACT_TYPE
from d810.analyses.value_flow.memory_use import MEMORY_USE_FACT_TYPE
from d810.analyses.value_flow.must_alias import MUST_ALIAS_FACT_TYPE
from d810.analyses.value_flow.observable_memory_def import (
    OBSERVABLE_MEMORY_DEF_FACT_TYPE,
)
from d810.analyses.value_flow.observable_output import (
    OBSERVABLE_OUTPUT_FACT_TYPE,
)
from d810.analyses.value_flow.points_to import POINTS_TO_FACT_TYPE
from d810.analyses.value_flow.return_value import RETURN_VALUE_FACT_TYPE
from d810.analyses.value_flow.scalar_promotion import (
    SCALAR_PROMOTION_FACT_TYPE,
)
from d810.analyses.value_flow.scalar_replacement import (
    SCALAR_REPLACEMENT_FACT_TYPE,
)
from d810.analyses.value_flow.state_transition import (
    STATE_TRANSITION_FACT_TYPE,
)
from d810.analyses.value_flow.state_write_fact import STATE_WRITE_FACT_TYPE
from d810.analyses.value_flow.symbolic_expression import (
    SYMBOLIC_EXPRESSION_FACT_TYPE,
)
from d810.analyses.value_flow.alias_registry import (
    FACT_TYPE_ALIAS_REGISTRY,
    FactTypeAlias,
    accepted_kind_aliases_for,
    all_accepted_kind_aliases,
    all_canonical_fact_types,
    canonical_fact_type,
    canonical_fact_types,
    display_name_for,
    industry_term_for,
    producer_ontology_for,
)

VALUE_FLOW_FACT_TYPES = frozenset({
    OBSERVABLE_MEMORY_DEF_FACT_TYPE,
    SCALAR_PROMOTION_FACT_TYPE,
    MUST_ALIAS_FACT_TYPE,
    MAY_ALIAS_FACT_TYPE,
    SCALAR_REPLACEMENT_FACT_TYPE,
    SYMBOLIC_EXPRESSION_FACT_TYPE,
    LOOP_PREDICATE_VALUE_FACT_TYPE,
    CALL_RETURN_VALUE_FACT_TYPE,
    INDUCTION_VARIABLE_FACT_TYPE,
    MATERIALIZATION_POINT_FACT_TYPE,
    OBSERVABLE_OUTPUT_FACT_TYPE,
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
    "CONTRACT_EVIDENCE_KEY",
    "CONTRACT_EVIDENCE_TOKENS",
    "CONTRACT_EVIDENCE_TOKENS_KEY",
    "EFFECT_PATH_FACT_TYPE",
    "FACT_TYPE_ALIAS_REGISTRY",
    "FactObservation",
    "FactTypeAlias",
    "ContractEvidenceToken",
    "INDUCTION_VARIABLE_FACT_TYPE",
    "LOOP_PREDICATE_VALUE_FACT_TYPE",
    "LIFECYCLE_PRODUCTION_PROVEN",
    "MATERIALIZATION_POINT_FACT_TYPE",
    "MAY_ALIAS_FACT_TYPE",
    "MEMORY_PHI_FACT_TYPE",
    "MEMORY_USE_FACT_TYPE",
    "MUST_ALIAS_FACT_TYPE",
    "OBSERVABLE_MEMORY_DEF_FACT_TYPE",
    "OBSERVABLE_OUTPUT_FACT_TYPE",
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
    "canonical_fact_type",
    "canonical_fact_types",
    "contract_evidence_payload",
    "contract_evidence_tokens",
    "display_name_for",
    "exact_source_identity",
    "industry_term_for",
    "is_value_flow_fact",
    "producer_ontology_for",
    "production_value_flow_fact",
    "project_value_flow_facts",
]

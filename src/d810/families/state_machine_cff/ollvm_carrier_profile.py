"""Back-compat re-export. Canonical home: d810.backends.hexrays.evidence.ollvm_carrier
(recon fact-collection, not a CFF family). Importing this still triggers the
recon-profile registration handler (it lives in the canonical module), so any
legacy recon_fact_profile_modules entry pointing here keeps working. New code
imports from the canonical path."""
from __future__ import annotations

from d810.backends.hexrays.evidence.ollvm_carrier import (  # noqa: F401
    OLLVM_CARRIER_PROFILE_MODULE,
    OLLVM_CARRIER_PROFILE_NAME,
    OllvmCarrierBranchOwnershipOracle,
    OllvmCarrierProfileFactCollector,
    OllvmCarrierRawEvidenceCollector,
    collect_ollvm_branch_ownership_refiners,
    collect_ollvm_post_execute_carrier_facts,
    collect_ollvm_profile_fact_observations,
    collect_ollvm_raw_semantic_carrier_facts,
    project_ollvm_value_flow_evidence,
)

__all__ = [
    "OLLVM_CARRIER_PROFILE_MODULE",
    "OLLVM_CARRIER_PROFILE_NAME",
    "OllvmCarrierBranchOwnershipOracle",
    "OllvmCarrierProfileFactCollector",
    "OllvmCarrierRawEvidenceCollector",
    "collect_ollvm_branch_ownership_refiners",
    "collect_ollvm_post_execute_carrier_facts",
    "collect_ollvm_profile_fact_observations",
    "collect_ollvm_raw_semantic_carrier_facts",
    "project_ollvm_value_flow_evidence",
]

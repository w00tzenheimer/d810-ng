"""OLLVM carrier fact backend for the shared emulated-dispatcher profile."""
from __future__ import annotations

from d810.analyses.value_flow import project_value_flow_facts


def _collector_target(target: object) -> object | None:
    if target is None:
        return None
    if hasattr(target, "blocks") and not (
        hasattr(target, "qty") and hasattr(target, "get_mblock")
    ):
        return target
    try:
        from d810.hexrays.fact_target import mba_to_fact_target

        return mba_to_fact_target(target)
    except Exception:
        return None


def collect_ollvm_raw_semantic_carrier_facts(mba: object) -> tuple[object, ...]:
    if mba is None:
        return ()
    target = _collector_target(mba)
    if target is None:
        return ()
    try:
        from d810.analyses.value_flow.ollvm_semantic_carrier import OllvmValueFlowEvidenceCollector
    except Exception:
        return ()
    try:
        return tuple(
            OllvmValueFlowEvidenceCollector().collect(
                target,
                func_ea=int(getattr(mba, "entry_ea", 0) or 0),
                maturity=int(getattr(mba, "maturity", 0) or 0),
                phase="pre_d810",
            )
        )
    except Exception:
        return ()


def collect_ollvm_post_execute_carrier_facts(mba: object) -> tuple[object, ...]:
    return project_value_flow_facts(
        collect_ollvm_raw_semantic_carrier_facts(mba)
    )


def collect_ollvm_profile_fact_observations(mba: object) -> tuple[object, ...]:
    raw_facts = collect_ollvm_raw_semantic_carrier_facts(mba)
    if not raw_facts:
        return ()
    projected_facts = project_value_flow_facts(raw_facts)
    return (*raw_facts, *projected_facts)


def _hexrays_opcode_name(insn_or_opcode: object) -> str | None:
    opcode = getattr(insn_or_opcode, "opcode", insn_or_opcode)
    try:
        import ida_hexrays
    except Exception:
        return None
    for name in (
        "m_jz",
        "m_jnz",
        "m_jge",
        "m_jg",
        "m_jle",
        "m_jl",
        "m_jae",
        "m_ja",
        "m_jbe",
        "m_jb",
        "m_jcnd",
        "m_stx",
        "m_call",
        "m_icall",
    ):
        if opcode == getattr(ida_hexrays, name, None):
            return name
    return None


def collect_ollvm_branch_ownership_refiners(
    mba: object,
    logger: object,
) -> tuple[object, ...]:
    try:
        from d810.analyses.control_flow.branch_ownership_oracle import (
            MopTrackerBranchOwnershipOracle,
            OllvmCarrierBranchOwnershipOracle,
            Z3BranchOwnershipOracle,
        )

        return (
            OllvmCarrierBranchOwnershipOracle(
                mba=mba,
                carrier_facts=collect_ollvm_post_execute_carrier_facts(mba),
            ).refine,
            Z3BranchOwnershipOracle(
                mba=mba,
                opcode_name_resolver=_hexrays_opcode_name,
            ).refine,
            MopTrackerBranchOwnershipOracle(
                mba=mba,
                opcode_name_resolver=_hexrays_opcode_name,
            ).refine,
        )
    except Exception:
        log_debug = getattr(logger, "debug", None)
        if callable(log_debug):
            log_debug(
                "Microcode branch ownership oracle unavailable",
                exc_info=True,
            )
        return ()


__all__ = [
    "collect_ollvm_branch_ownership_refiners",
    "collect_ollvm_post_execute_carrier_facts",
    "collect_ollvm_profile_fact_observations",
    "collect_ollvm_raw_semantic_carrier_facts",
]

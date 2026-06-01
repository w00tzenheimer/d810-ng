"""Hodur adapter for generic recon-store artifact helpers."""
from __future__ import annotations

from pathlib import Path

from d810.analyses.control_flow.return_frontier import ReturnSite
from d810.backends.hexrays.evidence.return_sites import (
    HodurReturnSiteProvider,
)
from d810.passes.artifacts import (
    load_return_frontier_audit_from_store,
    load_return_sites_from_store as _load_return_sites_from_store,
    load_terminal_return_audit_from_store,
    load_transition_report_from_store,
    record_return_frontier_stage,
    recon_db_path,
    save_return_frontier_audit_to_store,
    save_terminal_return_audit_to_store,
    save_transition_report_to_store,
    write_return_frontier_artifact_from_store,
)


def load_return_sites_from_store(
    *,
    func_ea: int,
    maturity: int | None,
    log_dir: Path | str | None,
    provider: HodurReturnSiteProvider | None = None,
) -> tuple[ReturnSite, ...]:
    """Load transition-report-derived Hodur return sites from the recon store."""
    site_provider = provider or HodurReturnSiteProvider()
    return _load_return_sites_from_store(
        func_ea=func_ea,
        maturity=maturity,
        log_dir=log_dir,
        provider=site_provider,
    )


__all__ = [
    "recon_db_path",
    "load_transition_report_from_store",
    "save_transition_report_to_store",
    "load_return_sites_from_store",
    "load_return_frontier_audit_from_store",
    "save_return_frontier_audit_to_store",
    "record_return_frontier_stage",
    "write_return_frontier_artifact_from_store",
    "load_terminal_return_audit_from_store",
    "save_terminal_return_audit_to_store",
]

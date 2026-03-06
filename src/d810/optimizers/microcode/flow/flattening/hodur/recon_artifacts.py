"""Helpers for consuming recon-store artifacts in Hodur.

This module keeps store I/O separate from the unflattener orchestration logic.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from types import MappingProxyType
import time

from d810.cfg.flow.return_frontier import (
    ReturnFrontierAudit,
    ReturnSite,
    return_frontier_audit_from_dict,
)
from d810.optimizers.microcode.flow.flattening.hodur.return_sites import (
    HodurReturnSiteProvider,
)
from d810.recon.collectors.handler_transitions import HandlerTransitionsCollector
from d810.recon.collectors.return_frontier import ReturnFrontierCollector
from d810.recon.flow.transition_report import (
    DispatcherTransitionReport,
    transition_report_from_dict,
)
from d810.recon.models import ReconResult
from d810.recon.store import ReconStore

_HANDLER_TRANSITIONS = HandlerTransitionsCollector.name
_RETURN_FRONTIER = ReturnFrontierCollector.name


def recon_db_path(log_dir: Path | str | None) -> Path:
    """Resolve the canonical recon DB path for a worktree session."""
    if log_dir:
        return Path(log_dir) / "d810_recon.db"
    return Path(tempfile.gettempdir()) / "d810_recon.db"


def load_transition_report_from_store(
    *,
    func_ea: int,
    log_dir: Path | str | None,
    maturity: int | None = None,
) -> DispatcherTransitionReport | None:
    """Load the latest stored handler transition report for a function."""
    db_path = recon_db_path(log_dir)
    if not db_path.exists():
        return None

    with ReconStore(db_path) as store:
        result = store.load_latest_recon_result(
            func_ea=func_ea,
            collector_name=_HANDLER_TRANSITIONS,
            maturity=maturity,
        )
        if result is None and maturity is not None:
            result = store.load_latest_recon_result(
                func_ea=func_ea,
                collector_name=_HANDLER_TRANSITIONS,
            )

    if result is None:
        return None
    payload = result.metrics.get("transition_report")
    if not isinstance(payload, dict):
        return None
    return transition_report_from_dict(payload)


def save_transition_report_to_store(
    *,
    func_ea: int,
    maturity: int,
    report: DispatcherTransitionReport,
    log_dir: Path | str | None,
) -> None:
    """Persist a canonical transition report as a recon artifact."""
    db_path = recon_db_path(log_dir)
    result = HandlerTransitionsCollector.build_result_from_report(
        report,
        func_ea=func_ea,
        maturity=maturity,
    )
    with ReconStore(db_path) as store:
        store.save_recon_result(result)


def load_return_sites_from_store(
    *,
    func_ea: int,
    maturity: int | None,
    log_dir: Path | str | None,
    provider: HodurReturnSiteProvider | None = None,
) -> tuple:
    """Load transition-report-derived return sites from the recon store."""
    report = load_transition_report_from_store(
        func_ea=func_ea,
        maturity=maturity,
        log_dir=log_dir,
    )
    if report is None:
        return ()
    site_provider = provider or HodurReturnSiteProvider()
    return site_provider.collect_return_sites(report)


def load_return_frontier_audit_from_store(
    *,
    func_ea: int,
    log_dir: Path | str | None,
    maturity: int | None = None,
) -> ReturnFrontierAudit | None:
    """Load the latest stored return frontier audit for a function."""
    db_path = recon_db_path(log_dir)
    if not db_path.exists():
        return None

    with ReconStore(db_path) as store:
        result = store.load_latest_recon_result(
            func_ea=func_ea,
            collector_name=_RETURN_FRONTIER,
            maturity=maturity,
        )
        if result is None and maturity is not None:
            result = store.load_latest_recon_result(
                func_ea=func_ea,
                collector_name=_RETURN_FRONTIER,
            )

    if result is None:
        return None
    payload = result.metrics.get("audit_report")
    if not isinstance(payload, dict):
        return None
    return return_frontier_audit_from_dict(payload)


def save_return_frontier_audit_to_store(
    *,
    func_ea: int,
    maturity: int,
    audit: ReturnFrontierAudit,
    log_dir: Path | str | None,
) -> ReconResult:
    """Persist the full return frontier audit as a recon artifact."""
    db_path = recon_db_path(log_dir)
    result = ReturnFrontierCollector.build_result_from_audit(
        audit,
        func_ea=func_ea,
        maturity=maturity,
    )
    with ReconStore(db_path) as store:
        store.save_recon_result(result)
    return result


def record_return_frontier_stage(
    *,
    func_ea: int,
    maturity: int,
    log_dir: Path | str | None,
    return_sites: tuple[ReturnSite, ...],
    successors: dict[int, list[int]],
    entry: int,
    exits: frozenset[int],
    stage_name: str,
) -> ReconResult:
    """Load-or-create the audit, record one stage, and persist it."""
    audit = None
    if stage_name != "pre_plan":
        audit = load_return_frontier_audit_from_store(
            func_ea=func_ea,
            maturity=maturity,
            log_dir=log_dir,
        )
    if audit is None:
        if not return_sites:
            return ReconResult(
                collector_name=_RETURN_FRONTIER,
                func_ea=func_ea,
                maturity=maturity,
                timestamp=time.time(),
                metrics=MappingProxyType({}),
                candidates=(),
            )
        audit = ReturnFrontierAudit(return_sites=tuple(return_sites))

    stage_results = tuple(
        audit.record_stage(
            stage_name=stage_name,
            successors=successors,
            entry=entry,
            exits=exits,
        )
    )
    result = ReturnFrontierCollector.build_result_from_audit(
        audit,
        func_ea=func_ea,
        maturity=maturity,
        stage_results=stage_results,
    )
    db_path = recon_db_path(log_dir)
    with ReconStore(db_path) as store:
        store.save_recon_result(result)
    return result


def write_return_frontier_artifact_from_store(
    *,
    func_ea: int,
    maturity: int | None,
    log_dir: Path | str | None,
    artifact_dir: Path | str,
) -> Path | None:
    """Write the latest stored return frontier audit report to disk."""
    audit = load_return_frontier_audit_from_store(
        func_ea=func_ea,
        maturity=maturity,
        log_dir=log_dir,
    )
    if audit is None:
        return None

    artifact_path = Path(artifact_dir)
    artifact_path.mkdir(parents=True, exist_ok=True)
    output = artifact_path / f"{func_ea:#x}_return_frontier_audit.json"
    output.write_text(json.dumps(audit.report(), indent=2))
    return output


__all__ = [
    "recon_db_path",
    "load_transition_report_from_store",
    "save_transition_report_to_store",
    "load_return_sites_from_store",
    "load_return_frontier_audit_from_store",
    "save_return_frontier_audit_to_store",
    "record_return_frontier_stage",
    "write_return_frontier_artifact_from_store",
]

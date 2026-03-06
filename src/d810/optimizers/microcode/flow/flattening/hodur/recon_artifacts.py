"""Helpers for consuming recon-store artifacts in Hodur.

This module keeps store I/O separate from the unflattener orchestration logic.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from d810.optimizers.microcode.flow.flattening.hodur.return_sites import (
    HodurReturnSiteProvider,
)
from d810.recon.collectors.handler_transitions import HandlerTransitionsCollector
from d810.recon.flow.transition_report import (
    DispatcherTransitionReport,
    transition_report_from_dict,
)
from d810.recon.store import ReconStore

_HANDLER_TRANSITIONS = HandlerTransitionsCollector.name


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


__all__ = [
    "recon_db_path",
    "load_transition_report_from_store",
    "save_transition_report_to_store",
    "load_return_sites_from_store",
]

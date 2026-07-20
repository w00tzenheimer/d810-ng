"Helpers for consuming preanalysis-store artifacts.\n\nThis module keeps generic preanalysis-store I/O separate from strategy-family\norchestration. Family adapters remain responsible for naming and selecting\nwhich artifacts to consume.\n"
from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path
from types import MappingProxyType
import time

from d810.core import logging
from d810.core.typing import Protocol

logger = logging.getLogger(__name__)

from d810.analyses.control_flow.return_frontier import (
    ReturnFrontierAudit,
    ReturnSite,
    return_frontier_audit_from_dict,
)
from d810.analyses.control_flow.terminal_return_audit import \
    TerminalReturnSourceKind, TerminalReturnSiteAudit, TerminalReturnAuditReport
from d810.analyses.control_flow.handler_transitions import HandlerTransitionsCollector
from d810.analyses.control_flow.return_frontier_collector import ReturnFrontierCollector
from d810.analyses.control_flow.transition_report import (
    DispatcherTransitionReport,
    transition_report_from_dict,
)
from d810.analyses.control_flow.models import PreanalysisResult
from d810.passes.store import PreanalysisStore, get_preanalysis_writer

_HANDLER_TRANSITIONS = HandlerTransitionsCollector.name
_RETURN_FRONTIER = ReturnFrontierCollector.name
_TERMINAL_RETURN_COLLECTOR = "terminal_return_audit"


def _coerce_provider_level(
    provider_level: int | None,
    legacy_fields: dict[str, object],
) -> int | None:
    legacy_level = legacy_fields.pop("maturity", None)
    if legacy_fields:
        names = ", ".join(sorted(legacy_fields))
        raise TypeError(f"Unexpected preanalysis artifact field(s): {names}")
    if provider_level is None and legacy_level is not None:
        return int(legacy_level)
    if provider_level is None:
        return None
    return int(provider_level)


def _require_provider_level(
    provider_level: int | None,
    legacy_fields: dict[str, object],
) -> int:
    resolved = _coerce_provider_level(provider_level, legacy_fields)
    if resolved is None:
        raise TypeError("provider_level is required")
    return int(resolved)


class ReturnSiteProvider(Protocol):
    """Adapter for deriving return sites from a transition report."""

    def collect_return_sites(
        self,
        report: DispatcherTransitionReport,
    ) -> tuple[ReturnSite, ...]:
        ...


def analysis_db_path(log_dir: Path | str | None) -> Path:
    "Resolve the canonical preanalysis DB path for a worktree session."
    if log_dir:
        return Path(log_dir) / "d810_analysis.db"
    return Path(tempfile.gettempdir()) / "d810_analysis.db"


def _delete_corrupt_db(db_path: Path) -> None:
    """Remove corrupt SQLite DB and its WAL/SHM sidecar files."""
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(db_path) + suffix)
        try:
            p.unlink(missing_ok=True)
        except OSError:
            pass


def load_transition_report_from_store(
    *,
    func_ea: int,
    log_dir: Path | str | None,
    provider_level: int | None = None,
    **legacy_fields: object,
) -> DispatcherTransitionReport | None:
    """Load the latest stored handler transition report for a function."""
    provider_level = _coerce_provider_level(provider_level, legacy_fields)
    db_path = analysis_db_path(log_dir)
    if not db_path.exists():
        return None

    try:
        with PreanalysisStore(db_path) as store:
            result = store.load_latest_preanalysis_result(
                func_ea=func_ea,
                collector_name=_HANDLER_TRANSITIONS,
                provider_level=provider_level,
            )
            if result is None and provider_level is not None:
                result = store.load_latest_preanalysis_result(
                    func_ea=func_ea,
                    collector_name=_HANDLER_TRANSITIONS,
                )
    except sqlite3.DatabaseError as exc:
        logger.warning(
            "preanalysis DB corrupt or unreadable (%s), deleting and returning None: %s",
            db_path, exc,
        )
        _delete_corrupt_db(db_path)
        return None

    if result is None:
        return None
    payload = result.metrics.get("transition_report")
    if not isinstance(payload, dict):
        return None
    return transition_report_from_dict(payload)


def save_transition_report_to_store(
    *,
    func_ea: int,
    report: DispatcherTransitionReport,
    log_dir: Path | str | None,
    provider_level: int | None = None,
    **legacy_fields: object,
) -> None:
    "Persist a canonical transition report as a preanalysis artifact."
    provider_level = _require_provider_level(provider_level, legacy_fields)
    db_path = analysis_db_path(log_dir)
    result = HandlerTransitionsCollector.build_result_from_report(
        report,
        func_ea=func_ea,
        provider_level=provider_level,
    )
    writer = get_preanalysis_writer(db_path)
    writer.submit(lambda store: store.save_preanalysis_result(result))
    writer.flush()


def load_return_sites_from_store(
    *,
    func_ea: int,
    log_dir: Path | str | None,
    provider: ReturnSiteProvider,
    provider_level: int | None = None,
    **legacy_fields: object,
) -> tuple[ReturnSite, ...]:
    """Load transition-report-derived return sites from preanalysis storage."""
    provider_level = _coerce_provider_level(provider_level, legacy_fields)
    report = load_transition_report_from_store(
        func_ea=func_ea,
        provider_level=provider_level,
        log_dir=log_dir,
    )
    if report is None:
        return ()
    return provider.collect_return_sites(report)


def load_return_frontier_audit_from_store(
    *,
    func_ea: int,
    log_dir: Path | str | None,
    provider_level: int | None = None,
    **legacy_fields: object,
) -> ReturnFrontierAudit | None:
    """Load the latest stored return frontier audit for a function."""
    provider_level = _coerce_provider_level(provider_level, legacy_fields)
    db_path = analysis_db_path(log_dir)
    if not db_path.exists():
        return None

    try:
        with PreanalysisStore(db_path) as store:
            result = store.load_latest_preanalysis_result(
                func_ea=func_ea,
                collector_name=_RETURN_FRONTIER,
                provider_level=provider_level,
            )
            if result is None and provider_level is not None:
                result = store.load_latest_preanalysis_result(
                    func_ea=func_ea,
                    collector_name=_RETURN_FRONTIER,
                )
    except sqlite3.DatabaseError as exc:
        logger.warning(
            "preanalysis DB corrupt or unreadable (%s), deleting and returning None: %s",
            db_path, exc,
        )
        _delete_corrupt_db(db_path)
        return None

    if result is None:
        return None
    payload = result.metrics.get("audit_report")
    if not isinstance(payload, dict):
        return None
    return return_frontier_audit_from_dict(payload)


def save_return_frontier_audit_to_store(
    *,
    func_ea: int,
    audit: ReturnFrontierAudit,
    log_dir: Path | str | None,
    provider_level: int | None = None,
    **legacy_fields: object,
) -> PreanalysisResult:
    "Persist the full return frontier audit as a preanalysis artifact."
    provider_level = _require_provider_level(provider_level, legacy_fields)
    db_path = analysis_db_path(log_dir)
    result = ReturnFrontierCollector.build_result_from_audit(
        audit,
        func_ea=func_ea,
        provider_level=provider_level,
    )
    get_preanalysis_writer(db_path).submit(lambda store: store.save_preanalysis_result(result))
    return result


def record_return_frontier_stage(
    *,
    func_ea: int,
    log_dir: Path | str | None,
    return_sites: tuple[ReturnSite, ...],
    successors: dict[int, list[int]],
    entry: int,
    exits: frozenset[int],
    stage_name: str,
    provider_level: int | None = None,
    **legacy_fields: object,
) -> PreanalysisResult:
    """Load-or-create the audit, record one stage, and persist it."""
    provider_level = _require_provider_level(provider_level, legacy_fields)
    db_path = analysis_db_path(log_dir)

    def _do(store: PreanalysisStore) -> PreanalysisResult:
        audit = None
        if stage_name != "pre_plan":
            raw = store.load_latest_preanalysis_result(
                func_ea=func_ea,
                collector_name=_RETURN_FRONTIER,
                provider_level=provider_level,
            )
            if raw is None:
                raw = store.load_latest_preanalysis_result(
                    func_ea=func_ea,
                    collector_name=_RETURN_FRONTIER,
                )
            if raw is not None:
                payload = raw.metrics.get("audit_report")
                if isinstance(payload, dict):
                    audit = return_frontier_audit_from_dict(payload)

        if audit is None:
            if not return_sites:
                return PreanalysisResult(
                    collector_name=_RETURN_FRONTIER,
                    func_ea=func_ea,
                    provider_level=provider_level,
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
            provider_level=provider_level,
            stage_results=stage_results,
        )
        store.save_preanalysis_result(result)
        return result

    return get_preanalysis_writer(db_path).submit_sync(_do)


def write_return_frontier_artifact_from_store(
    *,
    func_ea: int,
    log_dir: Path | str | None,
    artifact_dir: Path | str,
    provider_level: int | None = None,
    **legacy_fields: object,
) -> Path | None:
    """Write the latest stored return frontier audit report to disk."""
    provider_level = _coerce_provider_level(provider_level, legacy_fields)
    audit = load_return_frontier_audit_from_store(
        func_ea=func_ea,
        provider_level=provider_level,
        log_dir=log_dir,
    )
    if audit is None:
        return None

    artifact_path = Path(artifact_dir)
    artifact_path.mkdir(parents=True, exist_ok=True)
    output = artifact_path / f"{func_ea:#x}_return_frontier_audit.json"
    output.write_text(json.dumps(audit.report(), indent=2))
    return output


def _terminal_return_audit_to_dict(audit: TerminalReturnAuditReport) -> dict:
    """Serialize a TerminalReturnAuditReport to a JSON-safe dict."""
    return {
        "function_ea": audit.function_ea,
        "total_handlers": audit.total_handlers,
        "terminal_handlers": audit.terminal_handlers,
        "sites": [
            {
                "handler_serial": s.handler_serial,
                "exit_serial": s.exit_serial,
                "source_kind": s.source_kind.value,
                "return_block_serial": s.return_block_serial,
                "exit_path_length": s.exit_path_length,
                "has_rax_write": s.has_rax_write,
                "notes": s.notes,
            }
            for s in audit.sites
        ],
    }


def _terminal_return_audit_from_dict(d: dict) -> TerminalReturnAuditReport:
    """Deserialize a TerminalReturnAuditReport from a dict."""
    sites = tuple(
        TerminalReturnSiteAudit(
            handler_serial=s["handler_serial"],
            exit_serial=s.get("exit_serial"),
            source_kind=TerminalReturnSourceKind(s["source_kind"]),
            return_block_serial=s.get("return_block_serial"),
            exit_path_length=s.get("exit_path_length", 0),
            has_rax_write=s.get("has_rax_write"),
            notes=s.get("notes", ""),
        )
        for s in d.get("sites", ())
    )
    return TerminalReturnAuditReport(
        function_ea=d["function_ea"],
        total_handlers=d["total_handlers"],
        terminal_handlers=d["terminal_handlers"],
        sites=sites,
    )


def load_terminal_return_audit_from_store(
    *,
    func_ea: int,
    log_dir: Path | str | None,
    provider_level: int | None = None,
    **legacy_fields: object,
) -> TerminalReturnAuditReport | None:
    """Load the latest stored terminal return audit for a function."""
    provider_level = _coerce_provider_level(provider_level, legacy_fields)
    db_path = analysis_db_path(log_dir)
    if not db_path.exists():
        return None

    try:
        with PreanalysisStore(db_path) as store:
            result = store.load_latest_preanalysis_result(
                func_ea=func_ea,
                collector_name=_TERMINAL_RETURN_COLLECTOR,
                provider_level=provider_level,
            )
            if result is None and provider_level is not None:
                result = store.load_latest_preanalysis_result(
                    func_ea=func_ea,
                    collector_name=_TERMINAL_RETURN_COLLECTOR,
                )
    except sqlite3.DatabaseError as exc:
        logger.warning(
            "preanalysis DB corrupt or unreadable (%s), deleting and returning None: %s",
            db_path, exc,
        )
        _delete_corrupt_db(db_path)
        return None

    if result is None:
        return None
    payload = result.metrics.get("audit_report")
    if not isinstance(payload, dict):
        return None
    return _terminal_return_audit_from_dict(payload)


def save_terminal_return_audit_to_store(
    *,
    func_ea: int,
    audit: TerminalReturnAuditReport,
    log_dir: Path | str | None,
    provider_level: int | None = None,
    **legacy_fields: object,
) -> None:
    "Persist a terminal return audit as a preanalysis artifact."
    provider_level = _require_provider_level(provider_level, legacy_fields)
    db_path = analysis_db_path(log_dir)
    report_dict = _terminal_return_audit_to_dict(audit)
    result = PreanalysisResult(
        collector_name=_TERMINAL_RETURN_COLLECTOR,
        func_ea=func_ea,
        provider_level=provider_level,
        timestamp=time.time(),
        metrics=MappingProxyType({
            "terminal_handlers": audit.terminal_handlers,
            "total_handlers": audit.total_handlers,
            "audit_report": report_dict,
        }),
        candidates=(),
    )
    writer = get_preanalysis_writer(db_path)
    writer.submit(lambda store: store.save_preanalysis_result(result))
    writer.flush()


__all__ = [
    "ReturnSiteProvider",
    "analysis_db_path",
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

"""Audit helpers for Hodur-compatible family runtime paths."""
from __future__ import annotations

from pathlib import Path

from d810.analyses.control_flow.return_frontier import ReturnSite
from d810.core.typing import Any
from d810.optimizers.microcode.flow.flattening.engine.snapshot import AnalysisSnapshot
from d810.optimizers.microcode.flow.flattening.engine.strategy import StageResult
from d810.optimizers.microcode.flow.flattening.hodur.recon_artifacts import (
    load_return_frontier_audit_from_store,
    load_transition_report_from_store,
    record_return_frontier_stage as record_return_frontier_stage_artifact,
    save_terminal_return_audit_to_store,
    save_transition_report_to_store,
    write_return_frontier_artifact_from_store,
)


def persist_terminal_return_audit(
    results: list[StageResult],
    *,
    func_ea: int,
    maturity: int,
    log_dir: Path | str | None,
) -> None:
    """Persist the first terminal-return audit emitted by the executor."""
    for result in results:
        audit = result.metadata.get("terminal_return_audit")
        if audit is None:
            continue
        save_terminal_return_audit_to_store(
            func_ea=func_ea,
            maturity=maturity,
            audit=audit,
            log_dir=log_dir,
        )
        return


def prepare_return_frontier_audit(
    snapshot: AnalysisSnapshot,
    *,
    current_return_sites: tuple,
    return_site_provider: object,
    func_ea: int,
    maturity: int,
    log_dir: Path | str | None,
    successors: dict[int, list[int]],
    exits: frozenset[int],
    handler_paths: dict[int, list] | None = None,
    state_var_stkoff: int | None = None,
    logger: Any | None = None,
) -> tuple:
    """Build return-frontier sites if needed and record the pre-plan stage."""
    return_sites = tuple(current_return_sites)
    if not return_sites:
        from d810.analyses.control_flow.transition_report import (
            build_dispatcher_transition_report,
        )

        report = load_transition_report_from_store(
            func_ea=func_ea,
            maturity=maturity,
            log_dir=log_dir,
        )
        used_report = False
        if report is not None and report.rows:
            return_sites = return_site_provider.collect_return_sites(report)
            used_report = True
            if logger is not None:
                logger.info(
                    "RETURN_FRONTIER_AUDIT: using recon-store transition report "
                    "(%d rows -> %d sites)",
                    len(report.rows),
                    len(return_sites),
                )
        elif snapshot.bst_dispatcher_serial >= 0:
            try:
                report = build_dispatcher_transition_report(
                    snapshot.mba,
                    snapshot.bst_dispatcher_serial,
                    state_var_stkoff=state_var_stkoff,
                )
                save_transition_report_to_store(
                    func_ea=func_ea,
                    maturity=maturity,
                    report=report,
                    log_dir=log_dir,
                )
            except Exception as exc:
                report = None
                if logger is not None:
                    logger.info(
                        "RETURN_FRONTIER_AUDIT: transition report failed "
                        "(diagnostic only): %s",
                        exc,
                    )

        if report is not None and report.rows and not used_report:
            return_sites = return_site_provider.collect_return_sites(report)
            if logger is not None:
                logger.info(
                    "RETURN_FRONTIER_AUDIT: using transition report "
                    "(%d rows -> %d sites)",
                    len(report.rows),
                    len(return_sites),
                )
        if not return_sites and handler_paths:
            return_sites = return_site_provider.collect_return_sites_legacy(
                snapshot, handler_paths
            )
            if logger is not None:
                logger.info(
                    "RETURN_FRONTIER_AUDIT: fallback to handler_paths "
                    "(%d handlers -> %d sites)",
                    len(handler_paths),
                    len(return_sites),
                )
        if not return_sites:
            sites: list[ReturnSite] = []
            for blk_serial in sorted(exits):
                sites.append(
                    ReturnSite(
                        site_id=f"hodur_exit_{blk_serial}",
                        origin_block=blk_serial,
                        guard_hash=f"{blk_serial:016x}",
                        expected_terminal_kind="return",
                        provenance="pre_plan_exit_block_scan",
                    )
                )
            return_sites = tuple(sites)
            if logger is not None:
                logger.info(
                    "RETURN_FRONTIER_AUDIT: fallback to exit block scan (%d sites)",
                    len(return_sites),
                )

    record_return_frontier_stage(
        return_sites,
        "pre_plan",
        func_ea=func_ea,
        maturity=maturity,
        log_dir=log_dir,
        successors=successors,
        exits=exits,
        logger=logger,
    )
    return return_sites


def record_return_frontier_stage(
    return_sites: tuple,
    stage_name: str,
    *,
    func_ea: int,
    maturity: int,
    log_dir: Path | str | None,
    successors: dict[int, list[int]],
    exits: frozenset[int],
    logger: Any | None = None,
) -> None:
    """Record one return-frontier audit stage."""
    result = record_return_frontier_stage_artifact(
        func_ea=func_ea,
        maturity=maturity,
        log_dir=log_dir,
        return_sites=return_sites,
        successors=successors,
        entry=0,
        exits=exits,
        stage_name=stage_name,
    )
    if logger is not None:
        logger.info(
            "RETURN_FRONTIER_AUDIT[%s]: sites=%d broken=%d "
            "(diagnostic only, not gated)",
            stage_name,
            result.metrics.get("total_sites", 0),
            result.metrics.get("broken_count", 0),
        )


def finalize_return_frontier_audit(
    return_sites: tuple,
    *,
    func_ea: int,
    maturity: int,
    log_dir: Path | str | None,
    artifact_dir: Path,
    successors: dict[int, list[int]],
    exits: frozenset[int],
    logger: Any | None = None,
) -> None:
    """Record the final audit stage and write the persisted artifact."""
    record_return_frontier_stage(
        return_sites,
        "post_pipeline",
        func_ea=func_ea,
        maturity=maturity,
        log_dir=log_dir,
        successors=successors,
        exits=exits,
        logger=logger,
    )
    write_return_frontier_artifact_from_store(
        func_ea=func_ea,
        maturity=maturity,
        log_dir=log_dir,
        artifact_dir=artifact_dir,
    )
    audit = load_return_frontier_audit_from_store(
        func_ea=func_ea,
        maturity=maturity,
        log_dir=log_dir,
    )
    if audit is not None:
        audit.summary_log()

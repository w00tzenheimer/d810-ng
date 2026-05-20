"""DAG-authoritative fragment arbitration helpers."""
from __future__ import annotations

from dataclasses import replace

from d810.core.logging import getLogger
from d810.optimizers.microcode.flow.flattening.engine.planner_context import (
    CumulativePlannerView,
)
from d810.optimizers.microcode.flow.flattening.engine.provenance import (
    DagDisagreementRecord,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import PlanFragment

__all__ = [
    "DAG_AUDIT_METADATA_KEY",
    "apply_dag_conformance_gate",
    "filter_dag_disagreements",
    "parse_dag_target_from_reason",
    "redirect_source",
    "redirect_target",
]

logger = getLogger(__name__)


DAG_AUDIT_METADATA_KEY: str = "dag_audit"


def redirect_source(mod: object) -> int | None:
    """Return the source-block serial of a redirect-shaped mod, else None.

    Uses hot-reload-safe class-name dispatch rather than concrete isinstance
    checks because this runs in the shared engine hot path.
    """
    kind = type(mod).__name__
    if kind == "RedirectGoto":
        return int(getattr(mod, "from_serial", -1))
    if kind == "ConvertToGoto":
        return int(getattr(mod, "block_serial", -1))
    return None


def redirect_target(mod: object) -> int | None:
    """Return the new-target serial of a redirect-shaped mod, else None."""
    kind = type(mod).__name__
    if kind == "RedirectGoto":
        return int(getattr(mod, "new_target", -1))
    if kind == "ConvertToGoto":
        return int(getattr(mod, "goto_target", -1))
    return None


def parse_dag_target_from_reason(reason: str) -> int | None:
    """Extract the DAG canonical target from a DAG_DISAGREEMENT reason."""
    marker = "dag="
    idx = reason.find(marker)
    if idx == -1:
        return None
    tail = reason[idx + len(marker):]
    end = 0
    for ch in tail:
        if ch in "0123456789abcdefABCDEFxX":
            end += 1
        else:
            break
    raw = tail[:end]
    if not raw:
        return None
    try:
        return int(raw, 0)
    except ValueError:
        return None


def filter_dag_disagreements(
    modifications: list,
    cumulative_planner_view: CumulativePlannerView | None,
    *,
    strategy_name: str,
    phase: str,
    log_prefix: str = "RECON DAG_ARBITER",
) -> tuple[list, tuple[DagDisagreementRecord, ...]]:
    """Drop redirect mods refused by the DAG authority.

    ``ALLOW`` and ``DAG_GAP`` decisions are kept; non-gap refusals are dropped
    and returned as :class:`DagDisagreementRecord` rows. This is the shared
    DAG-authoritative arbitration primitive used both by Hodur's fragment
    finalizer and by the engine-level post-plan gate.
    """
    if cumulative_planner_view is None:
        return modifications, ()
    authority = cumulative_planner_view.dag_authority
    if authority is None:
        return modifications, ()

    kept: list = []
    dropped: list[tuple[str, int, str]] = []
    records: list[DagDisagreementRecord] = []
    gaps = 0
    for mod in modifications:
        src = redirect_source(mod)
        if src is None:
            kept.append(mod)
            continue
        decision = authority.permits(mod)
        if decision.allowed:
            kept.append(mod)
            continue
        if decision.is_gap:
            kept.append(mod)
            gaps += 1
            continue

        planner_tgt = redirect_target(mod)
        dag_tgt = (
            parse_dag_target_from_reason(decision.reason)
            if decision.is_disagreement
            else None
        )
        records.append(
            DagDisagreementRecord(
                planner_name=strategy_name,
                mod_kind=type(mod).__name__,
                source_block=int(src),
                branch_arm=None,
                planner_target=int(planner_tgt) if planner_tgt is not None else None,
                dag_target=dag_tgt,
                phase=phase,
                decision_reason=decision.reason,
            )
        )
        dropped.append((type(mod).__name__, int(src), decision.reason))

    if dropped:
        logger.warning(
            "%s: dropped %d mod(s) from strategy %r as DAG-disagreement "
            "(planner target != DAG canonical target): %s",
            log_prefix,
            len(dropped),
            strategy_name,
            "; ".join(
                f"{mtype}(src={src} reason={reason})"
                for mtype, src, reason in dropped[:10]
            ),
        )
    if gaps:
        logger.debug(
            "%s: %d mod(s) from strategy %r in DAG_GAP regions; deferring "
            "to legacy fallback filters",
            log_prefix,
            gaps,
            strategy_name,
        )
    return kept, tuple(records)


def apply_dag_conformance_gate(
    fragment: PlanFragment,
    cumulative_view: CumulativePlannerView | None,
) -> PlanFragment:
    """Apply the shared DAG-conformance gate to one plan fragment."""
    if cumulative_view is None or cumulative_view.dag_authority is None:
        return fragment
    if fragment.metadata.get(DAG_AUDIT_METADATA_KEY) is not None:
        return fragment

    kept, records = filter_dag_disagreements(
        list(fragment.modifications),
        cumulative_view,
        strategy_name=fragment.strategy_name,
        phase="engine_post_plan_gate",
        log_prefix="ENGINE DAG_GATE",
    )
    if not records:
        return fragment

    new_metadata = dict(fragment.metadata)
    new_metadata[DAG_AUDIT_METADATA_KEY] = records

    contribution = new_metadata.get("planner_ctx")
    if contribution is not None and hasattr(contribution, "linearizations"):
        dropped_sources = {int(r.source_block) for r in records}
        retained_linearizations = tuple(
            d for d in contribution.linearizations
            if int(getattr(d, "src", -1)) not in dropped_sources
        )
        if len(retained_linearizations) != len(contribution.linearizations):
            new_metadata["planner_ctx"] = replace(
                contribution,
                linearizations=retained_linearizations,
            )

    return replace(fragment, modifications=kept, metadata=new_metadata)

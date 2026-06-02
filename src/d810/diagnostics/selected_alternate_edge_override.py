"""SQLite-backed selected-alternate-edge override diagnostics."""
from __future__ import annotations

from d810.core import getLogger
from d810.core.settings import get_settings
from d810.analyses.control_flow.selected_alternate_edge_override import (
    apply_selected_alternate_edge_overrides,
)

logger = getLogger(__name__)


def _fact_lifecycle_enabled() -> bool:
    return get_settings().fact_lifecycle


def _run_cascade(diag_db, snap_id: int) -> None:
    """Run classify -> correlate -> select against ``snap_id``."""
    from d810.diagnostics.alternate_correlation import (
        correlate_collapsed_edges,
        persist_alternate_correlations,
    )
    from d810.diagnostics.alternate_selection import (
        persist_alternate_selections,
        select_alternate_edges,
    )
    from d810.diagnostics.edge_diagnostics import (
        classify_dag_edges,
        persist_edge_diagnostics,
    )

    try:
        diags = classify_dag_edges(diag_db, snap_id)
        persist_edge_diagnostics(diag_db, diags)
    except Exception:
        logger.warning(
            "RECON_DAG_OVERRIDE_CASCADE_FAILED phase=classify snap_id=%d",
            int(snap_id),
            exc_info=True,
        )
        return

    try:
        corrs = correlate_collapsed_edges(diag_db, snap_id)
        persist_alternate_correlations(diag_db, corrs)
    except Exception:
        logger.warning(
            "RECON_DAG_OVERRIDE_CASCADE_FAILED phase=correlate snap_id=%d",
            int(snap_id),
            exc_info=True,
        )
        return

    try:
        sels = select_alternate_edges(diag_db, snap_id)
        persist_alternate_selections(diag_db, sels)
    except Exception:
        logger.warning(
            "RECON_DAG_OVERRIDE_CASCADE_FAILED phase=select snap_id=%d",
            int(snap_id),
            exc_info=True,
        )


def _gated_overrides(
    diag_db,
    snap_id: int,
) -> dict[tuple[str, str, int | None], tuple[str, int | None]]:
    """Return selected terminal-tail alternate targets keyed by edge value."""
    rows = diag_db.execute(
        """
        SELECT
            d.edge_id,
            d.source_state_hex,
            d.target_state_hex,
            d.classification,
            e.source_block,
            (
                SELECT COUNT(*) FROM state_cfg_edge_alternate_selections s2
                 WHERE s2.snapshot_id = d.snapshot_id
                   AND s2.collapsed_edge_id = d.edge_id
                   AND s2.selected = 1
            ) AS sel_count,
            (
                SELECT s3.reached_state_hex FROM state_cfg_edge_alternate_selections s3
                 WHERE s3.snapshot_id = d.snapshot_id
                   AND s3.collapsed_edge_id = d.edge_id
                   AND s3.selected = 1
                 LIMIT 1
            ) AS reached_state_hex,
            (
                SELECT s4.reached_byte_index
                  FROM state_cfg_edge_alternate_selections s4
                 WHERE s4.snapshot_id = d.snapshot_id
                   AND s4.collapsed_edge_id = d.edge_id
                   AND s4.selected = 1
                 LIMIT 1
            ) AS reached_byte_index,
            (
                SELECT s5.source_byte_index
                  FROM state_cfg_edge_alternate_selections s5
                 WHERE s5.snapshot_id = d.snapshot_id
                   AND s5.collapsed_edge_id = d.edge_id
                   AND s5.selected = 1
                 LIMIT 1
            ) AS source_byte_index
        FROM state_cfg_edge_diagnostics d
        JOIN state_cfg_edges e
          ON e.snapshot_id = d.snapshot_id
         AND e.edge_id     = d.edge_id
        WHERE d.snapshot_id = ?
          AND d.classification = 'COLLAPSED_TO_REWRITTEN_TARGET'
        """,
        (int(snap_id),),
    ).fetchall()

    out: dict[
        tuple[str, str, int | None],
        tuple[str, int | None],
    ] = {}
    for (
        _edge_id,
        src,
        tgt,
        _cls,
        src_block,
        sel_count,
        reached_state,
        reached_bi,
        source_bi,
    ) in rows:
        if int(sel_count) != 1:
            continue
        if reached_state is None:
            continue
        if src is None or tgt is None:
            continue
        if source_bi is None or reached_bi is None:
            continue
        try:
            if int(reached_bi) <= int(source_bi):
                continue
        except (TypeError, ValueError):
            continue
        try:
            src_block_int: int | None = (
                int(src_block) if src_block is not None else None
            )
        except (TypeError, ValueError):
            src_block_int = None
        out[(str(src).lower(), str(tgt).lower(), src_block_int)] = (
            str(reached_state).lower(),
            int(reached_bi),
        )
    return out


def apply_selected_alternate_edge_overrides_from_diag(
    dag,
    snap_ref,
):
    """Apply selected alternate-edge overrides from the active diag DB."""
    if not _fact_lifecycle_enabled():
        return dag
    if snap_ref is None:
        return dag

    from d810.core.observability import (
        get_active_diag_conn,
        resolve_snapshot_id_for,
    )

    diag_db = get_active_diag_conn(int(snap_ref.func_ea))
    snap_id = resolve_snapshot_id_for(snap_ref)
    if diag_db is None or snap_id is None:
        return dag

    try:
        _run_cascade(diag_db, int(snap_id))
        gated = _gated_overrides(diag_db, int(snap_id))
    except Exception:
        logger.warning(
            "RECON_DAG_OVERRIDE_GATING_FAILED snap_id=%d",
            int(snap_id),
            exc_info=True,
        )
        return dag

    if not gated:
        return dag

    return apply_selected_alternate_edge_overrides(
        dag,
        None,
        override_map=gated,
    )


__all__ = ["apply_selected_alternate_edge_overrides_from_diag"]

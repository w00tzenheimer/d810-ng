"""Thin command adapter for manager-owned diagnostic explorer operations."""

from __future__ import annotations

from collections.abc import Callable, Sequence

from d810.diagnostics.workbench_models import DiagnosticRecord, DiagnosticViewKind


_VIEW_KINDS = {item.value: item for item in DiagnosticViewKind}


class WorkbenchDiagnosticsAdapter:
    """Delegate allowlisted reads, plans, and cleanup to the current state."""

    def __init__(
        self,
        state: object,
        *,
        navigate: Callable[[int], object] | None = None,
    ) -> None:
        self._state = state
        self._navigate = navigate

    def databases(self) -> tuple[object, ...]:
        return tuple(self._state.get_diagnostic_databases())

    def snapshots(self, path: str) -> tuple[object, ...]:
        return tuple(self._state.get_diagnostic_snapshots(path))

    def records(
        self,
        path: str,
        snapshot_id: int,
        kind: str,
    ) -> tuple[DiagnosticRecord, ...]:
        try:
            view_kind = _VIEW_KINDS[str(kind)]
        except KeyError as error:
            raise ValueError(f"Unsupported diagnostic view: {kind}") from error
        return tuple(
            self._state.get_diagnostic_records(path, int(snapshot_id), view_kind)
        )

    def plan(
        self,
        action_id: str,
        *,
        path: str | None = None,
        paths: Sequence[str] = (),
        snapshot_ids: Sequence[int] = (),
        keep: int = 0,
        recorded_before: float = 0.0,
    ) -> object:
        if action_id == "delete_selected_snapshots" and path is not None:
            return self._state.plan_diagnostic_selected_snapshots(
                path, tuple(int(value) for value in snapshot_ids)
            )
        if action_id == "delete_all_snapshots" and path is not None:
            return self._state.plan_diagnostic_all_snapshots(path)
        if action_id == "keep_latest" and path is not None:
            return self._state.plan_diagnostic_keep_latest(path, int(keep))
        if action_id == "older_than" and path is not None:
            return self._state.plan_diagnostic_older_than(path, float(recorded_before))
        if action_id == "delete_selected_databases":
            return self._state.plan_diagnostic_selected_databases(tuple(paths))
        if action_id == "delete_all_closed_databases":
            return self._state.plan_diagnostic_all_closed_databases(tuple(paths))
        if action_id == "vacuum_selected_databases":
            return self._state.plan_diagnostic_vacuum(tuple(paths))
        raise ValueError(f"Unsupported or incomplete diagnostic action: {action_id}")

    def execute(
        self,
        plan: object,
        *,
        checkpoint_wal: bool,
        vacuum_after: bool,
    ) -> object:
        return self._state.execute_diagnostic_cleanup(
            plan,
            checkpoint_wal=bool(checkpoint_wal),
            vacuum_after=bool(vacuum_after),
        )

    def navigate(self, ea: int) -> None:
        if self._navigate is None:
            raise RuntimeError("IDA navigation is unavailable")
        self._navigate(int(ea))


__all__ = ["WorkbenchDiagnosticsAdapter"]

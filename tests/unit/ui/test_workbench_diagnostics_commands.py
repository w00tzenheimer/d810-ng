from __future__ import annotations

from types import SimpleNamespace

from d810.diagnostics.workbench_models import DiagnosticViewKind
from d810.ui.workbench_diagnostics_commands import WorkbenchDiagnosticsAdapter


def test_adapter_delegates_inventory_views_plans_execution_and_navigation() -> None:
    events: list[object] = []
    plan = object()
    result = object()
    state = SimpleNamespace(
        get_diagnostic_databases=lambda: events.append("databases") or ("db",),
        get_diagnostic_snapshots=lambda path: events.append(("snapshots", path))
        or ("snapshot",),
        get_diagnostic_records=lambda path, snapshot_id, kind: events.append(
            ("records", path, snapshot_id, kind)
        )
        or ("record",),
        plan_diagnostic_selected_snapshots=lambda path, ids: events.append(
            ("selected_snapshots", path, ids)
        )
        or plan,
        plan_diagnostic_all_snapshots=lambda path: events.append(
            ("all_snapshots", path)
        )
        or plan,
        plan_diagnostic_keep_latest=lambda path, keep: events.append(
            ("keep_latest", path, keep)
        )
        or plan,
        plan_diagnostic_older_than=lambda path, timestamp: events.append(
            ("older_than", path, timestamp)
        )
        or plan,
        plan_diagnostic_selected_databases=lambda paths: events.append(
            ("selected_databases", tuple(paths))
        )
        or plan,
        plan_diagnostic_all_closed_databases=lambda paths: events.append(
            ("all_closed_databases", tuple(paths))
        )
        or plan,
        plan_diagnostic_vacuum=lambda paths: events.append(("vacuum", tuple(paths)))
        or plan,
        execute_diagnostic_cleanup=lambda candidate, **kwargs: events.append(
            ("execute", candidate, kwargs)
        )
        or result,
    )
    jumps: list[int] = []
    adapter = WorkbenchDiagnosticsAdapter(state, navigate=jumps.append)

    assert adapter.databases() == ("db",)
    assert adapter.snapshots("/a") == ("snapshot",)
    assert adapter.records("/a", 7, "blocks") == ("record",)
    assert events[-1][-1] is DiagnosticViewKind.BLOCKS
    assert (
        adapter.plan("delete_selected_snapshots", path="/a", snapshot_ids=(2, 1))
        is plan
    )
    assert adapter.plan("delete_all_snapshots", path="/a") is plan
    assert adapter.plan("keep_latest", path="/a", keep=3) is plan
    assert adapter.plan("older_than", path="/a", recorded_before=4.5) is plan
    assert adapter.plan("delete_selected_databases", paths=("/a", "/b")) is plan
    assert adapter.plan("delete_all_closed_databases", paths=("/a", "/b")) is plan
    assert adapter.plan("vacuum_selected_databases", paths=("/a",)) is plan
    assert adapter.execute(plan, checkpoint_wal=True, vacuum_after=False) is result
    adapter.navigate(0x401000)
    assert jumps == [0x401000]


def test_adapter_rejects_unknown_views_and_actions() -> None:
    adapter = WorkbenchDiagnosticsAdapter(SimpleNamespace())

    for operation in (
        lambda: adapter.records("/a", 1, "arbitrary-sql"),
        lambda: adapter.plan("drop-table", path="/a"),
    ):
        try:
            operation()
        except ValueError:
            pass
        else:
            raise AssertionError("unallowlisted diagnostic operation must fail")

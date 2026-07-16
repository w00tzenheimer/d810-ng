from __future__ import annotations

import ast
import contextlib
import dataclasses
from pathlib import Path
from types import SimpleNamespace

import pytest

from d810.manager.workbench_models import (
    AttackSummary,
    BaselineRef,
    D810OutputRef,
    DeobfuscationWorkbenchSnapshot,
    FunctionRef,
    RuleScopeSummary,
    RuntimeConfigRef,
    SnapshotFreshness,
    StatisticsSummary,
)
from d810.ui.workbench_comparison import (
    WorkbenchComparisonAdapter,
    WorkbenchComparisonCaptureError,
)


def _snapshot() -> DeobfuscationWorkbenchSnapshot:
    return DeobfuscationWorkbenchSnapshot(
        generation=7,
        function=FunctionRef(0x401000, "target", "sha256:abc", 7),
        runtime=RuntimeConfigRef(
            source_name="source.json",
            source_path="/source.json",
            runtime_name="runtime.json",
            runtime_path="/runtime.json",
            mode="config-v2",
            routed=True,
            hook_mode="config-v2",
            pass_ids=("pass.one", "pass.two"),
        ),
        attack=AttackSummary("unknown", "unavailable", None, "none", None, (), (), ()),
        pipeline=(),
        consumers=(),
        rule_scope=RuleScopeSummary((), (), (), (), (), "", None, (), (), False),
        statistics=StatisticsSummary((), (), (), 0, (), 0),
        baseline=BaselineRef(False, None, None, None),
        latest_output=D810OutputRef(False, None, None, None),
        artifacts=(),
        freshness=SnapshotFreshness.CURRENT,
        engine_started=True,
        collection_errors=(),
    )


def test_capture_suppresses_hooks_once_and_decompiles_native_once_inside() -> None:
    events: list[str] = []
    manager = SimpleNamespace(started=True)
    native_cfunc = SimpleNamespace(name="native")
    current_cfunc = SimpleNamespace(name="d810")
    captured: dict[str, object] = {}
    comparison = object()

    @contextlib.contextmanager
    def suppress(candidate: object):
        assert candidate is manager
        events.append("suppress:enter")
        try:
            yield
        finally:
            events.append("suppress:exit")

    def decompile(function_ea: int) -> object:
        events.append(f"decompile:{function_ea:x}")
        assert events[-2:] == ["suppress:enter", "decompile:401000"]
        return native_cfunc

    def render(cfunc: object) -> str:
        events.append(f"render:{cfunc.name}")
        return f"{cfunc.name}();\n"

    state = SimpleNamespace(
        capture_workbench_baseline=lambda identity, text: captured.update(
            baseline_identity=identity,
            baseline_text=text,
        ),
        capture_workbench_d810_output=lambda identity, text: captured.update(
            output_identity=identity,
            output_text=text,
        ),
        get_workbench_comparison=lambda identity: comparison,
    )
    adapter = WorkbenchComparisonAdapter(
        state=state,
        manager=manager,
        hooks_suppressed=suppress,
        decompile=decompile,
        render_pseudocode=render,
        idb_identity=lambda: "idb:sample",
        type_generation=lambda: "types:4",
        hexrays_version=lambda: "9.2",
    )

    result = adapter.capture(_snapshot(), current_cfunc=current_cfunc)

    assert result is comparison
    assert events == [
        "suppress:enter",
        "decompile:401000",
        "suppress:exit",
        "render:native",
        "render:d810",
    ]
    assert manager.started is True
    identity = captured["baseline_identity"]
    assert identity == captured["output_identity"]
    assert identity.function_ea == 0x401000
    assert identity.function_fingerprint == "sha256:abc"
    assert identity.decompilation_generation == 7
    assert identity.idb_identity == "idb:sample"
    assert identity.type_generation == "types:4"
    assert identity.hexrays_version == "9.2"
    assert identity.runtime_path == "/runtime.json"
    assert identity.runtime_pass_ids == ("pass.one", "pass.two")
    assert identity.runtime_generation == 7
    assert captured["baseline_text"] == "native();\n"
    assert captured["output_text"] == "d810();\n"


def test_capture_rejects_missing_native_result_without_persisting() -> None:
    captures: list[object] = []
    state = SimpleNamespace(
        capture_workbench_baseline=lambda *args: captures.append(args),
        capture_workbench_d810_output=lambda *args: captures.append(args),
    )
    adapter = WorkbenchComparisonAdapter(
        state=state,
        manager=SimpleNamespace(started=True),
        hooks_suppressed=lambda manager: contextlib.nullcontext(),
        decompile=lambda function_ea: None,
        render_pseudocode=lambda cfunc: "unused",
        idb_identity=lambda: "idb",
        type_generation=lambda: "types",
        hexrays_version=lambda: "9.2",
    )

    with pytest.raises(WorkbenchComparisonCaptureError, match="Native decompilation"):
        adapter.capture(_snapshot(), current_cfunc=object())

    assert captures == []


def test_capture_rejects_missing_current_d810_cfunc_before_decompile() -> None:
    calls: list[int] = []
    adapter = WorkbenchComparisonAdapter(
        state=object(),
        manager=SimpleNamespace(started=True),
        hooks_suppressed=lambda manager: contextlib.nullcontext(),
        decompile=lambda function_ea: calls.append(function_ea),
        render_pseudocode=lambda cfunc: "unused",
        idb_identity=lambda: "idb",
        type_generation=lambda: "types",
        hexrays_version=lambda: "9.2",
    )

    with pytest.raises(WorkbenchComparisonCaptureError, match="current D810"):
        adapter.capture(_snapshot(), current_cfunc=None)

    assert calls == []


@pytest.mark.parametrize(
    ("snapshot", "message"),
    (
        (
            lambda: dataclasses.replace(_snapshot(), freshness=SnapshotFreshness.STALE),
            "current workbench snapshot",
        ),
        (
            lambda: dataclasses.replace(_snapshot(), engine_started=False),
            "started D810 runtime",
        ),
    ),
)
def test_capture_rechecks_action_preconditions_before_decompile(
    snapshot: object,
    message: str,
) -> None:
    calls: list[int] = []
    adapter = WorkbenchComparisonAdapter(
        state=object(),
        manager=SimpleNamespace(started=True),
        hooks_suppressed=lambda manager: contextlib.nullcontext(),
        decompile=lambda function_ea: calls.append(function_ea),
        render_pseudocode=lambda cfunc: "unused",
        idb_identity=lambda: "idb",
        type_generation=lambda: "types",
        hexrays_version=lambda: "9.2",
    )

    with pytest.raises(WorkbenchComparisonCaptureError, match=message):
        adapter.capture(snapshot(), current_cfunc=object())

    assert calls == []


def test_adapter_never_assigns_persistent_started_state() -> None:
    path = Path(WorkbenchComparisonAdapter.__module__.replace(".", "/") + ".py")
    source_path = Path(__file__).parents[3] / "src" / path
    tree = ast.parse(source_path.read_text(encoding="utf-8"))

    assignments = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign))
    ]
    assert not any(
        isinstance(target, ast.Attribute) and target.attr == "started"
        for node in assignments
        for target in (
            node.targets
            if isinstance(node, ast.Assign)
            else (node.target,)
        )
    )

"""d81-uncr: the manager must own the residual sink through the lifecycle.

``D810Manager`` cannot be constructed without IDA, so the sequencing itself is
covered by ``tests/unit/mba/test_residual_sink_rebind_on_restart.py`` against
:class:`MbaResidualObservationLifecycle`.  This module pins the manager to that
seam so the restart path cannot regress back into hand-rolled register/close
calls that skip publishing the active generation.
"""

from __future__ import annotations

import ast
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[3]
_MANAGER = _ROOT / "src/d810/manager/manager.py"


def _method(class_name: str, method_name: str) -> ast.FunctionDef:
    tree = ast.parse(_MANAGER.read_text(encoding="utf-8"), filename=str(_MANAGER))
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == method_name:
                    return item
    raise AssertionError(f"{class_name}.{method_name} not found")


def _calls(node: ast.AST) -> set[str]:
    result: set[str] = set()
    for item in ast.walk(node):
        if isinstance(item, ast.Call):
            if isinstance(item.func, ast.Name):
                result.add(item.func.id)
            elif isinstance(item.func, ast.Attribute):
                result.add(item.func.attr)
    return result


def test_initialize_delegates_to_the_residual_observation_lifecycle() -> None:
    calls = _calls(_method("D810Manager", "_initialize_mba_residual_observation"))
    assert "MbaResidualObservationLifecycle" in calls
    assert "start" in calls
    # The registration must not be hand-rolled: publishing the active
    # generation is what the lifecycle adds over a bare register() call.
    assert "register" not in calls


def test_initialize_reuses_the_one_lifecycle_this_manager_already_owns() -> None:
    """d81-mcqr: the relay every issued view names must survive a restart.

    A per-start lifecycle would build a fresh relay, so a provider rule that
    bound the capability before ``state.load_project()`` would keep a routing
    point nothing ever targets again -- the d81-uncr symptom, reintroduced.
    """
    method = _method("D810Manager", "_initialize_mba_residual_observation")
    source = ast.dump(method)
    assert "_mba_residual_observation_lifecycle" in source
    # The construction must be conditional on there not already being one.
    constructed = [
        node
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "MbaResidualObservationLifecycle"
    ]
    assert len(constructed) == 1
    guarded = any(
        any(
            isinstance(inner, ast.Call)
            and isinstance(inner.func, ast.Name)
            and inner.func.id == "MbaResidualObservationLifecycle"
            for inner in ast.walk(branch)
        )
        for node in ast.walk(method)
        if isinstance(node, ast.If)
        for branch in node.body
    )
    assert guarded, "the lifecycle must only be built when the manager has none"
    assert "restart" in _calls(method)


def test_release_stops_the_lifecycle_and_only_retires_it_on_full_cleanup() -> None:
    method = _method("D810Manager", "_release_mba_residual_observation")
    argument_names = {argument.arg for argument in method.args.args}
    assert "full_cleanup" in argument_names
    calls = _calls(method)
    assert "stop" in calls
    # Only a full cleanup may retire the relay; a plain stop must keep it so
    # the views already issued can be re-targeted by the next start.
    assert "close" in calls
    cleared = {
        target.attr
        for node in ast.walk(method)
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Attribute)
        and isinstance(node.value, ast.Constant)
        and node.value.value is None
    }
    assert {
        "_mba_residual_observation_lifecycle",
        "_mba_residual_observation_lease",
        "_mba_residual_observation_sink",
    } <= cleared

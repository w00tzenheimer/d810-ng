"""Structural contract for manager-owned Hex-Rays session lifecycle wiring.

This remains a system-runtime test because it pins the real IDA hook source and
manager composition. It does not substitute a fake Hex-Rays API.
"""

from __future__ import annotations

import ast
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[4]
_HOOK = _ROOT / "src/d810/hexrays/hooks/hexrays_hooks.py"
_OPTBLOCK = _ROOT / "src/d810/hexrays/hooks/optblock_adapter.py"
_LIFECYCLE = _ROOT / "src/d810/hexrays/lifecycle.py"
_MANAGER = _ROOT / "src/d810/manager/manager.py"
_COORDINATOR = _ROOT / "src/d810/manager/decompilation_lifecycle.py"


def _method_source(path: Path, class_name: str, method_name: str) -> str:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef) or node.name != class_name:
            continue
        for method in node.body:
            if isinstance(method, ast.FunctionDef) and method.name == method_name:
                return ast.get_source_segment(source, method) or ""
    raise AssertionError(f"{class_name}.{method_name} not found in {path}")


def test_hook_starts_and_finishes_typed_sessions_through_the_coordinator() -> None:
    prolog = _method_source(_HOOK, "HexraysDecompilationHook", "prolog")
    ensure_session = _method_source(
        _HOOK, "HexraysDecompilationHook", "_ensure_lifecycle_session"
    )
    decision = _method_source(_HOOK, "HexraysDecompilationHook", "_decision_for_mba")
    structural = _method_source(_HOOK, "HexraysDecompilationHook", "structural")

    assert "HexraysDecompilationHook._ensure_lifecycle_session(self, mba)" in prolog
    assert "ensure_hexrays_session" in ensure_session
    assert "DecompilationEvent.SESSION_STARTED" in ensure_session
    assert "HexraysDecompilationHook._ensure_lifecycle_session(self, mba)" in decision
    assert "lifecycle.finish_hexrays_session()" in structural
    assert "DecompilationEvent.SESSION_FINISHED" in structural
    assert "DecompilationEvent.STARTED" not in prolog
    assert "DecompilationEvent.FINISHED" not in structural


def test_every_resolver_callback_receives_the_lifecycle_session_decision() -> None:
    build_callinfo = _method_source(
        _HOOK, "HexraysDecompilationHook", "build_callinfo"
    )
    stkpnts = _method_source(_HOOK, "HexraysDecompilationHook", "stkpnts")
    preoptimized = _method_source(_HOOK, "HexraysDecompilationHook", "preoptimized")

    assert "_decision_for_mba(self, blk.mba)" in build_callinfo
    assert "_decision_for_mba(self, mba)" in stkpnts
    assert "bind_live_identity=True" not in build_callinfo
    assert "bind_live_identity=True" not in stkpnts
    assert "_decision_for_mba(" in preoptimized
    assert "bind_live_identity=True" in preoptimized


def test_live_mba_gateway_is_bound_once_per_flow_context() -> None:
    context = _method_source(
        _OPTBLOCK,
        "BlockOptimizerManager",
        "_get_or_create_flow_context",
    )

    create_branch = context.split("        else:\n", maxsplit=1)[0]
    assert "self._bind_resolver_session_state(self._flow_context, mba)" in create_branch
    assert "self._bind_mutation_gateway_port(self._flow_context, mba)" in create_branch


def test_manager_has_one_coordinator_and_no_legacy_flowgraph_subscriber() -> None:
    source = _MANAGER.read_text(encoding="utf-8")

    assert "DecompilationLifecycleCoordinator(" in source
    assert "decompilation_lifecycle=self.decompilation_lifecycle" in source
    assert "self._capture_flowgraph_ready" in source
    assert "FlowGraphReadySubscriber" not in source


def test_coordinator_is_the_only_production_lifecycle_runtime_bridge() -> None:
    source = _COORDINATOR.read_text(encoding="utf-8")

    assert ".reset_for_func(" in source
    assert ".analyze_and_persist(" in source
    for adapter in (
        _ROOT / "src/d810/hexrays/hooks/optinsn_adapter.py",
        _ROOT / "src/d810/hexrays/hooks/optblock_adapter.py",
        _ROOT / "src/d810/hexrays/hooks/ctree_hooks.py",
    ):
        adapter_source = adapter.read_text(encoding="utf-8")
        assert ".reset_for_func(" not in adapter_source
        assert ".analyze_and_persist(" not in adapter_source


def test_legacy_start_and_finish_enum_members_are_removed() -> None:
    source = _LIFECYCLE.read_text(encoding="utf-8")

    assert "SESSION_STARTED" in source
    assert "SESSION_FINISHED" in source
    assert "    STARTED =" not in source
    assert "    FINISHED =" not in source

"""Test that PreanalysisPhase is wired into the hook managers.

These tests use source-level inspection (ast.parse / inspect.getsource) to
verify the structural wiring without importing IDA-dependent modules.
No IDA imports, no mocking of IDA modules.
"""
from __future__ import annotations
import ast
import inspect
import pathlib

def _find_src_root() -> pathlib.Path:
    p = pathlib.Path(__file__).resolve()
    while p != p.parent:
        if (p / "pyproject.toml").exists():
            return p / "src" / "d810"
        p = p.parent
    raise RuntimeError("Cannot find project root (no pyproject.toml found)")


_SRC = _find_src_root()


def _resolve_hook_file(*relative_paths: tuple[str, ...] | str) -> pathlib.Path:
    for rel in relative_paths:
        path = _SRC / rel
        if path.exists():
            return path
    return _SRC / str(relative_paths[0])


_OPTINSN_ADAPTER = _resolve_hook_file(
    "hexrays/hooks/optinsn_adapter.py",
)
_OPTBLOCK_ADAPTER = _resolve_hook_file(
    "hexrays/hooks/optblock_adapter.py",
)
_CTREE_HOOKS = _resolve_hook_file(
    "hexrays/hooks/ctree_hooks.py",
    "hexrays/ctree_hooks.py",
)
_ANALYSIS_RUNTIME_FACTORY = _SRC / "passes/analysis_runtime_factory.py"


def _get_class_source(filepath: pathlib.Path, class_name: str) -> str:
    """Return the source text of a class definition in a file."""
    source = filepath.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return ast.get_source_segment(source, node) or ""
    return ""


class TestInstructionOptimizerManagerUsesLifecyclePort:
    """Instruction adapter delegates lifecycle work to the coordinator."""

    def test_has_lifecycle_port_in_init(self):
        filepath = _OPTINSN_ADAPTER
        cls_src = _get_class_source(filepath, "InstructionOptimizerManager")
        assert "_decompilation_lifecycle" in cls_src, (
            "InstructionOptimizerManager must retain the injected lifecycle port"
        )

    def test_configure_accepts_lifecycle_port(self):
        filepath = _OPTINSN_ADAPTER
        cls_src = _get_class_source(filepath, "InstructionOptimizerManager")
        assert "decompilation_lifecycle" in cls_src, (
            "InstructionOptimizerManager.configure() must accept the lifecycle port"
        )

    def test_log_info_emits_flowgraph_ready(self):
        "E4a contract: microcode preanalysis collection is driven by the\n        lifecycle coordinator on ``D810``.  Each manager\n        maturity gate must invoke ``_emit_flowgraph_ready_event``;\n        the direct ``run_microcode_collectors(mba, ...)`` call is\n        gone.\n\n        Architectural pin: catches drift that either removes the\n        emit (preanalysis stops firing for this manager) or re-introduces\n        a direct ``run_microcode_collectors`` call (double-collect)."
        filepath = _OPTINSN_ADAPTER
        cls_src = _get_class_source(filepath, "InstructionOptimizerManager")
        assert "_emit_flowgraph_ready_event(" in cls_src, (
            "InstructionOptimizerManager.log_info_on_input() must call "
            "_emit_flowgraph_ready_event(); the FLOWGRAPH_READY "
            "coordinator on D810 is the sole microcode-collection "
            "trigger after E4a."
        )
        assert ".reset_for_func(" not in cls_src
        assert ".analyze_and_persist(" not in cls_src


class TestBlockOptimizerManagerUsesLifecyclePort:
    """Block adapter delegates lifecycle work to the coordinator."""

    def test_has_lifecycle_port_in_init(self):
        filepath = _OPTBLOCK_ADAPTER
        cls_src = _get_class_source(filepath, "BlockOptimizerManager")
        assert "_decompilation_lifecycle" in cls_src

    def test_configure_accepts_lifecycle_port(self):
        filepath = _OPTBLOCK_ADAPTER
        cls_src = _get_class_source(filepath, "BlockOptimizerManager")
        assert "decompilation_lifecycle" in cls_src

    def test_log_info_emits_flowgraph_ready_and_owns_no_runtime_lifecycle(self):
        filepath = _OPTBLOCK_ADAPTER
        cls_src = _get_class_source(filepath, "BlockOptimizerManager")
        assert "_emit_flowgraph_ready_event(" in cls_src
        assert ".reset_for_func(" not in cls_src
        assert ".analyze_and_persist(" not in cls_src


class TestCtreeOptimizerManagerUsesLifecyclePort:
    """Ctree adapter delegates collection and analysis to the coordinator."""

    def test_init_accepts_lifecycle_port(self):
        filepath = _CTREE_HOOKS
        cls_src = _get_class_source(filepath, "CtreeOptimizerManager")
        assert "decompilation_lifecycle" in cls_src

    def test_on_maturity_calls_lifecycle_port(self):
        filepath = _CTREE_HOOKS
        cls_src = _get_class_source(filepath, "CtreeOptimizerManager")
        assert "lifecycle.capture_ctree(" in cls_src
        assert "lifecycle.analyze_current_function(" in cls_src
        assert ".analyze_and_persist(" not in cls_src

    def test_has_lifecycle_parameter(self):
        """Ctree manager remains importable without an initialized IDA runtime."""
        from d810.hexrays.hooks.ctree_hooks import CtreeOptimizerManager

        sig = inspect.signature(CtreeOptimizerManager.__init__)
        assert "decompilation_lifecycle" in sig.parameters


class TestAnalysisRuntimeFactoryBuildsFullPreanalysisPhase:
    """The analysis runtime factory owns the flow-recovery collector inventory."""

    def test_build_preanalysis_phase_registers_handler_transitions(self):
        src = _ANALYSIS_RUNTIME_FACTORY.read_text(encoding="utf-8")
        assert "HandlerTransitionsCollector" in src

    def test_build_preanalysis_phase_registers_return_frontier(self):
        src = _ANALYSIS_RUNTIME_FACTORY.read_text(encoding="utf-8")
        assert "ReturnFrontierCollector" in src

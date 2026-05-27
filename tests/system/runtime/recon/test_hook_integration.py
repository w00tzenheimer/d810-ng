"""Test that ReconPhase is wired into the hook managers.

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


_HEXRAYS_HOOKS = _resolve_hook_file(
    "hexrays/hooks/hexrays_hooks.py",
    "hexrays/hexrays_hooks.py",
)
_CTREE_HOOKS = _resolve_hook_file(
    "hexrays/hooks/ctree_hooks.py",
    "hexrays/ctree_hooks.py",
)
_MANAGER = _SRC / "manager.py"


def _get_class_source(filepath: pathlib.Path, class_name: str) -> str:
    """Return the source text of a class definition in a file."""
    source = filepath.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return ast.get_source_segment(source, node) or ""
    return ""


class TestInstructionOptimizerManagerHasReconPhase:
    """InstructionOptimizerManager must have _recon_phase support."""

    def test_has_recon_phase_in_init(self):
        filepath = _HEXRAYS_HOOKS
        cls_src = _get_class_source(filepath, "InstructionOptimizerManager")
        assert "_recon_phase" in cls_src, (
            "InstructionOptimizerManager.__init__ must set self._recon_phase"
        )

    def test_configure_accepts_recon_phase(self):
        filepath = _HEXRAYS_HOOKS
        cls_src = _get_class_source(filepath, "InstructionOptimizerManager")
        assert "recon_phase" in cls_src, (
            "InstructionOptimizerManager.configure() must accept recon_phase kwarg"
        )

    def test_log_info_emits_flowgraph_ready(self):
        """E4a contract: microcode recon collection is driven by the
        ``FLOWGRAPH_READY`` subscriber on ``D810``.  Each manager
        maturity gate must invoke ``_emit_flowgraph_ready_event``;
        the direct ``run_microcode_collectors(mba, ...)`` call is
        gone.

        Architectural pin: catches drift that either removes the
        emit (recon stops firing for this manager) or re-introduces
        a direct ``run_microcode_collectors`` call (double-collect)."""
        filepath = _HEXRAYS_HOOKS
        cls_src = _get_class_source(filepath, "InstructionOptimizerManager")
        assert "_emit_flowgraph_ready_event(" in cls_src, (
            "InstructionOptimizerManager.log_info_on_input() must call "
            "_emit_flowgraph_ready_event(); the FLOWGRAPH_READY "
            "subscriber on D810 is the sole microcode-collection "
            "trigger after E4a."
        )
        # Direct call shape must be absent.
        assert "self._recon_phase.run_microcode_collectors(" not in cls_src, (
            "InstructionOptimizerManager must not call "
            "_recon_phase.run_microcode_collectors() directly -- "
            "E4a routes that through the FLOWGRAPH_READY subscriber "
            "on D810.  A direct call here would double-collect."
        )


class TestBlockOptimizerManagerHasReconPhase:
    """BlockOptimizerManager must have _recon_phase support."""

    def test_has_recon_phase_in_init(self):
        filepath = _HEXRAYS_HOOKS
        cls_src = _get_class_source(filepath, "BlockOptimizerManager")
        assert "_recon_phase" in cls_src, (
            "BlockOptimizerManager.__init__ must set self._recon_phase"
        )

    def test_configure_accepts_recon_phase(self):
        filepath = _HEXRAYS_HOOKS
        cls_src = _get_class_source(filepath, "BlockOptimizerManager")
        assert "recon_phase" in cls_src, (
            "BlockOptimizerManager.configure() must accept recon_phase kwarg"
        )

    def test_log_info_emits_flowgraph_ready(self):
        """E4a contract: see ``InstructionOptimizerManager`` sibling.
        Both manager maturity gates emit; ``ReconPhase`` dedupes the
        two emits per ``(func_ea, maturity)``."""
        filepath = _HEXRAYS_HOOKS
        cls_src = _get_class_source(filepath, "BlockOptimizerManager")
        assert "_emit_flowgraph_ready_event(" in cls_src, (
            "BlockOptimizerManager.log_info_on_input() must call "
            "_emit_flowgraph_ready_event(); the FLOWGRAPH_READY "
            "subscriber on D810 is the sole microcode-collection "
            "trigger after E4a."
        )
        # Direct call shape must be absent.
        assert "self._recon_phase.run_microcode_collectors(" not in cls_src, (
            "BlockOptimizerManager must not call "
            "_recon_phase.run_microcode_collectors() directly -- "
            "E4a routes that through the FLOWGRAPH_READY subscriber "
            "on D810.  A direct call here would double-collect."
        )


class TestCtreeOptimizerManagerHasReconPhase:
    """CtreeOptimizerManager must have a recon_phase parameter."""

    def test_init_accepts_recon_phase(self):
        filepath = _CTREE_HOOKS
        cls_src = _get_class_source(filepath, "CtreeOptimizerManager")
        assert "recon_phase" in cls_src, (
            "CtreeOptimizerManager.__init__ must accept recon_phase parameter"
        )

    def test_on_maturity_calls_run_ctree_collectors(self):
        filepath = _CTREE_HOOKS
        cls_src = _get_class_source(filepath, "CtreeOptimizerManager")
        assert "run_ctree_collectors" in cls_src, (
            "CtreeOptimizerManager.on_maturity() must call "
            "_recon_phase.run_ctree_collectors()"
        )

    def test_has_recon_phase_attribute(self):
        """CtreeOptimizerManager can be imported without IDA (guarded imports)."""
        from d810.hexrays.hooks.ctree_hooks import CtreeOptimizerManager
        sig = inspect.signature(CtreeOptimizerManager.__init__)
        assert "recon_phase" in sig.parameters or \
               hasattr(CtreeOptimizerManager, "_recon_phase"), (
            "CtreeOptimizerManager must expose recon_phase"
        )


class TestManagerBuildsFullReconPhase:
    """D810Manager must register the flow-recovery collectors we rely on."""

    def test_build_recon_phase_registers_handler_transitions(self):
        src = _MANAGER.read_text(encoding="utf-8")
        assert "phase.register(HandlerTransitionsCollector())" in src

    def test_build_recon_phase_registers_return_frontier(self):
        src = _MANAGER.read_text(encoding="utf-8")
        assert "phase.register(ReturnFrontierCollector())" in src

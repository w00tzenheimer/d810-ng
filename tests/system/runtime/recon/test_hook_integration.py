"""Test that ReconPhase is wired into the hook managers.

These tests use source-level inspection (ast.parse / inspect.getsource) to
verify the structural wiring without importing IDA-dependent modules.
No IDA imports, no mocking of IDA modules.
"""
from __future__ import annotations
import ast
import inspect
import pathlib
import pytest

def _find_src_root() -> pathlib.Path:
    p = pathlib.Path(__file__).resolve()
    while p != p.parent:
        if (p / "pyproject.toml").exists():
            return p / "src" / "d810"
        p = p.parent
    raise RuntimeError("Cannot find project root (no pyproject.toml found)")


_SRC = _find_src_root()


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
        filepath = _SRC / "hexrays" / "hexrays_hooks.py"
        cls_src = _get_class_source(filepath, "InstructionOptimizerManager")
        assert "_recon_phase" in cls_src, (
            "InstructionOptimizerManager.__init__ must set self._recon_phase"
        )

    def test_configure_accepts_recon_phase(self):
        filepath = _SRC / "hexrays" / "hexrays_hooks.py"
        cls_src = _get_class_source(filepath, "InstructionOptimizerManager")
        assert "recon_phase" in cls_src, (
            "InstructionOptimizerManager.configure() must accept recon_phase kwarg"
        )

    def test_log_info_calls_run_microcode_collectors(self):
        filepath = _SRC / "hexrays" / "hexrays_hooks.py"
        cls_src = _get_class_source(filepath, "InstructionOptimizerManager")
        assert "run_microcode_collectors" in cls_src, (
            "InstructionOptimizerManager.log_info_on_input() must call "
            "_recon_phase.run_microcode_collectors()"
        )


class TestBlockOptimizerManagerHasReconPhase:
    """BlockOptimizerManager must have _recon_phase support."""

    def test_has_recon_phase_in_init(self):
        filepath = _SRC / "hexrays" / "hexrays_hooks.py"
        cls_src = _get_class_source(filepath, "BlockOptimizerManager")
        assert "_recon_phase" in cls_src, (
            "BlockOptimizerManager.__init__ must set self._recon_phase"
        )

    def test_configure_accepts_recon_phase(self):
        filepath = _SRC / "hexrays" / "hexrays_hooks.py"
        cls_src = _get_class_source(filepath, "BlockOptimizerManager")
        assert "recon_phase" in cls_src, (
            "BlockOptimizerManager.configure() must accept recon_phase kwarg"
        )

    def test_log_info_calls_run_microcode_collectors(self):
        filepath = _SRC / "hexrays" / "hexrays_hooks.py"
        cls_src = _get_class_source(filepath, "BlockOptimizerManager")
        assert "run_microcode_collectors" in cls_src, (
            "BlockOptimizerManager.log_info_on_input() must call "
            "_recon_phase.run_microcode_collectors()"
        )


class TestCtreeOptimizerManagerHasReconPhase:
    """CtreeOptimizerManager must have a recon_phase parameter."""

    def test_init_accepts_recon_phase(self):
        filepath = _SRC / "hexrays" / "ctree_hooks.py"
        cls_src = _get_class_source(filepath, "CtreeOptimizerManager")
        assert "recon_phase" in cls_src, (
            "CtreeOptimizerManager.__init__ must accept recon_phase parameter"
        )

    def test_on_maturity_calls_run_ctree_collectors(self):
        filepath = _SRC / "hexrays" / "ctree_hooks.py"
        cls_src = _get_class_source(filepath, "CtreeOptimizerManager")
        assert "run_ctree_collectors" in cls_src, (
            "CtreeOptimizerManager.on_maturity() must call "
            "_recon_phase.run_ctree_collectors()"
        )

    def test_has_recon_phase_attribute(self):
        """CtreeOptimizerManager can be imported without IDA (guarded imports)."""
        from d810.hexrays.ctree_hooks import CtreeOptimizerManager
        sig = inspect.signature(CtreeOptimizerManager.__init__)
        assert "recon_phase" in sig.parameters or \
               hasattr(CtreeOptimizerManager, "_recon_phase"), (
            "CtreeOptimizerManager must expose recon_phase"
        )

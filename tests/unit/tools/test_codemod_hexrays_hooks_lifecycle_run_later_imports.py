from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = (
    REPO_ROOT
    / "tools"
    / "scripts"
    / "codemod_hexrays_hooks_lifecycle_run_later_imports.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location("codemod_hexrays_hooks", SCRIPT)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_rewrite_text_splits_mixed_hexrays_hooks_import() -> None:
    mod = _load_module()
    source = """from d810.hexrays.hooks.hexrays_hooks import (
    BlockOptimizerManager as BOM,
    DecompilationEvent,
    HexraysDecompilationHook,
    InstructionOptimizerManager as IOM,
    _emit_flowgraph_ready_event as emit_ready,
    local_helper,
)
"""

    result = mod.rewrite_text(source)

    assert result.changed
    assert (
        "from d810.hexrays.hooks.optblock_adapter import "
        "BlockOptimizerManager as BOM"
    ) in result.text
    assert (
        "from d810.hexrays.hooks.optinsn_adapter import "
        "InstructionOptimizerManager as IOM"
    ) in result.text
    assert (
        "from d810.hexrays.lifecycle import DecompilationEvent, "
        "_emit_flowgraph_ready_event as emit_ready"
    ) in result.text
    assert (
        "from d810.hexrays.hooks.hexrays_hooks import "
        "HexraysDecompilationHook, local_helper"
    ) in result.text


def test_rewrite_text_keeps_hexrays_decompilation_hook_owner() -> None:
    mod = _load_module()
    source = (
        "from d810.hexrays.hooks.hexrays_hooks import "
        "HexraysDecompilationHook\n"
    )

    result = mod.rewrite_text(source)

    assert not result.changed
    assert result.text == source


def test_rewrite_text_updates_fully_qualified_moved_symbols() -> None:
    mod = _load_module()
    source = (
        "target = "
        "d810.hexrays.hooks.hexrays_hooks.InstructionOptimizerManager\n"
        "hook = d810.hexrays.hooks.hexrays_hooks.HexraysDecompilationHook\n"
    )

    result = mod.rewrite_text(source)

    assert (
        "d810.hexrays.hooks.optinsn_adapter.InstructionOptimizerManager"
        in result.text
    )
    assert "d810.hexrays.hooks.hexrays_hooks.HexraysDecompilationHook" in result.text


def test_rewrite_text_handles_hooks_module_alias_access() -> None:
    mod = _load_module()
    source = """def test_both_managers():
    from d810.hexrays.hooks import hexrays_hooks

    instr_src = inspect.getsource(
        hexrays_hooks.InstructionOptimizerManager.log_info_on_input
    )
    block_src = inspect.getsource(
        hexrays_hooks.BlockOptimizerManager.log_info_on_input
    )
"""

    result = mod.rewrite_text(source)

    assert result.changed
    assert "from d810.hexrays.hooks import hexrays_hooks" in result.text
    assert (
        "from d810.hexrays.hooks.optinsn_adapter import "
        "InstructionOptimizerManager"
    ) in result.text
    assert (
        "from d810.hexrays.hooks.optblock_adapter import "
        "BlockOptimizerManager"
    ) in result.text
    assert "hexrays_hooks.InstructionOptimizerManager" not in result.text
    assert "hexrays_hooks.BlockOptimizerManager" not in result.text
    assert "InstructionOptimizerManager.log_info_on_input" in result.text
    assert "BlockOptimizerManager.log_info_on_input" in result.text


def test_rewrite_text_preserves_hooks_module_import_alias() -> None:
    mod = _load_module()
    source = """def test_alias(monkeypatch):
    from d810.hexrays.hooks import hexrays_hooks as hh

    monkeypatch.setattr(hh, "lift_mba_to_flowgraph", fake_lift)
    src = hh.InstructionOptimizerManager.log_info_on_input
"""

    result = mod.rewrite_text(source)

    assert result.changed
    assert "from d810.hexrays.hooks import hexrays_hooks as hh" in result.text
    assert (
        "from d810.hexrays.hooks.optinsn_adapter import "
        "InstructionOptimizerManager"
    ) in result.text
    assert "hh.InstructionOptimizerManager" not in result.text
    assert "src = InstructionOptimizerManager.log_info_on_input" in result.text
    assert 'monkeypatch.setattr(hh, "lift_mba_to_flowgraph", fake_lift)' in result.text


def test_cli_default_dry_run_does_not_write(tmp_path: Path) -> None:
    sample = tmp_path / "sample.py"
    sample.write_text(
        "from d810.hexrays.hooks.hexrays_hooks import "
        "InstructionOptimizerManager, HexraysDecompilationHook\n",
        encoding="utf-8",
    )

    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--root",
            str(tmp_path),
            str(sample),
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=30,
    )

    assert proc.returncode == 0, proc.stderr
    assert "would rewrite sample.py" in proc.stdout
    assert "dry-run: rewritten=1" in proc.stdout
    assert (
        "from d810.hexrays.hooks.hexrays_hooks import "
        "InstructionOptimizerManager, HexraysDecompilationHook\n"
    ) == sample.read_text(encoding="utf-8")

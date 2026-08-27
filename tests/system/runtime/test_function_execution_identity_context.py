"""Runtime-shaped proof for callback-local MBA observation identity."""

from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.core.function_execution_identity import FunctionExecutionIdentity
from d810.core.plugins import PluginIdentity
from d810.hexrays.hooks.optinsn_adapter import InstructionOptimizerManager
from d810.ir.maturity import IRMaturity


def _identity() -> FunctionExecutionIdentity:
    return FunctionExecutionIdentity(
        input_identity="sha256:" + "a" * 64,
        input_identity_provenance="verified_loader_sha256",
        external_evidence_allowed=True,
        database_uuid="12345678-1234-5678-1234-567812345678",
        database_identity="runtime.i64",
        function_ea=0x401000,
        function_rva=0x1000,
        function_fingerprint="sha256:" + "b" * 64,
        decompilation_session_id="runtime-session",
        top_level_epoch=1,
        maturity=IRMaturity.CANONICAL,
        evidence_generation=4,
    )


def test_live_shaped_mba_context_has_ea_anchored_block_identity() -> None:
    lifecycle = SimpleNamespace(
        current_function_execution_identity=lambda function_ea, maturity: (
            _identity()
            if function_ea == 0x401000 and maturity is IRMaturity.CANONICAL
            else None
        )
    )
    manager = object.__new__(InstructionOptimizerManager)
    manager._decompilation_lifecycle = lifecycle
    mba = SimpleNamespace(entry_ea=0x401000, maturity=ida_hexrays.MMAT_PREOPTIMIZED)
    block = SimpleNamespace(mba=mba, serial=7, start=0x401000)
    instruction = SimpleNamespace(ea=0x401005)
    plugin = PluginIdentity("cobra", "d810-cobra", "1.0", "runtime")

    context = manager.mba_observation_context(block, instruction, plugin)

    assert context is not None
    assert context.function_identity.maturity is IRMaturity.CANONICAL
    assert context.instruction_ea == 0x401005
    assert context.block_identity == "blk7@0x401000"
    assert context.function_identity.evidence_generation == 4
    assert all("observation" not in key for key in manager.__dict__)


def test_live_shaped_context_fails_closed_without_block_anchor() -> None:
    lifecycle = SimpleNamespace(
        current_function_execution_identity=lambda _function_ea, _maturity: _identity()
    )
    manager = object.__new__(InstructionOptimizerManager)
    manager._decompilation_lifecycle = lifecycle
    mba = SimpleNamespace(entry_ea=0x401000, maturity=ida_hexrays.MMAT_PREOPTIMIZED)
    block = SimpleNamespace(mba=mba, serial=7)
    instruction = SimpleNamespace(ea=0x401005)
    plugin = PluginIdentity("cobra", "d810-cobra", "1.0", "runtime")

    assert manager.mba_observation_context(block, instruction, plugin) is None

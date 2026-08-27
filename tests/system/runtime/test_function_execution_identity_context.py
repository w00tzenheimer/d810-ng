"""Real-IDB proof for callback-local MBA observation identity."""

from __future__ import annotations

import contextlib
from collections import Counter

import ida_hexrays
import idaapi

from d810.core.plugins import PluginIdentity
from d810.manager import D810State
from tests.system.runtime.conftest import gen_microcode_at_maturity, get_func_ea


@contextlib.contextmanager
def _started_real_state():
    """Start the real D810 manager with a minimal valid runtime project."""
    state = D810State()
    was_loaded = state.is_loaded()
    if not was_loaded:
        state.load(gui=False)
    was_started = state.manager.started
    if not was_started:
        manager = state.manager
        manager.configure_instruction_optimizer([])
        manager.configure_block_optimizer([])
        manager.configure(
            project_name="task4-runtime.json",
            idb_key="task4-runtime",
            enable_analysis_pipeline=False,
        )
        manager.start()
    try:
        yield state
    finally:
        if not was_started:
            state.stop_d810()
        if not was_loaded:
            state.unload(gui=False)


class TestFunctionExecutionIdentityContext:
    binary_name = "libobfuscated.dll"

    def test_real_mba_context_reuses_active_session_and_generation(
        self,
        ida_database,
        configure_hexrays,
        setup_libobfuscated_funcs,
    ) -> None:
        del ida_database, configure_hexrays, setup_libobfuscated_funcs
        assert idaapi.init_hexrays_plugin()
        function_ea = get_func_ea("test_xor")
        assert function_ea != idaapi.BADADDR
        with _started_real_state() as state:
            manager = state.manager
            lifecycle = manager.decompilation_lifecycle
            session, created = lifecycle.ensure_hexrays_session(
                function_ea=function_ea,
                database_identity=manager._database_identity,
            )
            assert created
            lifecycle.begin_current_mba_generation(function_ea=function_ea)
            mba = gen_microcode_at_maturity(function_ea, ida_hexrays.MMAT_PREOPTIMIZED)
            assert mba is not None
            block = next(
                (
                    mba.get_mblock(index)
                    for index in range(mba.qty)
                    if mba.get_mblock(index) is not None
                    and mba.get_mblock(index).head is not None
                ),
                None,
            )
            assert block is not None
            instruction = block.head
            assert instruction is not None
            plugin = PluginIdentity("cobra", "d810-cobra", "1.0", "runtime")
            try:
                context = manager.instruction_optimizer.mba_observation_context(
                    block, instruction, plugin
                )
                assert context is not None
                assert context.function_identity.decompilation_session_id == (
                    session.session_id.value
                )
                assert context.function_identity.maturity == "ir.canonical"
                assert context.function_identity.evidence_generation == (
                    lifecycle.current_evidence_generation(function_ea=function_ea)
                )
                assert context.instruction_ea == int(instruction.ea)
                assert context.block_serial == int(block.serial)
                assert context.block_ea is not None
                assert context.block_identity == (
                    f"blk{int(block.serial)}@0x{int(context.block_ea):X}"
                )
                assert not any(
                    value is context
                    for value in manager.instruction_optimizer.__dict__.values()
                )
            finally:
                lifecycle.finish_hexrays_session()

    def test_real_invalid_or_synthetic_anchors_abstain(
        self,
        ida_database,
        configure_hexrays,
        setup_libobfuscated_funcs,
    ) -> None:
        del ida_database, configure_hexrays, setup_libobfuscated_funcs
        function_ea = get_func_ea("test_xor")
        with _started_real_state() as state:
            manager = state.manager
            lifecycle = manager.decompilation_lifecycle
            lifecycle.ensure_hexrays_session(
                function_ea=function_ea,
                database_identity=manager._database_identity,
            )
            lifecycle.begin_current_mba_generation(function_ea=function_ea)
            plugin = PluginIdentity("cobra", "d810-cobra", "1.0", "runtime")
            try:
                invalid_case = None
                shared_case = None
                for maturity in (
                    ida_hexrays.MMAT_GENERATED,
                    ida_hexrays.MMAT_PREOPTIMIZED,
                    ida_hexrays.MMAT_LOCOPT,
                ):
                    mba = gen_microcode_at_maturity(function_ea, maturity)
                    if mba is None:
                        continue
                    starts = Counter(
                        int(mba.get_mblock(index).start)
                        for index in range(mba.qty)
                        if mba.get_mblock(index) is not None
                    )
                    for index in range(mba.qty):
                        block = mba.get_mblock(index)
                        if block is None or block.head is None:
                            continue
                        instruction = block.head
                        context = manager.instruction_optimizer.mba_observation_context(
                            block, instruction, plugin
                        )
                        block_start = int(block.start)
                        if block_start == int(idaapi.BADADDR) or not idaapi.is_mapped(
                            block_start
                        ):
                            if not idaapi.is_mapped(int(instruction.ea)):
                                invalid_case = context
                        if (
                            starts[block_start] > 1
                            and int(instruction.ea) != block_start
                        ):
                            shared_case = context
                if invalid_case is None:
                    mba = gen_microcode_at_maturity(
                        function_ea, ida_hexrays.MMAT_PREOPTIMIZED
                    )
                    assert mba is not None
                    synthetic_block = next(
                        (
                            mba.get_mblock(index)
                            for index in range(mba.qty)
                            if mba.get_mblock(index) is not None
                            and mba.get_mblock(index).head is not None
                        ),
                        None,
                    )
                    assert synthetic_block is not None
                    synthetic_instruction = synthetic_block.head
                    assert synthetic_instruction is not None
                    original_block_start = synthetic_block.start
                    original_instruction_ea = synthetic_instruction.ea
                    try:
                        synthetic_block.start = idaapi.BADADDR
                        synthetic_instruction.ea = idaapi.BADADDR
                        invalid_case = (
                            manager.instruction_optimizer.mba_observation_context(
                                synthetic_block, synthetic_instruction, plugin
                            )
                        )
                    finally:
                        synthetic_block.start = original_block_start
                        synthetic_instruction.ea = original_instruction_ea
                assert invalid_case is None
                if shared_case is not None:
                    assert shared_case.block_ea is not None
                    assert shared_case.instruction_ea == shared_case.block_ea
            finally:
                lifecycle.finish_hexrays_session()

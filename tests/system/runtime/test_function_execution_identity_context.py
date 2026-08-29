"""Real-IDB proof for callback-local MBA observation identity."""

from __future__ import annotations

import contextlib
import gc

import ida_hexrays
import idaapi

from tests.system.runtime.conftest import gen_microcode_at_maturity, get_func_ea


@contextlib.contextmanager
def _started_real_state():
    """Start the real D810 manager with a minimal valid runtime project."""
    # Resolve the class after any opt-in reload-isolation test has completed.
    # A module-level import would retain the pre-reload class identity and
    # construct a second manager with colliding capability registrations.
    from d810.manager import D810State

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


def _current_identity_types():
    """Resolve reload-sensitive identity classes at test execution time."""
    from d810.core.function_execution_identity import MbaObservationContext
    from d810.core.plugins import PluginIdentity

    return MbaObservationContext, PluginIdentity


class TestFunctionExecutionIdentityContext:
    binary_name = "libobfuscated.dll"

    def test_real_mba_context_reuses_active_session_and_generation(
        self,
        ida_database,
        configure_hexrays,
        setup_libobfuscated_funcs,
        monkeypatch,
    ) -> None:
        del ida_database, configure_hexrays, setup_libobfuscated_funcs
        MbaObservationContext, PluginIdentity = _current_identity_types()
        assert idaapi.init_hexrays_plugin()
        function_ea = get_func_ea("test_function_ollvm_fla_bcf_sub")
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
            observed: list[dict[str, object]] = []

            def observe_callback(callback_block, callback_instruction):
                callback_context = (
                    manager.instruction_optimizer.mba_observation_context(
                        callback_block, callback_instruction, plugin
                    )
                )
                assert callback_context is not None
                observed.append(callback_context.to_dict())
                return False

            monkeypatch.setattr(
                manager.instruction_optimizer,
                "log_info_on_input",
                lambda *_args: False,
            )
            monkeypatch.setattr(
                manager.instruction_optimizer, "optimize", observe_callback
            )
            try:
                assert manager.instruction_optimizer.func(block, instruction) is False
                assert len(observed) == 1
                payload = observed[0]
                identity = payload["function_identity"]
                assert identity["decompilation_session_id"] == (
                    session.session_id.value
                )
                assert identity["maturity"] == "ir.canonical"
                assert identity["evidence_generation"] == (
                    lifecycle.current_evidence_generation(function_ea=function_ea)
                )
                assert payload["instruction_ea"] == int(instruction.ea)
                assert payload["block_serial"] == int(block.serial)
                assert payload["block_ea"] is not None
                assert payload["block_identity"] == (
                    f"blk{int(block.serial)}@0x{int(payload['block_ea']):X}"
                )
            finally:
                lifecycle.finish_hexrays_session()
            gc.collect()
            assert not any(
                isinstance(value, MbaObservationContext) for value in gc.get_objects()
            )

    def test_real_anchor_fallback_and_abstention_restore_mba(
        self,
        ida_database,
        configure_hexrays,
        setup_libobfuscated_funcs,
    ) -> None:
        del ida_database, configure_hexrays, setup_libobfuscated_funcs
        _, PluginIdentity = _current_identity_types()
        function_ea = get_func_ea("test_function_ollvm_fla_bcf_sub")
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
                mba = None
                blocks = []
                for maturity in (
                    ida_hexrays.MMAT_GENERATED,
                    ida_hexrays.MMAT_PREOPTIMIZED,
                    ida_hexrays.MMAT_LOCOPT,
                ):
                    candidate = gen_microcode_at_maturity(function_ea, maturity)
                    if candidate is None:
                        continue
                    candidate_blocks = [
                        candidate.get_mblock(index)
                        for index in range(candidate.qty)
                        if candidate.get_mblock(index) is not None
                        and candidate.get_mblock(index).head is not None
                    ]
                    if len(candidate_blocks) >= 2:
                        mba = candidate
                        blocks = candidate_blocks
                        break
                assert mba is not None
                assert len(blocks) >= 2
                first, second = blocks[:2]
                first_instruction = first.head
                second_instruction = second.head
                assert first_instruction is not None
                assert second_instruction is not None
                original_first_start = int(first.start)
                original_second_start = int(second.start)
                original_first_ea = int(first_instruction.ea)
                original_second_ea = int(second_instruction.ea)
                assert idaapi.is_mapped(original_first_ea)
                unmapped_start = 0x700000000000
                while idaapi.is_mapped(unmapped_start):
                    unmapped_start += 0x1000
                assert unmapped_start != int(idaapi.BADADDR)
                assert not idaapi.is_mapped(unmapped_start)
                try:
                    first.start = unmapped_start
                    fallback = manager.instruction_optimizer.mba_observation_context(
                        first, first_instruction, plugin
                    )
                    assert fallback is not None
                    assert fallback.block_ea == original_first_ea

                    shared_start = original_first_ea
                    first.start = shared_start
                    second.start = shared_start
                    assert int(first.start) == int(second.start) == shared_start
                    assert int(first.serial) != int(second.serial)
                    assert idaapi.is_mapped(shared_start)
                    shared = manager.instruction_optimizer.mba_observation_context(
                        second, second_instruction, plugin
                    )
                    assert shared is not None
                    assert original_second_ea != shared_start
                    assert shared.block_ea == original_second_ea

                    first.start = idaapi.BADADDR
                    first_instruction.ea = idaapi.BADADDR
                    assert (
                        manager.instruction_optimizer.mba_observation_context(
                            first, first_instruction, plugin
                        )
                        is None
                    )
                finally:
                    first.start = original_first_start
                    second.start = original_second_start
                    first_instruction.ea = original_first_ea
                    second_instruction.ea = original_second_ea
                assert int(first.start) == original_first_start
                assert int(second.start) == original_second_start
                assert int(first_instruction.ea) == original_first_ea
                assert int(second_instruction.ea) == original_second_ea
                mba.verify(True)
                assert mba.get_mblock(first.serial) is not None
            finally:
                lifecycle.finish_hexrays_session()

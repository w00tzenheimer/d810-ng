"""Runtime contract for the function-oriented INFO surface."""

from __future__ import annotations

import logging

import ida_hexrays
import ida_name
import idaapi
import pytest


class _RecordHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.INFO)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.mark.ida_required
class TestFunctionInfoLogging:
    binary_name = "libobfuscated.dll"

    def test_one_decompilation_emits_one_start_and_one_terminal_story(
        self,
        d810_state,
        configure_hexrays,
        ida_database,
        setup_libobfuscated_funcs,
    ) -> None:
        del configure_hexrays, ida_database, setup_libobfuscated_funcs
        assert idaapi.init_hexrays_plugin()
        function_ea = ida_name.get_name_ea(idaapi.BADADDR, "test_cst_simplification")
        if function_ea == idaapi.BADADDR:
            pytest.skip("test_cst_simplification is absent from this fixture")

        with d810_state() as state:
            project_index = next(
                index
                for index, project in enumerate(state.project_manager.projects())
                if project.path.name == "default_instruction_only_config_v2_canary.json"
            )
            state.load_project(project_index)
            state.start_d810()
            handler = _RecordHandler()
            loggers = tuple(
                logging.getLogger(name)
                for name in (
                    "d810",
                    "d810.passes.runtime",
                    "d810.passes.facts.runtime",
                    "d810.unflat",
                    "d810.unflat.cleanup_family",
                    "d810.hexrays.mutation.byte_emit_tail_isolation_runtime",
                )
            )
            for target_logger in loggers:
                target_logger.addHandler(handler)
            try:
                cfunc = ida_hexrays.decompile_func(
                    idaapi.get_func(function_ea),
                    None,
                    idaapi.DECOMP_NO_CACHE,
                )
            finally:
                for target_logger in loggers:
                    target_logger.removeHandler(handler)
            assert cfunc is not None

        messages = [record.getMessage() for record in handler.records]
        starts = [
            message for message in messages if message.startswith("[D810] Decompiling ")
        ]
        terminals = [
            message
            for message in messages
            if message.startswith("[D810] ") and " -> " in message
        ]
        assert len(starts) == 1, messages
        assert len(terminals) == 1, messages
        assert "evaluated=" in terminals[0]
        assert "applicable=" in terminals[0]
        assert "applied=" in terminals[0]
        assert " -> changed;" in terminals[0]
        assert "applied=0" not in terminals[0]
        assert not any("FACT_VIEW" in message for message in messages)
        assert not any("FACT_LIFECYCLE_CAPTURE" in message for message in messages)
        assert not any("derived fresh hints" in message for message in messages)
        assert not any("unflat optimize:" in message for message in messages)
        assert not any(
            "SimpleFlatteningCleanupMetadata(" in message for message in messages
        )
        assert not any(
            record.levelno >= logging.WARNING
            and "native mutation abstained" in record.getMessage()
            for record in handler.records
        )

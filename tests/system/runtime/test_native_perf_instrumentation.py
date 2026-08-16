"""Real-IDB coverage for the opt-in Cython performance counters."""

from __future__ import annotations

import os
import platform
import json
import importlib

import pytest

from d810.core import MOP_TO_AST_CACHE, native_perf
from d810.core.settings import reset_settings
from d810.hexrays.ir.minsn_utils import minsn_to_ast

try:
    c_pattern_match = importlib.import_module(
        "d810.speedups.optimizers.c_pattern_match"
    )
    c_ast = importlib.import_module("d810.speedups.expr.c_ast")
    _CYTHON_EXTENSION_IMPORT_ERROR = None
except ImportError as exc:
    # Keep Python-mode tests runnable when optional extensions are absent, but
    # compiled-focused tests below fail closed instead of skipping the module.
    c_pattern_match = None
    c_ast = None
    _CYTHON_EXTENSION_IMPORT_ERROR = exc


def _require_extension_modules_present() -> None:
    if c_pattern_match is None or c_ast is None:
        pytest.fail(
            "compiled Cython extensions are required; import failed: "
            + repr(_CYTHON_EXTENSION_IMPORT_ERROR)
        )
    assert c_pattern_match.__file__.endswith((".so", ".pyd", ".dylib"))
    assert c_ast.__file__.endswith((".so", ".pyd", ".dylib"))


def _require_compiled_extensions() -> None:
    _require_extension_modules_present()
    from d810.core.cymode import CythonMode

    if not CythonMode().is_enabled():
        pytest.fail("CythonMode is disabled in the compiled-focused test")


def _cython_disabled_by_environment() -> bool:
    return os.environ.get("D810_NO_CYTHON", "").lower() in {
        "1",
        "true",
        "yes",
    }


def _activate_cython_providers() -> None:
    """Re-select the complete compiled composition through production dispatchers."""
    _require_compiled_extensions()
    from d810.manager.manager import D810Manager

    # Registry-clearing unit tests can run before this module in a combined
    # invocation. Reuse the manager's selected-dispatcher composition so the
    # Python-boundary ast_builder provider is restored alongside Cython ones.
    D810Manager._ensure_native_perf_providers()


class TestNativePerfInstrumentation:
    binary_name = os.environ.get(
        "D810_TEST_BINARY",
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll",
    )

    @pytest.mark.ida_required
    @pytest.mark.skipif(
        _cython_disabled_by_environment(), reason="compiled mode is disabled"
    )
    def test_compiled_pattern_match_counters_cover_real_ast_work(self, real_asts):
        """Fingerprint, lookup, match, binding, and materialization counters move."""
        _require_extension_modules_present()
        print(
            "D810_CYTHON_EXTENSION_PATHS="
            + json.dumps(
                {
                    "c_pattern_match": c_pattern_match.__file__,
                    "c_ast": c_ast.__file__,
                },
                sort_keys=True,
            )
        )
        _activate_cython_providers()
        native_perf.configure(True)
        native_perf.reset()

        pattern = next((ast for ast, _ins in real_asts if ast.is_node()), None)
        if pattern is None:
            pytest.skip("no real AST node available for the compiled matcher")

        storage = c_pattern_match.COpcodeIndexedStorage()
        storage.add_pattern(pattern, object())
        candidates = storage.get_candidates(pattern)
        assert candidates
        leaf = next((ast for ast, _ins in real_asts if ast.is_leaf()), None)
        if leaf is not None:
            storage.get_candidates(leaf)

        bindings = c_pattern_match.CMatchBindings()
        assert c_pattern_match.match_pattern_nomut(pattern, pattern, bindings)
        bindings.to_dict()
        bindings.get_leafs_by_name()

        counters = native_perf.snapshot()["providers"]["pattern_match"]["counters"]
        assert counters["fingerprint_calls"] >= 2
        assert counters["bucket_lookups"] >= 1
        assert counters["bucket_hits"] >= 1
        assert counters["bucket_hits"] + counters["bucket_misses"] == counters[
            "bucket_lookups"
        ]
        assert counters["entries_scanned"] >= 1
        assert counters["entries_accepted"] >= 1
        assert counters["entries_accepted"] <= counters["entries_scanned"]
        assert counters["match_calls"] == 1
        assert counters["match_nodes"] >= 1
        assert counters["binding_additions"] >= 1
        assert counters["to_dict_calls"] == 1
        assert counters["result_list_materializations"] >= 1
        assert counters["clock_reads"] > 0
        print(
            "D810_NATIVE_PERF_PATTERN_COUNTERS="
            + json.dumps(counters, sort_keys=True)
        )

        # Disabled instrumentation must not read the native steady clock and
        # must not leave stale counter state behind after a reset.
        native_perf.configure(False)
        native_perf.reset()
        storage.get_candidates(pattern)
        c_pattern_match.match_pattern_nomut(pattern, pattern)
        disabled = native_perf.snapshot()["providers"]["pattern_match"][
            "counters"
        ]
        assert all(value == 0 for value in disabled.values())

    @pytest.mark.ida_required
    @pytest.mark.skipif(
        _cython_disabled_by_environment(), reason="compiled mode is disabled"
    )
    def test_compiled_ast_counters_cover_builder_and_global_cache(self, real_asts):
        """The actual minsn->AST route records keys, local/global caches, and proxies."""
        _require_compiled_extensions()
        _activate_cython_providers()
        native_perf.configure(True)
        native_perf.reset()

        # The shared fixture retains ASTs but its source mba may have already
        # been released. Generate a fresh mba here so both calls exercise the
        # live ``mop_utils.mop_to_ast`` path against valid native operands.
        from tests.system.runtime.conftest import (
            gen_microcode_at_maturity,
            get_func_ea,
        )
        import ida_hexrays
        import idaapi

        instruction = None
        for function_name in ("test_xor", "test_chained_add", "test_mba_guessing"):
            func_ea = get_func_ea(function_name)
            if func_ea == idaapi.BADADDR:
                continue
            mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_PREOPTIMIZED)
            if mba is None:
                continue
            for block_index in range(mba.qty):
                block = mba.get_mblock(block_index)
                if block is None:
                    continue
                candidate = block.head
                while candidate is not None:
                    if minsn_to_ast(candidate) is not None:
                        instruction = candidate
                        break
                    candidate = candidate.next
                if instruction is not None:
                    break
            if instruction is not None:
                break
        if instruction is None:
            pytest.skip("no live microcode instruction available for AST construction")

        # The first conversion above may have populated the global cache while
        # searching. Reset and convert the same native instruction twice for a
        # deterministic miss-then-hit assertion.
        MOP_TO_AST_CACHE.clear()
        native_perf.reset()
        first = minsn_to_ast(instruction)
        second = minsn_to_ast(instruction)
        if first is None or second is None:
            pytest.skip("selected instruction is not AST-buildable")

        providers = native_perf.snapshot()["providers"]
        builder = providers["ast_builder"]["counters"]
        ast_types = providers["ast_types"]["counters"]
        assert builder["builder_calls"] >= 1
        assert builder["local_cache_lookups"] >= 1
        assert builder["local_cache_misses"] >= 1
        assert builder["global_cache_lookups"] >= 2
        assert builder["global_cache_misses"] >= 1
        assert builder["global_cache_hits"] >= 1
        assert builder["global_cache_lookups"] == (
            builder["global_cache_hits"] + builder["global_cache_misses"]
        )
        assert builder["owner_scope_key_calls"] == builder["global_cache_lookups"]
        assert builder["ast_constructions"] >= 1
        assert builder["proxy_returns"] >= 2
        assert ast_types["structural_key_calls"] >= 1
        assert ast_types["structural_key_time_ns"] > 0
        assert ast_types["ast_proxy_creations"] >= 2
        print(
            "D810_NATIVE_PERF_AST_BUILDER_COUNTERS="
            + json.dumps(builder, sort_keys=True)
        )
        print(
            "D810_NATIVE_PERF_AST_TYPE_COUNTERS="
            + json.dumps(ast_types, sort_keys=True)
        )

        native_perf.configure(False)
        native_perf.reset()
        _ = minsn_to_ast(instruction)
        disabled = native_perf.snapshot()["providers"]
        assert all(
            value == 0
            for provider in ("ast_builder", "ast_types")
            for value in disabled[provider]["counters"].values()
        )

    @pytest.mark.ida_required
    @pytest.mark.skipif(
        _cython_disabled_by_environment(), reason="compiled mode is disabled"
    )
    def test_trace_profile_records_compiled_pattern_functions(self, real_asts):
        """Trace mode is attribution-only and must expose compiled Cython frames."""
        _require_compiled_extensions()
        if os.environ.get("D810_CYTHON_PROFILE") != "1":
            pytest.skip("D810_CYTHON_PROFILE=1 is required for trace attribution")

        import cProfile
        import pstats
        from pathlib import Path

        _activate_cython_providers()
        pattern = next((ast for ast, _ins in real_asts if ast.is_node()), None)
        if pattern is None:
            pytest.skip("no real AST node available for Cython trace profiling")

        profiler = cProfile.Profile()
        profiler.enable()
        try:
            storage = c_pattern_match.COpcodeIndexedStorage()
            storage.add_pattern(pattern, object())
            storage.get_candidates(pattern)
            c_pattern_match.match_pattern_nomut(pattern, pattern)
        finally:
            profiler.disable()

        artifact = Path(os.environ.get("D810_CYTHON_PROFILE_ARTIFACT", ".tmp"))
        artifact.mkdir(parents=True, exist_ok=True)
        profile_path = artifact / "native_perf_cython_trace.prof"
        profiler.dump_stats(str(profile_path))
        stats = pstats.Stats(profiler)
        compiled = sorted(
            f"{filename}:{name}"
            for filename, _line, name in stats.stats
            if "c_pattern_match.pyx" in filename
        )
        assert compiled, "cProfile did not record any c_pattern_match.pyx frames"
        assert any(
            name.endswith((":__cinit__", ":add_pattern", ":get_candidates", ":match_pattern_nomut"))
            for name in compiled
        )
        print("D810_CYTHON_PROFILE_ARTIFACT=" + str(profile_path))
        print("D810_CYTHON_PROFILE_FUNCTIONS=" + json.dumps(compiled))

    @pytest.mark.ida_required
    @pytest.mark.skipif(
        _cython_disabled_by_environment(), reason="compiled mode is disabled"
    )
    def test_manager_provider_discovery_keeps_selected_cython_backends(
        self, monkeypatch
    ):
        """Manager discovery must select dispatchers, not Python fallback modules."""
        import importlib

        from d810.manager.manager import D810Manager

        python_pattern = importlib.import_module(
            "d810.optimizers.microcode.instructions.pattern_matching.pattern_speedups"
        )
        fallback_registration = []
        monkeypatch.setattr(
            python_pattern,
            "register_native_perf_provider",
            lambda: fallback_registration.append(True),
        )
        native_perf.clear_providers_for_tests()
        native_perf.configure(True)
        D810Manager._ensure_native_perf_providers()

        providers = native_perf.snapshot()["providers"]
        assert fallback_registration == []
        assert providers["pattern_match"]["backend"] == "cython"
        assert providers["ast_types"]["backend"] == "cython"
        assert providers["ast_builder"]["backend"] == "python"
        assert providers["ast_builder"]["counter_domain"] == "python-boundary"
        native_perf.configure(False)

    @pytest.mark.ida_required
    @pytest.mark.skipif(
        _cython_disabled_by_environment(), reason="compiled mode is disabled"
    )
    def test_cython_provider_activation_restores_complete_selected_composition(self):
        """Test helpers restore every selected provider after registry clearing."""
        _require_compiled_extensions()
        native_perf.clear_providers_for_tests()
        _activate_cython_providers()

        providers = native_perf.snapshot()["providers"]
        assert {
            "ast_builder",
            "ast_types",
            "pattern_match",
        }.issubset(providers)
        native_perf.configure(False)

    @pytest.mark.ida_required
    def test_manager_provider_discovery_failure_marks_receipt_incomplete(
        self, monkeypatch
    ):
        """Provider import failures are explicit receipt errors, not backend none."""
        from d810.manager import manager as manager_module
        from d810.manager.manager import D810Manager

        native_perf.clear_providers_for_tests()
        native_perf.configure(True)

        def fail_import(_module_name):
            raise ImportError("provider import failed")

        monkeypatch.setattr(manager_module.importlib, "import_module", fail_import)
        D810Manager._ensure_native_perf_providers()

        report = native_perf.snapshot()
        assert report["complete"] is False
        assert "required" in report["provider_errors"]
        assert "missing required providers" in report["provider_errors"]["required"]
        assert any(
            "load" in error and "ImportError" in error
            for error in report["provider_errors"].values()
        )
        native_perf.configure(False)

    @pytest.mark.ida_required
    @pytest.mark.skipif(
        _cython_disabled_by_environment(), reason="compiled mode is disabled"
    )
    def test_nested_lifecycle_emits_one_real_receipt(
        self, real_asts, monkeypatch, caplog
    ):
        """Manager callbacks retain child counters and flag wrong-order close."""
        import types

        from d810.core.decompilation_session import DecompilationSessionEvent
        from d810.manager import manager as manager_module
        from d810.manager.manager import D810Manager

        _require_compiled_extensions()

        # Exercise the manager-owned lifecycle callbacks without starting all
        # of the optimizer/hook machinery. Every callback dependency that the
        # lifecycle methods touch is a no-op test double; provider selection,
        # begin/end, receipt logging, and event metadata remain production code.
        manager = object.__new__(D810Manager)
        manager.start_profiling = lambda _event: None
        manager.stop_profiling = lambda _event: None
        manager._start_timer = lambda: None
        manager._stop_timer = lambda: None
        manager.stats = types.SimpleNamespace(
            reset=lambda: None,
            report=lambda: None,
        )
        manager.instruction_optimizer = types.SimpleNamespace(
            reset_cycle_detection=lambda: None,
            reset_run_later_state=lambda: None,
        )
        manager.block_optimizer = types.SimpleNamespace(
            reset_pass_counter=lambda: None,
            reset_pipeline_tracker=lambda: None,
            reset_perf_counters=lambda: None,
            report_perf_counters=lambda: None,
        )
        monkeypatch.setattr(
            manager_module,
            "Z3MopProver",
            lambda: types.SimpleNamespace(clear_caches=lambda: None),
        )
        monkeypatch.setenv("D810_NATIVE_PERF", "1")
        reset_settings()
        native_perf.clear_providers_for_tests()

        outer = DecompilationSessionEvent(
            function_ea=0x401000,
            database_identity="idb",
            top_level_epoch=1,
            session_id="outer",
        )
        child = DecompilationSessionEvent(
            function_ea=0x402000,
            database_identity="idb",
            top_level_epoch=2,
            session_id="child",
        )
        manager._on_session_started(outer)
        manager._on_session_started(child)

        pattern = next((ast for ast, _ins in real_asts if ast.is_node()), None)
        if pattern is None:
            pytest.skip("no real AST node available for nested matcher work")
        storage = c_pattern_match.COpcodeIndexedStorage()
        storage.add_pattern(pattern, object())
        assert storage.get_candidates(pattern)
        assert c_pattern_match.match_pattern_nomut(pattern, pattern)

        with caplog.at_level("INFO", logger="d810"):
            # Closing the outer owner first must not pop the child or emit a
            # receipt. The mismatch is sticky and makes the eventual receipt
            # incomplete, while the child and outer owners remain closable.
            manager._on_session_finished(outer)
            assert native_perf.snapshot()["lifecycle_depth"] == 2
            manager._on_session_finished(child)
            child_receipts = [
                record.getMessage()
                for record in caplog.records
                if record.getMessage().startswith(native_perf.RECEIPT_PREFIX)
            ]
            manager._on_session_finished(outer)
        receipts = [
            record.getMessage()
            for record in caplog.records
            if record.getMessage().startswith(native_perf.RECEIPT_PREFIX)
        ]
        assert child_receipts == []
        assert len(receipts) == 1
        payload = json.loads(receipts[0].split("=", 1)[1])
        assert payload["session"] == {
            "database_identity": "idb",
            "function_ea": 0x401000,
            "session_id": "outer",
            "top_level_epoch": 1,
        }
        counters = payload["providers"]["pattern_match"]["counters"]
        assert payload["complete"] is False
        assert payload["lifecycle_errors"]
        assert counters["match_calls"] >= 1
        assert counters["bucket_lookups"] >= 1
        assert payload["provider_identities"]["pattern_match"]["backend"] == "cython"
        print(receipts[0])
        native_perf.configure(False)

    @pytest.mark.ida_required
    def test_manager_finish_closes_native_session_after_reporting_failures(
        self, monkeypatch
    ):
        """Finalization closes once, preserves failures, and starts fresh next time."""
        import types

        from d810.core.decompilation_session import DecompilationSessionEvent
        from d810.manager import manager as manager_module
        from d810.manager.manager import D810Manager

        manager = object.__new__(D810Manager)
        manager.start_profiling = lambda _event: None

        def fail_stop_profiling(_event):
            raise RuntimeError("stop profiling failed")

        manager.stop_profiling = fail_stop_profiling
        manager._start_timer = lambda: None
        manager._stop_timer = lambda: None
        manager.stats = types.SimpleNamespace(
            reset=lambda: None,
            report=lambda: None,
        )
        manager.instruction_optimizer = types.SimpleNamespace(
            reset_cycle_detection=lambda: None,
            reset_run_later_state=lambda: None,
        )
        manager.block_optimizer = types.SimpleNamespace(
            reset_pass_counter=lambda: None,
            reset_pipeline_tracker=lambda: None,
            reset_perf_counters=lambda: None,
            report_perf_counters=lambda: None,
        )
        monkeypatch.setattr(
            manager_module,
            "Z3MopProver",
            lambda: types.SimpleNamespace(clear_caches=lambda: None),
        )
        monkeypatch.setenv("D810_NATIVE_PERF", "1")
        reset_settings()
        native_perf.clear_providers_for_tests()
        finish_calls = []
        original_end_session = native_perf.end_session

        def spy_end_session(session_id):
            finish_calls.append(str(session_id))
            return original_end_session(session_id)

        monkeypatch.setattr(native_perf, "end_session", spy_end_session)
        outer = DecompilationSessionEvent(
            function_ea=0x401000,
            database_identity="idb",
            top_level_epoch=1,
            session_id="outer",
        )
        next_event = DecompilationSessionEvent(
            function_ea=0x402000,
            database_identity="idb",
            top_level_epoch=2,
            session_id="next",
        )
        manager._on_session_started(outer)

        with pytest.raises(RuntimeError, match="stop profiling failed"):
            manager._on_session_finished(outer)
        assert finish_calls == ["outer"]
        assert native_perf.snapshot()["lifecycle_depth"] == 0

        manager.stop_profiling = lambda _event: None
        manager._on_session_started(next_event)
        fresh = native_perf.snapshot()
        assert fresh["lifecycle_depth"] == 1
        assert fresh["session"] == {
            "database_identity": "idb",
            "function_ea": 0x402000,
            "session_id": "next",
            "top_level_epoch": 2,
        }
        assert fresh["session_generation"] == 2

        def fail_receipt_logging(message, *args, **kwargs):
            if message == "%s":
                raise RuntimeError("receipt logging failed")
            return None

        monkeypatch.setattr(manager_module.logger, "info", fail_receipt_logging)
        with pytest.raises(RuntimeError, match="receipt logging failed"):
            manager._on_session_finished(next_event)
        assert finish_calls == ["outer", "next"]
        assert native_perf.snapshot()["lifecycle_depth"] == 0
        native_perf.configure(False)

    @pytest.mark.ida_required
    def test_manager_session_uses_runtime_native_perf_setting(
        self, monkeypatch, caplog
    ):
        """A configured runtime setting enables receipts without an env var."""
        import types

        from d810.core.decompilation_session import DecompilationSessionEvent
        from d810.core.settings import configure_settings, reset_settings
        from d810.manager import manager as manager_module
        from d810.manager.manager import D810Manager

        monkeypatch.delenv("D810_NATIVE_PERF", raising=False)
        reset_settings()
        configure_settings(native_perf=True)
        native_perf.clear_providers_for_tests()
        monkeypatch.setattr(
            D810Manager,
            "_ensure_native_perf_providers",
            staticmethod(lambda: None),
        )

        manager = object.__new__(D810Manager)
        manager.start_profiling = lambda _event: None
        manager.stop_profiling = lambda _event: None
        manager._start_timer = lambda: None
        manager._stop_timer = lambda: None
        manager.stats = types.SimpleNamespace(
            reset=lambda: None,
            report=lambda: None,
        )
        manager.instruction_optimizer = types.SimpleNamespace(
            reset_cycle_detection=lambda: None,
            reset_run_later_state=lambda: None,
        )
        manager.block_optimizer = types.SimpleNamespace(
            reset_pass_counter=lambda: None,
            reset_pipeline_tracker=lambda: None,
            reset_perf_counters=lambda: None,
            report_perf_counters=lambda: None,
        )
        monkeypatch.setattr(
            manager_module,
            "Z3MopProver",
            lambda: types.SimpleNamespace(clear_caches=lambda: None),
        )

        event = DecompilationSessionEvent(
            function_ea=0x401000,
            database_identity="idb",
            top_level_epoch=1,
            session_id="runtime-setting",
        )
        try:
            manager._on_session_started(event)
            assert native_perf.enabled() is True

            with caplog.at_level("INFO", logger="d810"):
                manager._on_session_finished(event)

            receipts = [
                record.getMessage()
                for record in caplog.records
                if record.getMessage().startswith(native_perf.RECEIPT_PREFIX)
            ]
            assert len(receipts) == 1
            payload = json.loads(receipts[0].split("=", 1)[1])
            assert payload["session"]["session_id"] == "runtime-setting"
        finally:
            native_perf.configure(False)
            native_perf.clear_providers_for_tests()
            reset_settings()

    @pytest.mark.ida_required
    @pytest.mark.skipif(
        not _cython_disabled_by_environment(), reason="Python mode is disabled"
    )
    def test_python_mode_selects_python_providers_with_extensions_present(self):
        """D810_NO_CYTHON selects Python dispatchers even when .so files exist."""
        from d810.core.cymode import CythonMode
        from d810.hexrays.expr import ast as ast_dispatcher
        from d810.manager.manager import D810Manager
        from d810.optimizers.microcode.instructions.pattern_matching import (
            engine as pattern_dispatcher,
        )

        _require_extension_modules_present()
        assert not CythonMode().is_enabled()
        print(
            "D810_CYTHON_EXTENSION_PATHS="
            + json.dumps(
                {
                    "c_pattern_match": c_pattern_match.__file__,
                    "c_ast": c_ast.__file__,
                },
                sort_keys=True,
            )
        )
        native_perf.clear_providers_for_tests()
        native_perf.configure(True)
        D810Manager._ensure_native_perf_providers()

        providers = native_perf.snapshot()["providers"]
        assert pattern_dispatcher.get_engine_info()["backend"] == "python"
        assert ast_dispatcher._USING_CYTHON is False
        assert providers["pattern_match"]["backend"] == "python"
        assert providers["pattern_match"]["counter_domain"] == "python"
        assert providers["ast_types"]["backend"] == "python"
        assert providers["ast_types"]["counter_domain"] == "python"
        native_perf.configure(False)

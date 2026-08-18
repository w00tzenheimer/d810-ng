from __future__ import annotations

import os
import platform
from pathlib import Path

import idaapi
import pytest

from d810.testing.runner import run_deobfuscation_test
from tests.system.cases.libobfuscated_comprehensive import CONSTANT_FOLDING_CASES


_CASE = next(
    case
    for case in CONSTANT_FOLDING_CASES
    if case.function == "AntiDebug_ExceptionFilter"
)


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestAntiDebugProfileDiagnostic:
    binary_name = (
        "libobfuscated.dylib"
        if platform.system() == "Darwin"
        else "libobfuscated.dll"
    )

    @pytest.mark.profile
    def test_profile_antidebug_exception_filter(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ) -> None:
        output_dir = Path(".tmp/profiles/antidebug-exception-filter")
        output_dir.mkdir(parents=True, exist_ok=True)
        mode = os.environ.get("D810_ANTIDEBUG_PROFILE_MODE", "pyinstrument")
        assert mode in {"pyinstrument", "cprofile"}

        def enable_profile(state) -> None:
            controller = state.manager.profiling
            controller.log_dir = output_dir
            if mode == "pyinstrument":
                assert controller.profiler is not None
                controller.cprofiler = None
            else:
                assert controller.cprofiler is not None
                controller.profiler = None
            state.manager.enable_profiling()

        def capture_profile(state) -> None:
            if mode != "pyinstrument":
                return
            profiler = state.manager.profiling.profiler
            (output_dir / "d810_profile.txt").write_text(
                profiler.output_text(unicode=False, color=False, show_all=True),
                encoding="utf-8",
            )

        run_deobfuscation_test(
            case=_CASE,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
            prepare_runtime_state=enable_profile,
            capture_runtime_state=capture_profile,
        )

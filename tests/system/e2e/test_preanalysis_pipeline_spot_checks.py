'E2E per-function preanalysis pipeline spot checks.\n\nLayer 2: For known-flattened functions, verify that the preanalysis pipeline\nproduced correct analysis AND the inference layer acted on it:\n- Classification is a flattening type\n- Confidence >= 0.7\n- "unflattening" inference is recommended\n- Session summary records the inference\n- Consumer outcomes are recorded\n\nUses the same IDB/fixture chain as the DSL test suite.\n'

import platform

import pytest

import idaapi
import idc

from d810.testing.runner import _resolve_test_project_index


def _get_default_binary() -> str:
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


def _resolve_ea(name: str) -> int:
    """Resolve a function name to EA, trying with and without underscore prefix."""
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)
    return ea


# Known-flattened functions from the libobfuscated.dll test binary.
_FLATTENING_TYPES = {"flattening", "ollvm_flat"}

KNOWN_FLATTENED = [
    "test_function_ollvm_fla_bcf_sub",
    "while_switch_flattened",
]


@pytest.fixture(scope="class")
def known_flattened_preanalysis():
    """Analyze the asserted functions instead of depending on test order."""
    from d810.manager import D810State
    from d810.passes.store import PreanalysisStore

    state = D810State()
    was_loaded = state.is_loaded()
    if not was_loaded:
        state.load(gui=False)
    project_index = _resolve_test_project_index(
        state, "default_unflattening_ollvm.json"
    )
    state.load_project(project_index)
    was_started = state.manager.started
    if not was_started:
        state.start_d810()

    try:
        resolved = {name: _resolve_ea(name) for name in KNOWN_FLATTENED}
        for name, func_ea in resolved.items():
            if func_ea == idaapi.BADADDR:
                pytest.fail(f"Known flattened fixture function {name!r} is absent")
            cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert cfunc is not None, f"Failed to decompile {name} for preanalysis"

        db_path = state.manager.analysis_db
        assert db_path is not None, "Preanalysis runtime did not expose a database"
        with PreanalysisStore(db_path) as store:
            records = {
                name: {
                    "ea": func_ea,
                    "hints": store.load_hints(func_ea=func_ea),
                    "summary": store.load_session_summary(func_ea),
                    "outcomes": store.load_consumer_outcomes(func_ea),
                }
                for name, func_ea in resolved.items()
            }
        yield records
    finally:
        if not was_started:
            state.stop_d810()
        if not was_loaded:
            state.unload(gui=False)


@pytest.mark.e2e
@pytest.mark.usefixtures(
    "ida_database", "configure_hexrays", "setup_libobfuscated_funcs"
)
class TestAnalysisPipelineSpotChecks:
    """Per-function pipeline assertions for known cases."""

    binary_name = _get_default_binary()

    @pytest.mark.parametrize("func_name", KNOWN_FLATTENED)
    def test_flattened_function_classified_correctly(
        self,
        func_name,
        known_flattened_preanalysis,
    ):
        """Known-flattened functions should be classified as flattening."""
        record = known_flattened_preanalysis[func_name]
        hints = record["hints"]
        assert hints is not None, (
            f"{func_name} (0x{record['ea']:x}): no hints in preanalysis DB"
        )
        assert hints.obfuscation_type in _FLATTENING_TYPES, (
            f"{func_name}: expected one of {_FLATTENING_TYPES}, "
            f"got '{hints.obfuscation_type}'"
        )

    @pytest.mark.parametrize("func_name", KNOWN_FLATTENED)
    def test_flattened_function_high_confidence(
        self,
        func_name,
        known_flattened_preanalysis,
    ):
        """Known-flattened functions should have confidence >= 0.7."""
        hints = known_flattened_preanalysis[func_name]["hints"]
        assert hints is not None
        assert hints.confidence >= 0.7, (
            f"{func_name}: confidence {hints.confidence:.2f} < 0.7"
        )

    @pytest.mark.parametrize("func_name", KNOWN_FLATTENED)
    def test_flattened_function_recommends_unflattening(
        self,
        func_name,
        known_flattened_preanalysis,
    ):
        """Known-flattened functions should recommend 'unflattening' inference."""
        hints = known_flattened_preanalysis[func_name]["hints"]
        assert hints is not None
        assert "unflattening" in hints.recommended_inferences, (
            f"{func_name}: 'unflattening' not in {hints.recommended_inferences}"
        )

    @pytest.mark.parametrize("func_name", KNOWN_FLATTENED)
    def test_flattened_function_session_summary_has_inference(
        self,
        func_name,
        known_flattened_preanalysis,
    ):
        """Session summary for flattened functions should list unflattening."""
        record = known_flattened_preanalysis[func_name]
        summary = record["summary"]
        assert summary is not None, (
            f"{func_name} (0x{record['ea']:x}): no session summary"
        )
        assert "unflattening" in summary["inferences"], (
            f"{func_name}: 'unflattening' not in session inferences: "
            f"{summary['inferences']}"
        )

    @pytest.mark.parametrize("func_name", KNOWN_FLATTENED)
    def test_flattened_function_consumer_outcome(
        self,
        func_name,
        known_flattened_preanalysis,
    ):
        """Flattened functions should have consumer outcomes recorded."""
        record = known_flattened_preanalysis[func_name]
        outcomes = record["outcomes"]
        assert len(outcomes) > 0, (
            f"{func_name} (0x{record['ea']:x}): no consumer outcomes recorded"
        )

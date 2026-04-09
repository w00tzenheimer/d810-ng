"""E2E per-function recon pipeline spot checks.

Layer 2: For known-flattened functions, verify that the recon pipeline
produced correct analysis AND the inference layer acted on it:
- Classification is a flattening type
- Confidence >= 0.7
- "unflattening" inference is recommended
- Session summary records the inference
- Consumer outcomes are recorded

Uses the same IDB/fixture chain as the DSL test suite.
"""
import platform

import pytest

import idaapi
import idc


def _get_default_binary() -> str:
    return "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"


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


@pytest.mark.e2e
@pytest.mark.usefixtures("ida_database", "configure_hexrays", "setup_libobfuscated_funcs")
class TestReconPipelineSpotChecks:
    """Per-function pipeline assertions for known cases."""

    binary_name = _get_default_binary()

    @pytest.mark.parametrize("func_name", KNOWN_FLATTENED)
    def test_flattened_function_classified_correctly(
        self, func_name, recon_store_session,
    ):
        """Known-flattened functions should be classified as flattening."""
        if recon_store_session is None:
            pytest.skip("Recon pipeline disabled")
        func_ea = _resolve_ea(func_name)
        if func_ea == idaapi.BADADDR:
            pytest.skip(f"Function {func_name} not found in IDB")

        hints = recon_store_session.load_hints(func_ea=func_ea)
        assert hints is not None, (
            f"{func_name} (0x{func_ea:x}): no hints in recon DB"
        )
        assert hints.obfuscation_type in _FLATTENING_TYPES, (
            f"{func_name}: expected one of {_FLATTENING_TYPES}, "
            f"got '{hints.obfuscation_type}'"
        )

    @pytest.mark.parametrize("func_name", KNOWN_FLATTENED)
    def test_flattened_function_high_confidence(
        self, func_name, recon_store_session,
    ):
        """Known-flattened functions should have confidence >= 0.7."""
        if recon_store_session is None:
            pytest.skip("Recon pipeline disabled")
        func_ea = _resolve_ea(func_name)
        if func_ea == idaapi.BADADDR:
            pytest.skip(f"Function {func_name} not found in IDB")

        hints = recon_store_session.load_hints(func_ea=func_ea)
        assert hints is not None
        assert hints.confidence >= 0.7, (
            f"{func_name}: confidence {hints.confidence:.2f} < 0.7"
        )

    @pytest.mark.parametrize("func_name", KNOWN_FLATTENED)
    def test_flattened_function_recommends_unflattening(
        self, func_name, recon_store_session,
    ):
        """Known-flattened functions should recommend 'unflattening' inference."""
        if recon_store_session is None:
            pytest.skip("Recon pipeline disabled")
        func_ea = _resolve_ea(func_name)
        if func_ea == idaapi.BADADDR:
            pytest.skip(f"Function {func_name} not found in IDB")

        hints = recon_store_session.load_hints(func_ea=func_ea)
        assert hints is not None
        assert "unflattening" in hints.recommended_inferences, (
            f"{func_name}: 'unflattening' not in {hints.recommended_inferences}"
        )

    @pytest.mark.parametrize("func_name", KNOWN_FLATTENED)
    def test_flattened_function_session_summary_has_inference(
        self, func_name, recon_store_session,
    ):
        """Session summary for flattened functions should list unflattening."""
        if recon_store_session is None:
            pytest.skip("Recon pipeline disabled")
        func_ea = _resolve_ea(func_name)
        if func_ea == idaapi.BADADDR:
            pytest.skip(f"Function {func_name} not found in IDB")

        summary = recon_store_session.load_session_summary(func_ea)
        assert summary is not None, (
            f"{func_name} (0x{func_ea:x}): no session summary"
        )
        assert "unflattening" in summary["inferences"], (
            f"{func_name}: 'unflattening' not in session inferences: "
            f"{summary['inferences']}"
        )

    @pytest.mark.parametrize("func_name", KNOWN_FLATTENED)
    def test_flattened_function_consumer_outcome(
        self, func_name, recon_store_session,
    ):
        """Flattened functions should have consumer outcomes recorded."""
        if recon_store_session is None:
            pytest.skip("Recon pipeline disabled")
        func_ea = _resolve_ea(func_name)
        if func_ea == idaapi.BADADDR:
            pytest.skip(f"Function {func_name} not found in IDB")

        outcomes = recon_store_session.load_consumer_outcomes(func_ea)
        assert len(outcomes) > 0, (
            f"{func_name} (0x{func_ea:x}): no consumer outcomes recorded"
        )

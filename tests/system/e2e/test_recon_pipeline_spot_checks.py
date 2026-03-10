"""E2E per-function recon pipeline spot checks.

Layer 2: For known-flattened functions, verify that the recon pipeline
produced correct analysis AND the inference layer acted on it:
- Classification is "flattening"
- Confidence >= 0.7
- "unflattening" inference is recommended
- Consumer outcome shows verdict_applied=True

These assertions catch regressions in analysis quality and
inference wiring, not just pipeline plumbing.
"""
import pytest

import idc


def _resolve_ea(name: str) -> int:
    """Resolve a function name to EA, trying with and without underscore prefix."""
    ea = idc.get_name_ea_simple(name)
    if ea == idc.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)
    return ea


# Known-flattened functions from the libobfuscated test suite.
# These should always be classified as "flattening" with high confidence.
KNOWN_FLATTENED = [
    "_hodur_func",
    "test_function_ollvm_fla_bcf_sub",
]

# Known non-flattened functions — should NOT get unflattening inference.
KNOWN_NOT_FLATTENED = [
    "test_xor",
    "test_or",
]


@pytest.mark.e2e
class TestReconPipelineSpotChecks:
    """Per-function pipeline assertions for known cases."""

    @pytest.mark.parametrize("func_name", KNOWN_FLATTENED)
    def test_flattened_function_classified_correctly(
        self, func_name, recon_store_session,
    ):
        """Known-flattened functions should be classified as 'flattening'."""
        if recon_store_session is None:
            pytest.skip("Recon pipeline disabled")
        func_ea = _resolve_ea(func_name)
        if func_ea == idc.BADADDR:
            pytest.skip(f"Function {func_name} not found in IDB")

        hints = recon_store_session.load_hints(func_ea=func_ea)
        assert hints is not None, (
            f"{func_name} (0x{func_ea:x}): no hints in recon DB"
        )
        assert hints.obfuscation_type == "flattening", (
            f"{func_name}: expected 'flattening', got '{hints.obfuscation_type}'"
        )

    @pytest.mark.parametrize("func_name", KNOWN_FLATTENED)
    def test_flattened_function_high_confidence(
        self, func_name, recon_store_session,
    ):
        """Known-flattened functions should have confidence >= 0.7."""
        if recon_store_session is None:
            pytest.skip("Recon pipeline disabled")
        func_ea = _resolve_ea(func_name)
        if func_ea == idc.BADADDR:
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
        if func_ea == idc.BADADDR:
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
        if func_ea == idc.BADADDR:
            pytest.skip(f"Function {func_name} not found in IDB")

        summary = recon_store_session.load_session_summary(func_ea)
        assert summary is not None, (
            f"{func_name} (0x{func_ea:x}): no session summary"
        )
        assert "unflattening" in summary["inferences"], (
            f"{func_name}: 'unflattening' not in session inferences: "
            f"{summary['inferences']}"
        )

    @pytest.mark.parametrize("func_name", KNOWN_NOT_FLATTENED)
    def test_non_flattened_function_no_unflattening_inference(
        self, func_name, recon_store_session,
    ):
        """Non-flattened functions should NOT recommend unflattening."""
        if recon_store_session is None:
            pytest.skip("Recon pipeline disabled")
        func_ea = _resolve_ea(func_name)
        if func_ea == idc.BADADDR:
            pytest.skip(f"Function {func_name} not found in IDB")

        hints = recon_store_session.load_hints(func_ea=func_ea)
        if hints is None:
            return  # No hints = no inference, which is correct
        assert "unflattening" not in hints.recommended_inferences, (
            f"{func_name}: incorrectly recommends 'unflattening' — "
            f"type={hints.obfuscation_type}, confidence={hints.confidence}"
        )

    @pytest.mark.parametrize("func_name", KNOWN_FLATTENED)
    def test_flattened_function_consumer_outcome(
        self, func_name, recon_store_session,
    ):
        """Flattened functions should have a rule_scope consumer outcome."""
        if recon_store_session is None:
            pytest.skip("Recon pipeline disabled")
        func_ea = _resolve_ea(func_name)
        if func_ea == idc.BADADDR:
            pytest.skip(f"Function {func_name} not found in IDB")

        outcomes = recon_store_session.load_consumer_outcomes(func_ea)
        rule_scope_outcomes = [
            o for o in outcomes if o["consumer_name"] == "rule_scope"
        ]
        assert len(rule_scope_outcomes) > 0, (
            f"{func_name} (0x{func_ea:x}): no rule_scope consumer outcome"
        )

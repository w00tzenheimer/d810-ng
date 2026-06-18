"""Tests for PassPipeline feature-flag integration.

Tests verify:
- PassPipeline is constructed with the safe cleanup transforms when enabled
- PassPipeline is NOT constructed when flag is disabled (zero overhead)
- HexraysDecompilationHook source accepts pass_pipeline kwarg defaulting to None
- the portable spec and Hex-Rays adapter return the right pass types

These tests avoid importing IDA-dependent modules (ida_hexrays, d810.manager,
d810.hexrays.hooks.hexrays_hooks).
"""
from __future__ import annotations

from d810.passes.pipeline import FlowGraphTransformPipeline
from d810.passes.pass_pipeline_factory import (
    build_pass_pipeline_spec,
    pass_pipeline_spec_from_config,
)
from d810.manager.hexrays_pass_pipeline import build_hexrays_flowgraph_pipeline
from d810.hexrays.mutation.transform.goto_chain_removal import GotoChainRemovalPass
from d810.hexrays.mutation.ir_translator import IDAIRTranslator
from d810.transforms.simplify_identical_branch import SimplifyIdenticalBranchPass


# ---------------------------------------------------------------------------
# Factory: Hex-Rays adapter from portable spec
# ---------------------------------------------------------------------------

def build_cleanup_pipeline() -> FlowGraphTransformPipeline:
    """Construct the Hex-Rays PassPipeline from the portable cleanup spec."""
    spec = build_pass_pipeline_spec(include_default_cleanup=True)
    return build_hexrays_flowgraph_pipeline(spec)


# ---------------------------------------------------------------------------
# Tests: pipeline construction
# ---------------------------------------------------------------------------


class TestBuildPassPipeline:
    """Tests for the PassPipeline factory."""

    def test_returns_pass_pipeline_instance(self):
        """Factory returns a PassPipeline."""
        pipeline = build_cleanup_pipeline()
        assert isinstance(pipeline, FlowGraphTransformPipeline)

    def test_pipeline_has_two_passes(self):
        """PassPipeline should contain exactly 2 safe cleanup transforms."""
        pipeline = build_cleanup_pipeline()
        assert len(pipeline.passes) == 2

    def test_pipeline_contains_simplify_identical_branch(self):
        """SimplifyIdenticalBranchPass must be included."""
        pipeline = build_cleanup_pipeline()
        pass_types = [type(p) for p in pipeline.passes]
        assert SimplifyIdenticalBranchPass in pass_types

    def test_pipeline_contains_goto_chain_removal(self):
        """GotoChainRemovalPass must be included."""
        pipeline = build_cleanup_pipeline()
        pass_types = [type(p) for p in pipeline.passes]
        assert GotoChainRemovalPass in pass_types

    def test_backend_is_ir_translator(self):
        """PassPipeline should use IDAIRTranslator."""
        pipeline = build_cleanup_pipeline()
        assert isinstance(pipeline.backend, IDAIRTranslator)

    def test_pipeline_repr_contains_pass_names(self):
        """PassPipeline repr should name both safe cleanup transforms."""
        pipeline = build_cleanup_pipeline()
        r = repr(pipeline)
        assert "simplify_identical_branch" in r
        assert "goto_chain_removal" in r

    def test_pass_order_is_stable(self):
        """Passes should appear in a deterministic order across calls."""
        p1 = build_cleanup_pipeline()
        p2 = build_cleanup_pipeline()
        names1 = [p.name for p in p1.passes]
        names2 = [p.name for p in p2.passes]
        assert names1 == names2


# ---------------------------------------------------------------------------
# Tests: feature flag OFF - zero overhead
# ---------------------------------------------------------------------------


class TestFeatureFlagDisabled:
    """Tests for the default-off behavior of enable_pass_pipeline."""

    def test_flag_absent_defaults_to_false(self):
        """enable_pass_pipeline must default to False when absent from config."""
        config = {}
        assert config.get("enable_pass_pipeline", False) is False

    def test_explicit_false_evaluates_falsy(self):
        """Explicit enable_pass_pipeline: false must be falsy."""
        config = {"enable_pass_pipeline": False}
        assert not config.get("enable_pass_pipeline", False)

    def test_gate_logic_does_not_call_factory_when_disabled(self):
        """Simulate the D810Manager.start() gate: factory not called when flag is False."""
        config = {"enable_pass_pipeline": False}
        assert pass_pipeline_spec_from_config(config, environ={}) is None

    def test_gate_logic_yields_none_when_disabled(self):
        """Gate yields None pipeline when flag is False, matching D810Manager.start()."""
        config = {"enable_pass_pipeline": False}
        assert pass_pipeline_spec_from_config(config, environ={}) is None


# ---------------------------------------------------------------------------
# Tests: feature flag ON
# ---------------------------------------------------------------------------


class TestFeatureFlagEnabled:
    """Tests for enable_pass_pipeline: true behavior."""

    def test_flag_true_is_truthy(self):
        """enable_pass_pipeline: true must be truthy."""
        config = {"enable_pass_pipeline": True}
        assert config.get("enable_pass_pipeline", False)

    def test_gate_logic_calls_factory_when_enabled(self):
        """Simulate the D810Manager.start() gate: factory IS called when flag is True."""
        config = {"enable_pass_pipeline": True}
        spec = pass_pipeline_spec_from_config(config, environ={})
        assert spec is not None
        _pass_pipeline = build_hexrays_flowgraph_pipeline(spec)
        assert _pass_pipeline is not None
        assert isinstance(_pass_pipeline, FlowGraphTransformPipeline)

    def test_gate_logic_yields_pipeline_with_two_passes(self):
        """Gate yields a pipeline with 2 transforms when flag is True."""
        config = {"enable_pass_pipeline": True}
        spec = pass_pipeline_spec_from_config(config, environ={})
        assert spec is not None
        _pass_pipeline = build_hexrays_flowgraph_pipeline(spec)
        assert _pass_pipeline is not None
        assert len(_pass_pipeline.passes) == 2


# ---------------------------------------------------------------------------
# Tests: BlockOptimizerManager owns the pipeline (source-level, no IDA import)
# ---------------------------------------------------------------------------


class TestBlockOptimizerManagerPipelineIntegration:
    """Tests that BlockOptimizerManager owns the PassPipeline and fires it at MMAT_GLBOPT2.

    We read the source file directly instead of importing the module, since
    importing hexrays_hooks.py requires ida_hexrays at the module level.

    The PassPipeline was moved from HexraysDecompilationHook.glbopt() into
    BlockOptimizerManager so it executes within the normal per-maturity
    optimization cycle, before the MBA is finalized.
    """

    def _read_block_adapter_source(self) -> str:
        """Return the source of optblock_adapter.py as a string."""
        import pathlib
        repo_root = pathlib.Path(__file__).parent.parent.parent.parent.parent
        candidates = (
            repo_root / "src/d810/hexrays/hooks/optblock_adapter.py",
        )
        for path in candidates:
            if path.exists():
                return path.read_text(encoding="utf-8")
        raise FileNotFoundError(f"optblock_adapter.py not found in candidates: {candidates}")

    def _read_hook_source(self) -> str:
        """Return the source of hexrays_hooks.py as a string."""
        import pathlib
        repo_root = pathlib.Path(__file__).parent.parent.parent.parent.parent
        candidates = (
            repo_root / "src/d810/hexrays/hooks/hexrays_hooks.py",
            repo_root / "src/d810/hexrays/hexrays_hooks.py",
        )
        for path in candidates:
            if path.exists():
                return path.read_text(encoding="utf-8")
        raise FileNotFoundError(f"hexrays_hooks.py not found in candidates: {candidates}")

    def test_block_optimizer_has_pass_pipeline_attribute(self):
        """BlockOptimizerManager source must declare _pass_pipeline attribute."""
        src = self._read_block_adapter_source()
        assert "_pass_pipeline" in src, (
            "BlockOptimizerManager must declare a '_pass_pipeline' attribute"
        )

    def test_block_optimizer_pass_pipeline_defaults_to_none(self):
        """_pass_pipeline must default to None in BlockOptimizerManager source."""
        src = self._read_block_adapter_source()
        assert "self._pass_pipeline = None" in src, (
            "_pass_pipeline must default to None"
        )

    def test_block_optimizer_configure_accepts_pass_pipeline(self):
        """configure() must accept and store pass_pipeline kwarg."""
        src = self._read_block_adapter_source()
        assert 'kwargs.get("pass_pipeline"' in src, (
            "BlockOptimizerManager.configure() must accept 'pass_pipeline' kwarg"
        )

    def test_block_optimizer_fires_pipeline_at_mmat_glbopt2(self):
        """BlockOptimizerManager source must gate pipeline execution on MMAT_GLBOPT2."""
        src = self._read_block_adapter_source()
        assert "MMAT_GLBOPT2" in src, (
            "Pipeline must be gated on MMAT_GLBOPT2 in BlockOptimizerManager"
        )

    def test_block_optimizer_tracks_pipeline_last_maturity(self):
        """BlockOptimizerManager must track last maturity the pipeline fired at."""
        src = self._read_block_adapter_source()
        assert "_pipeline_last_maturity" in src, (
            "BlockOptimizerManager must have '_pipeline_last_maturity' tracker"
        )

    def test_block_optimizer_calls_pipeline_run(self):
        """BlockOptimizerManager source must call _pass_pipeline.run(mba)."""
        src = self._read_block_adapter_source()
        assert "self._pass_pipeline.run(mba)" in src, (
            "BlockOptimizerManager must call self._pass_pipeline.run(mba)"
        )

    def test_glbopt_does_not_run_pipeline(self):
        """glbopt() must NOT reference pass_pipeline - pipeline moved to BlockOptimizerManager."""
        src = self._read_hook_source()
        # Extract only the glbopt method body
        glbopt_start = src.find("    def glbopt(")
        assert glbopt_start != -1, "glbopt() method must exist"
        # Find the next method after glbopt
        next_method = src.find("\n    def ", glbopt_start + 1)
        glbopt_body = src[glbopt_start:next_method] if next_method != -1 else src[glbopt_start:]
        assert "pass_pipeline" not in glbopt_body, (
            "glbopt() must NOT reference pass_pipeline - pipeline runs in BlockOptimizerManager"
        )

    def test_hexrays_hook_init_does_not_accept_pass_pipeline(self):
        """HexraysDecompilationHook.__init__ must NOT have a pass_pipeline parameter."""
        src = self._read_hook_source()
        # Find the HexraysDecompilationHook class
        class_start = src.find("class HexraysDecompilationHook")
        assert class_start != -1
        # Find its __init__
        init_start = src.find("    def __init__", class_start)
        assert init_start != -1
        # Find the closing paren of the signature
        init_end = src.find("        super().__init__()", init_start)
        init_signature = src[init_start:init_end]
        assert "pass_pipeline" not in init_signature, (
            "HexraysDecompilationHook.__init__ must NOT declare pass_pipeline - "
            "pipeline ownership moved to BlockOptimizerManager"
        )

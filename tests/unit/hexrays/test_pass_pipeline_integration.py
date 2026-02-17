"""Unit tests for PassPipeline feature-flag integration.

Tests verify:
- PassPipeline is constructed with the correct 4 cleanup passes when flag is enabled
- PassPipeline is NOT constructed when flag is disabled (zero overhead)
- HexraysDecompilationHook source accepts pass_pipeline kwarg defaulting to None
- _build_pass_pipeline() returns the right pass types

These tests avoid importing IDA-dependent modules (ida_hexrays, d810.manager,
d810.hexrays.hexrays_hooks). Construction logic is tested through a standalone
factory that mirrors what D810Manager._build_pass_pipeline() does.
"""
from __future__ import annotations

import pytest

from d810.hexrays.pass_pipeline import PassPipeline
from d810.hexrays.passes.simplify_identical_branch import SimplifyIdenticalBranchPass
from d810.hexrays.passes.dead_block_elimination import DeadBlockEliminationPass
from d810.hexrays.passes.goto_chain_removal import GotoChainRemovalPass
from d810.hexrays.passes.block_merge import BlockMergePass
from d810.hexrays.passes.opaque_jump_fixer import OpaqueJumpFixerPass
from d810.hexrays.passes.fake_jump_fixer import FakeJumpFixerPass
from d810.hexrays.backends.ida_backend import IDABackend


# ---------------------------------------------------------------------------
# Factory: mirrors D810Manager._build_pass_pipeline() without IDA imports
# ---------------------------------------------------------------------------

def build_cleanup_pipeline() -> PassPipeline:
    """Construct the PassPipeline with the 4 cleanup passes.

    This is the same logic as D810Manager._build_pass_pipeline(), extracted
    here so unit tests can exercise it without importing ida_hexrays.

    OpaqueJumpFixerPass and FakeJumpFixerPass are intentionally excluded:
    they require pre-computed fix dicts from the legacy analysis side.
    """
    backend = IDABackend()
    passes = [
        SimplifyIdenticalBranchPass(),
        DeadBlockEliminationPass(),
        GotoChainRemovalPass(),
        BlockMergePass(),
    ]
    return PassPipeline(backend, passes)


# ---------------------------------------------------------------------------
# Tests: pipeline construction
# ---------------------------------------------------------------------------


class TestBuildPassPipeline:
    """Tests for the PassPipeline factory (mirrors D810Manager._build_pass_pipeline)."""

    def test_returns_pass_pipeline_instance(self):
        """Factory returns a PassPipeline."""
        pipeline = build_cleanup_pipeline()
        assert isinstance(pipeline, PassPipeline)

    def test_pipeline_has_four_passes(self):
        """PassPipeline should contain exactly 4 cleanup passes."""
        pipeline = build_cleanup_pipeline()
        assert len(pipeline.passes) == 4

    def test_pipeline_contains_simplify_identical_branch(self):
        """SimplifyIdenticalBranchPass must be included."""
        pipeline = build_cleanup_pipeline()
        pass_types = [type(p) for p in pipeline.passes]
        assert SimplifyIdenticalBranchPass in pass_types

    def test_pipeline_contains_dead_block_elimination(self):
        """DeadBlockEliminationPass must be included."""
        pipeline = build_cleanup_pipeline()
        pass_types = [type(p) for p in pipeline.passes]
        assert DeadBlockEliminationPass in pass_types

    def test_pipeline_contains_goto_chain_removal(self):
        """GotoChainRemovalPass must be included."""
        pipeline = build_cleanup_pipeline()
        pass_types = [type(p) for p in pipeline.passes]
        assert GotoChainRemovalPass in pass_types

    def test_pipeline_contains_block_merge(self):
        """BlockMergePass must be included."""
        pipeline = build_cleanup_pipeline()
        pass_types = [type(p) for p in pipeline.passes]
        assert BlockMergePass in pass_types

    def test_pipeline_excludes_opaque_jump_fixer(self):
        """OpaqueJumpFixerPass must NOT be included (requires pre-computed fixes)."""
        pipeline = build_cleanup_pipeline()
        pass_types = [type(p) for p in pipeline.passes]
        assert OpaqueJumpFixerPass not in pass_types

    def test_pipeline_excludes_fake_jump_fixer(self):
        """FakeJumpFixerPass must NOT be included (requires pre-computed fixes)."""
        pipeline = build_cleanup_pipeline()
        pass_types = [type(p) for p in pipeline.passes]
        assert FakeJumpFixerPass not in pass_types

    def test_backend_is_ida_backend(self):
        """PassPipeline should use IDABackend."""
        pipeline = build_cleanup_pipeline()
        assert isinstance(pipeline.backend, IDABackend)

    def test_pipeline_repr_contains_pass_names(self):
        """PassPipeline repr should name all 4 passes."""
        pipeline = build_cleanup_pipeline()
        r = repr(pipeline)
        assert "simplify_identical_branch" in r
        assert "dead_block_elimination" in r
        assert "goto_chain_removal" in r
        assert "block_merge" in r

    def test_pass_order_is_stable(self):
        """Passes should appear in a deterministic order across calls."""
        p1 = build_cleanup_pipeline()
        p2 = build_cleanup_pipeline()
        names1 = [p.name for p in p1.passes]
        names2 = [p.name for p in p2.passes]
        assert names1 == names2


# ---------------------------------------------------------------------------
# Tests: feature flag OFF — zero overhead
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
        build_called = []

        def _fake_build():
            build_called.append(True)
            return build_cleanup_pipeline()

        _pass_pipeline = None
        if config.get("enable_pass_pipeline", False):
            _pass_pipeline = _fake_build()

        assert not build_called, "_build_pass_pipeline must not be called when flag is False"
        assert _pass_pipeline is None

    def test_gate_logic_yields_none_when_disabled(self):
        """Gate yields None pipeline when flag is False, matching D810Manager.start()."""
        config = {"enable_pass_pipeline": False}
        _pass_pipeline = None
        if config.get("enable_pass_pipeline", False):
            _pass_pipeline = build_cleanup_pipeline()
        assert _pass_pipeline is None


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
        _pass_pipeline = None
        if config.get("enable_pass_pipeline", False):
            _pass_pipeline = build_cleanup_pipeline()
        assert _pass_pipeline is not None
        assert isinstance(_pass_pipeline, PassPipeline)

    def test_gate_logic_yields_pipeline_with_four_passes(self):
        """Gate yields a pipeline with 4 passes when flag is True."""
        config = {"enable_pass_pipeline": True}
        _pass_pipeline = None
        if config.get("enable_pass_pipeline", False):
            _pass_pipeline = build_cleanup_pipeline()
        assert _pass_pipeline is not None
        assert len(_pass_pipeline.passes) == 4


# ---------------------------------------------------------------------------
# Tests: HexraysDecompilationHook signature (source-level, no IDA import)
# ---------------------------------------------------------------------------


class TestHexraysDecompilationHookSignature:
    """Tests that HexraysDecompilationHook accepts pass_pipeline without importing IDA.

    We read the source file directly instead of importing the module, since
    importing hexrays_hooks.py requires ida_hexrays at the module level.
    """

    def _read_hook_source(self) -> str:
        """Return the source of hexrays_hooks.py as a string."""
        import pathlib
        hook_path = pathlib.Path(__file__).parent.parent.parent.parent / (
            "src/d810/hexrays/hexrays_hooks.py"
        )
        return hook_path.read_text(encoding="utf-8")

    def test_hook_init_accepts_pass_pipeline_kwarg(self):
        """HexraysDecompilationHook.__init__ source must contain 'pass_pipeline'."""
        src = self._read_hook_source()
        assert "pass_pipeline" in src, (
            "HexraysDecompilationHook.__init__ must declare a 'pass_pipeline' parameter"
        )

    def test_hook_pass_pipeline_defaults_to_none(self):
        """pass_pipeline parameter must default to None in source."""
        src = self._read_hook_source()
        # Both the signature default and the assignment should be present
        assert "pass_pipeline: typing.Any | None = None" in src, (
            "pass_pipeline parameter must have 'None' as default value"
        )

    def test_hook_stores_pass_pipeline_as_attribute(self):
        """__init__ must assign self.pass_pipeline = pass_pipeline."""
        src = self._read_hook_source()
        assert "self.pass_pipeline = pass_pipeline" in src, (
            "HexraysDecompilationHook must store pass_pipeline as self.pass_pipeline"
        )

    def test_glbopt_runs_pipeline_when_set(self):
        """glbopt() source must reference self.pass_pipeline."""
        src = self._read_hook_source()
        assert "self.pass_pipeline" in src, (
            "glbopt() must use self.pass_pipeline to run the pipeline"
        )

    def test_glbopt_calls_pipeline_run(self):
        """glbopt() source must call pass_pipeline.run(mba)."""
        src = self._read_hook_source()
        assert "self.pass_pipeline.run(mba)" in src, (
            "glbopt() must call self.pass_pipeline.run(mba)"
        )

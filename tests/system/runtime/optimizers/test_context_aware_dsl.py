"""Tests for context-aware DSL extensions.

These tests verify that the context-aware DSL correctly handles:
1. Context providers (binding variables from instruction context)
2. Context constraints (checking destination properties)
3. Destination updates (modifying the instruction destination)

WHY THIS IS IN system/ TESTS:
    The extensions module (d810.backends.hexrays.evidence.extensions) directly imports from
    ida_hexrays at module level, so it requires IDA Pro to be available.
    These are IDA-specific helpers for pattern matching optimization rules.
"""

from contextlib import contextmanager
import signal
from types import SimpleNamespace

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.backends.hexrays.evidence import extensions
from d810.backends.hexrays.evidence.extensions import context, when
from d810.hexrays.expr.ast import AstLeaf
from d810.hexrays.utils.hexrays_formatters import format_mop_t
from d810.mba.canonical_pattern import (
    CanonicalPatternUnsupported,
    compile_canonical_pattern,
)
from d810.mba.certified_catalogue import (
    _referenced_global_names,
    build_certified_catalogue_snapshot,
)

# --- DestinationHelpers tests ---


@pytest.mark.parametrize(
    "helper, ctx, expected",
    [
        (when.dst.is_high_half, {"_candidate": None}, False),
        (when.dst.is_register, {"_candidate": None}, False),
        (when.dst.is_memory, {"_candidate": None}, False),
    ],
)
def test_destination_helpers_no_candidate(helper, ctx, expected):
    """Test destination helpers when candidate is None."""
    assert helper(ctx) is expected


# --- ContextProviders tests ---


@pytest.mark.parametrize(
    "provider, ctx, expected",
    [
        (context.dst.parent_register, {"_candidate": None}, None),
        (context.dst.operand_size, {}, None),
    ],
)
def test_context_providers_no_candidate(provider, ctx, expected):
    """Test context providers when candidate is None or missing."""
    assert provider(ctx) is expected


# --- Context-aware Rule Integration tests ---


def import_replace_mov_high_context():
    """Utility to try importing ReplaceMovHighContext, skip test if not found."""
    try:
        from d810.optimizers.microcode.instructions.pattern_matching.experimental import (
            ReplaceMovHighContext,
        )

        return ReplaceMovHighContext
    except ImportError as e:
        pytest.skip(f"Could not import context-aware rule: {e}")


def test_rule_imports_correctly():
    """Test that the context-aware rule can be imported and has expected attributes."""
    ReplaceMovHighContext = import_replace_mov_high_context()
    # Verify the rule has the expected attributes
    assert hasattr(ReplaceMovHighContext, "PATTERN")
    assert hasattr(ReplaceMovHighContext, "REPLACEMENT")
    assert hasattr(ReplaceMovHighContext, "CONSTRAINTS")
    assert hasattr(ReplaceMovHighContext, "CONTEXT_VARS")
    assert hasattr(ReplaceMovHighContext, "UPDATE_DESTINATION")
    # Verify class-level values
    assert ReplaceMovHighContext.UPDATE_DESTINATION == "full_reg"
    assert "full_reg" in ReplaceMovHighContext.CONTEXT_VARS
    assert len(ReplaceMovHighContext.CONSTRAINTS) > 0


def test_rule_instance_creation():
    """Test that we can create an instance of the context-aware rule."""
    ReplaceMovHighContext = import_replace_mov_high_context()
    rule = ReplaceMovHighContext()
    # Check that the rule has the required properties
    assert rule.name == "ReplaceMovHighContext"
    assert rule.SKIP_VERIFICATION is True  # Size-changing rule
    assert hasattr(rule, "check_candidate")


def test_context_vars_processing():
    """Test that CONTEXT_VARS are processed correctly."""
    ReplaceMovHighContext = import_replace_mov_high_context()
    rule = ReplaceMovHighContext()
    # CONTEXT_VARS should be a dict and its items callable
    assert isinstance(rule.CONTEXT_VARS, dict)
    assert "full_reg" in rule.CONTEXT_VARS
    provider = rule.CONTEXT_VARS["full_reg"]
    assert callable(provider)


# --- Bounded ABC callback-dependency experiment ---


@contextmanager
def _snapshot_deadline(seconds):
    """Bound only snapshot construction, never native setup or imports."""

    class SnapshotDeadlineExpired(BaseException):
        pass

    def fail_on_timeout(_signum, _frame):
        raise SnapshotDeadlineExpired

    previous_handler = signal.signal(signal.SIGALRM, fail_on_timeout)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        try:
            yield
        except SnapshotDeadlineExpired:
            pytest.fail(f"one-rule snapshot exceeded {seconds} seconds")
    finally:
        signal.setitimer(signal.ITIMER_REAL, *previous_timer)
        signal.signal(signal.SIGALRM, previous_handler)


def _candidate(destination):
    return {"_candidate": SimpleNamespace(dst_mop=destination)}


def _native_register_matrix():
    register_limit = int(ida_hexrays.mr_first) + 128
    mops = []
    for size in (1, 2, 4, 8):
        for register in range(register_limit):
            mop = ida_hexrays.mop_t()
            mop.make_reg(register, size)
            mops.append(mop)
    return tuple(mops)


class TestAbcCallbackDependencyBoundary:
    binary_name = "libobfuscated.dll"

    def test_high_half_matches_old_formatter_for_real_register_mops(
        self, libobfuscated_setup
    ):
        assert ida_hexrays.mop_r <= 15
        results = []
        sizes = set()
        for mop in _native_register_matrix():
            sizes.add(int(mop.size))
            expected = "^2" in format_mop_t(mop)
            actual = extensions.DestinationHelpers.is_high_half(_candidate(mop))
            assert actual is (int(mop.size) == 2 and expected)
            if int(mop.size) == 2:
                results.append(actual)

        assert sizes == {1, 2, 4, 8}
        assert any(results), "native processor exposed no size-2 high-half witness"
        assert not all(results), "native processor exposed no size-2 negative witness"

    @pytest.mark.parametrize(
        ("destination", "expected"),
        [
            (SimpleNamespace(t=-1, size=2, dstr=lambda: "r0^2"), False),
            (SimpleNamespace(t=ida_hexrays.mop_r, size=4, dstr=lambda: "r0^2"), False),
        ],
    )
    def test_high_half_retains_non_register_and_wrong_size_results(
        self, libobfuscated_setup, destination, expected
    ):
        assert extensions.DestinationHelpers.is_high_half(
            _candidate(destination)
        ) is expected

    @pytest.mark.parametrize(
        ("destination", "expected"),
        [
            (
                type(
                    "NoDstrMop",
                    (),
                    {
                        "t": ida_hexrays.mop_r,
                        "size": 2,
                        "__str__": lambda self: "fallback^2",
                    },
                )(),
                True,
            ),
            (
                type(
                    "RaisingMarkerMop",
                    (),
                    {
                        "t": ida_hexrays.mop_r,
                        "size": 2,
                        "dstr": lambda self: (_ for _ in ()).throw(
                            RuntimeError("render ^2 failed")
                        ),
                    },
                )(),
                True,
            ),
            (
                type(
                    "RaisingPlainMop",
                    (),
                    {
                        "t": ida_hexrays.mop_r,
                        "size": 2,
                        "dstr": lambda self: (_ for _ in ()).throw(
                            RuntimeError("render failed")
                        ),
                    },
                )(),
                False,
            ),
        ],
    )
    def test_high_half_retains_display_fallback_and_exception_text(
        self, libobfuscated_setup, destination, expected
    ):
        assert extensions.DestinationHelpers.is_high_half(
            _candidate(destination)
        ) is expected

    def test_parent_register_matches_native_construction_oracle(
        self, libobfuscated_setup
    ):
        source = next(
            (
                mop
                for mop in _native_register_matrix()
                if int(mop.size) == 2 and "^2" in format_mop_t(mop)
            ),
            None,
        )
        assert source is not None, "native processor exposed no high-half register"

        result = extensions.ContextProviders.parent_register(_candidate(source))
        oracle = ida_hexrays.mop_t()
        oracle.make_reg(int(source.r) - 2, 4)

        assert isinstance(result, AstLeaf)
        assert result.name == "parent_reg"
        assert result.mop.t == ida_hexrays.mop_r
        assert int(result.mop.r) == int(source.r) - 2
        assert int(result.mop.size) == 4
        assert result.mop.dstr() == oracle.dstr()

    def test_parent_register_retains_false_non_register_and_constructor_failure(
        self, libobfuscated_setup, monkeypatch
    ):
        assert extensions.ContextProviders.parent_register({"_candidate": None}) is None
        assert (
            extensions.ContextProviders.parent_register(
                _candidate(SimpleNamespace(t=-1, size=2, r=4))
            )
            is None
        )

        class ConstructionFailure:
            def __init__(self):
                raise RuntimeError("mop construction failed")

        monkeypatch.setattr(extensions, "_MOP_T", ConstructionFailure)
        with pytest.raises(RuntimeError, match="mop construction failed"):
            extensions.ContextProviders.parent_register(
                _candidate(SimpleNamespace(t=extensions._MOP_R, size=1, r=4))
            )

    def test_callbacks_resolve_only_bounded_globals(self, libobfuscated_setup):
        high_half_names = set(
            _referenced_global_names(
                extensions.DestinationHelpers.is_high_half.__code__
            )
        )
        parent_names = set(
            _referenced_global_names(
                extensions.ContextProviders.parent_register.__code__
            )
        )

        assert {"_MOP_R", "_has_high_half_display_marker"} <= high_half_names
        assert high_half_names.isdisjoint({"ida_hexrays", "format_mop_t"})
        assert {"_MOP_R", "_MOP_T", "AstLeaf"} <= parent_names
        assert "ida_hexrays" not in parent_names
        assert isinstance(extensions._MOP_T, type)
        assert isinstance(AstLeaf, type)

    def test_one_rule_snapshot_is_bounded_and_keeps_expected_statuses(
        self, libobfuscated_setup
    ):
        ReplaceMovHighContext = import_replace_mov_high_context()
        with _snapshot_deadline(5):
            snapshot = build_certified_catalogue_snapshot(
                (ReplaceMovHighContext(),),
                compiler_version="abc-callback-boundary-v1",
            )

        assert snapshot.structural_authorizable is True
        assert snapshot.canonical_status_by_rule_width == {
            (0, 8): "unsupported",
            (0, 16): "unsupported",
            (0, 32): "unsupported",
            (0, 64): "unsupported",
        }

    @pytest.mark.parametrize("width", (8, 16, 32, 64))
    def test_canonical_rejection_precedes_callback_semantics(
        self, libobfuscated_setup, width
    ):
        ReplaceMovHighContext = import_replace_mov_high_context()
        rule = ReplaceMovHighContext()

        class ConstraintsMustNotBeRead:
            def __iter__(self):
                raise AssertionError("callback constraints were read")

        rule.CONSTRAINTS = ConstraintsMustNotBeRead()
        with pytest.raises(CanonicalPatternUnsupported) as error:
            compile_canonical_pattern(rule, width=width, declaration_index=0)

        assert str(error.value) == "symbolic shl requires a fixed-count term"

    def test_snapshot_fingerprint_binds_resolved_scalars_and_helper_code(
        self, libobfuscated_setup, monkeypatch
    ):
        ReplaceMovHighContext = import_replace_mov_high_context()

        def snapshot_fingerprint():
            with _snapshot_deadline(5):
                return build_certified_catalogue_snapshot(
                    (ReplaceMovHighContext(),),
                    compiler_version="abc-callback-fingerprint-v1",
                ).fingerprint

        baseline = snapshot_fingerprint()
        with monkeypatch.context() as patch:
            patch.setattr(extensions, "_MOP_R", int(extensions._MOP_R) + 1000)
            assert snapshot_fingerprint() != baseline

        original_helper = extensions._has_high_half_display_marker

        def same_result_helper(destination):
            return bool(original_helper(destination))

        with monkeypatch.context() as patch:
            patch.setattr(
                extensions, "_has_high_half_display_marker", same_result_helper
            )
            assert snapshot_fingerprint() != baseline

    def test_snapshot_ignores_unread_ida_hexrays_attributes(
        self, libobfuscated_setup, monkeypatch
    ):
        ReplaceMovHighContext = import_replace_mov_high_context()

        def snapshot_fingerprint():
            with _snapshot_deadline(5):
                return build_certified_catalogue_snapshot(
                    (ReplaceMovHighContext(),),
                    compiler_version="abc-callback-module-independence-v1",
                ).fingerprint

        baseline = snapshot_fingerprint()
        monkeypatch.setattr(
            ida_hexrays, "_d810_unrelated_callback_test_value", 1, raising=False
        )
        assert snapshot_fingerprint() == baseline


# --- DSL Documentation tests ---


def test_extensions_module_has_docstring():
    """Verify the extensions module has documentation."""
    assert extensions.__doc__ is not None
    assert "context-aware" in extensions.__doc__.lower()


def test_helpers_have_docstrings():
    """Verify all helpers have documentation."""
    from d810.backends.hexrays.evidence.extensions import (
        ContextProviders,
        DestinationHelpers,
    )

    # Check DestinationHelpers
    assert DestinationHelpers.is_high_half.__doc__ is not None
    assert DestinationHelpers.is_register.__doc__ is not None
    assert DestinationHelpers.is_memory.__doc__ is not None

    # Check ContextProviders
    assert ContextProviders.parent_register.__doc__ is not None
    assert ContextProviders.operand_size.__doc__ is not None


def test_example_rule_has_comprehensive_docstring():
    """Verify the example rule has comprehensive documentation."""
    ReplaceMovHighContext = import_replace_mov_high_context()
    docstring = ReplaceMovHighContext.__doc__
    assert docstring is not None
    assert "when.dst.is_high_half" in docstring
    assert "context.dst.parent_register" in docstring
    assert "UPDATE_DESTINATION" in docstring
    assert "Example:" in docstring

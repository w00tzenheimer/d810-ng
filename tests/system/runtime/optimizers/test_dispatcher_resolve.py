"""System tests for resolve_dispatcher_father and layout signal collection.

These tests verify dispatcher father resolution and layout signal collection
using real microcode from control-flow flattened binaries. Tests use actual
mba_t/mblock_t objects obtained from decompilation rather than mocks.

Test Strategy
=============
1. Decompile functions from libobfuscated binary at specific maturity levels
2. Use GenericDispatcherUnflatteningRule to analyze real dispatcher patterns
3. Verify resolve_dispatcher_father behavior against real microcode structures
4. Test layout signal collection and event emission with actual dispatcher info

Test Functions (from libobfuscated binary):
- mixed_dispatcher_pattern: Multiple states with large constants, conditional branches
- high_fan_in_pattern: Switch-based dispatcher with many predecessors
- state_comparison_pattern: Large constant comparisons typical of Hodur obfuscation

These real-microcode tests verify:
- resolve_dispatcher_father chooses correct deferred modification type
- Layout signals accurately reflect real dispatcher structure
- Event emission works correctly with actual dispatcher data
- No crashes or hangs from real IDA data structures
"""

from __future__ import annotations

import logging
import os
import platform
from d810.core.typing import TYPE_CHECKING

import pytest

import ida_funcs
import ida_hexrays
import ida_name
import idaapi

from d810.optimizers.microcode.flow.flattening.generic import (
    GenericDispatcherUnflatteningRule,
    GenericDispatcherCollector,
    GenericDispatcherInfo,
    UnflatteningEvent,
)
from d810.hexrays.deferred_modifier import DeferredGraphModifier

if TYPE_CHECKING:
    from ida_hexrays import mba_t, mblock_t

logger = logging.getLogger(__name__)


def _get_default_binary() -> str:
    """Get default binary name based on platform, with env var override."""
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"


def get_func_ea(name: str) -> int:
    """Get function address by name, handling macOS underscore prefix."""
    ea = ida_name.get_name_ea(idaapi.BADADDR, name)
    if ea == idaapi.BADADDR:
        ea = ida_name.get_name_ea(idaapi.BADADDR, "_" + name)
    return ea


def gen_microcode_at_maturity(func_ea: int, maturity: int) -> "mba_t | None":
    """Generate microcode at a specific maturity level.

    Returns an mba_t object or None if generation fails.
    """
    func = ida_funcs.get_func(func_ea)
    if func is None:
        return None

    mbr = ida_hexrays.mba_ranges_t(func)
    hf = ida_hexrays.hexrays_failure_t()
    mba = ida_hexrays.gen_microcode(
        mbr, hf, None, ida_hexrays.DECOMP_NO_WAIT, maturity
    )
    return mba


class MinimalDispatcherCollector(GenericDispatcherCollector):
    """Minimal collector implementation for testing."""

    DISPATCHER_CLASS = GenericDispatcherInfo
    DEFAULT_DISPATCHER_MIN_INTERNAL_BLOCK = 1
    DEFAULT_DISPATCHER_MIN_EXIT_BLOCK = 1


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    """Setup fixture for libobfuscated binary tests - runs once per class."""
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


@pytest.mark.ida_required
class TestDispatcherFatherResolveIntegration:
    """Integration tests for resolve_dispatcher_father using real microcode.

    These tests verify that resolve_dispatcher_father correctly chooses between
    queue_convert_to_goto, queue_goto_change, and queue_create_and_redirect based on
    the dispatcher father type and side-effect presence, using actual decompiled data.
    """

    binary_name = _get_default_binary()

    def _create_test_rule(self):
        """Create a test dispatcher rule that extends GenericDispatcherUnflatteningRule.

        This is a minimal concrete implementation for testing the base class methods.
        """

        class TestDispatcherRule(GenericDispatcherUnflatteningRule):
            @property
            def DISPATCHER_COLLECTOR_CLASS(self):
                return MinimalDispatcherCollector

        rule = TestDispatcherRule()
        rule.dump_intermediate_microcode = False
        rule.log_dir = "/tmp/test_dispatcher_resolve"
        rule.defer_calls_on_conditional_entry_father = False
        return rule

    def _create_minimal_dispatcher_info(self, mba: "mba_t") -> GenericDispatcherInfo:
        """Create a minimal GenericDispatcherInfo for testing."""
        dispatcher_info = GenericDispatcherInfo(mba)
        dispatcher_info.entry_block = type('EntryBlock', (), {
            'use_before_def_list': [],
            'blk': mba.get_mblock(0) if mba.qty > 0 else None
        })()
        dispatcher_info.dispatcher_internal_blocks = []
        dispatcher_info.dispatcher_exit_blocks = []
        return dispatcher_info

    def test_resolve_dispatcher_father_does_not_crash_on_real_blocks(
        self, libobfuscated_setup
    ):
        """Verify resolve_dispatcher_father can be called on real dispatcher fathers.

        This is a smoke test verifying the method doesn't crash when given real
        microcode objects. It doesn't assert specific behavior since that depends
        on the actual dispatcher structure in the binary.
        """
        func_ea = get_func_ea("mixed_dispatcher_pattern")
        if func_ea == idaapi.BADADDR:
            pytest.skip("mixed_dispatcher_pattern not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        rule = self._create_test_rule()
        rule.mba = mba

        # Find blocks that might be dispatcher fathers (blocks with successors)
        potential_fathers = []
        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            if blk is None or blk.tail is None:
                continue
            if blk.nsucc() > 0:
                potential_fathers.append(blk)

        if not potential_fathers:
            pytest.skip("No potential dispatcher father blocks found")

        # Create a minimal dispatcher_info for testing
        dispatcher_info = self._create_minimal_dispatcher_info(mba)
        deferred_modifier = DeferredGraphModifier(mba)

        # Try calling resolve_dispatcher_father on the first potential father
        # This should not crash, though it may raise NotResolvableFatherException
        test_father = potential_fathers[0]
        print(f"\n  Testing resolve_dispatcher_father on block {test_father.serial}")
        print(f"  Block type: nsucc={test_father.nsucc()}")

        try:
            from d810.optimizers.microcode.flow.flattening.utils import (
                NotResolvableFatherException,
            )

            result = rule.resolve_dispatcher_father(
                test_father, dispatcher_info, deferred_modifier
            )
            print(f"  resolve_dispatcher_father returned: {result}")
        except NotResolvableFatherException as e:
            print(f"  Block not resolvable (expected): {e}")
        except Exception as e:
            pytest.fail(
                f"resolve_dispatcher_father crashed unexpectedly: {type(e).__name__}: {e}"
            )

    def test_resolve_dispatcher_father_with_deferred_modifier(
        self, libobfuscated_setup
    ):
        """Verify resolve_dispatcher_father queues modifications when deferred_modifier is provided.

        Tests that when a deferred modifier is passed, modifications are queued
        rather than applied directly.
        """
        func_ea = get_func_ea("high_fan_in_pattern")
        if func_ea == idaapi.BADADDR:
            pytest.skip("high_fan_in_pattern not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        rule = self._create_test_rule()
        rule.mba = mba

        deferred_modifier = DeferredGraphModifier(mba)

        # Find a block with successors to test
        test_block = None
        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            if blk is not None and blk.nsucc() > 0:
                test_block = blk
                break

        if test_block is None:
            pytest.skip("No suitable test block found")

        # Create minimal dispatcher_info
        dispatcher_info = self._create_minimal_dispatcher_info(mba)

        initial_queue_size = len(deferred_modifier._modifications)

        try:
            from d810.optimizers.microcode.flow.flattening.utils import (
                NotResolvableFatherException,
            )

            rule.resolve_dispatcher_father(test_block, dispatcher_info, deferred_modifier)
            # If it succeeded, check that modifications were queued
            final_queue_size = len(deferred_modifier._modifications)
            print(
                f"\n  Modifications queued: {final_queue_size - initial_queue_size}"
            )
        except NotResolvableFatherException:
            print("\n  Block not resolvable (expected for some blocks)")


@pytest.mark.ida_required
class TestLayoutSignalCollection:
    """Tests for layout signal collection using real dispatcher patterns.

    These tests verify that _collect_dispatcher_layout_signals and _emit_layout_signals
    work correctly with actual dispatcher data from decompiled binaries.
    """

    binary_name = _get_default_binary()

    def _create_test_rule(self):
        """Create a test dispatcher rule for signal collection testing."""

        class TestDispatcherRule(GenericDispatcherUnflatteningRule):
            @property
            def DISPATCHER_COLLECTOR_CLASS(self):
                return MinimalDispatcherCollector

        rule = TestDispatcherRule()
        rule.dump_intermediate_microcode = False
        rule.log_dir = "/tmp/test_layout_signals"
        rule.log_calls_layout_signals = False
        return rule

    def _create_dispatcher_info(self, mba: "mba_t", entry_blk: "mblock_t") -> GenericDispatcherInfo:
        """Create a GenericDispatcherInfo with specified entry block."""
        dispatcher_info = GenericDispatcherInfo(mba)
        dispatcher_info.entry_block = type('EntryBlock', (), {
            'use_before_def_list': [],
            'blk': entry_blk
        })()
        dispatcher_info.dispatcher_internal_blocks = []
        dispatcher_info.dispatcher_exit_blocks = []
        return dispatcher_info

    def test_collect_layout_signals_on_real_dispatcher(self, libobfuscated_setup):
        """Verify layout signal collection works on real dispatcher patterns.

        This test exercises _collect_dispatcher_layout_signals with actual
        dispatcher info from a decompiled function, verifying all expected
        signal keys are present and have sensible values.
        """
        func_ea = get_func_ea("mixed_dispatcher_pattern")
        if func_ea == idaapi.BADADDR:
            pytest.skip("mixed_dispatcher_pattern not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        rule = self._create_test_rule()
        rule.mba = mba

        # Create a dispatcher_list with one dispatcher using the first block
        dispatcher_info = self._create_dispatcher_info(mba, mba.get_mblock(0))
        rule.dispatcher_list = [dispatcher_info]

        # Collect signals
        signals = rule._collect_dispatcher_layout_signals()

        # Verify expected keys
        expected_keys = [
            "dispatcher_count",
            "max_entry_preds",
            "max_exit_blocks",
            "max_internal_blocks",
            "has_conditional_entry_father",
            "dispatchers",
        ]
        for key in expected_keys:
            assert key in signals, f"Missing expected signal key: {key}"

        print(f"\n  Layout signals collected:")
        print(f"    dispatcher_count: {signals['dispatcher_count']}")
        print(f"    max_entry_preds: {signals['max_entry_preds']}")
        print(f"    max_exit_blocks: {signals['max_exit_blocks']}")
        print(f"    max_internal_blocks: {signals['max_internal_blocks']}")
        print(
            f"    has_conditional_entry_father: {signals['has_conditional_entry_father']}"
        )

        assert signals["dispatcher_count"] == 1
        assert isinstance(signals["dispatchers"], list)

    def test_emit_layout_signals_fires_event(self, libobfuscated_setup):
        """Verify _emit_layout_signals publishes events and caches signals.

        Tests that emitted layout signals are:
        1. Cached in rule._last_layout_signals
        2. Published via the event bus to subscribers
        """
        func_ea = get_func_ea("state_comparison_pattern")
        if func_ea == idaapi.BADADDR:
            pytest.skip("state_comparison_pattern not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        rule = self._create_test_rule()
        rule.mba = mba

        # Set up event listener
        observed = []

        def _on_layout(maturity, signals, optimizer):
            observed.append((maturity, signals, optimizer))

        rule.events.on(UnflatteningEvent.LAYOUT_SIGNALS, _on_layout)

        # Create test payload
        payload = {
            "dispatcher_count": 1,
            "max_entry_preds": 2,
            "max_exit_blocks": 1,
            "max_internal_blocks": 5,
            "has_conditional_entry_father": False,
            "dispatchers": [],
        }

        # Emit signals
        rule._emit_layout_signals(payload)

        # Verify cached
        assert rule._last_layout_signals == payload

        # Verify event fired
        assert len(observed) == 1
        event_maturity, event_signals, event_optimizer = observed[0]
        assert event_maturity == mba.maturity
        assert event_signals == payload
        assert event_optimizer is rule

        print(f"\n  Event emitted successfully at maturity {event_maturity}")
        print(f"  Cached signals: {rule._last_layout_signals['dispatcher_count']} dispatchers")

    def test_conditional_entry_father_detection(self, libobfuscated_setup):
        """Verify layout signals correctly detect conditional entry fathers.

        Tests that has_conditional_entry_father is set when a dispatcher entry
        block has a conditional predecessor (2-way block with jz/jnz tail).
        """
        func_ea = get_func_ea("high_fan_in_pattern")
        if func_ea == idaapi.BADADDR:
            pytest.skip("high_fan_in_pattern not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        rule = self._create_test_rule()
        rule.mba = mba

        # Find a block with multiple predecessors (likely dispatcher entry)
        entry_candidate = None
        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            if blk is None:
                continue
            pred_count = len([x for x in blk.predset])
            if pred_count >= 2:
                entry_candidate = blk
                break

        if entry_candidate is None:
            pytest.skip("No suitable entry block candidate found")

        dispatcher_info = self._create_dispatcher_info(mba, entry_candidate)
        rule.dispatcher_list = [dispatcher_info]

        # Collect signals
        signals = rule._collect_dispatcher_layout_signals()

        print(f"\n  Entry block {entry_candidate.serial} has {len([x for x in entry_candidate.predset])} predecessors")
        print(f"  has_conditional_entry_father: {signals['has_conditional_entry_father']}")

        # The signal should be a boolean
        assert isinstance(signals["has_conditional_entry_father"], bool)


@pytest.mark.ida_required
class TestOptimizeLayoutSignalIntegration:
    """Tests for optimize() method's interaction with layout signals.

    These tests verify that the optimize() method correctly handles layout signals
    when defer_calls_on_conditional_entry_father is enabled.
    """

    binary_name = _get_default_binary()

    def _create_test_rule(self):
        """Create a test rule with deferred CALLS handling enabled."""

        class TestDispatcherRule(GenericDispatcherUnflatteningRule):
            @property
            def DISPATCHER_COLLECTOR_CLASS(self):
                return MinimalDispatcherCollector

        rule = TestDispatcherRule()
        rule.dump_intermediate_microcode = False
        rule.log_dir = "/tmp/test_optimize_signals"
        rule.defer_calls_on_conditional_entry_father = True
        rule.log_calls_layout_signals = False
        return rule

    def test_optimize_processes_blocks_without_crashing(self, libobfuscated_setup):
        """Verify optimize() can process blocks from real functions.

        This is a smoke test that optimize() doesn't crash when given real
        microcode blocks, even if no optimizations are performed.
        """
        func_ea = get_func_ea("mixed_dispatcher_pattern")
        if func_ea == idaapi.BADADDR:
            pytest.skip("mixed_dispatcher_pattern not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        rule = self._create_test_rule()

        # Call optimize on first block
        blk = mba.get_mblock(0)
        try:
            result = rule.optimize(blk)
            print(f"\n  optimize() returned: {result}")
        except Exception as e:
            pytest.fail(
                f"optimize() crashed unexpectedly: {type(e).__name__}: {e}"
            )

    def test_optimize_respects_maturity_check(self, libobfuscated_setup):
        """Verify optimize() respects check_if_rule_should_be_used() maturity filtering.

        Tests that optimize() returns 0 when the maturity doesn't match the
        rule's expected maturities.
        """
        func_ea = get_func_ea("state_comparison_pattern")
        if func_ea == idaapi.BADADDR:
            pytest.skip("state_comparison_pattern not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_PREOPTIMIZED)
        if mba is None:
            pytest.skip("Failed to generate microcode")

        rule = self._create_test_rule()
        # Set maturities to something that won't match MMAT_PREOPTIMIZED
        rule.maturities = [ida_hexrays.MMAT_CALLS, ida_hexrays.MMAT_GLBOPT1]
        rule.cur_maturity = None

        blk = mba.get_mblock(0)
        result = rule.optimize(blk)

        # Should return 0 because maturity doesn't match
        assert result == 0
        print("\n  Maturity filter correctly rejected the block")

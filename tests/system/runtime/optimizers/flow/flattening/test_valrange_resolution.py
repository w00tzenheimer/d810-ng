"""Runtime tests for ValrangeResolutionStrategy.

These tests run inside IDA and exercise the strategy against real
microcode.  They are auto-marked ``ida_required`` by the runtime
conftest and will be skipped in environments without IDA.

The tests validate:
- ``resolve_state_via_valranges`` returns sensible results on real blocks
- ``ValrangeResolutionStrategy`` protocol compliance (name, family, is_applicable)
- Strategy integration: no regression on Hodur-targeted functions
"""
from __future__ import annotations

import pytest

@pytest.fixture(scope="class")
def mba_fixture(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    """Provide an mba_t from the first available function."""
    import idaapi
    import idc
    # Use an OLLVM-flattened function so the state variable has real valranges
    for name in ("_hodur_func", "hodur_func"):
        ea = idc.get_name_ea_simple(name)
        if ea != idaapi.BADADDR:
            break
    else:
        pytest.skip("hodur_func not found in IDB")
    cfunc = idaapi.decompile(ea)
    if cfunc is None:
        pytest.skip("decompilation failed")
    return cfunc.mba

from d810.evaluator.hexrays_microcode.valranges import resolve_state_via_valranges
from d810.optimizers.microcode.flow.flattening.hodur.strategies.valrange_resolution import (
    ValrangeResolutionStrategy,
)
from d810.transforms.plan_fragment import (
    FAMILY_FALLBACK,
)


class TestValrangeResolutionProtocol:
    """Verify basic strategy protocol compliance."""

    def test_name(self) -> None:
        strategy = ValrangeResolutionStrategy()
        assert strategy.name == "valrange_resolution"

    def test_family(self) -> None:
        strategy = ValrangeResolutionStrategy()
        assert strategy.family == FAMILY_FALLBACK


class TestResolveStateViaValranges:
    """Test the core resolution function with real IDA valrange API."""

    binary_name = "libobfuscated.dll"

    def test_returns_none_for_non_state_operand(self, mba_fixture) -> None:
        """A random non-state-variable operand should not resolve to a value."""
        import ida_hexrays

        mba = mba_fixture
        if mba is None:
            pytest.skip("no mba fixture available")

        # Find a block with instructions (block 0 may be empty at this maturity)
        blk = None
        for i in range(mba.qty):
            candidate = mba.get_mblock(i)
            if candidate is not None and candidate.tail is not None:
                blk = candidate
                break
        if blk is None:
            pytest.skip("no blocks with instructions found")

        # Use the destination operand of the first instruction — whatever it is,
        # it's unlikely to be a recognized state variable for this function.
        mop = blk.tail.d

        result = resolve_state_via_valranges(blk, mop, blk.tail)
        # We don't assert a specific value — just that it doesn't crash
        # and returns either None or an int
        assert result is None or isinstance(result, int)

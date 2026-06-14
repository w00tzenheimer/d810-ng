"""Runtime regression test: concolic engine recovers a GLOBAL-CARRIED next-state.

Ticket llr-k8oa.  ``approov_vm_dispatcher`` is a real switch state machine whose
entry-state (``0xF6A1F``) writes its next state THROUGH a writable ``.data`` global:

    case 0xF6A1F:  opcode = (int)(approov_qword |= 0xF6A20);  // -> 0xF6A20

Before the fix the :class:`ConcolicEmulationEngine` abstained (``recover -> None``,
map_rows=0) on this shape for two compounding reasons, both verified against the live
binary and both fixed here:

* **read/write slot split** -- the dispatcher COMPARES a header copy of the slot the
  handlers WRITE (``var_C = var_8`` at the loop head), so anchoring on the compared
  copy made initial-state recovery + the handler write-scan miss everything.  The
  engine now follows the dispatcher-header copy back to the write-source slot
  (``_resolve_state_var_alias``), exactly like the legacy ``minimal_state_recovery``.
* **global-carried fold** -- the next-state write ``state = (int)approov_qword`` after
  ``approov_qword |= 0xF6A20`` cannot fold instruction-by-instruction (the writable
  global read is "not defined" in a fresh env).  The block fold now steps the WHOLE
  block via the proven legacy forward-fold with reaching-defs-sound initializer folding
  (``foldable_global_reads``), so the in-block ``|=`` write + readback resolves.

The result is map_rows 0 -> 3 with the global-carried transition
``0xF6A1F -> 0xF6A20`` recovered.  IDA-dependent (live ``mba`` + ``.data`` reads) ->
system/runtime.
"""
from __future__ import annotations

import os
import platform

import pytest

import ida_hexrays
import idaapi
import idc

from d810.analyses.control_flow.dispatcher_recovery import build_dispatch_map_any_kind
from d810.backends.hexrays.evidence.bst_analysis import build_bst_walker_provider
from d810.backends.hexrays.evidence.concolic_emulation_engine import (
    ConcolicEmulationEngine,
)
from d810.backends.hexrays.evidence.dispatcher_anchor_discovery import discover_anchors
from d810.backends.hexrays.lifter import lift_function
from d810.capabilities.providers import register_bst_walkers

#: The entry-state handler's global-carried next-state (Approov source line
#: ``opcode = (int)(approov_qword |= 1010208)`` -> 0xF6A20).
_ENTRY_STATE = 0xF6A1F
_GLOBAL_CARRIED_NEXT = 0xF6A20
_STATE_B_NEXT = 0xF6A1E  # case 0xF6A20: opcode = 0xF6A1E (direct write)


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"


def _get_func_ea(name: str) -> int:
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)
    return ea


@pytest.fixture(scope="class")
def approov_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    # The global fold consumes the live BST walker provider (forward_eval_insn +
    # fetch_idb_value); start_d810 registers it in production, here we do it directly.
    register_bst_walkers(build_bst_walker_provider())
    return ida_database


class TestConcolicGlobalCarriedNextState:
    """The concolic engine recovers a global-carried state machine (llr-k8oa)."""

    binary_name = _get_default_binary()

    def test_concolic_recovers_global_carried_next_state(self, approov_setup) -> None:
        func_ea = _get_func_ea("approov_vm_dispatcher")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_vm_dispatcher' not found")

        func = idaapi.get_func(func_ea)
        mbr = ida_hexrays.mba_ranges_t(func)
        hf = ida_hexrays.hexrays_failure_t()
        mba = ida_hexrays.gen_microcode(
            mbr, hf, None, ida_hexrays.DECOMP_NO_WAIT, ida_hexrays.MMAT_CALLS
        )
        assert mba is not None, "microcode generation failed"

        graph = lift_function(mba, maturity=mba.maturity).flow_graph
        prelim = build_dispatch_map_any_kind(graph, min_state_constant=0x10000)
        anchors = discover_anchors(mba, graph, prelim)
        assert anchors is not None
        # Production anchors on the COMPARED slot; the engine must follow the
        # dispatcher-header copy to the write slot internally.
        engine = ConcolicEmulationEngine(mba=mba, enabled=True)
        machine = engine.recover(graph, anchors)

        assert machine is not None, (
            "concolic engine abstained (map_rows=0) on the global-carried machine"
        )
        # map_rows 0 -> >=3 (the three reachable states).
        states = {int(r.state_const) for r in machine.rows}
        assert _ENTRY_STATE in states
        assert _GLOBAL_CARRIED_NEXT in states
        assert len(machine.rows) >= 3

        # The global-carried transition 0xF6A1F -> 0xF6A20 is recovered.
        by_src = {
            int(t.src_state): {int(s) for s in t.next_states}
            for t in machine.transitions
        }
        assert by_src.get(_ENTRY_STATE) == {_GLOBAL_CARRIED_NEXT}, (
            "global-carried next-state 0xF6A1F -> 0xF6A20 not recovered: "
            f"{by_src.get(_ENTRY_STATE)!r}"
        )
        # The sibling direct-write transition still resolves (no regression).
        assert by_src.get(_GLOBAL_CARRIED_NEXT) == {_STATE_B_NEXT}

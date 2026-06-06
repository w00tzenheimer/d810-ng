"""Phase 1: reconstruct lab_flat_mini's linear CFG via block INSERT (not patch).

Runs in the Docker IDA harness with D810_TEST_BINARY=restructuring_lab.dll.
See samples/restructuring_lab/specs/2026-06-06-insert-unflatten-phase1.md.
"""
from __future__ import annotations

import os

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")
import idaapi

from tests.system.runtime.conftest import gen_microcode_at_maturity, get_func_ea
from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier

FUNCTION = "lab_flat_mini"
# Large-const states from the fixture.
STATE_K0 = 0xC6685257
STATE_K1 = 0xB92456DE
STATE_K2 = 0x3C8960A9
STATE_TERM = 0x1A2B3C4D


def _map_state_machine(mba):
    """Map the flattened state machine by dest-filtered state writes.

    Returns (writers, dispatcher, terminal, state_dest) where writers maps each
    next-state constant -> the serial of the block that writes it (the handler),
    dispatcher is the loop header all handlers return to, and terminal is the
    block whose successor is the BLT_STOP exit.
    """
    # state slot = dest of the m_mov writing the init state K0.
    state_dest = None
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        ins = blk.head if blk else None
        while ins is not None:
            if int(ins.opcode) == ida_hexrays.m_mov and ins.l is not None \
               and ins.l.t == ida_hexrays.mop_n \
               and (int(ins.l.nnn.value) & 0xFFFFFFFF) == STATE_K0 and ins.d is not None:
                state_dest = ins.d.dstr()
                break
            ins = ins.next
        if state_dest is not None:
            break
    writers: dict[int, int] = {}
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        ins = blk.head if blk else None
        while ins is not None:
            if int(ins.opcode) == ida_hexrays.m_mov and ins.l is not None \
               and ins.l.t == ida_hexrays.mop_n and ins.d is not None \
               and ins.d.dstr() == state_dest:
                v = int(ins.l.nnn.value) & 0xFFFFFFFF
                if v in (STATE_K1, STATE_K2, STATE_TERM):
                    writers[v] = blk.serial
            ins = ins.next
    succ_sets = [
        set(int(s) for s in mba.get_mblock(w).succset) for w in writers.values()
    ]
    common = set.intersection(*succ_sets) if succ_sets else set()
    dispatcher = min(common) if common else -1
    stop = next(
        (i for i in range(mba.qty)
         if mba.get_mblock(i).type == ida_hexrays.BLT_STOP),
        mba.qty - 1,
    )
    terminal = -1
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk.type != ida_hexrays.BLT_STOP and stop in [int(s) for s in blk.succset]:
            terminal = i
            break
    return writers, dispatcher, terminal, state_dest


def _build_insert_plan(mba):
    """Return the ordered list of (source, final_target, old_target) inserts that
    rewire the dispatcher loop into the linear handler chain."""
    writers, disp, terminal, _ = _map_state_machine(mba)
    h0, h1, h2 = writers[STATE_K1], writers[STATE_K2], writers[STATE_TERM]
    # H0 -> H1 -> H2 -> terminal; each redirected off the dispatcher.
    return [(h0, h1, disp), (h1, h2, disp), (h2, terminal, disp)], disp


class TestInsertUnflattenMini:
    # ida_database reads this CLASS attribute to pick which binary to open.
    binary_name = os.environ.get("D810_TEST_BINARY", "restructuring_lab.dll")

    def test_baseline_is_flattened(self, ida_database, configure_hexrays):
        """Sanity: lab_flat_mini decompiles to a dispatcher loop (it is flattened)."""
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")
        ea = get_func_ea(FUNCTION)
        assert ea != idaapi.BADADDR, f"symbol not found: {FUNCTION}"
        cfunc = idaapi.decompile(ea)
        assert cfunc is not None
        text = str(cfunc)
        up = text.upper()
        assert ("WHILE" in up) or ("FOR" in up) or ("DO" in up), text
        assert (f"{STATE_K1:X}" in up) or (f"{STATE_K1:#X}"[2:] in up), text

    def test_dump_structure_across_maturities(self, ida_database, configure_hexrays):
        """Diagnostic: identify the state slot, then map handlers by dest-filtered
        state writes (filters out clang's compare-load movs)."""
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")
        ea = get_func_ea(FUNCTION)
        for label, mat in [("CALLS", ida_hexrays.MMAT_CALLS),
                           ("GLBOPT1", ida_hexrays.MMAT_GLBOPT1)]:
            mba = gen_microcode_at_maturity(ea, mat)
            if mba is None:
                print(f"\n=== {label}: None ===")
                continue
            # 1) state slot = dest of the m_mov writing the INIT state K0.
            state_dest = None
            for i in range(mba.qty):
                blk = mba.get_mblock(i)
                ins = blk.head if blk else None
                while ins is not None:
                    if int(ins.opcode) == ida_hexrays.m_mov and ins.l is not None \
                       and ins.l.t == ida_hexrays.mop_n \
                       and (int(ins.l.nnn.value) & 0xFFFFFFFF) == STATE_K0 \
                       and ins.d is not None:
                        state_dest = ins.d.dstr()
                        break
                    ins = ins.next
                if state_dest is not None:
                    break
            print(f"\n=== {label}: qty={mba.qty} state_slot={state_dest!r} ===")
            for i in range(mba.qty):
                blk = mba.get_mblock(i)
                if blk is None:
                    continue
                succs = [int(s) for s in blk.succset]
                preds = [int(p) for p in blk.predset]
                tail = blk.tail
                tail_op = int(tail.opcode) if tail is not None else -1
                # real state write: m_mov, immediate in l, dest == state slot.
                sw = None
                ins = blk.head
                while ins is not None:
                    if int(ins.opcode) == ida_hexrays.m_mov and ins.l is not None \
                       and ins.l.t == ida_hexrays.mop_n and ins.d is not None \
                       and ins.d.dstr() == state_dest:
                        sw = hex(int(ins.l.nnn.value) & 0xFFFFFFFF)
                    ins = ins.next
                stag = f" STATE_WRITE={sw}" if sw else ""
                print(f"  blk[{i}] type={int(blk.type)} preds={preds} "
                      f"succs={succs} tail_op={tail_op}{stag}")
        # The mapping helper must resolve a clean 3-handler machine at GLBOPT1.
        mba = gen_microcode_at_maturity(ea, ida_hexrays.MMAT_GLBOPT1)
        writers, disp, terminal, _sd = _map_state_machine(mba)
        assert set(writers) == {STATE_K1, STATE_K2, STATE_TERM}, writers
        assert disp >= 0 and terminal >= 0, (disp, terminal)

    def test_insert_verifies_clean(self, ida_database, configure_hexrays):
        """Insert private blocks rewiring the dispatcher loop into a linear chain
        on a live GLBOPT1 mba; assert mba.verify() is clean (no INTERR)."""
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")
        ea = get_func_ea(FUNCTION)
        mba = gen_microcode_at_maturity(ea, ida_hexrays.MMAT_GLBOPT1)
        assert mba is not None
        plan, disp = _build_insert_plan(mba)
        assert len(plan) == 3 and disp >= 0, f"bad plan: {plan} disp={disp}"
        mod = DeferredGraphModifier(mba)
        for src, final, old in plan:
            mod.queue_create_and_redirect(src, final, [], old_target_serial=old)
        mod.coalesce()
        applied = mod.apply(run_optimize_local=True, enable_snapshot_rollback=True)
        print(f"\n=== insert plan={plan} applied={applied} ===")
        assert applied >= 3, f"expected >=3 inserts applied, got {applied}"
        # mba.verify(True) raises on INTERR; no exception == clean.
        verify_ok = True
        try:
            mba.verify(True)
        except Exception as exc:  # noqa: BLE001
            verify_ok = False
            print(f"=== mba.verify FAILED: {exc} ===")
        assert verify_ok, "mba.verify() reported INTERR after insert"

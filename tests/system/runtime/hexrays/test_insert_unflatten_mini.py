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
STATE_CONSTS = frozenset({STATE_K0, STATE_K1, STATE_K2, STATE_TERM})


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

    @pytest.mark.xfail(
        reason="Live render via glbopt-stage mutation trips INTERR 50346 at ctree. "
        "Reverse-engineered (hexx64 mba_finalize_glbopt__verify_graphcache_50346): "
        "50346 fires when the mba graph/chains cache (mbl_graph_t at *(mba+0x310)) "
        "is left dirty at the post-glbopt finalizer. The cheap post-mutation fixes "
        "(mark_chains_dirty + build_graph) do NOT clear the structural dirty bit0, "
        "so clean live render requires mutating in the optblock/GLBOPT1 pass (d810 "
        "BlockOptimizerManager) where IDA manages this cache. Insert VALIDITY is "
        "already proven by test_insert_verifies_clean.",
        strict=False,
    )
    def test_insert_renders_linear(self, ida_database, configure_hexrays):
        """Apply the insert plan during a live decompile (one-shot GLBOPT1 hook)
        and assert the pseudocode renders without the dispatcher loop.

        XFAIL (see marker): glbopt is the wrong mutation stage; tracked follow-up.
        """
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")
        ea = get_func_ea(FUNCTION)

        class _InsertHook(ida_hexrays.Hexrays_Hooks):
            def __init__(self):
                super().__init__()
                self.done = False
                self.calls = 0
                self.applied = 0
                self.verify_ok = None
                self.error = None

            def glbopt(self, mba):  # noqa: D401
                self.calls += 1
                if self.done:
                    return 0
                try:
                    plan, disp = _build_insert_plan(mba)
                except Exception as exc:  # noqa: BLE001
                    self.error = f"plan: {exc}"
                    return 0
                if len(plan) != 3 or disp < 0:
                    self.error = f"bad plan {plan} disp={disp}"
                    return 0
                mod = DeferredGraphModifier(mba)
                for src, final, old in plan:
                    mod.queue_create_and_redirect(src, final, [], old_target_serial=old)
                mod.coalesce()
                self.applied = mod.apply(
                    run_optimize_local=True, enable_snapshot_rollback=True
                )
                # Post-mutation cache hygiene. NOTE (reverse-engineered): these are
                # NECESSARY but NOT SUFFICIENT at the glbopt stage -- the finalizer
                # mba_finalize_glbopt__verify_graphcache_50346 still sees the
                # structural dirty bit0 of *(mba+0x310)+0x30 and raises INTERR 50346.
                # Only optblock/GLBOPT1-stage mutation clears it (see xfail reason).
                mba.mark_chains_dirty()
                try:
                    mba.build_graph()
                except Exception as exc:  # noqa: BLE001
                    self.error = "build_graph: %r" % exc
                try:
                    mba.verify(True)
                    self.verify_ok = True
                except Exception as exc:  # noqa: BLE001
                    self.verify_ok = False
                    self.error = f"verify: {exc}"
                self.done = True
                return 0

        hook = _InsertHook()
        assert hook.hook()
        hf = ida_hexrays.hexrays_failure_t()
        try:
            ida_hexrays.mark_cfunc_dirty(ea)  # bypass the baseline cfunc cache
            cfunc = ida_hexrays.decompile(ea, hf)
        finally:
            hook.unhook()
        print(f"\n=== decompile: calls={hook.calls} applied={hook.applied} "
              f"verify_ok={hook.verify_ok} hook_err={hook.error} "
              f"hf.code={hf.code} hf.errea={hf.errea:#x} hf.desc={hf.desc()!r} ===")
        assert cfunc is not None, f"decompile failed: code={hf.code} {hf.desc()!r}"
        text = str(cfunc)
        print(f"\n=== rendered (calls={hook.calls} applied={hook.applied} "
              f"verify_ok={hook.verify_ok} error={hook.error}) ===")
        print(text)
        print("=== end render ===")
        assert hook.applied >= 3, f"hook applied={hook.applied}; mutation did not fire"
        assert hook.verify_ok, "mba.verify() reported INTERR after insert"
        up = text.upper()
        # Dispatcher gone: the state-compare constants no longer appear.
        assert f"{STATE_K1:X}" not in up, f"K1 dispatcher const survived:\n{text}"
        assert f"{STATE_K2:X}" not in up, f"K2 dispatcher const survived:\n{text}"
        # Linear: no dispatcher loop.
        assert "WHILE" not in up, f"dispatcher loop survived:\n{text}"

    def test_insert_renders_linear_optblock(self, ida_database, configure_hexrays):
        """Apply the insert plan via an optblock_t during the GLBOPT1 pass (not the
        glbopt notification). Returning the change count makes IDA re-run
        optimization, which rebuilds the graph/chains cache and clears the dirty
        bit that otherwise raises INTERR 50346 -- so the function renders."""
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")
        ea = get_func_ea(FUNCTION)

        class _InsertOptblock(ida_hexrays.optblock_t):
            def __init__(self):
                super().__init__()
                self.done = False
                self.applied = 0
                self.error = None

            def func(self, blk):  # returns number of changes
                try:
                    mba = blk.mba
                    if (self.done or mba is None
                            or int(mba.maturity) != int(ida_hexrays.MMAT_GLBOPT1)):
                        return 0
                    plan, disp = _build_insert_plan(mba)
                    if len(plan) != 3 or disp < 0:
                        return 0
                    self.done = True  # one-shot; set before apply (re-entrancy)
                    mod = DeferredGraphModifier(mba)
                    for src, final, old in plan:
                        mod.queue_create_and_redirect(src, final, [], old_target_serial=old)
                    mod.coalesce()
                    self.applied = mod.apply(run_optimize_local=True)
                    return self.applied  # signal IDA: CFG changed, re-run + re-verify
                except Exception as exc:  # noqa: BLE001
                    self.error = repr(exc)
                    return 0

        opt = _InsertOptblock()
        opt.install()
        hf = ida_hexrays.hexrays_failure_t()
        try:
            ida_hexrays.mark_cfunc_dirty(ea)
            cfunc = ida_hexrays.decompile(ea, hf)
        finally:
            opt.remove()
        print(f"\n=== optblock render (applied={opt.applied} err={opt.error} "
              f"hf={hf.code}/{hf.desc()!r}) ===")
        if cfunc is not None:
            print(str(cfunc))
        print("=== end optblock render ===")
        assert opt.applied >= 3, f"optblock applied={opt.applied} err={opt.error}"
        assert cfunc is not None, f"decompile failed: {hf.code} {hf.desc()!r}"
        up = str(cfunc).upper()
        assert f"{STATE_K1:X}" not in up, f"K1 dispatcher const survived:\n{cfunc}"
        assert f"{STATE_K2:X}" not in up, f"K2 dispatcher const survived:\n{cfunc}"
        assert "WHILE" not in up, f"dispatcher loop survived:\n{cfunc}"


COND_FUNCTION = "lab_flat_cond"


def _state_slot(mba):
    """Return the real state-var slot. Several slots may receive state-constant
    writes (entry-conditional register temps, decoy copies); the true state var
    is distinguished by receiving the TERMINAL state (STATE_TERM) -- decoy copies
    only carry the routed next-states. Tie-break by write count."""
    writes: dict[str, list[int]] = {}
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        ins = blk.head if blk else None
        while ins is not None:
            if (int(ins.opcode) == ida_hexrays.m_mov and ins.l is not None
                    and ins.l.t == ida_hexrays.mop_n
                    and (int(ins.l.nnn.value) & 0xFFFFFFFF) in STATE_CONSTS
                    and ins.d is not None):
                writes.setdefault(ins.d.dstr(), []).append(int(ins.l.nnn.value) & 0xFFFFFFFF)
            ins = ins.next
    if not writes:
        return None
    term_slots = {d: v for d, v in writes.items() if STATE_TERM in v}
    pool = term_slots or writes
    return max(pool, key=lambda d: len(pool[d]))


def _state_writers(mba, state_dest):
    """value -> [serials] of blocks whose m_mov writes that immediate to the slot."""
    writers: dict[int, list[int]] = {}
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        ins = blk.head if blk else None
        while ins is not None:
            if (int(ins.opcode) == ida_hexrays.m_mov and ins.l is not None
                    and ins.l.t == ida_hexrays.mop_n and ins.d is not None
                    and ins.d.dstr() == state_dest):
                writers.setdefault(int(ins.l.nnn.value) & 0xFFFFFFFF, []).append(blk.serial)
            ins = ins.next
    return writers


def _dispatcher_routing(mba, state_dest=None):
    """Decode dispatcher m_jz/m_jnz compares -> {state_const K: handler serial}.

    The compared state often sits in a register (loaded from the slot), so we
    identify a dispatcher compare by its immediate being a KNOWN state constant
    rather than by matching the slot operand.
    """
    routing: dict[int, int] = {}
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk is None or blk.type != ida_hexrays.BLT_2WAY:
            continue
        tail = blk.tail
        if tail is None or int(tail.opcode) not in (ida_hexrays.m_jz, ida_hexrays.m_jnz):
            continue
        imm = None
        for op in (tail.l, tail.r):
            if op is not None and op.t == ida_hexrays.mop_n:
                v = int(op.nnn.value) & 0xFFFFFFFF
                if v in STATE_CONSTS:
                    imm = v
        if imm is None:
            continue
        tgt = int(tail.d.b) if (tail.d is not None and tail.d.t == ida_hexrays.mop_b) else None
        succs = [int(s) for s in blk.succset]
        other = [s for s in succs if s != tgt]
        # m_jz: taken target reached when state == imm; m_jnz: the inverse.
        if int(tail.opcode) == ida_hexrays.m_jz:
            handler = tgt
        else:
            handler = other[0] if other else None
        if handler is not None:
            routing[imm] = handler
    return routing


def _terminal_serial(mba):
    stop = next((i for i in range(mba.qty)
                 if mba.get_mblock(i).type == ida_hexrays.BLT_STOP), mba.qty - 1)
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk.type != ida_hexrays.BLT_STOP and stop in [int(s) for s in blk.succset]:
            return i
    return -1


def _build_cond_insert_plan(mba):
    """Reconstruct the conditional transition: redirect H0's arms to their real
    handlers and the handlers to the terminal, preserving the existing jcc.
    Returns (plan, dispatcher) where plan = [(source, final, old_target), ...]."""
    state_dest = _state_slot(mba)
    writers = _state_writers(mba, state_dest)
    routing = _dispatcher_routing(mba, state_dest)
    terminal = _terminal_serial(mba)
    arm_k1 = writers[STATE_K1][0]
    arm_k2 = writers[STATE_K2][0]
    h1 = routing[STATE_K1]
    h2 = routing[STATE_K2]
    # dispatcher = the block every redirected source currently flows to.
    succ_sets = [set(int(s) for s in mba.get_mblock(b).succset)
                 for b in (arm_k1, arm_k2, h1, h2)]
    disp = min(set.intersection(*succ_sets))
    plan = [
        (arm_k1, h1, disp),   # H0 taken arm -> H1
        (arm_k2, h2, disp),   # H0 fallthrough arm -> H2
        (h1, terminal, disp),  # H1 -> return
        (h2, terminal, disp),  # H2 -> return
    ]
    return plan, disp


class TestInsertUnflattenCond:
    """Phase 2: a flattened CONDITIONAL transition (H0 -> H1|H2) reconstructed
    into a real if/else branch via the conditional insert primitive."""

    binary_name = os.environ.get("D810_TEST_BINARY", "restructuring_lab.dll")

    def test_dump_cond_structure(self, ida_database, configure_hexrays):
        """Diagnostic: dump the conditional fixture's GLBOPT1 layout, marking the
        2-way (jcc) block, the dest-filtered state writes, and the dispatcher."""
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")
        ea = get_func_ea(COND_FUNCTION)
        mba = gen_microcode_at_maturity(ea, ida_hexrays.MMAT_GLBOPT1)
        assert mba is not None
        state_dest = None
        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            ins = blk.head if blk else None
            while ins is not None:
                if (int(ins.opcode) == ida_hexrays.m_mov and ins.l is not None
                        and ins.l.t == ida_hexrays.mop_n
                        and (int(ins.l.nnn.value) & 0xFFFFFFFF) == STATE_K0
                        and ins.d is not None):
                    state_dest = ins.d.dstr()
                    break
                ins = ins.next
            if state_dest is not None:
                break
        print(f"\n=== lab_flat_cond GLBOPT1 qty={mba.qty} state_slot={state_dest!r} ===")
        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            if blk is None:
                continue
            succs = [int(s) for s in blk.succset]
            preds = [int(p) for p in blk.predset]
            tail = blk.tail
            top = int(tail.opcode) if tail is not None else -1
            sw = None
            ins = blk.head
            while ins is not None:
                if (int(ins.opcode) == ida_hexrays.m_mov and ins.l is not None
                        and ins.l.t == ida_hexrays.mop_n and ins.d is not None
                        and ins.d.dstr() == state_dest):
                    v = int(ins.l.nnn.value) & 0xFFFFFFFF
                    if v in (STATE_K1, STATE_K2, STATE_TERM):
                        sw = hex(v)
                ins = ins.next
            two = "(2WAY)" if blk.type == ida_hexrays.BLT_2WAY else ""
            print(f"  blk[{i}] type={int(blk.type)}{two} preds={preds} succs={succs} "
                  f"tail_op={top}{' STATE_WRITE=' + sw if sw else ''}")
        assert state_dest is not None

    def test_cond_renders_branch_optblock(self, ida_database, configure_hexrays):
        """Reconstruct the conditional transition into a real if/else by
        redirecting H0's arms to their handlers (preserving the existing jcc) via
        the optblock-stage insert. Renders a branch, no dispatcher."""
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")
        ea = get_func_ea(COND_FUNCTION)

        class _CondOptblock(ida_hexrays.optblock_t):
            def __init__(self):
                super().__init__()
                self.done = False
                self.applied = 0
                self.plan = None
                self.error = None
                self.dbg = None

            def func(self, blk):
                try:
                    mba = blk.mba
                    if (self.done or mba is None
                            or int(mba.maturity) != int(ida_hexrays.MMAT_GLBOPT1)):
                        return 0
                    sd = _state_slot(mba)
                    writers = _state_writers(mba, sd)
                    routing = _dispatcher_routing(mba, sd)
                    term = _terminal_serial(mba)
                    self.dbg = (sd, dict(writers), dict(routing), term)
                    # Only act once the dispatcher is fully mapped; otherwise let
                    # a later pass retry (the live mba stabilizes during GLBOPT1).
                    if not (STATE_K1 in writers and STATE_K2 in writers
                            and STATE_K1 in routing and STATE_K2 in routing
                            and term >= 0):
                        return 0
                    arm_k1, arm_k2 = writers[STATE_K1][0], writers[STATE_K2][0]
                    h1, h2 = routing[STATE_K1], routing[STATE_K2]
                    succ_sets = [set(int(s) for s in mba.get_mblock(b).succset)
                                 for b in (arm_k1, arm_k2, h1, h2)]
                    inter = set.intersection(*succ_sets)
                    if not inter:
                        return 0
                    disp = min(inter)
                    plan = [(arm_k1, h1, disp), (arm_k2, h2, disp),
                            (h1, term, disp), (h2, term, disp)]
                    self.plan = plan
                    self.done = True
                    mod = DeferredGraphModifier(mba)
                    for src, final, old in plan:
                        mod.queue_create_and_redirect(src, final, [], old_target_serial=old)
                    mod.coalesce()
                    self.applied = mod.apply(run_optimize_local=True)
                    return self.applied
                except Exception as exc:  # noqa: BLE001
                    self.error = repr(exc)
                    return 0

        opt = _CondOptblock()
        opt.install()
        hf = ida_hexrays.hexrays_failure_t()
        try:
            ida_hexrays.mark_cfunc_dirty(ea)
            cfunc = ida_hexrays.decompile(ea, hf)
        finally:
            opt.remove()
        print(f"\n=== cond render (plan={opt.plan} applied={opt.applied} "
              f"err={opt.error} hf={hf.code}/{hf.desc()!r}) ===\nlive_maps={opt.dbg}")
        if cfunc is not None:
            print(str(cfunc))
        print("=== end cond render ===")
        assert opt.applied >= 4, f"applied={opt.applied} err={opt.error}"
        assert cfunc is not None, f"decompile failed: {hf.code} {hf.desc()!r}"
        up = str(cfunc).upper()
        # Dispatcher gone: state-routing constants absent.
        assert f"{STATE_K1:X}" not in up, f"K1 dispatcher const survived:\n{cfunc}"
        assert f"{STATE_K2:X}" not in up, f"K2 dispatcher const survived:\n{cfunc}"
        # Branch reconstructed: a two-arm if/else (the token&1 predicate).
        assert "IF (" in up, f"no if branch in render:\n{cfunc}"
        assert "ELSE" in up, f"no else arm (two-arm branch) in render:\n{cfunc}"
        # H0 ran before the branch; the taken arm's XOR survives folding.
        assert "0X11" in up, f"H0 effect missing:\n{cfunc}"
        assert "0X22" in up, f"taken-arm XOR missing:\n{cfunc}"
        # No dispatcher loop.
        assert "WHILE" not in up and "FOR (" not in up, f"loop survived:\n{cfunc}"


SHARED_FUNCTION = "lab_flat_shared"
# In lab_flat_shared: A,B write KS (==STATE_K2); SHARED writes KT (==STATE_TERM).
STATE_KS = STATE_K2


_CONTROL_OPS = frozenset({
    ida_hexrays.m_goto, ida_hexrays.m_jcnd,
    ida_hexrays.m_jnz, ida_hexrays.m_jz,
    ida_hexrays.m_jae, ida_hexrays.m_jb, ida_hexrays.m_ja, ida_hexrays.m_jbe,
    ida_hexrays.m_jg, ida_hexrays.m_jge, ida_hexrays.m_jl, ida_hexrays.m_jle,
})


def _capture_state_free(blk):
    """Return blk's live instructions with ALL state-constant writes (to any
    slot) and ALL control-flow removed -- the state-free straight-line payload to
    copy into private blocks. The inserted block supplies its own goto, so the
    captured body must carry neither dispatcher scaffolding nor a terminator.
    (Identity vs blk.tail is unreliable -- SWIG returns fresh wrappers -- so we
    strip control-flow by opcode.)"""
    insns = []
    ins = blk.head
    while ins is not None:
        op = int(ins.opcode)
        is_state_const_write = (op == ida_hexrays.m_mov and ins.l is not None
                                and ins.l.t == ida_hexrays.mop_n
                                and (int(ins.l.nnn.value) & 0xFFFFFFFF) in STATE_CONSTS)
        if not is_state_const_write and op not in _CONTROL_OPS:
            insns.append(ins)
        ins = ins.next
    return insns


class TestInsertUnflattenShared:
    """Phase 3: a SHARED block (2 preds) de-shared into two private copies emitted
    STATE-FREE via capture-then-insert (the captured payload omits state writes)."""

    binary_name = os.environ.get("D810_TEST_BINARY", "restructuring_lab.dll")

    def test_dump_shared_structure(self, ida_database, configure_hexrays):
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")
        ea = get_func_ea(SHARED_FUNCTION)
        mba = gen_microcode_at_maturity(ea, ida_hexrays.MMAT_GLBOPT1)
        assert mba is not None
        sd = _state_slot(mba)
        writers = _state_writers(mba, sd)
        routing = _dispatcher_routing(mba, sd)
        term = _terminal_serial(mba)
        # Per-slot state-const-write map (which slot is the real state var).
        per_slot: dict[str, list[str]] = {}
        for i in range(mba.qty):
            b = mba.get_mblock(i)
            ins = b.head if b else None
            while ins is not None:
                if (int(ins.opcode) == ida_hexrays.m_mov and ins.l is not None
                        and ins.l.t == ida_hexrays.mop_n
                        and (int(ins.l.nnn.value) & 0xFFFFFFFF) in STATE_CONSTS
                        and ins.d is not None):
                    per_slot.setdefault(ins.d.dstr(), []).append(
                        "blk%d:%#x" % (i, int(ins.l.nnn.value) & 0xFFFFFFFF))
                ins = ins.next
        print(f"\n=== lab_flat_shared GLBOPT1 qty={mba.qty} state_slot={sd!r} ===")
        print(f"  per_slot_state_writes={per_slot}")
        print(f"  writers={ {hex(k): v for k, v in writers.items()} }")
        print(f"  routing={ {hex(k): v for k, v in routing.items()} } terminal={term}")
        shared = routing.get(STATE_KS)
        if shared is not None:
            free = _capture_state_free(mba.get_mblock(shared))
            print(f"  SHARED=blk[{shared}] state-free insns: "
                  f"{[ins.dstr() for ins in free]}")
        # KS is written by BOTH A and B (2 preds to SHARED).
        assert len(writers.get(STATE_KS, [])) == 2, writers
        assert shared is not None

    def test_shared_deshare_optblock(self, ida_database, configure_hexrays):
        """De-share SHARED into two private STATE-FREE copies (one per path) via
        capture-then-insert at the optblock stage. The copies carry SHARED's work
        but no state writes by construction; assert the render has no state var."""
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")
        ea = get_func_ea(SHARED_FUNCTION)

        class _DeshareOptblock(ida_hexrays.optblock_t):
            def __init__(self):
                super().__init__()
                self.done = False
                self.applied = 0
                self.captured = None
                self.error = None

            def func(self, blk):
                try:
                    mba = blk.mba
                    if (self.done or mba is None
                            or int(mba.maturity) != int(ida_hexrays.MMAT_GLBOPT1)):
                        return 0
                    sd = _state_slot(mba)
                    writers = _state_writers(mba, sd)
                    routing = _dispatcher_routing(mba, sd)
                    term = _terminal_serial(mba)
                    arms = writers.get(STATE_KS, [])
                    shared = routing.get(STATE_KS)
                    if len(arms) != 2 or shared is None or term < 0:
                        return 0
                    free = _capture_state_free(mba.get_mblock(shared))
                    if not free:
                        return 0
                    self.captured = [ins.dstr() for ins in free]
                    succ_sets = [set(int(s) for s in mba.get_mblock(a).succset) for a in arms]
                    inter = set.intersection(*succ_sets)
                    if not inter:
                        return 0
                    disp = min(inter)
                    self.done = True
                    mod = DeferredGraphModifier(mba)
                    for arm in arms:
                        # Insert a private STATE-FREE copy of SHARED on each path.
                        mod.queue_create_and_redirect(
                            arm, term, list(free), old_target_serial=disp)
                    mod.coalesce()
                    self.applied = mod.apply(run_optimize_local=True)
                    return self.applied
                except Exception as exc:  # noqa: BLE001
                    self.error = repr(exc)
                    return 0

        opt = _DeshareOptblock()
        opt.install()
        hf = ida_hexrays.hexrays_failure_t()
        try:
            ida_hexrays.mark_cfunc_dirty(ea)
            cfunc = ida_hexrays.decompile(ea, hf)
        finally:
            opt.remove()
        print(f"\n=== shared de-share (applied={opt.applied} captured={opt.captured} "
              f"err={opt.error} hf={hf.code}/{hf.desc()!r}) ===")
        if cfunc is not None:
            print(str(cfunc))
        print("=== end shared de-share ===")
        assert opt.applied >= 2, f"applied={opt.applied} err={opt.error}"
        assert cfunc is not None, f"decompile failed: {hf.code} {hf.desc()!r}"
        up = str(cfunc).upper()
        # The de-shared SHARED block is STATE-FREE by construction: its state
        # constants (KS, written by the copies' source; KT, the terminal) are
        # gone -- the captured payload carried no state writes (not DCE).
        assert f"{STATE_KS:X}" not in up, f"SHARED state KS survived:\n{cfunc}"
        assert f"{STATE_TERM:X}" not in up, f"terminal state KT survived:\n{cfunc}"
        # SHARED's work (-0x33) was de-shared into the paths.
        assert "0X33" in up, f"SHARED work missing after de-share:\n{cfunc}"
        # No dispatcher loop; the two paths are a clean branch.
        assert "WHILE" not in up and "FOR (" not in up, f"loop survived:\n{cfunc}"
        assert "IF (" in up, f"branch missing:\n{cfunc}"
        # NOTE: the entry selector (K0/K1 in v1) is residual scaffolding from the
        # un-reconstructed entry conditional (reg-sourced; a Phase 2 entry
        # reconstruction, out of scope for this de-share demo).

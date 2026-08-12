"""Task 0.4: measure the two native-patch lifecycle strategies.

The plan's review finding P1 ("There is no safe IDA/Hex-Rays apply point") was
argued from the ``execute_sync`` contract rather than measured, and two shipping
implementations contradict it -- d810's own computed-goto resolver and retired-reference
both patch from the flowchart seam and return ``MERR_REDO``. This module replaces
the argument with numbers.

Strategy A  patch inside ``hxe_flowchart``, return ``MERR_REDO``
Strategy B  collect in the callback, write later off the callback, reanalyze,
            invalidate, decompile again

**Scope limit, stated up front.** idalib is headless and single-threaded, so this
measures *correctness, redo cost, re-entrancy and cache scope* -- not thread
affinity. ``execute_sync``/``MFF_WRITE`` exists to marshal onto IDA's main thread,
and headless has no second thread to marshal from, so the thread-safety half of
P1 is genuinely out of reach here and needs a GUI run
(``tools/scripts/run_ida_gui_docker.sh``). Do not read a green result here as
"patching from a Hex-Rays callback is thread-safe".

The site is found by shape, not hardcoded, so a recompiled fixture does not
silently retarget the experiment at the wrong bytes.
"""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.requires_ida, pytest.mark.runtime, pytest.mark.hexrays]

ida_auto = pytest.importorskip("ida_auto")
ida_bytes = pytest.importorskip("ida_bytes")
ida_funcs = pytest.importorskip("ida_funcs")
ida_gdl = pytest.importorskip("ida_gdl")
ida_hexrays = pytest.importorskip("ida_hexrays")
ida_ua = pytest.importorskip("ida_ua")
idaapi = pytest.importorskip("idaapi")

from d810.backends.ida.native_patch.encoder import (  # noqa: E402
    plan_direct_jump_region,
)

TARGET_FUNCTION = "fake_jump_opaque_predicate"


def _find_conditional_site(func_name: str):
    """Locate the first two-byte conditional branch in ``func_name``.

    Returns ``(ea, length, taken_target, fallthrough)``. Shape-matched rather
    than hardcoded: an address baked into the test would keep "passing" against
    unrelated bytes after the fixture is rebuilt.
    """
    ea = idaapi.get_name_ea(idaapi.BADADDR, func_name)
    if ea == idaapi.BADADDR:
        pytest.skip(f"{func_name} not present in fixture")
    func = ida_funcs.get_func(ea)
    assert func is not None

    insn = ida_ua.insn_t()
    cursor = func.start_ea
    while cursor < func.end_ea:
        length = ida_ua.decode_insn(insn, cursor)
        if length <= 0:
            cursor += 1
            continue
        feature = insn.get_canon_feature()
        mnem = ida_ua.print_insn_mnem(cursor)
        is_conditional = (
            mnem.startswith("j")
            and mnem != "jmp"
            and bool(feature & idaapi.CF_JUMP or insn.Op1.type == idaapi.o_near)
        )
        if is_conditional and length == 2:
            return cursor, length, insn.Op1.addr, cursor + length
        cursor += length
    pytest.skip(f"no two-byte conditional branch found in {func_name}")


def _successors(func_ea: int, block_tail_ea: int) -> set[int]:
    """Successor addresses of the basic block whose last instruction is at tail."""
    func = ida_funcs.get_func(func_ea)
    chart = ida_gdl.FlowChart(func, flags=ida_gdl.FC_PREDS)
    for block in chart:
        insn = ida_ua.insn_t()
        cursor, last = block.start_ea, None
        while cursor < block.end_ea:
            length = ida_ua.decode_insn(insn, cursor)
            if length <= 0:
                break
            last = cursor
            cursor += length
        if last == block_tail_ea:
            return {succ.start_ea for succ in block.succs()}
    return set()


def _decompile_text(ea: int) -> str:
    cfunc = ida_hexrays.decompile(ea)
    return str(cfunc) if cfunc is not None else ""


class _FlowchartPatcher(ida_hexrays.Hexrays_Hooks):
    """Strategy A: write from inside ``hxe_flowchart`` and force a rebuild.

    Records every invocation so re-entrancy is measured rather than assumed --
    the handler must not patch again on the rebuild it just requested, which is
    the one-redo guard both d810 and retired-reference implement.
    """

    def __init__(self, function_ea: int, patch_ea: int, data: bytes):
        super().__init__()
        self.function_ea = function_ea
        self.patch_ea = patch_ea
        self.data = data
        self.invocations = 0
        self.patches = 0
        self.redos = 0

    def flowchart(self, fc, mba, reachable_blocks, decomp_flags):
        if int(mba.entry_ea) != self.function_ea:
            return 0
        self.invocations += 1
        current = ida_bytes.get_bytes(self.patch_ea, len(self.data))
        if current == self.data:
            # Already normalized: this is the rebuild we asked for. Patching
            # again here is what turns a redo into an infinite loop.
            return 0
        ida_bytes.patch_bytes(self.patch_ea, self.data)
        self.patches += 1
        self.redos += 1
        return ida_hexrays.MERR_REDO


class TestLifecycleStrategyExperiment:
    binary_name = "fake_jumps.dll"

    def test_measure_both_strategies(self, ida_database, configure_hexrays):
        site_ea, size, taken, fallthrough = _find_conditional_site(TARGET_FUNCTION)
        func_ea = ida_funcs.get_func(site_ea).start_ea

        original = ida_bytes.get_bytes(site_ea, size)
        plan = plan_direct_jump_region(site_ea, site_ea + size, taken)
        assert plan.ok, plan.reason
        patched = plan.sequence.data
        assert len(patched) == size, "region must be filled exactly"

        report: list[str] = []

        def note(line: str) -> None:
            report.append(line)
            print(f"[phase0.4] {line}", flush=True)

        note(f"function      {TARGET_FUNCTION} @ {func_ea:#x}")
        note(
            f"site          {site_ea:#x} size={size} {original.hex()} -> {patched.hex()}"
        )
        note(f"targets       taken={taken:#x} fallthrough={fallthrough:#x}")

        before_succs = _successors(func_ea, site_ea)
        before_text = _decompile_text(func_ea)
        note(f"pre  succs    {sorted(hex(s) for s in before_succs)}")
        assert len(before_succs) == 2, (
            "expected a conditional block with two successors before patching; "
            f"got {sorted(hex(s) for s in before_succs)}"
        )

        # ---------------- Strategy A: patch in hxe_flowchart + MERR_REDO -----
        hooks = _FlowchartPatcher(func_ea, site_ea, patched)
        hooks.hook()
        try:
            ida_hexrays.mark_cfunc_dirty(func_ea)
            a_text = _decompile_text(func_ea)
        finally:
            hooks.unhook()

        a_bytes = ida_bytes.get_bytes(site_ea, size)
        a_succs = _successors(func_ea, site_ea)
        note(
            f"A: invocations={hooks.invocations} patches={hooks.patches} "
            f"redos={hooks.redos} bytes={a_bytes.hex()}"
        )
        note(f"A: succs      {sorted(hex(s) for s in a_succs)}")
        note(f"A: text_changed={a_text != before_text}")

        assert a_bytes == patched, "strategy A did not reach the database"
        assert hooks.patches == 1, (
            f"expected exactly one patch, got {hooks.patches} -- the one-redo "
            "guard is not holding"
        )
        assert hooks.invocations >= 2, (
            "expected the MERR_REDO to drive a second flowchart callback; "
            f"got {hooks.invocations}"
        )

        # THE FINDING. MERR_REDO rebuilds Hex-Rays from the patched bytes -- the
        # pseudocode below is already correct -- but it does not reanalyze the
        # database, so IDA's own flowchart still carries the dead fallthrough
        # edge. Anything that reads the IDB rather than the decompiler still
        # sees the pre-patch CFG. This is asserted, not tolerated: if a future
        # IDA makes MERR_REDO also reanalyze, this assertion fires and the
        # conclusion below needs revisiting.
        assert a_succs == before_succs, (
            "expected MERR_REDO to leave IDA's flowchart stale; it appears to "
            "reanalyze now, which would invalidate the mandatory-reanalysis "
            f"conclusion. before={sorted(hex(s) for s in before_succs)} "
            f"after={sorted(hex(s) for s in a_succs)}"
        )
        note("A: FINDING - pseudocode updated but IDA flowchart still stale")

        # ---------------- Strategy A': same, plus IDA reanalysis -------------
        ida_funcs.reanalyze_function(ida_funcs.get_func(func_ea))
        ida_auto.auto_wait()
        ida_hexrays.mark_cfunc_dirty(func_ea)
        a2_text = _decompile_text(func_ea)
        a2_succs = _successors(func_ea, site_ea)
        note(f"A': succs     {sorted(hex(s) for s in a2_succs)} (after reanalyze)")
        assert a2_succs != a_succs, "reanalysis did not refresh the flowchart"

        # ---------------- restore, so B starts from the same state -----------
        ida_bytes.patch_bytes(site_ea, original)
        ida_funcs.reanalyze_function(ida_funcs.get_func(func_ea))
        ida_auto.auto_wait()
        ida_hexrays.mark_cfunc_dirty(func_ea)
        restored = ida_bytes.get_bytes(site_ea, size)
        note(
            f"restored      {restored.hex()} succs={sorted(hex(s) for s in _successors(func_ea, site_ea))}"
        )
        assert restored == original

        # ---------------- Strategy B: deferred write, then reanalyze ---------
        ida_bytes.patch_bytes(site_ea, patched)
        ida_funcs.reanalyze_function(ida_funcs.get_func(func_ea))
        ida_auto.auto_wait()
        ida_hexrays.mark_cfunc_dirty(func_ea)
        b_text = _decompile_text(func_ea)
        b_bytes = ida_bytes.get_bytes(site_ea, size)
        b_succs = _successors(func_ea, site_ea)
        note(f"B: bytes={b_bytes.hex()} succs={sorted(hex(s) for s in b_succs)}")
        note(f"B: text_changed={b_text != before_text}")

        assert b_bytes == patched

        # ---------------- compare the arms -----------------------------------
        note(
            f"A  == B  pseudocode: {a_text == b_text}   successors: {a_succs == b_succs}"
        )
        note(
            f"A' == B  pseudocode: {a2_text == b_text}   successors: {a2_succs == b_succs}"
        )

        # Once A is followed by reanalysis it converges with B. That is the
        # actual conclusion: the two are not competing strategies, they are two
        # halves of one sequence. MERR_REDO owns the decompiler's view,
        # reanalysis owns the database's.
        assert a2_succs == b_succs, (
            "strategy A plus reanalysis should converge with strategy B; "
            f"A'={sorted(hex(s) for s in a2_succs)} B={sorted(hex(s) for s in b_succs)}"
        )
        assert a2_text == b_text, "A' and B produced different pseudocode"
        assert a_text == b_text, (
            "Hex-Rays should lift correctly from patched bytes under MERR_REDO "
            "even while the IDA flowchart is stale"
        )

        # ---------------- the normalization actually did something -----------
        assert b_succs == {taken}, (
            f"expected the fallthrough edge to disappear, leaving {taken:#x}; "
            f"got {sorted(hex(s) for s in b_succs)}"
        )
        assert fallthrough not in b_succs

        # ---------------- original-byte layer survives -----------------------
        original_layer = bytes(
            ida_bytes.get_original_byte(site_ea + offset) & 0xFF
            for offset in range(size)
        )
        note(
            f"original-byte layer preserved: {original_layer.hex()} == {original.hex()}"
        )
        assert original_layer == original, (
            "patch_bytes must preserve IDA's original-byte layer; without it "
            "there is nothing to revert to"
        )

        print("\n[phase0.4] === measurement summary ===")
        for line in report:
            print(f"[phase0.4] {line}")

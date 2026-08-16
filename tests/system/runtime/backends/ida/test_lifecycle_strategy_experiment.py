"""Task 0.4: measure the two native-patch lifecycle strategies.

The plan's review finding P1 ("There is no safe IDA/Hex-Rays apply point") was
argued from the ``execute_sync`` contract rather than measured, and two shipping
implementations contradict it -- d810's own computed-goto resolver and the
native-patch strategy both patch from the flowchart seam and return ``MERR_REDO``.
This module replaces
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

import json
from pathlib import Path

import pytest

pytestmark = [pytest.mark.requires_ida, pytest.mark.runtime, pytest.mark.hexrays]

ida_auto = pytest.importorskip("ida_auto")
ida_bytes = pytest.importorskip("ida_bytes")
ida_funcs = pytest.importorskip("ida_funcs")
ida_gdl = pytest.importorskip("ida_gdl")
ida_hexrays = pytest.importorskip("ida_hexrays")
ida_ua = pytest.importorskip("ida_ua")
idaapi = pytest.importorskip("idaapi")
idautils = pytest.importorskip("idautils")

from d810.backends.ida.native_patch.encoder import (  # noqa: E402
    plan_direct_jump_region,
)
from tests.system.runtime.support.mutation_witness import (  # noqa: E402
    MutationWitness,
)

TARGET_FUNCTION = "fake_jump_opaque_predicate"
_REPO_ROOT = Path(__file__).resolve().parents[5]


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
    the one-redo guard required by both strategies.
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


# =============================================================================
# Task 0.4 step 4: cache-scope measurement.
#
# The experiment above establishes that MERR_REDO refreshes Hex-Rays but does
# not reanalyze the database, and that ``mark_cfunc_dirty(ea)`` plus
# reanalysis converges the two. What it does not establish is *radius*:
# ``mark_cfunc_dirty(ea)`` is documented as function-scoped, so patching
# function F and marking F dirty says nothing about whether a *caller*'s
# cached decompilation, or a function that shares a tail/chunk with F,
# survives untouched or gets invalidated too. That is measured below rather
# than inferred from the documentation.
# =============================================================================


def _callers_of(func_ea: int) -> set[int]:
    """Distinct calling-function start EAs, found by decoding each xref site.

    A call is identified by ``CF_CALL`` on the referring instruction's
    decoded feature bits -- the same shape-based approach
    ``_find_conditional_site`` above uses for ``CF_JUMP`` -- rather than by
    xref *type* constants, so this does not depend on which xref-type enum a
    given IDA build exposes.
    """
    callers: set[int] = set()
    insn = ida_ua.insn_t()
    for ref_ea in idautils.CodeRefsTo(func_ea, 0):
        length = ida_ua.decode_insn(insn, ref_ea)
        if length <= 0:
            continue
        if not (insn.get_canon_feature() & idaapi.CF_CALL):
            continue
        caller_func = ida_funcs.get_func(ref_ea)
        if caller_func is None or caller_func.start_ea == func_ea:
            continue
        callers.add(caller_func.start_ea)
    return callers


def _find_skippable_instruction(func_ea: int) -> tuple[int, int, int] | None:
    """A ``(start_ea, end_ea, target_ea)`` direct-jump normalization site.

    Rather than requiring a two-byte conditional branch -- the fixture
    functions that have a caller (see the class docstring below) are
    straight-line, with no conditional at all -- this picks any instruction
    strictly inside the function's body (not the entry prologue, not the
    final instruction) that is at least 2 bytes long, so
    ``plan_direct_jump_region`` can always fit at least a rel8 jump.
    Collapsing ``[start_ea, end_ea)`` to a direct jump *to* ``end_ea`` elides
    exactly that one instruction's effect, which is what makes the resulting
    pseudocode observably different without needing a conditional at all --
    it is still the same primitive (``plan_direct_jump_region``), applied to
    a plain instruction instead of a ``jcc``.
    """
    func = ida_funcs.get_func(func_ea)
    if func is None:
        return None
    insn = ida_ua.insn_t()
    boundaries: list[tuple[int, int]] = []
    cursor = func.start_ea
    while cursor < func.end_ea:
        length = ida_ua.decode_insn(insn, cursor)
        if length <= 0:
            break
        boundaries.append((cursor, cursor + length))
        cursor += length
    if len(boundaries) < 3:
        return None
    candidates = [(s, e) for s, e in boundaries[1:-1] if e - s >= 2]
    if not candidates:
        return None
    start, end = max(candidates, key=lambda pair: pair[1] - pair[0])
    return start, end, end


def _scan_shared_tail_chunks() -> list[tuple[int, list[int]]]:
    """``(tail_chunk_ea, [owner_ea, ...])`` for every tail chunk with >1 owner.

    A function tail with more than one referer is code genuinely shared by
    more than one function (e.g. linker identical-code-folding) -- IDA's own
    concept (``func_t.refqty`` / ``get_fchunk_referer``), not a d810 one.
    This scans the whole binary rather than assuming a shared chunk exists.
    """
    shared: list[tuple[int, list[int]]] = []
    for idx in range(ida_funcs.get_fchunk_qty()):
        chunk = ida_funcs.getn_fchunk(idx)
        if chunk is None or not ida_funcs.is_func_tail(chunk):
            continue
        if chunk.refqty <= 1:
            continue
        owners = [
            ida_funcs.get_fchunk_referer(chunk.start_ea, i) for i in range(chunk.refqty)
        ]
        shared.append((chunk.start_ea, owners))
    return shared


def _pick_target_with_caller() -> tuple[int, set[int], tuple[int, int, int]]:
    """First function (by ea) with a fixture-owned caller and a normalizable site.

    "Fixture-owned" means at least one caller's name starts with
    ``fake_jump`` -- the fixture's own authored surface -- rather than
    accepting the first caller/callee edge found anywhere. Unfiltered, the
    first such edge in this binary is compiler/CRT startup plumbing
    (``_CRT_INIT`` called from ``__DllMainCRTStartup``), which is not a
    function d810 could plausibly own and normalize; this experiment is
    about the kind of edge d810's gateway would actually face. Restricting
    by *name* is not the address-hardcoding the task warns against -- names
    survive a fixture recompile the way addresses do not, and the existing
    ``TARGET_FUNCTION`` constant above already relies on the same property.
    Address order among the remaining candidates is deterministic for a
    fixed binary and IDA version and is not chosen for any other reason.
    """
    for func_ea in idautils.Functions():
        callers = _callers_of(func_ea)
        fixture_callers = {
            c
            for c in callers
            if (idaapi.get_func_name(c) or "").startswith("fake_jump")
        }
        if not fixture_callers:
            continue
        site = _find_skippable_instruction(func_ea)
        if site is None:
            continue
        return func_ea, fixture_callers, site
    pytest.skip(
        "fake_jumps.dll offers no function with both a fixture-owned caller "
        "and a normalizable instruction; try libobfuscated.dll instead"
    )


class TestCacheInvalidationRadius:
    """Task 0.4 step 4: measure the cfunc cache invalidation radius.

    ``mark_cfunc_dirty(ea)`` is documented as function-scoped. Whether a
    caller's cached decompilation -- or a shared-tail owner's -- survives a
    native patch to a *different* function is not stated anywhere and must
    not be inferred from that scoping. It is measured here, empirically, on
    this IDA build.

    Fixture choice and why: fake_jumps.dll, the same binary the strategy
    experiment above uses. Its eleven top-level ``fake_jump_*`` functions are
    each self-contained -- nothing in the binary calls them, so none of them
    can serve as F. Two of them, though (``fake_jump_after_call`` and
    ``fake_jump_after_constant_call``), call a tiny ``static`` helper
    (``always_returns_42`` / ``always_returns_99`` in the C source). The
    compiler outlines each helper as its own call target with its own
    prologue/epilogue rather than inlining it, and IDA recovers that as a
    distinct function reachable from exactly one caller -- confirmed by
    disassembling the actual compiled ``samples/bins/fake_jumps.dll``, not
    assumed from the source. That is a genuine caller/callee pair produced by
    the compiled shape, discovered below by decoding call xrefs at runtime --
    not by hand-editing the fixture or hardcoding an address. No
    multi-owner tail chunk (linker identical-code-folding or similar) was
    found anywhere in this binary by the generic scan below, so the
    "shared tail" leg of the measurement is reported absent rather than
    faked; libobfuscated.dll was not needed because fake_jumps.dll did supply
    the required caller relationship.
    """

    binary_name = "fake_jumps.dll"

    def test_measure_cache_invalidation_radius(self, ida_database, configure_hexrays):
        func_ea, callers, (skip_start, skip_end, skip_target) = (
            _pick_target_with_caller()
        )
        caller_ea = sorted(callers)[0]

        shared_chunks = _scan_shared_tail_chunks()
        shared_tail_ea: int | None = None
        shared_tail_note = "none found anywhere in this binary"
        for chunk_ea, owners in shared_chunks:
            if func_ea in owners or caller_ea in owners:
                others = [o for o in owners if o not in (func_ea, caller_ea)]
                if others:
                    shared_tail_ea = others[0]
                    shared_tail_note = (
                        f"chunk {chunk_ea:#x} owners={[hex(o) for o in owners]}"
                    )
                break

        probes: dict[str, int] = {"F": func_ea, "caller": caller_ea}
        if shared_tail_ea is not None:
            probes["shared_tail_owner"] = shared_tail_ea

        report: list[str] = []

        def note(line: str) -> None:
            report.append(line)
            print(f"[phase0.4-cachescope] {line}", flush=True)

        note(f"F               {func_ea:#x} ({idaapi.get_func_name(func_ea)})")
        note(f"F callers       {sorted(hex(c) for c in callers)}")
        note(f"caller probe    {caller_ea:#x} ({idaapi.get_func_name(caller_ea)})")
        note(f"shared tail     {shared_tail_note}")
        note(f"skip site       {skip_start:#x}..{skip_end:#x} -> {skip_target:#x}")

        original = ida_bytes.get_bytes(skip_start, skip_end - skip_start)
        plan = plan_direct_jump_region(skip_start, skip_end, skip_target)
        assert plan.ok, plan.reason
        patched = plan.sequence.data
        assert len(patched) == skip_end - skip_start, "region must be filled exactly"
        note(f"bytes           {original.hex()} -> {patched.hex()}")

        # ---------------- baseline: decompile every probe, cache must warm ---
        # Wrapped in a MutationWitness: this phase must be read-only, or the
        # "before" state compared against below would be contaminated by our
        # own setup rather than reflecting the pre-patch database.
        baseline_text: dict[str, str] = {}
        with MutationWitness() as witness:
            for label, ea in probes.items():
                baseline_text[label] = _decompile_text(ea)
            reading = witness.assert_clean("decompiling F/caller/shared-tail baselines")
        note(reading.describe())

        for label, ea in probes.items():
            assert ida_hexrays.has_cached_cfunc(ea), (
                f"decompile({label}@{ea:#x}) did not leave a cached cfunc; "
                "the staleness probe below would be meaningless with a cold "
                "cache to begin with"
            )

        # ---------------- the patch: F only -----------------------------------
        ida_bytes.patch_bytes(skip_start, patched)
        assert ida_bytes.get_bytes(skip_start, len(patched)) == patched

        ida_funcs.reanalyze_function(ida_funcs.get_func(func_ea))
        ida_auto.auto_wait()
        erased = ida_hexrays.mark_cfunc_dirty(func_ea)
        note(f"mark_cfunc_dirty(F) erased an existing cache entry: {erased}")
        assert erased, (
            "F had no cache entry to erase -- the baseline decompile above "
            "did not stick, so this run cannot measure anything"
        )

        # ---------------- THE MEASUREMENT ---------------------------------
        # has_cached_cfunc for every probe *before* calling decompile() again
        # anywhere: the ambient cache state left behind by patch_bytes +
        # reanalyze_function + auto_wait() + mark_cfunc_dirty(F) alone,
        # untouched by any decompilation of ours since the patch. That is the
        # invalidation radius -- which entries IDA/Hex-Rays itself discarded,
        # and which it left exactly as they were.
        pre_recompute_cached: dict[str, bool] = {}
        for label, ea in probes.items():
            pre_recompute_cached[label] = bool(ida_hexrays.has_cached_cfunc(ea))
            note(
                f"{label}@{ea:#x} has_cached_cfunc (before recompute) = "
                f"{pre_recompute_cached[label]}"
            )

        post_text: dict[str, str] = {}
        text_changed: dict[str, bool] = {}
        for label, ea in probes.items():
            post_text[label] = _decompile_text(ea)
            text_changed[label] = post_text[label] != baseline_text[label]
            note(f"{label}@{ea:#x} pseudocode changed = {text_changed[label]}")

        # ---------------- artifact: the observed invalidation set ------------
        artifact_dir = _REPO_ROOT / ".tmp" / "cfunc-cache-invalidation-radius"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        summary = {
            "ida_version": idaapi.get_kernel_version(),
            "function_names": {
                label: idaapi.get_func_name(ea) for label, ea in probes.items()
            },
            "addresses": {label: hex(ea) for label, ea in probes.items()},
            "callers_of_F": sorted(hex(c) for c in callers),
            "shared_tail": shared_tail_note,
            "patch_site": {
                "start_ea": hex(skip_start),
                "end_ea": hex(skip_end),
                "target_ea": hex(skip_target),
                "before": original.hex(),
                "after": patched.hex(),
            },
            "has_cached_cfunc_before_recompute": pre_recompute_cached,
            "pseudocode_changed_after_patch": text_changed,
        }
        artifact_path = artifact_dir / "summary.json"
        artifact_path.write_text(
            json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
        )
        note(f"artifact written to {artifact_path}")

        print("\n[phase0.4-cachescope] === measurement summary ===")
        for line in report:
            print(f"[phase0.4-cachescope] {line}")

        # ---------------- assertions on what was actually observed -----------
        # F is unconditionally expected to come back fresh: we erased its own
        # cache entry and changed its own bytes.
        assert pre_recompute_cached["F"] is False, (
            "mark_cfunc_dirty(F) is documented to erase F's own cache entry; "
            "has_cached_cfunc(F) should be False immediately afterward"
        )
        assert text_changed["F"], (
            "F's pseudocode did not change after eliding an instruction and "
            "reanalyzing; the patch had no effect Hex-Rays could see"
        )

        # EMPIRICAL AND VERSION-SPECIFIC. Everything below encodes what this
        # IDA build was actually observed to do to a caller's (and, if this
        # fixture ever grows one, a shared-tail owner's) cfunc cache when only
        # the callee is patched, reanalyzed and marked dirty. It is not a
        # specification of correct behavior -- d810's own gateway still has to
        # invalidate every affected function explicitly rather than trust
        # this. If a future IDA build changes this behavior, the assertion
        # below fails on purpose so the change is caught, not silently
        # assumed away; do not "fix" a failure here by relaxing it to a
        # tautology.
        assert pre_recompute_cached["caller"] is True, (
            "expected the caller's pre-existing cfunc cache entry to survive "
            "a patch to its callee -- patch_bytes + reanalyze_function + "
            "auto_wait() + mark_cfunc_dirty(F) does not appear to widen its "
            "reach to F's callers on this IDA build, which would mean a "
            "future gateway can no longer assume caller caches need "
            "separate invalidation"
        )
        assert not text_changed["caller"], (
            "the caller's pseudocode changed even though it was served from "
            "an untouched cache entry -- has_cached_cfunc() and the actual "
            "decompiled text disagree, which should not happen"
        )

        if "shared_tail_owner" in probes:
            note(
                "shared-tail owner probe present: "
                f"has_cached_cfunc={pre_recompute_cached['shared_tail_owner']} "
                f"text_changed={text_changed['shared_tail_owner']}"
            )

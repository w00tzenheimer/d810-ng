from __future__ import annotations

from dataclasses import dataclass
import os
import platform
from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.cfg.contracts.ida_contract import CfgContractViolationError
from d810.cfg.contracts.report import InvariantViolation
from d810.cfg.graph_modification import CreateConditionalRedirect
from d810.cfg.plan import compile_patch_plan
from d810.cfg.flowgraph import InsnSnapshot
from d810.hexrays.mutation import deferred_modifier as dm
from d810.hexrays.mutation.ir_translator import IDAIRTranslator
from d810.optimizers.microcode.flow.flattening import fix_pred_cond_jump_block as fix_pred
from d810.optimizers.microcode.flow.flattening.fix_pred_cond_jump_block import (
    FixPredecessorOfConditionalJumpBlock,
    PredecessorModification,
    PredecessorModificationType,
)
from d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family import (
    EMULATED_DISPATCHER_MODIFICATIONS_KEY,
    EmulatedDispatcherStrategyFamily,
)
from tests.system.runtime.conftest import gen_microcode_at_maturity, get_func_ea


class _FakeEdgeSet:
    """Minimal stub for IDA succset/predset (intvec_t-like interface)."""

    def __init__(self, items: list[int] | None = None):
        self._items: list[int] = list(items) if items else []

    def size(self) -> int:
        return len(self._items)

    def __getitem__(self, idx: int) -> int:
        return self._items[idx]

    def __iter__(self):
        return iter(list(self._items))

    def clear(self) -> None:
        self._items.clear()

    def push_back(self, val: int) -> None:
        self._items.append(val)

    def _del(self, val: int) -> None:
        try:
            self._items.remove(val)
        except ValueError:
            return None


class _FakeBlock:
    # Base EA for deriving stable start addresses for fake blocks.  The
    # staged_atomic Bug 3 fix re-resolves blocks by ``mblock_t.start``
    # (the block's byte-address range start, which IDA guarantees is
    # stable across serial-shifting mutations).  Every fake block now
    # has a default ``start`` derived from its initial serial.
    _DEFAULT_EA_BASE = 0x18000000

    def __init__(self, serial: int, *, start: int | None = None):
        self.serial = serial
        self.type = ida_hexrays.BLT_1WAY
        self.flags = 0
        self.tail = SimpleNamespace(opcode=ida_hexrays.m_goto, ea=0x1000, l=None, d=None, r=None)
        self.succset = _FakeEdgeSet()
        self.predset = _FakeEdgeSet()
        self.prevb = None
        # Stable byte-address range start (see class docstring).
        self.start = start if start is not None else self._DEFAULT_EA_BASE + serial * 0x100
        self.end = self.start + 0x100

    def nsucc(self) -> int:
        return 1

    def succ(self, _idx: int) -> int:
        return 0

    def npred(self) -> int:
        return 0

    def pred(self, _idx: int) -> int:
        return 0

    def mark_lists_dirty(self) -> None:
        return None


class _FakeMBA:
    def __init__(self):
        self.blocks = {0: _FakeBlock(0)}
        self.cleaned = 0
        self.marked_dirty = 0
        self.qty = len(self.blocks)
        self.entry_ea = 0x180000000

    def get_mblock(self, serial: int):
        return self.blocks.get(serial)

    def mark_chains_dirty(self):
        self.marked_dirty += 1

    def optimize_local(self, _flags: int):
        pass


def test_apply_aborts_on_first_failed_modification_and_cleans(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(mba)
    modifier.modifications = [
        dm.GraphModification(dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=0, new_target=1),
        dm.GraphModification(dm.ModificationType.INSN_NOP, block_serial=0, insn_ea=0x1000),
        dm.GraphModification(dm.ModificationType.INSN_REMOVE, block_serial=0, insn_ea=0x1001),
    ]

    calls: list[int] = []

    def _fake_apply_single(_mod):
        calls.append(1)
        # first succeeds, second fails -> must abort before third
        return len(calls) == 1

    monkeypatch.setattr(modifier, "_apply_single", _fake_apply_single)
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
    monkeypatch.setattr(
        dm,
        "mba_deep_cleaning",
        lambda *_a, **_k: setattr(mba, "cleaned", mba.cleaned + 1),
    )

    applied = modifier.apply(run_optimize_local=False, run_deep_cleaning=False)
    assert applied == 1
    assert len(calls) == 2
    assert mba.cleaned == 1


def test_apply_transactional_rolls_back_when_mid_batch_aborts(monkeypatch):
    """transactional=True must restore pre-snapshot if the loop breaks early.

    Non-transactional apply returns the partial count (1/3) and leaves the
    first mutation live on the MBA. Transactional apply on the same scenario
    must invoke the snapshot restore path and return 0.
    """
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(mba)
    modifier.modifications = [
        dm.GraphModification(dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=0, new_target=1),
        dm.GraphModification(dm.ModificationType.INSN_NOP, block_serial=0, insn_ea=0x1000),
        dm.GraphModification(dm.ModificationType.INSN_REMOVE, block_serial=0, insn_ea=0x1001),
    ]

    calls: list[int] = []

    def _fake_apply_single(_mod):
        calls.append(1)
        return len(calls) == 1

    restore_calls: list[object] = []

    def _fake_restore(_snap):
        restore_calls.append(_snap)
        return True

    monkeypatch.setattr(modifier, "_apply_single", _fake_apply_single)
    monkeypatch.setattr(modifier, "_restore_from_snapshot", _fake_restore)
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
    monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_a, **_k: None)
    monkeypatch.setattr(dm, "lift", lambda _m: SimpleNamespace(num_blocks=1, entry_serial=0))

    applied = modifier.apply(
        run_optimize_local=False, run_deep_cleaning=False, transactional=True,
    )
    assert applied == 0
    assert len(calls) == 2
    assert len(restore_calls) == 1


def test_apply_transactional_returns_full_count_when_all_mods_succeed(monkeypatch):
    """transactional=True must return the full applied count on success.

    No rollback should fire when every queued mod lands cleanly.
    """
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(mba)
    modifier.modifications = [
        dm.GraphModification(dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=0, new_target=1),
        dm.GraphModification(dm.ModificationType.INSN_NOP, block_serial=0, insn_ea=0x1000),
    ]

    restore_calls: list[object] = []

    monkeypatch.setattr(modifier, "_apply_single", lambda _mod: True)
    monkeypatch.setattr(
        modifier,
        "_restore_from_snapshot",
        lambda snap: restore_calls.append(snap) or True,
    )
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
    monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_a, **_k: None)
    monkeypatch.setattr(dm, "lift", lambda _m: SimpleNamespace(num_blocks=1, entry_serial=0))

    applied = modifier.apply(
        run_optimize_local=False, run_deep_cleaning=False, transactional=True,
    )
    assert applied == 2
    assert restore_calls == []


def test_apply_transactional_rejects_batch_with_contradictory_redirects(monkeypatch):
    """transactional=True must reject a batch where two BLOCK_GOTO_CHANGE
    mods on the same source block prescribe different targets.

    This is the Mode 1 pattern we observed on sub_7FFD3338C040:
        mod[26]: RedirectGoto src=76 tgt=11
        mod[75]: RedirectGoto src=76 tgt=2
    Both succeed individually; the pair cancels. The gate catches it
    before any live mutation so verify_failed is set and apply loop is
    never entered.
    """
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(mba)
    modifier.modifications = [
        dm.GraphModification(dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=76, new_target=11),
        dm.GraphModification(dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=76, new_target=2),
    ]

    apply_calls: list[int] = []
    monkeypatch.setattr(modifier, "_apply_single", lambda _mod: apply_calls.append(1) or True)
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
    monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_a, **_k: None)
    monkeypatch.setattr(dm, "lift", lambda _m: SimpleNamespace(num_blocks=1, entry_serial=0))

    applied = modifier.apply(
        run_optimize_local=False, run_deep_cleaning=False, transactional=True,
    )
    assert applied == 0
    # Apply loop must not have been entered.
    assert apply_calls == []
    assert modifier.verify_failed is True


def test_detect_transactional_batch_conflicts_direct():
    """Unit-test the gate's conflict-detection logic in isolation.

    Covers the decision predicate without running the full apply() flow,
    because the coalescer already deduplicates many same-(src, mod_type)
    pairs before the gate would see them. The gate is defense-in-depth
    for cases the coalescer misses (different old_targets etc.) and is
    easiest to validate directly.
    """
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(mba)

    # No conflict: single graph mod.
    modifier.modifications = [
        dm.GraphModification(dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=76, new_target=11),
    ]
    assert modifier._detect_transactional_batch_conflicts() is None

    # No conflict: graph mod + instruction mod on same block.
    modifier.modifications = [
        dm.GraphModification(dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=76, new_target=11),
        dm.GraphModification(dm.ModificationType.INSN_NOP, block_serial=76, insn_ea=0x1000),
    ]
    assert modifier._detect_transactional_batch_conflicts() is None

    # Conflict: two graph mods on blk[76] pointing at different targets.
    modifier.modifications = [
        dm.GraphModification(dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=76, new_target=11),
        dm.GraphModification(dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=76, new_target=2),
    ]
    reason = modifier._detect_transactional_batch_conflicts()
    assert reason is not None
    assert "blk[76]" in reason
    assert "new_targets" in reason

    # No conflict: same block, same target (redundant but consistent).
    modifier.modifications = [
        dm.GraphModification(dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=76, new_target=11),
        dm.GraphModification(dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=76, new_target=11),
    ]
    assert modifier._detect_transactional_batch_conflicts() is None


def test_apply_transactional_marks_verify_failed_when_rollback_itself_fails(monkeypatch):
    """If the snapshot restore call returns False, MBA is in an inconsistent
    state and verify_failed must be set so callers can abort gracefully.
    """
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(mba)
    modifier.modifications = [
        dm.GraphModification(dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=0, new_target=1),
        dm.GraphModification(dm.ModificationType.INSN_NOP, block_serial=0, insn_ea=0x1000),
    ]

    calls: list[int] = []

    def _fake_apply_single(_mod):
        calls.append(1)
        return False  # first one fails immediately

    monkeypatch.setattr(modifier, "_apply_single", _fake_apply_single)
    monkeypatch.setattr(modifier, "_restore_from_snapshot", lambda _snap: False)
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
    monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_a, **_k: None)
    monkeypatch.setattr(dm, "lift", lambda _m: SimpleNamespace(num_blocks=1, entry_serial=0))

    applied = modifier.apply(
        run_optimize_local=False, run_deep_cleaning=False, transactional=True,
    )
    # restore failed → we cannot claim successful rollback → return partial count
    # and signal verify_failed so the caller can quarantine the function.
    assert applied == 0
    assert modifier.verify_failed is True


def test_apply_transactional_rolls_back_alias_scalarization_verify_failure(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(mba)
    modifier.modifications = [
        dm.GraphModification(
            dm.ModificationType.INSN_SCALARIZE_LOCAL_ALIAS_ACCESS,
            block_serial=0,
            insn_ea=0x1000,
            host_opcode=ida_hexrays.m_ldx,
            alias_token="%var_378",
            base_token="%var_18",
            description="alias scalarization must rollback on verify failure",
        ),
    ]

    apply_calls = {"count": 0}
    restore_calls = {"count": 0}
    verify_calls = {"count": 0}

    def _apply_alias(*_args, **_kwargs):
        apply_calls["count"] += 1
        return True

    def _safe_verify(*_args, **_kwargs):
        verify_calls["count"] += 1
        if verify_calls["count"] == 2:
            raise RuntimeError("alias scalarization verify failure")

    monkeypatch.setattr(modifier, "_apply_scalarize_local_alias_access", _apply_alias)
    monkeypatch.setattr(
        modifier,
        "_restore_from_snapshot",
        lambda _snap: restore_calls.__setitem__("count", restore_calls["count"] + 1) or True,
    )
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", _safe_verify)
    monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_a, **_k: None)
    monkeypatch.setattr(dm, "lift", lambda _m: SimpleNamespace(num_blocks=1, entry_serial=0))

    applied = modifier.apply(
        run_optimize_local=False,
        run_deep_cleaning=False,
        verify_each_mod=True,
        rollback_on_verify_failure=True,
        transactional=True,
    )

    assert applied == 0
    assert apply_calls["count"] == 1
    assert restore_calls["count"] == 1
    assert modifier.verify_failed is False


def test_ollvm_local_alias_mem2reg_uses_transactional_verified_apply(monkeypatch):
    from d810.optimizers.microcode.flow.flattening import (
        emulated_dispatcher_family as edf,
    )
    from d810.recon.facts.carrier import (
        LIFECYCLE_PRODUCTION_PROVEN,
        LOCAL_STORAGE_SCALARIZATION_FACT_KIND,
    )

    class _Mop:
        def __init__(self, text: str):
            self._text = text
            self.size = 4

        def dstr(self) -> str:
            return self._text

    insn = SimpleNamespace(
        opcode=ida_hexrays.m_ldx,
        ea=0x18000F123,
        r=_Mop("[ds.2:%var_378.8].4"),
        d=_Mop("%var_420.4"),
        next=None,
    )
    block = _FakeBlock(0)
    block.head = insn
    block.make_lists_ready = lambda: None  # type: ignore[attr-defined]
    mba = _FakeMBA()
    mba.blocks = {0: block}
    mba.qty = 1

    created_modifiers = []

    class _FakeModifier:
        def __init__(self, _mba):
            self.queued = []
            self.apply_kwargs = {}
            self.verify_failed = False
            created_modifiers.append(self)

        def queue_scalarize_local_alias_access(self, *args, **kwargs):
            self.queued.append((args, kwargs))

        def apply(self, **kwargs):
            self.apply_kwargs = dict(kwargs)
            return len(self.queued)

    fact = SimpleNamespace(
        kind=LOCAL_STORAGE_SCALARIZATION_FACT_KIND,
        fact_id="local-scalarization",
        payload={
            "lifecycle_status": LIFECYCLE_PRODUCTION_PROVEN,
            "storage_identity": "%var_378",
            "details": {
                "proof_family": "local_expression_storage_scalarization",
                "local_base_token": "%var_18",
            },
        },
    )
    verify_calls = {"count": 0}

    monkeypatch.setattr(dm, "DeferredGraphModifier", _FakeModifier)
    monkeypatch.setattr(
        edf,
        "_verify_ollvm_carrier_mutation",
        lambda *_args, **_kwargs: verify_calls.__setitem__("count", verify_calls["count"] + 1),
    )

    applied = edf._apply_local_alias_mem2reg(
        mba,
        SimpleNamespace(info=lambda *_a, **_k: None, warning=lambda *_a, **_k: None),
        (fact,),
    )

    assert applied == 1
    assert verify_calls["count"] == 1
    assert len(created_modifiers) == 1
    assert len(created_modifiers[0].queued) == 1
    assert created_modifiers[0].apply_kwargs == {
        "run_optimize_local": True,
        "run_deep_cleaning": False,
        "verify_each_mod": True,
        "rollback_on_verify_failure": True,
        "transactional": True,
    }


def test_apply_tolerates_queued_mod_logging_introspection_failure(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(mba)
    modifier.modifications = [
        dm.GraphModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE,
            block_serial=0,
            new_target=0,
            description="self-loop debug case",
        ),
    ]

    state = {"calls": 0}

    def _boom_once(_blk):
        state["calls"] += 1
        if state["calls"] == 1:
            raise RuntimeError("debug formatter blew up")
        return "<blk>"

    monkeypatch.setattr(dm, "_format_block_info", _boom_once)
    monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
    monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_a, **_k: None)
    monkeypatch.setattr(modifier, "_apply_single", lambda _mod: True)

    applied = modifier.apply(run_optimize_local=False, run_deep_cleaning=False)

    assert applied == 1


def test_block_target_change_rewrites_fallthrough_via_helper_and_remaps_later_targets(monkeypatch):
    mba = _FakeMBA()
    blk = _FakeBlock(15)
    blk.type = ida_hexrays.BLT_2WAY
    blk.tail.opcode = ida_hexrays.m_jnz
    blk.tail.d = SimpleNamespace(t=ida_hexrays.mop_b, b=17)
    blk.succset = _FakeEdgeSet([16, 17])
    blk.nextb = SimpleNamespace(serial=16)
    blk.nsucc = lambda: 2  # type: ignore[assignment]
    blk.succ = lambda idx: [16, 17][idx]  # type: ignore[assignment]
    mba.blocks = {15: blk}
    mba.qty = 300

    modifier = dm.DeferredGraphModifier(mba)

    nop_blk = _FakeBlock(16)
    helper_targets: list[tuple[int, int]] = []
    conditional_targets: list[tuple[int, int, int | None]] = []

    def _insert_nop(_blk):
        mba.qty += 1
        return nop_blk

    def _change_1way(_blk, new_target, verify=False):
        helper_targets.append((_blk.serial, new_target))
        return True

    def _change_2way(_blk, new_target, verify=False, old_target=None):
        conditional_targets.append((_blk.serial, new_target, old_target))
        return True

    monkeypatch.setattr(dm, "insert_nop_blk", _insert_nop)
    monkeypatch.setattr(dm, "change_1way_block_successor", _change_1way)
    monkeypatch.setattr(dm, "change_2way_block_conditional_successor", _change_2way)

    ok_fallthrough = modifier._apply_single(
        dm.GraphModification(
            dm.ModificationType.BLOCK_TARGET_CHANGE,
            block_serial=15,
            new_target=66,
            old_target=16,
        )
    )
    ok_conditional = modifier._apply_single(
        dm.GraphModification(
            dm.ModificationType.BLOCK_TARGET_CHANGE,
            block_serial=15,
            new_target=202,
            old_target=17,
        )
    )

    assert ok_fallthrough is True
    assert ok_conditional is True
    assert helper_targets == [(16, 67)]
    assert conditional_targets == [(15, 203, 18)]
    assert modifier._serial_remap[16] == 17
    assert modifier._serial_remap[17] == 18
    assert modifier._serial_remap[202] == 203


def test_create_and_redirect_rejects_non_1way_source(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(mba)
    src = _FakeBlock(5)
    src.nsucc = lambda: 2  # type: ignore[assignment]

    called = {"create": 0}
    monkeypatch.setattr(
        dm,
        "create_standalone_block",
        lambda *_a, **_k: called.__setitem__("create", called["create"] + 1),
    )

    ok = modifier._apply_create_and_redirect(
        source_blk=src,
        final_target=0,
        instructions_to_copy=[SimpleNamespace()],
        is_0_way=False,
        expected_serial=None,
    )
    assert ok is False
    assert called["create"] == 0


def test_create_and_redirect_materializes_symbolic_snapshots_before_block_creation(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(mba)
    src = _FakeBlock(5)

    captured: dict[str, object] = {}
    rebuilt_instructions = [SimpleNamespace(opcode=ida_hexrays.m_nop, ea=0x1234)]

    monkeypatch.setattr(
        dm,
        "materialize_insn_snapshots",
        lambda instructions, *, safe_ea: (
            captured.update({"instructions": instructions, "safe_ea": safe_ea})
            or rebuilt_instructions
        ),
    )
    monkeypatch.setattr(
        dm,
        "create_standalone_block",
        lambda *_a, **_k: (
            captured.update({"blk_ins": _a[1]})
            or SimpleNamespace(serial=1, head=None)
        ),
    )
    monkeypatch.setattr(dm, "change_1way_block_successor", lambda *_a, **_k: True)

    ok = modifier._apply_create_and_redirect(
        source_blk=src,
        final_target=0,
        instructions_to_copy=[InsnSnapshot(opcode=ida_hexrays.m_nop, ea=0x1234, operands=())],
        is_0_way=False,
        expected_serial=None,
    )

    assert ok is True
    assert captured["instructions"] == (
        InsnSnapshot(opcode=ida_hexrays.m_nop, ea=0x1234, operands=()),
    )
    assert captured["safe_ea"] == mba.entry_ea
    assert captured["blk_ins"] is rebuilt_instructions


def test_apply_pre_rejects_create_and_redirect_from_entry_block(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(mba)
    modifier.modifications = [
        dm.GraphModification(
            dm.ModificationType.BLOCK_CREATE_WITH_REDIRECT,
            block_serial=0,
            new_target=0,
            final_target=0,
            instructions_to_copy=[],
            description="entry insert should pre-reject",
        )
    ]

    called = {"apply_single": 0}
    monkeypatch.setattr(modifier, "_apply_single", lambda _m: called.__setitem__("apply_single", 1))
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
    monkeypatch.setattr(
        dm,
        "mba_deep_cleaning",
        lambda *_a, **_k: setattr(mba, "cleaned", mba.cleaned + 1),
    )

    applied = modifier.apply(run_optimize_local=False, run_deep_cleaning=False)

    assert applied == 0
    assert called["apply_single"] == 0


def test_coalesce_resolves_mixed_terminal_conflicts():
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(mba)
    modifier.modifications = [
        dm.GraphModification(
            dm.ModificationType.BLOCK_CREATE_WITH_REDIRECT,
            block_serial=7,
            new_target=11,
            final_target=11,
            instructions_to_copy=[SimpleNamespace(opcode=ida_hexrays.m_mov)],
            rule_priority=0,
        ),
        dm.GraphModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE,
            block_serial=7,
            new_target=22,
            rule_priority=100,
        ),
    ]

    removed = modifier.coalesce()

    assert removed == 1
    assert len(modifier.modifications) == 1
    assert modifier.modifications[0].mod_type == dm.ModificationType.BLOCK_GOTO_CHANGE
    assert modifier.modifications[0].new_target == 22


def test_apply_runs_conservative_cleanup_without_optimize_local(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(mba)
    modifier.modifications = [
        dm.GraphModification(dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=0, new_target=1),
    ]

    monkeypatch.setattr(modifier, "_apply_single", lambda _m: True)
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
    monkeypatch.setattr(
        dm,
        "mba_deep_cleaning",
        lambda *_a, **_k: setattr(mba, "cleaned", mba.cleaned + 1),
    )

    applied = modifier.apply(run_optimize_local=False, run_deep_cleaning=False)
    assert applied == 1
    assert mba.cleaned == 1


def test_apply_attempts_verify_recovery(monkeypatch):
    # With unconditional pre-apply verify: the first safe_verify call is the
    # pre-apply check. When it raises, _repair_wrong_successors() is attempted
    # (finds nothing to fix on this fake MBA) and apply proceeds optimistically.
    # The second safe_verify call is the post-apply check, which passes.
    # mba_deep_cleaning is NOT called in this path (run_optimize_local=True
    # takes the optimize_local(0) branch, and post-apply verify succeeds so
    # the recovery branch is not entered).
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(mba)
    modifier.modifications = [
        dm.GraphModification(dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=0, new_target=1),
    ]

    monkeypatch.setattr(modifier, "_apply_single", lambda _m: True)
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(
        dm,
        "mba_deep_cleaning",
        lambda *_a, **_k: setattr(mba, "cleaned", mba.cleaned + 1),
    )

    verify_calls = {"n": 0}

    def _safe_verify(*_a, **_k):
        verify_calls["n"] += 1
        if verify_calls["n"] == 1:
            raise RuntimeError("boom")

    monkeypatch.setattr(dm, "safe_verify", _safe_verify)

    applied = modifier.apply(run_optimize_local=True, run_deep_cleaning=False)
    assert applied == 1
    assert verify_calls["n"] == 2
    assert modifier.verify_failed is False


def test_apply_attempts_verify_recovery_on_non_runtime_preapply_exception(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(mba)
    modifier.modifications = [
        dm.GraphModification(dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=0, new_target=1),
    ]

    monkeypatch.setattr(modifier, "_apply_single", lambda _m: True)
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(
        dm,
        "mba_deep_cleaning",
        lambda *_a, **_k: setattr(mba, "cleaned", mba.cleaned + 1),
    )

    verify_calls = {"n": 0}

    def _safe_verify(*_a, **_k):
        verify_calls["n"] += 1
        if verify_calls["n"] == 1:
            raise ValueError("opaque verify failure")

    monkeypatch.setattr(dm, "safe_verify", _safe_verify)

    applied = modifier.apply(run_optimize_local=True, run_deep_cleaning=False)
    assert applied == 1
    assert verify_calls["n"] == 2
    assert modifier.verify_failed is False


def test_apply_executes_post_apply_hook(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(mba)
    modifier.modifications = [
        dm.GraphModification(dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=0, new_target=1),
    ]

    hook_calls = {"count": 0}

    monkeypatch.setattr(modifier, "_apply_single", lambda _m: True)
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
    monkeypatch.setattr(
        dm,
        "mba_deep_cleaning",
        lambda *_a, **_k: setattr(mba, "cleaned", mba.cleaned + 1),
    )

    def _hook():
        hook_calls["count"] += 1

    applied = modifier.apply(
        run_optimize_local=False,
        run_deep_cleaning=False,
        post_apply_hook=_hook,
    )

    assert applied == 1
    assert hook_calls["count"] == 1
    assert mba.cleaned == 1
    assert modifier.verify_failed is False


def test_apply_pre_rejects_illegal_edge_split_trampoline_and_continues(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(mba)
    modifier.modifications = [
        dm.GraphModification(
            dm.ModificationType.EDGE_SPLIT_TRAMPOLINE,
            block_serial=0,
            new_target=1,
            src_block=2,
            old_target=3,
            via_pred=4,
            expected_serial=5,
            priority=5,
            description="bad trampoline",
        ),
        dm.GraphModification(
            dm.ModificationType.INSN_NOP,
            block_serial=0,
            insn_ea=0x1000,
            priority=10,
            description="good nop",
        ),
    ]

    calls: list[dm.ModificationType] = []

    monkeypatch.setattr(
        modifier,
        "_check_edge_split_trampoline_preconditions",
        lambda **_kwargs: False,
    )
    monkeypatch.setattr(
        modifier,
        "_apply_single",
        lambda mod: calls.append(mod.mod_type) or True,
    )
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
    monkeypatch.setattr(
        dm,
        "mba_deep_cleaning",
        lambda *_a, **_k: setattr(mba, "cleaned", mba.cleaned + 1),
    )

    applied = modifier.apply(run_optimize_local=False, run_deep_cleaning=False)

    assert applied == 1
    assert calls == [dm.ModificationType.INSN_NOP]


def test_create_conditional_redirect_records_serial_drift_remap_and_continues(monkeypatch, request):
    import logging

    mba = _FakeMBA()
    source = _FakeBlock(5)
    ref = _FakeBlock(6)
    mba.blocks.update({5: source, 6: ref})
    mba.qty = len(mba.blocks)

    modifier = dm.DeferredGraphModifier(mba)
    modifier._serial_remap[10] = 13
    modifier._serial_remap[11] = 14

    monkeypatch.setattr(dm.ida_hexrays, "is_mcode_jcond", lambda _opcode: True)
    monkeypatch.setattr(
        dm,
        "duplicate_block",
        lambda *_a, **_k: (_FakeBlock(7), _FakeBlock(8)),
    )

    records: list[logging.LogRecord] = []

    class _ListHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _ListHandler(level=logging.WARNING)
    dm.logger.addHandler(handler)
    request.addfinalizer(lambda: dm.logger.removeHandler(handler))

    cond_calls = {"count": 0}
    ft_calls = {"count": 0}
    src_calls = {"count": 0}
    cond_targets: list[int] = []
    ft_targets: list[int] = []
    src_targets: list[int] = []

    def _change_2way(_blk, new_target, *_a, **_k):
        cond_calls["count"] += 1
        cond_targets.append(new_target)
        return True

    def _change_1way(blk, new_target, *_a, **_k):
        if blk.serial == 8:
            ft_calls["count"] += 1
            ft_targets.append(new_target)
        else:
            src_calls["count"] += 1
            src_targets.append(new_target)
        return True

    monkeypatch.setattr(
        dm,
        "change_2way_block_conditional_successor",
        _change_2way,
    )
    monkeypatch.setattr(
        dm,
        "change_1way_block_successor",
        _change_1way,
    )

    ok = modifier._apply_create_conditional_redirect(
        source_blk=source,
        ref_blk_serial=6,
        conditional_target_serial=10,
        fallthrough_target_serial=11,
        expected_conditional_serial=9,
        expected_fallthrough_serial=12,
    )

    assert ok is True
    assert cond_calls["count"] == 1
    assert ft_calls["count"] == 1
    assert src_calls["count"] == 1
    assert cond_targets == [13]
    assert ft_targets == [14]
    assert src_targets == [7]
    assert modifier._serial_remap[9] == 7
    assert modifier._serial_remap[12] == 8
    messages = [record.getMessage() for record in records]
    assert any(
        "created conditional blk[7], expected blk[9]" in message
        for message in messages
    )
    assert any(
        "created fallthrough blk[8], expected blk[12]" in message
        for message in messages
    )


def test_create_conditional_redirect_rejects_stale_source_edge_before_cloning(
    monkeypatch,
):
    mba = _FakeMBA()
    source = _FakeBlock(5)
    source.succset = _FakeEdgeSet([9])
    source.succ = lambda _idx: 9
    mba.blocks.update({5: source})
    mba.qty = len(mba.blocks)

    modifier = dm.DeferredGraphModifier(mba)
    duplicate_calls = {"count": 0}

    def _duplicate_block(*_args, **_kwargs):
        duplicate_calls["count"] += 1
        return (_FakeBlock(7), _FakeBlock(8))

    monkeypatch.setattr(dm, "duplicate_block", _duplicate_block)

    ok = modifier._apply_create_conditional_redirect(
        source_blk=source,
        ref_blk_serial=6,
        conditional_target_serial=10,
        fallthrough_target_serial=11,
        old_target_serial=6,
    )

    assert ok is False
    assert duplicate_calls["count"] == 0


def test_duplicate_block_records_serial_drift_remap_and_continues(monkeypatch):
    mba = _FakeMBA()
    source = _FakeBlock(5)
    pred = _FakeBlock(7)
    source.mba = mba
    pred.mba = mba
    source.head = None
    source.tail = None
    source.nsucc = lambda: 1  # type: ignore[assignment]
    source.succ = lambda _idx: 0  # type: ignore[assignment]
    pred.nsucc = lambda: 1  # type: ignore[assignment]
    mba.blocks.update({5: source, 7: pred})
    mba.qty = len(mba.blocks)

    modifier = dm.DeferredGraphModifier(mba)

    monkeypatch.setattr(
        modifier,
        "_check_duplicate_block_preconditions",
        lambda **_kwargs: True,
    )
    monkeypatch.setattr(
        dm,
        "create_standalone_block",
        lambda *_a, **_k: SimpleNamespace(
            serial=223,
            predset=_FakeEdgeSet(),
            succset=_FakeEdgeSet(),
        ),
    )
    monkeypatch.setattr(dm, "change_1way_block_successor", lambda *_a, **_k: True)

    ok = modifier._apply_duplicate_block_and_redirect(
        source_blk=source,
        pred_serial=7,
        target_serial=0,
        expected_serial=225,
    )

    assert ok is True
    assert modifier._serial_remap[225] == 223


def test_duplicate_replay_queue_records_single_composite_modification():
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(mba)
    body = (InsnSnapshot(opcode=ida_hexrays.m_nop, ea=0, operands=()),)

    modifier.queue_duplicate_replay_and_redirect(
        source_block_serial=5,
        dispatcher_entry_serial=2,
        per_pred_replays=(
            (8, 3, 20, None, body),
            (9, 4, 21, 22, body),
        ),
        description="duplicate replay test",
    )

    assert len(modifier.modifications) == 1
    queued = modifier.modifications[0]
    assert queued.mod_type == dm.ModificationType.BLOCK_DUPLICATE_REPLAY_AND_REDIRECT
    assert queued.block_serial == 5
    assert queued.new_target == 2
    assert queued.replay_entries == (
        (8, 3, 20, None, body),
        (9, 4, 21, 22, body),
    )
    assert modifier.coalesce() == 0


def _clone_as_goto_fixture():
    mba = _FakeMBA()
    source = _FakeBlock(5)
    pred = _FakeBlock(6)
    fallthrough = _FakeBlock(20)
    target = _FakeBlock(30)
    clone = _FakeBlock(7)

    source.type = ida_hexrays.BLT_2WAY
    source.succset = _FakeEdgeSet([20, 30])
    source.predset = _FakeEdgeSet([6])
    source.nsucc = lambda: 2  # type: ignore[assignment]
    source.succ = lambda idx: (20, 30)[idx]  # type: ignore[assignment]
    source.tail = SimpleNamespace(
        opcode=ida_hexrays.m_jnz,
        ea=0x1005,
        d=SimpleNamespace(t=ida_hexrays.mop_b, b=30),
    )

    pred.succset = _FakeEdgeSet([5])
    pred.nsucc = lambda: 1  # type: ignore[assignment]
    pred.succ = lambda _idx: 5  # type: ignore[assignment]

    clone.type = ida_hexrays.BLT_2WAY
    clone.succset = _FakeEdgeSet([20, 30])
    clone.predset = _FakeEdgeSet([6, 9])
    clone.nsucc = lambda: 2  # type: ignore[assignment]
    clone.succ = lambda idx: (20, 30)[idx]  # type: ignore[assignment]
    clone.tail = SimpleNamespace(
        opcode=ida_hexrays.m_jnz,
        ea=0x1005,
        d=SimpleNamespace(t=ida_hexrays.mop_b, b=30),
    )

    mba.blocks = {
        5: source,
        6: pred,
        7: clone,
        20: fallthrough,
        30: target,
    }
    mba.qty = 31

    return mba, source, pred, clone


def test_clone_conditional_as_goto_records_serial_drift_remap_and_replays_shape(
    monkeypatch,
):
    mba, source, pred, clone = _clone_as_goto_fixture()
    modifier = dm.DeferredGraphModifier(mba)
    trace: list[tuple] = []

    monkeypatch.setattr(dm, "copy_block_keep", lambda *_a, **_k: clone)

    def _convert(blk, target, **_kwargs):
        trace.append(("convert", blk.serial, target))
        return True

    def _redirect(blk, new_target, **_kwargs):
        trace.append(("redirect", blk.serial, blk.succ(0), new_target))
        return True

    monkeypatch.setattr(dm, "make_2way_block_goto", _convert)
    monkeypatch.setattr(dm, "change_1way_block_successor", _redirect)

    ok = modifier._apply_clone_conditional_as_goto(
        source_blk=source,
        pred_serial=pred.serial,
        goto_target_serial=30,
        expected_serial=9,
    )

    assert ok is True
    assert modifier._serial_remap[9] == 7
    assert list(clone.predset) == []
    assert trace == [
        ("convert", 7, 30),
        ("redirect", 6, 5, 7),
    ]


def _clone_as_goto_from_arm_fixture():
    """Mirror of :func:`_clone_as_goto_fixture` but with a 2-way predecessor.

    pred blk[6] is 2-way: explicit branch arm targets source blk[5] (arm=1),
    fallthrough arm targets blk[40].  source blk[5] is itself 2-way with
    arms blk[20] (fallthrough) / blk[30] (explicit branch).  Selected
    target is blk[30] (the branch arm of source).
    """
    mba = _FakeMBA()
    source = _FakeBlock(5)
    pred = _FakeBlock(6)
    fallthrough = _FakeBlock(20)
    target = _FakeBlock(30)
    pred_other = _FakeBlock(40)
    clone = _FakeBlock(7)

    source.type = ida_hexrays.BLT_2WAY
    source.succset = _FakeEdgeSet([20, 30])
    source.predset = _FakeEdgeSet([6])
    source.nsucc = lambda: 2  # type: ignore[assignment]
    source.succ = lambda idx: (20, 30)[idx]  # type: ignore[assignment]
    source.tail = SimpleNamespace(
        opcode=ida_hexrays.m_jnz,
        ea=0x1005,
        d=SimpleNamespace(t=ida_hexrays.mop_b, b=30),
    )

    # pred is 2-way; explicit branch arm targets source (arm == 1).
    pred.type = ida_hexrays.BLT_2WAY
    pred.succset = _FakeEdgeSet([40, 5])
    pred.nsucc = lambda: 2  # type: ignore[assignment]
    pred.succ = lambda idx: (40, 5)[idx]  # type: ignore[assignment]
    pred.tail = SimpleNamespace(
        opcode=ida_hexrays.m_jnz,
        ea=0x1006,
        d=SimpleNamespace(t=ida_hexrays.mop_b, b=5),
    )

    clone.type = ida_hexrays.BLT_2WAY
    clone.succset = _FakeEdgeSet([20, 30])
    clone.predset = _FakeEdgeSet([6, 9])
    clone.nsucc = lambda: 2  # type: ignore[assignment]
    clone.succ = lambda idx: (20, 30)[idx]  # type: ignore[assignment]
    clone.tail = SimpleNamespace(
        opcode=ida_hexrays.m_jnz,
        ea=0x1005,
        d=SimpleNamespace(t=ida_hexrays.mop_b, b=30),
    )

    mba.blocks = {
        5: source,
        6: pred,
        7: clone,
        20: fallthrough,
        30: target,
        40: pred_other,
    }
    mba.qty = 41

    return mba, source, pred, clone


def test_clone_conditional_as_goto_from_branch_arm_applies_2way_rewire(monkeypatch):
    mba, source, pred, clone = _clone_as_goto_from_arm_fixture()
    modifier = dm.DeferredGraphModifier(mba)
    trace: list[tuple] = []

    monkeypatch.setattr(dm, "copy_block_keep", lambda *_a, **_k: clone)

    def _convert(blk, target, **_kwargs):
        trace.append(("convert", blk.serial, target))
        return True

    def _rewire_branch(blk, new_target, **kwargs):
        trace.append(
            (
                "rewire_branch",
                blk.serial,
                int(blk.tail.d.b),
                new_target,
                kwargs.get("old_target"),
            )
        )
        return True

    monkeypatch.setattr(dm, "make_2way_block_goto", _convert)
    monkeypatch.setattr(
        dm, "change_2way_block_conditional_successor", _rewire_branch
    )

    ok = modifier._apply_clone_conditional_as_goto_from_branch_arm(
        source_blk=source,
        pred_serial=pred.serial,
        goto_target_serial=30,
        expected_serial=9,
    )

    assert ok is True
    assert modifier._serial_remap[9] == 7
    assert list(clone.predset) == []
    # The clone gets converted to a goto, then the 2-way predecessor's
    # explicit branch arm is rewired to the clone via the 2-way helper.
    assert trace == [
        ("convert", 7, 30),
        ("rewire_branch", 6, 5, 7, 5),
    ]


def test_clone_conditional_as_goto_from_branch_arm_refuses_one_way_predecessor(
    monkeypatch,
):
    """Apply path rejects when pred is 1-way at apply-time (drift / mis-queue)."""
    mba, source, pred, clone = _clone_as_goto_from_arm_fixture()
    modifier = dm.DeferredGraphModifier(mba)

    # Mutate pred to 1-way to simulate stale/drifted topology.
    pred.nsucc = lambda: 1  # type: ignore[assignment]

    monkeypatch.setattr(dm, "copy_block_keep", lambda *_a, **_k: clone)
    monkeypatch.setattr(
        dm,
        "make_2way_block_goto",
        lambda *_a, **_k: pytest.fail("convert must not run when pred is 1-way"),
    )
    monkeypatch.setattr(
        dm,
        "change_2way_block_conditional_successor",
        lambda *_a, **_k: pytest.fail("rewire must not run when pred is 1-way"),
    )

    ok = modifier._apply_clone_conditional_as_goto_from_branch_arm(
        source_blk=source,
        pred_serial=pred.serial,
        goto_target_serial=30,
    )

    assert ok is False


def test_clone_conditional_as_goto_from_branch_arm_refuses_fallthrough_arm(
    monkeypatch,
):
    """Apply path rejects when pred's explicit branch arm doesn't point at source.

    The legacy live rule bails on the fallthrough-arm case in
    ``update_blk_successor``; the engine path's planner already declines via
    ``PRED_FALLTHROUGH_ARM_NOT_SUPPORTED``.  This is the apply-time defense
    in depth against a stale queue.
    """
    mba, source, pred, clone = _clone_as_goto_from_arm_fixture()
    modifier = dm.DeferredGraphModifier(mba)

    # Flip pred's explicit branch operand to target the OTHER successor.
    pred.tail = SimpleNamespace(
        opcode=ida_hexrays.m_jnz,
        ea=0x1006,
        d=SimpleNamespace(t=ida_hexrays.mop_b, b=40),
    )

    monkeypatch.setattr(dm, "copy_block_keep", lambda *_a, **_k: clone)
    monkeypatch.setattr(
        dm,
        "make_2way_block_goto",
        lambda *_a, **_k: pytest.fail("convert must not run on fallthrough arm"),
    )
    monkeypatch.setattr(
        dm,
        "change_2way_block_conditional_successor",
        lambda *_a, **_k: pytest.fail("rewire must not run on fallthrough arm"),
    )

    ok = modifier._apply_clone_conditional_as_goto_from_branch_arm(
        source_blk=source,
        pred_serial=pred.serial,
        goto_target_serial=30,
    )

    assert ok is False


def test_clone_conditional_as_goto_planned_path_matches_legacy_live_sequence(
    monkeypatch,
):
    legacy_mba, legacy_source, _legacy_pred, legacy_clone = _clone_as_goto_fixture()
    planned_mba, planned_source, _planned_pred, planned_clone = _clone_as_goto_fixture()

    legacy_trace: list[tuple] = []
    planned_trace: list[tuple] = []

    def _legacy_copy_block(_source, _insert_before):
        legacy_trace.append(("clone", _source.serial))
        legacy_mba.blocks[legacy_clone.serial] = legacy_clone
        return legacy_clone

    legacy_mba.copy_block = _legacy_copy_block  # type: ignore[attr-defined]

    def _legacy_convert(blk, target, **_kwargs):
        legacy_trace.append(("convert", blk.serial, target))
        return True

    def _legacy_redirect(blk, old_target, new_target, **_kwargs):
        legacy_trace.append(("redirect", blk.serial, old_target, new_target))
        return True

    monkeypatch.setattr(fix_pred, "make_2way_block_goto", _legacy_convert)
    monkeypatch.setattr(fix_pred, "update_blk_successor", _legacy_redirect)

    rule = FixPredecessorOfConditionalJumpBlock()
    rule.mba = legacy_mba
    legacy_ok = rule._apply_single_modification(
        PredecessorModification(
            mod_type=PredecessorModificationType.ALWAYS_TAKEN,
            pred_serial=6,
            cond_block_serial=5,
            target_serial=30,
            description="parity",
        ),
        legacy_source,
    )

    def _planned_copy(_mba, source_blk, _insert_before):
        planned_trace.append(("clone", source_blk.serial))
        return planned_clone

    def _planned_convert(blk, target, **_kwargs):
        planned_trace.append(("convert", blk.serial, target))
        return True

    def _planned_redirect(blk, new_target, **_kwargs):
        planned_trace.append(("redirect", blk.serial, blk.succ(0), new_target))
        return True

    monkeypatch.setattr(dm, "copy_block_keep", _planned_copy)
    monkeypatch.setattr(dm, "make_2way_block_goto", _planned_convert)
    monkeypatch.setattr(dm, "change_1way_block_successor", _planned_redirect)

    modifier = dm.DeferredGraphModifier(planned_mba)
    planned_ok = modifier._apply_clone_conditional_as_goto(
        source_blk=planned_source,
        pred_serial=6,
        goto_target_serial=30,
        expected_serial=7,
    )

    assert legacy_ok is True
    assert planned_ok is True
    assert planned_trace == legacy_trace == [
        ("clone", 5),
        ("convert", 7, 30),
        ("redirect", 6, 5, 7),
    ]


@dataclass
class _StepTrace:
    label: str
    verify_error: str | None
    source_serial: int
    cond_serial: int | None
    helper_serial: int | None


@dataclass
class _BatchTrace:
    mod_type: str
    block_serial: int | None
    new_target: int | None
    verify_error: str | None


def _find_real_conditional_redirect_candidate(mba) -> CreateConditionalRedirect | None:
    family = EmulatedDispatcherStrategyFamily()
    detection = family.detect(mba)
    snapshot = family.build_snapshot(mba, detection)
    for mod in snapshot.flow_graph.metadata.get(EMULATED_DISPATCHER_MODIFICATIONS_KEY, ()):
        if isinstance(mod, CreateConditionalRedirect):
            return mod

    # Prefer the planner-produced CreateConditionalRedirect above when it is
    # available: that keeps this test tied to the exact edit the strategy family
    # intended to emit. The sampled Approov function does not always produce that
    # edit kind, though. If the strategy changes shape, the old behavior was to
    # skip this test entirely, which meant the deferred mutator backend could
    # lose real-MBA coverage without anyone noticing.
    #
    # This fallback is deliberately narrower than planner validation. It builds
    # a structurally valid CreateConditionalRedirect from the live MBA topology:
    # clone any real 2-way conditional block as the reference block, reuse its
    # real successors as the conditional/fallthrough targets, then redirect an
    # unrelated real 1-way goto source block through the newly created
    # conditional. That exercises the runtime operation that matters here:
    #
    #     source -> cloned conditional -> taken target
    #                              \-> helper fallthrough block -> fallthrough target
    #
    # In other words, if this path is used, the test is asserting backend safety
    # for CreateConditionalRedirect on real IDA microcode. It is not asserting
    # that the emulated-dispatcher planner discovered a semantically meaningful
    # conditional redirect for this particular function.
    ref_blk = None
    for serial in range(int(getattr(mba, "qty", 0) or 0)):
        blk = mba.get_mblock(serial)
        if blk is None or blk.tail is None:
            continue
        if blk.nsucc() != 2 or not ida_hexrays.is_mcode_jcond(blk.tail.opcode):
            continue
        ref_blk = blk
        break
    if ref_blk is None:
        return None

    ref_successors = tuple(int(ref_blk.succ(idx)) for idx in range(ref_blk.nsucc()))
    if len(ref_successors) != 2:
        return None

    for serial in range(int(getattr(mba, "qty", 0) or 0)):
        blk = mba.get_mblock(serial)
        if blk is None or blk.serial == ref_blk.serial or blk.serial == 0:
            continue
        if blk.nsucc() != 1 or blk.tail is None or blk.tail.opcode != ida_hexrays.m_goto:
            continue
        return CreateConditionalRedirect(
            source_block=int(blk.serial),
            ref_block=int(ref_blk.serial),
            conditional_target=int(ref_successors[0]),
            fallthrough_target=int(ref_successors[1]),
        )
    return None


def _real_emulated_dispatcher_modifications(mba) -> tuple[object, ...]:
    family = EmulatedDispatcherStrategyFamily()
    detection = family.detect(mba)
    snapshot = family.build_snapshot(mba, detection)
    return tuple(snapshot.flow_graph.metadata.get(EMULATED_DISPATCHER_MODIFICATIONS_KEY, ()))


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"


def _verify_error(mba) -> str | None:
    try:
        mba.verify(True)
    except Exception as exc:  # pragma: no cover - real IDA failure surface
        return f"{type(exc).__name__}: {exc}"
    return None


def _trace_real_emulated_dispatcher_batch(
    func_name: str,
    *,
    maturity: int = ida_hexrays.MMAT_GLBOPT1,
) -> list[_BatchTrace]:
    mba, modifier = _build_real_emulated_dispatcher_modifier(
        func_name,
        maturity=maturity,
    )

    trace: list[_BatchTrace] = []
    for mod in sorted(modifier.modifications, key=lambda queued: queued.priority):
        ok = modifier._apply_single(mod)
        verify_error = None if ok else "apply_returned_false"
        if verify_error is None:
            verify_error = _verify_error(mba)
        trace.append(
            _BatchTrace(
                mod_type=getattr(mod.mod_type, "name", str(mod.mod_type)),
                block_serial=getattr(mod, "block_serial", None),
                new_target=getattr(mod, "new_target", None),
                verify_error=verify_error,
            )
        )
        if verify_error is not None:
            break

    return trace


def _build_real_emulated_dispatcher_modifier(
    func_name: str,
    *,
    maturity: int = ida_hexrays.MMAT_GLBOPT1,
):
    func_ea = get_func_ea(func_name)
    if func_ea == 0xFFFFFFFFFFFFFFFF:
        pytest.skip(f"Function '{func_name}' not found")

    mba = gen_microcode_at_maturity(func_ea, maturity)
    if mba is None:
        pytest.skip(
            f"Failed to generate maturity {maturity} microcode for {func_name}"
        )

    modifications = _real_emulated_dispatcher_modifications(mba)
    if not modifications:
        pytest.skip(f"No emulated-dispatcher modifications found for {func_name}")

    translator = IDAIRTranslator()
    patch_plan = compile_patch_plan(list(modifications))
    modifier = dm.DeferredGraphModifier(mba)
    for step in patch_plan.steps:
        translator._queue_patch_step(modifier, step)

    modifier.coalesce()
    return mba, modifier


@pytest.mark.ida_required
class TestCreateConditionalRedirectIntegration:
    binary_name = _get_default_binary()

    def test_emulated_dispatcher_batch_real_approov_pattern_traces_first_invalid_mod(
        self,
        libobfuscated_setup,
    ) -> None:
        trace = _trace_real_emulated_dispatcher_batch("approov_real_pattern")
        first_invalid = next((entry for entry in trace if entry.verify_error is not None), None)
        assert first_invalid is None, f"fresh batched apply should stay verify-clean, got {trace!r}"

    def test_emulated_dispatcher_batch_real_approov_multistate_stepwise_apply_stays_verify_clean(
        self,
        libobfuscated_setup,
    ) -> None:
        trace = _trace_real_emulated_dispatcher_batch("approov_multistate")

        first_invalid = next((entry for entry in trace if entry.verify_error is not None), None)
        assert first_invalid is None, f"stepwise multistate apply should stay verify-clean, got {trace!r}"

    def test_emulated_dispatcher_batch_real_approov_multistate_modifier_apply_stays_verify_clean(
        self,
        libobfuscated_setup,
    ) -> None:
        mba, modifier = _build_real_emulated_dispatcher_modifier("approov_multistate")

        apply_error = None
        try:
            modifier.apply(run_optimize_local=True, run_deep_cleaning=False)
        except Exception as exc:  # pragma: no cover - real IDA failure surface
            apply_error = f"{type(exc).__name__}: {exc}"

        verify_error = _verify_error(mba)
        assert apply_error is None
        assert verify_error is None

    def test_emulated_dispatcher_batch_real_approov_multistate_glbopt2_preapply_logging_reaches_raw_apply(
        self,
        libobfuscated_setup,
        monkeypatch,
    ) -> None:
        mba, modifier = _build_real_emulated_dispatcher_modifier(
            "approov_multistate",
            maturity=ida_hexrays.MMAT_GLBOPT2,
        )

        calls = {"count": 0}

        def _fake_apply_single(_mod):
            calls["count"] += 1
            return False

        monkeypatch.setattr(modifier, "_apply_single", _fake_apply_single)
        monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
        monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_a, **_k: None)

        applied = modifier.apply(run_optimize_local=False, run_deep_cleaning=False)

        assert applied == 0
        assert calls["count"] == 1
        assert modifier.last_apply_phase == "backend_apply"
        assert modifier.last_apply_subphase == "raw_apply"

    def test_emulated_dispatcher_batch_real_approov_pattern_rejects_unsupported_batch_cleanly(
        self,
        libobfuscated_setup,
    ) -> None:
        func_ea = get_func_ea("approov_real_pattern")
        if func_ea == 0xFFFFFFFFFFFFFFFF:
            pytest.skip("Function 'approov_real_pattern' not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_GLBOPT1)
        if mba is None:
            pytest.skip("Failed to generate GLBOPT1 microcode for approov_real_pattern")

        modifications = _real_emulated_dispatcher_modifications(mba)
        if not modifications:
            pytest.skip("No emulated-dispatcher modifications found for approov_real_pattern")

        translator = IDAIRTranslator()
        patch_plan = compile_patch_plan(list(modifications))
        modifier = dm.DeferredGraphModifier(mba)
        for step in patch_plan.steps:
            translator._queue_patch_step(modifier, step)

        applied = modifier.apply(
            run_optimize_local=True,
            run_deep_cleaning=False,
        )
        # Current runtime lowering can queue InsertBlock-style edits whose
        # InsnSnapshot->minsn_t backend conversion is intentionally not
        # implemented in DeferredGraphModifier. Treat that as a clean reject:
        # do not force legacy best-effort mutation just to get a non-zero
        # apply count.
        assert applied == 0
        assert _verify_error(mba) is None

        mba.mark_chains_dirty()
        verify_error = _verify_error(mba)
        assert verify_error is None

    def test_legacy_like_goto_batch_rejects_two_way_goto_rewrite(
        self,
        libobfuscated_setup,
    ) -> None:
        func_ea = get_func_ea("approov_real_pattern")
        if func_ea == 0xFFFFFFFFFFFFFFFF:
            pytest.skip("Function 'approov_real_pattern' not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_GLBOPT1)
        if mba is None:
            pytest.skip("Failed to generate GLBOPT1 microcode for approov_real_pattern")

        legacy_like = dm.DeferredGraphModifier(mba)
        legacy_like.queue_goto_change(2, 8, description="legacy-like goto 2->8")
        legacy_like.queue_goto_change(8, 9, description="legacy-like goto 8->9")
        applied = legacy_like.apply(run_optimize_local=True, run_deep_cleaning=False)
        # BLOCK_GOTO_CHANGE is legal only on 1-way blocks. blk[8] is 2-way in
        # this pattern, so the second queued legacy mutation must be rejected
        # and the batch must abort before compounding CFG corruption. Do not
        # "fix" this back to 2: rewriting a 2-way block via goto loses a branch.
        assert applied == 1
        assert _verify_error(mba) is None
        mba.mark_chains_dirty()
        assert _verify_error(mba) is None

    def test_create_conditional_redirect_real_approov_pattern_isolated_apply_stays_verify_clean(
        self,
        libobfuscated_setup,
        monkeypatch,
    ) -> None:
        func_ea = get_func_ea("approov_real_pattern")
        if func_ea == 0xFFFFFFFFFFFFFFFF:
            pytest.skip("Function 'approov_real_pattern' not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_GLBOPT1)
        if mba is None:
            pytest.skip("Failed to generate GLBOPT1 microcode for approov_real_pattern")

        mod = _find_real_conditional_redirect_candidate(mba)
        if mod is None:
            pytest.skip("No CreateConditionalRedirect candidate found for approov_real_pattern")

        modifier = dm.DeferredGraphModifier(mba)
        source_blk = mba.get_mblock(mod.source_block)
        assert source_blk is not None

        trace: list[_StepTrace] = []
        state: dict[str, object] = {"cond": None, "helper": None}

        original_duplicate_block = dm.duplicate_block
        original_change_2way = dm.change_2way_block_conditional_successor
        original_change_1way = dm.change_1way_block_successor

        def _capture(label: str) -> None:
            cond_blk = state["cond"]
            helper_blk = state["helper"]
            trace.append(
                _StepTrace(
                    label=label,
                    verify_error=_verify_error(mba),
                    source_serial=source_blk.serial,
                    cond_serial=getattr(cond_blk, "serial", None),
                    helper_serial=getattr(helper_blk, "serial", None),
                )
            )

        def _duplicate_block(*args, **kwargs):
            cond_blk, helper_blk = original_duplicate_block(*args, **kwargs)
            state["cond"] = cond_blk
            state["helper"] = helper_blk
            _capture("after_duplicate")
            return cond_blk, helper_blk

        def _change_2way(blk, new_target, **kwargs):
            ok = original_change_2way(blk, new_target, **kwargs)
            _capture("after_change_2way")
            return ok

        def _change_1way(blk, new_target, **kwargs):
            ok = original_change_1way(blk, new_target, **kwargs)
            if getattr(state["helper"], "serial", None) == blk.serial:
                _capture("after_helper_rewire")
            elif source_blk.serial == blk.serial:
                _capture("after_source_redirect")
            else:
                _capture(f"after_change_1way_{blk.serial}")
            return ok

        monkeypatch.setattr(dm, "duplicate_block", _duplicate_block)
        monkeypatch.setattr(dm, "change_2way_block_conditional_successor", _change_2way)
        monkeypatch.setattr(dm, "change_1way_block_successor", _change_1way)

        ok = modifier._apply_create_conditional_redirect(
            source_blk=source_blk,
            ref_blk_serial=mod.ref_block,
            conditional_target_serial=mod.conditional_target,
            fallthrough_target_serial=mod.fallthrough_target,
            instructions_to_copy=tuple(mod.instructions),
        )
        _capture("after_apply")

        assert ok is True
        assert trace, "expected step trace for real conditional redirect"
        first_invalid = next((step for step in trace if step.verify_error is not None), None)
        assert first_invalid is None, f"isolated conditional redirect should stay verify-clean, got {trace!r}"


def test_apply_pre_rejects_duplicate_block_with_fallthrough_predecessor(monkeypatch):
    mba = _FakeMBA()
    source = _FakeBlock(5)
    pred = _FakeBlock(6)
    target = _FakeBlock(7)
    pred.nsucc = lambda: 2  # type: ignore[assignment]
    pred.tail = SimpleNamespace(
        opcode=ida_hexrays.m_jnz,
        ea=0x1000,
        l=None,
        r=None,
        d=SimpleNamespace(t=ida_hexrays.mop_b, b=99),
    )
    source.nsucc = lambda: 1  # type: ignore[assignment]
    mba.blocks.update({5: source, 6: pred, 7: target})
    mba.qty = len(mba.blocks)

    modifier = dm.DeferredGraphModifier(mba)
    modifier.modifications = [
        dm.GraphModification(
            dm.ModificationType.BLOCK_DUPLICATE_AND_REDIRECT,
            block_serial=5,
            via_pred=6,
            new_target=7,
            description="duplicate fallthrough edge should pre-reject",
        )
    ]

    called = {"apply_single": 0}
    monkeypatch.setattr(
        modifier,
        "_apply_single",
        lambda _m: called.__setitem__("apply_single", called["apply_single"] + 1) or True,
    )
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
    monkeypatch.setattr(
        dm,
        "mba_deep_cleaning",
        lambda *_a, **_k: setattr(mba, "cleaned", mba.cleaned + 1),
    )

    applied = modifier.apply(run_optimize_local=False, run_deep_cleaning=False)

    assert applied == 0
    assert called["apply_single"] == 0


def test_duplicate_block_rejects_unexpected_secondary_serial(monkeypatch):
    mba = _FakeMBA()
    source = _FakeBlock(5)
    pred = _FakeBlock(6)
    pred.succ = lambda _idx: 5  # type: ignore[assignment]
    source.nsucc = lambda: 2  # type: ignore[assignment]
    mba.blocks.update({5: source, 6: pred})
    mba.qty = len(mba.blocks)

    modifier = dm.DeferredGraphModifier(mba)

    monkeypatch.setattr(
        dm,
        "duplicate_block",
        lambda *_a, **_k: (_FakeBlock(7), _FakeBlock(8)),
    )

    calls = {"pred": 0, "clone": 0}
    monkeypatch.setattr(
        dm,
        "change_1way_block_successor",
        lambda blk, *_a, **_k: (
            calls.__setitem__("pred", calls["pred"] + 1)
            if blk.serial == 6
            else calls.__setitem__("clone", calls["clone"] + 1)
        ) or True,
    )

    ok = modifier._apply_duplicate_block_and_redirect(
        source_blk=source,
        pred_serial=6,
        target_serial=None,
        expected_serial=7,
        expected_secondary_serial=9,
    )

    assert ok is False
    assert calls["pred"] == 0
    assert calls["clone"] == 0


def test_duplicate_block_applies_explicit_conditional_targets(monkeypatch):
    mba = _FakeMBA()
    source = _FakeBlock(5)
    pred = _FakeBlock(6)
    conditional_target = _FakeBlock(30)
    fallthrough_target = _FakeBlock(40)
    duplicated_blk = _FakeBlock(7)
    duplicated_default = _FakeBlock(8)

    source.type = ida_hexrays.BLT_2WAY
    source.nsucc = lambda: 2  # type: ignore[assignment]
    source.succ = lambda idx: (2, 10)[idx]  # type: ignore[assignment]
    source.tail = SimpleNamespace(
        opcode=ida_hexrays.m_jnz,
        ea=0x1000,
        l=None,
        r=None,
        d=SimpleNamespace(t=ida_hexrays.mop_b, b=2),
    )
    pred.succ = lambda _idx: 5  # type: ignore[assignment]
    duplicated_blk.succset = _FakeEdgeSet([2, 10])
    duplicated_blk.predset = _FakeEdgeSet([6])

    mba.blocks.update({5: source, 6: pred, 30: conditional_target, 40: fallthrough_target})
    mba.qty = len(mba.blocks)
    mba.copy_block = lambda *_args, **_kwargs: duplicated_blk  # type: ignore[attr-defined]

    modifier = dm.DeferredGraphModifier(mba)

    monkeypatch.setattr(dm.ida_hexrays, "is_mcode_jcond", lambda _opcode: True)
    monkeypatch.setattr(
        dm,
        "create_standalone_block",
        lambda *_args, **kwargs: duplicated_default
        if kwargs.get("target_serial") == 40
        else None,
    )

    rewired: dict[str, object] = {}
    monkeypatch.setattr(
        dm,
        "_rewire_edge",
        lambda _blk, old_succs, new_succs, **_kwargs: (
            rewired.update({"old": list(old_succs), "new": list(new_succs)}) or True
        ),
    )

    pred_calls = {"count": 0}
    monkeypatch.setattr(
        dm,
        "change_1way_block_successor",
        lambda blk, new_target, **_kwargs: (
            pred_calls.__setitem__("count", pred_calls["count"] + 1)
            if blk.serial == 6 and new_target == 7
            else None
        )
        or True,
    )

    monkeypatch.setattr(dm.ida_hexrays, "mop_t", lambda: SimpleNamespace(make_blkref=lambda _value: None))

    ok = modifier._apply_duplicate_block_and_redirect(
        source_blk=source,
        pred_serial=6,
        target_serial=None,
        conditional_target=30,
        fallthrough_target=40,
        expected_serial=None,
        expected_secondary_serial=None,
    )

    assert ok is True
    assert rewired == {"old": [2, 10], "new": [8, 30]}
    assert pred_calls["count"] == 1


def test_apply_marks_verify_failed_on_post_apply_hook_exception(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(mba)
    modifier.modifications = [
        dm.GraphModification(dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=0, new_target=1),
    ]

    monkeypatch.setattr(modifier, "_apply_single", lambda _m: True)
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "capture_failure_artifact", lambda *_a, **_k: None)
    monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
    monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_a, **_k: None)

    def _hook():
        raise RuntimeError("hook failure")

    applied = modifier.apply(
        run_optimize_local=False,
        run_deep_cleaning=False,
        post_apply_hook=_hook,
    )

    assert applied == 1
    assert modifier.verify_failed is True


def test_apply_skips_post_native_verify_after_contract_failure(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(mba)
    modifier.modifications = [
        dm.GraphModification(dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=0, new_target=1),
    ]

    verify_calls = {"count": 0}

    monkeypatch.setattr(modifier, "_apply_single", lambda _m: True)
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "capture_failure_artifact", lambda *_a, **_k: None)
    monkeypatch.setattr(
        dm,
        "safe_verify",
        lambda *_a, **_k: verify_calls.__setitem__("count", verify_calls["count"] + 1),
    )
    monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_a, **_k: None)

    def _hook():
        raise CfgContractViolationError(
            phase="post",
            violations=(
                InvariantViolation(
                    code="CFG_BAD",
                    message="bad succset",
                    phase="post",
                    block_serial=0,
                ),
            ),
        )

    applied = modifier.apply(
        run_optimize_local=False,
        run_deep_cleaning=False,
        post_apply_hook=_hook,
    )

    assert applied == 1
    assert modifier.verify_failed is True
    assert verify_calls["count"] == 1


def test_apply_rolls_back_snapshot_after_contract_failure(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(mba)
    modifier.modifications = [
        dm.GraphModification(dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=0, new_target=1),
    ]

    verify_calls = {"count": 0}
    restored = {"count": 0}

    monkeypatch.setattr(modifier, "_apply_single", lambda _m: True)
    monkeypatch.setattr(modifier, "_restore_from_snapshot", lambda _snap: restored.__setitem__("count", restored["count"] + 1) or True)
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "capture_failure_artifact", lambda *_a, **_k: None)
    monkeypatch.setattr(dm, "lift", lambda _mba: SimpleNamespace(num_blocks=1, entry_serial=0))
    monkeypatch.setattr(
        dm,
        "safe_verify",
        lambda *_a, **_k: verify_calls.__setitem__("count", verify_calls["count"] + 1),
    )
    monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_a, **_k: None)

    def _hook():
        raise CfgContractViolationError(
            phase="post",
            violations=(
                InvariantViolation(
                    code="CFG_BAD",
                    message="bad succset",
                    phase="post",
                    block_serial=0,
                ),
            ),
        )

    applied = modifier.apply(
        run_optimize_local=False,
        run_deep_cleaning=False,
        enable_snapshot_rollback=True,
        post_apply_hook=_hook,
    )

    assert applied == 0
    assert modifier.verify_failed is False
    assert restored["count"] == 1
    assert verify_calls["count"] == 1


def test_apply_rolls_back_failed_mod_and_continues(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(mba)
    modifier.modifications = [
        dm.GraphModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE,
            block_serial=0,
            new_target=1,
            description="first",
        ),
        dm.GraphModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE,
            block_serial=1,
            new_target=2,
            description="second",
        ),
    ]

    apply_calls = {"count": 0}
    rollback_calls = {"count": 0}
    verify_calls = {"count": 0}

    def _apply_single(_mod):
        apply_calls["count"] += 1
        return True

    def _prepare_rollback(mod):
        if mod.description != "first":
            return None

        def _rb():
            rollback_calls["count"] += 1
            return True

        return ("restore first", _rb)

    def _safe_verify(*_args, **_kwargs):
        verify_calls["count"] += 1
        # Call 1: pre-apply verify (unconditional) -> passes through
        # Call 2: after first mod apply -> fails, triggers rollback
        # Call 3: after rollback verify -> passes
        # Call 4: after second mod apply -> passes
        # Call 5: post-apply verify -> passes
        if verify_calls["count"] == 2:
            raise RuntimeError("verify failed")

    monkeypatch.setattr(modifier, "_apply_single", _apply_single)
    monkeypatch.setattr(modifier, "_prepare_rollback", _prepare_rollback)
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", _safe_verify)
    monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_a, **_k: None)

    applied = modifier.apply(
        run_optimize_local=False,
        run_deep_cleaning=False,
        verify_each_mod=True,
        rollback_on_verify_failure=True,
        continue_on_verify_failure=True,
    )

    assert applied == 1
    assert apply_calls["count"] == 2
    assert rollback_calls["count"] == 1
    assert verify_calls["count"] == 5
    assert modifier.verify_failed is False


def test_apply_sets_verify_failed_if_rollback_cannot_recover(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(mba)
    modifier.modifications = [
        dm.GraphModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE,
            block_serial=0,
            new_target=1,
            description="bad",
        ),
    ]

    monkeypatch.setattr(modifier, "_apply_single", lambda _mod: True)
    monkeypatch.setattr(
        modifier,
        "_prepare_rollback",
        lambda _mod: ("restore bad", lambda: False),
    )
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")

    verify_calls = {"count": 0}

    def _fail_after_precheck(*_args, **_kwargs):
        verify_calls["count"] += 1
        # Call 1: pre-apply verify -> pass (no pre-existing stale succset)
        # Call 2+: per-mod verify -> fail, triggering rollback path
        if verify_calls["count"] > 1:
            raise RuntimeError("verify failed")

    monkeypatch.setattr(dm, "safe_verify", _fail_after_precheck)
    monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_a, **_k: None)

    applied = modifier.apply(
        run_optimize_local=False,
        run_deep_cleaning=False,
        verify_each_mod=True,
        rollback_on_verify_failure=True,
        continue_on_verify_failure=True,
    )

    assert applied == 0
    assert modifier.verify_failed is True


# ---------------------------------------------------------------------------
#  Helpers for PrivateTerminalSuffix tests
# ---------------------------------------------------------------------------


class _SuffixEdgeSet(_FakeEdgeSet):
    """Extended edge set with __iter__, __len__, and _del for suffix tests."""

    def __iter__(self):
        return iter(list(self._items))

    def __len__(self) -> int:
        return len(self._items)

    def _del(self, val: int) -> None:
        try:
            self._items.remove(val)
        except ValueError:
            pass


class _FakeInsn:
    """Minimal instruction stub with a linked-list ``next`` pointer."""

    def __init__(self, opcode: int = 0, ea: int = 0x1000):
        self.opcode = opcode
        self.ea = ea
        self.next = None  # type: _FakeInsn | None

    def setaddr(self, _ea: int) -> None:
        pass


def _make_suffix_block(
    serial: int,
    *,
    nsucc: int = 1,
    succ_serial: int = 0,
    insn_opcodes: tuple[int, ...] = (),
    tail_opcode: int | None = None,
) -> _FakeBlock:
    """Build a _FakeBlock with configurable successor count and instruction chain."""
    blk = _FakeBlock(serial)
    blk.succset = _SuffixEdgeSet([succ_serial] if nsucc >= 1 else [])
    blk.predset = _SuffixEdgeSet()
    blk.nsucc = lambda _nsucc=nsucc: _nsucc  # type: ignore[assignment]
    blk.succ = lambda _idx, _s=succ_serial: _s  # type: ignore[assignment]

    # Build instruction linked list
    head = None
    prev = None
    for opc in (insn_opcodes or (ida_hexrays.m_nop,)):
        ins = _FakeInsn(opcode=opc, ea=0x1000 + serial)
        if head is None:
            head = ins
        if prev is not None:
            prev.next = ins
        prev = ins

    blk.head = head
    if tail_opcode is not None and head is not None:
        # Walk to tail and set its opcode
        cur = head
        while cur.next is not None:
            cur = cur.next
        cur.opcode = tail_opcode
        blk.tail = cur
    elif head is not None:
        cur = head
        while cur.next is not None:
            cur = cur.next
        blk.tail = cur
    else:
        blk.tail = None

    return blk


def _build_suffix_mba(blocks: dict[int, _FakeBlock]) -> _FakeMBA:
    """Build a _FakeMBA with the given blocks."""
    mba = _FakeMBA()
    mba.blocks = blocks
    mba.qty = max(blocks.keys()) + 1 if blocks else 0
    return mba


def _patch_suffix_dependencies(monkeypatch, mba):
    """Monkeypatch ida_hexrays.minsn_t copy constructor and create_standalone_block.

    Returns a state dict tracking created clones and successor changes.
    """
    state = {
        "clones_created": [],       # list of (template_serial, clone_serial, is_0_way, target_serial)
        "successor_changes": [],    # list of (blk_serial, new_target)
        "next_serial": mba.qty,     # next serial for new clones
    }

    # Monkeypatch ida_hexrays.minsn_t as identity copy constructor
    original_minsn_t = ida_hexrays.minsn_t
    monkeypatch.setattr(
        dm.ida_hexrays,
        "minsn_t",
        lambda obj, _orig=original_minsn_t: obj if isinstance(obj, _FakeInsn) else _orig(obj),
    )

    def _fake_create_standalone_block(ref_blk, blk_ins, target_serial=None, is_0_way=False, verify=True):
        serial = state["next_serial"]
        state["next_serial"] += 1

        clone = _make_suffix_block(
            serial,
            nsucc=0 if is_0_way else 1,
            succ_serial=target_serial if target_serial is not None else 0,
            insn_opcodes=(ida_hexrays.m_nop,),
        )
        mba.blocks[serial] = clone
        mba.qty = max(mba.blocks.keys()) + 1

        state["clones_created"].append((ref_blk.serial, serial, is_0_way, target_serial))
        return clone

    def _fake_change_1way(blk, new_target, verify=True):
        state["successor_changes"].append((blk.serial, new_target))
        # Update the fake block's successor
        blk.succ = lambda _idx, _t=new_target: _t  # type: ignore[assignment]
        blk.succset = _SuffixEdgeSet([new_target])
        return True

    monkeypatch.setattr(dm, "create_standalone_block", _fake_create_standalone_block)
    monkeypatch.setattr(dm, "change_1way_block_successor", _fake_change_1way)

    return state


# ---------------------------------------------------------------------------
#  TestPrivateTerminalSuffix
# ---------------------------------------------------------------------------


class TestPrivateTerminalSuffix:
    """Tests for _apply_private_terminal_suffix covering P1 fixes."""

    def test_apply_suffix_creates_private_chain(self, monkeypatch):
        """Queue and apply a 2-block suffix (S->T) for anchor A.

        Topology before:  A(1) -> S(2) -> T(3, 0-way stop)
        Expected after:   A(1) -> clone_S(4) -> clone_T(5, 0-way)
                          S(2) -> T(3) still exists unchanged.
        """
        # Block 3 is 0-way (BLT_STOP equivalent), block 2 is 1-way -> 3
        blk_a = _make_suffix_block(1, nsucc=1, succ_serial=2, tail_opcode=ida_hexrays.m_goto)
        blk_s = _make_suffix_block(2, nsucc=1, succ_serial=3, tail_opcode=ida_hexrays.m_goto)
        blk_t = _make_suffix_block(3, nsucc=0, succ_serial=0, tail_opcode=ida_hexrays.m_nop)

        mba = _build_suffix_mba({1: blk_a, 2: blk_s, 3: blk_t})
        state = _patch_suffix_dependencies(monkeypatch, mba)
        modifier = dm.DeferredGraphModifier(mba)

        ok = modifier._apply_private_terminal_suffix(
            anchor_blk=blk_a,
            shared_entry_serial=2,
            suffix_serials=(2, 3),
            clone_expected_serials=(),
        )

        assert ok is True

        # Two clones created: one for S (serial 4), one for T (serial 5)
        assert len(state["clones_created"]) == 2
        clone_s_info = state["clones_created"][0]
        clone_t_info = state["clones_created"][1]
        assert clone_s_info[0] == 2  # template = S
        assert clone_s_info[2] is False  # not 0-way (interior)
        assert clone_s_info[3] == 2  # placeholder target = shared_entry_serial
        assert clone_t_info[0] == 3  # template = T
        assert clone_t_info[2] is True  # 0-way (final)
        assert clone_t_info[3] is None  # no target for 0-way

        clone_s_serial = clone_s_info[1]
        clone_t_serial = clone_t_info[1]

        # Successor changes: chain wiring + anchor redirect
        # 1. Wire clone_S -> clone_T
        # 2. Redirect anchor A -> clone_S
        wiring_changes = [
            (s, t)
            for s, t in state["successor_changes"]
            if s not in (1,)  # exclude anchor redirect and stop-block fixes
            and s >= 4  # only cloned blocks
        ]
        anchor_redirects = [(s, t) for s, t in state["successor_changes"] if s == 1]

        assert any(s == clone_s_serial and t == clone_t_serial for s, t in wiring_changes), (
            f"Expected clone_S({clone_s_serial}) -> clone_T({clone_t_serial}), got {wiring_changes}"
        )
        assert any(t == clone_s_serial for _, t in anchor_redirects), (
            f"Expected anchor redirect to clone_S({clone_s_serial}), got {anchor_redirects}"
        )

        # Original S->T chain is unchanged (blocks still in MBA)
        assert 2 in mba.blocks
        assert 3 in mba.blocks

    def test_apply_suffix_anchor_wrong_successor_fails_closed(self, monkeypatch):
        """When anchor does NOT point at shared_entry_serial, apply rejects (P1 Bug 2)."""
        # Anchor points at block 5 (not the shared entry 2)
        blk_a = _make_suffix_block(1, nsucc=1, succ_serial=5, tail_opcode=ida_hexrays.m_goto)
        blk_s = _make_suffix_block(2, nsucc=1, succ_serial=3, tail_opcode=ida_hexrays.m_goto)
        blk_t = _make_suffix_block(3, nsucc=0, succ_serial=0)
        blk_other = _make_suffix_block(5, nsucc=1, succ_serial=3)

        mba = _build_suffix_mba({1: blk_a, 2: blk_s, 3: blk_t, 5: blk_other})
        state = _patch_suffix_dependencies(monkeypatch, mba)
        modifier = dm.DeferredGraphModifier(mba)

        ok = modifier._apply_private_terminal_suffix(
            anchor_blk=blk_a,
            shared_entry_serial=2,  # anchor points at 5, not 2
            suffix_serials=(2, 3),
            clone_expected_serials=(),
        )

        assert ok is False
        # No clones should have been created
        assert len(state["clones_created"]) == 0
        # Anchor successor unchanged
        assert blk_a.succ(0) == 5

    def test_apply_suffix_multi_block_chain(self, monkeypatch):
        """3-block suffix (S1->S2->T) exercises multi-block chain wiring (P1 Bug 3).

        Non-final clones must get placeholder target_serial for chain wiring.
        """
        blk_a = _make_suffix_block(1, nsucc=1, succ_serial=2, tail_opcode=ida_hexrays.m_goto)
        blk_s1 = _make_suffix_block(2, nsucc=1, succ_serial=3, tail_opcode=ida_hexrays.m_goto)
        blk_s2 = _make_suffix_block(3, nsucc=1, succ_serial=4, tail_opcode=ida_hexrays.m_goto)
        blk_t = _make_suffix_block(4, nsucc=0, succ_serial=0)

        mba = _build_suffix_mba({1: blk_a, 2: blk_s1, 3: blk_s2, 4: blk_t})
        state = _patch_suffix_dependencies(monkeypatch, mba)
        modifier = dm.DeferredGraphModifier(mba)

        ok = modifier._apply_private_terminal_suffix(
            anchor_blk=blk_a,
            shared_entry_serial=2,
            suffix_serials=(2, 3, 4),
            clone_expected_serials=(),
        )

        assert ok is True

        # Three clones created
        assert len(state["clones_created"]) == 3

        # Non-final clones (S1, S2) get placeholder target (shared_entry_serial=2)
        clone_s1_info = state["clones_created"][0]
        clone_s2_info = state["clones_created"][1]
        clone_t_info = state["clones_created"][2]

        assert clone_s1_info[2] is False  # not 0-way
        assert clone_s1_info[3] == 2  # placeholder target = shared_entry_serial
        assert clone_s2_info[2] is False  # not 0-way
        assert clone_s2_info[3] == 2  # placeholder target = shared_entry_serial
        assert clone_t_info[2] is True  # 0-way (final)
        assert clone_t_info[3] is None  # no target

        clone_s1_serial = clone_s1_info[1]
        clone_s2_serial = clone_s2_info[1]
        clone_t_serial = clone_t_info[1]

        # Chain wiring: clone_S1 -> clone_S2 -> clone_T
        chain_wires = [
            (s, t)
            for s, t in state["successor_changes"]
            if s in (clone_s1_serial, clone_s2_serial)
        ]
        assert (clone_s1_serial, clone_s2_serial) in chain_wires
        assert (clone_s2_serial, clone_t_serial) in chain_wires

        # Anchor redirect: A -> clone_S1
        assert any(
            s == 1 and t == clone_s1_serial
            for s, t in state["successor_changes"]
        )

    def test_apply_suffix_clone_serial_mismatch_non_fatal(self, monkeypatch):
        """Expected serials that don't match actual IDA serials are non-fatal (P1 Bug 1).

        Apply must still succeed with clones created and anchor rewired.
        """
        blk_a = _make_suffix_block(1, nsucc=1, succ_serial=2, tail_opcode=ida_hexrays.m_goto)
        blk_s = _make_suffix_block(2, nsucc=1, succ_serial=3, tail_opcode=ida_hexrays.m_goto)
        blk_t = _make_suffix_block(3, nsucc=0, succ_serial=0)

        mba = _build_suffix_mba({1: blk_a, 2: blk_s, 3: blk_t})
        state = _patch_suffix_dependencies(monkeypatch, mba)
        modifier = dm.DeferredGraphModifier(mba)

        # Expected serials (99, 100) will NOT match actual (4, 5)
        ok = modifier._apply_private_terminal_suffix(
            anchor_blk=blk_a,
            shared_entry_serial=2,
            suffix_serials=(2, 3),
            clone_expected_serials=(99, 100),
        )

        # Must succeed despite serial mismatch (informational only)
        assert ok is True
        assert len(state["clones_created"]) == 2

        # Anchor was redirected to actual clone serial (not the expected one)
        clone_s_serial = state["clones_created"][0][1]
        assert any(
            s == 1 and t == clone_s_serial
            for s, t in state["successor_changes"]
        )


# ---------------------------------------------------------------------------
#  TestStagedAtomic -- Strategy B: stage-into-new-blocks apply path
# ---------------------------------------------------------------------------


class _StagedFakeBlock(_FakeBlock):
    """Extended fake block with configurable nsucc, iterable predset, and stable ``start`` EA.

    The ``start`` field models ``mblock_t.start`` — the byte-address range
    start, which IDA guarantees is stable across ``insert_block`` /
    ``copy_block`` / ``remove_block``.  Serials shift; ``start`` does not.
    The staged_atomic Bug 3 fix re-resolves blocks by ``start`` EA at every
    phase boundary so stale serials are never dereferenced.
    """

    def __init__(
        self,
        serial: int,
        *,
        nsucc: int = 1,
        succ_serial: int = 0,
        start: int | None = None,
    ):
        super().__init__(serial, start=start)
        self.succset = _SuffixEdgeSet([succ_serial] if nsucc >= 1 else [])
        self.predset = _SuffixEdgeSet()
        self._nsucc_override = nsucc
        self._succ_override = succ_serial

    def nsucc(self) -> int:  # type: ignore[override]
        return self.succset.size()

    def succ(self, _idx: int) -> int:  # type: ignore[override]
        return self.succset[_idx]


class _StagedFakeMBA(_FakeMBA):
    """Extended fake MBA with copy_block + remove_block hooks for staging tests.

    ``get_mblock(serial)`` respects the positional block array: after a
    simulated ``remove_block`` or ``copy_block`` shifts serials, lookups
    by the *old* serial return the block now sitting at that index, not
    the original block.  This reproduces the serial-shift behaviour of
    real IDA MBA that exposed Bug 3 in the staged_atomic pipeline.
    """

    def __init__(self):
        super().__init__()
        self.copied_blocks: list[tuple[int, int]] = []  # (src_serial, new_serial)
        self.removed_blocks: list[int] = []
        # Inject a BLT_STOP block so mba.qty - 1 is valid.
        self.blocks[1] = _StagedFakeBlock(1, nsucc=0)
        self.qty = 2

    def copy_block(self, src_blk, new_serial, cpblk_flags=3):
        """Simulate mba.copy_block -- append a copy at new_serial, shift BLT_STOP.

        The freshly-minted copy gets a fresh ``start`` EA (distinct from the
        source) so tests can confirm the staged_atomic pipeline tracks each
        block by its stable start address.
        """
        # Synthesize a fresh start EA for the copy — in real IDA the
        # copy shares the source's byte range, but for test purposes we
        # need a distinct EA so we can validate EA-based resolution of
        # copy-vs-original.  Place it in the high range so it doesn't
        # collide with existing fake blocks.
        fresh_start = 0x1F000000 + len(self.copied_blocks) * 0x100
        copy = _StagedFakeBlock(new_serial, nsucc=0, start=fresh_start)
        # Faithfully replicate the full succset (2-way blocks need both edges).
        for k in range(src_blk.succset.size()):
            copy.succset.push_back(src_blk.succset[k])
        copy.type = src_blk.type
        copy.tail = src_blk.tail
        # copy_block inherits predset/succset from src
        for k in range(src_blk.predset.size()):
            copy.predset.push_back(src_blk.predset[k])
        self.copied_blocks.append((src_blk.serial, new_serial))

        # Shift existing BLT_STOP (highest serial) up by one — this is
        # exactly the serial-drift pattern that makes serial-based handles
        # unsafe in the staged_atomic pipeline.
        max_existing = max(self.blocks.keys())
        old_stop = self.blocks.pop(max_existing)
        new_stop_serial = max_existing + 1
        old_stop.serial = new_stop_serial
        self.blocks[new_stop_serial] = old_stop
        self.blocks[new_serial] = copy
        self.qty = new_stop_serial + 1
        return copy

    def remove_block(self, blk):
        self.removed_blocks.append(blk.serial)
        if blk.serial in self.blocks:
            del self.blocks[blk.serial]

    def simulate_serial_shift(self, *, removed_serial: int) -> None:
        """Helper: simulate IDA's post-``remove_block`` serial compaction.

        Real IDA ``remove_block`` shifts every serial greater than the
        removed index down by one.  ``_StagedFakeMBA.remove_block`` by
        itself only deletes the dict entry; this helper mirrors the
        positional-compaction behaviour so unit tests can exercise the
        EA-based lookup under *real* serial drift.
        """
        shifted: dict[int, _StagedFakeBlock] = {}
        for serial, blk in self.blocks.items():
            if serial > removed_serial:
                new_serial = serial - 1
                blk.serial = new_serial
                shifted[new_serial] = blk
            else:
                shifted[serial] = blk
        self.blocks = shifted
        self.qty = max(self.blocks.keys()) + 1 if self.blocks else 0


def _staged_patch_wiring(monkeypatch, mba):
    """Patch change_*_block_successor to operate on _StagedFakeBlock succset."""
    changes: list[tuple[int, int, str]] = []

    def _fake_1way(blk, new_target, verify=True):
        old_target = blk.succset[0] if blk.succset.size() > 0 else None
        blk.succset.clear()
        blk.succset.push_back(new_target)
        if old_target is not None:
            old_succ = mba.get_mblock(old_target)
            if old_succ is not None:
                old_succ.predset._del(blk.serial)
        new_succ = mba.get_mblock(new_target)
        if new_succ is not None:
            new_succ.predset.push_back(blk.serial)
        changes.append((blk.serial, new_target, "1way"))
        return True

    def _fake_2way(blk, new_target, verify=True, old_target=None):
        if blk.tail is not None and hasattr(blk.tail, "d") and blk.tail.d is not None:
            blk.tail.d.b = new_target
        blk.succset.clear()
        blk.succset.push_back(new_target)
        new_succ = mba.get_mblock(new_target)
        if new_succ is not None:
            new_succ.predset.push_back(blk.serial)
        changes.append((blk.serial, new_target, "2way"))
        return True

    def _fake_make_goto(blk, new_target, verify=True):
        blk.succset.clear()
        blk.succset.push_back(new_target)
        changes.append((blk.serial, new_target, "make_goto"))
        return True

    def _fake_remove_edge(blk, to_serial, verify=True):
        blk.succset._del(to_serial)
        changes.append((blk.serial, to_serial, "remove_edge"))
        return True

    monkeypatch.setattr(dm, "change_1way_block_successor", _fake_1way)
    monkeypatch.setattr(dm, "change_2way_block_conditional_successor", _fake_2way)
    monkeypatch.setattr(dm, "make_2way_block_goto", _fake_make_goto)
    monkeypatch.setattr(dm, "remove_block_edge", _fake_remove_edge)
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
    monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_a, **_k: setattr(mba, "cleaned", mba.cleaned + 1))

    return changes


class TestStagedAtomicClassification:
    """Module-level classification helpers for staged_atomic."""

    def test_classify_for_staged_atomic_goto_is_destructive_expressible(self):
        """BLOCK_GOTO_CHANGE is a destructive-expressible mod under staged_atomic."""
        cls = dm.classify_for_staged_atomic(dm.ModificationType.BLOCK_GOTO_CHANGE)
        assert cls == dm.StagedAtomicClassification.DESTRUCTIVE_EXPRESSIBLE

    def test_classify_for_staged_atomic_insn_nop_is_instruction_only(self):
        """INSN_NOP touches instructions only, never topology."""
        cls = dm.classify_for_staged_atomic(dm.ModificationType.INSN_NOP)
        assert cls == dm.StagedAtomicClassification.INSTRUCTION_ONLY

    def test_classify_for_staged_atomic_reorder_is_additive(self):
        """REORDER_BLOCKS already uses copy_block pattern -- classified ADDITIVE."""
        cls = dm.classify_for_staged_atomic(dm.ModificationType.REORDER_BLOCKS)
        assert cls == dm.StagedAtomicClassification.ADDITIVE

    def test_classify_all_known_mod_types_have_classification(self):
        """Every ModificationType must have a staged_atomic classification."""
        for mod_type in dm.ModificationType:
            cls = dm.classify_for_staged_atomic(mod_type)
            assert isinstance(cls, dm.StagedAtomicClassification), (
                f"{mod_type.name} returned {cls!r}"
            )

    def test_classify_destructive_expressible_bucket_contents(self):
        """Destructive-expressible bucket must contain the four known in-place mods."""
        expected = {
            dm.ModificationType.BLOCK_GOTO_CHANGE,
            dm.ModificationType.BLOCK_TARGET_CHANGE,
            dm.ModificationType.BLOCK_CONVERT_TO_GOTO,
            dm.ModificationType.EDGE_REMOVE,
        }
        actual = {
            mt for mt in dm.ModificationType
            if dm.classify_for_staged_atomic(mt)
            == dm.StagedAtomicClassification.DESTRUCTIVE_EXPRESSIBLE
        }
        assert actual == expected


class TestStagedAtomicPendingRewire:
    """Data contract for the _StagedPendingRewire record."""

    def test_pending_rewire_carries_block_pointers(self):
        """_StagedPendingRewire holds direct mblock_t pointers.

        Bug 4 fix: copy_block preserves source ``start`` EA, so
        EA-based lookup cannot distinguish original from copy.  The
        record now holds direct block pointers (stable across
        insert_block/copy_block) and uses them for all phase-boundary
        re-resolution.  Serial/EA fields are kept for diagnostics.
        """
        orig = _FakeBlock(10, start=0x1800C100)
        new = _FakeBlock(42, start=0x1F000000)
        pred_a = _FakeBlock(5, start=0x1800C500)
        pred_b = _FakeBlock(6, start=0x1800C600)
        rw = dm._StagedPendingRewire(
            original_blk=orig,
            new_blk=new,
            preds_to_redirect=(pred_a, pred_b),
            mod_type=dm.ModificationType.BLOCK_GOTO_CHANGE,
            original_serial=10,
            new_serial=42,
            original_start_ea=0x1800C100,
            new_start_ea=0x1F000000,
        )
        assert rw.original_blk is orig
        assert rw.new_blk is new
        assert rw.preds_to_redirect == (pred_a, pred_b)
        assert rw.original_serial == 10
        assert rw.new_serial == 42
        assert rw.original_start_ea == 0x1800C100
        assert rw.new_start_ea == 0x1F000000
        import dataclasses
        assert dataclasses.is_dataclass(rw)


class TestStagedAtomicApply:
    """Integration tests for DeferredGraphModifier.apply(staged_atomic=True)."""

    def test_staged_atomic_goto_change_stages_copy_and_redirects_preds(
        self, monkeypatch,
    ):
        """Destructive-expressible BLOCK_GOTO_CHANGE is lowered to copy-and-swap.

        Before: blk[5] (pred=10) -> blk[20]
        After:  blk[10] -> copy(5) -> blk[30]; original blk[5] orphaned.
        """
        mba = _StagedFakeMBA()
        # Build: blk[5] is 1-way -> blk[20]; blk[10] is pred targeting blk[5].
        src = _StagedFakeBlock(5, nsucc=1, succ_serial=20)
        src.predset.push_back(10)
        pred = _StagedFakeBlock(10, nsucc=1, succ_serial=5)
        tgt = _StagedFakeBlock(20, nsucc=0)
        tgt.predset.push_back(5)
        mba.blocks.update({5: src, 10: pred, 20: tgt})
        mba.qty = max(mba.blocks.keys()) + 1

        changes = _staged_patch_wiring(monkeypatch, mba)

        modifier = dm.DeferredGraphModifier(mba)
        modifier.modifications = [
            dm.GraphModification(
                dm.ModificationType.BLOCK_GOTO_CHANGE,
                block_serial=5,
                new_target=30,
                description="goto 5 -> 30",
            ),
        ]

        applied = modifier.apply(
            run_optimize_local=False,
            run_deep_cleaning=False,
            staged_atomic=True,
        )

        # Exactly one copy was staged.
        assert len(mba.copied_blocks) == 1
        src_serial, copy_serial = mba.copied_blocks[0]
        assert src_serial == 5

        # Commit phase redirected pred blk[10] to the copy.
        pred_redirects = [(s, t, kind) for (s, t, kind) in changes if s == 10]
        assert any(t == copy_serial for (_, t, _) in pred_redirects)

        # applied counts both staging and commit rewire.
        assert applied >= 1

    def test_staged_atomic_instruction_only_bypasses_staging(self, monkeypatch):
        """INSN_NOP must NOT trigger copy_block; it runs through _apply_single."""
        mba = _StagedFakeMBA()
        blk = _StagedFakeBlock(5, nsucc=1, succ_serial=1)
        blk.head = _FakeInsn(opcode=ida_hexrays.m_mov, ea=0x1234)
        blk.tail = blk.head
        mba.blocks[5] = blk
        mba.qty = 6

        _staged_patch_wiring(monkeypatch, mba)

        modifier = dm.DeferredGraphModifier(mba)
        modifier.modifications = [
            dm.GraphModification(
                dm.ModificationType.INSN_NOP,
                block_serial=5,
                insn_ea=0x1234,
                description="nop insn",
            ),
        ]

        nop_calls: list[int] = []

        def _fake_make_nop(self, _ins):
            nop_calls.append(self.serial)

        monkeypatch.setattr(_StagedFakeBlock, "make_nop", _fake_make_nop, raising=False)

        applied = modifier.apply(
            run_optimize_local=False,
            run_deep_cleaning=False,
            staged_atomic=True,
        )

        # No block copies were made: instruction-only mods skip staging.
        assert len(mba.copied_blocks) == 0
        assert applied >= 1

    def test_staged_atomic_default_false_does_not_change_control_flow(
        self, monkeypatch,
    ):
        """staged_atomic=False (default) preserves the existing sequential path."""
        mba = _StagedFakeMBA()
        modifier = dm.DeferredGraphModifier(mba)
        modifier.modifications = [
            dm.GraphModification(
                dm.ModificationType.BLOCK_GOTO_CHANGE,
                block_serial=0,
                new_target=1,
            ),
        ]

        captured_calls: list[str] = []

        def _fake_apply_single(_mod):
            captured_calls.append("sequential")
            return True

        monkeypatch.setattr(modifier, "_apply_single", _fake_apply_single)
        monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
        monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
        monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_a, **_k: None)

        applied = modifier.apply(run_optimize_local=False, run_deep_cleaning=False)
        # Default path still uses _apply_single via the sequential for-loop.
        assert applied == 1
        assert captured_calls == ["sequential"]
        # No staging copies performed.
        assert len(mba.copied_blocks) == 0

    def test_staged_atomic_failed_staging_does_not_rewire_preds(self, monkeypatch):
        """If staging fails, no commit rewire is issued and preds stay on original."""
        mba = _StagedFakeMBA()
        src = _StagedFakeBlock(5, nsucc=2, succ_serial=20)  # 2-way — rejects BLOCK_GOTO_CHANGE staging
        src.succset.push_back(30)
        src.predset.push_back(10)
        pred = _StagedFakeBlock(10, nsucc=1, succ_serial=5)
        mba.blocks.update({5: src, 10: pred})
        mba.qty = max(mba.blocks.keys()) + 1

        changes = _staged_patch_wiring(monkeypatch, mba)

        modifier = dm.DeferredGraphModifier(mba)
        modifier.modifications = [
            dm.GraphModification(
                dm.ModificationType.BLOCK_GOTO_CHANGE,
                block_serial=5,
                new_target=30,
            ),
        ]

        applied = modifier.apply(
            run_optimize_local=False,
            run_deep_cleaning=False,
            staged_atomic=True,
        )

        # Mutation on the copy fails (block is 2-way, not 1-way).
        # BUT: copy_block IS called first (stage step 2).  The mutation (step 3)
        # fails, so NO pending rewire is recorded, and NO external pred is
        # redirected.  Result: pred blk[10] still targets blk[5].
        pred_changes = [(s, t) for (s, t, _) in changes if s == 10]
        assert not pred_changes, f"pred should not be redirected, got {pred_changes}"
        assert applied == 0

    def test_staged_atomic_classify_mixed_bucket(self, monkeypatch):
        """Mixed mod list: one destructive, one instruction-only, one additive."""
        mba = _StagedFakeMBA()
        src = _StagedFakeBlock(5, nsucc=1, succ_serial=20)
        src.predset.push_back(10)
        pred = _StagedFakeBlock(10, nsucc=1, succ_serial=5)
        tgt = _StagedFakeBlock(20, nsucc=0)
        tgt.predset.push_back(5)
        other = _StagedFakeBlock(7, nsucc=1, succ_serial=1)
        other.head = _FakeInsn(opcode=ida_hexrays.m_mov, ea=0x5678)
        other.tail = other.head
        mba.blocks.update({5: src, 10: pred, 20: tgt, 7: other})
        mba.qty = max(mba.blocks.keys()) + 1

        _staged_patch_wiring(monkeypatch, mba)
        # Stub make_nop so INSN_NOP doesn't crash.
        monkeypatch.setattr(
            _StagedFakeBlock, "make_nop", lambda self, _ins: None, raising=False,
        )

        modifier = dm.DeferredGraphModifier(mba)
        modifier.modifications = [
            dm.GraphModification(
                dm.ModificationType.BLOCK_GOTO_CHANGE,
                block_serial=5,
                new_target=30,
                description="destructive",
            ),
            dm.GraphModification(
                dm.ModificationType.INSN_NOP,
                block_serial=7,
                insn_ea=0x5678,
                description="insn-only",
            ),
        ]

        applied = modifier.apply(
            run_optimize_local=False,
            run_deep_cleaning=False,
            staged_atomic=True,
        )

        # Both mods applied, each through its own path:
        # - destructive via stage + commit rewire
        # - instruction-only via _apply_single
        assert applied >= 2
        # Exactly one copy was made (for the destructive mod's source block).
        assert len(mba.copied_blocks) == 1

    def test_staged_atomic_entry_block_pred_rewires_via_direct_succset(
        self, monkeypatch,
    ):
        """Bug 1 — Entry-block (serial 0) rewire must bypass change_1way_block_successor.

        The 1-way wiring helper rejects ``serial == 0`` unconditionally.  When
        the source block's sole pred is the synthetic function-entry block
        (blk[0]), staged_atomic must rewire via direct succset/predset ``_del`` +
        ``push_back`` rather than routing through the rejecting helper.  If the
        direct-rewire path is missing, the entry edge stays on the original
        block and the copy is orphaned from the outside.
        """
        mba = _StagedFakeMBA()
        # Build: entry blk[0] -> blk[5] (1-way) -> blk[20].
        src = _StagedFakeBlock(5, nsucc=1, succ_serial=20)
        src.predset.push_back(0)  # sole pred is the synthetic entry block
        # Make blk[0] a real 1-way block targeting blk[5].  It is the ONLY
        # pred of blk[5] (no other fake preds).
        entry = mba.blocks[0]
        entry.succset = _SuffixEdgeSet([5])
        tgt = _StagedFakeBlock(20, nsucc=0)
        tgt.predset.push_back(5)
        mba.blocks.update({5: src, 20: tgt})
        mba.qty = max(mba.blocks.keys()) + 1

        changes = _staged_patch_wiring(monkeypatch, mba)

        modifier = dm.DeferredGraphModifier(mba)
        modifier.modifications = [
            dm.GraphModification(
                dm.ModificationType.BLOCK_GOTO_CHANGE,
                block_serial=5,
                new_target=30,
                description="goto 5 -> 30 (entry block pred)",
            ),
        ]

        applied = modifier.apply(
            run_optimize_local=False,
            run_deep_cleaning=False,
            staged_atomic=True,
        )

        # A copy was staged.
        assert len(mba.copied_blocks) == 1
        _src_serial, copy_serial = mba.copied_blocks[0]

        # The direct-rewire path must have severed blk[0] -> blk[5] and
        # wired blk[0] -> copy.  Because we bypass change_1way_block_successor
        # for serial 0, no (0, *, "1way") entry is recorded by the patched
        # wiring helpers — we validate the succset/predset state instead.
        assert 5 not in list(entry.succset), (
            "entry blk[0] must no longer target the original blk[5]"
        )
        assert copy_serial in list(entry.succset), (
            "entry blk[0] must target the copy after direct rewire"
        )
        assert 0 not in list(src.predset), (
            "original blk[5] must no longer list blk[0] as a pred"
        )
        copy_blk = mba.get_mblock(copy_serial)
        assert 0 in list(copy_blk.predset), (
            "copy must list blk[0] as a pred after direct rewire"
        )
        # Sanity: no "1way"-style wrapper call ever fired for the entry block.
        assert not any(s == 0 for (s, _t, _k) in changes), (
            "entry-block rewire must avoid change_1way_block_successor "
            "(which rejects serial 0)"
        )
        # Commit rewire counts toward applied.
        assert applied >= 1

    def test_staged_atomic_cleanup_pre_disconnects_edges_before_remove(
        self, monkeypatch,
    ):
        """Bug 2 — cleanup must strip succset/predset entries before remove_block.

        IDA's ``mba.remove_block`` errors with INTERR 51919 when the block
        still has outgoing (succset) or incoming (predset) entries at removal
        time.  The cleanup phase must pre-disconnect both sides of every edge
        before invoking ``remove_block``.  Simulate a _StagedFakeMBA whose
        ``remove_block`` raises unless both sides are empty — confirm the
        cleanup phase satisfies the precondition in practice.
        """
        mba = _StagedFakeMBA()
        src = _StagedFakeBlock(5, nsucc=1, succ_serial=20)
        src.predset.push_back(10)
        pred = _StagedFakeBlock(10, nsucc=1, succ_serial=5)
        tgt = _StagedFakeBlock(20, nsucc=0)
        tgt.predset.push_back(5)
        mba.blocks.update({5: src, 10: pred, 20: tgt})
        mba.qty = max(mba.blocks.keys()) + 1

        _staged_patch_wiring(monkeypatch, mba)

        # Tighten remove_block: INTERR 51919 if the block still has edges.
        removed_ok: list[int] = []
        remove_calls: list[tuple[int, int, int]] = []  # (serial, succset_sz, predset_sz)

        def _strict_remove_block(self, blk):
            succsz = blk.succset.size()
            predsz = blk.predset.size()
            remove_calls.append((blk.serial, succsz, predsz))
            if succsz != 0 or predsz != 0:
                raise RuntimeError(
                    f"INTERR 51919: blk[{blk.serial}] still has "
                    f"succset={succsz} predset={predsz}"
                )
            removed_ok.append(blk.serial)
            if blk.serial in self.blocks:
                del self.blocks[blk.serial]

        monkeypatch.setattr(_StagedFakeMBA, "remove_block", _strict_remove_block)

        modifier = dm.DeferredGraphModifier(mba)
        modifier.modifications = [
            dm.GraphModification(
                dm.ModificationType.BLOCK_GOTO_CHANGE,
                block_serial=5,
                new_target=30,
                description="goto 5 -> 30 (cleanup test)",
            ),
        ]

        applied = modifier.apply(
            run_optimize_local=False,
            run_deep_cleaning=False,
            staged_atomic=True,
        )

        # The staged rewire + cleanup pipeline must have disconnected
        # edges on the original block BEFORE calling remove_block, so the
        # strict-remove guard never fires INTERR 51919.
        assert remove_calls, "cleanup phase never invoked remove_block"
        assert 5 in removed_ok, (
            "original blk[5] must have been removed after cleanup "
            f"(remove_calls={remove_calls}, removed={removed_ok})"
        )
        # Every recorded remove_block call saw empty succset/predset.
        for serial, succsz, predsz in remove_calls:
            assert succsz == 0, (
                f"remove_block(blk[{serial}]) saw succset size {succsz} -- "
                "cleanup failed to pre-disconnect outgoing edges"
            )
            assert predsz == 0, (
                f"remove_block(blk[{serial}]) saw predset size {predsz} -- "
                "cleanup failed to pre-disconnect incoming edges"
            )
        assert applied >= 1


class TestStagedAtomicEaIdentity:
    """Bug 3 — EA-based identity for stage -> commit -> cleanup pipeline.

    ``mba.remove_block`` / ``mba.copy_block`` / ``mba.insert_block`` shift
    block *serials* while ``mblock_t.start`` (byte-address range start) is
    stable.  The staged_atomic pipeline must therefore use start EAs as
    block *handles* across phase boundaries.  These tests validate:

    1. Staging captures each block's start EA (not just serials).
    2. Commit re-resolves by start EA after simulated serial drift.
    3. Cleanup does not remove the wrong block when serials have shifted.
    4. A captured-EA block removed out-of-band causes a skipped rewire
       with a warning (no crash, no wrong-block mutation).
    """

    def test_get_mblock_by_start_ea_returns_none_when_missing(self):
        """Helper must return None for an unknown EA (no exception)."""
        mba = _StagedFakeMBA()
        assert dm._get_mblock_by_start_ea(mba, 0xDEADBEEF) is None

    def test_get_mblock_by_start_ea_finds_block_after_simulated_shift(self):
        """After a simulated serial shift, EA-based lookup still finds the right block."""
        mba = _StagedFakeMBA()
        src = _StagedFakeBlock(5, nsucc=1, succ_serial=20, start=0x18001000)
        mba.blocks[5] = src
        mba.qty = max(mba.blocks.keys()) + 1

        # Baseline: EA lookup finds the block at serial 5.
        found = dm._get_mblock_by_start_ea(mba, 0x18001000)
        assert found is src
        assert found.serial == 5

        # Simulate a copy_block that shifted serial 5's position.
        # (We manually shift — not via mba.copy_block — to isolate the
        # lookup behaviour under pure serial drift.)
        shifted = {}
        for serial, blk in mba.blocks.items():
            if serial == 5:
                blk.serial = 7
                shifted[7] = blk
            else:
                shifted[serial] = blk
        mba.blocks = shifted
        mba.qty = max(mba.blocks.keys()) + 1

        # Lookup by serial 5 now returns None (or the wrong block).
        # Lookup by start EA must still find the block at its new serial.
        found_after = dm._get_mblock_by_start_ea(mba, 0x18001000)
        assert found_after is src
        assert found_after.serial == 7, "EA-based lookup must find the drifted block"

    def test_stage_captures_start_eas_on_pending_rewire(self, monkeypatch):
        """_stage_destructive_mod_via_copy records start EA for original + copy + preds."""
        mba = _StagedFakeMBA()
        src = _StagedFakeBlock(5, nsucc=1, succ_serial=20, start=0x18005000)
        src.predset.push_back(10)
        pred = _StagedFakeBlock(10, nsucc=1, succ_serial=5, start=0x1800A000)
        tgt = _StagedFakeBlock(20, nsucc=0, start=0x18014000)
        tgt.predset.push_back(5)
        mba.blocks.update({5: src, 10: pred, 20: tgt})
        mba.qty = max(mba.blocks.keys()) + 1

        _staged_patch_wiring(monkeypatch, mba)

        modifier = dm.DeferredGraphModifier(mba)
        mod = dm.GraphModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE,
            block_serial=5,
            new_target=30,
        )
        rewire = modifier._stage_destructive_mod_via_copy(mod, index=0)

        assert rewire is not None, "staging must succeed for 1-way BLOCK_GOTO_CHANGE"
        # Original serial/ea captured pre-copy.
        assert rewire.original_serial == 5
        assert rewire.original_start_ea == 0x18005000
        # Copy got a fresh EA (0x1F000000 by the fake MBA's synthesizer).
        assert rewire.new_start_ea != rewire.original_start_ea
        copy_blk = mba.get_mblock(rewire.new_serial)
        assert copy_blk is not None
        assert rewire.new_start_ea == copy_blk.start
        # Pred snapshot recorded as mblock_t pointers (Bug 4 fix).
        # copy_block preserves source EAs, so EA-based lookup cannot
        # disambiguate original from copy; the record now holds direct
        # pointers captured at stage time.
        assert len(rewire.preds_to_redirect) == 1
        assert rewire.preds_to_redirect[0] is pred

    def test_commit_re_resolves_original_by_ea_after_staging_shift(self, monkeypatch):
        """After a Phase 2 inner staging shift, commit still hits the right block.

        Simulate: a later staging step shifts the serial of an already-staged
        original block (e.g. BLT_STOP moves, compacting inner serials).
        The commit phase must locate the original by its captured start EA,
        not by the now-stale ``original_serial``.
        """
        mba = _StagedFakeMBA()
        src = _StagedFakeBlock(5, nsucc=1, succ_serial=20, start=0x18005000)
        src.predset.push_back(10)
        pred = _StagedFakeBlock(10, nsucc=1, succ_serial=5, start=0x1800A000)
        tgt = _StagedFakeBlock(20, nsucc=0, start=0x18014000)
        tgt.predset.push_back(5)
        mba.blocks.update({5: src, 10: pred, 20: tgt})
        mba.qty = max(mba.blocks.keys()) + 1

        changes = _staged_patch_wiring(monkeypatch, mba)

        modifier = dm.DeferredGraphModifier(mba)
        mod = dm.GraphModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE,
            block_serial=5,
            new_target=30,
        )
        rewire = modifier._stage_destructive_mod_via_copy(mod, index=0)
        assert rewire is not None
        staged_orig_serial = rewire.original_serial
        staged_copy_serial = rewire.new_serial

        # Simulate a drift: shuffle serial numbers without touching start EAs.
        # This models what a second copy_block (for a different staged mod)
        # would do to the positional block array: IDA's real copy_block
        # not only shifts blk.serial but also rewrites every succset/predset
        # entry pointing at any shifted block.  Mirror both effects so the
        # fake MBA behaves like the real one.
        SHIFT = 3
        old_to_new = {s: s + SHIFT for s in mba.blocks}
        shuffled: dict[int, _StagedFakeBlock] = {}
        for serial, blk in mba.blocks.items():
            new_serial = old_to_new[serial]
            blk.serial = new_serial
            # Update every outgoing edge to point at the new serial of its target.
            remapped_succs = [
                old_to_new.get(int(blk.succset[k]), int(blk.succset[k]))
                for k in range(blk.succset.size())
            ]
            blk.succset.clear()
            for s in remapped_succs:
                blk.succset.push_back(s)
            # Update every incoming edge the same way.
            remapped_preds = [
                old_to_new.get(int(blk.predset[k]), int(blk.predset[k]))
                for k in range(blk.predset.size())
            ]
            blk.predset.clear()
            for s in remapped_preds:
                blk.predset.push_back(s)
            shuffled[new_serial] = blk
        mba.blocks = shuffled
        mba.qty = max(mba.blocks.keys()) + 1

        # After drift, the staging serials are stale.  Commit must re-resolve
        # by EA.
        ok = modifier._commit_staged_rewire(rewire)
        assert ok is True, (
            "commit must succeed even after serial drift, by re-resolving "
            "original + copy + preds via their captured start EAs"
        )
        # The recorded wiring change targeted the (post-drift) copy serial.
        copy_blk_now = dm._get_mblock_by_start_ea(mba, rewire.new_start_ea)
        assert copy_blk_now is not None
        assert any(
            t == copy_blk_now.serial for (_, t, _) in changes
        ), (
            f"commit must redirect pred to the copy's CURRENT serial "
            f"({copy_blk_now.serial}), not the staging-time serial "
            f"({staged_copy_serial}); changes={changes}, "
            f"staged_orig_serial={staged_orig_serial}"
        )

    def test_cleanup_ignores_stale_serial_and_uses_ea(self, monkeypatch):
        """Cleanup must remove the block with the captured EA, even if serials shifted.

        If we relied on ``rewire.original_serial`` after the commit phase
        did its work, cleanup would either (a) fail silently because the
        serial now points to a different block, or (b) worse, remove the
        wrong block.  EA-based re-resolution eliminates both failure modes.
        """
        mba = _StagedFakeMBA()
        src = _StagedFakeBlock(5, nsucc=1, succ_serial=20, start=0x18005000)
        src.predset.push_back(10)
        pred = _StagedFakeBlock(10, nsucc=1, succ_serial=5, start=0x1800A000)
        tgt = _StagedFakeBlock(20, nsucc=0, start=0x18014000)
        tgt.predset.push_back(5)
        mba.blocks.update({5: src, 10: pred, 20: tgt})
        mba.qty = max(mba.blocks.keys()) + 1

        _staged_patch_wiring(monkeypatch, mba)

        modifier = dm.DeferredGraphModifier(mba)
        modifier.modifications = [
            dm.GraphModification(
                dm.ModificationType.BLOCK_GOTO_CHANGE,
                block_serial=5,
                new_target=30,
            ),
        ]

        # Capture the src object up-front — tests that cleanup removed
        # *this specific object*, regardless of its serial at removal time.
        original_src_id = id(src)

        applied = modifier.apply(
            run_optimize_local=False,
            run_deep_cleaning=False,
            staged_atomic=True,
        )
        assert applied >= 1

        # Cleanup must have called remove_block on the block at start_ea
        # 0x18005000 — the original src.  Inject a marker: ensure mba.removed_blocks
        # contains the serial that the src had at the *time of removal*
        # (which may differ from the staging-time serial 5 if drift occurred).
        # Regardless of serial, src must no longer be in mba.blocks.
        assert not any(id(b) == original_src_id for b in mba.blocks.values()), (
            "cleanup must have removed the specific src block object "
            "(identified by its captured start EA), not a wrong block "
            "at the stale serial"
        )

    def test_cleanup_removes_correct_block_after_multi_stage_serial_drift(
        self, monkeypatch,
    ):
        """Multiple staged mods -> cumulative serial drift -> cleanup targets each by EA.

        Stage two destructive mods on different source blocks.  Each copy_block
        shifts the BLT_STOP serial.  Cleanup, iterating in descending EA order,
        must re-resolve each original by its captured start EA and remove the
        correct object — not fall for the stale serial that now points at a
        different (live) block.
        """
        mba = _StagedFakeMBA()
        # Two independent source blocks, each with a distinct pred and succ.
        src_a = _StagedFakeBlock(5, nsucc=1, succ_serial=20, start=0x18005000)
        src_a.predset.push_back(10)
        pred_a = _StagedFakeBlock(10, nsucc=1, succ_serial=5, start=0x1800A000)
        tgt_a = _StagedFakeBlock(20, nsucc=0, start=0x18014000)
        tgt_a.predset.push_back(5)

        src_b = _StagedFakeBlock(6, nsucc=1, succ_serial=21, start=0x18006000)
        src_b.predset.push_back(11)
        pred_b = _StagedFakeBlock(11, nsucc=1, succ_serial=6, start=0x1800B000)
        tgt_b = _StagedFakeBlock(21, nsucc=0, start=0x18015000)
        tgt_b.predset.push_back(6)

        mba.blocks.update({
            5: src_a, 6: src_b, 10: pred_a, 11: pred_b, 20: tgt_a, 21: tgt_b,
        })
        mba.qty = max(mba.blocks.keys()) + 1

        _staged_patch_wiring(monkeypatch, mba)

        modifier = dm.DeferredGraphModifier(mba)
        modifier.modifications = [
            dm.GraphModification(
                dm.ModificationType.BLOCK_GOTO_CHANGE,
                block_serial=5,
                new_target=30,
                description="destructive A",
            ),
            dm.GraphModification(
                dm.ModificationType.BLOCK_GOTO_CHANGE,
                block_serial=6,
                new_target=31,
                description="destructive B",
            ),
        ]

        applied = modifier.apply(
            run_optimize_local=False,
            run_deep_cleaning=False,
            staged_atomic=True,
        )
        assert applied >= 2, f"expected two staged rewires, got applied={applied}"

        # Both original source objects must be gone from mba.blocks, identified
        # by their stable start EAs — not by their staging-time serials.
        live_starts = {b.start for b in mba.blocks.values()}
        assert src_a.start not in live_starts, (
            "src_a (ea=0x18005000) must be removed by cleanup"
        )
        assert src_b.start not in live_starts, (
            "src_b (ea=0x18006000) must be removed by cleanup"
        )
        # Both copies survived (distinct synthetic EAs per _StagedFakeMBA).
        assert len(mba.copied_blocks) == 2

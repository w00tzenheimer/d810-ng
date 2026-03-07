from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.cfg.contracts.ida_contract import CfgContractViolationError
from d810.cfg.contracts.report import InvariantViolation
from d810.cfg.flowgraph import InsnSnapshot
from d810.hexrays.mutation import deferred_modifier as dm


class _FakeEdgeSet:
    """Minimal stub for IDA succset/predset (intvec_t-like interface)."""

    def __init__(self, items: list[int] | None = None):
        self._items: list[int] = list(items) if items else []

    def size(self) -> int:
        return len(self._items)

    def __getitem__(self, idx: int) -> int:
        return self._items[idx]

    def clear(self) -> None:
        self._items.clear()

    def push_back(self, val: int) -> None:
        self._items.append(val)


class _FakeBlock:
    def __init__(self, serial: int):
        self.serial = serial
        self.type = ida_hexrays.BLT_1WAY
        self.tail = SimpleNamespace(opcode=ida_hexrays.m_goto, ea=0x1000, l=None, d=None, r=None)
        self.succset = _FakeEdgeSet()
        self.predset = _FakeEdgeSet()

    def nsucc(self) -> int:
        return 1

    def succ(self, _idx: int) -> int:
        return 0

    def npred(self) -> int:
        return 0

    def pred(self, _idx: int) -> int:
        return 0


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


def test_create_conditional_redirect_rejects_unexpected_serial(monkeypatch):
    mba = _FakeMBA()
    source = _FakeBlock(5)
    ref = _FakeBlock(6)
    mba.blocks.update({5: source, 6: ref})
    mba.qty = len(mba.blocks)

    modifier = dm.DeferredGraphModifier(mba)

    monkeypatch.setattr(dm.ida_hexrays, "is_mcode_jcond", lambda _opcode: True)
    monkeypatch.setattr(
        dm,
        "duplicate_block",
        lambda *_a, **_k: (_FakeBlock(7), _FakeBlock(8)),
    )

    cond_calls = {"count": 0}
    ft_calls = {"count": 0}
    src_calls = {"count": 0}
    monkeypatch.setattr(
        dm,
        "change_2way_block_conditional_successor",
        lambda *_a, **_k: cond_calls.__setitem__("count", cond_calls["count"] + 1) or True,
    )
    monkeypatch.setattr(
        dm,
        "change_1way_block_successor",
        lambda blk, *_a, **_k: (
            ft_calls.__setitem__("count", ft_calls["count"] + 1)
            if blk.serial == 8
            else src_calls.__setitem__("count", src_calls["count"] + 1)
        ) or True,
    )

    ok = modifier._apply_create_conditional_redirect(
        source_blk=source,
        ref_blk_serial=6,
        conditional_target_serial=10,
        fallthrough_target_serial=11,
        expected_conditional_serial=9,
        expected_fallthrough_serial=8,
    )

    assert ok is False
    assert cond_calls["count"] == 0
    assert ft_calls["count"] == 0
    assert src_calls["count"] == 0


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

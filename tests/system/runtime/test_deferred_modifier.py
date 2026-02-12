from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.hexrays import deferred_modifier as dm


class _FakeBlock:
    def __init__(self, serial: int):
        self.serial = serial
        self.type = ida_hexrays.BLT_1WAY
        self.tail = SimpleNamespace(opcode=ida_hexrays.m_goto, ea=0x1000)

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
    )
    assert ok is False
    assert called["create"] == 0


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
    assert mba.cleaned == 1
    assert modifier.verify_failed is False

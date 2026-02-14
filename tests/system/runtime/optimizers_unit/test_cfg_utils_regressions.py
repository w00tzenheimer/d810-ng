"""Regression tests for cfg_utils CFG safety guards.

These tests run with mocked IDA modules and focus on crash-prone CFG helpers:
1. ensure_child_has_an_unconditional_father() default-child handling
2. create_block(is_0_way=True) goto cleanup
"""

from __future__ import annotations

import json
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


class _FakeSet(list):
    def push_back(self, value):
        self.append(value)

    def _del(self, value):
        if value in self:
            self.remove(value)


class _FakeMBA:
    def __init__(self, qty: int = 12):
        self.qty = qty
        self.entry_ea = 0x1000
        self.maturity = 0
        self.blocks: dict[int, _FakeBlock] = {}
        self.marked_dirty = 0
        self.verify_error: RuntimeError | None = None

    def get_mblock(self, serial: int):
        return self.blocks[serial]

    def mark_chains_dirty(self):
        self.marked_dirty += 1

    def verify(self, _always: bool):
        if self.verify_error is not None:
            raise self.verify_error


class _FakeBlock:
    def __init__(
        self,
        serial: int,
        mba: _FakeMBA,
        succs: list[int] | None = None,
        preds: list[int] | None = None,
        tail=None,
    ):
        self.serial = serial
        self.mba = mba
        self.succset = _FakeSet(succs or [])
        self.predset = _FakeSet(preds or [])
        self.tail = tail
        self.type = 1
        self.flags = 0
        self.marked_dirty = 0
        self.nopped: list[object] = []
        mba.blocks[serial] = self

    def nsucc(self) -> int:
        return len(self.succset)

    def mark_lists_dirty(self):
        self.marked_dirty += 1

    def make_nop(self, ins):
        self.nopped.append(ins)


@pytest.fixture(autouse=True)
def _mock_cfg_utils_import_deps():
    """Load cfg_utils with minimal mocked IDA/transitive Hex-Rays deps."""
    mock_hexrays = SimpleNamespace(
        BLT_0WAY=0,
        BLT_1WAY=1,
        BLT_2WAY=2,
        MBL_GOTO=0x20,
        m_goto=0x37,
    )
    mock_idaapi = MagicMock()

    class _Printer:
        def get_block_mc(self):
            return ""

    modules_to_mock = {
        "ida_hexrays": mock_hexrays,
        "idaapi": mock_idaapi,
        "d810.hexrays.hexrays_formatters": SimpleNamespace(block_printer=lambda: _Printer()),
        "d810.hexrays.hexrays_helpers": SimpleNamespace(CONDITIONAL_JUMP_OPCODES=frozenset()),
    }

    # Ensure cfg_utils imports against this fixture's module mocks.
    popped = {}
    for mod_name in (
        "d810.hexrays.cfg_utils",
        "d810.hexrays.hexrays_formatters",
        "d810.hexrays.hexrays_helpers",
    ):
        if mod_name in sys.modules:
            popped[mod_name] = sys.modules.pop(mod_name)

    with patch.dict("sys.modules", modules_to_mock):
        yield

    # Restore previously cached modules.
    for mod_name, mod in popped.items():
        sys.modules[mod_name] = mod


def test_ensure_child_skips_default_child_rewrite(monkeypatch):
    """Default-child path must not create helper blocks (orphan risk / INTERR 50856)."""
    from d810.hexrays import cfg_utils

    mba = _FakeMBA(qty=20)
    father = _FakeBlock(
        3,
        mba,
        succs=[4, 5],
        tail=SimpleNamespace(d=SimpleNamespace(b=4)),
    )
    child = _FakeBlock(5, mba, succs=[])

    calls = {"insert": 0, "c1": 0, "c2": 0}
    monkeypatch.setattr(
        cfg_utils,
        "insert_nop_blk",
        lambda *_a, **_k: calls.__setitem__("insert", calls["insert"] + 1),
    )
    monkeypatch.setattr(
        cfg_utils,
        "change_1way_block_successor",
        lambda *_a, **_k: calls.__setitem__("c1", calls["c1"] + 1),
    )
    monkeypatch.setattr(
        cfg_utils,
        "change_2way_block_conditional_successor",
        lambda *_a, **_k: calls.__setitem__("c2", calls["c2"] + 1),
    )
    monkeypatch.setattr(
        cfg_utils,
        "create_standalone_block",
        lambda *_a, **_k: pytest.fail("create_standalone_block should not be called"),
    )

    changed = cfg_utils.ensure_child_has_an_unconditional_father(
        father,
        child,
        verify=False,
    )

    assert changed == 0
    assert calls == {"insert": 0, "c1": 0, "c2": 0}


def test_ensure_child_conditional_path_rewires_via_helper_block(monkeypatch):
    """Conditional-child path should still perform the helper-block rewrite."""
    from d810.hexrays import cfg_utils

    mba = _FakeMBA(qty=120)
    father = _FakeBlock(
        10,
        mba,
        succs=[11, 12],
        tail=SimpleNamespace(d=SimpleNamespace(b=33)),
    )
    child = _FakeBlock(33, mba, succs=[])
    new_father = _FakeBlock(77, mba, succs=[11])

    calls = {"standalone": None, "c2": None}

    def _change_2way(blk, serial, verify=True):
        calls["c2"] = (blk.serial, serial, verify)
        return True

    def _create_standalone(ref_blk, blk_ins, target_serial, is_0_way, verify=True):
        calls["standalone"] = (
            ref_blk.serial,
            list(blk_ins),
            target_serial,
            is_0_way,
            verify,
        )
        return new_father

    monkeypatch.setattr(cfg_utils, "create_standalone_block", _create_standalone)
    monkeypatch.setattr(cfg_utils, "change_2way_block_conditional_successor", _change_2way)

    changed = cfg_utils.ensure_child_has_an_unconditional_father(
        father,
        child,
        verify=False,
    )

    assert changed == 1
    assert calls["standalone"] == (10, [], 33, False, False)
    assert calls["c2"] == (10, 77, False)


@pytest.mark.parametrize(
    "father_factory",
    [
        lambda mba: None,
        lambda mba: _FakeBlock(1, mba, succs=[2], tail=SimpleNamespace(d=SimpleNamespace(b=2))),
        lambda mba: _FakeBlock(2, mba, succs=[3, 4, 5], tail=SimpleNamespace(d=SimpleNamespace(b=5))),
        lambda mba: _FakeBlock(3, mba, succs=[4, 5], tail=None),
    ],
)
def test_ensure_child_guard_paths_noop(father_factory, monkeypatch):
    """Guard clauses should no-op without touching CFG rewrite helpers."""
    from d810.hexrays import cfg_utils

    mba = _FakeMBA(qty=20)
    child = _FakeBlock(9, mba, succs=[])
    father = father_factory(mba)

    monkeypatch.setattr(
        cfg_utils,
        "insert_nop_blk",
        lambda *_a, **_k: pytest.fail("insert_nop_blk should not be called"),
    )
    monkeypatch.setattr(
        cfg_utils,
        "create_standalone_block",
        lambda *_a, **_k: pytest.fail("create_standalone_block should not be called"),
    )
    monkeypatch.setattr(
        cfg_utils,
        "change_1way_block_successor",
        lambda *_a, **_k: pytest.fail("change_1way_block_successor should not be called"),
    )
    monkeypatch.setattr(
        cfg_utils,
        "change_2way_block_conditional_successor",
        lambda *_a, **_k: pytest.fail("change_2way_block_conditional_successor should not be called"),
    )

    changed = cfg_utils.ensure_child_has_an_unconditional_father(
        father,
        child,
        verify=False,
    )
    assert changed == 0


def test_create_block_0way_clears_goto_and_edges(monkeypatch):
    """0-way created blocks must not keep insert_nop_blk's goto (INTERR 50856 regression)."""
    from d810.hexrays import cfg_utils

    mba = _FakeMBA(qty=12)
    prev_succ = _FakeBlock(7, mba, succs=[], preds=[6])
    ref_blk = _FakeBlock(2, mba, succs=[7])
    new_blk = _FakeBlock(
        6,
        mba,
        succs=[7],
        preds=[],
        tail=SimpleNamespace(opcode=cfg_utils.ida_hexrays.m_goto),
    )
    new_blk.flags = cfg_utils.ida_hexrays.MBL_GOTO

    monkeypatch.setattr(cfg_utils, "insert_nop_blk", lambda _blk: new_blk)

    result = cfg_utils.create_block(
        ref_blk,
        blk_ins=[],
        is_0_way=True,
        verify=False,
    )

    assert result is new_blk
    assert new_blk.type == cfg_utils.ida_hexrays.BLT_0WAY
    assert (new_blk.flags & cfg_utils.ida_hexrays.MBL_GOTO) == 0
    assert new_blk.nopped == [new_blk.tail]
    assert list(new_blk.succset) == []
    assert 6 not in prev_succ.predset
    assert prev_succ.marked_dirty == 1
    assert new_blk.marked_dirty == 1
    assert mba.marked_dirty == 1


def test_safe_verify_persists_failure_artifact(tmp_path, monkeypatch):
    """safe_verify should emit a JSON artifact with focused block capture."""
    from d810.hexrays import cfg_utils

    mba = _FakeMBA(qty=6)
    _FakeBlock(0, mba, succs=[1], preds=[])
    _FakeBlock(
        1,
        mba,
        succs=[2],
        preds=[0],
        tail=SimpleNamespace(
            ea=0x1234,
            opcode=0x37,
            l=SimpleNamespace(t=0, b=2),
            d=SimpleNamespace(t=0, b=3),
        ),
    )
    _FakeBlock(2, mba, succs=[3], preds=[1])
    mba.verify_error = RuntimeError("Unknown exception")

    monkeypatch.setenv("D810_VERIFY_CAPTURE", "1")
    monkeypatch.setenv("D810_VERIFY_CAPTURE_DIR", str(tmp_path))

    with pytest.raises(RuntimeError):
        cfg_utils.safe_verify(
            mba,
            "unit-test verify failure",
            capture_blocks=[1],
            capture_metadata={"rule": "unit_test_rule", "mod_index": 7},
        )

    artifacts = list(tmp_path.glob("verify_fail_*.json"))
    assert len(artifacts) == 1

    payload = json.loads(artifacts[0].read_text(encoding="utf-8"))
    assert payload["context"] == "verify failure after unit-test verify failure"
    assert payload["error_type"] == "RuntimeError"
    assert payload["metadata"]["rule"] == "unit_test_rule"
    assert 1 in payload["focus_blocks"]
    captured_serials = {blk["serial"] for blk in payload["captured_blocks"]}
    assert 1 in captured_serials


def test_verify_failure_analyzer_contract_matches_capture_artifact(tmp_path, monkeypatch, capsys):
    """Analyzer contract should accept payloads produced by safe_verify/capture_failure_artifact."""
    from d810.hexrays import cfg_utils
    from tools import analyze_verify_failures as avf

    mba = _FakeMBA(qty=7)
    _FakeBlock(0, mba, succs=[1], preds=[])
    _FakeBlock(
        1,
        mba,
        succs=[2, 3],
        preds=[0],
        tail=SimpleNamespace(
            ea=0x2222,
            opcode=0x44,
            l=SimpleNamespace(t=0, b=2),
            d=SimpleNamespace(t=0, b=3),
        ),
    )
    _FakeBlock(2, mba, succs=[4], preds=[1])
    _FakeBlock(3, mba, succs=[4], preds=[1])
    _FakeBlock(4, mba, succs=[], preds=[2, 3])
    mba.verify_error = RuntimeError("Unknown exception")

    monkeypatch.setenv("D810_VERIFY_CAPTURE", "1")
    monkeypatch.setenv("D810_VERIFY_CAPTURE_DIR", str(tmp_path))

    with pytest.raises(RuntimeError):
        cfg_utils.safe_verify(
            mba,
            "unit-test analyzer contract",
            capture_blocks=[1, 2],
            capture_metadata={
                "phase": "incremental_verify",
                "modification": {
                    "mod_type": "BLOCK_GOTO_CHANGE",
                    "block_serial": 1,
                    "new_target": 4,
                    "description": "unit-test change",
                },
            },
        )

    artifacts = sorted(tmp_path.glob("verify_fail_*.json"))
    assert len(artifacts) == 1
    payload = avf._load_artifact(artifacts[0])

    # Contract check: analyzer-required shape should be present in real captures.
    contract_warnings = avf._validate_capture_contract(payload)
    assert contract_warnings == []

    # Heuristic APIs should consume captured payload without fallback contract warnings.
    hypotheses = avf._infer_hypotheses(payload)
    assert hypotheses
    assert not any("Artifact contract warnings:" in h for h in hypotheses)
    formatted = avf._format_entry(payload, artifacts[0])
    assert "Contract warnings:" not in formatted

    # CLI JSON mode should include contract_warnings=[] for this artifact.
    rc = avf.main([str(tmp_path), "--latest", "1", "--json"])
    assert rc == 0
    out = capsys.readouterr().out
    rendered = json.loads(out)
    assert rendered["count"] == 1
    assert rendered["artifacts"][0]["contract_warnings"] == []

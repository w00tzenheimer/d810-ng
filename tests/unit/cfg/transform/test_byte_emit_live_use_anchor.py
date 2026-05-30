"""Unit tests for the split-XOR live-use anchor orchestrator.

No IDA. Fake adapter records every call. The point of these tests is
the *control flow* of the orchestrator, not the IR shape of the anchor
(that is verified end-to-end by the snap18 v190 count experiment).
"""
from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from d810.core.typing import Any

from d810.transforms.byte_emit_live_use_anchor import (
    ByteEmitAnchorReport,
    execute_split_xor_anchor,
    parse_byte_anchor_env,
)
from d810.transforms.byte_emit_tail_isolation import BlockView


class _AnchorInsertFailure(RuntimeError):
    """Used to simulate adapter.insert_anchor_block_xor_pair() raising."""


@dataclass(slots=True)
class _OperandStub:
    label: str = "v190+#6.8"


@dataclass(slots=True)
class FakeAnchorAdapter:
    """Fake adapter mimicking LiveUseAnchorAdapter for unit tests."""

    byte_emit_block: BlockView | None = None
    source_operand: Any | None = field(default_factory=_OperandStub)
    pre_return_serial: int | None = 222
    insert_results: list[int] = field(default_factory=lambda: [301, 302])
    raise_on_extract: Exception | None = None
    raise_on_pre_return: Exception | None = None
    raise_on_insert: list[Exception | None] = field(default_factory=lambda: [None, None])

    calls_find_byte_emit: list[int] = field(default_factory=list)
    calls_extract: list[tuple[int, int]] = field(default_factory=list)
    calls_find_pre_return: int = 0
    calls_insert: list[dict] = field(default_factory=list)

    def find_byte_emit_block_by_v190_offset(self, byte_index: int) -> BlockView | None:
        self.calls_find_byte_emit.append(byte_index)
        return self.byte_emit_block

    def extract_v190_indexed_operand(self, byte_emit_serial: int, byte_index: int) -> Any:
        self.calls_extract.append((byte_emit_serial, byte_index))
        if self.raise_on_extract is not None:
            raise self.raise_on_extract
        return self.source_operand

    def find_pre_return_block(self) -> int:
        self.calls_find_pre_return += 1
        if self.raise_on_pre_return is not None:
            raise self.raise_on_pre_return
        assert self.pre_return_serial is not None
        return self.pre_return_serial

    def insert_anchor_block_xor_pair(
        self,
        *,
        predecessor_serial: int,
        successor_serial: int,
        source_addr_operand: Any,
        accumulator_stkoff: int,
    ) -> int:
        idx = len(self.calls_insert)
        self.calls_insert.append({
            "predecessor_serial": predecessor_serial,
            "successor_serial": successor_serial,
            "source_addr_operand": source_addr_operand,
            "accumulator_stkoff": accumulator_stkoff,
        })
        if idx < len(self.raise_on_insert) and self.raise_on_insert[idx] is not None:
            raise self.raise_on_insert[idx]
        return self.insert_results[idx]


def _byte6_block(serial: int = 200, succ: int = 201) -> BlockView:
    return BlockView(
        serial=serial,
        start_ea=0x7FFD3338C3A0,
        nsucc=1,
        succ_serial=succ,
        succ_npred=2,
        tail_kind="goto",
    )


# ---- parse_byte_anchor_env ------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("1", "split_xor"),
        (" 1 ", "split_xor"),
        ("0", None),
        ("2", None),
        ("xyz", None),
        ("", None),
        (None, None),
    ],
)
def test_parse_byte_anchor_env(value, expected):
    assert parse_byte_anchor_env(value) == expected


# ---- execute_split_xor_anchor --------------------------------------------


def test_happy_path_returns_applied():
    adapter = FakeAnchorAdapter(byte_emit_block=_byte6_block())
    report = execute_split_xor_anchor(byte_index=6, adapter=adapter)
    assert report.applied is True
    assert report.byte_index == 6
    assert report.mechanism == "split_xor"
    assert report.byte_emit_serial == 200
    assert report.anchor_a_serial == 301
    assert report.anchor_b_serial == 302
    assert report.accumulator_stkoff == 0x818
    # Both insert calls used the same source operand.
    assert adapter.calls_insert[0]["source_addr_operand"] is adapter.source_operand
    assert adapter.calls_insert[1]["source_addr_operand"] is adapter.source_operand
    # ANCHOR_A inserted between byte_emit and its original successor.
    assert adapter.calls_insert[0]["predecessor_serial"] == 200
    assert adapter.calls_insert[0]["successor_serial"] == 201
    # ANCHOR_B inserted between pre-return block and BLT_STOP's existing successor edge.
    assert adapter.calls_insert[1]["predecessor_serial"] == 222


def test_rejects_byte_index_not_six():
    adapter = FakeAnchorAdapter(byte_emit_block=_byte6_block())
    for bi in (0, 1, 2, 3, 4, 5, 7, -1):
        report = execute_split_xor_anchor(byte_index=bi, adapter=adapter)
        assert report.applied is False
        assert report.reason == "probe_byte6_only"
        assert report.byte_index == bi
    # No adapter calls made — gate fires first.
    assert adapter.calls_find_byte_emit == []


def test_rejects_when_byte_emit_unresolvable():
    adapter = FakeAnchorAdapter(byte_emit_block=None)
    report = execute_split_xor_anchor(byte_index=6, adapter=adapter)
    assert report.applied is False
    assert report.reason == "byte_emit_not_resolvable"
    assert adapter.calls_extract == []  # gated early


def test_rejects_when_source_operand_extraction_raises():
    adapter = FakeAnchorAdapter(
        byte_emit_block=_byte6_block(),
        raise_on_extract=RuntimeError("no xdu sub-expr"),
    )
    report = execute_split_xor_anchor(byte_index=6, adapter=adapter)
    assert report.applied is False
    assert report.reason == "source_operand_unavailable"
    assert adapter.calls_find_pre_return == 0


def test_rejects_when_pre_return_ambiguous():
    adapter = FakeAnchorAdapter(
        byte_emit_block=_byte6_block(),
        raise_on_pre_return=RuntimeError("multiple BLT_STOP preds"),
    )
    report = execute_split_xor_anchor(byte_index=6, adapter=adapter)
    assert report.applied is False
    assert report.reason == "pre_return_ambiguous"
    assert adapter.calls_insert == []


def test_rejects_when_first_insert_fails():
    adapter = FakeAnchorAdapter(
        byte_emit_block=_byte6_block(),
        raise_on_insert=[_AnchorInsertFailure("anchor A fail"), None],
    )
    report = execute_split_xor_anchor(byte_index=6, adapter=adapter)
    assert report.applied is False
    assert report.reason == "anchor_insert_failed:a"
    assert len(adapter.calls_insert) == 1  # second call never attempted


def test_rejects_when_second_insert_fails():
    adapter = FakeAnchorAdapter(
        byte_emit_block=_byte6_block(),
        raise_on_insert=[None, _AnchorInsertFailure("anchor B fail")],
    )
    report = execute_split_xor_anchor(byte_index=6, adapter=adapter)
    assert report.applied is False
    assert report.reason == "anchor_insert_failed:b"
    assert len(adapter.calls_insert) == 2  # both attempted; second blew up


def test_report_is_frozen_dataclass():
    report = ByteEmitAnchorReport(
        applied=True,
        byte_index=6,
        mechanism="split_xor",
        reason="ok",
    )
    with pytest.raises(Exception):
        report.applied = False  # frozen

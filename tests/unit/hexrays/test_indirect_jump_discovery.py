"""Unit tests for structural indirect jump-table discovery (pure logic)."""
from d810.hexrays.preanalysis.indirect_jump_discovery import (
    _ea_owned_by_function,
    bound_table_count,
)

FUNC_START = 0x180013BD0
FUNC_END = 0x18001433F


def test_ea_ownership_predicate_bounds():
    assert _ea_owned_by_function(0x180013C2A, FUNC_START, FUNC_END)
    assert _ea_owned_by_function(FUNC_START, FUNC_START, FUNC_END)
    assert not _ea_owned_by_function(FUNC_END, FUNC_START, FUNC_END)
    assert not _ea_owned_by_function(0x7473656C6C616D53, FUNC_START, FUNC_END)


def test_bound_table_count_stops_at_first_out_of_function_qword():
    # 37 in-function targets followed by string data (mirrors the live table).
    targets = [
        0x180013D46, 0x180014106, 0x180013E91, 0x180013CB2, 0x1800141E8,
    ] + [0x180013C2A] * 32  # 5 + 32 = 37 in-function entries
    raw = targets + [0x7473656C6C616D53, 0x746E656D656C6520]
    count = bound_table_count(
        raw, func_start=FUNC_START, func_end=FUNC_END, max_entries=4096
    )
    assert count == 37


def test_bound_table_count_zero_terminates_walk():
    raw = [0x180013D46, 0x180013E91, 0, 0x180013CB2]
    count = bound_table_count(
        raw, func_start=FUNC_START, func_end=FUNC_END, max_entries=4096
    )
    assert count == 2


def test_bound_table_count_respects_max_entries_cap():
    raw = [0x180013C2A] * 100
    count = bound_table_count(
        raw, func_start=FUNC_START, func_end=FUNC_END, max_entries=10
    )
    assert count == 10


def test_bound_table_count_empty_when_first_entry_out_of_range():
    raw = [0xDEADBEEF, 0x180013C2A]
    count = bound_table_count(
        raw, func_start=FUNC_START, func_end=FUNC_END, max_entries=4096
    )
    assert count == 0

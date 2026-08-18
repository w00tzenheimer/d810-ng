"""Unit tests for structural indirect jump-table discovery (pure logic)."""

from d810.hexrays.preanalysis.indirect_jump_discovery import (
    _ea_owned_by_function,
    bound_table_count,
    validate_table_target_window,
)

FUNC_START = 0x180013BD0
FUNC_END = 0x18001433F
NEXT_FUNCTION_START = 0x180014CC0
TEXT_SEGMENT_START = 0x180010000
TEXT_SEGMENT_END = 0x180080000


def test_ea_ownership_predicate_bounds():
    assert _ea_owned_by_function(0x180013C2A, FUNC_START, FUNC_END)
    assert _ea_owned_by_function(FUNC_START, FUNC_START, FUNC_END)
    assert not _ea_owned_by_function(FUNC_END, FUNC_START, FUNC_END)
    assert not _ea_owned_by_function(0x7473656C6C616D53, FUNC_START, FUNC_END)


def test_bound_table_count_stops_at_first_out_of_function_qword():
    # 37 in-function targets followed by string data (mirrors the live table).
    targets = [
        0x180013D46,
        0x180014106,
        0x180013E91,
        0x180013CB2,
        0x1800141E8,
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


def test_extended_targets_use_next_function_boundary_in_same_executable_segment():
    targets = (FUNC_START + 0x20, FUNC_END + 0x20, FUNC_END + 0x2A0)

    assert (
        validate_table_target_window(
            targets,
            func_start=FUNC_START,
            func_end=FUNC_END,
            next_function_start=NEXT_FUNCTION_START,
            segment_start=TEXT_SEGMENT_START,
            segment_end=TEXT_SEGMENT_END,
            segment_executable=True,
        )
        == NEXT_FUNCTION_START
    )
    assert (
        bound_table_count(
            targets + (0x7473656C6C616D53,),
            func_start=FUNC_START,
            func_end=FUNC_END,
            next_function_start=NEXT_FUNCTION_START,
            segment_start=TEXT_SEGMENT_START,
            segment_end=TEXT_SEGMENT_END,
            segment_executable=True,
            max_entries=4096,
        )
        == len(targets)
    )


def test_extended_targets_without_primary_function_anchor_are_rejected():
    assert (
        validate_table_target_window(
            (FUNC_END + 0x20, FUNC_END + 0x2A0),
            func_start=FUNC_START,
            func_end=FUNC_END,
            next_function_start=NEXT_FUNCTION_START,
            segment_start=TEXT_SEGMENT_START,
            segment_end=TEXT_SEGMENT_END,
            segment_executable=True,
        )
        is None
    )


def test_primary_targets_keep_the_tighter_function_boundary():
    targets = (FUNC_START, FUNC_END - 1)

    assert (
        validate_table_target_window(
            targets,
            func_start=FUNC_START,
            func_end=FUNC_END,
            next_function_start=NEXT_FUNCTION_START,
            segment_start=TEXT_SEGMENT_START,
            segment_end=TEXT_SEGMENT_END,
            segment_executable=True,
        )
        == FUNC_END
    )


def test_extended_target_outside_next_function_window_is_rejected():
    assert (
        validate_table_target_window(
            (FUNC_END + 1, NEXT_FUNCTION_START),
            func_start=FUNC_START,
            func_end=FUNC_END,
            next_function_start=NEXT_FUNCTION_START,
            segment_start=TEXT_SEGMENT_START,
            segment_end=TEXT_SEGMENT_END,
            segment_executable=True,
        )
        is None
    )


def test_extended_target_in_mixed_segment_is_rejected():
    assert (
        validate_table_target_window(
            (FUNC_END + 1, FUNC_END + 2),
            func_start=FUNC_START,
            func_end=FUNC_END,
            next_function_start=NEXT_FUNCTION_START,
            segment_start=TEXT_SEGMENT_START,
            segment_end=FUNC_END + 1,
            segment_executable=True,
        )
        is None
    )


def test_extended_targets_in_non_executable_segment_are_rejected():
    assert (
        validate_table_target_window(
            (FUNC_END + 1,),
            func_start=FUNC_START,
            func_end=FUNC_END,
            next_function_start=NEXT_FUNCTION_START,
            segment_start=TEXT_SEGMENT_START,
            segment_end=TEXT_SEGMENT_END,
            segment_executable=False,
        )
        is None
    )

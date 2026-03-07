"""Unit tests for structured valrange records.

These tests verify the dump-stable formatting of the structured evaluator API
without requiring IDA/Hex-Rays.
"""
from __future__ import annotations

from d810.evaluator.hexrays_microcode.valranges import (
    ValrangeLocation,
    ValrangeLocationKind,
    ValrangeRecord,
)


class TestValrangeLocation:
    """Location identity should preserve enough structure for planner/proof use."""

    def test_register_location_label(self) -> None:
        loc = ValrangeLocation(
            kind=ValrangeLocationKind.REGISTER,
            identifier=0x12,
            width=8,
        )
        assert loc.ida_label == "%0x12.8"

    def test_stack_location_label(self) -> None:
        loc = ValrangeLocation(
            kind=ValrangeLocationKind.STACK,
            identifier=0xA8,
            width=4,
        )
        assert loc.ida_label == "%0xA8.4"


class TestValrangeRecord:
    """Structured records should stringify like the old dump-oriented API."""

    def test_record_str_matches_historic_dump_format(self) -> None:
        loc = ValrangeLocation(
            kind=ValrangeLocationKind.STACK,
            identifier=0xA8,
            width=4,
        )
        record = ValrangeRecord(
            block_serial=6,
            location=loc,
            range_text="==B2FD8FB6",
            instruction_ea=0x18000B19D,
        )
        assert str(record) == "%0xA8.4:==B2FD8FB6"

    def test_record_keeps_structured_metadata(self) -> None:
        loc = ValrangeLocation(
            kind=ValrangeLocationKind.REGISTER,
            identifier=7,
            width=8,
        )
        record = ValrangeRecord(
            block_serial=21,
            location=loc,
            range_text="!=0",
            instruction_ea=None,
        )
        assert record.block_serial == 21
        assert record.location.kind == ValrangeLocationKind.REGISTER
        assert record.location.identifier == 7
        assert record.location.width == 8
        assert record.range_text == "!=0"
        assert record.instruction_ea is None

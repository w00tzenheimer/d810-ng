"""Portable C-tree-to-native range relations."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

__all__ = [
    "CtreeNativeRangeProjection",
    "CtreeStatementNativeRanges",
    "NativeRange",
]


def _require_ea(value: object, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{field_name} must be an int")
    if value < 0:
        raise ValueError(f"{field_name} must be non-negative")
    return value


@dataclass(frozen=True, slots=True, order=True)
class NativeRange:
    start_ea: int
    end_ea: int

    def __post_init__(self) -> None:
        _require_ea(self.start_ea, "start_ea")
        _require_ea(self.end_ea, "end_ea")
        if self.end_ea <= self.start_ea:
            raise ValueError("end_ea must exceed start_ea")

    @property
    def length(self) -> int:
        return self.end_ea - self.start_ea

    def contains(self, ea: int) -> bool:
        _require_ea(ea, "ea")
        return self.start_ea <= ea < self.end_ea

    def contains_range(self, candidate: NativeRange) -> bool:
        if not isinstance(candidate, NativeRange):
            raise TypeError("candidate must be a NativeRange")
        return self.start_ea <= candidate.start_ea and candidate.end_ea <= self.end_ea


def _canonical_ranges(
    value: object,
    field_name: str,
    *,
    reject_overlap: bool,
) -> tuple[NativeRange, ...]:
    if not isinstance(value, tuple) or not all(
        isinstance(item, NativeRange) for item in value
    ):
        raise TypeError(f"{field_name} must be a tuple of NativeRange values")
    ranges = tuple(sorted(set(value)))
    if reject_overlap:
        for previous, current in zip(ranges, ranges[1:], strict=False):
            if current.start_ea < previous.end_ea:
                raise ValueError(f"{field_name} must not contain overlapping ranges")
    return ranges


@dataclass(frozen=True, slots=True)
class CtreeStatementNativeRanges:
    citem_index: int
    statement_op: int
    representative_ea: int | None
    ranges: tuple[NativeRange, ...]

    def __post_init__(self) -> None:
        _require_ea(self.citem_index, "citem_index")
        _require_ea(self.statement_op, "statement_op")
        if self.representative_ea is not None:
            _require_ea(self.representative_ea, "representative_ea")
        object.__setattr__(
            self,
            "ranges",
            _canonical_ranges(self.ranges, "ranges", reject_overlap=True),
        )


def _projection_content(
    *,
    function_ea: int,
    function_ranges: tuple[NativeRange, ...],
    statements: tuple[CtreeStatementNativeRanges, ...],
    ea_to_statement_indices: tuple[tuple[int, tuple[int, ...]], ...],
) -> tuple[object, ...]:
    return (
        function_ea,
        tuple((item.start_ea, item.end_ea) for item in function_ranges),
        tuple(
            (
                item.citem_index,
                item.statement_op,
                item.representative_ea,
                tuple((span.start_ea, span.end_ea) for span in item.ranges),
            )
            for item in statements
        ),
        ea_to_statement_indices,
    )


def _fingerprint(content: tuple[object, ...]) -> str:
    encoded = json.dumps(content, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class CtreeNativeRangeProjection:
    function_ea: int
    function_ranges: tuple[NativeRange, ...]
    statements: tuple[CtreeStatementNativeRanges, ...]
    ea_to_statement_indices: tuple[tuple[int, tuple[int, ...]], ...]
    fingerprint: str = ""

    def __post_init__(self) -> None:
        _require_ea(self.function_ea, "function_ea")
        function_ranges = _canonical_ranges(
            self.function_ranges,
            "function_ranges",
            reject_overlap=True,
        )
        if not function_ranges:
            raise ValueError("function_ranges must not be empty")
        if not any(item.contains(self.function_ea) for item in function_ranges):
            raise ValueError("function_ea must belong to function_ranges")

        if not isinstance(self.statements, tuple) or not all(
            isinstance(item, CtreeStatementNativeRanges) for item in self.statements
        ):
            raise TypeError(
                "statements must be a tuple of CtreeStatementNativeRanges values"
            )
        statement_by_index: dict[int, CtreeStatementNativeRanges] = {}
        for statement in self.statements:
            previous = statement_by_index.get(statement.citem_index)
            if previous is not None and previous != statement:
                raise ValueError("citem_index identifies conflicting statement rows")
            statement_by_index[statement.citem_index] = statement
            if statement.representative_ea is not None and not any(
                item.contains(statement.representative_ea) for item in function_ranges
            ):
                raise ValueError("representative_ea must belong to function_ranges")
            if any(
                not any(owner.contains_range(span) for owner in function_ranges)
                for span in statement.ranges
            ):
                raise ValueError(
                    "statement ranges must be contained in function_ranges"
                )
        statements = tuple(
            sorted(statement_by_index.values(), key=lambda item: item.citem_index)
        )

        if not isinstance(self.ea_to_statement_indices, tuple):
            raise TypeError("ea_to_statement_indices must be a tuple")
        reverse: dict[int, set[int]] = {}
        for row in self.ea_to_statement_indices:
            if (
                not isinstance(row, tuple)
                or len(row) != 2
                or not isinstance(row[1], tuple)
            ):
                raise TypeError(
                    "ea_to_statement_indices rows must be (ea, indices) tuples"
                )
            ea = _require_ea(row[0], "ea_to_statement_indices ea")
            if not any(item.contains(ea) for item in function_ranges):
                raise ValueError("reverse-map EA must belong to function_ranges")
            indices = row[1]
            if not all(
                isinstance(index, int) and not isinstance(index, bool) and index >= 0
                for index in indices
            ):
                raise TypeError(
                    "reverse-map statement indices must be non-negative ints"
                )
            unknown = set(indices).difference(statement_by_index)
            if unknown:
                raise ValueError("reverse map references an unknown statement")
            reverse.setdefault(ea, set()).update(indices)
        reverse_rows = tuple(
            (ea, tuple(sorted(indices))) for ea, indices in sorted(reverse.items())
        )

        content = _projection_content(
            function_ea=self.function_ea,
            function_ranges=function_ranges,
            statements=statements,
            ea_to_statement_indices=reverse_rows,
        )
        expected_fingerprint = _fingerprint(content)
        if self.fingerprint and self.fingerprint != expected_fingerprint:
            raise ValueError("fingerprint does not match projection content")

        object.__setattr__(self, "function_ranges", function_ranges)
        object.__setattr__(self, "statements", statements)
        object.__setattr__(self, "ea_to_statement_indices", reverse_rows)
        object.__setattr__(self, "fingerprint", expected_fingerprint)

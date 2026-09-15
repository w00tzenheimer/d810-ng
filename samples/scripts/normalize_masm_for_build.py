#!/usr/bin/env python3
"""Prepare structural IDA MASM exports for relocation-safe assembly.

The committed export is the hash-bound evidence.  This tool writes a derived
build input and never edits that evidence in place.  Rewrites are deliberately
limited to IDA renderer forms whose relocation meaning can be checked from the
same listing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path
from typing import Mapping, NamedTuple


_STRUCTURAL_EXPORT_MARKER = "Auto-generated x64 MASM (d810 structural export)"

_FRAME_TERM_RE = re.compile(
    r"\+(?P<frame>[0-9A-Fa-f]+)h\+var_(?P<offset>[0-9A-Fa-f]+)\b"
)
_INDEXED_SYMBOL_RE = re.compile(
    r"\((?P<symbol>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*-\s*(?P<absolute>[0-9A-Fa-f]+)h\)"
    r"\[(?P<address>[^\]\r\n]+)\]"
)
_INVALID_LOCK_SETO_RE = re.compile(
    r"^(?P<indent>[ \t]*)lock[ \t]+seto(?P<operand>[ \t]+[^\r\n]+)$",
    re.IGNORECASE | re.MULTILINE,
)
_DD_DEFINITION_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?:(?P<symbol>[A-Za-z_][A-Za-z0-9_]*)[ \t]+)?"
    r"dd[ \t]+(?P<value>[0-9A-Fa-f]+h?)[ \t]*(?:;.*)?(?:\r?\n)?$",
    re.IGNORECASE,
)
_NATIVE_TARGET_LABEL_RE = re.compile(
    r"^[ \t]*(?P<label>(?:loc|def)_[0-9A-Fa-f]+):",
    re.IGNORECASE | re.MULTILINE,
)
_TEXT_SEGMENT_RE = re.compile(
    r"^[ \t]*_TEXT[ \t]+SEGMENT\b[^\r\n]*(?:\r?\n)",
    re.IGNORECASE | re.MULTILINE,
)
_SYMBOLIC_RELATIVE_DWORD_RE = re.compile(
    r"^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*[ \t]+)?dd[ \t]+"
    r"(?:loc|def)_[0-9A-Fa-f]+[ \t]*-[ \t]*[A-Za-z_][A-Za-z0-9_]*",
    re.IGNORECASE | re.MULTILINE,
)
_DB_DEFINITION_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<symbol>[A-Za-z_][A-Za-z0-9_]*)[ \t]+"
    r"db[ \t]+(?P<values>[0-9A-Fa-fh, \t]+)[ \t]*(?:;.*)?(?:\r?\n)?$",
    re.IGNORECASE,
)
_SUPPLEMENT_SCHEMA = "d810.masm-materialized-relative-tables.v1"


class MasmNormalizationError(ValueError):
    """Raised when a prospective relocation rewrite is not locally proven."""


class NormalizationStats(NamedTuple):
    frame_terms: int = 0
    unwind_frames: int = 0
    rebased_indexed_symbols: int = 0
    raw_lock_prefixes: int = 0
    relative_jump_tables: int = 0
    relative_jump_entries: int = 0

    @property
    def total(self) -> int:
        return sum(self)


class NormalizationResult(NamedTuple):
    text: str
    stats: NormalizationStats


def _fold_frame_terms(text: str) -> tuple[str, int]:
    count = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        displacement = int(match.group("frame"), 16) - int(
            match.group("offset"), 16
        )
        if displacement == 0:
            return ""
        sign = "+" if displacement > 0 else "-"
        return f"{sign}{abs(displacement):X}h"

    return _FRAME_TERM_RE.sub(replace, text), count


_PUBLIC_RE = re.compile(
    r"^[ \t]*PUBLIC[ \t]+(?P<name>[A-Za-z_][A-Za-z0-9_]*)[ \t]*(?:;.*)?$",
    re.IGNORECASE,
)
_PUSH_NONVOLATILE_RE = re.compile(
    r"^(?P<indent>[ \t]*)push[ \t]+(?P<reg>rbx|rbp|rsi|rdi|r1[2-5])[ \t]*(?:;.*)?$",
    re.IGNORECASE,
)
_ALLOCSTACK_RE = re.compile(
    r"^(?P<indent>[ \t]*)sub[ \t]+rsp[ \t]*,[ \t]*(?P<size>[0-9A-Fa-f]+h|[0-9]+)[ \t]*(?:;.*)?$",
    re.IGNORECASE,
)


def _add_x64_unwind_frame(text: str) -> tuple[str, int]:
    """Annotate one exact manual x64 prologue for MASM unwind emission.

    The directives emit only ``.pdata``/``.xdata``; the instruction stream is
    unchanged.  Any prologue outside the narrow push-nonvolatiles plus
    ``sub rsp, imm`` shape remains untouched instead of being guessed.
    """

    lines = text.splitlines(keepends=True)
    public_names = [
        match.group("name")
        for line in lines
        if (match := _PUBLIC_RE.fullmatch(line.rstrip("\r\n"))) is not None
    ]
    if len(public_names) != 1:
        return text, 0
    function_name = public_names[0]
    label_index = next(
        (
            index
            for index, line in enumerate(lines)
            if line.strip().lower() == f"{function_name.lower()}:"
        ),
        None,
    )
    if label_index is None:
        return text, 0

    cursor = label_index + 1
    push_rows: list[tuple[int, str, str]] = []
    while cursor < len(lines):
        raw = lines[cursor].rstrip("\r\n")
        match = _PUSH_NONVOLATILE_RE.fullmatch(raw)
        if match is None:
            break
        push_rows.append((cursor, match.group("indent"), match.group("reg")))
        cursor += 1
    if not push_rows or cursor >= len(lines):
        return text, 0
    allocation = _ALLOCSTACK_RE.fullmatch(lines[cursor].rstrip("\r\n"))
    if allocation is None:
        return text, 0
    segment_end = next(
        (
            index
            for index in range(cursor + 1, len(lines))
            if re.fullmatch(
                r"[ \t]*_TEXT[ \t]+ENDS[ \t]*(?:;.*)?",
                lines[index].rstrip("\r\n"),
                re.IGNORECASE,
            )
        ),
        None,
    )
    if segment_end is None:
        return text, 0

    lines[label_index] = f"{function_name} PROC FRAME\n"
    insertions: dict[int, list[str]] = {}
    for index, indent, register in push_rows:
        insertions.setdefault(index, []).append(f"{indent}.pushreg {register}\n")
    indent = allocation.group("indent")
    size = allocation.group("size")
    insertions.setdefault(cursor, []).extend(
        (f"{indent}.allocstack {size}\n", f"{indent}.endprolog\n")
    )
    output: list[str] = []
    for index, line in enumerate(lines):
        if index == segment_end:
            output.append(f"{function_name} ENDP\n")
        output.append(line)
        output.extend(insertions.get(index, ()))
    return "".join(output), 1


def _has_symbol_definition(text: str, symbol: str) -> bool:
    return bool(
        re.search(
            rf"^[ \t]*{re.escape(symbol)}[ \t]+(?:db|dw|dd|dq|label)\b",
            text,
            re.IGNORECASE | re.MULTILINE,
        )
    )


def _has_matching_base_load(text: str, base: str, symbol: str) -> bool:
    return bool(
        re.search(
            rf"^[ \t]*lea[ \t]+{re.escape(base)}[ \t]*,[ \t]*"
            rf"(?:offset[ \t]+)?{re.escape(symbol)}[ \t]*(?:;.*)?$",
            text,
            re.IGNORECASE | re.MULTILINE,
        )
    )


def _rebase_indexed_symbols(text: str) -> tuple[str, int]:
    count = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal count
        symbol = match.group("symbol")
        address = match.group("address")
        base = address.split("+", 1)[0].strip()
        if not _has_symbol_definition(text, symbol):
            raise MasmNormalizationError(
                f"indexed symbol {symbol} has no materialized definition"
            )
        if not _has_matching_base_load(text, base, symbol):
            raise MasmNormalizationError(
                f"indexed symbol {symbol} has no matching LEA into base {base}"
            )
        count += 1
        return f"[{address}]"

    return _INDEXED_SYMBOL_RE.sub(replace, text), count


def _parse_dd_value(token: str) -> int:
    return int(token[:-1], 16) if token.lower().endswith("h") else int(token, 10)


def _native_target_labels(text: str) -> tuple[dict[int, str], dict[str, str]]:
    exact: dict[int, str] = {}
    defaults: dict[str, str] = {}
    for match in _NATIVE_TARGET_LABEL_RE.finditer(text):
        label = match.group("label")
        kind, suffix = label.split("_", 1)
        if kind.lower() == "loc":
            exact[int(suffix, 16)] = label
        else:
            defaults[suffix.lower()] = label
    return exact, defaults


def _relative_table_anchors(text: str) -> dict[str, int]:
    anchors: dict[str, int] = {}
    for match in _INDEXED_SYMBOL_RE.finditer(text):
        symbol = match.group("symbol")
        address = match.group("address")
        base = address.split("+", 1)[0].strip()
        if not _has_symbol_definition(text, symbol):
            raise MasmNormalizationError(
                f"indexed symbol {symbol} has no materialized definition"
            )
        if not _has_matching_base_load(text, base, symbol):
            raise MasmNormalizationError(
                f"indexed symbol {symbol} has no matching LEA into base {base}"
            )
        anchor = int(match.group("absolute"), 16)
        prior = anchors.setdefault(symbol, anchor)
        if prior != anchor:
            raise MasmNormalizationError(
                f"indexed symbol {symbol} has conflicting source anchors"
            )
    return anchors


def _parse_db_values(raw: str) -> tuple[int, ...]:
    return tuple(
        _parse_dd_value(token.strip()) & 0xFF
        for token in raw.split(",")
        if token.strip()
    )


def _relocate_relative_jump_tables(
    text: str,
    supplemental_tables: Mapping[str, tuple[int, ...]],
) -> tuple[str, int, int]:
    """Rewrite source-relative table values into linked-label differences.

    The structural exporter preserves the original 32-bit deltas but emits a
    symbolic displacement that cannot survive relocation.  Stripping that
    displacement without rewriting the deltas makes every target relative to
    the new table address.  Resolve each original delta against its explicit
    source anchor, require a matching native target label, and place the
    derived table beside its destinations in ``_TEXT``.
    """
    anchors = _relative_table_anchors(text)
    if not anchors:
        return text, 0, 0

    exact_labels, default_labels = _native_target_labels(text)
    lines = text.splitlines(keepends=True)
    removed: set[int] = set()
    relocated: list[str] = []
    table_count = 0
    entry_count = 0

    for symbol, anchor in anchors.items():
        definition_index = None
        values: list[int] = []
        indexes: list[int] = []
        for index, line in enumerate(lines):
            match = _DD_DEFINITION_RE.match(line)
            if match and match.group("symbol") == symbol:
                definition_index = index
                break
        if definition_index is not None:
            for index in range(definition_index, len(lines)):
                match = _DD_DEFINITION_RE.match(lines[index])
                if match is None:
                    break
                row_symbol = match.group("symbol")
                if index != definition_index and row_symbol is not None:
                    break
                values.append(_parse_dd_value(match.group("value")) & 0xFFFFFFFF)
                indexes.append(index)
        else:
            supplement = supplemental_tables.get(symbol)
            if supplement is None:
                raise MasmNormalizationError(
                    f"indexed symbol {symbol} has no relative dword table"
                )
            byte_index = None
            materialized_prefix: tuple[int, ...] = ()
            for index, line in enumerate(lines):
                match = _DB_DEFINITION_RE.match(line)
                if match and match.group("symbol") == symbol:
                    byte_index = index
                    materialized_prefix = _parse_db_values(match.group("values"))
                    break
            if byte_index is None:
                raise MasmNormalizationError(
                    f"supplemented symbol {symbol} has no materialized byte prefix"
                )
            supplement_bytes = b"".join(
                struct.pack("<I", int(value) & 0xFFFFFFFF) for value in supplement
            )
            if supplement_bytes[: len(materialized_prefix)] != bytes(materialized_prefix):
                raise MasmNormalizationError(
                    f"supplemented symbol {symbol} disagrees with materialized prefix"
                )
            definition_index = byte_index
            values.extend(int(value) & 0xFFFFFFFF for value in supplement)
            indexes.append(byte_index)
        if not values:
            raise MasmNormalizationError(f"relative table {symbol} has no entries")

        target_eas = tuple(
            anchor + (value - 0x100000000 if value & 0x80000000 else value)
            for value in values
        )
        missing_targets = {target for target in target_eas if target not in exact_labels}
        default_label = default_labels.get(symbol.removeprefix("jpt_").lower())
        if missing_targets and (len(missing_targets) != 1 or default_label is None):
            missing = ", ".join(f"0x{target:X}" for target in sorted(missing_targets))
            raise MasmNormalizationError(
                f"relative table {symbol} has no native target label for {missing}"
            )

        rendered: list[str] = []
        for offset, target in enumerate(target_eas):
            label = exact_labels.get(target, default_label)
            if label is None:
                raise MasmNormalizationError(
                    f"relative table {symbol} has no native target label for 0x{target:X}"
                )
            prefix = f"{symbol} dd" if offset == 0 else "dd"
            rendered.append(f"{prefix} {label} - {symbol}\n")
        removed.update(indexes)
        relocated.extend(rendered)
        table_count += 1
        entry_count += len(rendered)

    without_tables = "".join(
        line for index, line in enumerate(lines) if index not in removed
    )
    text_segment = _TEXT_SEGMENT_RE.search(without_tables)
    if text_segment is None:
        raise MasmNormalizationError("relative jump tables require an _TEXT segment")
    table_text = "".join(relocated)
    insertion = text_segment.end()
    relocated_text = without_tables[:insertion] + table_text + without_tables[insertion:]
    if not re.search(
        r"^[ \t]*OPTION[ \t]+NOSCOPED[ \t]*(?:;.*)?$",
        relocated_text,
        re.IGNORECASE | re.MULTILINE,
    ):
        first_line_end = relocated_text.find("\n") + 1
        relocated_text = (
            relocated_text[:first_line_end]
            + "OPTION NOSCOPED\n"
            + relocated_text[first_line_end:]
        )
    return relocated_text, table_count, entry_count


def _preserve_invalid_lock_seto(text: str) -> tuple[str, int]:
    count = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        indent = match.group("indent")
        operand = match.group("operand")
        return f"{indent}db 0F0h\n{indent}seto{operand}"

    return _INVALID_LOCK_SETO_RE.sub(replace, text), count


def _ensure_cross_proc_symbols_unscoped(text: str) -> str:
    """Keep pre-materialized code tables visible across an added PROC scope."""

    if not _SYMBOLIC_RELATIVE_DWORD_RE.search(text):
        return text
    if re.search(
        r"^[ \t]*OPTION[ \t]+NOSCOPED[ \t]*(?:;.*)?$",
        text,
        re.IGNORECASE | re.MULTILINE,
    ):
        return text
    first_line_end = text.find("\n") + 1
    return text[:first_line_end] + "OPTION NOSCOPED\n" + text[first_line_end:]


def normalize_masm_text(
    text: str,
    *,
    supplemental_tables: Mapping[str, tuple[int, ...]] | None = None,
) -> NormalizationResult:
    """Return a strict derived build listing without mutating source evidence."""
    if _STRUCTURAL_EXPORT_MARKER not in text:
        return NormalizationResult(text, NormalizationStats())

    normalized, frame_terms = _fold_frame_terms(text)
    normalized, unwind_frames = _add_x64_unwind_frame(normalized)
    normalized, relative_tables, relative_entries = _relocate_relative_jump_tables(
        normalized,
        supplemental_tables or {},
    )
    normalized = _ensure_cross_proc_symbols_unscoped(normalized)
    normalized, rebased = _rebase_indexed_symbols(normalized)
    normalized, raw_prefixes = _preserve_invalid_lock_seto(normalized)
    return NormalizationResult(
        normalized,
        NormalizationStats(
            frame_terms=frame_terms,
            unwind_frames=unwind_frames,
            rebased_indexed_symbols=rebased,
            raw_lock_prefixes=raw_prefixes,
            relative_jump_tables=relative_tables,
            relative_jump_entries=relative_entries,
        ),
    )


def _load_materialized_table_supplement(
    source: Path,
    source_payload: bytes,
) -> dict[str, tuple[int, ...]]:
    sidecar = source.with_suffix(".materialized.json")
    if not sidecar.exists():
        return {}
    payload = json.loads(sidecar.read_text(encoding="utf-8"))
    if payload.get("schema") != _SUPPLEMENT_SCHEMA:
        raise MasmNormalizationError(f"unsupported materialized-data schema: {sidecar}")
    actual_sha256 = hashlib.sha256(source_payload).hexdigest()
    if payload.get("masm_sha256") != actual_sha256:
        raise MasmNormalizationError(
            f"materialized-data sidecar does not match source MASM SHA-256: {sidecar}"
        )
    tables: dict[str, tuple[int, ...]] = {}
    for raw in payload.get("tables", ()):
        symbol = str(raw["symbol"])
        if symbol in tables:
            raise MasmNormalizationError(f"duplicate supplemented table: {symbol}")
        tables[symbol] = tuple(
            int(value, 0) if isinstance(value, str) else int(value)
            for value in raw.get("dwords", ())
        )
        if not tables[symbol]:
            raise MasmNormalizationError(f"empty supplemented table: {symbol}")
    return tables


def normalize_file(source: Path, output: Path) -> NormalizationStats:
    if source.resolve() == output.resolve():
        raise MasmNormalizationError("source evidence and derived output must differ")
    source_payload = source.read_bytes()
    supplements = _load_materialized_table_supplement(source, source_payload)
    result = normalize_masm_text(
        source_payload.decode("utf-8"),
        supplemental_tables=supplements,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(result.text, encoding="utf-8", newline="\n")
    return result.stats


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    stats = normalize_file(args.source, args.output)
    print(
        "normalized MASM: "
        f"frame_terms={stats.frame_terms} "
        f"unwind_frames={stats.unwind_frames} "
        f"rebased_indexed_symbols={stats.rebased_indexed_symbols} "
        f"raw_lock_prefixes={stats.raw_lock_prefixes} "
        f"relative_jump_tables={stats.relative_jump_tables} "
        f"relative_jump_entries={stats.relative_jump_entries}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Prepare structural IDA MASM exports for relocation-safe assembly.

The committed export is the hash-bound evidence.  This tool writes a derived
build input and never edits that evidence in place.  Rewrites are deliberately
limited to IDA renderer forms whose relocation meaning can be checked from the
same listing.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import NamedTuple


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


class MasmNormalizationError(ValueError):
    """Raised when a prospective relocation rewrite is not locally proven."""


class NormalizationStats(NamedTuple):
    frame_terms: int = 0
    rebased_indexed_symbols: int = 0
    raw_lock_prefixes: int = 0

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


def _preserve_invalid_lock_seto(text: str) -> tuple[str, int]:
    count = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        indent = match.group("indent")
        operand = match.group("operand")
        return f"{indent}db 0F0h\n{indent}seto{operand}"

    return _INVALID_LOCK_SETO_RE.sub(replace, text), count


def normalize_masm_text(text: str) -> NormalizationResult:
    """Return a strict derived build listing without mutating source evidence."""
    if _STRUCTURAL_EXPORT_MARKER not in text:
        return NormalizationResult(text, NormalizationStats())

    normalized, frame_terms = _fold_frame_terms(text)
    normalized, rebased = _rebase_indexed_symbols(normalized)
    normalized, raw_prefixes = _preserve_invalid_lock_seto(normalized)
    return NormalizationResult(
        normalized,
        NormalizationStats(frame_terms, rebased, raw_prefixes),
    )


def normalize_file(source: Path, output: Path) -> NormalizationStats:
    if source.resolve() == output.resolve():
        raise MasmNormalizationError("source evidence and derived output must differ")
    result = normalize_masm_text(source.read_text(encoding="utf-8"))
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
        f"rebased_indexed_symbols={stats.rebased_indexed_symbols} "
        f"raw_lock_prefixes={stats.raw_lock_prefixes}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Correlate backend microcode provenance with authoritative decoded native
spans.

Task 5 ("Read-only capture, lowering, and preflight") of
``_gitless/profile-guided-native-mutation-implementer-plan.md``, Step 1. This
module's entire purpose is captured by one negative: **a microblock's claimed
``[start_ea, end_ea)`` boundary never by itself creates an owned span.**
:func:`correlate_native_span` always independently decodes the claimed range
through an injected reader and classifies coverage from what actually decoded
there -- never from what the caller merely asserted.

Read-only, and pure where it can be
--------------------------------------------------------------------------

This module makes no ``patch_bytes``/``patch_byte``/``put_bytes``/
``del_items``/``create_insn``/``add_cref``/``add_func``/``set_func_*`` call --
in fact the correlation logic here does not import ``ida_*`` at all.
:data:`DecodedRangeReader` is a plain injected callable (mirroring
``d810.backends.ida.native_patch.journal``'s ``NativeCurrentByteReader``
precedent: "Fakes are used in the unit tests per this repository's 'no IDA
mocking in unit tests' rule"), so :func:`correlate_native_span` and
:func:`correlate_microblock_origin` are unit-testable with a plain fake and
never touch a live database themselves. :func:`ida_decoded_range_reader`
is the one function that does -- it lazy-imports ``ida_ua``/``ida_bytes``
inside its closure (this repository's established pattern for keeping a
module importable without a live IDA runtime; see e.g.
``d810.backends.hexrays.native_preanalysis_key``) and is exercised only by
the Docker system-test suite, never by ``tests/unit``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable

from d810.ir.native_origin import (
    MicroblockNativeOrigin,
    NativeInstructionIdentity,
    NativeOriginCoverage,
    NativeOriginSpan,
)

__all__ = [
    "DecodedRangeReader",
    "correlate_microblock_origin",
    "correlate_native_span",
    "ida_decoded_range_reader",
]

# Decodes [start_ea, end_ea) and returns every instruction identity found,
# in any order, restricted to that window. Mirrors
# d810.backends.ida.native_patch.journal.NativeCurrentByteReader's precedent
# of a plain injected Callable rather than a Protocol class.
DecodedRangeReader = Callable[[int, int], tuple[NativeInstructionIdentity, ...]]


def _has_overlap(ordered: tuple[NativeInstructionIdentity, ...]) -> bool:
    for prev, nxt in zip(ordered, ordered[1:]):
        if nxt.ea < prev.end_ea:
            return True
    return False


def correlate_native_span(
    start_ea: int,
    end_ea: int,
    decode_range: DecodedRangeReader,
    *,
    expected_bytes_hash: str,
) -> NativeOriginSpan:
    """Independently decode ``[start_ea, end_ea)`` and classify coverage.

    Never trusts ``[start_ea, end_ea)`` as ownership by itself: the returned
    coverage reflects only what ``decode_range`` actually reports.

    * Nothing decoded at all -> ``SYNTHETIC`` (also covers a fictitious/
      fabricated native-EA correlation: querying an address with no real
      decodable instruction always lands here).
    * Overlapping decode candidates, or a decode reported outside the
      queried window (a ``decode_range`` contract violation) -> ``AMBIGUOUS``.
    * A clean, full, contiguous tiling of ``[start_ea, end_ea)`` -> ``COMPLETE``.
    * Anything else with real content -- most importantly a genuine gap
      between two decoded runs, i.e. a non-contiguous span -> ``PARTIAL``.
    """
    decoded = tuple(sorted(decode_range(start_ea, end_ea), key=lambda i: i.ea))

    if not decoded:
        return NativeOriginSpan(
            start_ea=start_ea,
            end_ea=end_ea,
            expected_bytes_hash=expected_bytes_hash,
            instructions=(),
            terminal_ea=None,
            incoming_refs=(),
            coverage=NativeOriginCoverage.SYNTHETIC,
        )

    out_of_bounds = any(i.ea < start_ea or i.end_ea > end_ea for i in decoded)
    if out_of_bounds or _has_overlap(decoded):
        return NativeOriginSpan(
            start_ea=start_ea,
            end_ea=end_ea,
            expected_bytes_hash=expected_bytes_hash,
            instructions=decoded,
            terminal_ea=None,
            incoming_refs=(),
            coverage=NativeOriginCoverage.AMBIGUOUS,
        )

    # Reuse NativeOriginSpan's own contiguous-tiling validator as the single
    # source of truth for "does this fully and contiguously cover the range"
    # rather than re-deriving that logic here.
    try:
        return NativeOriginSpan(
            start_ea=start_ea,
            end_ea=end_ea,
            expected_bytes_hash=expected_bytes_hash,
            instructions=decoded,
            terminal_ea=decoded[-1].ea,
            incoming_refs=(),
            coverage=NativeOriginCoverage.COMPLETE,
        )
    except ValueError:
        return NativeOriginSpan(
            start_ea=start_ea,
            end_ea=end_ea,
            expected_bytes_hash=expected_bytes_hash,
            instructions=decoded,
            terminal_ea=None,
            incoming_refs=(),
            coverage=NativeOriginCoverage.PARTIAL,
        )


def correlate_microblock_origin(
    *,
    microblock_serial: int,
    microblock_maturity: str,
    native_ea_anchor: int,
    expected_ranges: tuple[tuple[int, int], ...],
    decode_range: DecodedRangeReader,
) -> MicroblockNativeOrigin:
    """Correlate one microblock's claimed native ranges into origin spans.

    ``native_ea_anchor`` is carried through unconditionally (global
    constraint: "a microcode block serial alone is not acceptable") -- every
    result carries it regardless of what coverage each span ends up with,
    including a wholly ``SYNTHETIC`` result with zero real content.
    """
    spans = tuple(
        correlate_native_span(
            start_ea,
            end_ea,
            decode_range,
            expected_bytes_hash=hashlib.sha256(
                f"{start_ea:#x}-{end_ea:#x}".encode("utf-8")
            ).hexdigest(),
        )
        for start_ea, end_ea in expected_ranges
    )
    correlation_evidence = tuple(
        f"{span.coverage.value} span [{span.start_ea:#x}, {span.end_ea:#x}) "
        f"with {len(span.instructions)} decoded instruction(s)"
        for span in spans
    )
    return MicroblockNativeOrigin(
        microblock_serial=microblock_serial,
        microblock_maturity=microblock_maturity,
        native_ea_anchor=native_ea_anchor,
        spans=spans,
        correlation_evidence=correlation_evidence,
    )


def ida_decoded_range_reader() -> DecodedRangeReader:
    """Build a :data:`DecodedRangeReader` backed by the live IDA decoder.

    Read-only: only ``ida_ua.decode_insn``, ``ida_ua.print_insn_mnem``, and
    ``ida_bytes.get_bytes`` are called. Lazy-imports so importing this module
    (and unit-testing everything above) never requires a real IDA runtime;
    this factory itself is exercised only by the Docker system-test suite.
    """
    import ida_bytes
    import ida_ua

    def _read(start_ea: int, end_ea: int) -> tuple[NativeInstructionIdentity, ...]:
        identities: list[NativeInstructionIdentity] = []
        cursor = start_ea
        insn = ida_ua.insn_t()
        while cursor < end_ea:
            length = ida_ua.decode_insn(insn, cursor)
            if length <= 0:
                cursor += 1
                continue
            if cursor + length > end_ea:
                break
            data = ida_bytes.get_bytes(cursor, length) or b""
            mnemonic = ida_ua.print_insn_mnem(cursor) or "?"
            identities.append(
                NativeInstructionIdentity(
                    ea=cursor,
                    end_ea=cursor + length,
                    bytes_hash=hashlib.sha256(data).hexdigest(),
                    mnemonic=mnemonic,
                    operand_shape=(),
                    pc_relative_sites=(),
                )
            )
            cursor += length
        return tuple(identities)

    return _read

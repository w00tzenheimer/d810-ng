"""Exact read-only live value-range proofs for fragment validation."""

from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind


class ExactValueRangeQueryUnavailable(RuntimeError):
    """The live backend cannot answer one exact value-range query safely."""


@dataclass(frozen=True, slots=True)
class ExactValueRangeProof:
    """An unsigned inclusive envelope proven to contain the live value set."""

    lo: int | None
    hi: int | None

    def __post_init__(self) -> None:
        lo = None if self.lo is None else int(self.lo)
        hi = None if self.hi is None else int(self.hi)
        if lo is None and hi is None:
            raise ValueError("exact value-range proof requires at least one bound")
        if any(bound is not None and bound < 0 for bound in (lo, hi)):
            raise ValueError("exact value-range proof bounds must be unsigned")
        if lo is not None and hi is not None and lo > hi:
            raise ValueError("exact value-range proof lower bound exceeds upper bound")
        object.__setattr__(self, "lo", lo)
        object.__setattr__(self, "hi", hi)


def _value_interval(storage: StorageIdentity, width: int):
    interval = ida_hexrays.vivl_t()
    if storage.kind is StorageIdentityKind.REGISTER:
        interval.set_reg(int(storage.offset), int(width))
        return interval
    if storage.kind is StorageIdentityKind.STACK:
        interval.set_stkoff(int(storage.offset), int(width))
        return interval
    raise ExactValueRangeQueryUnavailable(
        f"unsupported value-range storage namespace {storage.kind.name.lower()}"
    )


def _has_values_below(observed, width: int, lo: int) -> bool:
    if int(lo) == 0:
        return False
    below = ida_hexrays.valrng_t(int(width))
    below.set_cmp(ida_hexrays.CMP_B, int(lo))
    violation = ida_hexrays.valrng_t(observed)
    violation.intersect_with(below)
    return not violation.empty()


def _has_values_above(observed, width: int, hi: int) -> bool:
    if int(hi) == (1 << (int(width) * 8)) - 1:
        return False
    above = ida_hexrays.valrng_t(int(width))
    above.set_cmp(ida_hexrays.CMP_A, int(hi))
    violation = ida_hexrays.valrng_t(observed)
    violation.intersect_with(above)
    return not violation.empty()


def prove_exact_unsigned_range(
    block: object,
    instruction: object,
    storage: StorageIdentity,
    width: int,
    *,
    at_end: bool,
    required_lo: int | None,
    required_hi: int | None,
) -> ExactValueRangeProof | None:
    """Prove the live set is contained by the requested unsigned envelope."""
    width = int(width)
    if not 1 <= width <= 8:
        raise ExactValueRangeQueryUnavailable(
            "exact value-range query requires a 1..8 byte value"
        )
    try:
        interval = _value_interval(storage, width)
        observed = ida_hexrays.valrng_t(width)
        flags = int(ida_hexrays.VR_EXACT) | int(
            ida_hexrays.VR_AT_END if at_end else ida_hexrays.VR_AT_START
        )
        if not block.get_valranges(observed, interval, instruction, flags):
            return None
        if (
            observed.empty()
            or observed.all_values()
            or observed.is_unknown()
            or int(observed.get_size()) != width
        ):
            return None
        if (
            required_lo is not None and _has_values_below(observed, width, required_lo)
        ) or (
            required_hi is not None and _has_values_above(observed, width, required_hi)
        ):
            return None
        is_singleton, value = observed.cvt_to_single_value()
    except ExactValueRangeQueryUnavailable:
        raise
    except Exception as exc:
        raise ExactValueRangeQueryUnavailable(
            "Hex-Rays exact value-range query failed"
        ) from exc
    if is_singleton:
        singleton = int(value)
        return ExactValueRangeProof(lo=singleton, hi=singleton)
    return ExactValueRangeProof(lo=required_lo, hi=required_hi)


__all__ = [
    "ExactValueRangeProof",
    "ExactValueRangeQueryUnavailable",
    "prove_exact_unsigned_range",
]

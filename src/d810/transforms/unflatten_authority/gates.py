"""Lossless transport for the generic CFG gate decisions.

The source checks intentionally remain in ``analyses.control_flow``.  This
adapter carries their exact result objects through the portable authority
boundary and rejects any lossy boolean/serial reconstruction.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from d810.analyses.control_flow.graph_checks import (
    EffectfulReachabilityResult,
    EntryReachabilityResult,
    TerminalReachabilityResult,
)


def _exact_nonnegative(value: object, label: str) -> None:
    if type(value) is not int or value < 0:
        raise TypeError(f"{label} must be an exact non-negative int")


def _exact_finite_float(value: object, label: str) -> None:
    if type(value) is not float or not math.isfinite(value):
        raise TypeError(f"{label} must be an exact finite float")


def _serial_set(value: object, label: str) -> frozenset[int]:
    if type(value) is not frozenset:
        raise TypeError(f"{label} must be an exact frozenset")
    if any(type(item) is not int or item < 0 for item in value):
        raise TypeError(f"{label} must contain exact non-negative ints")
    return value


def _validate_entry(result: EntryReachabilityResult) -> None:
    if type(result.passed) is not bool:
        raise TypeError("entry passed must be an exact bool")
    for name in ("pre_reachable_count", "post_reachable_count", "min_pre_reachable"):
        _exact_nonnegative(getattr(result, name), f"entry {name}")
    _exact_finite_float(result.retained_ratio, "entry retained_ratio")
    _exact_finite_float(result.min_retained_ratio, "entry min_retained_ratio")
    if result.min_retained_ratio < 0.0:
        raise ValueError("entry min_retained_ratio must not be negative")
    expected_ratio = (
        result.post_reachable_count / result.pre_reachable_count
        if result.pre_reachable_count
        else 1.0
    )
    if result.retained_ratio != expected_ratio:
        raise ValueError("entry retained_ratio is not recomputed from counts")
    expected_passed = (
        result.pre_reachable_count < result.min_pre_reachable
        or result.retained_ratio >= result.min_retained_ratio
    )
    if result.passed != expected_passed:
        raise ValueError("entry passed does not match exact threshold semantics")
    if type(result.reason) is not str:
        raise TypeError("entry reason must be an exact string")


def _validate_effect(result: EffectfulReachabilityResult, label: str) -> None:
    if type(result.passed) is not bool:
        raise TypeError(f"{label} passed must be an exact bool")
    pre = _serial_set(result.pre_effectful_block_serials, f"{label} pre")
    post = _serial_set(result.post_reachable_effectful_block_serials, f"{label} post")
    lost = _serial_set(result.lost_block_serials, f"{label} lost")
    if post & lost or post | lost != pre:
        raise ValueError(f"{label} post/lost must partition pre")
    if result.passed != (not lost):
        raise ValueError(f"{label} passed must equal not lost")
    if type(result.reason) is not str:
        raise TypeError(f"{label} reason must be an exact string")


def _validate_terminal(result: TerminalReachabilityResult) -> None:
    if type(result.passed) is not bool:
        raise TypeError("terminal passed must be an exact bool")
    pre = _serial_set(result.pre_reachable_terminals, "terminal pre")
    post = _serial_set(result.post_reachable_terminals, "terminal post")
    _exact_nonnegative(result.pre_reachable_count, "terminal pre_reachable_count")
    _exact_nonnegative(result.post_reachable_count, "terminal post_reachable_count")
    expected_passed = not (bool(pre) and not post)
    if result.passed != expected_passed:
        raise ValueError("terminal passed does not match exact terminal semantics")
    if len(pre) > result.pre_reachable_count or len(post) > result.post_reachable_count:
        raise ValueError("terminal counts cannot be smaller than terminal sets")
    if type(result.reason) is not str:
        raise TypeError("terminal reason must be an exact string")


@dataclass(frozen=True, slots=True)
class GenericCfgGateBundle:
    """Exact raw/effective gate results retained across both transaction phases."""

    entry: EntryReachabilityResult
    effectful_raw: EffectfulReachabilityResult
    effectful_effective: EffectfulReachabilityResult
    terminal: TerminalReachabilityResult

    def __post_init__(self) -> None:
        validate_generic_cfg_gate_bundle(self)

    @property
    def allowed_effect_exclusions(self) -> frozenset[int]:
        """Derived effective adjustment; callers cannot supply this separately."""
        return frozenset(
            self.effectful_raw.lost_block_serials
            - self.effectful_effective.lost_block_serials
        )


def validate_generic_cfg_gate_bundle(bundle: GenericCfgGateBundle) -> GenericCfgGateBundle:
    """Revalidate an exact bundle after construction or low-level mutation."""
    if type(bundle) is not GenericCfgGateBundle:
        raise TypeError("generic gate transport requires the exact bundle type")
    entry = bundle.entry
    raw = bundle.effectful_raw
    effective = bundle.effectful_effective
    terminal = bundle.terminal
    if type(entry) is not EntryReachabilityResult:
        raise TypeError("entry must be the exact EntryReachabilityResult type")
    if type(raw) is not EffectfulReachabilityResult:
        raise TypeError("effectful_raw must be the exact EffectfulReachabilityResult type")
    if type(effective) is not EffectfulReachabilityResult:
        raise TypeError("effectful_effective must be the exact EffectfulReachabilityResult type")
    if type(terminal) is not TerminalReachabilityResult:
        raise TypeError("terminal must be the exact TerminalReachabilityResult type")
    _validate_entry(entry)
    _validate_effect(raw, "effectful_raw")
    _validate_effect(effective, "effectful_effective")
    if effective.pre_effectful_block_serials != raw.pre_effectful_block_serials:
        raise ValueError("raw/effective effect pre sets differ")
    if not effective.lost_block_serials <= raw.lost_block_serials:
        raise ValueError("effective lost effects must be a raw-lost subset")
    expected_post = raw.post_reachable_effectful_block_serials | (
        raw.lost_block_serials - effective.lost_block_serials
    )
    if effective.post_reachable_effectful_block_serials != expected_post:
        raise ValueError("effective post effects do not preserve raw/effective delta")
    _validate_terminal(terminal)
    return bundle


__all__ = ["GenericCfgGateBundle", "validate_generic_cfg_gate_bundle"]

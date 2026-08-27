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
class GenericEntryGateFacts:
    """Lossless portable DTO for one entry reachability result."""

    passed: bool
    pre_reachable_count: int
    post_reachable_count: int
    retained_ratio: float
    min_pre_reachable: int
    min_retained_ratio: float
    reason: str

    @classmethod
    def from_result(cls, result: EntryReachabilityResult) -> GenericEntryGateFacts:
        if type(result) is not EntryReachabilityResult:
            raise TypeError("entry facts require EntryReachabilityResult")
        _validate_entry(result)
        return cls(
            result.passed, result.pre_reachable_count, result.post_reachable_count,
            result.retained_ratio, result.min_pre_reachable,
            result.min_retained_ratio, result.reason,
        )

    def to_result(self) -> EntryReachabilityResult:
        result = EntryReachabilityResult(
            self.passed, self.pre_reachable_count, self.post_reachable_count,
            self.retained_ratio, self.min_pre_reachable,
            self.min_retained_ratio, self.reason,
        )
        _validate_entry(result)
        return result

    def __post_init__(self) -> None:
        _validate_entry(self.to_result())


@dataclass(frozen=True, slots=True)
class GenericEffectfulGateFacts:
    """Lossless portable DTO for raw or effective effect reachability."""

    passed: bool
    pre_effectful_block_serials: frozenset[int]
    post_reachable_effectful_block_serials: frozenset[int]
    lost_block_serials: frozenset[int]
    reason: str

    @classmethod
    def from_result(cls, result: EffectfulReachabilityResult) -> GenericEffectfulGateFacts:
        if type(result) is not EffectfulReachabilityResult:
            raise TypeError("effect facts require EffectfulReachabilityResult")
        _validate_effect(result, "effect")
        return cls(
            result.passed, result.pre_effectful_block_serials,
            result.post_reachable_effectful_block_serials,
            result.lost_block_serials, result.reason,
        )

    def to_result(self) -> EffectfulReachabilityResult:
        result = EffectfulReachabilityResult(
            self.passed, self.pre_effectful_block_serials,
            self.post_reachable_effectful_block_serials,
            self.lost_block_serials, self.reason,
        )
        _validate_effect(result, "effect")
        return result

    def __post_init__(self) -> None:
        _validate_effect(self.to_result(), "effect")


@dataclass(frozen=True, slots=True)
class GenericTerminalGateFacts:
    """Lossless portable DTO for terminal reachability."""

    passed: bool
    pre_reachable_terminals: frozenset[int]
    post_reachable_terminals: frozenset[int]
    pre_reachable_count: int
    post_reachable_count: int
    reason: str

    @classmethod
    def from_result(cls, result: TerminalReachabilityResult) -> GenericTerminalGateFacts:
        if type(result) is not TerminalReachabilityResult:
            raise TypeError("terminal facts require TerminalReachabilityResult")
        _validate_terminal(result)
        return cls(
            result.passed, result.pre_reachable_terminals,
            result.post_reachable_terminals, result.pre_reachable_count,
            result.post_reachable_count, result.reason,
        )

    def to_result(self) -> TerminalReachabilityResult:
        result = TerminalReachabilityResult(
            self.passed, self.pre_reachable_terminals,
            self.post_reachable_terminals, self.pre_reachable_count,
            self.post_reachable_count, self.reason,
        )
        _validate_terminal(result)
        return result

    def __post_init__(self) -> None:
        _validate_terminal(self.to_result())


@dataclass(frozen=True, slots=True)
class GenericCfgGateFacts:
    """The only portable transport for native generic CFG facts."""

    entry: GenericEntryGateFacts
    effectful_raw: GenericEffectfulGateFacts
    effectful_effective: GenericEffectfulGateFacts
    terminal: GenericTerminalGateFacts

    def __post_init__(self) -> None:
        if type(self.entry) is not GenericEntryGateFacts:
            raise TypeError("entry must be GenericEntryGateFacts")
        if type(self.effectful_raw) is not GenericEffectfulGateFacts:
            raise TypeError("effectful_raw must be GenericEffectfulGateFacts")
        if type(self.effectful_effective) is not GenericEffectfulGateFacts:
            raise TypeError("effectful_effective must be GenericEffectfulGateFacts")
        if type(self.terminal) is not GenericTerminalGateFacts:
            raise TypeError("terminal must be GenericTerminalGateFacts")
        validate_generic_cfg_gate_bundle(self.to_bundle())

    @classmethod
    def from_bundle(cls, bundle: GenericCfgGateBundle) -> GenericCfgGateFacts:
        validate_generic_cfg_gate_bundle(bundle)
        return cls(
            GenericEntryGateFacts.from_result(bundle.entry),
            GenericEffectfulGateFacts.from_result(bundle.effectful_raw),
            GenericEffectfulGateFacts.from_result(bundle.effectful_effective),
            GenericTerminalGateFacts.from_result(bundle.terminal),
        )

    def to_bundle(self) -> GenericCfgGateBundle:
        return GenericCfgGateBundle(
            self.entry.to_result(), self.effectful_raw.to_result(),
            self.effectful_effective.to_result(), self.terminal.to_result(),
        )


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

    @property
    def facts(self) -> GenericCfgGateFacts:
        return GenericCfgGateFacts.from_bundle(self)


def generic_cfg_gate_facts_from_bundle(bundle: GenericCfgGateBundle) -> GenericCfgGateFacts:
    """Adapt native graph-check results once into the closed facts DTO."""

    return GenericCfgGateFacts.from_bundle(bundle)


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


def _validate_projected_ledger(
    ledger: object,
    case: object,
    *,
    gate: str,
) -> None:
    """Require a projected gate to consume its exact canonical loss ledger."""
    # Import lazily: generic CFG transport intentionally has no static
    # dependency on the semantic model for ordinary transactions.
    from . import model

    if type(case) is not model.SemanticSafetyCase:
        raise TypeError(f"{gate} requires SemanticSafetyCase")
    if type(ledger) is not model.SemanticLossLedger:
        raise TypeError(f"{gate} requires SemanticLossLedger")
    if ledger.case is not case:
        raise ValueError(f"{gate} ledger must retain the exact safety case")
    if case.phase not in (
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
    ):
        raise ValueError(f"{gate} requires projected or observed safety case")
    model.SemanticLossLedger.__post_init__(ledger)
    if ledger.unclassified or ledger.conflicting:
        raise ValueError(f"{gate} rejects unclassified semantic loss")


def validate_projected_effect_loss_ledger(ledger: object, case: object) -> None:
    _validate_projected_ledger(ledger, case, gate="projected effect gate")


def validate_projected_dispatcher_removal_ledger(ledger: object, case: object) -> None:
    _validate_projected_ledger(ledger, case, gate="projected dispatcher removal gate")


def validate_projected_corridor_coverage_ledger(ledger: object, case: object) -> None:
    _validate_projected_ledger(ledger, case, gate="projected corridor coverage gate")


def validate_projected_terminal_loss_ledger(ledger: object, case: object) -> None:
    _validate_projected_ledger(ledger, case, gate="projected terminal gate")


__all__ = [
    "GenericCfgGateBundle", "GenericCfgGateFacts", "GenericEntryGateFacts",
    "GenericEffectfulGateFacts", "GenericTerminalGateFacts",
    "generic_cfg_gate_facts_from_bundle", "validate_generic_cfg_gate_bundle",
    "validate_projected_effect_loss_ledger",
    "validate_projected_dispatcher_removal_ledger",
    "validate_projected_corridor_coverage_ledger",
    "validate_projected_terminal_loss_ledger",
]

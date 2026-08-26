"""Portable refinement of attested call return values.

The serialized fact is deliberately kept at the value-flow boundary.  This
module parses only the versioned call-result envelope and translates it into
the existing concolic reduced-product domain; no backend or solver objects are
needed here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

from d810.core.typing import Annotated, Callable
from d810.ir.maturity import IRMaturity
from d810.analyses.data_flow.concolic.abstract_evidence import AbstractEvidence
from d810.analyses.data_flow.concolic.refs import LocationRef
from d810.analyses.data_flow.concolic.values import (
    ConcolicValue,
    PrecisionStatus,
    reduce,
)
from d810.analyses.abstract_domains.known_bits import KnownBits
from d810.analyses.abstract_domains.wrapped_interval import WrappedInterval
from d810.analyses.value_flow.projection import (
    production_value_flow_fact,
)

CALL_RETURN_VALUE_FACT_TYPE = "CallReturnValueFact"
SUPPORTED_CALL_RESULT_WIDTHS = frozenset({8, 16, 32, 64, 128})


@dataclass(frozen=True)
class CallResultQuery:
    function_ea: int
    maturity: Annotated[int, IRMaturity]
    call_ea: int
    callee_ea: int | None
    result_location: LocationRef
    result_width_bits: int
    argument_fingerprint: str | None = None


class CallResultRefinementStatus(str, Enum):
    REFINED = "refined"
    NO_EVIDENCE = "no_evidence"
    INVALID_EVIDENCE = "invalid_evidence"
    INCOMPATIBLE_EVIDENCE = "incompatible_evidence"
    CONFLICTING_EVIDENCE = "conflicting_evidence"


@dataclass(frozen=True)
class CallResultRefinement:
    value: ConcolicValue
    status: CallResultRefinementStatus
    used_fact_ids: tuple[str, ...] = ()
    rejected_fact_ids: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()


CallResultRefiner = Callable[[CallResultQuery], CallResultRefinement]


_ENVELOPE_REQUIRED_KEYS = frozenset(
    {"schema_version", "call_ea", "result_width_bits", "evidence"}
)
_ENVELOPE_OPTIONAL_KEYS = frozenset({"callee_ea", "argument_fingerprint"})
_EVIDENCE_KEYS = {
    "exact": frozenset({"kind", "value"}),
    "known_bits": frozenset({"kind", "known_zero", "known_one"}),
    "wrapped_interval": frozenset({"kind", "lo", "hi"}),
    "reduced_product": frozenset(
        {"kind", "known_zero", "known_one", "lo", "hi"}
    ),
}


def _strict_int(value: object, *, field: str, width: int | None = None) -> int:
    if type(value) is not int:
        raise ValueError(f"{field} must be an integer")
    if value < 0:
        raise ValueError(f"{field} must be non-negative")
    if width is not None and value >= 1 << width:
        raise ValueError(f"{field} does not fit {width} bits")
    return value


def _mapping(value: object, *, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be an object")
    return value


def _keys_exact(
    value: Mapping[str, object], *, required: frozenset[str], optional: frozenset[str] = frozenset()
) -> None:
    keys = set(value)
    if not required <= keys:
        missing = sorted(required - keys)[0]
        raise ValueError(f"missing {missing}")
    unknown = keys - required - optional
    if unknown:
        raise ValueError(f"unknown key {sorted(unknown)[0]}")


def _top_for_width(width: object) -> ConcolicValue:
    safe_width = width if type(width) is int and width in SUPPORTED_CALL_RESULT_WIDTHS else 8
    return ConcolicValue.top(safe_width)


def _abstract_value(
    evidence: Mapping[str, object], *, width: int
) -> ConcolicValue:
    kind = evidence["kind"]
    if not isinstance(kind, str) or kind not in _EVIDENCE_KEYS:
        raise ValueError("unknown evidence kind")
    _keys_exact(evidence, required=_EVIDENCE_KEYS[kind])

    if kind == "exact":
        # An exact observation is already an attested concrete result.  The
        # emulation-oriented refine_concrete API cannot consume a fact without
        # fabricating an InsnRef/store, so use the domain's singleton factory.
        return ConcolicValue.of(_strict_int(evidence["value"], field="value", width=width), width)

    known_zero = known_one = None
    if kind in {"known_bits", "reduced_product"}:
        known_zero = _strict_int(evidence["known_zero"], field="known_zero", width=width)
        known_one = _strict_int(evidence["known_one"], field="known_one", width=width)
        if known_zero & known_one:
            raise ValueError("known_zero and known_one overlap")

    lo = hi = None
    if kind in {"wrapped_interval", "reduced_product"}:
        lo = _strict_int(evidence["lo"], field="lo", width=width)
        hi = _strict_int(evidence["hi"], field="hi", width=width)

    bits = (
        KnownBits.top(width)
        if known_zero is None
        else KnownBits(width, known_zero, known_one or 0)
    )
    interval = (
        WrappedInterval.top(width)
        if lo is None
        else WrappedInterval(width, lo, hi or 0, "range")
    )
    evidence_value = AbstractEvidence(width, bits, interval)._reduce()
    return reduce(
        ConcolicValue(None, None, evidence_value, width, PrecisionStatus.TOP)
    )


def _parse_envelope(payload: object) -> tuple[int, int | None, str | None, ConcolicValue]:
    envelope = _mapping(payload, field="call_return_value")
    _keys_exact(
        envelope,
        required=_ENVELOPE_REQUIRED_KEYS,
        optional=_ENVELOPE_OPTIONAL_KEYS,
    )
    schema_version = _strict_int(envelope["schema_version"], field="schema_version")
    if schema_version != 1:
        raise ValueError("unsupported schema_version")
    call_ea = _strict_int(envelope["call_ea"], field="call_ea")
    width = _strict_int(envelope["result_width_bits"], field="result_width_bits")
    if width not in SUPPORTED_CALL_RESULT_WIDTHS:
        raise ValueError("unsupported result_width_bits")

    callee_ea = envelope.get("callee_ea")
    if callee_ea is not None:
        callee_ea = _strict_int(callee_ea, field="callee_ea")
    fingerprint = envelope.get("argument_fingerprint")
    if fingerprint is not None and not isinstance(fingerprint, str):
        raise ValueError("argument_fingerprint must be text or null")
    evidence = _abstract_value(_mapping(envelope["evidence"], field="evidence"), width=width)
    return call_ea, callee_ea, fingerprint, evidence


def _compatible(
    query: CallResultQuery,
    *,
    call_ea: int,
    width: int,
    callee_ea: int | None,
    fingerprint: str | None,
) -> str | None:
    if call_ea != query.call_ea:
        return "call_ea does not match"
    if width != query.result_width_bits:
        return "result_width_bits does not match"
    if callee_ea is not None and query.callee_ea is not None and callee_ea != query.callee_ea:
        return "callee_ea does not match"
    if fingerprint is not None and fingerprint != query.argument_fingerprint:
        return "argument_fingerprint does not match"
    return None


def refine_call_result(
    query: CallResultQuery, view: object | None
) -> CallResultRefinement:
    """Refine one definition-scoped call result from active production facts."""
    if type(query.result_width_bits) is not int or query.result_width_bits not in SUPPORTED_CALL_RESULT_WIDTHS:
        return CallResultRefinement(
            _top_for_width(query.result_width_bits),
            CallResultRefinementStatus.INVALID_EVIDENCE,
            reasons=("query result_width_bits is unsupported",),
        )

    candidates: list[tuple[str, ConcolicValue]] = []
    rejected: list[str] = []
    invalid_reasons: list[tuple[str, str]] = []
    incompatible_reasons: list[tuple[str, str]] = []
    observations = getattr(view, "active_observations", ()) if view is not None else ()
    for observation in observations or ():
        if getattr(observation, "kind", None) != CALL_RETURN_VALUE_FACT_TYPE:
            continue
        fact_id = str(getattr(observation, "fact_id", ""))
        if not production_value_flow_fact(observation, CALL_RETURN_VALUE_FACT_TYPE):
            rejected.append(fact_id)
            invalid_reasons.append((fact_id, f"{fact_id}: not production-proven"))
            continue
        try:
            payload = getattr(observation, "payload", None)
            call_ea, callee_ea, fingerprint, candidate = _parse_envelope(
                _mapping(payload, field="payload")["call_return_value"]
            )
        except (KeyError, TypeError, ValueError) as exc:
            rejected.append(fact_id)
            invalid_reasons.append((fact_id, f"{fact_id}: {exc}"))
            continue
        reason = _compatible(
            query,
            call_ea=call_ea,
            width=candidate.width,
            callee_ea=callee_ea,
            fingerprint=fingerprint,
        )
        if reason is not None:
            rejected.append(fact_id)
            incompatible_reasons.append((fact_id, f"{fact_id}: {reason}"))
            continue
        candidates.append((fact_id, candidate))

    candidates.sort(key=lambda item: (item[0], repr(item[1])))
    used_ids = tuple(sorted(fact_id for fact_id, _ in candidates))
    rejected_ids = tuple(sorted(rejected))
    value: ConcolicValue | None = None
    for _, candidate in candidates:
        value = candidate if value is None else value.meet(candidate)

    diagnostic_records = sorted(
        (*invalid_reasons, *incompatible_reasons), key=lambda item: item[0]
    )
    diagnostic_reasons = tuple(reason for _, reason in diagnostic_records)
    if value is not None:
        if value.status is PrecisionStatus.BOTTOM:
            return CallResultRefinement(
                _top_for_width(query.result_width_bits),
                CallResultRefinementStatus.CONFLICTING_EVIDENCE,
                used_ids,
                rejected_ids,
                diagnostic_reasons + ("compatible facts meet to bottom",),
            )
        return CallResultRefinement(
            value,
            CallResultRefinementStatus.REFINED,
            used_ids,
            rejected_ids,
            diagnostic_reasons,
        )
    if invalid_reasons:
        status = CallResultRefinementStatus.INVALID_EVIDENCE
        reasons = diagnostic_reasons
    elif incompatible_reasons:
        status = CallResultRefinementStatus.INCOMPATIBLE_EVIDENCE
        reasons = diagnostic_reasons
    else:
        status = CallResultRefinementStatus.NO_EVIDENCE
        reasons = []
    return CallResultRefinement(
        _top_for_width(query.result_width_bits), status, (), rejected_ids, tuple(reasons)
    )


__all__ = [
    "CALL_RETURN_VALUE_FACT_TYPE",
    "SUPPORTED_CALL_RESULT_WIDTHS",
    "CallResultQuery",
    "CallResultRefinementStatus",
    "CallResultRefinement",
    "CallResultRefiner",
    "refine_call_result",
]

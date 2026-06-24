"""Hex-Rays opcode-to-portable semantic label adapters."""
from __future__ import annotations

from d810.capabilities.providers import get_microcode_evidence
from d810.ir.expressions import ValueOpKind
from d810.ir.semantics import CallKind, PredicateKind


_HEX_RAYS_PREDICATE_CONSTANTS = {
    "m_jz": PredicateKind.EQ,
    "m_jnz": PredicateKind.NE,
    "m_jcnd": PredicateKind.TRUTHY,
    "m_jae": PredicateKind.UGE,
    "m_jb": PredicateKind.ULT,
    "m_ja": PredicateKind.UGT,
    "m_jbe": PredicateKind.ULE,
    "m_jg": PredicateKind.SGT,
    "m_jge": PredicateKind.SGE,
    "m_jl": PredicateKind.SLT,
    "m_jle": PredicateKind.SLE,
}

_HEX_RAYS_VALUE_CONSTANTS = {
    "m_stx": ValueOpKind.STORE,
}

_HEX_RAYS_CALL_CONSTANTS = {
    "m_call": CallKind.DIRECT,
    "m_icall": CallKind.INDIRECT,
}


def microcode_semantic_label_resolver(mba: object):
    """Return a resolver from live Hex-Rays opcode integers to portable labels."""

    try:
        constants = get_microcode_evidence().microcode_constants(mba)
    except Exception:
        return None

    labels: dict[int, object] = {}
    for constant_name, semantic_label in (
        *_HEX_RAYS_PREDICATE_CONSTANTS.items(),
        *_HEX_RAYS_VALUE_CONSTANTS.items(),
        *_HEX_RAYS_CALL_CONSTANTS.items(),
    ):
        raw_value = getattr(constants, constant_name, -1)
        try:
            value = int(raw_value)
        except (TypeError, ValueError):
            continue
        if value >= 0:
            labels[value] = semantic_label
    if not labels:
        return None

    def _resolve(insn_or_opcode: object) -> object | None:
        opcode = getattr(insn_or_opcode, "opcode", insn_or_opcode)
        try:
            return labels.get(int(opcode))
        except (TypeError, ValueError):
            return None

    return _resolve

"""Cheap admitted-rule fixtures for matcher tests.

These helpers deliberately do not run Z3. Algebraic certification belongs to
the explicit slow gate; matcher tests exercise already-certified descriptors.
"""

from __future__ import annotations

from d810.mba.certified_rule_compiler import CompiledMbaRule, _enroll_admitted_rule
from d810.mba.rules._base import VerifiableRule


def admitted_rule(
    rule_type: type[VerifiableRule],
    *,
    family: str,
    proof_widths: tuple[int, ...] = (8, 16, 32, 64),
) -> CompiledMbaRule:
    rule = rule_type()
    return _enroll_admitted_rule(
        CompiledMbaRule(
            source_name=rule_type.__name__,
            aliases=(),
            rule_type=rule_type,
            proof_widths=proof_widths,
            guarded=bool(rule.CONSTRAINTS),
            family=family,
        )
    )

"""Ownership identity for MBA-bound operand trees."""

from __future__ import annotations

import ida_hexrays


def mop_mba_owner_scope(mop: object) -> tuple[int, ...]:
    """Return every MBA identity embedded in one operand tree.

    Structural operand keys are insufficient for process-global caches because
    stack and local references retain the live ``mba_t`` that created them.
    An unreadable owner receives an object-identity scope so it cannot alias a
    healthy MBA-owned operand.
    """
    pending = [mop]
    owners: set[int] = set()
    budget = 4096
    while pending and budget > 0:
        budget -= 1
        current = pending.pop()
        try:
            operand_type = int(current.t)
        except Exception:
            continue
        if operand_type == int(ida_hexrays.mop_S):
            try:
                owners.add(int(current.s.mba.this))
            except Exception:
                owners.add(id(current))
            continue
        if operand_type == int(ida_hexrays.mop_l):
            try:
                owners.add(int(current.l.mba.this))
            except Exception:
                owners.add(id(current))
            continue
        if operand_type == int(ida_hexrays.mop_d):
            try:
                nested = current.d
                pending.extend((nested.l, nested.r, nested.d))
            except Exception:
                pass
        elif operand_type == int(ida_hexrays.mop_a):
            try:
                pending.append(current.a)
            except Exception:
                pass
        elif operand_type == int(ida_hexrays.mop_f):
            try:
                pending.extend(tuple(current.f.args))
            except Exception:
                pass
        elif operand_type == int(ida_hexrays.mop_p):
            try:
                pending.extend((current.pair.lop, current.pair.hop))
            except Exception:
                pass
    return tuple(sorted(owners))


__all__ = ["mop_mba_owner_scope"]

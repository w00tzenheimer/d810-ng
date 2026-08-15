"""Portable structural fingerprint of one final Hex-Rays C-tree."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

__all__ = ["CtreeFingerprint", "fingerprint_ctree"]


@dataclass(frozen=True, slots=True)
class CtreeFingerprint:
    digest: str
    node_count: int


def fingerprint_ctree(cfunc: object) -> CtreeFingerprint:
    """Hash stable C-tree structure without retaining SDK objects.

    Traversal order and node opcodes encode control nesting. Integer literal
    values and direct object/call addresses are included. Lvar indices,
    generated names, C-tree item indices, and Python/SWIG identities are not.
    """
    import ida_hexrays

    rows: list[tuple[object, ...]] = []

    class _Visitor(ida_hexrays.ctree_visitor_t):
        def __init__(self) -> None:
            super().__init__(ida_hexrays.CV_FAST)

        def visit_insn(self, insn) -> int:
            rows.append(("i", int(insn.op)))
            return 0

        def visit_expr(self, expr) -> int:
            op = int(expr.op)
            row: tuple[object, ...] = ("e", op)
            if op == int(ida_hexrays.cot_num):
                try:
                    row += ("num", int(expr.numval()))
                except Exception:
                    row += ("num", "unresolved")
            elif op == int(ida_hexrays.cot_obj):
                try:
                    row += ("obj", int(expr.obj_ea))
                except Exception:
                    row += ("obj", "unresolved")
            rows.append(row)
            return 0

    try:
        body = getattr(cfunc, "body")
        _Visitor().apply_to(body, None)
    except Exception as exc:
        raise ValueError("could not traverse final C-tree") from exc
    payload = json.dumps(rows, separators=(",", ":"), ensure_ascii=True).encode()
    return CtreeFingerprint(
        digest=hashlib.sha256(payload).hexdigest(),
        node_count=len(rows),
    )

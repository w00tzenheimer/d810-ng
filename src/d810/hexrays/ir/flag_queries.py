"""Exact read-only condition-code observations for fragment validation."""

from __future__ import annotations


_BADADDR = 0xFFFFFFFFFFFFFFFF


class ConditionCodeQueryUnavailable(RuntimeError):
    """The live operand cannot answer the required condition-code query."""


def instruction_writes_condition_codes(instruction: object) -> bool:
    """Return whether one top-level instruction writes condition-code state."""
    destination = getattr(instruction, "d", None)
    if destination is None:
        return False
    queried = False
    for method_name in ("is_ccflags", "is_cc"):
        predicate = getattr(destination, method_name, None)
        if not callable(predicate):
            continue
        queried = True
        try:
            if bool(predicate()):
                return True
        except Exception as exc:
            raise ConditionCodeQueryUnavailable(
                f"condition-code predicate {method_name} failed"
            ) from exc
    if not queried:
        raise ConditionCodeQueryUnavailable(
            "destination operand exposes no condition-code predicate"
        )
    return False


def condition_code_write_eas(block: object) -> tuple[int, ...]:
    """Return writer EAs in physical order, preserving duplicate observations."""
    writes: list[int] = []
    instruction = getattr(block, "head", None)
    tail = getattr(block, "tail", None)
    while instruction is not None:
        ea = int(getattr(instruction, "ea", -1) or -1)
        if instruction_writes_condition_codes(instruction):
            if not 0 <= ea < _BADADDR:
                raise ConditionCodeQueryUnavailable(
                    "condition-code writer has no portable EA anchor"
                )
            writes.append(ea)
        if instruction is tail:
            break
        instruction = getattr(instruction, "next", None)
    return tuple(writes)


__all__ = [
    "ConditionCodeQueryUnavailable",
    "condition_code_write_eas",
    "instruction_writes_condition_codes",
]

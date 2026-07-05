"""Pure-Python logic for the `d810cli.py fixture` workflow (ticket d81-rtfh).

NO IDA imports live here — the IDA-bound extract/resolve jobs run in the
subprocess worker ``samples/scripts/fixture_idb_worker.py``. Everything in this
module is unit-testable without IDA.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_MASK64 = (1 << 64) - 1


@dataclass(frozen=True)
class CallSiteFold:
    slot_symbol: str
    const: int
    call_reg: str
    materialized: int | None


@dataclass(frozen=True)
class ResolvedTarget:
    va: int
    name: str
    is_import: bool
    retargetable: bool


@dataclass(frozen=True)
class RetargetAction:
    slot_symbol: str
    const: int
    name: str


@dataclass(frozen=True)
class RetargetPlan:
    actions: tuple[RetargetAction, ...]
    skipped: tuple[str, ...]


def _parse_int(tok: str) -> int:
    """Parse a MASM integer literal: ``64E2..h`` (hex) or plain decimal."""
    tok = tok.strip().rstrip(",")
    if tok.lower().endswith("h"):
        return int(tok[:-1], 16) & _MASK64
    return int(tok, 10) & _MASK64


def _materialized_value(asm_text: str, slot: str) -> int | None:
    """Return the raw ``<slot> dq <hex>`` value, or None if it is a reloc expr."""
    m = re.search(rf"^\s*{re.escape(slot)}\s+dq\s+([0-9A-Fa-f]+h|\d+)\s*$",
                  asm_text, re.MULTILINE)
    return _parse_int(m.group(1)) if m else None


def detect_indirect_call_folds(asm_text: str) -> list[CallSiteFold]:
    """Find ``mov R,[slot]; mov R2,const; add R,R2; ... call R`` sites.

    Linear backward scan from each ``call <reg>``. Tolerates the cmov-decoy
    variant (intervening ``cmov`` on the call reg does not overwrite the true
    slot+const value on the taken path).
    """
    lines = [ln.strip() for ln in asm_text.splitlines()]
    load_re = re.compile(r"^mov\s+(\w+),\s*qword ptr \[(\w+)\]$", re.I)
    imm_re = re.compile(r"^mov\s+(\w+),\s*([0-9A-Fa-f]+h|-?\d+)$", re.I)
    add_re = re.compile(r"^add\s+(\w+),\s*(\w+)$", re.I)
    call_re = re.compile(r"^call\s+(\w+)$", re.I)

    folds: list[CallSiteFold] = []
    for i, ln in enumerate(lines):
        cm = call_re.match(ln)
        if not cm:
            continue
        reg = cm.group(1)
        slot = const = const_reg = None
        for j in range(i - 1, max(-1, i - 40), -1):
            am = add_re.match(lines[j])
            if am and am.group(1).lower() == reg.lower():
                const_reg = am.group(2)
                for k in range(j - 1, max(-1, j - 40), -1):
                    lm = load_re.match(lines[k])
                    if lm and lm.group(1).lower() == reg.lower():
                        slot = lm.group(2)
                    im = imm_re.match(lines[k])
                    if im and im.group(1).lower() == const_reg.lower():
                        const = _parse_int(im.group(2))
                    if slot is not None and const is not None:
                        break
                break
        if slot is not None and const is not None:
            folds.append(CallSiteFold(
                slot_symbol=slot, const=const, call_reg=reg,
                materialized=_materialized_value(asm_text, slot),
            ))
    return folds

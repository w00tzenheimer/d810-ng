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


def plan_retargets(
    folds: list[CallSiteFold],
    resolved: dict[int, ResolvedTarget],
    image_symbols: set[str],
) -> RetargetPlan:
    """Decide which folds to retarget. LEAF/IMPORT ONLY (§7.2)."""
    actions: list[RetargetAction] = []
    skipped: list[str] = []
    seen: set[str] = set()
    for f in folds:
        if f.materialized is None:
            skipped.append(f"{f.slot_symbol}: slot already a reloc expr (not a fresh extract)")
            continue
        va = (f.materialized + f.const) & _MASK64
        tgt = resolved.get(va)
        if tgt is None or not tgt.name:
            skipped.append(f"{f.slot_symbol}: target VA {va:#x} unresolved in source idb")
            continue
        if tgt.name in image_symbols:
            skipped.append(f"{f.slot_symbol}: target {tgt.name} is in-image (already fine)")
            continue
        if not tgt.retargetable:
            skipped.append(f"{f.slot_symbol}: target {tgt.name} is an obfuscated helper, left as MEMORY[...]")
            continue
        key = f"{f.slot_symbol}->{tgt.name}"
        if key in seen:
            continue
        seen.add(key)
        actions.append(RetargetAction(f.slot_symbol, f.const, tgt.name))
    return RetargetPlan(actions=tuple(actions), skipped=tuple(skipped))


def apply_retargets(asm_text: str, plan: RetargetPlan) -> str:
    """Rewrite slot lines to ``<name> - <const>h`` and inject EXTERN decls."""
    text = asm_text
    externs: list[str] = []
    for act in plan.actions:
        text = re.sub(
            rf"^\s*{re.escape(act.slot_symbol)}\s+dq\s+(?:[0-9A-Fa-f]+h|\d+)\s*$",
            f"{act.slot_symbol} dq {act.name} - {act.const:X}h",
            text, count=1, flags=re.MULTILINE,
        )
        externs.append(f"EXTERN {act.name}:PROC")
    if externs:
        # inject EXTERN block just before the first SEGMENT (after existing
        # header comments and any pre-existing EXTERN decls).
        lines = text.splitlines(keepends=True)
        insert_at = next((i for i, ln in enumerate(lines) if "SEGMENT" in ln), 0)
        block = "".join(e + "\n" for e in externs) + "\n"
        text = "".join(lines[:insert_at]) + block + "".join(lines[insert_at:])
    return text


def render_stub(name: str) -> str:
    """A dependency-free leaf stub, auto-exported by the Makefile."""
    return (
        f"; d810 fixture retarget stub for {name} (dependency-free leaf)\n"
        "OPTION PROLOGUE:NONE\n"
        "OPTION EPILOGUE:NONE\n"
        "_TEXT SEGMENT ALIGN(16) 'CODE'\n"
        f"PUBLIC {name}\n"
        f"{name}:\n"
        "    xor eax, eax\n"
        "    ret\n"
        "_TEXT ENDS\n"
        "END\n"
    )


def emit_fixture_case(function: str, project: str) -> str:
    """Render a MINIMAL DeobfuscationCase (assertion policy = §7.1 minimal)."""
    return (
        "    DeobfuscationCase(\n"
        f'        function="{function}",\n'
        f'        description="TODO(human): {function} MASM fixture (d810cli fixture, '
        'd81-rtfh). Auto-generated MINIMAL case: only must_change + no-INTERR '
        'guarded. Replace this description and add semantic assertions '
        '(contains / not-contains / expected-rules) from the '
        'before/after dump before merging.",\n'
        f'        project="{project}",\n'
        "        must_change=True,\n"
        "        skip_if_function_absent=True,\n"
        "    ),\n"
    )


def upsert_case_in_list(list_source: str, function: str, case_src: str) -> str:
    """Insert/replace a case keyed by ``function="<function>"`` in a
    ``DAC_MASM_CASES = [ ... ]`` block (idempotent, §7.4/§7.5)."""
    # Try to replace an existing DeobfuscationCase(...) whose function matches.
    case_block = re.compile(r"[ \t]*DeobfuscationCase\(\s*.*?\),\n", re.DOTALL)

    def _matches(block: str) -> bool:
        return bool(re.search(rf'function="{re.escape(function)}"', block))

    replaced = False
    out_parts: list[str] = []
    pos = 0
    for m in case_block.finditer(list_source):
        out_parts.append(list_source[pos:m.start()])
        block = m.group(0)
        if _matches(block) and not replaced:
            out_parts.append(case_src)
            replaced = True
        else:
            out_parts.append(block)
        pos = m.end()
    out_parts.append(list_source[pos:])
    result = "".join(out_parts)
    if replaced:
        return result
    # Append before the closing bracket of DAC_MASM_CASES.
    idx = list_source.rfind("]")
    return list_source[:idx] + case_src + list_source[idx:]

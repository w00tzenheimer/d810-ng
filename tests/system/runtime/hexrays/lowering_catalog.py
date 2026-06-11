"""Lowering-primitive catalog, extracted from the restructuring lab.

A LOWERING PRIMITIVE takes a portable IR description of a recovered structure and
emits the microcode that Hex-Rays lowers to the EXPECTED pseudocode -- the
original, non-flattened source (the ``lab_ref_*`` oracle sibling, decompiled at
baseline). The lab is the primitive's proof-suite: each primitive is proven to
lower to the compiled-source oracle (the project's oracle-equivalence gate).

The catalog's thesis: there are only a FEW lowering primitives; every flattened
shape is one of them with a different *analysis front-end*. ``DispatchDrain`` is
ONE primitive whether the routing was recovered from a jz-chain or a jump table.

Separation of concerns (mirrors the three-tier invariant):
  - ANALYSIS (read-only)  : ``recover_*`` -> an IR plan (pure data, no mutation)
  - LOWERING (this catalog): ``lower_*``   (IR plan -> DeferredGraphModifier emits)
  - MUTATION              : ``DeferredGraphModifier.apply`` (the vendor backend)
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

import ida_hexrays

from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier

# --- the lab's large-const state scheme ---
STATE_K0 = 0xC6685257
STATE_K1 = 0xB92456DE
STATE_K2 = 0x3C8960A9
STATE_TERM = 0x1A2B3C4D
STATE_RT = 0x7D4E1F3A
STATE_KENTRY = 0xDEADBEEF
LAB_STATE_CONSTS = frozenset(
    {STATE_KENTRY, STATE_K0, STATE_K1, STATE_K2, STATE_RT, STATE_TERM})


# =====================================================================
# IR -- the lowering-primitive INPUTS (pure data; no analysis, no mutation).
# =====================================================================
@dataclass(frozen=True)
class DispatchDrainPlan:
    """Drain a state dispatcher into direct edges.

    ``redirects``: a tuple of ``(source_writer, routed_handler, old_target)``.
    A linear chain, a back-edge (loop), a join, and a preserved handler-branch
    all fall out of this single plan -- the shape is in the recovered routing
    graph, not in the lowering. ``disp`` is the dispatcher head (diagnostic)."""

    redirects: tuple
    disp: int = -1


# =====================================================================
# ANALYSIS front-ends (read-only): flattened microcode -> IR plan.
# =====================================================================
def _state_slot(mba, consts=LAB_STATE_CONSTS):
    writes: dict[str, list[int]] = {}
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        ins = blk.head if blk else None
        while ins is not None:
            if (int(ins.opcode) == ida_hexrays.m_mov and ins.l is not None
                    and ins.l.t == ida_hexrays.mop_n
                    and (int(ins.l.nnn.value) & 0xFFFFFFFF) in consts
                    and ins.d is not None):
                writes.setdefault(ins.d.dstr(), []).append(
                    int(ins.l.nnn.value) & 0xFFFFFFFF)
            ins = ins.next
    if not writes:
        return None
    term_slots = {d: v for d, v in writes.items() if STATE_TERM in v}
    pool = term_slots or writes
    return max(pool, key=lambda d: len(pool[d]))


def _state_writers(mba, slot, consts=LAB_STATE_CONSTS):
    writers: dict[int, list[int]] = {}
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        ins = blk.head if blk else None
        while ins is not None:
            if (int(ins.opcode) == ida_hexrays.m_mov and ins.l is not None
                    and ins.l.t == ida_hexrays.mop_n and ins.d is not None
                    and ins.d.dstr() == slot):
                v = int(ins.l.nnn.value) & 0xFFFFFFFF
                if v in consts:
                    writers.setdefault(v, []).append(blk.serial)
            ins = ins.next
    return writers


def _jz_routing(mba, consts=LAB_STATE_CONSTS):
    routing: dict[int, int] = {}
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk is None or blk.type != ida_hexrays.BLT_2WAY:
            continue
        tail = blk.tail
        if tail is None or int(tail.opcode) not in (ida_hexrays.m_jz, ida_hexrays.m_jnz):
            continue
        imm = None
        for op in (tail.l, tail.r):
            if op is not None and op.t == ida_hexrays.mop_n:
                v = int(op.nnn.value) & 0xFFFFFFFF
                if v in consts:
                    imm = v
        if imm is None:
            continue
        tgt = int(tail.d.b) if (tail.d is not None and tail.d.t == ida_hexrays.mop_b) else None
        succs = [int(s) for s in blk.succset]
        other = [s for s in succs if s != tgt]
        handler = tgt if int(tail.opcode) == ida_hexrays.m_jz else (other[0] if other else None)
        if handler is not None:
            routing[imm] = handler
    return routing


def _terminal(mba):
    stop = next((i for i in range(mba.qty)
                 if mba.get_mblock(i).type == ida_hexrays.BLT_STOP), mba.qty - 1)
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk.type != ida_hexrays.BLT_STOP and stop in [int(s) for s in blk.succset]:
            return i
    return -1


def _mode_dispatcher(mba, writers):
    counter: Counter = Counter()
    for blist in writers.values():
        for b in blist:
            for s in mba.get_mblock(b).succset:
                counter[int(s)] += 1
    return counter.most_common(1)[0][0] if counter else -1


def recover_dispatch_jzchain(mba, consts=LAB_STATE_CONSTS):
    """Front-end: recover a DispatchDrainPlan from a jz-chain dispatcher. Returns
    None until the dispatcher is fully mapped (every non-terminal writer-state is
    routed) so the optblock can retry as the live mba stabilizes."""
    slot = _state_slot(mba, consts)
    if slot is None:
        return None
    writers = _state_writers(mba, slot, consts)
    routing = _jz_routing(mba, consts)
    terminal = _terminal(mba)
    disp = _mode_dispatcher(mba, writers)
    if terminal < 0 or disp < 0 or not writers:
        return None
    # Ready only when every non-terminal writer-state has a route.
    for k in writers:
        if k != STATE_TERM and k not in routing:
            return None
    redirects = []
    for k, blist in writers.items():
        tgt = routing.get(k, terminal if k == STATE_TERM else None)
        if tgt is None or tgt < 0:
            continue
        for w in blist:
            if disp in [int(s) for s in mba.get_mblock(w).succset]:
                redirects.append((w, tgt, disp))
    if not redirects:
        return None
    return DispatchDrainPlan(tuple(redirects), disp)


def _find_jtbl(mba):
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        tail = blk.tail if blk else None
        if (tail is not None and int(tail.opcode) == ida_hexrays.m_jtbl
                and tail.r is not None and tail.r.t == ida_hexrays.mop_c):
            return blk.serial, tail.r.c
    return -1, None


def recover_dispatch_jtbl(mba):
    """Front-end: recover a DispatchDrainPlan from an m_jtbl dispatcher -- routing
    read straight from the mcases_t case/target pairs. Per-writer ``old_target``
    (jtbl handlers goto a re-dispatch join; the entry gotos the jtbl block)."""
    jserial, cases = _find_jtbl(mba)
    if jserial < 0:
        return None
    routing: dict[int, int] = {}
    for j in range(cases.size()):
        tgt = int(cases.targets[j])
        vv = cases.values[j]
        n = vv.size() if hasattr(vv, "size") else len(vv)
        for k in range(n):
            routing[int(vv[k]) & 0xFFFFFFFF] = tgt
    if len(routing) < 2:
        return None
    jblk = mba.get_mblock(jserial)
    jsuccs = set(int(s) for s in jblk.succset)
    default_pool = jsuccs - set(routing.values())
    default_target = min(default_pool) if default_pool else _terminal(mba)
    slot = re.sub(r"\{[^}]*\}", "", jblk.tail.l.dstr())
    writers: dict[int, list[int]] = {}
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        ins = blk.head if blk else None
        while ins is not None:
            if (int(ins.opcode) == ida_hexrays.m_mov and ins.l is not None
                    and ins.l.t == ida_hexrays.mop_n and ins.d is not None
                    and re.sub(r"\{[^}]*\}", "", ins.d.dstr()) == slot):
                writers.setdefault(int(ins.l.nnn.value) & 0xFFFFFFFF, []).append(
                    blk.serial)
            ins = ins.next
    redirects = []
    for val, wblocks in writers.items():
        tgt = routing.get(val, default_target)
        if tgt is None or tgt < 0:
            continue
        for w in wblocks:
            wsuccs = [int(s) for s in mba.get_mblock(w).succset]
            old = wsuccs[0] if len(wsuccs) == 1 else jserial
            redirects.append((w, tgt, old))
    if not redirects:
        return None
    return DispatchDrainPlan(tuple(redirects), jserial)


# =====================================================================
# LOWERING primitive: IR plan -> microcode emission (via the deferred modifier).
# =====================================================================
def lower_dispatch_drain(mod: DeferredGraphModifier, plan: DispatchDrainPlan) -> int:
    """LOWERING PRIMITIVE. Redirect each state-writer to its routed handler. The
    emission is identical for every dispatcher shape -- the analysis front-end
    that built ``plan`` is what differs (jz-chain vs jump table vs ...)."""
    for src, tgt, old in plan.redirects:
        mod.queue_create_and_redirect(src, tgt, [], old_target_serial=old)
    return len(plan.redirects)


# =====================================================================
# Oracle harness: prove a lowering lowers to the EXPECTED (compiled-source) render.
# =====================================================================
_TEMP = r"(?:[av]\d+|result)"
_LOCAL_RE = re.compile(r"\b" + _TEMP + r"\b")
_COMMENT_RE = re.compile(r"//[^\n]*")
_WS_RE = re.compile(r"\s+")
_SINK = "g_hexrays_lab_sink"


def _copy_propagate(body: str) -> str:
    """Inline single-assignment Hex-Rays temps (``result = X; ... result ...`` ->
    ``... X ...``). Models Hex-Rays' own store-forwarding so a decompile that
    spills through a temp compares equal to one that doesn't."""
    for _ in range(40):
        m = re.search(r"\b(" + _TEMP + r")\s*=\s*([^;{}]+?);", body)
        if m is None:
            break
        var, expr = m.group(1), m.group(2).strip()
        # only inline a temp assigned exactly once and not self-referential
        if len(re.findall(r"\b" + re.escape(var) + r"\s*=", body)) != 1:
            break
        if re.search(r"\b" + re.escape(var) + r"\b", expr):
            break
        body = body[:m.start()] + body[m.end():]
        body = re.sub(r"\b" + re.escape(var) + r"\b", expr, body)
    return body


def normalize_pseudocode(text: str) -> str:
    """Canonicalize a decompile body for oracle comparison. Models the two
    Hex-Rays transforms that render the SAME semantics differently: (1) dead-store
    elimination of consecutive same-LHS sink writes, (2) store-forwarding through
    a single-use temp. Then canonicalizes temp names + whitespace. The result is
    robust to variable numbering / store-forwarding / DSE while preserving the
    operations and control structure (so a wrong handler op still fails)."""
    lo, hi = text.find("{"), text.rfind("}")
    body = text[lo + 1:hi] if (lo >= 0 and hi > lo) else text
    body = _COMMENT_RE.sub("", body)
    # Drop local declaration lines ("int v2;") -- numbering is incidental.
    kept = []
    for line in body.splitlines():
        s = line.strip()
        if re.fullmatch(
            r"(unsigned\s+)?(int|__int\d+|char|short|long|_BOOL|bool|_DWORD|_QWORD)\s+"
            + _TEMP + r";", s):
            continue
        kept.append(line)
    body = "\n".join(kept)
    body = _copy_propagate(body)
    body = _WS_RE.sub(" ", body).strip()
    # DSE: collapse a run of consecutive sink stores to the last (keeps only the
    # surviving write, exactly as Hex-Rays does for the non-flattened sibling).
    prev = None
    while prev != body:
        prev = body
        body = re.sub(
            re.escape(_SINK) + r" = [^;]*;\s*(?=" + re.escape(_SINK) + r" = )",
            "", body)
    # Store-to-load forward on the sink: Hex-Rays sometimes renders `return
    # g_hexrays_lab_sink;` (reading back the global it just wrote) instead of
    # `return <expr>;`. Forward the written value into the read-back.
    body = re.sub(
        r"(" + re.escape(_SINK) + r" = )([^;]*)(;\s*return )"
        + re.escape(_SINK) + r";",
        lambda m: m.group(1) + m.group(2) + m.group(3) + m.group(2) + ";",
        body)
    body = _LOCAL_RE.sub("V", body)
    body = _WS_RE.sub(" ", body).strip()
    return body


def _norm_cond(c: str) -> str:
    c = re.sub(r"(!=|==)\s*0\b", "", c)          # strip `!= 0` / `== 0` truthiness
    c = _LOCAL_RE.sub("V", c)
    c = re.sub(r"[()\s]", "", c)
    return c.lower()


def _skeleton(body: str) -> str:
    """The control-flow keyword + condition sequence (if/else/while/do/for/return),
    dropping plain statements and braces -- so where Hex-Rays places/hoists a store
    is irrelevant, but the branch/loop structure (and its predicates) is captured."""
    out, i, n = [], 0, len(body)
    kws = ("if", "while", "for", "else", "do", "return")

    def isw(ch):
        return ch.isalnum() or ch == "_"

    while i < n:
        m = None
        for kw in kws:
            if (body[i:i + len(kw)] == kw and (i == 0 or not isw(body[i - 1]))
                    and (i + len(kw) >= n or not isw(body[i + len(kw)]))):
                m = kw
                break
        if m in ("if", "while", "for"):
            j = body.find("(", i)
            depth, k = 0, j
            while k < n:
                if body[k] == "(":
                    depth += 1
                elif body[k] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            out.append(m.upper() + "(" + _norm_cond(body[j + 1:k]) + ")")
            i = k + 1
        elif m in ("else", "do"):
            out.append(m.upper())
            i += len(m)
        elif m == "return":
            out.append("RET")
            i += 6
        else:
            i += 1
    return " ".join(out)


_OP_RE = re.compile(r"([-+^&|*]|<<|>>)\s*(0x[0-9a-fA-F]+|\d+)")


def _ops(body: str) -> frozenset:
    """The SET of arithmetic operations ``(operator, constant)`` -- the handler
    work, independent of how many times / where Hex-Rays materializes it."""
    return frozenset((op, int(v, 0)) for op, v in _OP_RE.findall(body))


def semantic_signature(text: str):
    """Semantic-structural signature of a decompile: (control-flow skeleton,
    operation set). Two renders are equivalent iff their signatures are equal --
    robust to Hex-Rays' store placement / DSE / hoisting / temp naming, while
    still failing on a wrong control structure or a wrong/missing handler op."""
    lo, hi = text.find("{"), text.rfind("}")
    body = text[lo + 1:hi] if (lo >= 0 and hi > lo) else text
    body = _COMMENT_RE.sub("", body)
    return (_skeleton(body), _ops(body))


def render_reference(ea) -> str:
    """Baseline decompile (no d810) of the oracle sibling = expected pseudocode."""
    cfunc = ida_hexrays.decompile(ea)
    return str(cfunc) if cfunc is not None else ""


def apply_lowering_and_render(flat_ea, recover_fn, lower_fn=lower_dispatch_drain):
    """Install a one-shot GLBOPT1 ``optblock_t`` that recovers the IR via
    ``recover_fn`` and lowers it via ``lower_fn``, then decompile the flattened
    function and return ``(render_text, applied, error)``."""
    box = {"applied": 0, "error": None, "done": False}

    class _LowerOptblock(ida_hexrays.optblock_t):
        def func(self, blk):
            try:
                mba = blk.mba
                if (box["done"] or mba is None
                        or int(mba.maturity) != int(ida_hexrays.MMAT_GLBOPT1)):
                    return 0
                plan = recover_fn(mba)
                if plan is None:
                    return 0
                box["done"] = True
                mod = DeferredGraphModifier(mba)
                lower_fn(mod, plan)
                mod.coalesce()
                box["applied"] = mod.apply(run_optimize_local=True)
                return box["applied"]
            except Exception as exc:  # noqa: BLE001
                box["error"] = repr(exc)
                return 0

    opt = _LowerOptblock()
    opt.install()
    hf = ida_hexrays.hexrays_failure_t()
    try:
        ida_hexrays.mark_cfunc_dirty(flat_ea)
        cfunc = ida_hexrays.decompile(flat_ea, hf)
    finally:
        opt.remove()
    text = str(cfunc) if cfunc is not None else ""
    return text, box["applied"], box["error"]

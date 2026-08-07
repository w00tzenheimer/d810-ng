"""Find MBA-shaped expressions in microcode.

Two things here are load-bearing and were established by measurement, not by
reading PR #14 (trailofbits/CoBRA#14), whose detector does neither:

1. **Def-use inlining is mandatory, not an enhancement.** Hex-Rays microcode is
   largely 3-address, so an MBA expression is spread across many instructions
   joined by temporaries rather than nested inside one ``minsn_t``.
   Single-instruction detection finds **zero** candidates on VM_DecryptPacket
   and zero across 60 diagnostic snapshots of other functions. Substituting
   single-assignment temporaries back into their consumer is what turns 0 into
   55.

2. **An unsupported opcode REJECTS the candidate; it is never approximated.**
   PR #14 evaluates unknown opcodes as 0, and because the same evaluator
   produces both the signature handed to the solver and the equivalence check,
   a mis-modelled opcode is wrong on both sides and invisible. Rejecting is
   free; a wrong rewrite is not.

Design and measurements:
``docs/plans/2026-08-06-cobra-mba-solve-integration.md``
"""

from __future__ import annotations

import collections
import dataclasses

import ida_hexrays

from d810.backends.cobra.expr import node_count
from d810.hexrays.ir.mop_snapshot import MopSnapshot

M_MOV = ida_hexrays.m_mov
M_NEG = ida_hexrays.m_neg
M_BNOT = ida_hexrays.m_bnot
M_XDU = ida_hexrays.m_xdu
M_SHL = ida_hexrays.m_shl

_BINOP = {
    ida_hexrays.m_add: "+",
    ida_hexrays.m_sub: "-",
    ida_hexrays.m_mul: "*",
    ida_hexrays.m_or: "|",
    ida_hexrays.m_and: "&",
    ida_hexrays.m_xor: "^",
}
_UNOP = {M_NEG: "-", M_BNOT: "~"}
_SUPPORTED = set(_BINOP) | set(_UNOP) | {M_MOV}

_LEAF_TYPES = frozenset(
    {ida_hexrays.mop_r, ida_hexrays.mop_l, ida_hexrays.mop_S, ida_hexrays.mop_v}
)

_BOOL_OPS = frozenset({"~", "|", "&", "^"})
_ARITH_OPS = frozenset({"-", "+", "*"})

#: Signature cost is 2**n evaluations, so the leaf cap is the real constraint:
#: 256 evaluations at 8 leaves versus 65,536 at PR #14's kMaxVars = 16.
DEFAULT_MAX_LEAVES = 8

#: Guard against an inlined tree exploding through a long temporary chain.
_MAX_INLINE_DEPTH = 24
_MAX_INLINE_NODES = 200


class UnsupportedMicrocode(Exception):
    """This instruction cannot be modelled exactly, so it is not a candidate."""


@dataclasses.dataclass(frozen=True)
class MbaCandidate:
    """One MBA expression, reassembled across instructions."""

    ea: int
    block_serial: int
    tree: dict
    leaf_names: tuple[str, ...]
    leaf_snapshots: dict[str, MopSnapshot]
    dest_size: int

    @property
    def bitwidth(self) -> int:
        return self.dest_size * 8

    @property
    def mask(self) -> int:
        return (1 << self.bitwidth) - 1

    @property
    def node_count(self) -> int:
        return node_count(self.tree)

    def render(self) -> str:
        """Render as cobra-cli input, with leaves mapped to x0..xN."""
        varmap = {name: f"x{i}" for i, name in enumerate(self.leaf_names)}
        return _render(self.tree, varmap)


def _render(tree: dict, varmap: dict[str, str]) -> str:
    kind = tree["kind"]
    if kind == "const":
        return str(tree["value"])
    if kind == "var":
        return varmap[tree["name"]]
    if kind == "un":
        return f"({tree['op']}{_render(tree['a'], varmap)})"
    return f"({_render(tree['a'], varmap)}{tree['op']}{_render(tree['b'], varmap)})"


class _TreeBuilder:
    """Builds trees for one block, snapshotting the operand behind each leaf.

    Snapshots rather than ``mop_t`` references: IDA invalidates operands when
    the optimizer runs or a block changes, and a candidate outlives detection
    (it crosses a solver subprocess before reconstruction).  Enforced by
    ``rules/no-borrowed-mop-storage.yml``.
    """

    def __init__(self) -> None:
        self.snapshots: dict[str, MopSnapshot] = {}

    def operand(self, op) -> dict:
        if op is None:
            raise UnsupportedMicrocode("missing operand")
        if op.t == ida_hexrays.mop_n:
            return {"kind": "const", "value": int(op.nnn.value)}
        if op.t == ida_hexrays.mop_d:
            return self.instruction(op.d)
        if op.t in _LEAF_TYPES:
            name = op.dstr()
            if name not in self.snapshots:
                self.snapshots[name] = MopSnapshot.from_mop(op)
            return {"kind": "var", "name": name}
        raise UnsupportedMicrocode(f"operand type {op.t}")

    def instruction(self, ins) -> dict:
        if ins is None:
            raise UnsupportedMicrocode("missing instruction")
        opcode = ins.opcode

        # shl by a constant is exact multiplication by 2**k.
        if opcode == M_SHL:
            if (
                ins.r is not None
                and ins.r.t == ida_hexrays.mop_n
                and int(ins.r.nnn.value) < 64
            ):
                return {
                    "kind": "bin",
                    "op": "*",
                    "a": self.operand(ins.l),
                    "b": {"kind": "const", "value": 1 << int(ins.r.nnn.value)},
                }
            raise UnsupportedMicrocode("shl by non-constant")

        # Zero-extend is exactly AND with the source mask, which is right for
        # EVALUATION. It is not enough for RECONSTRUCTION -- the AND does not
        # widen the operand -- which is why narrow leaves are rejected below.
        if opcode == M_XDU:
            src_bits = (ins.l.size or 0) * 8
            if 0 < src_bits <= 64:
                return {
                    "kind": "bin",
                    "op": "&",
                    "a": self.operand(ins.l),
                    "b": {"kind": "const", "value": (1 << src_bits) - 1},
                }
            raise UnsupportedMicrocode("xdu width out of range")

        if opcode not in _SUPPORTED:
            raise UnsupportedMicrocode(f"opcode {opcode}")
        if ins.l is None or ins.l.t == ida_hexrays.mop_z:
            raise UnsupportedMicrocode("missing left operand")
        if opcode == M_MOV:
            return self.operand(ins.l)
        if opcode in _UNOP:
            return {"kind": "un", "op": _UNOP[opcode], "a": self.operand(ins.l)}
        if ins.r is None or ins.r.t == ida_hexrays.mop_z:
            raise UnsupportedMicrocode("missing right operand")
        return {
            "kind": "bin",
            "op": _BINOP[opcode],
            "a": self.operand(ins.l),
            "b": self.operand(ins.r),
        }


def _inline(tree: dict, env: dict[str, dict], depth: int = 0) -> dict:
    """Substitute known temporaries to reassemble the real expression."""
    if depth > _MAX_INLINE_DEPTH:
        raise UnsupportedMicrocode("inline depth exceeded")
    kind = tree["kind"]
    if kind == "var":
        bound = env.get(tree["name"])
        if bound is not None and node_count(bound) < _MAX_INLINE_NODES:
            return _inline(bound, env, depth + 1)
        return tree
    if kind == "un":
        return {"kind": "un", "op": tree["op"], "a": _inline(tree["a"], env, depth + 1)}
    if kind == "bin":
        return {
            "kind": "bin",
            "op": tree["op"],
            "a": _inline(tree["a"], env, depth + 1),
            "b": _inline(tree["b"], env, depth + 1),
        }
    return tree


def _walk(tree: dict, names: list[str], ops: list[str]) -> None:
    kind = tree["kind"]
    if kind == "var":
        if tree["name"] not in names:
            names.append(tree["name"])
    elif kind == "un":
        ops.append(tree["op"])
        _walk(tree["a"], names, ops)
    elif kind == "bin":
        ops.append(tree["op"])
        _walk(tree["a"], names, ops)
        _walk(tree["b"], names, ops)


def detect_candidates(
    mba,
    *,
    max_leaves: int = DEFAULT_MAX_LEAVES,
) -> tuple[list[MbaCandidate], collections.Counter]:
    """Return MBA candidates in *mba*, plus a histogram of rejection reasons.

    Inlining is intra-block: the environment is cleared at each block boundary,
    so a temporary never leaks across blocks. Genuine cross-block chaining is
    unexplored upside.
    """
    candidates: list[MbaCandidate] = []
    reasons: collections.Counter = collections.Counter()
    seen: set[str] = set()

    for serial in range(mba.qty):
        block = mba.get_mblock(serial)
        builder = _TreeBuilder()
        env: dict[str, dict] = {}
        ins = block.head

        while ins is not None:
            dest_name = (
                ins.d.dstr()
                if ins.d is not None and ins.d.t in _LEAF_TYPES
                else None
            )
            try:
                tree = _inline(builder.instruction(ins), env)
            except UnsupportedMicrocode as exc:
                # A definition we cannot model invalidates any stale binding.
                if dest_name is not None:
                    env.pop(dest_name, None)
                reasons[str(exc)] += 1
                ins = ins.next
                continue

            if dest_name is not None:
                env[dest_name] = tree

            candidate = _classify(
                ins, serial, tree, builder, max_leaves, reasons, seen
            )
            if candidate is not None:
                candidates.append(candidate)
            ins = ins.next

    return candidates, reasons


def _classify(ins, serial, tree, builder, max_leaves, reasons, seen):
    if tree["kind"] not in ("bin", "un"):
        reasons["not an expression"] += 1
        return None

    names: list[str] = []
    ops: list[str] = []
    _walk(tree, names, ops)

    if not any(op in _BOOL_OPS for op in ops):
        reasons["no boolean operator"] += 1
        return None
    if not any(op in _ARITH_OPS for op in ops):
        reasons["no arithmetic operator"] += 1
        return None
    if not names:
        reasons["no variables"] += 1
        return None
    if len(names) > max_leaves:
        reasons[f"more than {max_leaves} leaves"] += 1
        return None

    dest_size = ins.d.size if ins.d is not None else 0
    if dest_size not in (1, 2, 4, 8):
        reasons["unsupported destination size"] += 1
        return None

    # Every leaf must already be destination width.  Reconstruction emits a
    # single-width expression, and a narrower leaf produces mixed operand sizes
    # that IDA's verifier rejects -- measured: 5 of 5 such candidates rejected,
    # 55 of 55 uniform-width candidates accepted.  Widening properly means
    # emitting a real m_xdu/m_xds rather than the mask used for evaluation.
    if any(builder.snapshots[name].size != dest_size for name in names):
        reasons["leaf narrower than destination"] += 1
        return None

    expression = _render(tree, {n: f"x{i}" for i, n in enumerate(names)})
    if expression in seen:
        reasons["duplicate expression"] += 1
        return None
    seen.add(expression)

    return MbaCandidate(
        ea=ins.ea,
        block_serial=serial,
        tree=tree,
        leaf_names=tuple(names),
        leaf_snapshots={n: builder.snapshots[n] for n in names},
        dest_size=dest_size,
    )

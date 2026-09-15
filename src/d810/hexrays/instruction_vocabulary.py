"""Closed Hex-Rays opcode vocabulary shared by capture and replay adapters."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from d810.core.typing import Any, Callable
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import InsnKind
from d810.ir.semantics import CallKind, ControlTransferKind, PredicateKind
from d810.ir.flowgraph import OperandKind

_ALIASES = {
    "nop": "m_nop", "mov": "m_mov", "load": "m_ldx", "store": "m_stx",
    "add": "m_add", "sub": "m_sub", "mul": "m_mul", "and": "m_and",
    "xdu": "m_xdu", "xds": "m_xds", "call": "m_call", "icall": "m_icall",
    "goto": "m_goto", "ret": "m_ret", "jtbl": "m_jtbl", "ijmp": "m_ijmp",
    "jz": "m_jz", "jnz": "m_jnz", "jae": "m_jae", "ja": "m_ja",
    "jbe": "m_jbe", "jb": "m_jb", "jge": "m_jge", "jg": "m_jg",
    "jle": "m_jle", "jl": "m_jl", "jcnd": "m_jcnd",
}
_OPERAND_KINDS = MappingProxyType({
    "mop_z": OperandKind.EMPTY, "mop_r": OperandKind.REGISTER,
    "mop_n": OperandKind.NUMBER, "mop_str": OperandKind.STRING,
    "mop_d": OperandKind.SUBINSN, "mop_S": OperandKind.STACK,
    "mop_v": OperandKind.GLOBAL, "mop_b": OperandKind.BLOCK,
    "mop_f": OperandKind.ARG_LIST, "mop_l": OperandKind.LVAR,
    "mop_a": OperandKind.ADDRESS, "mop_h": OperandKind.HELPER,
    "mop_c": OperandKind.CASE_LIST, "mop_fn": OperandKind.FP_CONST,
    "mop_p": OperandKind.PAIR, "mop_sc": OperandKind.SCATTERED,
})


@dataclass(frozen=True, slots=True)
class OperandShape:
    """Required presence for Hex-Rays ``l``, ``r``, and ``d`` slots."""

    l: bool | None
    r: bool | None
    d: bool | None


@dataclass(frozen=True, slots=True)
class InstructionVocabularyEntry:
    """One canonical opcode row shared by capture and replay."""

    kind: InsnKind
    shape: OperandShape
    value_op_kind: ValueOpKind | None = None
    predicate_kind: PredicateKind | None = None
    control_transfer_kind: ControlTransferKind | None = None
    call_kind: CallKind | None = None


def _entry(
    kind: InsnKind,
    shape: OperandShape,
    *,
    value: ValueOpKind | None = None,
    predicate: PredicateKind | None = None,
    transfer: ControlTransferKind | None = None,
    call: CallKind | None = None,
) -> InstructionVocabularyEntry:
    return InstructionVocabularyEntry(
        kind=kind,
        shape=shape,
        value_op_kind=value,
        predicate_kind=predicate,
        control_transfer_kind=transfer,
        call_kind=call,
    )


# This immutable row table is the sole opcode semantics source.  All lookup
# functions below derive from it; adding a captured opcode therefore requires
# its structural class, exact semantic family, and replay operand shape here.
_VOCABULARY_ROWS = (
    ("m_nop", _entry(InsnKind.NOP, OperandShape(False, False, False))),
    ("m_mov", _entry(InsnKind.MOV, OperandShape(True, False, True), value=ValueOpKind.MOVE)),
    ("m_ldx", _entry(InsnKind.LOAD, OperandShape(True, True, True), value=ValueOpKind.LOAD)),
    ("m_stx", _entry(InsnKind.STORE, OperandShape(True, True, True), value=ValueOpKind.STORE)),
    ("m_add", _entry(InsnKind.ADD, OperandShape(True, True, True), value=ValueOpKind.ADD)),
    ("m_sub", _entry(InsnKind.SUB, OperandShape(True, True, True), value=ValueOpKind.SUB)),
    ("m_mul", _entry(InsnKind.MUL, OperandShape(True, True, True), value=ValueOpKind.MUL)),
    ("m_and", _entry(InsnKind.AND, OperandShape(True, True, True), value=ValueOpKind.AND)),
    ("m_xdu", _entry(InsnKind.XDU, OperandShape(True, False, True), value=ValueOpKind.ZEXT)),
    ("m_xds", _entry(InsnKind.XDS, OperandShape(True, False, True), value=ValueOpKind.SEXT)),
    ("m_ldc", _entry(InsnKind.VALUE, OperandShape(True, False, True), value=ValueOpKind.CONST)),
    ("m_udiv", _entry(InsnKind.VALUE, OperandShape(True, True, True), value=ValueOpKind.UDIV)),
    ("m_sdiv", _entry(InsnKind.VALUE, OperandShape(True, True, True), value=ValueOpKind.SDIV)),
    ("m_umod", _entry(InsnKind.VALUE, OperandShape(True, True, True), value=ValueOpKind.UMOD)),
    ("m_smod", _entry(InsnKind.VALUE, OperandShape(True, True, True), value=ValueOpKind.SMOD)),
    ("m_or", _entry(InsnKind.VALUE, OperandShape(True, True, True), value=ValueOpKind.OR)),
    ("m_xor", _entry(InsnKind.VALUE, OperandShape(True, True, True), value=ValueOpKind.XOR)),
    ("m_bnot", _entry(InsnKind.VALUE, OperandShape(True, False, True), value=ValueOpKind.NOT)),
    ("m_lnot", _entry(InsnKind.VALUE, OperandShape(True, False, True), value=ValueOpKind.LNOT)),
    ("m_neg", _entry(InsnKind.VALUE, OperandShape(True, False, True), value=ValueOpKind.NEG)),
    ("m_shl", _entry(InsnKind.VALUE, OperandShape(True, True, True), value=ValueOpKind.SHL)),
    ("m_shr", _entry(InsnKind.VALUE, OperandShape(True, True, True), value=ValueOpKind.SHR)),
    ("m_sar", _entry(InsnKind.VALUE, OperandShape(True, True, True), value=ValueOpKind.SAR)),
    ("m_low", _entry(InsnKind.VALUE, OperandShape(True, False, True), value=ValueOpKind.LOW)),
    ("m_high", _entry(InsnKind.VALUE, OperandShape(True, False, True), value=ValueOpKind.HIGH)),
    ("m_cfadd", _entry(InsnKind.SET, OperandShape(True, True, True), value=ValueOpKind.CARRY_ADD)),
    ("m_ofadd", _entry(InsnKind.SET, OperandShape(True, True, True), value=ValueOpKind.OVERFLOW_ADD)),
    ("m_cfshl", _entry(InsnKind.SET, OperandShape(True, True, True), value=ValueOpKind.CARRY_SHL)),
    ("m_cfshr", _entry(InsnKind.SET, OperandShape(True, True, True), value=ValueOpKind.CARRY_SHR)),
    ("m_sets", _entry(InsnKind.SET, OperandShape(True, False, True), value=ValueOpKind.SIGN_BIT)),
    ("m_seto", _entry(InsnKind.SET, OperandShape(True, True, True), value=ValueOpKind.OVERFLOW_FLAG)),
    ("m_setp", _entry(InsnKind.SET, OperandShape(True, True, True), value=ValueOpKind.PARITY)),
    ("m_setz", _entry(InsnKind.SET, OperandShape(True, True, True), predicate=PredicateKind.EQ)),
    ("m_setnz", _entry(InsnKind.SET, OperandShape(True, True, True), predicate=PredicateKind.NE)),
    ("m_setae", _entry(InsnKind.SET, OperandShape(True, True, True), predicate=PredicateKind.UGE)),
    ("m_seta", _entry(InsnKind.SET, OperandShape(True, True, True), predicate=PredicateKind.UGT)),
    ("m_setbe", _entry(InsnKind.SET, OperandShape(True, True, True), predicate=PredicateKind.ULE)),
    ("m_setb", _entry(InsnKind.SET, OperandShape(True, True, True), predicate=PredicateKind.ULT)),
    ("m_setge", _entry(InsnKind.SET, OperandShape(True, True, True), predicate=PredicateKind.SGE)),
    ("m_setg", _entry(InsnKind.SET, OperandShape(True, True, True), predicate=PredicateKind.SGT)),
    ("m_setle", _entry(InsnKind.SET, OperandShape(True, True, True), predicate=PredicateKind.SLE)),
    ("m_setl", _entry(InsnKind.SET, OperandShape(True, True, True), predicate=PredicateKind.SLT)),
    ("m_goto", _entry(InsnKind.GOTO, OperandShape(True, False, False), transfer=ControlTransferKind.GOTO)),
    ("m_jtbl", _entry(InsnKind.TABLE_JUMP, OperandShape(True, True, False), transfer=ControlTransferKind.TABLE_BRANCH)),
    ("m_ijmp", _entry(InsnKind.INDIRECT_JUMP, OperandShape(True, None, False), transfer=ControlTransferKind.INDIRECT_BRANCH)),
    ("m_ret", _entry(InsnKind.RET, OperandShape(False, False, False), transfer=ControlTransferKind.RETURN)),
    ("m_jz", _entry(InsnKind.EQUALITY_JUMP, OperandShape(True, True, True), predicate=PredicateKind.EQ, transfer=ControlTransferKind.CONDITIONAL_BRANCH)),
    ("m_jnz", _entry(InsnKind.EQUALITY_JUMP, OperandShape(True, True, True), predicate=PredicateKind.NE, transfer=ControlTransferKind.CONDITIONAL_BRANCH)),
    ("m_jae", _entry(InsnKind.COND_JUMP, OperandShape(True, True, True), predicate=PredicateKind.UGE, transfer=ControlTransferKind.CONDITIONAL_BRANCH)),
    ("m_ja", _entry(InsnKind.COND_JUMP, OperandShape(True, True, True), predicate=PredicateKind.UGT, transfer=ControlTransferKind.CONDITIONAL_BRANCH)),
    ("m_jbe", _entry(InsnKind.COND_JUMP, OperandShape(True, True, True), predicate=PredicateKind.ULE, transfer=ControlTransferKind.CONDITIONAL_BRANCH)),
    ("m_jb", _entry(InsnKind.COND_JUMP, OperandShape(True, True, True), predicate=PredicateKind.ULT, transfer=ControlTransferKind.CONDITIONAL_BRANCH)),
    ("m_jge", _entry(InsnKind.COND_JUMP, OperandShape(True, True, True), predicate=PredicateKind.SGE, transfer=ControlTransferKind.CONDITIONAL_BRANCH)),
    ("m_jg", _entry(InsnKind.COND_JUMP, OperandShape(True, True, True), predicate=PredicateKind.SGT, transfer=ControlTransferKind.CONDITIONAL_BRANCH)),
    ("m_jle", _entry(InsnKind.COND_JUMP, OperandShape(True, True, True), predicate=PredicateKind.SLE, transfer=ControlTransferKind.CONDITIONAL_BRANCH)),
    ("m_jl", _entry(InsnKind.COND_JUMP, OperandShape(True, True, True), predicate=PredicateKind.SLT, transfer=ControlTransferKind.CONDITIONAL_BRANCH)),
    ("m_jcnd", _entry(InsnKind.COND_JUMP, OperandShape(True, False, True), predicate=PredicateKind.TRUTHY, transfer=ControlTransferKind.CONDITIONAL_BRANCH)),
    # IDA 9.4 emits target-only direct calls with ``d=mop_z``; when present,
    # d carries the call-info argument list.
    ("m_call", _entry(InsnKind.CALL, OperandShape(True, False, None), call=CallKind.DIRECT)),
    # IDA 9.4 applies the same optional call-info encoding to indirect calls.
    ("m_icall", _entry(InsnKind.CALL, OperandShape(True, True, None), call=CallKind.INDIRECT)),
    # SDK-known retained operations without a portable semantic model. Their
    # exact roles remain closed and replayable; authority consumers must ignore
    # them unless an independent semantic fact authorizes use.
    ("m_push", _entry(InsnKind.UNKNOWN, OperandShape(True, False, False), value=ValueOpKind.VENDOR)),
    ("m_pop", _entry(InsnKind.UNKNOWN, OperandShape(False, False, True), value=ValueOpKind.VENDOR)),
    ("m_und", _entry(InsnKind.UNKNOWN, OperandShape(False, False, True), value=ValueOpKind.VENDOR)),
    # Hex-Rays treats m_ext as an external instruction with opcode-specific
    # operands.  The SDK validity contract imposes no presence pattern (only
    # mop_b/mop_f are forbidden), and live 9.4 microcode includes destination-
    # only forms such as the lock/seto extension.
    ("m_ext", _entry(InsnKind.UNKNOWN, OperandShape(None, None, None), value=ValueOpKind.VENDOR)),
    ("m_f2i", _entry(InsnKind.UNKNOWN, OperandShape(True, False, True), value=ValueOpKind.VENDOR)),
    ("m_f2u", _entry(InsnKind.UNKNOWN, OperandShape(True, False, True), value=ValueOpKind.VENDOR)),
    ("m_i2f", _entry(InsnKind.UNKNOWN, OperandShape(True, False, True), value=ValueOpKind.VENDOR)),
    ("m_u2f", _entry(InsnKind.UNKNOWN, OperandShape(True, False, True), value=ValueOpKind.VENDOR)),
    ("m_f2f", _entry(InsnKind.UNKNOWN, OperandShape(True, False, True), value=ValueOpKind.VENDOR)),
    ("m_fneg", _entry(InsnKind.UNKNOWN, OperandShape(True, False, True), value=ValueOpKind.VENDOR)),
    ("m_fadd", _entry(InsnKind.UNKNOWN, OperandShape(True, True, True), value=ValueOpKind.VENDOR)),
    ("m_fsub", _entry(InsnKind.UNKNOWN, OperandShape(True, True, True), value=ValueOpKind.VENDOR)),
    ("m_fmul", _entry(InsnKind.UNKNOWN, OperandShape(True, True, True), value=ValueOpKind.VENDOR)),
    ("m_fdiv", _entry(InsnKind.UNKNOWN, OperandShape(True, True, True), value=ValueOpKind.VENDOR)),
)
_VOCABULARY = MappingProxyType(dict(_VOCABULARY_ROWS))
# IDA 9.4 exposes ``m_ijmp`` in two closed maturity-dependent layouts.  The
# canonical replay form is ``l,*,z``; early live CALLS/LOCOPT capture can carry
# the indirect selector in ``r`` and its resolved/fictitious destination in
# ``d`` as ``z,r,d``.  Keep the alternatives explicit rather than weakening
# every slot to "don't care".
_OPERAND_SHAPE_VARIANTS = MappingProxyType({
    "m_ijmp": (
        OperandShape(True, None, False),
        OperandShape(False, True, True),
    ),
})
if len(_VOCABULARY) != len(_VOCABULARY_ROWS):
    raise RuntimeError("duplicate opcode in canonical vocabulary")
if any(not entry.shape for _name, entry in _VOCABULARY_ROWS):
    raise RuntimeError("canonical vocabulary row lacks replay operand shape")
if any(
    entry.kind is InsnKind.UNKNOWN
    and entry.value_op_kind is not ValueOpKind.VENDOR
    for _name, entry in _VOCABULARY_ROWS
):
    raise RuntimeError("unmodeled canonical opcode must carry explicit vendor semantics")
if any(
    entry.kind is not InsnKind.NOP
    and entry.value_op_kind is None
    and entry.predicate_kind is None
    and entry.control_transfer_kind is None
    and entry.call_kind is None
    for _name, entry in _VOCABULARY_ROWS
):
    raise RuntimeError("canonical vocabulary row lacks semantic classification")
if any(
    entry.predicate_kind is not None
    and (entry.control_transfer_kind is ControlTransferKind.CONDITIONAL_BRANCH)
    == (entry.kind is InsnKind.SET)
    for _name, entry in _VOCABULARY_ROWS
):
    raise RuntimeError("predicate row must be exactly one of branch or set")


def canonical_opcode_name(name: str) -> str:
    return _ALIASES.get(str(name), str(name))


def operand_kind_for_name(name: str) -> OperandKind | None:
    """Resolve a recorded canonical ``mop_*`` name without numeric guessing."""

    return _OPERAND_KINDS.get(str(name))


def operand_type_names() -> tuple[str, ...]:
    """Return canonical SDK mop names for live adapters to resolve by constant."""

    return tuple(_OPERAND_KINDS)


def insn_kind_for_opcode_name(name: str) -> InsnKind | None:
    entry = _VOCABULARY.get(canonical_opcode_name(name))
    return entry.kind if entry is not None else None


def vocabulary_entry_for_opcode_name(name: str) -> InstructionVocabularyEntry | None:
    """Return the complete immutable row for a canonical or portable alias."""

    return _VOCABULARY.get(canonical_opcode_name(name))


def predicate_for_opcode_name(name: str) -> PredicateKind | None:
    entry = _VOCABULARY.get(canonical_opcode_name(name))
    return entry.predicate_kind if entry is not None else None


def branch_predicate_for_opcode_name(name: str) -> PredicateKind | None:
    entry = _VOCABULARY.get(canonical_opcode_name(name))
    return entry.predicate_kind if entry is not None and entry.control_transfer_kind is ControlTransferKind.CONDITIONAL_BRANCH else None


def set_predicate_for_opcode_name(name: str) -> PredicateKind | None:
    entry = _VOCABULARY.get(canonical_opcode_name(name))
    return entry.predicate_kind if entry is not None and entry.kind is InsnKind.SET else None


def call_kind_for_opcode_name(name: str) -> CallKind | None:
    entry = _VOCABULARY.get(canonical_opcode_name(name))
    return entry.call_kind if entry is not None else None


def value_op_kind_for_opcode_name(name: str) -> ValueOpKind | None:
    """Return the recorded value-operation semantics, if any."""

    entry = _VOCABULARY.get(canonical_opcode_name(name))
    return entry.value_op_kind if entry is not None else None


def live_value_operations() -> tuple[tuple[str, ValueOpKind], ...]:
    return tuple((name, entry.value_op_kind) for name, entry in _VOCABULARY_ROWS if entry.value_op_kind is not None)


def live_branch_predicates() -> tuple[tuple[str, PredicateKind], ...]:
    return tuple((name, entry.predicate_kind) for name, entry in _VOCABULARY_ROWS if entry.control_transfer_kind is ControlTransferKind.CONDITIONAL_BRANCH)


def live_set_predicates() -> tuple[tuple[str, PredicateKind], ...]:
    return tuple((name, entry.predicate_kind) for name, entry in _VOCABULARY_ROWS if entry.kind is InsnKind.SET and entry.predicate_kind is not None)


def live_control_transfers() -> tuple[tuple[str, ControlTransferKind], ...]:
    return tuple((name, entry.control_transfer_kind) for name, entry in _VOCABULARY_ROWS if entry.control_transfer_kind is not None)


def live_calls() -> tuple[tuple[str, CallKind], ...]:
    return tuple((name, entry.call_kind) for name, entry in _VOCABULARY_ROWS if entry.call_kind is not None)


def live_known_opcode_names() -> tuple[str, ...]:
    return tuple(name for name, _entry in _VOCABULARY_ROWS)


def replay_supported_opcode_name(name: str) -> bool:
    return canonical_opcode_name(name) in _VOCABULARY


def branch_opcode_name_for_predicate(predicate: PredicateKind) -> str | None:
    if not isinstance(predicate, PredicateKind):
        raise TypeError("branch opcode lookup requires a PredicateKind")
    for name, candidate in live_branch_predicates():
        if candidate is predicate:
            return name
    return None


def control_transfer_kind_for_opcode_name(name: str) -> ControlTransferKind | None:
    """Return the recorded non-call transfer semantics, if any."""

    entry = _VOCABULARY.get(canonical_opcode_name(name))
    return entry.control_transfer_kind if entry is not None else None


def tail_kind_for_opcode_name(name: str) -> str | None:
    kind = insn_kind_for_opcode_name(name)
    if kind is None:
        return None
    if kind is InsnKind.CALL:
        return "call"
    if kind is InsnKind.TABLE_JUMP:
        return "table_jump"
    if kind is InsnKind.INDIRECT_JUMP:
        return "indirect_jump"
    return kind.value


def is_supported_opcode_name(name: str) -> bool:
    return insn_kind_for_opcode_name(name) is not None

_CONDITIONALS = frozenset(name for name, entry in _VOCABULARY_ROWS if entry.control_transfer_kind is ControlTransferKind.CONDITIONAL_BRANCH)
_DIRECT_TARGET_KINDS = frozenset({OperandKind.BLOCK, OperandKind.GLOBAL})


def operand_shape_for_opcode_name(name: str) -> OperandShape | None:
    entry = _VOCABULARY.get(canonical_opcode_name(name))
    return entry.shape if entry is not None else None


def _present(operand: Any) -> bool:
    return operand is not None and getattr(operand, "kind", None) is not OperandKind.EMPTY


def _validate_roles(name: str, *, l: Any, r: Any, d: Any) -> None:
    canonical = canonical_opcode_name(name)
    if canonical == "m_goto" and getattr(l, "kind", None) not in _DIRECT_TARGET_KINDS:
        raise ValueError(f"opcode {name} operand shape rejects non-block target")
    # The SDK documents m_jcnd.d as mop_v or mop_b.  Preserve both target
    # encodings at capture because direct-address branches occur in live
    # microcode before they are normalized to local CFG block references.
    if canonical == "m_jcnd" and getattr(d, "kind", None) not in _DIRECT_TARGET_KINDS:
        raise ValueError(f"opcode {name} operand shape rejects non-block target")
    if canonical in _CONDITIONALS - {"m_jcnd"} and getattr(d, "kind", None) is not OperandKind.BLOCK:
        raise ValueError(f"opcode {name} operand shape rejects non-block target")
    if canonical == "m_jtbl" and getattr(r, "kind", None) is not OperandKind.CASE_LIST:
        raise ValueError(f"opcode {name} operand shape rejects non-case-list table")
    if canonical == "m_call" and (
        getattr(l, "kind", None) in {None, OperandKind.EMPTY}
        or (_present(d) and getattr(d, "kind", None) is not OperandKind.ARG_LIST)
    ):
        raise ValueError(f"opcode {name} operand shape rejects incomplete call")
    if canonical == "m_icall" and (
        getattr(l, "kind", None) in {None, OperandKind.EMPTY}
        or (_present(d) and getattr(d, "kind", None) is not OperandKind.ARG_LIST)
    ):
        raise ValueError(f"opcode {name} operand shape rejects incomplete call")


def validate_operand_shape(name: str, *, l: Any, r: Any, d: Any) -> OperandShape:
    shape = operand_shape_for_opcode_name(name)
    if shape is None:
        raise ValueError(f"opcode {name!r} has no closed operand shape")
    actual = tuple(_present(value) for value in (l, r, d))
    variants = _OPERAND_SHAPE_VARIANTS.get(canonical_opcode_name(name), (shape,))
    if not any(
        all(
            required is None or required == observed
            for observed, required in zip(
                actual, (variant.l, variant.r, variant.d),
            )
        )
        for variant in variants
    ):
        raise ValueError(
            f"opcode {name} operand shape rejects recorded presence: "
            "expected="
            f"{tuple((item.l, item.r, item.d) for item in variants)!r} "
            f"actual={actual!r}"
        )
    if any(
        present and getattr(operand, "kind", None) is OperandKind.UNKNOWN
        for present, operand in zip(actual, (l, r, d))
    ):
        raise ValueError(f"opcode {name} operand shape rejects unknown operand kind")
    _validate_roles(name, l=l, r=r, d=d)
    return shape


def validate_live_operand_shape(
    name: str, *, l: Any, r: Any, d: Any,
    kind_classifier: Callable[[Any], OperandKind],
) -> OperandShape | None:
    """Validate live mops using caller-owned SDK kind classification."""

    shape = operand_shape_for_opcode_name(name)
    if shape is None:
        return None
    snapshots = tuple(
        None
        if mop is None
        else _LiveOperand(kind_classifier(mop))
        for mop in (l, r, d)
    )
    validate_operand_shape(name, l=snapshots[0], r=snapshots[1], d=snapshots[2])
    return shape


@dataclass(frozen=True, slots=True)
class _LiveOperand:
    kind: OperandKind | None


def normalize_conditional_operands(name: str, *, l: Any, r: Any, d: Any) -> tuple[Any, Any, int] | None:
    validate_operand_shape(name, l=l, r=r, d=d)
    canonical = canonical_opcode_name(name)
    if canonical not in _CONDITIONALS:
        return None
    if canonical == "m_jcnd":
        width = int(getattr(l, "size", 0) or 0)
        if getattr(l, "kind", None) is OperandKind.EMPTY or width <= 0:
            raise ValueError("conditional operand shape is opaque or incomplete")
        return l, r, width
    if canonical in {"m_jz", "m_jnz"} and (
        getattr(l, "kind", None) is OperandKind.NUMBER
        and getattr(r, "kind", None) is OperandKind.STACK
    ):
        l, r = r, l
    left_width = int(getattr(l, "size", 0) or 0)
    right_width = int(getattr(r, "size", 0) or 0)
    if left_width > 0 and right_width > 0 and left_width == right_width:
        return l, r, left_width
    raise ValueError("conditional operand shape is opaque or incomplete")

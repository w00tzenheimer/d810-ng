"""Live Hex-Rays adapter for equality-chain dispatcher extraction."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from d810.backends.hexrays import condition_chain_runtime as _hexrays_condition_chain_runtime
from d810.analyses.control_flow.dispatcher_resolution import StateDispatcherMap
from d810.analyses.control_flow.equality_chain_dispatcher import (
    extract_state_dispatcher_map_from_mba,
)
from d810.ir.flowgraph import InsnKind, InsnSnapshot, MopSnapshot, OperandKind
from d810.ir.semantics import PredicateKind


_OPERAND_KIND_BY_MOP_NAME = {
    "mop_r": OperandKind.REGISTER,
    "mop_n": OperandKind.NUMBER,
    "mop_S": OperandKind.STACK,
    "mop_v": OperandKind.GLOBAL,
    "mop_b": OperandKind.BLOCK,
    "mop_l": OperandKind.LVAR,
}

_INSN_KIND_BY_OPCODE_NAME = {
    "m_mov": InsnKind.MOV,
    "m_jz": InsnKind.EQUALITY_JUMP,
    "m_jnz": InsnKind.EQUALITY_JUMP,
}

_PREDICATE_BY_OPCODE_NAME = {
    "m_jz": PredicateKind.EQ,
    "m_jnz": PredicateKind.NE,
}


@dataclass(frozen=True, slots=True)
class _MopView:
    _mop: object
    _mop_type_names: Mapping[int, str]

    @property
    def t(self) -> object:
        raw_type = getattr(self._mop, "t", None)
        try:
            return self._mop_type_names.get(int(raw_type), raw_type)
        except Exception:
            return raw_type

    @property
    def kind(self) -> OperandKind:
        return _OPERAND_KIND_BY_MOP_NAME.get(str(self.t), OperandKind.UNKNOWN)

    @property
    def size(self) -> int:
        return int(getattr(self._mop, "size", 0) or 0)

    @property
    def value(self) -> int | None:
        if self.kind is not OperandKind.NUMBER:
            return None
        return _first_int(
            getattr(self._mop, "value", None),
            getattr(self._mop, "nnn_value", None),
            getattr(getattr(self._mop, "nnn", None), "value", None),
        )

    @property
    def stkoff(self) -> int | None:
        if self.kind is not OperandKind.STACK:
            return None
        return _first_int(
            getattr(self._mop, "stkoff", None),
            getattr(getattr(self._mop, "s", None), "off", None),
        )

    @property
    def reg(self) -> int | None:
        if self.kind is not OperandKind.REGISTER:
            return None
        return _first_int(
            getattr(self._mop, "reg", None),
            getattr(self._mop, "r", None),
        )

    @property
    def block_ref(self) -> int | None:
        if self.kind is not OperandKind.BLOCK:
            return None
        return _first_int(
            getattr(self._mop, "block_ref", None),
            getattr(self._mop, "block_num", None),
            getattr(self._mop, "b", None),
        )

    @property
    def gaddr(self) -> int | None:
        if self.kind is not OperandKind.GLOBAL:
            return None
        return _first_int(
            getattr(self._mop, "gaddr", None),
            getattr(self._mop, "g", None),
        )

    @property
    def lvar_off(self) -> int | None:
        if self.kind is not OperandKind.LVAR:
            return None
        lvar = getattr(self._mop, "l", None)
        return _first_int(
            getattr(self._mop, "lvar_off", None),
            getattr(self._mop, "idx", None),
            getattr(lvar, "off", None),
            getattr(lvar, "idx", None),
            _call_lvar_idx(lvar),
        )

    def __getattr__(self, name: str) -> object:
        return getattr(self._mop, name)


def _mop_snapshot_from_view(view: _MopView | None) -> MopSnapshot | None:
    "Materialize a normalized ``_MopView`` into a frozen ``MopSnapshot``.\n\n    The ``_MopView`` already normalizes the raw Hex-Rays operand into portable\n    fields (``kind`` / ``size`` / ``value`` / ``stkoff`` / ``reg`` /\n    ``block_ref`` / ``gaddr`` / ``lvar_off``); copying them onto a real\n    ``MopSnapshot`` lets the canonical preanalysis extractor read operands through\n    ``operand_storages`` / ``project_instruction`` instead of raw operand slots.\n    "
    if view is None:
        return None
    kind = view.kind
    if kind is OperandKind.UNKNOWN:
        return None
    stkoff = view.stkoff
    return MopSnapshot(
        size=int(view.size or 0),
        value=view.value,
        stkoff=stkoff,
        reg=view.reg,
        block_ref=view.block_ref,
        gaddr=view.gaddr,
        lvar_off=view.lvar_off,
        stack_refs=() if stkoff is None else (int(stkoff),),
        kind=kind,
    )


def _insn_snapshot_from_live(
    insn: object,
    opcode_names: Mapping[int, str],
    mop_type_names: Mapping[int, str],
) -> InsnSnapshot:
    "Build a portable ``InsnSnapshot`` from one live microcode instruction.\n\n    The raw opcode / operand types are normalized through the same\n    ``opcode_names`` / ``mop_type_names`` maps the legacy views used, then the\n    portable semantic ``kind`` / ``predicate_kind`` and the ``l`` / ``r`` / ``d``\n    ``MopSnapshot`` operands are stamped onto a real ``InsnSnapshot``.  The\n    canonical projection infers ``control_transfer_kind`` (CONDITIONAL_BRANCH for\n    the equality-jump ``kind``) so the preanalysis extractor's\n    ``project_instruction`` reads of ``control.target`` / ``control.predicate``\n    resolve.\n    "
    raw_opcode = getattr(insn, "opcode", None)
    try:
        opcode_name = opcode_names.get(int(raw_opcode), raw_opcode)
    except Exception:
        opcode_name = raw_opcode
    kind = _INSN_KIND_BY_OPCODE_NAME.get(str(opcode_name), InsnKind.UNKNOWN)
    predicate = _PREDICATE_BY_OPCODE_NAME.get(str(opcode_name))
    left = _mop_snapshot_from_view(
        _adapt_live_mop(getattr(insn, "l", None), mop_type_names)
    )
    right = _mop_snapshot_from_view(
        _adapt_live_mop(getattr(insn, "r", None), mop_type_names)
    )
    dest = _mop_snapshot_from_view(
        _adapt_live_mop(getattr(insn, "d", None), mop_type_names)
    )
    return InsnSnapshot(
        opcode=-1,
        ea=0,
        operands=(),
        kind=kind,
        l=left,
        r=right,
        d=dest,
        predicate_kind=predicate,
    )


def _adapt_live_mop(
    mop: object | None,
    mop_type_names: Mapping[int, str],
) -> _MopView | None:
    if mop is None:
        return None
    return _MopView(mop, mop_type_names)


@dataclass(frozen=True, slots=True)
class _BlockView:
    _blk: object
    _opcode_names: Mapping[int, str]
    _mop_type_names: Mapping[int, str]
    _insns: tuple[InsnSnapshot, ...] = field(init=False, repr=False)
    _tail: InsnSnapshot | None = field(init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_insns", tuple(self._iter_live_insns()))
        object.__setattr__(self, "_tail", self._build_tail())

    @property
    def serial(self) -> int:
        return int(getattr(self._blk, "serial", -1))

    @property
    def type(self) -> object:
        return getattr(self._blk, "type", None)

    @property
    def tail(self) -> InsnSnapshot | None:
        return self._tail

    @property
    def succs(self) -> tuple[int, ...]:
        nsucc = getattr(self._blk, "nsucc", None)
        succ = getattr(self._blk, "succ", None)
        if callable(nsucc) and callable(succ):
            try:
                return tuple(int(succ(i)) for i in range(int(nsucc())))
            except Exception:
                return ()
        raw_succs = getattr(self._blk, "succset", getattr(self._blk, "succs", ()))
        try:
            return tuple(int(item) for item in raw_succs)
        except Exception:
            return ()

    @property
    def insns(self) -> tuple[InsnSnapshot, ...]:
        return self._insns

    def nsucc(self) -> int:
        return len(self.succs)

    def succ(self, index: int) -> int:
        return self.succs[int(index)]

    def _build_tail(self) -> InsnSnapshot | None:
        tail = getattr(self._blk, "tail", None)
        if tail is None:
            return None
        return _insn_snapshot_from_live(
            tail, self._opcode_names, self._mop_type_names
        )

    def _iter_live_insns(self):
        head = getattr(self._blk, "head", None)
        tail = getattr(self._blk, "tail", None)
        if head is None:
            return
        current = head
        seen: set[int] = set()
        while current is not None and id(current) not in seen:
            seen.add(id(current))
            yield _insn_snapshot_from_live(
                current, self._opcode_names, self._mop_type_names
            )
            if current is tail:
                break
            current = getattr(current, "next", None)

    def __getattr__(self, name: str) -> object:
        return getattr(self._blk, name)


@dataclass(slots=True)
class _MbaView:
    _mba: object
    _opcode_names: Mapping[int, str]
    _mop_type_names: Mapping[int, str]
    _block_cache: dict[int, _BlockView] = field(default_factory=dict, init=False)

    @property
    def qty(self) -> int:
        return int(getattr(self._mba, "qty", 0) or 0)

    @property
    def entry_ea(self) -> int:
        return int(getattr(self._mba, "entry_ea", 0) or 0)

    @property
    def maturity(self) -> int:
        return int(getattr(self._mba, "maturity", -1) or -1)

    def get_mblock(self, serial: int) -> _BlockView | None:
        serial = int(serial)
        if serial in self._block_cache:
            return self._block_cache[serial]
        getter = getattr(self._mba, "get_mblock", None)
        if not callable(getter):
            return None
        blk = getter(serial)
        if blk is None:
            return None
        view = _BlockView(blk, self._opcode_names, self._mop_type_names)
        self._block_cache[serial] = view
        return view

    def __getattr__(self, name: str) -> object:
        return getattr(self._mba, name)


def extract_state_dispatcher_map_from_hexrays_mba(
    mba: object,
    *,
    dispatcher_entry_block: int | None = None,
    max_depth: int | None = None,
) -> StateDispatcherMap | None:
    """Adapt live Hex-Rays microcode before invoking the pure extractor."""

    view = _MbaView(
        mba,
        _hexrays_condition_chain_runtime.build_opcode_map(),
        _hexrays_condition_chain_runtime.build_mop_type_map(),
    )
    dispatch_map = extract_state_dispatcher_map_from_mba(
        view,
        dispatcher_entry_block=dispatcher_entry_block,
        max_depth=max_depth,
    )
    if dispatch_map is not None:
        _observe_state_dispatcher_map(mba, dispatch_map)
    return dispatch_map


__all__ = ["extract_state_dispatcher_map_from_hexrays_mba"]


def _observe_state_dispatcher_map(
    mba: object,
    dispatch_map: StateDispatcherMap,
) -> None:
    """Publish equality-chain rows for the diag DB when observability is on."""
    try:
        from d810.core.observability_preanalysis import observe_state_dispatcher_rows

        observe_state_dispatcher_rows(
            func_ea=int(getattr(mba, "entry_ea", 0) or 0),
            maturity=_maturity_name(int(getattr(mba, "maturity", -1) or -1)),
            dispatcher_entry_block=int(dispatch_map.dispatcher_entry_block),
            dispatcher_kind=dispatch_map.router_kind.name,
            rows=dispatch_map.rows,
        )
    except Exception:
        return


def _maturity_name(maturity: int) -> str:
    names = {
        0: "MMAT_GENERATED",
        1: "MMAT_PREOPTIMIZED",
        2: "MMAT_LOCOPT",
        3: "MMAT_CALLS",
        4: "MMAT_GLBOPT1",
        5: "MMAT_GLBOPT2",
        6: "MMAT_GLBOPT3",
        7: "MMAT_LVARS",
    }
    return names.get(int(maturity), f"MMAT_{int(maturity)}")


def _first_int(*values: object) -> int | None:
    for value in values:
        if callable(value):
            try:
                value = value()
            except Exception:
                value = None
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return None


def _call_lvar_idx(lvar: object | None) -> int | None:
    var = getattr(lvar, "var", None)
    if not callable(var):
        return None
    try:
        resolved = var()
    except Exception:
        return None
    return _first_int(
        getattr(resolved, "idx", None),
        getattr(resolved, "off", None),
    )

"""Live Hex-Rays adapter for equality-chain dispatcher extraction."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from d810.backends.hexrays import bst_runtime as _hexrays_bst_runtime
from d810.analyses.control_flow.dispatcher_resolution import StateDispatcherMap
from d810.analyses.control_flow.equality_chain_dispatcher import (
    extract_state_dispatcher_map_from_mba,
)


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

    def __getattr__(self, name: str) -> object:
        return getattr(self._mop, name)


@dataclass(frozen=True, slots=True)
class _InsnView:
    _insn: object
    _opcode_names: Mapping[int, str]
    _mop_type_names: Mapping[int, str]

    @property
    def opcode(self) -> object:
        raw_opcode = getattr(self._insn, "opcode", None)
        try:
            return self._opcode_names.get(int(raw_opcode), raw_opcode)
        except Exception:
            return raw_opcode

    @property
    def l(self) -> object | None:
        return self._adapt_mop(getattr(self._insn, "l", None))

    @property
    def r(self) -> object | None:
        return self._adapt_mop(getattr(self._insn, "r", None))

    @property
    def d(self) -> object | None:
        return self._adapt_mop(getattr(self._insn, "d", None))

    def _adapt_mop(self, mop: object | None) -> object | None:
        if mop is None:
            return None
        return _MopView(mop, self._mop_type_names)

    def __getattr__(self, name: str) -> object:
        return getattr(self._insn, name)


@dataclass(frozen=True, slots=True)
class _BlockView:
    _blk: object
    _opcode_names: Mapping[int, str]
    _mop_type_names: Mapping[int, str]
    _insns: tuple[_InsnView, ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_insns", tuple(self._iter_live_insns()))

    @property
    def serial(self) -> int:
        return int(getattr(self._blk, "serial", -1))

    @property
    def type(self) -> object:
        return getattr(self._blk, "type", None)

    @property
    def tail(self) -> _InsnView | None:
        tail = getattr(self._blk, "tail", None)
        if tail is None:
            return None
        return _InsnView(tail, self._opcode_names, self._mop_type_names)

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
    def insns(self) -> tuple[_InsnView, ...]:
        return self._insns

    def nsucc(self) -> int:
        return len(self.succs)

    def succ(self, index: int) -> int:
        return self.succs[int(index)]

    def _iter_live_insns(self):
        head = getattr(self._blk, "head", None)
        tail = getattr(self._blk, "tail", None)
        if head is None:
            return
        current = head
        seen: set[int] = set()
        while current is not None and id(current) not in seen:
            seen.add(id(current))
            yield _InsnView(current, self._opcode_names, self._mop_type_names)
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
        _hexrays_bst_runtime.build_opcode_map(),
        _hexrays_bst_runtime.build_mop_type_map(),
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
        from d810.recon.observability import observe_state_dispatcher_rows

        observe_state_dispatcher_rows(
            func_ea=int(getattr(mba, "entry_ea", 0) or 0),
            maturity=_maturity_name(int(getattr(mba, "maturity", -1) or -1)),
            dispatcher_entry_block=int(dispatch_map.dispatcher_entry_block),
            dispatcher_kind=dispatch_map.source.name,
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

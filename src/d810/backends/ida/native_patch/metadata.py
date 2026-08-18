"""Transactional execution of non-byte (metadata) patch actions.

Task 6 declared ``NativeMetadataAction`` as vocabulary and left execution
unimplemented: the gateway raised ``NativePatchMetadataActionUnsupported`` for
any operation carrying one. That blocked Task 7, because the writer it
migrates (``d810.hexrays.preanalysis.indirect_jump_labels``) writes *zero*
bytes -- measured -- and is made entirely of these actions:
``append_func_tail`` x4, ``create_insn`` x3, ``add_cref`` x2, ``del_items``,
``set_switch_info``.

This executor does **not** make every legacy action writable. It enables only
transitions with an exact current-build before/after oracle; typed data,
entry-tail resizing, detached-tail adoption, and planner-created switch
records fail closed until they have positive lossless round-trip evidence.

Why this is not simply "do the IDA call"
--------------------------------------------------------------------------

The function-extent P0 established the governing rule: **state that is not
derived from the bytes is not restored by restoring the bytes.** Function
extent, ``FUNC_NORET`` and the stored prototype each had to be undone
explicitly. Metadata actions are *entirely* made of such state, so every one
of them needs an explicit inverse or it is not reversible at all.

So execution here is a read-verify-apply-verify cycle, and the value that
makes reversal possible is the **observed** before-state, not the plan's
``expected_before``:

1. Read the actual state at ``ea`` for this kind.
2. Verify it matches the plan's ``expected_before`` -- a mismatch means the
   database is not the one the plan was authorized against, so abstain.
3. Apply, moving the state to ``expected_after``.
4. Verify the result actually reads back as ``expected_after``.

The caller journals the observed before-state; reversal is then the same
``apply`` call aimed back at that recorded value. Re-deriving a before-state
at restore time would read the already-mutated database -- exactly the bug
the extent P0 was.

``OTHER`` is deliberately not executable. It names an action with no defined
state representation, so steps 1, 2 and 4 above are all impossible and the
result could be neither verified nor reversed.
"""

from __future__ import annotations

import json

from d810.core.logging import getLogger
from d810.core.typing import Protocol, runtime_checkable
from d810.transforms.native_patch_plan import NativeMetadataActionKind

logger = getLogger("d810.backends.ida.native_patch.metadata")

__all__ = [
    "IdaMetadataActionExecutor",
    "MetadataActionExecutor",
    "MetadataStateMismatch",
    "UnexecutableMetadataAction",
    "reversible_data_item_head",
    "is_reversible_data_item_state",
]


class UnexecutableMetadataAction(RuntimeError):
    """The action kind has no defined, verifiable, reversible execution."""

    def __init__(self, kind: str):
        self.kind = kind
        super().__init__(
            f"metadata action kind {kind!r} has no reversible execution; "
            "it cannot be applied through the gateway"
        )


class MetadataStateMismatch(RuntimeError):
    """Observed state did not match what the plan was authorized against."""

    def __init__(self, kind: str, ea: int, expected: str, observed: str):
        self.kind = kind
        self.ea = ea
        self.expected = expected
        self.observed = observed
        super().__init__(
            f"{kind} at {ea:#x}: expected state {expected!r}, observed {observed!r}"
        )


@runtime_checkable
class MetadataActionExecutor(Protocol):
    """Read/apply seam for one metadata action kind at one address."""

    def read_state(self, kind: NativeMetadataActionKind, ea: int) -> str:
        """The current state token at ``ea`` for ``kind``.

        Must be the same vocabulary the plan's ``expected_before``/
        ``expected_after`` use, and must round-trip: applying a token then
        reading it back returns that token.
        """
        ...

    def apply_state(
        self, kind: NativeMetadataActionKind, ea: int, target_state: str
    ) -> bool:
        """Drive the state at ``ea`` to ``target_state``. Returns success.

        Used for both directions: applying aims at ``expected_after``,
        reversing aims at the journaled observed-before.
        """
        ...


_ITEM_CODE = "code"
_ITEM_DATA = "data"
_ITEM_DATA_SNAPSHOT_PREFIX = "data:v1:"
_ITEM_UNKNOWN = "unknown"
_SWITCH_NONE = "switch:none"
_SWITCH_PREFIX = "switch:"
_CREF_PREFIX = "cref3:"
_SWITCH_COMMON_FIELDS = frozenset(
    {
        "custom",
        "defjump",
        "elbase",
        "expr_ea",
        "flags",
        "ind_lowcase",
        "jcases",
        "jumps",
        "ncases",
        "regdtype",
        "regnum",
        "startea",
        "version",
    }
)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _parse_reversible_data_item_state(
    token: str, *, expected_ea: int | None = None
) -> dict[str, object] | None:
    """Decode the deliberately narrow, versioned scalar-data token.

    ``data:<size>`` is retained for arbitrary IDA data because it is not
    enough information to restore the item.  The versioned form is emitted
    only for a plain scalar item and carries every fact the inverse needs.
    Returning ``None`` for malformed/legacy tokens is intentional: callers
    must fail closed rather than guessing that a partial token is reversible.
    """

    if not isinstance(token, str) or not token.startswith(
        _ITEM_DATA_SNAPSHOT_PREFIX
    ):
        return None
    try:
        payload = json.loads(token.removeprefix(_ITEM_DATA_SNAPSHOT_PREFIX))
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if set(payload) != {
        "bytes",
        "ea",
        "flags",
        "full_flags",
        "head_ea",
        "name",
        "offset",
        "size",
    }:
        return None
    if not all(
        _is_int(payload.get(key))
        for key in ("ea", "flags", "head_ea", "offset", "size")
    ):
        return None
    size = int(payload["size"])
    head_ea = int(payload["head_ea"])
    offset = int(payload["offset"])
    if (
        size <= 0
        or int(payload["flags"]) < 0
        or head_ea < 0
        or offset < 0
        or offset >= size
        or int(payload["ea"]) != head_ea + offset
    ):
        return None
    if expected_ea is not None and int(payload["ea"]) != int(expected_ea):
        return None
    full_flags = payload["full_flags"]
    if not isinstance(full_flags, list) or len(full_flags) != size:
        return None
    if not all(_is_int(value) and int(value) >= 0 for value in full_flags):
        return None
    raw_hex = payload["bytes"]
    if not isinstance(raw_hex, str) or len(raw_hex) != size * 2:
        return None
    name = payload["name"]
    if not isinstance(name, str):
        return None
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError:
        return None
    if len(raw) != size:
        return None
    return {
        "bytes": raw,
        "ea": int(payload["ea"]),
        "flags": int(payload["flags"]),
        "full_flags": tuple(int(value) for value in full_flags),
        "head_ea": head_ea,
        "name": name,
        "offset": offset,
        "size": size,
    }


def is_reversible_data_item_state(
    token: str, *, expected_ea: int | None = None
) -> bool:
    """Return whether ``token`` is a complete supported data-item snapshot."""

    return (
        _parse_reversible_data_item_state(token, expected_ea=expected_ea)
        is not None
    )


def reversible_data_item_head(
    token: str, *, expected_ea: int | None = None
) -> int | None:
    """Return the enclosing head EA carried by a valid data snapshot."""

    payload = _parse_reversible_data_item_state(token, expected_ea=expected_ea)
    return None if payload is None else int(payload["head_ea"])


class IdaMetadataActionExecutor:
    """:class:`MetadataActionExecutor` over the live IDA database.

    Exercised only by the Docker system-test suite; the unit-test suite never
    constructs this class (per this repository's no-IDA-mocking rule).

    State tokens are deliberately textual (``"code:2"``,
    ``"tail:0x2000-0x2010"``, ``"cref3:0x1000@0x11@u"``) to match the
    provider-neutral vocabulary ``NativeMetadataAction`` already specifies.
    Xref tokens include the xref kind and its separate user-owned flag.  IDA
    reports that flag through ``xrefblk_t.user`` rather than in
    ``xrefblk_t.type``; a target-only token would restore a user edge as an
    auto edge (or change its flow kind), which is not a reversible action.
    """

    # -- state reading --------------------------------------------------

    def read_state(self, kind: NativeMetadataActionKind, ea: int) -> str:
        if kind is NativeMetadataActionKind.RECREATE_ITEM:
            return self._read_item_state(int(ea))
        if kind is NativeMetadataActionKind.UPDATE_XREF:
            return self._read_cref_state(int(ea))
        if kind is NativeMetadataActionKind.SET_SWITCH_INFO:
            return self._read_switch_state(int(ea))
        if kind is NativeMetadataActionKind.SET_FUNCTION_TAIL:
            return self._read_tail_state(int(ea))
        if kind is NativeMetadataActionKind.FUNCTION_TAIL_CHUNK:
            return self._read_chunk_state(int(ea))
        raise UnexecutableMetadataAction(getattr(kind, "value", str(kind)))

    def _read_item_state(self, ea: int) -> str:
        import ida_bytes

        flags = ida_bytes.get_flags(ea)
        if ida_bytes.is_code(flags):
            return f"{_ITEM_CODE}:{ida_bytes.get_item_size(ea)}"
        head_ea = int(ida_bytes.get_item_head(ea))
        head_flags = ida_bytes.get_flags(head_ea)
        if ida_bytes.is_data(head_flags):
            snapshot = self._read_reversible_data_snapshot(ea)
            if snapshot is not None:
                return snapshot
            return f"{_ITEM_DATA}:{int(ida_bytes.get_item_size(head_ea))}"
        # ``is_head(flags)`` is deliberately false for IDA's FF_UNK bytes;
        # ``get_item_head(ea) == ea`` is the matching head witness for an
        # undefined item. A tail byte resolves to its enclosing item head.
        if ida_bytes.is_unknown(flags) and int(ida_bytes.get_item_head(ea)) == ea:
            return _ITEM_UNKNOWN
        # A tail byte, an unexplored non-head byte, or any other flag state is
        # not an item that this executor can recreate losslessly.  Preserve a
        # stable diagnostic token so the planner fails closed rather than
        # treating it as an undefined item head.
        return f"unsupported-item-flags:{int(flags):#x}"

    @staticmethod
    def _read_reversible_data_snapshot(ea: int) -> str | None:
        """Capture only scalar data whose IDA representation we can restore.

        The target data item is a compiler-created scalar label (``FF_WORD``)
        over the first six bytes of an instruction.  Structs, strings,
        user-named/commented items, and other typed data remain represented by
        the old ``data:<size>`` token and therefore remain fail-closed.
        """

        import ida_bytes
        import ida_name

        head_ea = int(ida_bytes.get_item_head(ea))
        item_flags = int(ida_bytes.get_flags(head_ea))
        size = int(ida_bytes.get_item_size(head_ea))
        if head_ea < 0 or size <= 0:
            return None
        data_type_mask = int(getattr(ida_bytes, "DT_TYPE", 0xF0000000))
        data_type = item_flags & data_type_mask
        scalar_widths = {
            int(getattr(ida_bytes, "FF_BYTE", -1)) & data_type_mask: 1,
            int(getattr(ida_bytes, "FF_WORD", -1)) & data_type_mask: 2,
            int(getattr(ida_bytes, "FF_DWORD", -1)) & data_type_mask: 4,
            int(getattr(ida_bytes, "FF_QWORD", -1)) & data_type_mask: 8,
            int(getattr(ida_bytes, "FF_TBYTE", -1)) & data_type_mask: 10,
        }
        width = scalar_widths.get(data_type)
        if width is None or size % width:
            return None
        # A scalar width alone does not imply plain data. Operand metadata is
        # stored outside the flags needed by ``create_data`` (offset bases,
        # enum ids, structure paths, stack references, custom formats). Until
        # the snapshot vocabulary captures that opinfo, reject it rather than
        # recreating a visually similar but semantically weaker item.
        operand_metadata_predicates = (
            "is_off0",
            "is_off1",
            "is_enum0",
            "is_enum1",
            "is_stroff0",
            "is_stroff1",
            "is_stkvar0",
            "is_stkvar1",
            "is_custfmt0",
            "is_custfmt1",
        )
        if any(
            bool(getattr(ida_bytes, predicate)(item_flags))
            for predicate in operand_metadata_predicates
        ):
            return None
        full_flags = [
            int(ida_bytes.get_full_flags(head_ea + offset))
            for offset in range(size)
        ]
        head_flags = full_flags[0]
        if bool(ida_bytes.has_user_name(head_flags)):
            return None
        if bool(
            getattr(ida_bytes, "is_manual_insn", lambda _ea: False)(head_ea)
        ):
            return None
        get_cmt = getattr(ida_bytes, "get_cmt", None)
        if get_cmt is not None and any(
            get_cmt(head_ea, repeatable) is not None
            for repeatable in (False, True)
        ):
            return None
        raw = ida_bytes.get_bytes(head_ea, size)
        if raw is None or len(raw) != size:
            return None
        payload = {
            "bytes": bytes(raw).hex(),
            "ea": int(ea),
            "flags": item_flags,
            "full_flags": full_flags,
            "head_ea": head_ea,
            "name": str(ida_name.get_name(head_ea) or ""),
            "offset": int(ea) - head_ea,
            "size": int(size),
        }
        return _ITEM_DATA_SNAPSHOT_PREFIX + json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        )

    def _read_cref_state(self, ea: int) -> str:
        import ida_xref

        edges: list[tuple[int, int, bool]] = []
        xref = ida_xref.xrefblk_t()
        ok = xref.first_from(ea, ida_xref.XREF_ALL)
        while ok:
            if xref.iscode:
                edges.append((int(xref.to), int(xref.type), bool(xref.user)))
            ok = xref.next_from()
        return _CREF_PREFIX + ",".join(
            f"{target:#x}@{xref_type:#x}@{'u' if user_owned else 'a'}"
            for target, xref_type, user_owned in sorted(set(edges))
        )

    def _read_switch_state(self, ea: int) -> str:
        """Encode all persisted ``switch_info_t`` state at ``ea``.

        Switch metadata is not implied by the instruction bytes.  The token
        therefore holds every field IDA persists through ``set_switch_info``,
        including the sparse/non-sparse union member, rather than only the
        fields the current writer configures.  IDA does *not* recreate a
        non-empty marker vector through that API, so such a record is rejected
        before mutation rather than journaled as though it were reversible.
        The version is a read-only ABI witness: IDA supplies it when a record
        is installed, and apply rejects a token from an incompatible runtime
        instead of silently dropping it.
        """
        import ida_nalt

        switch = ida_nalt.switch_info_t()
        if not ida_nalt.get_switch_info(switch, ea):
            return _SWITCH_NONE
        if list(switch.marks):
            raise UnexecutableMetadataAction("switch_info with markers")
        state: dict[str, int | list[int]] = {
            "custom": int(switch.custom),
            "defjump": int(switch.defjump),
            "elbase": int(switch.elbase),
            "expr_ea": int(switch.expr_ea),
            "flags": int(switch.flags),
            "ind_lowcase": int(switch.ind_lowcase),
            "jcases": int(switch.jcases),
            "jumps": int(switch.jumps),
            "ncases": int(switch.ncases),
            "regdtype": int(switch.regdtype),
            "regnum": int(switch.regnum),
            "startea": int(switch.startea),
            "version": int(switch.get_version()),
        }
        if switch.is_sparse():
            state["values"] = int(switch.values)
        else:
            state["lowcase"] = int(switch.lowcase)
        return _SWITCH_PREFIX + json.dumps(state, sort_keys=True, separators=(",", ":"))

    def _read_tail_state(self, ea: int) -> str:
        import ida_funcs

        func = ida_funcs.get_func(ea)
        if func is None:
            return "none"
        return f"tail:{int(func.start_ea):#x}-{int(func.end_ea):#x}"

    def _read_chunk_state(self, ea: int) -> str:
        """Every chunk the owning function holds, entry chunk included.

        Enumerating all of them (not just tails) makes the token a complete
        description of the function's extent, so reversal can both add back a
        removed chunk and remove an added one from the same value.
        """
        import ida_funcs

        func = ida_funcs.get_func(ea)
        if func is None:
            return "chunks:"
        spans: list[tuple[int, int]] = []
        iterator = ida_funcs.func_tail_iterator_t(func)
        ok = iterator.main()
        while ok:
            chunk = iterator.chunk()
            spans.append((int(chunk.start_ea), int(chunk.end_ea)))
            ok = iterator.next()
        return "chunks:" + ";".join(f"{s:#x}-{e:#x}" for s, e in sorted(spans))

    # -- state application ----------------------------------------------

    def apply_state(
        self, kind: NativeMetadataActionKind, ea: int, target_state: str
    ) -> bool:
        ea = int(ea)
        # A no-op is safe for every supported token and is important for the
        # certificate reread path, which must not call an IDA mutator merely
        # to prove that the requested state already holds.
        if self.read_state(kind, ea) == target_state:
            return True
        if kind is NativeMetadataActionKind.RECREATE_ITEM:
            return self._apply_item_state(ea, target_state)
        if kind is NativeMetadataActionKind.UPDATE_XREF:
            return self._apply_cref_state(ea, target_state)
        if kind is NativeMetadataActionKind.SET_SWITCH_INFO:
            return self._apply_switch_state(ea, target_state)
        if kind is NativeMetadataActionKind.SET_FUNCTION_TAIL:
            return self._apply_tail_state(ea, target_state)
        if kind is NativeMetadataActionKind.FUNCTION_TAIL_CHUNK:
            return self._apply_chunk_state(ea, target_state)
        raise UnexecutableMetadataAction(getattr(kind, "value", str(kind)))

    def _apply_switch_state(self, ea: int, target_state: str) -> bool:
        import ida_nalt

        if target_state == _SWITCH_NONE:
            ida_nalt.del_switch_info(ea)
            return self._read_switch_state(ea) == _SWITCH_NONE
        if not target_state.startswith(_SWITCH_PREFIX):
            raise UnexecutableMetadataAction(f"switch state {target_state!r}")
        try:
            state = json.loads(target_state.removeprefix(_SWITCH_PREFIX))
        except json.JSONDecodeError as error:
            raise UnexecutableMetadataAction(
                f"switch state {target_state!r}"
            ) from error
        if not isinstance(state, dict):
            raise UnexecutableMetadataAction(f"switch state {target_state!r}")

        union_field = (
            "values" if int(state.get("flags", 0)) & ida_nalt.SWI_SPARSE else "lowcase"
        )
        if set(state) != _SWITCH_COMMON_FIELDS | {union_field}:
            raise UnexecutableMetadataAction(f"switch state {target_state!r}")
        switch = ida_nalt.switch_info_t()
        switch.clear()
        switch.flags = int(state["flags"])
        switch.ncases = int(state["ncases"])
        switch.jumps = int(state["jumps"])
        if union_field == "values":
            switch.values = int(state["values"])
        else:
            switch.lowcase = int(state["lowcase"])
        switch.defjump = int(state["defjump"])
        switch.startea = int(state["startea"])
        switch.jcases = int(state["jcases"])
        switch.ind_lowcase = int(state["ind_lowcase"])
        switch.elbase = int(state["elbase"])
        switch.regnum = int(state["regnum"])
        switch.regdtype = int(state["regdtype"])
        switch.custom = int(state["custom"])
        switch.expr_ea = int(state["expr_ea"])
        if int(switch.get_version()) != int(state["version"]):
            raise UnexecutableMetadataAction(f"switch state {target_state!r}")
        ida_nalt.set_switch_info(ea, switch)
        return self._read_switch_state(ea) == target_state

    def _apply_chunk_state(self, ea: int, target_state: str) -> bool:
        raise UnexecutableMetadataAction(
            "function-tail adoption has no positive live-IDB reversibility oracle"
        )

    def _apply_item_state(self, ea: int, target_state: str) -> bool:
        import ida_bytes
        import ida_ua

        target_data = _parse_reversible_data_item_state(
            target_state, expected_ea=ea
        )
        if target_state.startswith(_ITEM_DATA_SNAPSHOT_PREFIX):
            if target_data is None:
                raise UnexecutableMetadataAction(
                    f"malformed reversible data item state {target_state!r}"
                )
            return self._apply_data_snapshot(ea, target_state, target_data)

        kind_name, _, _size_text = target_state.partition(":")
        current = self._read_item_state(ea)
        if kind_name == _ITEM_UNKNOWN:
            # This inverse is only emitted for a recorded UNKNOWN -> CODE
            # transition.  Reject data rather than flattening its type,
            # array, struct, alignment, and opinfo into FF_BYTE.
            if not current.startswith(f"{_ITEM_CODE}:"):
                raise UnexecutableMetadataAction(
                    f"cannot losslessly undefine item state {current!r}"
                )
            ida_bytes.del_items(
                ea, ida_bytes.DELIT_SIMPLE, max(1, ida_bytes.get_item_size(ea))
            )
            return self._read_item_state(ea) == _ITEM_UNKNOWN
        if kind_name == _ITEM_CODE:
            try:
                code_size = int(_size_text, 10)
            except ValueError as error:
                raise UnexecutableMetadataAction(
                    f"malformed code item state {target_state!r}"
                ) from error
            if code_size <= 0:
                raise UnexecutableMetadataAction(
                    f"malformed code item state {target_state!r}"
                )
            current_data = _parse_reversible_data_item_state(
                current, expected_ea=ea
            )
            if current_data is not None:
                return self._apply_data_to_code(
                    ea, target_state, current, current_data
                )
            if current != _ITEM_UNKNOWN:
                raise UnexecutableMetadataAction(
                    f"cannot recreate code over item state {current!r}"
                )
            ida_ua.create_insn(ea)
        else:
            # No generic data token is reversible.  In particular,
            # ``data:<size>`` loses flags, element width, arrays, structs,
            # alignment, and opinfo, so it is intentionally unsupported.
            raise UnexecutableMetadataAction(f"item state {target_state!r}")
        return self._read_item_state(ea) == target_state

    def _apply_data_to_code(
        self,
        ea: int,
        target_state: str,
        before_state: str,
        before_data: dict[str, object],
    ) -> bool:
        import ida_bytes
        import ida_ua

        data_head = int(before_data["head_ea"])
        data_size = int(before_data["size"])
        try:
            ida_bytes.del_items(
                data_head, ida_bytes.DELIT_SIMPLE, max(1, data_size)
            )
            ida_ua.create_insn(ea)
            observed = self._read_item_state(ea)
            if observed != target_state:
                raise UnexecutableMetadataAction(
                    f"IDA decoded item at {ea:#x} as {observed!r}, "
                    f"not {target_state!r}"
                )
            return True
        except Exception as error:
            try:
                self._restore_data_snapshot(ea, before_state, before_data)
            except Exception as restore_error:
                raise UnexecutableMetadataAction(
                    f"item transition at {ea:#x} failed and rollback failed"
                ) from restore_error
            if isinstance(error, UnexecutableMetadataAction):
                raise
            raise UnexecutableMetadataAction(
                f"item transition at {ea:#x} failed"
            ) from error

    def _apply_data_snapshot(
        self,
        ea: int,
        target_state: str,
        target_data: dict[str, object],
    ) -> bool:
        import ida_bytes

        current = self._read_item_state(ea)
        current_code = current.partition(":")
        if current_code[0] != _ITEM_CODE:
            raise UnexecutableMetadataAction(
                f"cannot recreate data over item state {current!r}"
            )
        try:
            code_size = int(current_code[2], 10)
        except ValueError as error:
            raise UnexecutableMetadataAction(
                f"malformed current code item state {current!r}"
            ) from error
        raw = target_data["bytes"]
        target_size = int(target_data["size"])
        if not isinstance(raw, bytes) or len(raw) != target_size:
            raise UnexecutableMetadataAction(
                f"invalid reversible data bytes at {ea:#x}"
            )
        target_head = int(target_data["head_ea"])
        if ida_bytes.get_bytes(target_head, target_size) != raw:
            raise UnexecutableMetadataAction(
                f"data snapshot bytes no longer match at {ea:#x}"
            )
        try:
            ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, max(1, code_size))
            self._restore_data_snapshot(ea, target_state, target_data)
            return True
        except Exception as error:
            try:
                self._restore_code_item(ea, current, code_size)
            except Exception as restore_error:
                raise UnexecutableMetadataAction(
                    f"item transition at {ea:#x} failed and rollback failed"
                ) from restore_error
            if isinstance(error, UnexecutableMetadataAction):
                raise
            raise UnexecutableMetadataAction(
                f"item transition at {ea:#x} failed"
            ) from error

    def _restore_data_snapshot(
        self,
        ea: int, target_state: str, target_data: dict[str, object]
    ) -> None:
        import ida_bytes
        import idaapi
        import ida_name

        if int(target_data["ea"]) != int(ea):
            raise UnexecutableMetadataAction(
                f"data snapshot belongs to {int(target_data['ea']):#x}, not {ea:#x}"
            )
        data_head = int(target_data["head_ea"])
        if int(target_data["offset"]) != int(ea) - data_head:
            raise UnexecutableMetadataAction(
                f"data snapshot offset is inconsistent at {ea:#x}"
            )
        if not ida_bytes.create_data(
            data_head,
            int(target_data["flags"]),
            int(target_data["size"]),
            int(getattr(idaapi, "BADADDR", -1)),
        ):
            raise UnexecutableMetadataAction(
                f"IDA refused data recreation at {ea:#x}"
            )
        name = str(target_data["name"])
        if name and not ida_name.set_name(data_head, name, ida_name.SN_AUTO):
            raise UnexecutableMetadataAction(
                f"IDA refused data name recreation at {data_head:#x}"
            )
        if self._read_item_state(ea) != target_state:
            raise UnexecutableMetadataAction(
                f"data recreation at {ea:#x} did not reproduce the recorded state"
            )

    def _restore_code_item(self, ea: int, target_state: str, code_size: int) -> None:
        import ida_ua

        ida_ua.create_insn(ea)
        observed = self._read_item_state(ea)
        if observed != target_state or not observed.endswith(f":{code_size}"):
            raise UnexecutableMetadataAction(
                f"code recreation at {ea:#x} did not reproduce {target_state!r}"
            )

    def _apply_cref_state(self, ea: int, target_state: str) -> bool:
        import ida_xref

        if not target_state.startswith(_CREF_PREFIX):
            raise UnexecutableMetadataAction(f"xref state {target_state!r}")

        def _parse(token: str) -> set[tuple[int, int, bool]]:
            if not token.startswith(_CREF_PREFIX):
                raise UnexecutableMetadataAction(f"xref state {token!r}")
            rows = token.removeprefix(_CREF_PREFIX)
            result: set[tuple[int, int, bool]] = set()
            for row in rows.split(","):
                if not row.strip():
                    continue
                target_text, separator, remainder = row.partition("@")
                type_text, separator2, owner_text = remainder.partition("@")
                if not separator or not separator2 or owner_text not in {"a", "u"}:
                    raise UnexecutableMetadataAction(f"xref state {token!r}")
                result.add(
                    (int(target_text, 16), int(type_text, 16), owner_text == "u")
                )
            return result

        before_state = self._read_cref_state(ea)
        wanted = _parse(target_state)
        current = _parse(before_state)

        removed = current - wanted
        added = wanted - current
        if not removed and not added:
            return True
        # A single source can own several requested user edges.  They must be
        # one metadata action: IDA reanalysis may canonicalize an individual
        # edge between sequential actions, making the second expected-before
        # witness stale.  Mixed add/remove transitions still describe a
        # replacement rather than one batch and remain unsupported.
        if removed and added:
            raise UnexecutableMetadataAction(
                "xref transition cannot mix additions and removals"
            )
        changed = tuple(sorted(removed or added))
        if any(not user_owned for _target, _xref_type, user_owned in changed):
            raise UnexecutableMetadataAction("gateway only owns user xrefs")

        def _rollback() -> None:
            try:
                if added:
                    for target, _xref_type, _user_owned in changed:
                        ida_xref.del_cref(ea, target, False)
                else:
                    for target, xref_type, _user_owned in changed:
                        ida_xref.add_cref(
                            ea, target, xref_type | ida_xref.XREF_USER
                        )
            except Exception as rollback_error:
                raise UnexecutableMetadataAction(
                    f"xref batch at {ea:#x} failed and rollback failed"
                ) from rollback_error
            if self._read_cref_state(ea) != before_state:
                raise UnexecutableMetadataAction(
                    f"xref batch at {ea:#x} rollback did not restore its before-state"
                )

        try:
            if added:
                for target, xref_type, _user_owned in changed:
                    ida_xref.add_cref(ea, target, xref_type | ida_xref.XREF_USER)
            else:
                for target, _xref_type, _user_owned in changed:
                    ida_xref.del_cref(ea, target, False)
        except Exception as error:
            _rollback()
            raise UnexecutableMetadataAction(
                f"xref batch at {ea:#x} failed"
            ) from error

        if self._read_cref_state(ea) == target_state:
            return True
        _rollback()
        return False

    def _apply_tail_state(self, ea: int, target_state: str) -> bool:
        raise UnexecutableMetadataAction(
            "set_function_tail has no lossless inverse for function attributes"
        )

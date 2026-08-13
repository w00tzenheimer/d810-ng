"""Transactional execution of non-byte (metadata) patch actions.

Task 6 declared ``NativeMetadataAction`` as vocabulary and left execution
unimplemented: the gateway raised ``NativePatchMetadataActionUnsupported`` for
any operation carrying one. That blocked Task 7, because the writer it
migrates (``d810.hexrays.preanalysis.indirect_jump_labels``) writes *zero*
bytes -- measured -- and is made entirely of these actions:
``append_func_tail`` x4, ``create_insn`` x3, ``add_cref`` x2, ``del_items``,
``set_switch_info``.

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

from d810.core.logging import getLogger
from d810.core.typing import Protocol, runtime_checkable
from d810.transforms.native_patch_plan import NativeMetadataActionKind

logger = getLogger("d810.backends.ida.native_patch.metadata")

__all__ = [
    "IdaMetadataActionExecutor",
    "MetadataActionExecutor",
    "MetadataStateMismatch",
    "UnexecutableMetadataAction",
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
_ITEM_UNKNOWN = "unknown"


class IdaMetadataActionExecutor:
    """:class:`MetadataActionExecutor` over the live IDA database.

    Exercised only by the Docker system-test suite; the unit-test suite never
    constructs this class (per this repository's no-IDA-mocking rule).

    State tokens are deliberately coarse and textual (``"code:2"``,
    ``"tail:0x2000-0x2010"``, ``"cref:0x1000,0x1010"``) to match the
    provider-neutral vocabulary ``NativeMetadataAction`` already specifies.
    """

    # -- state reading --------------------------------------------------

    def read_state(self, kind: NativeMetadataActionKind, ea: int) -> str:
        if kind is NativeMetadataActionKind.RECREATE_ITEM:
            return self._read_item_state(int(ea))
        if kind is NativeMetadataActionKind.UPDATE_XREF:
            return self._read_cref_state(int(ea))
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
        if ida_bytes.is_data(flags):
            return f"{_ITEM_DATA}:{ida_bytes.get_item_size(ea)}"
        return _ITEM_UNKNOWN

    def _read_cref_state(self, ea: int) -> str:
        import ida_xref

        targets: list[int] = []
        xref = ida_xref.xrefblk_t()
        ok = xref.first_from(ea, ida_xref.XREF_ALL)
        while ok:
            if xref.iscode:
                targets.append(int(xref.to))
            ok = xref.next_from()
        return "cref:" + ",".join(f"{t:#x}" for t in sorted(targets))

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
        if kind is NativeMetadataActionKind.RECREATE_ITEM:
            return self._apply_item_state(ea, target_state)
        if kind is NativeMetadataActionKind.UPDATE_XREF:
            return self._apply_cref_state(ea, target_state)
        if kind is NativeMetadataActionKind.SET_FUNCTION_TAIL:
            return self._apply_tail_state(ea, target_state)
        if kind is NativeMetadataActionKind.FUNCTION_TAIL_CHUNK:
            return self._apply_chunk_state(ea, target_state)
        raise UnexecutableMetadataAction(getattr(kind, "value", str(kind)))

    def _apply_chunk_state(self, ea: int, target_state: str) -> bool:
        import ida_funcs

        func = ida_funcs.get_func(ea)
        if func is None:
            return target_state == "chunks:"

        def _parse(token: str) -> set[tuple[int, int]]:
            _, _, spans = token.partition(":")
            out: set[tuple[int, int]] = set()
            for span in spans.split(";"):
                if not span.strip():
                    continue
                start_text, _, end_text = span.partition("-")
                out.add((int(start_text, 16), int(end_text, 16)))
            return out

        wanted = _parse(target_state)
        current = _parse(self._read_chunk_state(ea))
        entry_ea = int(func.start_ea)

        # Never add or remove the entry chunk through this action -- that is
        # SET_FUNCTION_TAIL's job, and removing it would delete the function.
        for start_ea, end_ea in sorted(current - wanted):
            if start_ea == entry_ea:
                continue
            if not ida_funcs.remove_func_tail(func, start_ea):
                return False
        for start_ea, end_ea in sorted(wanted - current):
            if start_ea == entry_ea:
                continue
            if not ida_funcs.append_func_tail(func, start_ea, end_ea):
                return False

        return self._read_chunk_state(ea) == target_state

    def _apply_item_state(self, ea: int, target_state: str) -> bool:
        import ida_bytes
        import idaapi

        kind_name, _, size_text = target_state.partition(":")
        # Undefine first in every direction. create_insn is a no-op on a byte
        # that is already a defined data item, which is the same trap
        # indirect_jump_labels documents at its own del_items call.
        ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, max(1, int(size_text or 1)))
        if kind_name == _ITEM_UNKNOWN:
            return self._read_item_state(ea) == _ITEM_UNKNOWN
        if kind_name == _ITEM_CODE:
            idaapi.create_insn(ea)
        elif kind_name == _ITEM_DATA:
            ida_bytes.create_data(
                ea, ida_bytes.FF_BYTE, max(1, int(size_text or 1)), idaapi.BADADDR
            )
        else:
            raise UnexecutableMetadataAction(f"item state {target_state!r}")
        return self._read_item_state(ea) == target_state

    def _apply_cref_state(self, ea: int, target_state: str) -> bool:
        import ida_xref

        _, _, targets_text = target_state.partition(":")
        wanted = {
            int(token, 16) for token in targets_text.split(",") if token.strip()
        }
        current_text = self._read_cref_state(ea)
        _, _, current_targets = current_text.partition(":")
        current = {
            int(token, 16) for token in current_targets.split(",") if token.strip()
        }

        for target in sorted(current - wanted):
            ida_xref.del_cref(ea, target, False)
        for target in sorted(wanted - current):
            ida_xref.add_cref(ea, target, ida_xref.fl_JN)
        return self._read_cref_state(ea) == target_state

    def _apply_tail_state(self, ea: int, target_state: str) -> bool:
        import ida_funcs

        if target_state == "none":
            func = ida_funcs.get_func(ea)
            if func is None:
                return True
            return bool(ida_funcs.del_func(int(func.start_ea)))

        _, _, span = target_state.partition(":")
        start_text, _, end_text = span.partition("-")
        start_ea, end_ea = int(start_text, 16), int(end_text, 16)

        func = ida_funcs.get_func(ea)
        if func is None:
            if not ida_funcs.add_func(start_ea, end_ea):
                return False
        elif int(func.end_ea) != end_ea:
            if not ida_funcs.set_func_end(start_ea, end_ea):
                return False
        return self._read_tail_state(ea) == target_state

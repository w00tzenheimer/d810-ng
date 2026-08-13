"""``IdaMetadataActionExecutor`` against a real IDA database.

The orchestration around metadata actions is covered by fakes in
``tests/unit/backends/ida/native_patch/test_gateway.py``. Fakes cannot cover
the part that has actually been wrong twice in this work: what IDA really does
when you undefine an item, add a cref, or resize a function. Both of this
epic's wrong turns -- a ``del_items``+``create_insn`` "fix" that measured worse,
and an unbaselined item count that prompted it -- were mistakes about live IDA
behaviour, not about control flow.

The property under test is the one reversal depends on, and it is stronger
than "the call succeeded":

    read_state(k, ea) -> before
    apply_state(k, ea, target);  read_state(k, ea) == target
    apply_state(k, ea, before);  read_state(k, ea) == before

If that round trip does not hold on real IDA, every journaled reversal is
worthless no matter how correct the gateway's bookkeeping is.
"""

from __future__ import annotations

import pytest

pytestmark = [
    pytest.mark.requires_ida,
    pytest.mark.runtime,
]

ida_bytes = pytest.importorskip("ida_bytes")
ida_funcs = pytest.importorskip("ida_funcs")
idaapi = pytest.importorskip("idaapi")
idautils = pytest.importorskip("idautils")

from d810.backends.ida.native_patch.metadata import (  # noqa: E402
    IdaMetadataActionExecutor,
    UnexecutableMetadataAction,
)
from d810.transforms.native_patch_plan import NativeMetadataActionKind  # noqa: E402


def _first_function_with_min_size(min_size: int = 0x20) -> int:
    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        if func is not None and (func.end_ea - func.start_ea) >= min_size:
            return int(ea)
    pytest.fail("no function large enough in the fixture")


class TestIdaMetadataActionExecutor:
    binary_name = "libobfuscated.dll"

    def test_item_state_round_trips_through_code_and_back(self, copy_of_idb) -> None:
        """RECREATE_ITEM must return the item to exactly what it was.

        Undefining and re-decoding is the operation that measured *worse* than
        doing nothing when it was applied blindly across a whole function
        during the extent P0. Scoped to a single item with a verified
        before-state, it must be exact.
        """
        executor = IdaMetadataActionExecutor()
        func_ea = _first_function_with_min_size()
        kind = NativeMetadataActionKind.RECREATE_ITEM

        before = executor.read_state(kind, func_ea)
        assert before.startswith("code:"), (
            f"expected a code item at a function entry, got {before!r}"
        )

        assert executor.apply_state(kind, func_ea, before)
        assert executor.read_state(kind, func_ea) == before

    def test_item_state_survives_an_undefine_and_restore(self, copy_of_idb) -> None:
        executor = IdaMetadataActionExecutor()
        func_ea = _first_function_with_min_size()
        kind = NativeMetadataActionKind.RECREATE_ITEM

        before = executor.read_state(kind, func_ea)

        # Drive it to something genuinely different, then back.
        assert executor.apply_state(kind, func_ea, "unknown")
        assert executor.read_state(kind, func_ea) == "unknown"

        assert executor.apply_state(kind, func_ea, before), (
            "restoring the recorded before-state must succeed"
        )
        assert executor.read_state(kind, func_ea) == before

    def test_cref_state_round_trips(self, copy_of_idb) -> None:
        executor = IdaMetadataActionExecutor()
        func_ea = _first_function_with_min_size()
        kind = NativeMetadataActionKind.UPDATE_XREF

        before = executor.read_state(kind, func_ea)
        target = int(ida_funcs.get_func(func_ea).end_ea) - 1
        added = f"{before},{target:#x}" if before != "cref:" else f"cref:{target:#x}"
        # Token order is sorted; rebuild it the way read_state would.
        wanted = {int(t, 16) for t in added.partition(":")[2].split(",") if t.strip()}
        added = "cref:" + ",".join(f"{t:#x}" for t in sorted(wanted))

        assert executor.apply_state(kind, func_ea, added)
        assert executor.read_state(kind, func_ea) == added

        assert executor.apply_state(kind, func_ea, before)
        assert executor.read_state(kind, func_ea) == before

    def test_function_tail_state_round_trips(self, copy_of_idb) -> None:
        """SET_FUNCTION_TAIL is the action the extent P0 was made of."""
        executor = IdaMetadataActionExecutor()
        func_ea = _first_function_with_min_size(0x30)
        kind = NativeMetadataActionKind.SET_FUNCTION_TAIL

        before = executor.read_state(kind, func_ea)
        assert before.startswith("tail:")

        start_ea = int(ida_funcs.get_func(func_ea).start_ea)
        end_ea = int(ida_funcs.get_func(func_ea).end_ea)
        shrunk = f"tail:{start_ea:#x}-{end_ea - 0x10:#x}"

        # Asserted, not tolerated. An earlier draft accepted "IDA refused the
        # shrink" as a passing outcome, which made both branches green and the
        # test worthless -- the same silent-skip failure mode that hid a
        # capstone oracle from CI earlier in this work. Measured on this
        # fixture: the shrink applies (0x1800010cb -> 0x1800010bb) and the
        # restore is exact, so anything less is a real regression.
        assert executor.apply_state(kind, func_ea, shrunk), (
            "IDA refused a function shrink this fixture is known to accept"
        )
        assert executor.read_state(kind, func_ea) == shrunk

        assert executor.apply_state(kind, func_ea, before), (
            "a shrunken function must be restorable to its recorded extent"
        )
        assert executor.read_state(kind, func_ea) == before

    def test_other_kind_is_rejected_rather_than_guessed_at(self, copy_of_idb) -> None:
        executor = IdaMetadataActionExecutor()
        func_ea = _first_function_with_min_size()

        with pytest.raises(UnexecutableMetadataAction):
            executor.read_state(NativeMetadataActionKind.OTHER, func_ea)
        with pytest.raises(UnexecutableMetadataAction):
            executor.apply_state(NativeMetadataActionKind.OTHER, func_ea, "anything")

    def test_read_state_is_stable_across_repeated_reads(self, copy_of_idb) -> None:
        """A token that changes without an apply would make every
        expected_before comparison a coin flip."""
        executor = IdaMetadataActionExecutor()
        func_ea = _first_function_with_min_size()

        for kind in (
            NativeMetadataActionKind.RECREATE_ITEM,
            NativeMetadataActionKind.UPDATE_XREF,
            NativeMetadataActionKind.SET_FUNCTION_TAIL,
        ):
            first = executor.read_state(kind, func_ea)
            assert executor.read_state(kind, func_ea) == first, (
                f"{kind.value} state token is not stable across reads"
            )

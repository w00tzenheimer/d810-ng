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

import json

import pytest

pytestmark = [
    pytest.mark.requires_ida,
    pytest.mark.runtime,
]

ida_bytes = pytest.importorskip("ida_bytes")
ida_funcs = pytest.importorskip("ida_funcs")
ida_xref = pytest.importorskip("ida_xref")
ida_nalt = pytest.importorskip("ida_nalt")
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


def _first_function_without_switch_info() -> int:
    for ea in idautils.Functions():
        switch = ida_nalt.switch_info_t()
        if not ida_nalt.get_switch_info(switch, ea):
            return int(ea)
    pytest.fail("no function without existing switch metadata in the fixture")


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
        assert before.startswith("cref3:")
        target = int(ida_funcs.get_func(func_ea).end_ea) - 1
        # Preserve the whole xref type word: in particular, the user-owned
        # bit must survive the gateway's eventual restore.
        rows = {
            tuple(item.split("@", 2))
            for item in before.removeprefix("cref3:").split(",")
            if item
        }
        rows.add((f"{target:#x}", f"{ida_xref.fl_JN:#x}", "u"))
        added = "cref3:" + ",".join(
            f"{target_text}@{xref_type}@{owner}"
            for target_text, xref_type, owner in sorted(
                rows,
                key=lambda row: (int(row[0], 16), int(row[1], 16), row[2]),
            )
        )

        assert executor.apply_state(kind, func_ea, added), executor.read_state(
            kind, func_ea
        )
        assert executor.read_state(kind, func_ea) == added

        assert executor.apply_state(kind, func_ea, before)
        assert executor.read_state(kind, func_ea) == before

    def test_function_tail_is_refused_without_a_lossless_snapshot(
        self, copy_of_idb
    ) -> None:
        """Changing the entry extent has attributes this action cannot restore."""
        executor = IdaMetadataActionExecutor()
        func_ea = _first_function_with_min_size(0x30)
        kind = NativeMetadataActionKind.SET_FUNCTION_TAIL

        before = executor.read_state(kind, func_ea)
        assert before.startswith("tail:")

        start_ea = int(ida_funcs.get_func(func_ea).start_ea)
        end_ea = int(ida_funcs.get_func(func_ea).end_ea)
        shrunk = f"tail:{start_ea:#x}-{end_ea - 0x10:#x}"

        with pytest.raises(UnexecutableMetadataAction):
            executor.apply_state(kind, func_ea, shrunk)
        assert executor.read_state(kind, func_ea) == before

    def test_typed_data_recreation_is_refused_without_flattening_it(
        self, copy_of_idb
    ) -> None:
        """``data:<size>`` is not a lossless representation of IDA data."""
        executor = IdaMetadataActionExecutor()
        func_ea = _first_function_with_min_size()

        before = executor.read_state(NativeMetadataActionKind.RECREATE_ITEM, func_ea)
        assert before.startswith("code:")
        with pytest.raises(UnexecutableMetadataAction):
            executor.apply_state(
                NativeMetadataActionKind.RECREATE_ITEM, func_ea, "data:1"
            )
        assert (
            executor.read_state(NativeMetadataActionKind.RECREATE_ITEM, func_ea)
            == before
        )

    def test_switch_info_state_round_trips_through_absence_and_back(
        self, copy_of_idb
    ) -> None:
        """SET_SWITCH_INFO must restore the complete persisted record.

        The Task 7 writer optionally installs a ``switch_info_t``. Unlike a
        byte patch, deleting that metadata cannot be reversed from bytes, so
        the executor must preserve every persisted field and the no-info
        state, not just the handful of fields the writer happens to set.
        """
        executor = IdaMetadataActionExecutor()
        kind = NativeMetadataActionKind.SET_SWITCH_INFO
        func_ea = _first_function_without_switch_info()

        assert executor.read_state(kind, func_ea) == "switch:none"

        configured = ida_nalt.switch_info_t()
        configured.clear()
        configured.flags = ida_nalt.SWI_USER | ida_nalt.SWI_ELBASE
        configured.jumps = func_ea + 0x10
        configured.ncases = 3
        configured.defjump = idaapi.BADADDR
        configured.startea = func_ea
        configured.expr_ea = func_ea
        configured.lowcase = 7
        configured.set_elbase(0)
        configured.set_jtable_element_size(8)
        configured.set_jtable_size(3)
        ida_nalt.set_switch_info(func_ea, configured)

        recorded = executor.read_state(kind, func_ea)
        assert recorded.startswith("switch:")
        state = json.loads(recorded.removeprefix("switch:"))
        assert state["jumps"] == func_ea + 0x10
        assert state["ncases"] == 3
        assert state["defjump"] == idaapi.BADADDR
        assert state["startea"] == func_ea
        # IDA canonicalizes this record's expression location to BADADDR on
        # storage.  Reversal must preserve the persisted state, not the
        # transient value we gave ``switch_info_t`` before installation.
        assert state["expr_ea"] == idaapi.BADADDR
        assert state["lowcase"] == 7
        assert state["elbase"] == 0

        assert executor.apply_state(kind, func_ea, "switch:none")
        assert executor.read_state(kind, func_ea) == "switch:none"

        assert executor.apply_state(kind, func_ea, recorded)
        assert executor.read_state(kind, func_ea) == recorded

    def test_sparse_switch_info_state_restores_values(self, copy_of_idb) -> None:
        """The sparse union is part of the persisted record too.

        Omitting it would make an initially valid switch look restored while
        changing its case lookup.
        """
        executor = IdaMetadataActionExecutor()
        kind = NativeMetadataActionKind.SET_SWITCH_INFO
        func_ea = _first_function_without_switch_info()

        configured = ida_nalt.switch_info_t()
        configured.clear()
        configured.flags = ida_nalt.SWI_USER | ida_nalt.SWI_ELBASE | ida_nalt.SWI_SPARSE
        configured.jumps = func_ea + 0x10
        configured.values = func_ea + 0x20
        configured.ncases = 3
        configured.defjump = idaapi.BADADDR
        configured.startea = func_ea
        configured.set_elbase(0)
        configured.set_jtable_element_size(8)
        configured.set_jtable_size(3)
        ida_nalt.set_switch_info(func_ea, configured)

        recorded = executor.read_state(kind, func_ea)
        state = json.loads(recorded.removeprefix("switch:"))
        assert state["values"] == func_ea + 0x20
        assert "lowcase" not in state
        assert executor.apply_state(kind, func_ea, "switch:none")
        assert executor.apply_state(kind, func_ea, recorded)
        assert executor.read_state(kind, func_ea) == recorded

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

    def test_tail_chunk_state_reads_the_whole_extent(self, copy_of_idb) -> None:
        """FUNCTION_TAIL_CHUNK is the action Task 7's writer actually uses.

        ``indirect_jump_labels`` calls ``append_func_tail`` -- a discontiguous
        chunk elsewhere in the image -- not ``set_func_end``. Conflating the
        two would turn "attach a label body over there" into "grow the entry
        chunk over everything in between", so they are separate kinds.
        """
        executor = IdaMetadataActionExecutor()
        kind = NativeMetadataActionKind.FUNCTION_TAIL_CHUNK
        func_ea = _first_function_with_min_size()

        state = executor.read_state(kind, func_ea)

        assert state.startswith("chunks:")
        func = ida_funcs.get_func(func_ea)
        assert f"{int(func.start_ea):#x}-{int(func.end_ea):#x}" in state, (
            "the entry chunk must appear in the extent token"
        )

    def test_a_refused_chunk_append_changes_nothing(self, copy_of_idb) -> None:
        """The property that matters when IDA says no.

        A partial apply that reports failure is exactly what leaves an
        unreversible database: the journal would hold a before-state for an
        action that half-happened. Measured on this fixture, IDA refuses to
        adopt a non-code span (``is_code`` is False at 0x1800011b3), so this
        drives that refusal deliberately and asserts nothing moved.

        A *successful* append round-trip is deliberately not asserted here:
        no function in this fixture has more than one chunk, and there is no
        free code span to adopt, so any positive case would have to fabricate
        a scenario IDA does not actually present. That gap is real and is
        recorded rather than papered over with a synthetic fixture.
        """
        executor = IdaMetadataActionExecutor()
        kind = NativeMetadataActionKind.FUNCTION_TAIL_CHUNK
        func_ea = _first_function_with_min_size()

        before = executor.read_state(kind, func_ea)
        non_code_ea = 0x1800011B3
        assert not ida_bytes.is_code(ida_bytes.get_flags(non_code_ea)), (
            "fixture changed: this probe needs a non-code span to be refused"
        )
        attempted = before + f";{non_code_ea:#x}-{non_code_ea + 8:#x}"

        with pytest.raises(UnexecutableMetadataAction):
            executor.apply_state(kind, func_ea, attempted)
        assert executor.read_state(kind, func_ea) == before, (
            "a refused append must leave the function extent untouched"
        )

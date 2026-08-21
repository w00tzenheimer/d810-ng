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
    _parse_reversible_data_item_state,
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


def _first_instruction_tail() -> int:
    """Find a real non-head byte inside a multi-byte instruction."""
    for function_ea in idautils.Functions():
        function = ida_funcs.get_func(function_ea)
        if function is None:
            continue
        ea = int(function.start_ea)
        while ea < int(function.end_ea):
            size = int(ida_bytes.get_item_size(ea))
            if size > 1:
                return ea + 1
            next_ea = int(ida_bytes.next_head(ea, int(function.end_ea)))
            if next_ea <= ea:
                break
            ea = next_ea
    pytest.fail("no multi-byte instruction tail in the fixture")


class TestIdaMetadataActionExecutor:
    binary_name = "libobfuscated.dll"

    def _reversible_scalar_data_heads(
        self, executor: IdaMetadataActionExecutor, *, minimum_size: int = 1
    ) -> list[int]:
        """Find plain scalar items accepted by the current live fixture."""

        kind = NativeMetadataActionKind.RECREATE_ITEM
        result: list[int] = []
        for candidate in idautils.Heads():
            data_head = int(candidate)
            flags = ida_bytes.get_flags(data_head)
            if not ida_bytes.is_data(flags):
                continue
            if int(ida_bytes.get_item_head(data_head)) != data_head:
                continue
            if int(ida_bytes.get_item_size(data_head)) < minimum_size:
                continue
            state = executor.read_state(kind, data_head)
            if state.startswith("data:v1:") and not self._has_xrefs_in_item(
                data_head
            ):
                result.append(data_head)
        return result

    def _canonical_scalar_data_head(self, executor: IdaMetadataActionExecutor) -> int:
        """Return one plain scalar item accepted by the current fixture."""

        candidates = self._reversible_scalar_data_heads(executor)
        if candidates:
            return candidates[0]
        pytest.fail("current fixture has no xref-free reversible scalar item")

    def _decodable_scalar_target_pair(
        self, executor: IdaMetadataActionExecutor
    ) -> tuple[int, tuple[tuple[int, int], tuple[int, int]]]:
        """Find two non-overlapping instruction-shaped labels in one item."""

        import ida_ua

        for data_head in self._reversible_scalar_data_heads(executor, minimum_size=100):
            data_end = data_head + int(ida_bytes.get_item_size(data_head))
            decoded: list[tuple[int, int]] = []
            for target_ea in range(data_head, data_end):
                instruction = ida_ua.insn_t()
                code_size = int(ida_ua.decode_insn(instruction, target_ea))
                if code_size <= 1 or target_ea + code_size > data_end:
                    continue
                if any(
                    target_ea < previous_ea + previous_size
                    and previous_ea < target_ea + code_size
                    for previous_ea, previous_size in decoded
                ):
                    continue
                decoded.append((target_ea, code_size))
                if len(decoded) == 2:
                    return data_head, (decoded[0], decoded[1])
        pytest.fail("current fixture has no scalar item with two decodable labels")

    @staticmethod
    def _has_xrefs_in_item(ea: int) -> bool:
        head = int(ida_bytes.get_item_head(ea))
        size = int(ida_bytes.get_item_size(head))
        for item_ea in range(head, head + size):
            incoming = ida_xref.xrefblk_t()
            if incoming.first_to(item_ea, ida_xref.XREF_ALL):
                return True
            outgoing = ida_xref.xrefblk_t()
            if outgoing.first_from(item_ea, ida_xref.XREF_ALL):
                return True
        return False

    @staticmethod
    def _xref_witness(
        ea: int, size: int
    ) -> tuple[tuple[int, int, int, bool, bool], ...]:
        edges: set[tuple[int, int, int, bool, bool]] = set()
        for item_ea in range(int(ea), int(ea) + int(size)):
            incoming = ida_xref.xrefblk_t()
            ok = incoming.first_to(item_ea, ida_xref.XREF_ALL)
            while ok:
                edges.add(
                    (
                        int(incoming.frm),
                        int(incoming.to),
                        int(incoming.type),
                        bool(incoming.user),
                        bool(incoming.iscode),
                    )
                )
                ok = incoming.next_to()
            outgoing = ida_xref.xrefblk_t()
            ok = outgoing.first_from(item_ea, ida_xref.XREF_ALL)
            while ok:
                edges.add(
                    (
                        int(outgoing.frm),
                        int(outgoing.to),
                        int(outgoing.type),
                        bool(outgoing.user),
                        bool(outgoing.iscode),
                    )
                )
                ok = outgoing.next_from()
        return tuple(sorted(edges))

    @pytest.mark.parametrize("direction", ("incoming", "outgoing"))
    def test_scalar_data_with_xrefs_is_captured_and_reverts_to_v1(
        self, copy_of_idb, direction: str
    ) -> None:
        """A temporary edge is represented by v2 and disappears afterward."""

        executor = IdaMetadataActionExecutor()
        kind = NativeMetadataActionKind.RECREATE_ITEM
        data_head = self._canonical_scalar_data_head(executor)
        before = executor.read_state(kind, data_head)
        data_size = int(ida_bytes.get_item_size(data_head))
        assert not self._has_xrefs_in_item(data_head)

        source_ea = _first_function_with_min_size()
        if direction == "incoming":
            xref_source, xref_target = source_ea, data_head
        else:
            xref_source, xref_target = data_head, source_ea
        assert ida_xref.add_dref(xref_source, xref_target, ida_xref.dr_R)
        try:
            assert self._has_xrefs_in_item(data_head)
            observed = executor.read_state(kind, data_head)
            assert observed.startswith("data:v2:"), (
                f"xref-bearing scalar item was not captured as v2: {observed!r}; "
                f"item size={data_size} direction={direction}"
            )
            witness = json.loads(observed.removeprefix("data:v2:"))["xrefs"]
            assert witness
        finally:
            ida_xref.del_dref(xref_source, xref_target)

        # Removing the temporary edge must restore the canonical fixture's
        # original positive admission result.
        assert executor.read_state(kind, data_head) == before

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

    def test_item_tail_is_not_authorized_as_unknown(self, copy_of_idb) -> None:
        """Only an explicit unknown item head may become a code item."""
        executor = IdaMetadataActionExecutor()
        tail_ea = _first_instruction_tail()
        flags = ida_bytes.get_flags(tail_ea)

        assert ida_bytes.is_tail(flags)
        assert (
            executor.read_state(NativeMetadataActionKind.RECREATE_ITEM, tail_ea)
            != "unknown"
        )

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

    def test_multiple_user_crefs_from_one_source_round_trip_atomically(
        self, copy_of_idb
    ) -> None:
        """One source action must carry all additions through IDA together."""

        executor = IdaMetadataActionExecutor()
        kind = NativeMetadataActionKind.UPDATE_XREF
        for candidate_ea in idautils.Functions():
            func = ida_funcs.get_func(candidate_ea)
            if func is None:
                continue
            source_ea = int(func.start_ea)
            before = executor.read_state(kind, source_ea)
            existing_targets = {
                int(row.split("@", 1)[0], 16)
                for row in before.removeprefix("cref3:").split(",")
                if row
            }
            targets = [
                int(item_ea)
                for item_ea in idautils.FuncItems(source_ea)
                if int(item_ea) != source_ea
                and int(item_ea) not in existing_targets
            ]
            if len(targets) < 2:
                continue
            target_a, target_b = targets[:2]
            rows = {
                tuple(item.split("@", 2))
                for item in before.removeprefix("cref3:").split(",")
                if item
            }
            rows.update(
                {
                    (f"{target_a:#x}", f"{ida_xref.fl_JN:#x}", "u"),
                    (f"{target_b:#x}", f"{ida_xref.fl_JN:#x}", "u"),
                }
            )
            after = "cref3:" + ",".join(
                f"{target}@{xref_type}@{owner}"
                for target, xref_type, owner in sorted(
                    rows,
                    key=lambda row: (int(row[0], 16), int(row[1], 16), row[2]),
                )
            )
            assert executor.apply_state(kind, source_ea, after), executor.read_state(
                kind, source_ea
            )
            assert executor.read_state(kind, source_ea) == after
            assert executor.apply_state(kind, source_ea, before)
            assert executor.read_state(kind, source_ea) == before
            return
        pytest.fail("no function had two unused code targets for a cref batch")

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

    def test_tigress_label_data_with_xrefs_round_trips_through_code_and_back(
        self, copy_of_idb
    ) -> None:
        """The exact canonical Tigress item must preserve its xref witness."""
        import ida_ua

        executor = IdaMetadataActionExecutor()
        kind = NativeMetadataActionKind.RECREATE_ITEM
        target_ea = 0x1800173A5
        data_head = int(ida_bytes.get_item_head(target_ea))
        data_size = int(ida_bytes.get_item_size(data_head))
        assert f"data:{data_size}" == "data:1400"
        assert self._has_xrefs_in_item(data_head)
        before = executor.read_state(kind, target_ea)
        assert before is not None and before.startswith("data:v2:")
        payload = json.loads(before.removeprefix("data:v2:"))
        expected_witness = tuple(
            tuple(
                row[key]
                for key in (
                    "source_ea",
                    "target_ea",
                    "xref_type",
                    "user_owned",
                    "is_code",
                )
            )
            for row in payload["xrefs"]
        )
        assert expected_witness
        assert expected_witness == self._xref_witness(data_head, data_size)

        instruction = ida_ua.insn_t()
        code_size = int(ida_ua.decode_insn(instruction, target_ea))
        assert code_size == 4
        promoted = "code:4"

        assert executor.apply_state(kind, target_ea, promoted)
        assert executor.read_state(kind, target_ea) == promoted
        assert expected_witness == self._xref_witness(data_head, data_size)
        assert executor.apply_state(kind, target_ea, before)
        assert executor.read_state(kind, target_ea) == before

    def test_tigress_v2_xref_drift_is_rejected_without_item_mutation(
        self, copy_of_idb
    ) -> None:
        """A changed witness cannot authorize a data-to-code transition."""

        executor = IdaMetadataActionExecutor()
        kind = NativeMetadataActionKind.RECREATE_ITEM
        target_ea = 0x1800173A5
        data_head = int(ida_bytes.get_item_head(target_ea))
        original = executor.read_state(kind, target_ea)
        assert original is not None and original.startswith("data:v2:")
        original_data = _parse_reversible_data_item_state(
            original, expected_ea=target_ea
        )
        assert original_data is not None

        source_ea = _first_function_with_min_size()
        data_size = int(ida_bytes.get_item_size(data_head))
        existing = self._xref_witness(data_head, data_size)
        xref_target = next(
            candidate
            for candidate in range(data_head, data_head + data_size)
            if (source_ea, candidate, int(ida_xref.dr_R), False, False)
            not in existing
        )
        assert ida_xref.add_dref(source_ea, xref_target, ida_xref.dr_R)
        try:
            drifted = executor.read_state(kind, target_ea)
            assert drifted is not None and drifted != original
            with pytest.raises(UnexecutableMetadataAction):
                executor._apply_data_to_code(
                    target_ea, "code:4", original, original_data
                )
            assert executor.read_state(kind, target_ea) == drifted
        finally:
            ida_xref.del_dref(source_ea, xref_target)
        assert executor.read_state(kind, target_ea) == original

    def test_shared_tigress_data_item_targets_restore_as_one_item(
        self, copy_of_idb
    ) -> None:
        """Several labels in one scalar item reverse only after the last code."""
        executor = IdaMetadataActionExecutor()
        kind = NativeMetadataActionKind.RECREATE_ITEM
        data_head, (first, second) = self._decodable_scalar_target_pair(executor)
        before_first = executor.read_state(kind, first[0])
        before_second = executor.read_state(kind, second[0])
        assert before_first.startswith("data:v1:")
        assert before_second.startswith("data:v1:")

        assert executor.apply_state(kind, first[0], f"code:{first[1]}")
        assert executor.read_state(kind, second[0]) == "unknown"
        assert executor.apply_state(kind, second[0], f"code:{second[1]}")

        assert executor.apply_state(kind, second[0], "unknown")
        assert executor.apply_state(kind, first[0], before_first)
        assert executor.read_state(kind, first[0]) == before_first
        assert executor.read_state(kind, second[0]) == before_second

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

from __future__ import annotations

import copy
import os
import platform
from types import SimpleNamespace

import pytest

import ida_bytes
import ida_hexrays
import ida_nalt
import ida_name
import ida_typeinf
import ida_xref
import idaapi

from d810.backends.hexrays.global_const_annotation import (
    GlobalConstAnnotationStatus,
    acknowledge_global_const_proposals,
    annotate_function_global_consts,
    annotate_global_table_access,
    discover_dynamic_global_table_access,
    pending_global_const_proposals,
    referenced_global_items,
)
from d810.backends.ida.type_serialization import capture_serialized_tinfo
from d810.capabilities.idb_preparation import PreparationTransactionId
from d810.core.persistence import Netnode
from d810.manager.post_d810_runtime import HexRaysPostD810Runtime


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


def _function_ea(name: str) -> int:
    return int(ida_name.get_name_ea(idaapi.BADADDR, name))


def _enable_global_const_persistence(state) -> None:
    project_index = next(
        index
        for index, project in enumerate(state.project_manager.projects())
        if project.path.name == "default_instruction_only_config_v2_canary.json"
    )
    state.load_project(project_index)
    runtime_project = state.current_runtime_project
    source_project = state.current_project
    assert runtime_project is not None
    assert source_project is not None
    additional = copy.deepcopy(runtime_project.additional_configuration)
    constant_pass = next(
        entry
        for entry in additional["pipeline_v2"]
        if entry["pass_id"] == "constant-simplification"
    )
    # Preparation is a separate lifecycle lane.  Keep readonly folding off in
    # this fixture so the runtime proof exercises the observation/preparation
    # subscriber rather than a peephole-rule side effect.
    constant_pass["options"] = {
        "preparation": {
            "global_const_types": {
                "enabled": True,
                "discover_bounded_tables": True,
            }
        },
        "stages": {
            "fold-readonly-data": {"enabled": False},
        },
    }
    runtime_project.additional_configuration = additional
    state._activate_runtime_project(
        project_index=project_index,
        source_project=source_project,
        runtime_project=runtime_project,
        default_selection=state.last_config_v2_default_selection,
    )


def _lookup_table_access():
    function_ea = _function_ea("global_const_simple_lookup")
    if function_ea == idaapi.BADADDR:
        pytest.skip("global_const_simple_lookup not found")
    function = idaapi.get_func(function_ea)
    if function is None:
        pytest.skip("global_const_simple_lookup function object unavailable")

    for maturity in (ida_hexrays.MMAT_CALLS, ida_hexrays.MMAT_GLBOPT1):
        ranges = ida_hexrays.mba_ranges_t(function)
        failure = ida_hexrays.hexrays_failure_t()
        mba = ida_hexrays.gen_microcode(
            ranges,
            failure,
            None,
            ida_hexrays.DECOMP_NO_WAIT,
            maturity,
        )
        if mba is None:
            continue
        for serial in range(mba.qty):
            block = mba.get_mblock(serial)
            instruction = block.head
            while instruction is not None:
                access = discover_dynamic_global_table_access(instruction)
                if access is not None:
                    return access
                instruction = instruction.next
    pytest.fail("no bounded dynamic global-table access found")


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestGlobalConstAnnotation:
    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_post_capture_passes_manager_generation_explicitly(self) -> None:
        calls: list[tuple[object, object, int]] = []
        observer = SimpleNamespace(
            observe=lambda mba, maturity, *, generation: calls.append(
                (mba, maturity, generation)
            )
        )
        mba = SimpleNamespace(entry_ea=0x401000, qty=0)
        runtime = HexRaysPostD810Runtime(
            preanalysis_runtime=None,
            block_optimizer=SimpleNamespace(cfg_rules=()),
            global_const_observer=observer,
            mba_generation_provider=lambda function_ea: function_ea + 9,
        )

        runtime.observe_global_const_types(mba, 17)

        assert calls == [(mba, 17, 0x401009)]

    @pytest.mark.ida_required
    def test_runtime_index_still_discovers_complete_lookup_table(
        self, libobfuscated_setup
    ) -> None:
        access = _lookup_table_access()

        assert access.item_end == access.item_head + 0x20
        assert access.element_size == 4
        assert access.element_count == 8
        assert tuple(
            int(ida_bytes.get_dword(access.item_head + index * 4))
            for index in range(access.element_count)
        ) == (
            0x12345678,
            0x9ABCDEF0,
            0x13579BDF,
            0x2468ACE0,
            0xDEADBEEF,
            0xCAFEBABE,
            0xFEEDFACE,
            0x8BADF00D,
        )

    @pytest.mark.ida_required
    def test_function_reference_annotation_handles_defined_readonly_items(
        self, libobfuscated_setup
    ) -> None:
        function_ea = _function_ea("global_const_rva_guard")
        if function_ea == idaapi.BADADDR:
            pytest.skip("global_const_rva_guard not found")
        items = referenced_global_items(function_ea)
        eligible = [item for item in items if item.decision.can_persist_const]
        assert eligible

        originals: dict[int, ida_typeinf.tinfo_t | None] = {}
        proposals: dict[int, object] = {}
        try:
            for item in eligible:
                item_ea = item.evidence.item_head
                original = ida_typeinf.tinfo_t()
                if ida_nalt.get_tinfo(original, item_ea) and not original.empty():
                    originals[item_ea] = original.copy()
                    working = original.copy()
                    working.clr_const()
                    assert ida_typeinf.apply_tinfo(
                        item_ea,
                        working,
                        ida_typeinf.TINFO_DEFINITE,
                    )
                else:
                    originals[item_ea] = None
                    ida_nalt.del_tinfo(item_ea)

            report = annotate_function_global_consts(
                function_ea,
                proposal_store=proposals,
            )

            assert report.queued_count == len(eligible)
            for item in eligible:
                live = ida_typeinf.tinfo_t()
                if ida_nalt.get_tinfo(live, item.evidence.item_head):
                    assert not live.is_const()
                assert item.evidence.item_head in proposals
        finally:
            for item_ea, original in originals.items():
                if original is None:
                    ida_nalt.del_tinfo(item_ea)
                else:
                    ida_typeinf.apply_tinfo(
                        item_ea,
                        original,
                        ida_typeinf.TINFO_DEFINITE,
                    )

    @pytest.mark.ida_required
    def test_default_public_operation_does_not_persist_defined_readonly_item(
        self,
        libobfuscated_setup,
        d810_state,
    ) -> None:
        function_ea = _function_ea("global_const_rva_guard")
        items = referenced_global_items(function_ea)
        eligible = [item for item in items if item.decision.can_persist_const]
        assert eligible
        item_ea = eligible[0].evidence.item_head
        original = ida_typeinf.tinfo_t()
        had_original = bool(
            ida_nalt.get_tinfo(original, item_ea) and not original.empty()
        )
        if had_original:
            working = original.copy()
            working.clr_const()
            assert ida_typeinf.apply_tinfo(
                item_ea,
                working,
                ida_typeinf.TINFO_DEFINITE,
            )
        else:
            ida_nalt.del_tinfo(item_ea)
        proposals = Netnode("$ d810.global_const_proposals.v1")
        before_snapshot = capture_serialized_tinfo(item_ea)
        try:
            try:
                del proposals[item_ea]
            except KeyError:
                pass
            with d810_state() as state:
                project_index = next(
                    index
                    for index, project in enumerate(state.project_manager.projects())
                    if project.path.name
                    == "default_instruction_only_config_v2_canary.json"
                )
                state.load_project(project_index)
                state.start_d810()
                assert idaapi.decompile(
                    function_ea,
                    flags=idaapi.DECOMP_NO_CACHE,
                )

            assert capture_serialized_tinfo(item_ea) == before_snapshot
            assert not pending_global_const_proposals(proposal_store=proposals)
        finally:
            try:
                del proposals[item_ea]
            except KeyError:
                pass
            if had_original:
                ida_typeinf.apply_tinfo(
                    item_ea,
                    original,
                    ida_typeinf.TINFO_DEFINITE,
                )
            else:
                ida_nalt.del_tinfo(item_ea)

    @pytest.mark.ida_required
    def test_enabled_pass_applies_static_const_before_one_decompilation_and_restores(
        self,
        libobfuscated_setup,
        d810_state,
    ) -> None:
        function_ea = _function_ea("global_const_rva_guard")
        items = referenced_global_items(function_ea)
        eligible = [item for item in items if item.decision.can_persist_const]
        assert eligible
        item_ea = eligible[0].evidence.item_head
        original = ida_typeinf.tinfo_t()
        had_original = bool(
            ida_nalt.get_tinfo(original, item_ea) and not original.empty()
        )
        if had_original:
            before_type = original.copy()
            before_type.clr_const()
            assert ida_typeinf.apply_tinfo(
                item_ea,
                before_type,
                ida_typeinf.TINFO_DEFINITE,
            )
        else:
            ida_nalt.del_tinfo(item_ea)
        before_snapshot = capture_serialized_tinfo(item_ea)
        proposals = Netnode("$ d810.global_const_proposals.v1")
        try:
            try:
                del proposals[item_ea]
            except KeyError:
                pass
            with d810_state() as state:
                _enable_global_const_persistence(state)
                state.start_d810()
                const_seen_by_decompile: list[bool] = []

                def decompile_once():
                    live = ida_typeinf.tinfo_t()
                    assert ida_nalt.get_tinfo(live, item_ea)
                    const_seen_by_decompile.append(bool(live.is_const()))
                    return idaapi.decompile(
                        function_ea,
                        flags=idaapi.DECOMP_NO_CACHE,
                    )

                result = state.manager.decompile_with_native_preanalysis(
                    function_ea,
                    decompile_once,
                    ida_hexrays.clear_cached_cfuncs,
                )
                assert result is not None
                assert const_seen_by_decompile == [True]
                assert not pending_global_const_proposals(proposal_store=proposals)

                snapshot = state.get_workbench_snapshot(
                    function_ea,
                    "global_const_rva_guard",
                )
                transaction = next(
                    row
                    for row in snapshot.preparation.transactions
                    if row.script_id == "d810-global-const-types"
                    and row.type_annotations > 0
                    and row.restore_allowed
                )
                restored = state.manager.restore_idb_preparation(
                    PreparationTransactionId(transaction.transaction_id)
                )
                assert restored.ok, restored
                assert capture_serialized_tinfo(item_ea) == before_snapshot
        finally:
            try:
                del proposals[item_ea]
            except KeyError:
                pass
            if had_original:
                ida_typeinf.apply_tinfo(
                    item_ea,
                    original,
                    ida_typeinf.TINFO_DEFINITE,
                )
            else:
                ida_nalt.del_tinfo(item_ea)

    @pytest.mark.ida_required
    def test_annotation_applies_const_once_to_dynamic_lookup_table(
        self, libobfuscated_setup
    ) -> None:
        access = _lookup_table_access()
        item_ea = access.item_head
        original = ida_typeinf.tinfo_t()
        had_original = bool(
            ida_nalt.get_tinfo(original, item_ea) and not original.empty()
        )
        if had_original:
            working = original.copy()
            working.clr_const()
            assert ida_typeinf.apply_tinfo(
                item_ea,
                working,
                ida_typeinf.TINFO_DEFINITE,
            )
        else:
            ida_nalt.del_tinfo(item_ea)

        proposals: dict[int, object] = {}
        before_snapshot = capture_serialized_tinfo(item_ea)
        try:
            first = annotate_global_table_access(
                access,
                proposal_store=proposals,
            )

            second = annotate_global_table_access(
                access,
                proposal_store=proposals,
            )

            assert first.queued_count == 1
            assert first.changed_count == 1
            assert capture_serialized_tinfo(item_ea) == before_snapshot
            assert second.changed_count == 0
            assert (
                second.outcomes[0].status is GlobalConstAnnotationStatus.ALREADY_QUEUED
            )
            pending = pending_global_const_proposals(proposal_store=proposals)
            assert len(pending) == 1
            acknowledge_global_const_proposals(
                pending,
                proposal_store=proposals,
            )
            assert not pending_global_const_proposals(proposal_store=proposals)
        finally:
            if had_original:
                ida_typeinf.apply_tinfo(
                    item_ea,
                    original,
                    ida_typeinf.TINFO_DEFINITE,
                )
            else:
                ida_nalt.del_tinfo(item_ea)

    @pytest.mark.ida_required
    def test_annotation_preserves_incompatible_existing_table_type(
        self, libobfuscated_setup
    ) -> None:
        access = _lookup_table_access()
        item_ea = access.item_head
        original = ida_typeinf.tinfo_t()
        had_original = bool(
            ida_nalt.get_tinfo(original, item_ea) and not original.empty()
        )
        scalar = ida_typeinf.tinfo_t()
        scalar.create_simple_type(ida_typeinf.BTF_UINT8)
        assert ida_typeinf.apply_tinfo(
            item_ea,
            scalar,
            ida_typeinf.TINFO_DEFINITE,
        )
        try:
            report = annotate_global_table_access(access, proposal_store={})
            current = ida_typeinf.tinfo_t()
            assert ida_nalt.get_tinfo(current, item_ea)

            assert report.changed_count == 0
            assert (
                report.outcomes[0].status
                is GlobalConstAnnotationStatus.PRESERVED_USER_TYPE
            )
            assert current.get_size() == 1
            assert not current.is_const()
        finally:
            if had_original:
                ida_typeinf.apply_tinfo(
                    item_ea,
                    original,
                    ida_typeinf.TINFO_DEFINITE,
                )
            else:
                ida_nalt.del_tinfo(item_ea)

    @pytest.mark.ida_required
    def test_annotation_removes_only_owned_const_after_write_evidence(
        self, libobfuscated_setup
    ) -> None:
        access = _lookup_table_access()
        item_ea = access.item_head
        source_ea = _function_ea("global_const_simple_lookup")
        original = ida_typeinf.tinfo_t()
        had_original = bool(
            ida_nalt.get_tinfo(original, item_ea) and not original.empty()
        )
        ida_nalt.del_tinfo(item_ea)
        proposals: dict[int, object] = {}
        write_added = False
        try:
            first = annotate_global_table_access(access, proposal_store=proposals)
            assert first.queued_count == 1
            write_added = bool(ida_xref.add_dref(source_ea, item_ea, ida_xref.dr_W))
            assert write_added

            cancelled = annotate_global_table_access(
                access,
                proposal_store=proposals,
            )
            current = ida_typeinf.tinfo_t()
            assert not ida_nalt.get_tinfo(current, item_ea)
            assert cancelled.cancelled_count == 1
            assert item_ea not in proposals

            user_const = ida_typeinf.tinfo_t()
            user_const.create_simple_type(ida_typeinf.BTF_UINT32)
            user_const.set_const()
            assert ida_typeinf.apply_tinfo(
                item_ea,
                user_const,
                ida_typeinf.TINFO_DEFINITE,
            )
            preserved = annotate_global_table_access(
                access,
                proposal_store={},
            )
            current = ida_typeinf.tinfo_t()
            assert ida_nalt.get_tinfo(current, item_ea)
            assert preserved.changed_count == 0
            assert (
                preserved.outcomes[0].status
                is GlobalConstAnnotationStatus.PRESERVED_USER_TYPE
            )
            assert current.is_const()
        finally:
            if write_added:
                ida_xref.del_dref(source_ea, item_ea)
            if had_original:
                ida_typeinf.apply_tinfo(
                    item_ea,
                    original,
                    ida_typeinf.TINFO_DEFINITE,
                )
            else:
                ida_nalt.del_tinfo(item_ea)

    @pytest.mark.ida_required
    def test_public_constant_simplification_annotates_dynamic_lookup_table(
        self,
        libobfuscated_setup,
        d810_state,
    ) -> None:
        function_ea = _function_ea("global_const_simple_lookup")
        access = _lookup_table_access()
        item_ea = access.item_head
        original = ida_typeinf.tinfo_t()
        had_original = bool(
            ida_nalt.get_tinfo(original, item_ea) and not original.empty()
        )
        before_type = original.dstr() if had_original else "<none>"
        before_const = bool(had_original and original.is_const())
        before_decompiled = idaapi.decompile(
            function_ea,
            flags=idaapi.DECOMP_NO_CACHE,
        )
        assert before_decompiled is not None
        ida_nalt.del_tinfo(item_ea)
        hexrays_only = idaapi.decompile(
            function_ea,
            flags=idaapi.DECOMP_NO_CACHE,
        )
        assert hexrays_only is not None
        hexrays_only_type = capture_serialized_tinfo(item_ea)
        ida_nalt.del_tinfo(item_ea)
        proposals = Netnode("$ d810.global_const_proposals.v1")
        try:
            try:
                del proposals[item_ea]
            except KeyError:
                pass
            with d810_state() as state:
                _enable_global_const_persistence(state)
                state.start_d810()
                decompiled = idaapi.decompile(
                    function_ea,
                    flags=idaapi.DECOMP_NO_CACHE,
                )
                assert decompiled is not None

            assert capture_serialized_tinfo(item_ea) == hexrays_only_type
            pending = pending_global_const_proposals(proposal_store=proposals)
            proposal = next(
                proposal for proposal in pending if proposal.item_head == item_ea
            )
            assert not proposal.before.present
            assert proposal.after.present
            print(
                f"[GLOBAL-CONST BEFORE] ea=0x{item_ea:X} "
                f"type={before_type!r} const={before_const}"
            )
            print(
                f"[GLOBAL-CONST PROPOSAL] ea=0x{item_ea:X} "
                f"before_present={proposal.before.present} "
                f"after_present={proposal.after.present}"
            )
            print(f"[PSEUDOCODE BEFORE]\n{before_decompiled}")
            print(f"[PSEUDOCODE AFTER]\n{decompiled}")
        finally:
            try:
                del proposals[item_ea]
            except KeyError:
                pass
            if had_original:
                ida_typeinf.apply_tinfo(
                    item_ea,
                    original,
                    ida_typeinf.TINFO_DEFINITE,
                )
            else:
                ida_nalt.del_tinfo(item_ea)

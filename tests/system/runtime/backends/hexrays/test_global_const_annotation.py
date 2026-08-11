from __future__ import annotations

import os
import platform

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
    annotate_function_global_consts,
    annotate_global_table_access,
    discover_dynamic_global_table_access,
    referenced_global_items,
)
from d810.core.persistence import Netnode


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


def _function_ea(name: str) -> int:
    return int(ida_name.get_name_ea(idaapi.BADADDR, name))


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
        receipts: dict[int, object] = {}
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
                receipt_store=receipts,
            )

            assert report.applied_count == len(eligible)
            for item in eligible:
                applied = ida_typeinf.tinfo_t()
                assert ida_nalt.get_tinfo(applied, item.evidence.item_head)
                assert applied.is_const()
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
    def test_public_operation_annotates_defined_readonly_item(
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
        receipts = Netnode("$ d810.global_const_annotations.v1")
        try:
            try:
                del receipts[item_ea]
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

            applied = ida_typeinf.tinfo_t()
            assert ida_nalt.get_tinfo(applied, item_ea)
            assert applied.is_const()
        finally:
            try:
                del receipts[item_ea]
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

        receipts: dict[int, object] = {}
        try:
            first = annotate_global_table_access(
                access,
                receipt_store=receipts,
            )
            applied = ida_typeinf.tinfo_t()
            assert ida_nalt.get_tinfo(applied, item_ea)

            second = annotate_global_table_access(
                access,
                receipt_store=receipts,
            )

            assert first.applied_count == 1
            assert first.changed_count == 1
            assert applied.is_const()
            assert second.changed_count == 0
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
            report = annotate_global_table_access(access, receipt_store={})
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
        receipts: dict[int, object] = {}
        write_added = False
        try:
            first = annotate_global_table_access(access, receipt_store=receipts)
            assert first.applied_count == 1
            write_added = bool(ida_xref.add_dref(source_ea, item_ea, ida_xref.dr_W))
            assert write_added

            removed = annotate_global_table_access(
                access,
                receipt_store=receipts,
            )
            current = ida_typeinf.tinfo_t()
            assert ida_nalt.get_tinfo(current, item_ea)
            assert removed.removed_count == 1
            assert not current.is_const()

            user_const = current.copy()
            user_const.set_const()
            assert ida_typeinf.apply_tinfo(
                item_ea,
                user_const,
                ida_typeinf.TINFO_DEFINITE,
            )
            preserved = annotate_global_table_access(
                access,
                receipt_store={},
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
        receipts = Netnode("$ d810.global_const_annotations.v1")
        try:
            try:
                del receipts[item_ea]
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
                decompiled = idaapi.decompile(
                    function_ea,
                    flags=idaapi.DECOMP_NO_CACHE,
                )
                assert decompiled is not None

            applied = ida_typeinf.tinfo_t()
            assert ida_nalt.get_tinfo(applied, item_ea)
            assert applied.is_const()
            assert "[8]" in applied.dstr()
            print(
                f"[GLOBAL-CONST BEFORE] ea=0x{item_ea:X} "
                f"type={before_type!r} const={before_const}"
            )
            print(
                f"[GLOBAL-CONST AFTER] ea=0x{item_ea:X} "
                f"type={applied.dstr()!r} const={applied.is_const()}"
            )
            print(f"[PSEUDOCODE BEFORE]\n{before_decompiled}")
            print(f"[PSEUDOCODE AFTER]\n{decompiled}")
        finally:
            try:
                del receipts[item_ea]
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

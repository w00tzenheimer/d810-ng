"""Native loading/decompilation gates for the shared Warden fixture corpus.

These are fixture acceptance checks, not whole-function semantic equivalence.
The whole function contains modeled external boundaries and is never executed.
"""

import ida_hexrays
import idaapi
import idc
import pytest


SLICE_PROTOTYPES = {
    "warden_v57_value_mba": "unsigned int __fastcall f(unsigned int x, unsigned int y);",
    "warden_v85_value_mba": "unsigned int __fastcall f(unsigned int x, unsigned int y);",
    "warden_v55_index_offset": "unsigned int __fastcall f(unsigned int x, unsigned int mask);",
    "warden_v55_index_lookup": "unsigned int __fastcall f(unsigned int x, unsigned int mask);",
    "warden_mixed_source": "unsigned __int64 __fastcall f(unsigned int x);",
    "warden_mixed64_negative_precondition": "unsigned __int64 __fastcall f(unsigned __int64 x);",
}


class TestWardenSharedFixtures:
    binary_name = "libobfuscated.dll"

    def test_all_authoritative_entrypoints(self, ida_database):
        for name in ("WardenScanModule_DecryptAndDispatchRequest", *SLICE_PROTOTYPES):
            ea = idc.get_name_ea_simple(name)
            assert ea != idaapi.BADADDR, name
            assert idaapi.get_func(ea) is not None, (name, hex(ea))

    @pytest.mark.parametrize("name", SLICE_PROTOTYPES)
    @pytest.mark.parametrize("enabled", (False, True), ids=("disabled", "enabled"))
    def test_slice_native_decompilation(
        self, name, enabled, ida_database, configure_hexrays, d810_state
    ):
        assert ida_hexrays.init_hexrays_plugin()
        ea = idc.get_name_ea_simple(name)
        assert ea != idaapi.BADADDR, name
        assert idc.SetType(ea, SLICE_PROTOTYPES[name].replace(" f(", f" {name}("))
        with d810_state() as state:
            state.stop_d810()
            if enabled:
                project = state.project_manager.index("default_constants_and_mba_simplifiers.json")
                loaded = state.load_project(project)
                assert loaded is not None, repr(state.invalid_projects)
                state.start_d810()
            ida_hexrays.mark_cfunc_dirty(ea, False)
            failure = ida_hexrays.hexrays_failure_t()
            result = ida_hexrays.decompile(ea, failure)
            assert result is not None, (name, enabled, failure.code, failure.desc())
            text = str(result)
            assert "return" in text, (name, enabled, text)
            print(f"WARDEN_SLICE name={name} ea={ea:#x} enabled={enabled}\n{text}")

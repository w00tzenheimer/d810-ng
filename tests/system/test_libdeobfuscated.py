import os
import textwrap
import unittest

import idaapi
import idc

from d810.manager import D810State


def pseudocode_to_string(pseudo_code: idaapi.strvec_t) -> str:
    converted_obj: list[str] = [
        idaapi.tag_remove(line_obj.line) for line_obj in pseudo_code
    ]

    return os.linesep.join(converted_obj)


class TestLibDeobfuscated(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Initialize the Hex-Rays decompiler plugin
        if not idaapi.init_hexrays_plugin():
            raise unittest.SkipTest("Hex-Rays decompiler plugin not available")

        idaapi.change_hexrays_config("COLLAPSE_LVARS = YES")

    @classmethod
    def tearDownClass(cls):
        pass

    def test_decompile_test_xor(self):
        # Locate the function named 'test_xor'
        func_ea = idc.get_name_ea_simple("test_xor")
        self.assertNotEqual(
            func_ea, idaapi.BADADDR, "Function 'test_xor' not found in database"
        )

        # TODO(w00tzenheimer): How do I set COLLAPSE_LVARS per function instead of hexrays configuration wide?
        # # Display user defined citem iflags
        # iflags = idaapi.restore_user_iflags(func_ea)
        # if iflags is not None:
        #     print("------- %u user defined citem iflags" % (len(iflags),))
        #     for cl, f in iflags.items():
        #         print(
        #             "%x(%d): %08X%s"
        #             % (
        #                 cl.ea,
        #                 cl.op,
        #                 f,
        #                 " CIT_COLLAPSED" if f & idaapi.CIT_COLLAPSED else "",
        #             )
        #         )
        # else:

        #     idaapi.user_iflags_insert(
        #         iflags,
        #         idaapi.citem_locator_t(func_ea, idaapi.VDI_LVAR),
        #         idaapi.CIT_COLLAPSED,
        #     )
        #     idaapi.save_user_iflags(func_ea, iflags)
        # idaapi.user_iflags_free(iflags)
        # Decompile the function

        state = D810State()  # TODO: use singleton
        state.load(gui=False)
        project_index = state.project_manager.index("example_libobfuscated.json")
        existing_proj_index = state.current_project_index
        if project_index != existing_proj_index:
            print("\n", "not using libdeobfuscated project, will set it to 5")
        state.stop_d810()
        decompiled_func = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
        self.assertIsNotNone(
            decompiled_func, "Decompilation returned None for 'test_xor'"
        )
        # Convert to pseudocode string
        pseudocode = decompiled_func.get_pseudocode()
        expected_pseudocode = textwrap.dedent(
            """\
        __int64 __fastcall test_xor(int a1, int a2, int a3, int *a4)
        {
            // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

            *a4 = a2 + a1 - 2 * (a2 & a1);
            a4[1] = a2 - 3 + a3 * a1 - 2 * ((a2 - 3) & (a3 * a1));
            return (unsigned int)(a4[1] + *a4);
        }"""
        )
        self.assertEqual(pseudocode_to_string(pseudocode), expected_pseudocode)
        state.load_project(project_index)
        state.start_d810()
        decompiled_func = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
        self.assertIsNotNone(
            decompiled_func, "Decompilation returned None for 'test_xor'"
        )
        # Convert to pseudocode string
        pseudocode = decompiled_func.get_pseudocode()
        print("optimized", "\n", pseudocode_to_string(pseudocode))
        expected_pseudocode = textwrap.dedent(
            """\
        __int64 __fastcall test_xor(int a1, int a2, int a3, int *a4)
        {
            // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

            *a4 = a2 ^ a1;
            a4[1] = (a2 - 3) ^ (a3 * a1);
            return (unsigned int)(a4[1] + *a4);
        }"""
        )
        state.load_project(existing_proj_index)


if __name__ == "__main__":
    unittest.main()

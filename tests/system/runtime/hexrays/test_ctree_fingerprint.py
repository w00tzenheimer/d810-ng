from __future__ import annotations

import os
import platform

import pytest

try:
    import idaapi
    import idc

    _IDA_AVAILABLE = True
except Exception:
    _IDA_AVAILABLE = False

from d810.backends.hexrays.ctree_fingerprint import fingerprint_ctree

pytestmark = pytest.mark.skipif(not _IDA_AVAILABLE, reason="IDA Pro not available")


def _binary_name() -> str:
    return os.environ.get(
        "D810_TEST_BINARY",
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll",
    )


def _resolve_function(name: str) -> int:
    ea = int(idc.get_name_ea_simple(name))
    if ea == int(idaapi.BADADDR):
        ea = int(idc.get_name_ea_simple("_" + name))
    return ea


class TestCtreeFingerprint:
    binary_name = _binary_name()

    @pytest.fixture(scope="class")
    @classmethod
    def libobfuscated_setup(
        cls,
        ida_database,
        configure_hexrays,
        setup_libobfuscated_funcs,
    ):
        assert idaapi.init_hexrays_plugin()
        return ida_database

    def test_two_clean_decompilations_have_one_structural_fingerprint(
        self,
        libobfuscated_setup,
    ) -> None:
        function_ea = _resolve_function("test_function_ollvm_fla_bcf_sub")
        assert function_ea != int(idaapi.BADADDR)
        first = idaapi.decompile(function_ea, flags=idaapi.DECOMP_NO_CACHE)
        second = idaapi.decompile(function_ea, flags=idaapi.DECOMP_NO_CACHE)
        assert first is not None and second is not None

        first_fingerprint = fingerprint_ctree(first)
        second_fingerprint = fingerprint_ctree(second)

        assert first_fingerprint == second_fingerprint
        assert first_fingerprint.node_count > 0

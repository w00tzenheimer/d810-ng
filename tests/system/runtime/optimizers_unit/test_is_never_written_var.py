"""System tests for is_never_written_var in d810.hexrays.ida_utils.

is_never_written_var checks whether a variable at a given address is never
written to by any code. It returns True only when:
  - No data xref of type dr_W points to the address

These tests use real IDA APIs against libobfuscated.dll to test the function's
branching logic with actual database state.
"""

from __future__ import annotations

import idaapi
import idc
import pytest

from d810.hexrays.ida_utils import is_never_written_var


@pytest.mark.ida_required
class TestIsNeverWrittenVarRealIDA:
    """Test is_never_written_var against real IDA database.

    We use libobfuscated.dll which contains:
    - Global variables that are written to (volatile globals, accumulators)
    - Read-only data that is never written (string literals, const data)
    """

    binary_name = "libobfuscated.dll"

    def test_writable_global_with_write_xrefs(self, ida_database):
        """A global variable that is written to should have dr_W xrefs."""
        # Search for any address in a writable segment that has write xrefs
        candidate_ea = idaapi.BADADDR

        # Iterate through all segments
        seg = idaapi.get_first_seg()
        while seg is not None:
            # Check if writable segment (e.g., .data, .bss)
            if seg.perm & idaapi.SEGPERM_WRITE:
                # Search for an address with write xrefs in this segment
                # Only check a small portion to avoid slow tests
                for ea in range(seg.start_ea, min(seg.start_ea + 0x1000, seg.end_ea), 4):
                    if not idaapi.is_loaded(ea):
                        continue

                    # Check if this has write xrefs
                    ref_finder = idaapi.xrefblk_t()
                    has_write = False
                    if ref_finder.first_to(ea, idaapi.XREF_DATA):
                        while True:
                            if ref_finder.type == idaapi.dr_W:
                                has_write = True
                                break
                            if not ref_finder.next_to():
                                break

                    # Found address with write xrefs
                    if has_write:
                        candidate_ea = ea
                        break

                if candidate_ea != idaapi.BADADDR:
                    break

            # Move to next segment
            seg = idaapi.get_next_seg(seg.start_ea)

        if candidate_ea == idaapi.BADADDR:
            pytest.skip("No suitable address with write xrefs found")

        # Address with write xrefs should return False (IS written)
        result = is_never_written_var(candidate_ea)
        assert result is False, (
            f"Expected is_never_written_var({candidate_ea:#x}) to return False "
            "for address with dr_W write xrefs"
        )

    def test_const_string_no_write_xrefs(self, ida_database):
        """String literals in .rdata should have no write xrefs."""
        # Search for any string in the binary
        # String literals are typically in read-only sections and never written
        min_ea = ida_database["min_ea"]
        max_ea = ida_database["max_ea"]

        # Find first string
        string_ea = idaapi.BADADDR
        for ea in range(min_ea, max_ea, 4):
            # Check if this is a string
            struc_id = idc.get_strlit_contents(ea)
            if struc_id is not None and len(struc_id) > 4:
                string_ea = ea
                break

        if string_ea == idaapi.BADADDR:
            pytest.skip("No string literals found in binary")

        # Verify loaded
        assert idaapi.is_loaded(string_ea), f"Expected string at {string_ea:#x} to be loaded"

        # String literals should never be written to
        result = is_never_written_var(string_ea)
        assert result is True, (
            f"Expected is_never_written_var({string_ea:#x}) to return True "
            "for read-only string literal with no write xrefs"
        )

    def test_uninitialized_data_no_write_xrefs(self, ida_database):
        """Test BSS section data that may have no xrefs at all."""
        # Look for uninitialized data (BSS) or padding
        # These addresses may have no xrefs at all
        candidate_ea = idaapi.BADADDR

        # Iterate through all segments
        seg = idaapi.get_first_seg()
        while seg is not None:
            # Check if writable segment (e.g., .data, .bss)
            if seg.perm & idaapi.SEGPERM_WRITE:
                # Search for an address with no xrefs in this segment
                # Only check a small portion to avoid slow tests
                for ea in range(seg.start_ea, min(seg.start_ea + 0x1000, seg.end_ea), 4):
                    # Check if this has any data xrefs
                    has_xref = False
                    ref_finder = idaapi.xrefblk_t()
                    if ref_finder.first_to(ea, idaapi.XREF_DATA):
                        has_xref = True

                    # Found address with no xrefs
                    if not has_xref and idaapi.is_loaded(ea):
                        candidate_ea = ea
                        break

                if candidate_ea != idaapi.BADADDR:
                    break

            # Move to next segment
            seg = idaapi.get_next_seg(seg.start_ea)

        if candidate_ea == idaapi.BADADDR:
            pytest.skip("No suitable address with no xrefs found")

        # Address with no xrefs should return True (never written)
        result = is_never_written_var(candidate_ea)
        assert result is True, (
            f"Expected is_never_written_var({candidate_ea:#x}) to return True "
            "for address with no xrefs"
        )

    def test_function_entry_no_write_xrefs(self, ida_database):
        """Code addresses (function entries) should have no write xrefs."""
        # Find any function
        func_ea = idaapi.get_func(ida_database["min_ea"])
        if func_ea is None:
            # Try to find first function
            func_ea = idc.get_next_func(ida_database["min_ea"])
            if func_ea == idaapi.BADADDR:
                pytest.skip("No functions found in binary")
        else:
            func_ea = func_ea.start_ea

        # Verify loaded
        assert idaapi.is_loaded(func_ea), f"Expected function at {func_ea:#x} to be loaded"

        # Code is never written to (should only have code xrefs, not data writes)
        result = is_never_written_var(func_ea)
        assert result is True, (
            f"Expected is_never_written_var({func_ea:#x}) to return True "
            "for code address with no data write xrefs"
        )

    def test_address_not_loaded_returns_true(self, ida_database):
        """Addresses outside loaded memory should return True."""
        # Use an address that is definitely not loaded
        # High address that's outside any segment
        max_ea = ida_database["max_ea"]
        not_loaded_ea = max_ea + 0x100000  # Well beyond any segment

        # Verify it's not loaded
        assert not idaapi.is_loaded(not_loaded_ea), (
            f"Expected {not_loaded_ea:#x} to not be loaded"
        )

        # Should return True (never written because not even present)
        result = is_never_written_var(not_loaded_ea)
        assert result is True, (
            f"Expected is_never_written_var({not_loaded_ea:#x}) to return True "
            "for address not loaded in IDB"
        )

    def test_read_only_segment_no_write_xrefs(self, ida_database):
        """Data in read-only segments should have no write xrefs."""
        # Find a read-only segment (like .rdata or .text)
        readonly_ea = idaapi.BADADDR

        # Iterate through all segments
        seg = idaapi.get_first_seg()
        while seg is not None:
            # Check if read-only (has read but not write permission)
            if (seg.perm & idaapi.SEGPERM_READ) and not (seg.perm & idaapi.SEGPERM_WRITE):
                # Find first data item in this segment
                # Only check a small portion to avoid slow tests
                for ea in range(seg.start_ea, min(seg.start_ea + 0x1000, seg.end_ea), 4):
                    if idaapi.is_loaded(ea):
                        # Check if it has any xrefs (to make test more interesting)
                        ref_finder = idaapi.xrefblk_t()
                        if ref_finder.first_to(ea, idaapi.XREF_DATA):
                            # Has xrefs but should have no writes
                            readonly_ea = ea
                            break

                if readonly_ea != idaapi.BADADDR:
                    break

            # Move to next segment
            seg = idaapi.get_next_seg(seg.start_ea)

        if readonly_ea == idaapi.BADADDR:
            pytest.skip("No suitable read-only data address found")

        # Read-only data should never be written
        result = is_never_written_var(readonly_ea)
        assert result is True, (
            f"Expected is_never_written_var({readonly_ea:#x}) to return True "
            "for read-only segment data"
        )

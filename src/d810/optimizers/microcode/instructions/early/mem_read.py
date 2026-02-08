from typing import Any, Optional

import ida_hexrays
from idaapi import (
    SEGPERM_READ,
    SEGPERM_WRITE,
    XREF_DATA,
    dr_W,
    getseg,
    is_loaded,
    segment_t,
    xrefblk_t,
)

from d810.expr.ast import AstConstant, AstLeaf, AstNode
from d810.optimizers.microcode.instructions.early.handler import EarlyRule


def segment_is_read_only(addr: int) -> bool:
    """
    Check if address is in a read-only segment based on segment permissions.

    Returns True if segment has READ but not WRITE permission.
    This is a fast check based on IDA's segment metadata.
    """
    s: segment_t = getseg(addr)
    if s is None:
        return False
    return (s.perm & SEGPERM_READ) != 0 and (s.perm & SEGPERM_WRITE) == 0


def is_never_written_var(address: int) -> bool:
    """Check if a variable at address is never written to by any code.

    Unlike is_read_only_inited_var(), this does NOT require the segment
    to be read-only. It only checks that no code writes to this address,
    making it suitable for detecting opaque constant tables in writable
    segments (e.g., volatile globals used in OLLVM obfuscation).
    """
    if is_loaded(address):
        return False
    ref_finder = xrefblk_t()
    is_ok = ref_finder.first_to(address, XREF_DATA)
    while is_ok:
        if ref_finder.type == dr_W:
            return False
        is_ok = ref_finder.next_to()
    return True


def is_read_only_inited_var(address: int) -> bool:
    """
    Stricter check for truly read-only initialized variables.

    Returns True only if ALL of:
    1. Address is in a read-only segment (segment_is_read_only)
    2. Address is NOT a loaded (imported) symbol
    3. No write xrefs point to this address (static analysis)

    Use this for optimization passes where we need to be certain
    the value cannot change at runtime.
    """
    if not segment_is_read_only(address):
        return False
    if is_loaded(address):
        return False
    ref_finder = xrefblk_t()
    is_ok = ref_finder.first_to(address, XREF_DATA)
    while is_ok:
        if ref_finder.type == dr_W:
            return False
        is_ok = ref_finder.next_to()
    return True


class SetGlobalVariablesToZero(EarlyRule):
    DESCRIPTION = "This rule can be used to patch memory read"

    @property
    def PATTERN(self) -> AstNode:
        """Return the pattern to match."""
        return AstNode(ida_hexrays.m_mov, AstLeaf("ro_dword"))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_mov, AstConstant("val_res"))

    def __init__(self):
        super().__init__()
        self.ro_dword_min_ea = None
        self.ro_dword_max_ea = None

    def configure(self, kwargs):
        super().configure(kwargs)
        self.ro_dword_min_ea = None
        self.ro_dword_max_ea = None
        if "ro_dword_min_ea" in kwargs.keys():
            self.ro_dword_min_ea = int(kwargs["ro_dword_min_ea"], 16)
        if "ro_dword_max_ea" in kwargs.keys():
            self.ro_dword_max_ea = int(kwargs["ro_dword_max_ea"], 16)

    def check_candidate(self, candidate):
        if (self.ro_dword_min_ea is None) or (self.ro_dword_max_ea is None):
            return False
        leaf = candidate["ro_dword"]
        if leaf is None:
            return False
        mop = leaf.mop
        if mop is None:
            return False
        if getattr(mop, "t", None) != ida_hexrays.mop_v:
            return False
        mem_read_address = getattr(mop, "g", None)
        if mem_read_address is None:
            return False
        if not (self.ro_dword_min_ea <= mem_read_address <= self.ro_dword_max_ea):
            return False

        candidate.add_constant_leaf("val_res", 0, mop.size)
        return True


# This rule is from
# https://www.carbonblack.com/blog/defeating-compiler-level-obfuscations-used-in-apt10-malware/
class SetGlobalVariablesToZeroIfDetectedReadOnly(EarlyRule):
    DESCRIPTION = "WARNING: Use it only if you know what you are doing as it may patch data not related to obfuscation"

    @property
    def PATTERN(self) -> AstNode:
        """Return the pattern to match."""
        return AstNode(ida_hexrays.m_mov, AstLeaf("ro_dword"))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_mov, AstConstant("val_res"))

    def __init__(self):
        super().__init__()
        # If we optimized too early (in MMAT_GENERATED), we may replace something like
        # 'mov     &($dword_10020CC8).4, eoff.4' by 'mov     #0.4, eoff.4'
        # and this will lead to incorrect decompilation where MEMORY[0] is used
        # Thus, we explicitly specify the MMAT_PREOPTIMIZED maturity.
        self.maturities = [ida_hexrays.MMAT_PREOPTIMIZED]

    def check_candidate(self, candidate):
        """
        Replace reads from read-only initialized variables with zero.

        This rule detects mov instructions that read from global variables
        in read-only segments (.rdata/.rodata) and replaces the read with
        an immediate zero value. This is useful for defeating obfuscation
        techniques that use initialized read-only globals as opaque constants.

        The check uses is_read_only_inited_var() which verifies:
        - The address is in a read-only segment
        - The address is not an imported symbol
        - No write xrefs exist to this address

        WARNING: This may incorrectly patch non-zero read-only data.
        Use with caution and verify results manually.
        """
        leaf = candidate["ro_dword"]
        if leaf is None:
            return False
        mop = leaf.mop
        if mop is None:
            return False
        mem_read_address: Optional[int] = None
        if mop.t == ida_hexrays.mop_v:
            mem_read_address = mop.g
        elif mop.t == ida_hexrays.mop_a and mop.a is not None:
            inner = mop.a
            if inner.t == ida_hexrays.mop_v:
                mem_read_address = inner.g

        if mem_read_address is None:
            return False

        if not is_read_only_inited_var(mem_read_address):
            return False
        candidate.add_constant_leaf("val_res", 0, mop.size)
        return True


class ReplaceReadonlyAddressOfWithImmediate(EarlyRule):
    DESCRIPTION = (
        "Replace mov &($sym[+off]), dst with immediate addr if in .rdata/.rodata"
    )

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_mov, AstLeaf("ro_addr"))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_mov, AstConstant("val_res"))

    def __init__(self) -> None:
        super().__init__()
        # Run early to avoid creating bogus MEMORY[0] later when addresses fold late
        self.maturities = [ida_hexrays.MMAT_PREOPTIMIZED]

    def _resolve_address_from_mop(self, mop_obj: ida_hexrays.mop_t | None) -> int | None:
        if mop_obj is None:
            return None
        t = mop_obj.t
        if t == ida_hexrays.mop_a:
            inner = mop_obj.a
            if inner is None:
                return None
            it = inner.t
            if it == ida_hexrays.mop_v:
                return inner.g
            if it == ida_hexrays.mop_S:
                # Prefer concrete address in `off`, fallback to `start_ea`
                return getattr(inner.s, "off", None) or getattr(
                    inner.s, "start_ea", None
                )
        elif t == ida_hexrays.mop_v:
            return mop_obj.g
        return None

    def check_candidate(self, candidate):
        leaf = candidate["ro_addr"]
        if leaf is None:
            return False
        mop_obj: ida_hexrays.mop_t | None = leaf.mop
        if mop_obj is None:
            return False
        addr = self._resolve_address_from_mop(mop_obj)
        if addr is None:
            return False
        if not segment_is_read_only(addr):
            return False
        size = mop_obj.size or 0
        if size == 0:
            return False
        candidate.add_constant_leaf("val_res", addr, size)
        return True

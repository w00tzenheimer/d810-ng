"""Architecture abstraction layer for d810.

This module provides architecture-independent utilities for analyzing native code
patterns, ported from the copycat project's arch_utils.h/.cpp.

Key abstractions:
  - Register roles (first argument, return value, link register)
  - Instruction type classification (mov, branch, call, return)
  - Pattern detection (identity functions, trampolines, indirect jumps)
  - Calling convention awareness

Supports x86-64 and ARM64 architectures.
"""
from __future__ import annotations

import enum
from d810.core.typing import TYPE_CHECKING

import ida_bytes
import ida_funcs
import ida_ida
import ida_idp
import ida_name
import ida_segment
import ida_xref
import idaapi
from idaapi import BADADDR

if TYPE_CHECKING:
    from ida_ua import insn_t

from d810.core import getLogger

logger = getLogger(__name__)


# ---------------------------------------------------------------------------
# Supported Architectures
# ---------------------------------------------------------------------------
class ArchType(enum.IntEnum):
    """Supported architectures."""

    UNKNOWN = 0
    X86 = 1  # 32-bit x86
    X86_64 = 2  # 64-bit x86-64
    ARM32 = 3  # 32-bit ARM
    ARM64 = 4  # 64-bit ARM (AArch64)


# Identity function detection caches
_identity_funcs: set[int] = set()
_non_identity_funcs: set[int] = set()

# Trampoline resolution cache
_trampoline_cache: dict[int, int] = {}


def clear_caches() -> None:
    """Clear all internal caches (identity functions, trampolines)."""
    _identity_funcs.clear()
    _non_identity_funcs.clear()
    _trampoline_cache.clear()


# ---------------------------------------------------------------------------
# Architecture Detection
# ---------------------------------------------------------------------------
def get_arch() -> ArchType:
    """Get the current architecture from IDA's processor module.

    Returns:
        ArchType enum value (UNKNOWN if IDA not available or unsupported arch)
    """
    proc_name = ida_idp.get_idp_name()
    is_64 = ida_ida.inf_is_64bit()

    if proc_name in ("386", "metapc", "pc"):
        return ArchType.X86_64 if is_64 else ArchType.X86
    elif proc_name in ("ARM", "arm"):
        return ArchType.ARM64 if is_64 else ArchType.ARM32

    return ArchType.UNKNOWN


# ---------------------------------------------------------------------------
# Register Role Abstraction
# ---------------------------------------------------------------------------
def get_first_arg_reg() -> int:
    """Get the first function argument register.

    Returns:
        - x86-64 System V: RDI (7)
        - x86-64 Windows:  RCX (1)  # TODO: detect calling convention
        - ARM64:           X0 (0)
        - -1 if unknown
    """
    arch = get_arch()
    if arch == ArchType.X86_64:
        # Heuristic calling convention split:
        # - PE binaries (`.dll`, `.exe`) usually follow Windows x64 ABI (RCX)
        # - Mach-O/ELF samples usually follow SysV ABI (RDI)
        root_name = (idaapi.get_root_filename() or "").lower()
        if root_name.endswith(".dll") or root_name.endswith(".exe"):
            return 1  # RCX (Windows x64)
        return 7  # RDI (SysV x86-64)
    elif arch == ArchType.ARM64:
        return 0  # X0
    elif arch == ArchType.X86:
        return 1  # ECX for fastcall
    elif arch == ArchType.ARM32:
        return 0  # R0

    return -1


def get_return_reg() -> int:
    """Get the return value register.

    Returns:
        - x86/x86-64: RAX/EAX (0)
        - ARM/ARM64:  X0/R0 (0)
        - -1 if unknown
    """
    arch = get_arch()
    if arch in (ArchType.X86, ArchType.X86_64):
        return 0  # RAX/EAX
    elif arch in (ArchType.ARM32, ArchType.ARM64):
        return 0  # X0/R0

    return -1


# ---------------------------------------------------------------------------
# Identity Function Analysis
# ---------------------------------------------------------------------------
def is_identity_function(func_ea: int) -> bool:
    """Check if a function is an identity function (returns first arg unchanged).

    An identity function pattern varies by architecture:
      - x86-64: mov rax, rdi; ret
      - ARM64:  ret (x0 is both first arg and return reg)

    Size constraints:
      - x86-64: < 32 bytes
      - ARM64:  < 16 bytes

    Args:
        func_ea: Function entry address

    Returns:
        True if function is identity, False otherwise
    """
    if not _IDA_AVAILABLE or func_ea == BADADDR:
        return False

    # Check cache first
    if func_ea in _identity_funcs:
        return True
    if func_ea in _non_identity_funcs:
        return False

    # Analyze the function
    result = _analyze_identity_function(func_ea)

    # Update cache
    if result:
        _identity_funcs.add(func_ea)
    else:
        _non_identity_funcs.add(func_ea)

    return result


def _analyze_identity_function(func_ea: int) -> bool:
    """Analyze if a function is an identity function (internal implementation).

    Args:
        func_ea: Function entry address

    Returns:
        True if function is identity, False otherwise
    """
    func = ida_funcs.get_func(func_ea)
    if not func:
        return False

    # Size constraints
    arch = get_arch()
    max_size = 16 if arch == ArchType.ARM64 else 32
    func_size = func.end_ea - func.start_ea
    if func_size > max_size:
        return False

    # Analyze instructions
    curr_ea = func.start_ea
    insn = idaapi.insn_t()
    insn_count = 0
    saw_identity_mov = False
    saw_ret = False
    stack_slots_from_arg: set[tuple[int, int]] = set()
    arg_reg = get_first_arg_reg()
    ret_reg = get_return_reg()
    rsp_reg = idaapi.str2reg("rsp")
    rbp_reg = idaapi.str2reg("rbp")

    while curr_ea < func.end_ea and insn_count < 10:
        if idaapi.decode_insn(insn, curr_ea) == 0:
            break

        insn_count += 1

        # Skip NOPs
        if _is_nop_insn(insn):
            curr_ea = insn.ea + insn.size
            continue

        # Check for identity mov (mov ret, arg).
        if _is_identity_mov(insn):
            saw_identity_mov = True

        # Also accept stack-spill wrappers:
        #   mov [rsp+off], arg
        #   mov ret, [rsp+off]
        if (
            arg_reg >= 0
            and ret_reg >= 0
            and idaapi.ua_mnem(insn.ea) == "mov"
        ):
            dst = insn.Op1
            src = insn.Op2
            if (
                dst.type in (idaapi.o_phrase, idaapi.o_displ)
                and dst.reg in (rsp_reg, rbp_reg)
                and src.type == idaapi.o_reg
                and src.reg == arg_reg
            ):
                stack_slots_from_arg.add((dst.reg, int(dst.addr)))

            if dst.type == idaapi.o_reg and dst.reg == ret_reg:
                if src.type == idaapi.o_reg and src.reg == arg_reg:
                    saw_identity_mov = True
                elif (
                    src.type in (idaapi.o_phrase, idaapi.o_displ)
                    and src.reg in (rsp_reg, rbp_reg)
                    and (src.reg, int(src.addr)) in stack_slots_from_arg
                ):
                    saw_identity_mov = True

        # Check for return
        if _is_return_insn(insn):
            saw_ret = True
            break

        curr_ea = insn.ea + insn.size

    # Determine if identity
    if not saw_ret:
        return False

    # ARM64: just "ret" is identity (x0 is both arg and return reg)
    if arch == ArchType.ARM64 and insn_count <= 2:
        return True

    # x86-64: need explicit "mov rax, rdi"
    if arch == ArchType.X86_64 and saw_identity_mov:
        return True

    # Very short function with identity mov or ARM64
    if insn_count <= 3 and (saw_identity_mov or arch == ArchType.ARM64):
        return True

    return False


def _is_identity_mov(insn: insn_t) -> bool:
    """Check if instruction is 'mov <return_reg>, <first_arg_reg>'.

    Args:
        insn: Decoded instruction

    Returns:
        True if identity mov pattern
    """
    arch = get_arch()
    ret_reg = get_return_reg()
    arg_reg = get_first_arg_reg()

    if arch == ArchType.X86_64:
        # x86: mov rax, rdi (itype 0x3C = NN_mov in some IDA versions)
        # Check instruction mnemonic
        mnem = idaapi.ua_mnem(insn.ea)
        if mnem == "mov":
            # Op1 = dest, Op2 = src
            if (
                insn.Op1.type == idaapi.o_reg
                and insn.Op1.reg == ret_reg
                and insn.Op2.type == idaapi.o_reg
                and insn.Op2.reg == arg_reg
            ):
                return True

    elif arch == ArchType.ARM64:
        # ARM64: mov x0, x0 (rare, usually just ret)
        mnem = idaapi.ua_mnem(insn.ea)
        if mnem in ("mov", "movz"):
            if (
                insn.Op1.type == idaapi.o_reg
                and insn.Op1.reg == 0
                and insn.Op2.type == idaapi.o_reg
                and insn.Op2.reg == 0
            ):
                return True

    return False


def _is_return_insn(insn: insn_t) -> bool:
    """Check if instruction is a return.

    Args:
        insn: Decoded instruction

    Returns:
        True if return instruction
    """
    mnem = idaapi.ua_mnem(insn.ea)
    return mnem in ("ret", "retn", "retf")


def _is_nop_insn(insn: insn_t) -> bool:
    """Check if instruction is a NOP.

    Args:
        insn: Decoded instruction

    Returns:
        True if NOP instruction
    """
    return idaapi.ua_mnem(insn.ea) == "nop"


# ---------------------------------------------------------------------------
# Global Pointer Resolution
# ---------------------------------------------------------------------------
def resolve_global_pointer(ptr_addr: int) -> int | None:
    """Resolve a global pointer to get the actual target address.

    Reads pointer from IDB and validates it points to code.

    Args:
        ptr_addr: Address of global pointer

    Returns:
        Target EA if valid code pointer, None otherwise
    """
    if not _IDA_AVAILABLE or ptr_addr == BADADDR:
        return None

    # Check if ptr_addr is in a data segment
    seg = ida_segment.getseg(ptr_addr)
    if not seg:
        return None

    # Skip code segments (we want data segment pointers)
    if seg.perm & ida_segment.SEGPERM_EXEC:
        return None

    # Read pointer value
    arch = get_arch()
    ptr_size = 8 if arch in (ArchType.X86_64, ArchType.ARM64) else 4

    if ptr_size == 8:
        target = ida_bytes.get_qword(ptr_addr)
    else:
        target = ida_bytes.get_dword(ptr_addr)

    if target == BADADDR or target == 0:
        return None

    # Validate target is in a code segment
    target_seg = ida_segment.getseg(target)
    if not target_seg:
        return None

    if target_seg.perm & ida_segment.SEGPERM_EXEC:
        return target

    return None


# ---------------------------------------------------------------------------
# Trampoline Analysis
# ---------------------------------------------------------------------------
def is_trampoline_code(addr: int) -> tuple[bool, int | None]:
    """Check if code location is a trampoline pattern.

    Trampolines follow patterns like:
      x86-64: mov rdi, [ptr]; call identity; jmp rax
      ARM64:  ldr x0, [ptr]; bl identity; br x0

    Args:
        addr: Code address to check

    Returns:
        Tuple of (is_trampoline, global_ptr_ea) where global_ptr_ea is None if
        not a trampoline or pointer address if it is
    """
    if not _IDA_AVAILABLE or addr == BADADDR:
        return (False, None)

    insn = idaapi.insn_t()
    curr_ea = addr
    insn_count = 0

    potential_ptr: int | None = None
    saw_identity_call = False
    saw_indirect_jump = False

    while insn_count < 30:
        if idaapi.decode_insn(insn, curr_ea) == 0:
            break

        insn_count += 1

        # Look for argument load from memory (mov rdi, [mem] or ldr x0, [mem])
        mem_addr = _get_arg_load_address(insn)
        if mem_addr is not None:
            potential_ptr = mem_addr

        # Look for call to identity function
        if _is_call_insn(insn):
            call_target = _get_call_target(curr_ea)
            if call_target and call_target != BADADDR:
                if is_identity_function(call_target):
                    saw_identity_call = True
                else:
                    # Check for HikariFunctionWrapper name pattern
                    func_name = ida_name.get_name(call_target)
                    if func_name and "HikariFunctionWrapper" in func_name:
                        saw_identity_call = True

        # Look for indirect jump via return register
        if _is_indirect_jump_via_return_reg(insn):
            saw_indirect_jump = True
            break

        # Stop at return
        if _is_return_insn(insn):
            break

        curr_ea = insn.ea + insn.size

    if saw_identity_call and saw_indirect_jump and potential_ptr is not None:
        return (True, potential_ptr)

    return (False, None)


def _get_arg_load_address(insn: insn_t) -> int | None:
    """Extract memory address from argument load instruction.

    Args:
        insn: Decoded instruction

    Returns:
        Memory address if instruction loads first arg from memory, None otherwise
    """
    arch = get_arch()
    arg_reg = get_first_arg_reg()
    mnem = idaapi.ua_mnem(insn.ea)

    if arch == ArchType.X86_64:
        # mov rdi, [mem]
        if mnem == "mov":
            if (
                insn.Op1.type == idaapi.o_reg
                and insn.Op1.reg == arg_reg
                and insn.Op2.type == idaapi.o_mem
            ):
                return insn.Op2.addr

    elif arch == ArchType.ARM64:
        # ldr x0, [mem] or ldr x0, =label
        if mnem in ("ldr", "ldur"):
            if insn.Op1.type == idaapi.o_reg and insn.Op1.reg == arg_reg:
                if insn.Op2.type == idaapi.o_mem:
                    return insn.Op2.addr

    return None


def _is_call_insn(insn: insn_t) -> bool:
    """Check if instruction is a call (direct or indirect).

    Args:
        insn: Decoded instruction

    Returns:
        True if call instruction
    """
    mnem = idaapi.ua_mnem(insn.ea)
    return mnem in ("call", "bl", "blr")


def _is_indirect_jump_via_return_reg(insn: insn_t) -> bool:
    """Check if instruction is an indirect jump via return register.

    Args:
        insn: Decoded instruction

    Returns:
        True if indirect jump via return register
    """
    mnem = idaapi.ua_mnem(insn.ea)
    arch = get_arch()
    ret_reg = get_return_reg()

    if arch == ArchType.X86_64:
        # jmp rax
        if mnem == "jmp" and insn.Op1.type == idaapi.o_reg:
            return insn.Op1.reg == ret_reg

    elif arch == ArchType.ARM64:
        # br x0 (or any register)
        if mnem == "br" and insn.Op1.type == idaapi.o_reg:
            return True

    return False


def _get_call_target(call_ea: int) -> int | None:
    """Get the target address of a call instruction.

    Args:
        call_ea: Address of call instruction

    Returns:
        Target EA if direct call, None otherwise
    """
    # Get first code xref from call
    xref = ida_xref.get_first_fcref_from(call_ea)
    if xref and xref != BADADDR:
        return xref

    return None


# ---------------------------------------------------------------------------
# Trampoline Chain Resolution
# ---------------------------------------------------------------------------
def resolve_trampoline_chain(
    start_addr: int, max_depth: int = 32, _cache: dict[int, int] | None = None
) -> int:
    """Recursively resolve a trampoline chain to find the final target.

    Follows chains of identity calls until reaching non-trampoline code.
    Detects cycles.

    Args:
        start_addr: Starting address
        max_depth: Maximum chain depth (default 32)
        _cache: Optional cache dict (internal use for recursion)

    Returns:
        Final target EA (may be start_addr if not a trampoline)
    """
    if not _IDA_AVAILABLE or start_addr == BADADDR or max_depth <= 0:
        return start_addr

    # Use module-level cache if not provided
    if _cache is None:
        _cache = _trampoline_cache

    # Check cache
    if start_addr in _cache:
        return _cache[start_addr]

    current = start_addr
    visited: set[int] = set()

    while max_depth > 0:
        if current in visited:
            logger.debug("Cycle detected in trampoline chain at %#x", current)
            break

        visited.add(current)

        is_tramp, next_ptr = is_trampoline_code(current)
        if not is_tramp or next_ptr is None:
            break

        next_target = resolve_global_pointer(next_ptr)
        if next_target is None:
            logger.debug("Chain broken at %#x (invalid pointer)", current)
            break

        logger.debug(
            "Trampoline chain: %#x -> ptr %#x -> %#x", current, next_ptr, next_target
        )

        current = next_target
        max_depth -= 1

    # Cache result
    _cache[start_addr] = current
    return current

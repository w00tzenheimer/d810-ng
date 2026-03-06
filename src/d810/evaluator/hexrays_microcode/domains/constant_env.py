"""Constant-propagation domain: universe collection, entry state, transfer.

This module extracts the constant-domain logic from
``ForwardConstantPropagationRule`` so it can be reused by the generic
forward-dataflow engine without depending on the rule class.

Every public function operates on plain ``LatticeEnv`` (``dict[str, LatticeValue]``)
dicts and IDA microcode objects.
"""
from __future__ import annotations

import ida_hexrays

from d810.cfg.lattice import (
    TOP,
    Const,
    LatticeEnv,
)
from d810.core.logging import getLogger
from d810.core.typing import Optional
from d810.hexrays.ir.mop_utils import (
    extract_base_and_offset,
    get_stack_var_name,
)

logger = getLogger(__name__)

ConstMap = LatticeEnv  # backward-compat alias


# ---------------------------------------------------------------------------
# Helper utilities (extracted from ForwardConstantPropagationRule)
# ---------------------------------------------------------------------------


def _get_written_var_name(ins: ida_hexrays.minsn_t) -> Optional[str]:
    """Identify the destination variable name of *ins*, or None if unknown."""
    d = ins.d
    if d is None:
        return None
    if d.t in {ida_hexrays.mop_S, ida_hexrays.mop_r}:
        return get_stack_var_name(d)
    if ins.opcode != ida_hexrays.m_stx:
        return None
    if d.t == ida_hexrays.mop_S:
        return get_stack_var_name(d)
    base, off = extract_base_and_offset(d)
    if base and (base_name := get_stack_var_name(base)):
        return f"{base_name}+{off:X}" if off else base_name
    return None


def _is_constant_stack_assignment(ins: ida_hexrays.minsn_t) -> bool:
    """Return True if *ins* is a constant store into a stack variable or register."""
    if ins.l is None or ins.l.t != ida_hexrays.mop_n:
        return False
    if (
        ins.opcode == ida_hexrays.m_mov
        and ins.d
        and ins.d.t in {ida_hexrays.mop_S, ida_hexrays.mop_r}
    ):
        return True
    if ins.opcode == ida_hexrays.m_stx:
        if ins.d and ins.d.t == ida_hexrays.mop_S:
            return True
        base, _ = extract_base_and_offset(ins.d) if ins.d else (None, 0)
        return base is not None
    return False


def _extract_assignment(
    ins: ida_hexrays.minsn_t,
) -> Optional[tuple[str, tuple[int, int]]]:
    """Extract ``(var_name, (value, size))`` for a constant assignment, or None."""
    if not _is_constant_stack_assignment(ins):
        return None
    value, size = ins.l.nnn.value, ins.l.size
    var: Optional[str] = None
    if ins.opcode == ida_hexrays.m_mov:
        var = get_stack_var_name(ins.d)
    elif ins.d.t in {ida_hexrays.mop_S, ida_hexrays.mop_r}:
        var = get_stack_var_name(ins.d)
    else:
        base, off = extract_base_and_offset(ins.d)
        if base and (base_name := get_stack_var_name(base)):
            var = f"{base_name}+{off:X}" if off else base_name
    return (var, (value, size)) if var else None


# ---------------------------------------------------------------------------
# Universe collection
# ---------------------------------------------------------------------------


def collect_universe(mba: ida_hexrays.mba_t) -> set[str]:
    """Scan all blocks+instructions to find all written variable names.

    Returns:
        Set of variable name strings that are written anywhere in *mba*.
    """
    universe: set[str] = set()
    for blk_idx in range(mba.qty):
        blk = mba.get_mblock(blk_idx)
        ins = blk.head
        while ins:
            dest_name = _get_written_var_name(ins)
            if dest_name is not None:
                universe.add(dest_name)
            ins = ins.next
    return universe


# ---------------------------------------------------------------------------
# Entry state builder
# ---------------------------------------------------------------------------


def build_constant_entry_state(mba: ida_hexrays.mba_t) -> ConstMap:
    """Build the entry-block IN state: every written variable mapped to TOP.

    Args:
        mba: The IDA microcode array for the current function.

    Returns:
        A ``ConstMap`` mapping every variable in the universe to ``TOP``.
    """
    universe = collect_universe(mba)
    return {var: TOP for var in universe}


# ---------------------------------------------------------------------------
# Transfer functions
# ---------------------------------------------------------------------------


def constant_transfer_single(
    mba: ida_hexrays.mba_t,
    ins: ida_hexrays.minsn_t,
    env: ConstMap,
) -> None:
    """Transfer function for a single instruction (GEN/KILL).

    Mutates *env* in-place. This is the core constant-domain transfer logic
    extracted from ``ForwardConstantPropagationRule._slow_transfer_single``.

    Note:
        This function does NOT handle readonly-ldx resolution (which depends
        on IDA segment APIs). It handles side-effects, variable kills, and
        constant-assignment GEN identically to the original.
    """
    # 1. Side-effects handling — pure helpers (ROL/ROR) are exempt.
    if (
        ins.opcode == ida_hexrays.m_call
        and ins.l is not None
        and ins.l.t == ida_hexrays.mop_h
    ):
        helper_name: str = ins.l.helper
        if helper_name.startswith(("__ROL", "__ROR")):
            return  # pure helper — preserve env

    if ins.has_side_effects() and ins.opcode != ida_hexrays.m_stx:
        for k in list(env):
            env[k] = TOP
        return

    # 2. ldx — KILL destination (readonly resolution is NOT done here;
    #    the rule class handles that separately).
    if ins.opcode == ida_hexrays.m_ldx:
        written_var = _get_written_var_name(ins)
        if written_var:
            env[written_var] = TOP
        return

    # 3. Determine written variable & apply precise KILL / GEN.
    written_var = _get_written_var_name(ins)
    is_const_assign = _is_constant_stack_assignment(ins)

    # KILL when overwritten by non-constant value
    if written_var and not is_const_assign:
        env[written_var] = TOP

    # GEN constant
    if is_const_assign:
        res = _extract_assignment(ins)
        if res and res[0]:
            var_name, (value, size) = res[0], res[1]
            env[var_name] = Const(value, size)
            if logger.debug_on:
                logger.debug(
                    "[constant_env] transfer: ins_ea=0x%x gen %s = %r",
                    ins.ea,
                    var_name,
                    env[var_name],
                )


def constant_transfer_block(
    blk: ida_hexrays.mblock_t,
    in_env: ConstMap,
) -> ConstMap:
    """Walk ``blk.head -> ins.next``, applying ``constant_transfer_single`` to each.

    Args:
        blk: The microcode block to transfer through.
        in_env: The input constant map (will NOT be mutated).

    Returns:
        The output constant map after processing all instructions in the block.
    """
    env: ConstMap = dict(in_env)
    ins = blk.head
    mba = blk.mba
    while ins:
        constant_transfer_single(mba, ins, env)
        ins = ins.next
    return env


__all__ = [
    "ConstMap",
    "build_constant_entry_state",
    "collect_universe",
    "constant_transfer_block",
    "constant_transfer_single",
]

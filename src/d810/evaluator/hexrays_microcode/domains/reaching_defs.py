"""Reaching-definitions dataflow domain.

Tracks which definition sites reach each program point. Used by the
terminal-return proof layer to determine which definitions of a variable
(e.g., rax) are live at a given block.

Domain values:
    BOTTOM  -- no information (identity for meet / union)
    TOP     -- overdefined (too many defs, collapsed)
    frozenset[DefSite] -- concrete set of reaching definitions

Meet semantics: **union** of def sets from all predecessors.
Transfer: KILL old defs for the written variable, GEN a new DefSite.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.lattice import BOTTOM, TOP, _Sentinel
from d810.core.logging import getLogger
from d810.core.typing import Optional, Union

logger = getLogger(__name__)

# Maximum number of DefSites per VarKey before collapsing to TOP.
_MAX_DEF_SET_SIZE: int = 32


# ---------------------------------------------------------------------------
# Core types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class VarKey:
    """Identifier for a microcode variable.

    Args:
        kind: One of ``"reg"``, ``"stkvar"``, ``"mem"``.
        identifier: mreg number for registers, stkoff for stack vars,
            base+offset string for memory.
        size: Operand size in bytes.
    """

    kind: str
    identifier: Union[int, str]
    size: int


@dataclass(frozen=True, slots=True)
class DefSite:
    """A single definition site in the microcode.

    Args:
        block_serial: Serial number of the containing block.
        ins_ea: Address of the instruction.
        opcode: IDA microcode opcode (optional).
    """

    block_serial: int
    ins_ea: int
    opcode: Optional[int] = None


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

ReachingDefValue = Union[frozenset[DefSite], _Sentinel]
"""Per-variable reaching-def lattice value."""

ReachingDefEnv = dict[VarKey, ReachingDefValue]
"""Map from variable to its reaching-def lattice value."""


# ---------------------------------------------------------------------------
# Meet (union semantics)
# ---------------------------------------------------------------------------


def _meet_values(a: ReachingDefValue, b: ReachingDefValue) -> ReachingDefValue:
    """Meet two reaching-def values (union semantics).

    Args:
        a: First value.
        b: Second value.

    Returns:
        The meet of a and b.
    """
    # BOTTOM is identity for union-meet
    if a is BOTTOM:
        return b
    if b is BOTTOM:
        return a

    # TOP is absorbing
    if a is TOP or b is TOP:
        return TOP

    # Both are frozenset[DefSite]
    merged = a | b  # type: ignore[operator]
    if len(merged) > _MAX_DEF_SET_SIZE:
        return TOP
    return merged


def reaching_defs_meet(pred_outs: list[ReachingDefEnv]) -> ReachingDefEnv:
    """Compute the meet over all predecessor OUT environments.

    Union semantics: for each VarKey present in any predecessor, union
    the def sets. BOTTOM acts as identity, TOP absorbs.

    Args:
        pred_outs: List of OUT environments from predecessor blocks.

    Returns:
        A new ReachingDefEnv that is the union-meet of all inputs.
    """
    if not pred_outs:
        return {}

    result: ReachingDefEnv = dict(pred_outs[0])
    for env in pred_outs[1:]:
        all_keys = result.keys() | env.keys()
        merged: ReachingDefEnv = {}
        for key in all_keys:
            va = result.get(key, BOTTOM)
            vb = env.get(key, BOTTOM)
            merged[key] = _meet_values(va, vb)
        result = merged

    return result


# ---------------------------------------------------------------------------
# Variable extraction (IDA-dependent -- lazy import)
# ---------------------------------------------------------------------------


def get_written_var_key(ins: object) -> Optional[VarKey]:
    """Extract the written VarKey from a microcode instruction.

    Args:
        ins: An ``ida_hexrays.minsn_t`` instance.

    Returns:
        VarKey if the instruction writes to a register or stack variable,
        None otherwise.
    """
    try:
        import ida_hexrays
    except ImportError:
        return None

    d = ins.d  # type: ignore[attr-defined]
    if d is None:
        return None

    if d.t == ida_hexrays.mop_r:
        return VarKey(kind="reg", identifier=d.r, size=d.size)  # type: ignore[attr-defined]

    if d.t == ida_hexrays.mop_S:
        stkoff = d.s  # type: ignore[attr-defined]
        if hasattr(stkoff, "off"):
            stkoff = stkoff.off
        return VarKey(kind="stkvar", identifier=stkoff, size=d.size)

    return None


# ---------------------------------------------------------------------------
# Transfer functions
# ---------------------------------------------------------------------------


def reaching_defs_transfer_single(
    ins: object,
    block_serial: int,
    env: ReachingDefEnv,
) -> None:
    """Apply GEN/KILL for a single instruction (mutates env in-place).

    If the instruction writes to a VarKey, KILL all previous defs for that
    key and GEN a new DefSite.

    Args:
        ins: An ``ida_hexrays.minsn_t`` instance.
        block_serial: Serial number of the containing block.
        env: The reaching-def environment to mutate.
    """
    var_key = get_written_var_key(ins)
    if var_key is None:
        return

    opcode = getattr(ins, "opcode", None)
    ea = getattr(ins, "ea", 0)
    env[var_key] = frozenset({DefSite(block_serial, ea, opcode)})


def reaching_defs_transfer_block(
    blk: object,
    in_env: ReachingDefEnv,
) -> ReachingDefEnv:
    """Walk a block's instruction list, applying GEN/KILL for each.

    Args:
        blk: An ``ida_hexrays.mblock_t`` instance.
        in_env: Input reaching-def environment (will NOT be mutated).

    Returns:
        Output reaching-def environment after processing all instructions.
    """
    env: ReachingDefEnv = dict(in_env)
    serial: int = getattr(blk, "serial", 0)
    ins = getattr(blk, "head", None)
    while ins:
        reaching_defs_transfer_single(ins, serial, env)
        ins = getattr(ins, "next", None)
    return env


# ---------------------------------------------------------------------------
# Entry state builder
# ---------------------------------------------------------------------------


def build_reaching_defs_entry_state(universe: set[VarKey]) -> ReachingDefEnv:
    """Build the entry-block IN state: every variable mapped to BOTTOM.

    Args:
        universe: Set of all VarKeys in the function.

    Returns:
        A ReachingDefEnv with every key mapped to BOTTOM.
    """
    return {var: BOTTOM for var in universe}


__all__ = [
    "DefSite",
    "ReachingDefEnv",
    "ReachingDefValue",
    "VarKey",
    "build_reaching_defs_entry_state",
    "get_written_var_key",
    "reaching_defs_meet",
    "reaching_defs_transfer_block",
    "reaching_defs_transfer_single",
]

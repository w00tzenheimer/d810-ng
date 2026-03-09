"""Generic forward dataflow fixpoint engine and abstract domains.

Domain-agnostic worklist solver. Callers provide:
- entry state
- meet function (merge predecessor outputs)
- transfer function (transform state through a block)
- graph topology (predecessors, successors, node set)

The engine does NOT import IDA types. The MBA adapter below wraps IDA access.

Also contains two concrete domains previously in the ``domains/`` sub-package:

1. **Reaching-definitions domain** -- tracks which definition sites reach each
   program point. Used by the terminal-return proof layer.
2. **Constant-propagation domain** -- tracks constant values of stack/register
   variables. Used by ``ForwardConstantPropagationRule``.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass

from d810.core.logging import getLogger
from d810.core.typing import (
    TYPE_CHECKING,
    Callable,
    Collection,
    Generic,
    Iterable,
    Optional,
    Protocol,
    TypeVar,
    Union,
    runtime_checkable,
)

if TYPE_CHECKING:
    pass

logger = getLogger(__name__)

StateT = TypeVar("StateT")


@runtime_checkable
class MeetFunction(Protocol[StateT]):
    """Merge multiple predecessor output states into one input state."""

    def __call__(self, pred_outs: list[StateT]) -> StateT: ...


@runtime_checkable
class TransferFunction(Protocol[StateT]):
    """Transform input state through a single node, producing output state."""

    def __call__(self, node_id: int, in_state: StateT) -> StateT: ...


@dataclass(frozen=True)
class FixpointResult(Generic[StateT]):
    """Result of a forward fixpoint computation."""

    in_states: dict[int, StateT]
    out_states: dict[int, StateT]
    iterations: int


def run_forward_fixpoint(
    *,
    nodes: Collection[int],
    entry_node: int,
    entry_state: StateT,
    bottom: StateT,
    predecessors_of: Callable[[int], Iterable[int]],
    successors_of: Callable[[int], Iterable[int]],
    meet: MeetFunction[StateT],
    transfer: TransferFunction[StateT],
    max_iterations: int = 1000,
) -> FixpointResult[StateT]:
    """Run forward dataflow to fixpoint.

    Algorithm: LIFO worklist. Entry node gets entry_state. All others start
    at bottom. Converges when OUT stops changing for all blocks.

    Args:
        nodes: Set of node identifiers in the graph.
        entry_node: The entry node where dataflow begins.
        entry_state: Initial abstract state at the entry node.
        bottom: The bottom element of the lattice (initial state for all
            non-entry nodes).
        predecessors_of: Returns predecessors of a given node.
        successors_of: Returns successors of a given node.
        meet: Merges multiple predecessor output states into one.
        transfer: Computes output state from input state for a node.
        max_iterations: Safety bound to prevent infinite loops.

    Returns:
        FixpointResult with IN/OUT states for every node and iteration count.
    """
    in_states: dict[int, StateT] = {n: bottom for n in nodes}
    out_states: dict[int, StateT] = {n: bottom for n in nodes}
    in_states[entry_node] = entry_state

    worklist: list[int] = [entry_node]
    iterations = 0

    while worklist and iterations < max_iterations:
        node = worklist.pop()  # LIFO
        iterations += 1

        preds = list(predecessors_of(node))
        if preds:
            in_new = meet([out_states[p] for p in preds])
        else:
            in_new = in_states[node]

        if in_new != in_states[node]:
            in_states[node] = in_new

        out_new = transfer(node, in_new)

        if out_new != out_states[node]:
            out_states[node] = out_new
            for succ in successors_of(node):
                if succ not in worklist:
                    worklist.append(succ)

    return FixpointResult(
        in_states=in_states,
        out_states=out_states,
        iterations=iterations,
    )


def run_forward_fixpoint_on_mba(
    mba: object,
    *,
    entry_serial: int = 0,
    entry_state: StateT,
    bottom: StateT,
    meet: MeetFunction[StateT],
    transfer: TransferFunction[StateT],
    max_iterations: int = 1000,
) -> FixpointResult[StateT]:
    """Convenience wrapper that extracts graph topology from an IDA mba_t.

    Args:
        mba: An ``ida_hexrays.mba_t`` instance (typed as ``object`` to
            avoid a hard import dependency on IDA).
        entry_serial: Serial number of the entry block (default 0).
        entry_state: Initial abstract state at the entry block.
        bottom: Bottom element of the lattice.
        meet: Meet function for the domain.
        transfer: Transfer function for the domain.
        max_iterations: Safety bound.

    Returns:
        FixpointResult with IN/OUT states for every block serial.
    """
    nodes = list(range(mba.qty))  # type: ignore[attr-defined]

    def predecessors_of(serial: int) -> list[int]:
        return list(mba.get_mblock(serial).predset)  # type: ignore[attr-defined]

    def successors_of(serial: int) -> list[int]:
        return list(mba.get_mblock(serial).succset)  # type: ignore[attr-defined]

    return run_forward_fixpoint(
        nodes=nodes,
        entry_node=entry_serial,
        entry_state=entry_state,
        bottom=bottom,
        predecessors_of=predecessors_of,
        successors_of=successors_of,
        meet=meet,
        transfer=transfer,
        max_iterations=max_iterations,
    )


def transfer_block_insnwise(
    blk: object,
    in_state: StateT,
    transfer_single: Callable[..., None],
) -> StateT:
    """Helper: apply transfer_single to each instruction in a block.

    Walks ``blk.head -> ins.next`` linked list. ``transfer_single(mba, ins, state)``
    mutates *state* in-place. Returns the final state after all instructions.

    Args:
        blk: An ``ida_hexrays.mblock_t`` instance.
        in_state: The input state (will be shallow-copied before mutation).
        transfer_single: Callable ``(mba, ins, state) -> None`` that updates
            *state* in place for one instruction.

    Returns:
        The output state after processing all instructions in the block.
    """
    env = copy.copy(in_state)  # shallow copy for dict-based states
    ins = blk.head  # type: ignore[attr-defined]
    mba = blk.mba  # type: ignore[attr-defined]
    while ins:
        transfer_single(mba, ins, env)
        ins = ins.next  # type: ignore[attr-defined]
    return env


# ===========================================================================
# Reaching-definitions domain
# ===========================================================================
#
# Tracks which definition sites reach each program point. Used by the
# terminal-return proof layer to determine which definitions of a variable
# (e.g., rax) are live at a given block.
#
# Domain values:
#     BOTTOM  -- no information (identity for meet / union)
#     TOP     -- overdefined (too many defs, collapsed)
#     frozenset[DefSite] -- concrete set of reaching definitions
#
# Meet semantics: **union** of def sets from all predecessors.
# Transfer: KILL old defs for the written variable, GEN a new DefSite.

from d810.cfg.lattice import BOTTOM, TOP, _Sentinel

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


# ===========================================================================
# Constant-propagation domain
# ===========================================================================
#
# Extracts the constant-domain logic from ``ForwardConstantPropagationRule``
# so it can be reused by the generic forward-dataflow engine without
# depending on the rule class.
#
# Every public function operates on plain ``LatticeEnv``
# (``dict[str, LatticeValue]``) dicts and IDA microcode objects.

from d810.cfg.lattice import (
    Const,
    LatticeEnv,
)

ConstMap = LatticeEnv  # backward-compat alias


# ---------------------------------------------------------------------------
# Helper utilities (extracted from ForwardConstantPropagationRule)
# ---------------------------------------------------------------------------


def _get_written_var_name(ins: object) -> Optional[str]:
    """Identify the destination variable name of *ins*, or None if unknown."""
    try:
        import ida_hexrays
    except ImportError:
        return None

    from d810.hexrays.ir.mop_utils import (
        extract_base_and_offset,
        get_stack_var_name,
    )

    d = ins.d  # type: ignore[attr-defined]
    if d is None:
        return None
    if d.t in {ida_hexrays.mop_S, ida_hexrays.mop_r}:
        return get_stack_var_name(d)
    if ins.opcode != ida_hexrays.m_stx:  # type: ignore[attr-defined]
        return None
    if d.t == ida_hexrays.mop_S:
        return get_stack_var_name(d)
    base, off = extract_base_and_offset(d)
    if base and (base_name := get_stack_var_name(base)):
        return f"{base_name}+{off:X}" if off else base_name
    return None


def _is_constant_stack_assignment(ins: object) -> bool:
    """Return True if *ins* is a constant store into a stack variable or register."""
    try:
        import ida_hexrays
    except ImportError:
        return False

    from d810.hexrays.ir.mop_utils import extract_base_and_offset

    if ins.l is None or ins.l.t != ida_hexrays.mop_n:  # type: ignore[attr-defined]
        return False
    if (
        ins.opcode == ida_hexrays.m_mov  # type: ignore[attr-defined]
        and ins.d  # type: ignore[attr-defined]
        and ins.d.t in {ida_hexrays.mop_S, ida_hexrays.mop_r}  # type: ignore[attr-defined]
    ):
        return True
    if ins.opcode == ida_hexrays.m_stx:  # type: ignore[attr-defined]
        if ins.d and ins.d.t == ida_hexrays.mop_S:  # type: ignore[attr-defined]
            return True
        base, _ = extract_base_and_offset(ins.d) if ins.d else (None, 0)  # type: ignore[attr-defined]
        return base is not None
    return False


def _extract_assignment(
    ins: object,
) -> Optional[tuple[str, tuple[int, int]]]:
    """Extract ``(var_name, (value, size))`` for a constant assignment, or None."""
    try:
        import ida_hexrays
    except ImportError:
        return None

    from d810.hexrays.ir.mop_utils import (
        extract_base_and_offset,
        get_stack_var_name,
    )

    if not _is_constant_stack_assignment(ins):
        return None
    value, size = ins.l.nnn.value, ins.l.size  # type: ignore[attr-defined]
    var: Optional[str] = None
    if ins.opcode == ida_hexrays.m_mov:  # type: ignore[attr-defined]
        var = get_stack_var_name(ins.d)  # type: ignore[attr-defined]
    elif ins.d.t in {ida_hexrays.mop_S, ida_hexrays.mop_r}:  # type: ignore[attr-defined]
        var = get_stack_var_name(ins.d)  # type: ignore[attr-defined]
    else:
        base, off = extract_base_and_offset(ins.d)  # type: ignore[attr-defined]
        if base and (base_name := get_stack_var_name(base)):
            var = f"{base_name}+{off:X}" if off else base_name
    return (var, (value, size)) if var else None


# ---------------------------------------------------------------------------
# Universe collection
# ---------------------------------------------------------------------------


def collect_universe(mba: object) -> set[str]:
    """Scan all blocks+instructions to find all written variable names.

    Returns:
        Set of variable name strings that are written anywhere in *mba*.
    """
    universe: set[str] = set()
    for blk_idx in range(mba.qty):  # type: ignore[attr-defined]
        blk = mba.get_mblock(blk_idx)  # type: ignore[attr-defined]
        ins = blk.head
        while ins:
            dest_name = _get_written_var_name(ins)
            if dest_name is not None:
                universe.add(dest_name)
            ins = ins.next
    return universe


# ---------------------------------------------------------------------------
# Entry state builder (constant domain)
# ---------------------------------------------------------------------------


def build_constant_entry_state(mba: object) -> ConstMap:
    """Build the entry-block IN state: every written variable mapped to TOP.

    Args:
        mba: The IDA microcode array for the current function.

    Returns:
        A ``ConstMap`` mapping every variable in the universe to ``TOP``.
    """
    universe = collect_universe(mba)
    return {var: TOP for var in universe}


# ---------------------------------------------------------------------------
# Transfer functions (constant domain)
# ---------------------------------------------------------------------------


def constant_transfer_single(
    mba: object,
    ins: object,
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
    try:
        import ida_hexrays
    except ImportError:
        return

    # 1. Side-effects handling -- pure helpers (ROL/ROR) are exempt.
    if (
        ins.opcode == ida_hexrays.m_call  # type: ignore[attr-defined]
        and ins.l is not None  # type: ignore[attr-defined]
        and ins.l.t == ida_hexrays.mop_h  # type: ignore[attr-defined]
    ):
        helper_name: str = ins.l.helper  # type: ignore[attr-defined]
        if helper_name.startswith(("__ROL", "__ROR")):
            return  # pure helper -- preserve env

    if ins.has_side_effects() and ins.opcode != ida_hexrays.m_stx:  # type: ignore[attr-defined]
        for k in list(env):
            env[k] = TOP
        return

    # 2. ldx -- KILL destination (readonly resolution is NOT done here;
    #    the rule class handles that separately).
    if ins.opcode == ida_hexrays.m_ldx:  # type: ignore[attr-defined]
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
                    ins.ea,  # type: ignore[attr-defined]
                    var_name,
                    env[var_name],
                )


def constant_transfer_block(
    blk: object,
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
    ins = blk.head  # type: ignore[attr-defined]
    mba = blk.mba  # type: ignore[attr-defined]
    while ins:
        constant_transfer_single(mba, ins, env)
        ins = ins.next  # type: ignore[attr-defined]
    return env


__all__ = [
    # Fixpoint engine
    "FixpointResult",
    "MeetFunction",
    "TransferFunction",
    "run_forward_fixpoint",
    "run_forward_fixpoint_on_mba",
    "transfer_block_insnwise",
    # Reaching-definitions domain
    "DefSite",
    "ReachingDefEnv",
    "ReachingDefValue",
    "VarKey",
    "_MAX_DEF_SET_SIZE",
    "build_reaching_defs_entry_state",
    "get_written_var_key",
    "reaching_defs_meet",
    "reaching_defs_transfer_block",
    "reaching_defs_transfer_single",
    # Constant-propagation domain
    "ConstMap",
    "build_constant_entry_state",
    "collect_universe",
    "constant_transfer_block",
    "constant_transfer_single",
]

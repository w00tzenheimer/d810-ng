"""Read-only chain-backed evaluator helpers for Hex-Rays microcode.

All functions in this module are READ-ONLY: they may observe the existing graph,
mblock_t.make_lists_ready(), and chain inspection APIs, but MUST NOT mutate
instructions, blocks, or CFG structure.

Allowed:
    - require_graph_ready(mba)
    - mblock_t.make_lists_ready()
    - mblock_t.build_use_list(), mblock_t.build_def_list()
    - get_ud()/get_du() chain access
    - dominator/postdominator queries

NOT allowed:
    - mblock_t.build_lists(kill_deads=True) if it prunes
    - mba.mark_chains_dirty()
    - any CFG/instruction mutation
"""

from __future__ import annotations

import ida_hexrays

from d810.hexrays.ir.graph_readiness import (
    GraphReadinessUnavailable,
    ensure_graph_and_lists_ready,
    require_graph_ready,
)
from d810.hexrays.ir.exact_data_flow import (
    find_reaching_defs_for_reg_use,
    find_reaching_defs_for_stkvar_use,
)

from d810.core.logging import getLogger
from d810.core.typing import NamedTuple, Optional
from d810.analyses.value_flow.aliased_stack_reaching_defs import (
    AliasedStackDefEvent,
    AliasedStackDefSite,
    collect_aliased_stack_reaching_defs,
)

logger = getLogger(__name__)


class DefSite(NamedTuple):
    """A single definition site for a register or stack variable.

    Lightweight and hashable for use in sets and as dict keys.

    Attributes:
        block_serial: Serial number of the block containing the definition.
        ins_ea: Effective address of the defining instruction.
        ins_opcode: Microcode opcode of the defining instruction (e.g. m_mov).
    """

    block_serial: int
    ins_ea: int
    ins_opcode: int


class UseSite(NamedTuple):
    """A single use site for a register or stack variable.

    Lightweight and hashable for use in sets and as dict keys.

    Attributes:
        block_serial: Serial number of the block containing the use.
        ins_ea: Effective address of the instruction reading the variable.
        ins_opcode: Microcode opcode of the instruction (e.g. m_xdu, m_mov).
    """

    block_serial: int
    ins_ea: int
    ins_opcode: int


def get_ud_du_chains(
    mba: object,
    gctype: Optional[int] = None,
) -> tuple[object | None, object | None]:
    """Retrieve use-def and def-use chains from the MBA (read-only).

    Uses ``mba.get_graph().get_ud(gctype)`` and ``get_du(gctype)`` to obtain
    the ``graph_chains_t`` objects.  Defaults to
    ``ida_hexrays.GC_REGS_AND_STKVARS`` when *gctype* is ``None``.

    This function is READ-ONLY.

    Args:
        mba: An ``ida_hexrays.mba_t`` instance.
        gctype: Graph-chain type constant (e.g.
            ``ida_hexrays.GC_REGS_AND_STKVARS``).  Defaults to
            ``GC_REGS_AND_STKVARS`` when ``None``.

    Returns:
        ``(ud_chains, du_chains)`` tuple.  Returns ``(None, None)`` if
        the chain API is unavailable or chains have not been computed.
    """

    if gctype is None:
        gctype = ida_hexrays.GC_REGS_AND_STKVARS

    try:
        graph = require_graph_ready(mba)
        ud = graph.get_ud(gctype)
        du = graph.get_du(gctype)
        return (ud, du)
    except (AttributeError, RuntimeError):
        logger.debug("get_ud_du_chains: chain API unavailable on this MBA")
        return (None, None)


def _scan_block_for_stkvar_defs(
    mba: object,
    blk_serial: int,
    stkoff: int,
    size: int,
) -> list[DefSite]:
    """Scan a block's instructions for definitions of a stack variable.

    Walks instructions from head to tail looking for ``m_mov`` instructions
    whose destination is ``mop_S`` with matching stack offset.

    Args:
        mba: An ``ida_hexrays.mba_t`` instance.
        blk_serial: Serial number of the block to scan.
        stkoff: Stack offset of the variable.
        size: Operand size in bytes.

    Returns:
        List of :class:`DefSite` entries found in the block.
    """

    blk = mba.get_mblock(blk_serial)  # type: ignore[attr-defined]
    if blk is None:
        return []

    results: list[DefSite] = []
    cur_ins = blk.head
    while cur_ins is not None:
        if cur_ins.d is not None:
            if (
                cur_ins.d.t == ida_hexrays.mop_S
                and cur_ins.d.s is not None
                and cur_ins.d.s.off == stkoff
                and cur_ins.d.size == size
            ):
                results.append(
                    DefSite(
                        block_serial=blk_serial,
                        ins_ea=cur_ins.ea,
                        ins_opcode=cur_ins.opcode,
                    )
                )
        cur_ins = cur_ins.next
    return results


def _stack_cells_overlap(
    left_offset: int,
    left_size: int,
    right_offset: int,
    right_size: int,
) -> bool:
    """Return whether two positive-width stack intervals overlap."""
    return (
        left_size > 0
        and right_size > 0
        and left_offset < right_offset + right_size
        and right_offset < left_offset + left_size
    )


def _stack_slot_is_aliased(mba: object, stkoff: int, size: int) -> bool:
    """Check the MBA ivlset first, with ``minstkref`` as an SDK fallback."""
    try:
        interval = ida_hexrays.ivl_t(stkoff, size)
        interval_set = ida_hexrays.ivlset_t(interval)
        aliased_memory = mba.aliased_memory  # type: ignore[attr-defined]
        if aliased_memory.includes(interval_set):
            return True
    except (AttributeError, RuntimeError, TypeError, ValueError):
        pass
    try:
        return stkoff >= int(mba.minstkref) > 0  # type: ignore[attr-defined]
    except (AttributeError, TypeError, ValueError):
        return False


def _aliased_stack_events_for_block(
    mba: object,
    blk_serial: int,
    stkoff: int,
    size: int,
) -> tuple[AliasedStackDefEvent, ...]:
    """Classify direct and MAY writes to one aliased stack cell in a block."""
    blk = mba.get_mblock(blk_serial)  # type: ignore[attr-defined]
    if blk is None:
        return ()

    events: list[AliasedStackDefEvent] = []
    instruction = blk.head
    call_opcodes = {
        getattr(ida_hexrays, "m_call", -1),
        getattr(ida_hexrays, "m_icall", -1),
    }
    while instruction is not None:
        destination = getattr(instruction, "d", None)
        site = AliasedStackDefSite(
            block_serial=blk_serial,
            ins_ea=getattr(instruction, "ea", 0),
            opcode=getattr(instruction, "opcode", None),
        )
        if (
            destination is not None
            and destination.t == ida_hexrays.mop_S
            and destination.s is not None
        ):
            destination_offset = int(destination.s.off)
            destination_size = int(destination.size)
            if _stack_cells_overlap(destination_offset, destination_size, stkoff, size):
                # Only an exact cell write can replace its prior scalar value.
                # A partial/larger overlap remains a MAY definition because the
                # emulator cannot safely reconstruct the untouched bytes here.
                events.append(
                    AliasedStackDefEvent(
                        site,
                        replaces_cell=(
                            destination_offset == stkoff and destination_size == size
                        ),
                    )
                )
        elif getattr(instruction, "opcode", None) == ida_hexrays.m_stx:
            # An indirect store whose address is not a direct stack cell might
            # alias any frame location. Do not drop earlier candidates.
            events.append(AliasedStackDefEvent(site))
        elif getattr(instruction, "opcode", None) in call_opcodes:
            # Hex-Rays does not expose a portable per-cell call-effect proof in
            # this read-only path. Without such a proof, every call is a MAY
            # clobber and therefore remains a candidate rather than a kill.
            events.append(AliasedStackDefEvent(site))
        instruction = instruction.next
    return tuple(events)


def _find_reaching_defs_for_aliased_stkvar(
    mba: object,
    blk_serial: int,
    stkoff: int,
    size: int,
) -> list[DefSite]:
    """Run the bounded, per-query forward fallback for an aliased cell."""
    sites = collect_aliased_stack_reaching_defs(
        entry_block=0,
        target_block=blk_serial,
        successors_of=lambda serial: mba.get_mblock(serial).succset,  # type: ignore[attr-defined]
        events_for_block=lambda serial: _aliased_stack_events_for_block(
            mba, serial, stkoff, size
        ),
    )
    return [
        DefSite(
            block_serial=site.block_serial,
            ins_ea=site.ins_ea,
            ins_opcode=site.opcode if site.opcode is not None else -1,
        )
        for site in sites
    ]


def _scan_block_for_reg_defs(
    mba: object,
    blk_serial: int,
    reg_mreg: int,
    size: int,
) -> list[DefSite]:
    """Scan a block's instructions for definitions of a register.

    Walks instructions from head to tail looking for instructions whose
    destination is ``mop_r`` with matching micro-register number.

    Args:
        mba: An ``ida_hexrays.mba_t`` instance.
        blk_serial: Serial number of the block to scan.
        reg_mreg: Micro-register number.
        size: Operand size in bytes.

    Returns:
        List of :class:`DefSite` entries found in the block.
    """

    blk = mba.get_mblock(blk_serial)  # type: ignore[attr-defined]
    if blk is None:
        return []

    results: list[DefSite] = []
    cur_ins = blk.head
    while cur_ins is not None:
        if cur_ins.d is not None:
            if (
                cur_ins.d.t == ida_hexrays.mop_r
                and cur_ins.d.r == reg_mreg
                and cur_ins.d.size == size
            ):
                results.append(
                    DefSite(
                        block_serial=blk_serial,
                        ins_ea=cur_ins.ea,
                        ins_opcode=cur_ins.opcode,
                    )
                )
        cur_ins = cur_ins.next
    return results


def _scan_block_for_stkvar_uses(
    mba: object,
    blk_serial: int,
    stkoff: int,
    size: int,
) -> list[UseSite]:
    """Scan a block's instructions for reads of a stack variable.

    Walks instructions from head to tail looking for instructions that
    reference the stack variable at *stkoff* as a **source** operand
    (``l``, ``r``, or sub-operands within ``d`` when ``d`` is ``mop_d``).

    Args:
        mba: An ``ida_hexrays.mba_t`` instance.
        blk_serial: Serial number of the block to scan.
        stkoff: Stack offset of the variable.
        size: Operand size in bytes.

    Returns:
        List of :class:`UseSite` entries found in the block.
    """

    blk = mba.get_mblock(blk_serial)  # type: ignore[attr-defined]
    if blk is None:
        return []

    results: list[UseSite] = []
    cur_ins = blk.head
    while cur_ins is not None:
        found = False
        # Check left operand
        if cur_ins.l is not None and _mop_is_stkvar(
            cur_ins.l, stkoff, size, ida_hexrays
        ):
            found = True
        # Check right operand
        if (
            not found
            and cur_ins.r is not None
            and _mop_is_stkvar(cur_ins.r, stkoff, size, ida_hexrays)
        ):
            found = True
        if found:
            results.append(
                UseSite(
                    block_serial=blk_serial,
                    ins_ea=cur_ins.ea,
                    ins_opcode=cur_ins.opcode,
                )
            )
        cur_ins = cur_ins.next
    return results


def _mop_is_stkvar(mop: object, stkoff: int, size: int, ida_hexrays: object) -> bool:
    """Check whether a micro-operand references a stack variable at *stkoff*.

    Args:
        mop: An ``ida_hexrays.mop_t`` instance.
        stkoff: Stack offset to match.
        size: Operand size in bytes.
        ida_hexrays: The ``ida_hexrays`` module (passed to avoid re-import).

    Returns:
        ``True`` if the operand is ``mop_S`` with matching offset.
    """
    try:
        return (
            mop.t == ida_hexrays.mop_S  # type: ignore[attr-defined]
            and mop.s is not None  # type: ignore[attr-defined]
            and mop.s.off == stkoff  # type: ignore[attr-defined]
        )
    except (AttributeError, TypeError):
        return False


def find_reaching_defs_for_reg(
    mba: object,
    blk_serial: int,
    reg_mreg: int,
    size: int,
    *,
    use_ea: int | None = None,
) -> list[DefSite]:
    """Find definitions reaching a block, or an exact use (read-only).

    ``use_ea`` selects the value-query contract: last definitions before that
    instruction, complete incoming CFG coverage, and no skipped clobbers.
    Omitting it preserves the historical block-level UD enumeration.

    Uses UD chains to locate every ``DefSite`` for the micro-register
    *reg_mreg* (with operand *size*) that reaches block *blk_serial*.

    This function is READ-ONLY.

    Args:
        mba: An ``ida_hexrays.mba_t`` instance.
        blk_serial: Serial number of the target block.
        reg_mreg: Micro-register number (e.g. ``mr_rax``).
        size: Operand size in bytes.

    Returns:
        List of :class:`DefSite` entries.  Empty if chains are unavailable.
    """

    if use_ea is not None:
        return [DefSite(*site) for site in find_reaching_defs_for_reg_use(
            mba, blk_serial, use_ea, reg_mreg, size, require_complete=True
        )]

    try:
        ensure_graph_and_lists_ready(mba)
    except GraphReadinessUnavailable:
        return []
    ud, _ = get_ud_du_chains(mba)
    if ud is None:
        return []

    try:
        blk_chains = ud[blk_serial]  # type: ignore[index]
        chain = blk_chains.get_reg_chain(reg_mreg, size)
    except (IndexError, AttributeError, RuntimeError):
        logger.debug(
            "find_reaching_defs_for_reg: chain access failed — blk=%d mreg=%d size=%d",
            blk_serial,
            reg_mreg,
            size,
        )
        return []

    if chain is None:
        return []

    # chain_t extends intvec_t — each element is a block serial where the
    # register is defined.  We scan those blocks for actual defining instructions.
    results: list[DefSite] = []
    n = chain.size()
    for i in range(n):
        def_blk_serial = chain.at(i)
        results.extend(_scan_block_for_reg_defs(mba, def_blk_serial, reg_mreg, size))

    logger.debug(
        "find_reaching_defs_for_reg: blk=%d mreg=%d size=%d -> %d defs from %d chain entries",
        blk_serial,
        reg_mreg,
        size,
        len(results),
        n,
    )
    return results


def find_reaching_defs_for_stkvar(
    mba: object,
    blk_serial: int,
    stkoff: int,
    size: int,
    *,
    use_ea: int | None = None,
) -> list[DefSite]:
    """Find stack definitions reaching a block, or an exact use (read-only).

    ``use_ea`` uses instruction order and complete CFG coverage, including
    aliased cells and conservative call/indirect-store barriers. Omitting it
    retains the historical UD enumeration and aliased-stack MAY fallback.

    Uses UD chains to locate every ``DefSite`` for the stack variable at
    *stkoff* (with operand *size*) that reaches block *blk_serial*.

    This function is READ-ONLY.

    Args:
        mba: An ``ida_hexrays.mba_t`` instance.
        blk_serial: Serial number of the target block.
        stkoff: Stack offset of the variable.
        size: Operand size in bytes.

    Returns:
        List of :class:`DefSite` entries.  Empty if chains are unavailable.
    """

    if use_ea is not None:
        return [DefSite(*site) for site in find_reaching_defs_for_stkvar_use(
            mba, blk_serial, use_ea, stkoff, size,
            require_complete=True,
        )]

    try:
        ensure_graph_and_lists_ready(mba)
    except GraphReadinessUnavailable:
        return []
    ud, _ = get_ud_du_chains(mba)
    if ud is None:
        return []

    try:
        blk_chains = ud[blk_serial]  # type: ignore[index]
        chain = blk_chains.get_stk_chain(stkoff, size)
    except (IndexError, AttributeError, RuntimeError):
        logger.debug(
            "find_reaching_defs_for_stkvar: chain access failed — blk=%d stkoff=0x%x size=%d",
            blk_serial,
            stkoff,
            size,
        )
        chain = None

    if chain is None:
        if _stack_slot_is_aliased(mba, stkoff, size):
            return _find_reaching_defs_for_aliased_stkvar(mba, blk_serial, stkoff, size)
        return []

    # chain_t extends intvec_t — each element is a block serial where the
    # stack variable is defined.  We scan those blocks for actual definitions.
    results: list[DefSite] = []
    n = chain.size()
    for i in range(n):
        def_blk_serial = chain.at(i)
        results.extend(_scan_block_for_stkvar_defs(mba, def_blk_serial, stkoff, size))

    logger.debug(
        "find_reaching_defs_for_stkvar: blk=%d stkoff=0x%x size=%d -> %d defs from %d chain entries",
        blk_serial,
        stkoff,
        size,
        len(results),
        n,
    )
    return results


def is_passthru_chain(chain: object) -> bool:
    """Check whether a chain entry has the ``CHF_PASSTHRU`` flag (read-only).

    A pass-through chain indicates the value flows through without being
    redefined.

    This function is READ-ONLY.

    Args:
        chain: A chain entry object (``ida_hexrays.chain_t`` or similar).

    Returns:
        ``True`` if the chain has ``CHF_PASSTHRU`` set, ``False`` otherwise
        or if the flag constant is unavailable.
    """
    return bool(chain.flags & ida_hexrays.CHF_PASSTHRU)  # type: ignore[attr-defined]


def collect_pred_defs_for_block(
    mba: object,
    blk_serial: int,
    target_mreg: Optional[int] = None,
    *,
    stkoff: Optional[int] = None,
    width: int = 4,
) -> dict[int, list[DefSite]]:
    """Collect DefSites from each predecessor of a block (read-only).

    For each predecessor of *blk_serial*, gathers definitions of
    *target_mreg* (register mode) or *stkoff* (stack variable mode).

    This function is READ-ONLY.

    Args:
        mba: An ``ida_hexrays.mba_t`` instance.
        blk_serial: Serial number of the target block.
        target_mreg: If provided, collect defs for this micro-register.
        stkoff: If provided, collect defs for this stack variable offset.
            Mutually exclusive with *target_mreg* in practice, though both
            may be ``None`` (returns empty defs for each predecessor).
        width: Operand size in bytes (used with *stkoff*).  Defaults to 4.

    Returns:
        ``{pred_serial: [DefSite, ...]}`` mapping.  Empty dict if chains
        are unavailable or the block has no predecessors.
    """

    try:
        blk = mba.get_mblock(blk_serial)  # type: ignore[attr-defined]
        pred_serials: list[int] = list(blk.predset)
    except (AttributeError, IndexError):
        return {}

    result: dict[int, list[DefSite]] = {}
    for pred_serial in pred_serials:
        if stkoff is not None:
            result[pred_serial] = find_reaching_defs_for_stkvar(
                mba,
                pred_serial,
                stkoff,
                width,
            )
        elif target_mreg is not None:
            result[pred_serial] = find_reaching_defs_for_reg(
                mba,
                pred_serial,
                target_mreg,
                width,
            )
        else:
            result[pred_serial] = []

    if result:
        logger.debug(
            "collect_pred_defs_for_block: blk=%d preds=%s target_mreg=%s stkoff=%s",
            blk_serial,
            list(result.keys()),
            target_mreg,
            hex(stkoff) if stkoff is not None else None,
        )

    return result


def is_phi_like_merge(
    mba: object,
    blk_serial: int,
    mreg: int,
    *,
    stkoff: Optional[int] = None,
    width: int = 4,
) -> bool:
    """Check if a block is a phi-like merge point for a variable (read-only).

    Returns ``True`` if two or more predecessors of *blk_serial* provide
    distinct definitions of *mreg* (or *stkoff*), indicating a merge point
    analogous to a phi-node in SSA form.

    This function is READ-ONLY.

    Args:
        mba: An ``ida_hexrays.mba_t`` instance.
        blk_serial: Serial number of the target block.
        mreg: Micro-register number to check (used when *stkoff* is ``None``).
        stkoff: If provided, check stack variable at this offset instead of
            the register *mreg*.
        width: Operand size in bytes (used with *stkoff*).  Defaults to 4.

    Returns:
        ``True`` if 2+ predecessors define the variable with different DefSites.
        ``False`` if chains are unavailable, the block has fewer than 2
        predecessors, or all predecessors agree on the definition.
    """
    pred_defs = collect_pred_defs_for_block(
        mba,
        blk_serial,
        target_mreg=mreg,
        stkoff=stkoff,
        width=width,
    )
    if len(pred_defs) < 2:
        return False

    # Collect unique DefSite sets across predecessors.
    unique_def_sets: set[frozenset[DefSite]] = set()
    for defs in pred_defs.values():
        unique_def_sets.add(frozenset(defs))

    # If all preds have identical def sets they agree — no phi.
    return len(unique_def_sets) >= 2


def find_all_uses_of_stkvar(
    mba: object,
    stkoff: int,
    width: int = 4,
) -> list[UseSite]:
    """Find all use (read) sites of a stack variable across the entire MBA.

    Uses DU chains to locate every block that reads the stack variable at
    *stkoff*, then scans each block's instructions to find the exact use
    sites.

    This function is READ-ONLY.

    Args:
        mba: An ``ida_hexrays.mba_t`` instance.
        stkoff: Stack offset of the variable.
        width: Operand size in bytes.  Defaults to 4.

    Returns:
        List of :class:`UseSite` entries.  Empty if chains are unavailable.
    """

    try:
        ensure_graph_and_lists_ready(mba)
    except GraphReadinessUnavailable:
        return []
    _, du = get_ud_du_chains(mba)
    if du is None:
        return []

    results: list[UseSite] = []
    qty: int = mba.qty  # type: ignore[attr-defined]

    for blk_idx in range(qty):
        try:
            blk_chains = du[blk_idx]  # type: ignore[index]
            chain = blk_chains.get_stk_chain(stkoff, width)
        except (IndexError, AttributeError, RuntimeError):
            continue

        if chain is None:
            continue

        # chain_t entries are block serials where the variable is used.
        # For DU chains accessed at block blk_idx, the chain lists blocks
        # that use the definition from blk_idx.  We scan each target block.
        n = chain.size()
        for i in range(n):
            use_blk_serial = chain.at(i)
            uses = _scan_block_for_stkvar_uses(mba, use_blk_serial, stkoff, width)
            results.extend(uses)

    # Deduplicate: the same use site may be reported by multiple def blocks.
    seen: set[UseSite] = set()
    deduped: list[UseSite] = []
    for use in results:
        if use not in seen:
            seen.add(use)
            deduped.append(use)

    logger.debug(
        "find_all_uses_of_stkvar: stkoff=0x%x width=%d -> %d unique use sites",
        stkoff,
        width,
        len(deduped),
    )
    return deduped


__all__ = [
    "DefSite",
    "UseSite",
    "collect_pred_defs_for_block",
    "ensure_graph_and_lists_ready",
    "find_all_uses_of_stkvar",
    "find_reaching_defs_for_reg",
    "find_reaching_defs_for_stkvar",
    "get_ud_du_chains",
    "is_passthru_chain",
    "is_phi_like_merge",
]

"""Read-only chain-backed evaluator helpers for Hex-Rays microcode.

All functions in this module are READ-ONLY: they may call mba.build_graph(),
mblock_t.make_lists_ready(), and chain inspection APIs, but MUST NOT mutate
instructions, blocks, or CFG structure.

Allowed:
    - mba.build_graph(), mba.get_graph()
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

from d810.core.logging import getLogger
from d810.core.typing import (
    TYPE_CHECKING,
    NamedTuple,
    Optional,
)

if TYPE_CHECKING:
    pass

logger = getLogger(__name__)

_CHAINS_STUB_WARNING = (
    "chains.py: IDA chain API not available; returning stub result. "
    "Wire in live IDA chain access when integrating with runtime."
)


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


def ensure_graph_and_lists_ready(mba: object) -> None:
    """Prepare the MBA graph and per-block use/def lists (read-only).

    Calls ``mba.build_graph()`` if the graph is not already built, then
    iterates all blocks and calls ``blk.make_lists_ready()`` on each.

    This function is READ-ONLY: it materialises cached internal structures
    but does not mutate instructions, blocks, or CFG edges.

    Args:
        mba: An ``ida_hexrays.mba_t`` instance (typed as ``object`` to
            avoid a hard import dependency on IDA).
    """
    try:
        import ida_hexrays  # noqa: F811
    except ImportError:
        logger.warning(_CHAINS_STUB_WARNING)
        return

    # build_graph is idempotent when the graph is already up-to-date.
    try:
        mba.build_graph()  # type: ignore[attr-defined]
    except Exception:
        logger.debug("ensure_graph_and_lists_ready: build_graph() failed or unavailable")

    qty: int = mba.qty  # type: ignore[attr-defined]
    for i in range(qty):
        blk = mba.get_mblock(i)  # type: ignore[attr-defined]
        try:
            blk.make_lists_ready()
        except Exception:
            logger.debug(
                "ensure_graph_and_lists_ready: make_lists_ready() failed for block %d",
                i,
            )


def get_ud_du_chains(
    mba: object,
    gctype: Optional[int] = None,
) -> tuple[object | None, object | None]:
    """Retrieve use-def and def-use chains from the MBA (read-only).

    Calls ``mba.get_ud()`` and ``mba.get_du()`` to obtain the chain
    objects.  If *gctype* is provided it is currently unused (reserved
    for future IDA API variants that accept a graph-chain type).

    This function is READ-ONLY.

    Args:
        mba: An ``ida_hexrays.mba_t`` instance.
        gctype: Optional graph-chain type constant (e.g.
            ``ida_hexrays.GC_REGS_AND_STKVARS``).  Reserved for future use.

    Returns:
        ``(ud_chains, du_chains)`` tuple.  Returns ``(None, None)`` if
        the chain API is unavailable or chains have not been computed.
    """
    try:
        import ida_hexrays  # noqa: F811
    except ImportError:
        logger.warning(_CHAINS_STUB_WARNING)
        return (None, None)

    try:
        ud = mba.get_ud()  # type: ignore[attr-defined]
        du = mba.get_du()  # type: ignore[attr-defined]
        return (ud, du)
    except (AttributeError, RuntimeError):
        logger.debug("get_ud_du_chains: chain API unavailable on this MBA")
        return (None, None)


def find_reaching_defs_for_reg(
    mba: object,
    blk_serial: int,
    reg_mreg: int,
    size: int,
) -> list[DefSite]:
    """Find all definitions of a register that reach a given block (read-only).

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
    try:
        import ida_hexrays  # noqa: F811
    except ImportError:
        logger.warning(_CHAINS_STUB_WARNING)
        return []

    ud, _ = get_ud_du_chains(mba)
    if ud is None:
        return []

    # Stub: the concrete UD-chain iteration protocol depends on the IDA
    # version's chain_t / graph_chains_t layout.  When wiring to live IDA,
    # iterate ud entries whose use-site matches (blk_serial, reg_mreg, size)
    # and collect corresponding def-sites.
    logger.debug(
        "find_reaching_defs_for_reg: stub — blk=%d mreg=%d size=%d",
        blk_serial,
        reg_mreg,
        size,
    )
    return []


def find_reaching_defs_for_stkvar(
    mba: object,
    blk_serial: int,
    stkoff: int,
    size: int,
) -> list[DefSite]:
    """Find all definitions of a stack variable that reach a given block (read-only).

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
    try:
        import ida_hexrays  # noqa: F811
    except ImportError:
        logger.warning(_CHAINS_STUB_WARNING)
        return []

    ud, _ = get_ud_du_chains(mba)
    if ud is None:
        return []

    # Stub: same as find_reaching_defs_for_reg but for stack variables.
    # Wire in the concrete chain iteration when integrating with live IDA.
    logger.debug(
        "find_reaching_defs_for_stkvar: stub — blk=%d stkoff=0x%x size=%d",
        blk_serial,
        stkoff,
        size,
    )
    return []


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
    try:
        import ida_hexrays  # noqa: F811
    except ImportError:
        logger.warning(_CHAINS_STUB_WARNING)
        return False

    try:
        chf_passthru = ida_hexrays.CHF_PASSTHRU
    except AttributeError:
        logger.debug("is_passthru_chain: CHF_PASSTHRU not available in this IDA version")
        return False

    try:
        return bool(chain.flags & chf_passthru)  # type: ignore[attr-defined]
    except (AttributeError, TypeError):
        return False


def collect_pred_defs_for_block(
    mba: object,
    blk_serial: int,
    target_mreg: Optional[int] = None,
) -> dict[int, list[DefSite]]:
    """Collect DefSites from each predecessor of a block (read-only).

    For each predecessor of *blk_serial*, gathers definitions of
    *target_mreg* (or all registers if ``None``).

    This function is READ-ONLY.

    Args:
        mba: An ``ida_hexrays.mba_t`` instance.
        blk_serial: Serial number of the target block.
        target_mreg: If provided, only collect defs for this micro-register.
            If ``None``, collect defs for all registers.

    Returns:
        ``{pred_serial: [DefSite, ...]}`` mapping.  Empty dict if chains
        are unavailable or the block has no predecessors.
    """
    try:
        import ida_hexrays  # noqa: F811
    except ImportError:
        logger.warning(_CHAINS_STUB_WARNING)
        return {}

    try:
        blk = mba.get_mblock(blk_serial)  # type: ignore[attr-defined]
        pred_serials: list[int] = list(blk.predset)
    except (AttributeError, IndexError):
        return {}

    result: dict[int, list[DefSite]] = {}
    for pred_serial in pred_serials:
        # Stub: in a live IDA environment, walk the UD chains for the
        # predecessor block and collect DefSites matching target_mreg.
        result[pred_serial] = []

    if result:
        logger.debug(
            "collect_pred_defs_for_block: stub — blk=%d preds=%s target_mreg=%s",
            blk_serial,
            list(result.keys()),
            target_mreg,
        )

    return result


def is_phi_like_merge(
    mba: object,
    blk_serial: int,
    mreg: int,
) -> bool:
    """Check if a block is a phi-like merge point for a register (read-only).

    Returns ``True`` if two or more predecessors of *blk_serial* provide
    distinct definitions of *mreg*, indicating a merge point analogous to
    a phi-node in SSA form.

    This function is READ-ONLY.

    Args:
        mba: An ``ida_hexrays.mba_t`` instance.
        blk_serial: Serial number of the target block.
        mreg: Micro-register number to check.

    Returns:
        ``True`` if 2+ predecessors define *mreg* with different DefSites.
        ``False`` if chains are unavailable, the block has fewer than 2
        predecessors, or all predecessors agree on the definition.
    """
    pred_defs = collect_pred_defs_for_block(mba, blk_serial, target_mreg=mreg)
    if len(pred_defs) < 2:
        return False

    # Collect unique DefSite sets across predecessors.
    unique_def_sets: set[frozenset[DefSite]] = set()
    for defs in pred_defs.values():
        unique_def_sets.add(frozenset(defs))

    # If the stub returns empty lists for all preds, they are "equal" (all empty).
    # In a live environment, distinct non-empty sets indicate a phi merge.
    return len(unique_def_sets) >= 2


__all__ = [
    "DefSite",
    "collect_pred_defs_for_block",
    "ensure_graph_and_lists_ready",
    "find_reaching_defs_for_reg",
    "find_reaching_defs_for_stkvar",
    "get_ud_du_chains",
    "is_passthru_chain",
    "is_phi_like_merge",
]

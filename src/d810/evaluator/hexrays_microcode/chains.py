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

import ida_hexrays

from d810.core.logging import getLogger
from d810.core.typing import NamedTuple, Optional

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


def _operand_matches_storage(
    operand,
    *,
    register: int | None,
    stack_offset: int | None,
    size: int,
) -> bool:
    try:
        if int(operand.size) != int(size):
            return False
        if register is not None:
            return bool(
                int(operand.t) == int(ida_hexrays.mop_r)
                and int(operand.r) == int(register)
            )
        if int(operand.t) != int(ida_hexrays.mop_S):
            return False
        stack_reference = getattr(operand, "s", None)
        offset = (
            getattr(stack_reference, "off", None)
            if stack_reference is not None
            else getattr(operand, "stkoff", None)
        )
        return offset is not None and int(offset) == int(stack_offset)
    except (AttributeError, TypeError, ValueError):
        return False


def _operand_storage_access(
    operand,
    *,
    is_target: bool,
    register: int | None,
    stack_offset: int | None,
    size: int,
    seen: set[int],
    depth: int = 0,
) -> tuple[bool, bool]:
    if operand is None or depth > 32 or id(operand) in seen:
        return (False, False)
    seen.add(id(operand))
    if _operand_matches_storage(
        operand,
        register=register,
        stack_offset=stack_offset,
        size=size,
    ):
        return (not is_target, is_target)
    try:
        operand_type = int(operand.t)
    except (AttributeError, TypeError, ValueError):
        return (False, False)

    children: tuple[tuple[object, bool], ...] = ()
    if operand_type == int(ida_hexrays.mop_d):
        nested = getattr(operand, "d", None)
        if nested is not None:
            children = (
                (getattr(nested, "l", None), False),
                (getattr(nested, "r", None), False),
                (getattr(nested, "d", None), True),
            )
    elif operand_type == int(ida_hexrays.mop_a):
        children = ((getattr(operand, "a", None), False),)
    elif operand_type == int(ida_hexrays.mop_f):
        call_info = getattr(operand, "f", None)
        children = tuple(
            (argument, False) for argument in tuple(getattr(call_info, "args", ()))
        )
    elif operand_type == int(ida_hexrays.mop_p):
        pair = getattr(operand, "pair", None)
        children = (
            (getattr(pair, "lop", None), is_target),
            (getattr(pair, "hop", None), is_target),
        )

    has_use = False
    has_definition = False
    for child, child_is_target in children:
        child_use, child_definition = _operand_storage_access(
            child,
            is_target=child_is_target,
            register=register,
            stack_offset=stack_offset,
            size=size,
            seen=set(seen),
            depth=depth + 1,
        )
        has_use = has_use or child_use
        has_definition = has_definition or child_definition
    return (has_use, has_definition)


def _instruction_storage_access(
    instruction,
    *,
    register: int | None = None,
    stack_offset: int | None = None,
    size: int,
) -> tuple[bool, bool]:
    if (register is None) == (stack_offset is None):
        raise ValueError("storage access requires exactly one storage namespace")
    has_use = False
    has_definition = False
    for operand, is_target in (
        (getattr(instruction, "l", None), False),
        (getattr(instruction, "r", None), False),
        (getattr(instruction, "d", None), True),
    ):
        operand_use, operand_definition = _operand_storage_access(
            operand,
            is_target=is_target,
            register=register,
            stack_offset=stack_offset,
            size=size,
            seen=set(),
        )
        has_use = has_use or operand_use
        has_definition = has_definition or operand_definition
    return (has_use, has_definition)


def _block_storage_accesses(
    mba: object,
    block_serial: int,
    *,
    register: int | None = None,
    stack_offset: int | None = None,
    size: int,
) -> tuple[tuple[object, bool, bool], ...]:
    block = mba.get_mblock(int(block_serial))  # type: ignore[attr-defined]
    if block is None:
        return ()
    accesses: list[tuple[object, bool, bool]] = []
    instruction = block.head
    while instruction is not None:
        has_use, has_definition = _instruction_storage_access(
            instruction,
            register=register,
            stack_offset=stack_offset,
            size=size,
        )
        accesses.append((instruction, has_use, has_definition))
        if instruction is block.tail:
            break
        instruction = instruction.next
    return tuple(accesses)


def _instruction_ea(instruction: object) -> int:
    return int(getattr(instruction, "ea", -1))


def _definition_site(block_serial: int, instruction: object) -> DefSite:
    return DefSite(
        block_serial=int(block_serial),
        ins_ea=_instruction_ea(instruction),
        ins_opcode=int(getattr(instruction, "opcode", -1)),
    )


def _use_site(block_serial: int, instruction: object) -> UseSite:
    return UseSite(
        block_serial=int(block_serial),
        ins_ea=_instruction_ea(instruction),
        ins_opcode=int(getattr(instruction, "opcode", -1)),
    )


def _exact_access_index(
    accesses: tuple[tuple[object, bool, bool], ...],
    instruction_ea: int,
    *,
    require_definition: bool,
) -> int | None:
    matches = tuple(
        index
        for index, (instruction, has_use, has_definition) in enumerate(accesses)
        if _instruction_ea(instruction) == int(instruction_ea)
        and (has_definition if require_definition else has_use)
    )
    return matches[0] if len(matches) == 1 else None


def _chain_block_serials(
    mba: object,
    block_serial: int,
    *,
    use_def: bool,
    register: int | None = None,
    stack_offset: int | None = None,
    size: int,
) -> tuple[int, ...]:
    ensure_graph_and_lists_ready(mba)
    ud, du = get_ud_du_chains(mba)
    chains = ud if use_def else du
    if chains is None:
        return ()
    try:
        block_chains = chains[int(block_serial)]  # type: ignore[index]
        chain = (
            block_chains.get_reg_chain(int(register), int(size))
            if register is not None
            else block_chains.get_stk_chain(int(stack_offset), int(size))
        )
        if chain is None:
            return ()
        return tuple(int(chain.at(index)) for index in range(int(chain.size())))
    except (AttributeError, IndexError, RuntimeError, TypeError, ValueError):
        return ()


def _dedupe_sites(sites):
    seen = set()
    result = []
    for site in sites:
        if site not in seen:
            seen.add(site)
            result.append(site)
    return result


def _find_reaching_defs_for_exact_use(
    mba: object,
    block_serial: int,
    use_ea: int,
    *,
    register: int | None = None,
    stack_offset: int | None = None,
    size: int,
) -> list[DefSite]:
    use_accesses = _block_storage_accesses(
        mba,
        block_serial,
        register=register,
        stack_offset=stack_offset,
        size=size,
    )
    use_index = _exact_access_index(
        use_accesses,
        use_ea,
        require_definition=False,
    )
    if use_index is None:
        return []
    for instruction, _has_use, has_definition in reversed(use_accesses[:use_index]):
        if has_definition:
            return [_definition_site(block_serial, instruction)]

    results: list[DefSite] = []
    for definition_block_serial in _chain_block_serials(
        mba,
        block_serial,
        use_def=True,
        register=register,
        stack_offset=stack_offset,
        size=size,
    ):
        definition_accesses = _block_storage_accesses(
            mba,
            definition_block_serial,
            register=register,
            stack_offset=stack_offset,
            size=size,
        )
        for instruction, _has_use, has_definition in reversed(definition_accesses):
            if has_definition:
                results.append(_definition_site(definition_block_serial, instruction))
                break
    return _dedupe_sites(results)


def _find_uses_reached_by_exact_definition(
    mba: object,
    block_serial: int,
    definition_ea: int,
    *,
    register: int | None = None,
    stack_offset: int | None = None,
    size: int,
) -> list[UseSite]:
    definition_accesses = _block_storage_accesses(
        mba,
        block_serial,
        register=register,
        stack_offset=stack_offset,
        size=size,
    )
    definition_index = _exact_access_index(
        definition_accesses,
        definition_ea,
        require_definition=True,
    )
    if definition_index is None:
        return []

    results: list[UseSite] = []
    definition_is_last = True
    for instruction, has_use, has_definition in definition_accesses[
        definition_index + 1 :
    ]:
        if has_use:
            results.append(_use_site(block_serial, instruction))
        if has_definition:
            definition_is_last = False
            break
    if not definition_is_last:
        return _dedupe_sites(results)

    for use_block_serial in _chain_block_serials(
        mba,
        block_serial,
        use_def=False,
        register=register,
        stack_offset=stack_offset,
        size=size,
    ):
        use_accesses = _block_storage_accesses(
            mba,
            use_block_serial,
            register=register,
            stack_offset=stack_offset,
            size=size,
        )
        for instruction, has_use, has_definition in use_accesses:
            if use_block_serial == int(block_serial) and (
                instruction is definition_accesses[definition_index][0]
            ):
                if has_use:
                    results.append(_use_site(use_block_serial, instruction))
                break
            if has_use:
                results.append(_use_site(use_block_serial, instruction))
            if has_definition:
                break
    return _dedupe_sites(results)


def find_reaching_defs_for_reg_use(
    mba: object,
    block_serial: int,
    use_ea: int,
    register: int,
    size: int,
) -> list[DefSite]:
    """Return exact register definitions reaching one unambiguous use anchor."""
    return _find_reaching_defs_for_exact_use(
        mba,
        block_serial,
        use_ea,
        register=register,
        size=size,
    )


def find_reaching_defs_for_stkvar_use(
    mba: object,
    block_serial: int,
    use_ea: int,
    stack_offset: int,
    size: int,
) -> list[DefSite]:
    """Return exact stack definitions reaching one unambiguous use anchor."""
    return _find_reaching_defs_for_exact_use(
        mba,
        block_serial,
        use_ea,
        stack_offset=stack_offset,
        size=size,
    )


def find_uses_reached_by_reg_definition(
    mba: object,
    block_serial: int,
    definition_ea: int,
    register: int,
    size: int,
) -> list[UseSite]:
    """Return exact register uses reached by one unambiguous definition anchor."""
    return _find_uses_reached_by_exact_definition(
        mba,
        block_serial,
        definition_ea,
        register=register,
        size=size,
    )


def find_uses_reached_by_stkvar_definition(
    mba: object,
    block_serial: int,
    definition_ea: int,
    stack_offset: int,
    size: int,
) -> list[UseSite]:
    """Return exact stack uses reached by one unambiguous definition anchor."""
    return _find_uses_reached_by_exact_definition(
        mba,
        block_serial,
        definition_ea,
        stack_offset=stack_offset,
        size=size,
    )


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

    # build_graph is idempotent when the graph is already up-to-date.
    try:
        mba.build_graph()  # type: ignore[attr-defined]
    except Exception:
        logger.debug(
            "ensure_graph_and_lists_ready: build_graph() failed or unavailable"
        )

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
        graph = mba.get_graph()  # type: ignore[attr-defined]
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

    ensure_graph_and_lists_ready(mba)
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

    ensure_graph_and_lists_ready(mba)
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
        return []

    if chain is None:
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

    ensure_graph_and_lists_ready(mba)
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
    "find_reaching_defs_for_reg_use",
    "find_reaching_defs_for_reg",
    "find_reaching_defs_for_stkvar_use",
    "find_reaching_defs_for_stkvar",
    "find_uses_reached_by_reg_definition",
    "find_uses_reached_by_stkvar_definition",
    "get_ud_du_chains",
    "is_passthru_chain",
    "is_phi_like_merge",
]

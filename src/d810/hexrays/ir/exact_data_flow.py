"""Exact read-only live-MBA data-flow queries for fragment validation.

The mutation gateway consumes these queries without crossing into the higher
evaluator layer. Every physical coordinate remains transaction-local, and each
reported block coordinate is paired with an instruction EA.
"""

from __future__ import annotations

import ida_hexrays

from d810.core.logging import getLogger
from d810.core.typing import Mapping, NamedTuple, Optional


logger = getLogger(__name__)


class DefSite(NamedTuple):
    """One live definition coordinate paired with its native EA anchor."""

    block_serial: int
    ins_ea: int
    ins_opcode: int


class UseSite(NamedTuple):
    """One live use coordinate paired with its native EA anchor."""

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


def instruction_storage_access_roles(
    instruction: object,
    *,
    register: int | None = None,
    stack_offset: int | None = None,
    size: int,
) -> tuple[bool, bool]:
    """Classify one SDK instruction as an exact storage use or definition.

    The result is read-only and retains both roles because one microinstruction
    may read and write the same storage location. Detached preparation uses
    this classifier before a planned block has a live MBA serial.
    """
    return _instruction_storage_access(
        instruction,
        register=register,
        stack_offset=stack_offset,
        size=size,
    )


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


def find_exact_storage_access_eas(
    mba: object,
    block_serial: int,
    candidate_eas: tuple[int, ...],
    *,
    register: int | None = None,
    stack_offset: int | None = None,
    size: int,
    require_definition: bool,
) -> tuple[int, ...]:
    """Select candidate instructions with one exact storage access role.

    The returned EAs remain transaction-local. Duplicate physical anchors are
    preserved so the caller can reject ambiguity instead of silently choosing
    one instruction.
    """
    candidates = frozenset(int(candidate_ea) for candidate_ea in candidate_eas)
    if not candidates:
        return ()
    return tuple(
        _instruction_ea(instruction)
        for instruction, has_use, has_definition in _block_storage_accesses(
            mba,
            block_serial,
            register=register,
            stack_offset=stack_offset,
            size=size,
        )
        if _instruction_ea(instruction) in candidates
        and (has_definition if require_definition else has_use)
    )


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


def _last_unambiguous_definition(
    accesses: tuple[tuple[object, bool, bool], ...],
) -> tuple[object | None, bool]:
    definitions = tuple(
        instruction
        for instruction, _has_use, has_definition in accesses
        if has_definition
    )
    if not definitions:
        return (None, False)
    candidate = definitions[-1]
    candidate_ea = _instruction_ea(candidate)
    ambiguous = (
        sum(_instruction_ea(instruction) == candidate_ea for instruction in definitions)
        != 1
    )
    return (candidate, ambiguous)


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
        return tuple(
            dict.fromkeys(int(chain.at(index)) for index in range(int(chain.size())))
        )
    except (AttributeError, IndexError, RuntimeError, TypeError, ValueError):
        return ()


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
    local_definition, ambiguous = _last_unambiguous_definition(use_accesses[:use_index])
    if ambiguous:
        return []
    if local_definition is not None:
        return [_definition_site(block_serial, local_definition)]

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
        definition, ambiguous = _last_unambiguous_definition(definition_accesses)
        if ambiguous:
            return []
        if definition is not None:
            results.append(_definition_site(definition_block_serial, definition))
    return results


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
        return results

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
    return results


def _find_reaching_defs_for_projected_exact_use(
    mba: object,
    block_serial: int,
    use_ea: int,
    predecessor_serials_by_block: Mapping[int, tuple[int, ...]],
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
    local_definition, ambiguous = _last_unambiguous_definition(use_accesses[:use_index])
    if ambiguous:
        return []
    if local_definition is not None:
        return [_definition_site(block_serial, local_definition)]

    results: list[DefSite] = []
    visited: set[int] = set()
    pending = list(predecessor_serials_by_block.get(int(block_serial), ()))
    while pending:
        predecessor_serial = int(pending.pop(0))
        if predecessor_serial in visited:
            continue
        visited.add(predecessor_serial)
        accesses = _block_storage_accesses(
            mba,
            predecessor_serial,
            register=register,
            stack_offset=stack_offset,
            size=size,
        )
        definition, ambiguous = _last_unambiguous_definition(accesses)
        if ambiguous:
            return []
        if definition is not None:
            results.append(_definition_site(predecessor_serial, definition))
            continue
        pending.extend(predecessor_serials_by_block.get(predecessor_serial, ()))
    return results


def _find_uses_reached_by_projected_exact_definition(
    mba: object,
    block_serial: int,
    definition_ea: int,
    successor_serials_by_block: Mapping[int, tuple[int, ...]],
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

    def collect_uses_until_definition(
        serial: int,
        accesses: tuple[tuple[object, bool, bool], ...],
    ) -> bool:
        for instruction, has_use, has_definition in accesses:
            if has_use:
                results.append(_use_site(serial, instruction))
            if has_definition:
                return True
        return False

    if collect_uses_until_definition(
        block_serial,
        definition_accesses[definition_index + 1 :],
    ):
        return results

    visited: set[int] = set()
    pending = list(successor_serials_by_block.get(int(block_serial), ()))
    while pending:
        successor_serial = int(pending.pop(0))
        if successor_serial in visited:
            continue
        visited.add(successor_serial)
        accesses = _block_storage_accesses(
            mba,
            successor_serial,
            register=register,
            stack_offset=stack_offset,
            size=size,
        )
        if collect_uses_until_definition(successor_serial, accesses):
            continue
        pending.extend(successor_serials_by_block.get(successor_serial, ()))
    return results


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


def find_reaching_defs_for_reg_use_in_projection(
    mba: object,
    block_serial: int,
    use_ea: int,
    register: int,
    size: int,
    predecessor_serials_by_block: Mapping[int, tuple[int, ...]],
) -> list[DefSite]:
    """Return exact register definitions through unpublished projected edges."""
    return _find_reaching_defs_for_projected_exact_use(
        mba,
        block_serial,
        use_ea,
        predecessor_serials_by_block,
        register=register,
        size=size,
    )


def find_reaching_defs_for_stkvar_use_in_projection(
    mba: object,
    block_serial: int,
    use_ea: int,
    stack_offset: int,
    size: int,
    predecessor_serials_by_block: Mapping[int, tuple[int, ...]],
) -> list[DefSite]:
    """Return exact stack definitions through unpublished projected edges."""
    return _find_reaching_defs_for_projected_exact_use(
        mba,
        block_serial,
        use_ea,
        predecessor_serials_by_block,
        stack_offset=stack_offset,
        size=size,
    )


def find_uses_reached_by_reg_definition_in_projection(
    mba: object,
    block_serial: int,
    definition_ea: int,
    register: int,
    size: int,
    successor_serials_by_block: Mapping[int, tuple[int, ...]],
) -> list[UseSite]:
    """Return exact register uses through unpublished projected edges."""
    return _find_uses_reached_by_projected_exact_definition(
        mba,
        block_serial,
        definition_ea,
        successor_serials_by_block,
        register=register,
        size=size,
    )


def find_uses_reached_by_stkvar_definition_in_projection(
    mba: object,
    block_serial: int,
    definition_ea: int,
    stack_offset: int,
    size: int,
    successor_serials_by_block: Mapping[int, tuple[int, ...]],
) -> list[UseSite]:
    """Return exact stack uses through unpublished projected edges."""
    return _find_uses_reached_by_projected_exact_definition(
        mba,
        block_serial,
        definition_ea,
        successor_serials_by_block,
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


__all__ = [
    "DefSite",
    "UseSite",
    "find_exact_storage_access_eas",
    "find_reaching_defs_for_reg_use",
    "find_reaching_defs_for_reg_use_in_projection",
    "find_reaching_defs_for_stkvar_use",
    "find_reaching_defs_for_stkvar_use_in_projection",
    "find_uses_reached_by_reg_definition",
    "find_uses_reached_by_reg_definition_in_projection",
    "find_uses_reached_by_stkvar_definition",
    "find_uses_reached_by_stkvar_definition_in_projection",
    "instruction_storage_access_roles",
]

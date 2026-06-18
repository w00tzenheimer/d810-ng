from __future__ import annotations

from collections import deque

import ida_hexrays

from d810.core import getLogger, typing

main_logger = getLogger("D810")


def prune_unreachable_condition_chain(
    mba: ida_hexrays.mbl_array_t,
    block_optimizer: typing.Any,
) -> int:
    """Diagnostic: identify condition-chain blocks proven unreachable by Hodur.

    Reads condition-chain block EAs persisted by HodurUnflattener during optblock pass
    and re-maps them to current serials (IDA renumbers blocks between
    maturities so GLBOPT1 serials are stale by hxe_glbopt time).

    Block removal is currently disabled; see BLOCKED comment near the end.
    Always returns 0.
    """
    if block_optimizer is None:
        main_logger.debug("PruneUnreachable: no block_optimizer")
        return 0

    # Find HodurUnflattener instance(s) with stored condition-chain data
    condition_chain_block_eas: set[int] = set()
    dispatcher_ea: int = 0
    for rule in block_optimizer.cfg_rules:
        has_attr = hasattr(rule, '_last_condition_chain_block_eas')
        if has_attr:
            main_logger.info(
                "PruneUnreachable: found rule %s, _last_condition_chain_block_eas=%d, "
                "_last_func_ea=%s, mba.entry_ea=%s",
                type(rule).__name__,
                len(getattr(rule, '_last_condition_chain_block_eas', set())),
                hex(getattr(rule, '_last_func_ea', 0)),
                hex(mba.entry_ea),
            )
        if (
            has_attr
            and getattr(rule, '_last_condition_chain_block_eas', set())
            and hasattr(rule, '_last_func_ea')
            and rule._last_func_ea == mba.entry_ea
        ):
            condition_chain_block_eas = rule._last_condition_chain_block_eas
            dispatcher_ea = getattr(rule, '_last_dispatcher_ea', 0)
            # Clear after use (one-shot)
            rule._last_condition_chain_block_eas = set()
            rule._last_dispatcher_ea = 0
            # Also clear legacy serial fields
            rule._last_condition_chain_serials = None
            rule._last_dispatcher_serial = -1
            break

    if not condition_chain_block_eas:
        main_logger.info("PruneUnreachable: no pending condition-chain block EAs for %s", hex(mba.entry_ea))
        return 0

    # Re-map EAs to current block serials
    ea_to_serial: dict[int, int] = {}
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk is not None:
            ea_to_serial[blk.start] = i

    current_condition_chain_serials: set[int] = {
        ea_to_serial[ea] for ea in condition_chain_block_eas if ea in ea_to_serial
    }
    current_dispatcher = ea_to_serial.get(dispatcher_ea, -1)

    if not current_condition_chain_serials:
        main_logger.info(
            "PruneUnreachable: EA re-mapping found 0 condition-chain blocks for %s",
            hex(mba.entry_ea),
        )
        return 0

    main_logger.info(
        "PruneUnreachable[glbopt]: re-mapped %d/%d condition-chain block EAs to current serials, "
        "dispatcher EA %s -> serial %s",
        len(current_condition_chain_serials), len(condition_chain_block_eas),
        hex(dispatcher_ea) if dispatcher_ea else "None",
        current_dispatcher if current_dispatcher >= 0 else "None",
    )

    # NOTE: edge severing at hxe_glbopt corrupts IDA (decompilation fails).
    # Only diagnostic BFS follows; no CFG mutations.

    # Forward BFS from block 0 to find reachable blocks
    visited: set[int] = set()
    queue = deque([0])
    while queue:
        serial = queue.popleft()
        if serial in visited:
            continue
        visited.add(serial)
        blk = mba.get_mblock(serial)
        if blk is None:
            continue
        for si in range(blk.nsucc()):
            succ = blk.succ(si)
            if succ not in visited:
                queue.append(succ)

    # Intersect unreachable with current condition-chain serials
    all_serials = set(range(mba.qty))
    unreachable_condition_chain = (all_serials - visited) & current_condition_chain_serials

    if not unreachable_condition_chain:
        main_logger.info(
            "PruneUnreachable[glbopt]: no unreachable condition-chain blocks for %s (dispatcher=%s)",
            hex(mba.entry_ea),
            hex(current_dispatcher) if current_dispatcher >= 0 else "None",
        )
        return 0

    main_logger.info(
        "PruneUnreachable[glbopt]: %d/%d blocks reachable, "
        "%d unreachable condition-chain blocks to prune for %s",
        len(visited), mba.qty, len(unreachable_condition_chain), hex(mba.entry_ea),
    )

    # BLOCKED: remove_block requires zero instruction-level references to target
    # block. TAIL_CHASE_FAILED handler exits still have goto instructions pointing
    # to dispatcher/condition-chain. Until all handler exits are resolved via instruction
    # operand redirects (like hrtng's DGM.ChangeGoto), remove_block will fail
    # with INTERR 51920 regardless of hook type (optblock_t or hxe_glbopt).
    # The diagnostic confirms 77/77 condition-chain blocks unreachable via edge-list BFS.
    return 0

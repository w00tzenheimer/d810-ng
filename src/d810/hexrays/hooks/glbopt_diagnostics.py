from __future__ import annotations

from collections import deque

import ida_hexrays

from d810.core import getLogger, typing
from d810.hexrays.mutation.return_carrier_corruption import (
    CandidateSite,
    find_droppable_return_const_corruptions,
)
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity

main_logger = getLogger("D810")

_RCCC_APPLY = True

_RCCC_MATURITIES = {
    # glbopt() ("microcode global optimization complete") fires once at GLBOPT2 for
    # this pipeline -- the residue created by optimize_global at GLBOPT1 persists
    # into the GLBOPT2 firing. Gate both so the cleanup runs wherever glbopt lands.
    # (Verified live, ticket d81-fzlo: the sub_7FFD residue is caught + removed at
    # maturity=6/GLBOPT2; a GLBOPT1-only gate never fires and disables the fix.)
    ida_hexrays.MMAT_GLBOPT1,
    ida_hexrays.MMAT_GLBOPT2,
}


def _iter_block_insns(blk: ida_hexrays.mblock_t):
    insn = getattr(blk, "head", None)
    while insn is not None:
        yield insn
        insn = getattr(insn, "next", None)


def _find_site_insn(mba: ida_hexrays.mbl_array_t, site: CandidateSite):
    blk = mba.get_mblock(int(site.block_serial))
    if blk is None:
        return None
    for insn in _iter_block_insns(blk):
        if int(getattr(insn, "ea", -1)) == int(site.insn_ea):
            return insn
    return None


def _make_nop(insn) -> None:
    insn.opcode = ida_hexrays.m_nop
    insn.l.erase()
    insn.r.erase()
    insn.d.erase()


def apply_return_const_corruption_cleanup(
    mba: ida_hexrays.mbl_array_t, *, prefold_def_eas: frozenset[int] = frozenset()
) -> int:
    """NOP proven return-register constant corruptions after GLBOPT folding.

    *prefold_def_eas* is the GLBOPT1 pre-fold severance snapshot (ticket d81-fzlo,
    function-keyed on the block optimizer); only defs whose consumer the fold
    actually severed are dropped.
    """
    if mba is None or int(mba.maturity) not in _RCCC_MATURITIES:
        return 0

    sites = find_droppable_return_const_corruptions(
        mba, prefold_def_eas=prefold_def_eas
    )
    if not sites:
        return 0

    main_logger.info(
        "ReturnCarrierCorruption[glbopt]: %d proven droppable site(s) for %s",
        len(sites),
        hex(int(getattr(mba, "entry_ea", 0) or 0)),
    )

    applied = 0
    for site in sites:
        main_logger.info("ReturnCarrierCorruption[glbopt]: %s", site.proof.reason)
        if not _RCCC_APPLY:
            continue
        insn = _find_site_insn(mba, site)
        if insn is None:
            main_logger.warning(
                "ReturnCarrierCorruption[glbopt]: proven site disappeared "
                "before NOP: blk[%d]@%#x",
                site.block_serial,
                site.insn_ea,
            )
            continue
        _make_nop(insn)
        applied += 1

    if applied:
        mba.mark_chains_dirty()
        main_logger.info(
            "ReturnCarrierCorruption[glbopt]: NOPed %d site(s); requesting loop",
            applied,
        )
    return applied


def prune_unreachable_condition_chain(
    mba: ida_hexrays.mbl_array_t,
    block_optimizer: typing.Any,
    *,
    identity_index: typing.Any | None,
) -> int:
    """Diagnostic: identify condition-chain blocks proven unreachable by Hodur.

    Reads condition-chain block EAs persisted by HodurUnflattener during optblock pass
    and rebinds them through the current-MBA identity index (IDA renumbers
    blocks between maturities so GLBOPT1 serials are stale by hxe_glbopt time).

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
        has_attr = hasattr(rule, "_last_condition_chain_block_eas")
        if has_attr:
            main_logger.info(
                "PruneUnreachable: found rule %s, _last_condition_chain_block_eas=%d, "
                "_last_func_ea=%s, mba.entry_ea=%s",
                type(rule).__name__,
                len(getattr(rule, "_last_condition_chain_block_eas", set())),
                hex(getattr(rule, "_last_func_ea", 0)),
                hex(mba.entry_ea),
            )
        if (
            has_attr
            and getattr(rule, "_last_condition_chain_block_eas", set())
            and hasattr(rule, "_last_func_ea")
            and rule._last_func_ea == mba.entry_ea
        ):
            condition_chain_block_eas = rule._last_condition_chain_block_eas
            dispatcher_ea = getattr(rule, "_last_dispatcher_ea", 0)
            # Clear after use (one-shot)
            rule._last_condition_chain_block_eas = set()
            rule._last_dispatcher_ea = 0
            # Also clear legacy serial fields
            rule._last_condition_chain_serials = None
            rule._last_dispatcher_serial = -1
            break

    if not condition_chain_block_eas:
        main_logger.info(
            "PruneUnreachable: no pending condition-chain block EAs for %s",
            hex(mba.entry_ea),
        )
        return 0

    if identity_index is None:
        main_logger.info("PruneUnreachable: no lifecycle-owned identity index")
        return 0

    def rebind_native_ea(ea: int):
        if int(ea) <= 0:
            return None
        identity = StableBlockIdentity.from_intervals(
            (NativeEaInterval(int(ea), int(ea) + 1),),
            native_key=identity_index.native_key,
        )
        return identity_index.rebind_identity(identity).block

    current_condition_chain_blocks = tuple(
        rebound
        for ea in sorted(condition_chain_block_eas)
        if (rebound := rebind_native_ea(int(ea))) is not None
    )
    current_condition_chain_serials = {
        int(block.serial) for block in current_condition_chain_blocks
    }
    current_dispatcher_block = rebind_native_ea(dispatcher_ea)
    current_dispatcher_label = (
        "None"
        if current_dispatcher_block is None
        else "blk[%d]@0x%X"
        % (
            int(current_dispatcher_block.serial),
            int(current_dispatcher_block.anchor_ea or dispatcher_ea),
        )
    )

    if not current_condition_chain_serials:
        main_logger.info(
            "PruneUnreachable: identity rebinding found 0 condition-chain "
            "blocks for %s (missing-or-ambiguous)",
            hex(mba.entry_ea),
        )
        return 0

    main_logger.info(
        "PruneUnreachable[glbopt]: rebound %d/%d condition-chain block "
        "identities, dispatcher=%s",
        len(current_condition_chain_serials),
        len(condition_chain_block_eas),
        current_dispatcher_label,
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
    unreachable_condition_chain = (
        all_serials - visited
    ) & current_condition_chain_serials

    if not unreachable_condition_chain:
        main_logger.info(
            "PruneUnreachable[glbopt]: no unreachable condition-chain blocks for %s (dispatcher=%s)",
            hex(mba.entry_ea),
            current_dispatcher_label,
        )
        return 0

    main_logger.info(
        "PruneUnreachable[glbopt]: %d/%d blocks reachable, "
        "%d unreachable condition-chain blocks to prune for %s",
        len(visited),
        mba.qty,
        len(unreachable_condition_chain),
        hex(mba.entry_ea),
    )

    # BLOCKED: remove_block requires zero instruction-level references to target
    # block. TAIL_CHASE_FAILED handler exits still have goto instructions pointing
    # to dispatcher/condition-chain. Until all handler exits are resolved via instruction
    # operand redirects (like hrtng's DGM.ChangeGoto), remove_block will fail
    # with INTERR 51920 regardless of hook type (optblock_t or hxe_glbopt).
    # The diagnostic confirms 77/77 condition-chain blocks unreachable via edge-list BFS.
    return 0

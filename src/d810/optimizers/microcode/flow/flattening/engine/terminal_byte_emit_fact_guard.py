"""Fact-backed redirect guard for state-indexed terminal-byte hazards.

This guard is the byte-emit analogue of
:mod:`d810.optimizers.microcode.flow.flattening.engine.return_carrier_fact_guard`.
It rejects ``RedirectGoto`` / ``RedirectBranch`` candidates that would
attach a *state-flow scaffolding block* (one that constant-defines the
state variable ``%var_7BC``) as a predecessor of a known
``terminal_tail`` byte-emit destination block.

Why this is necessary
---------------------
On OLLVM-style flattened functions like ``sub_7FFD3338C040`` the
linearized reference contains a state-indexed cascade
``state -> v52[byte_index]``.  When a state-write block H is wired up
as a predecessor of the byte-emit target T, IDA's MMAT_GLBOPT1
finalization sees a widened reaching-def set and folds the per-byte
``v52[k]`` indexed reads into a single rolled ``*v47`` loop, losing the
distinct ``v52[1] / v52[2] / ... / v52[6]`` structure that the
reconstruction pass is trying to preserve.

The guard is deliberately narrow:

* Operates only on ``RedirectGoto`` / ``RedirectBranch`` candidates.
* Skips silently when no validated fact view is attached.
* Restricts concrete target matching to facts with
  ``corridor_role == "terminal_tail"``.  ``guard_only`` rows are not
  treated as byte-emitter destinations; they are consulted only to
  protect the residual-zero early-return successor from being redirected
  into a byte-emitter destination.
* The state-flow scaffolding test is the sole source-side discriminator.
  Without a constant write to the state variable in H, the redirect is
  permitted -- the gate must not over-fire.
"""
from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.cfg.graph_modification import (
    GraphModification,
    RedirectBranch,
    RedirectGoto,
)
from d810.cfg.loop_bound_writer_guard import (
    InsnKindClassifier,
    OperandKindClassifier,
    collect_const_var_refs_in_block,
)
from d810.core import logging
from d810.core.typing import Any
from d810.analyses.control_flow.return_frontier_artifacts import (
    is_protected_non_carrier_return_writer,
)

logger = logging.getLogger("D810.unflat.hodur.terminal_byte_emit_fact_guard")

# State variable whose ``%var_7BC.4`` constant write marks a block as
# state-flow scaffolding for the OLLVM-style flattened functions we
# protect.  Stored lower-cased to match the token format produced by
# :func:`collect_const_var_refs_in_block`.
_STATE_VAR_REF_TOKEN: str = "7bc"


@dataclass(frozen=True)
class TerminalByteEmitFactRejection:
    """One rejected redirect and the fact evidence that rejected it."""

    source_block: int
    target_block: int
    old_target: int
    fact_id: str
    byte_index: int | None
    state_const_writes: tuple[str, ...]
    upstream_byte_emit_ea: int | None
    reason: str
    replacement_target: int | None = None


def _payload(site: Any) -> dict:
    raw = getattr(site, "payload", None)
    if isinstance(raw, dict):
        return raw
    return {}


def _byte_index(site: Any) -> int | None:
    payload = _payload(site)
    raw = payload.get("byte_index")
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _byte_emit_source_ea(site: Any) -> int | None:
    raw = getattr(site, "source_ea", None)
    if raw is None:
        raw = _payload(site).get("block_ea")
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _is_state_flow_scaffolding(
    mba: Any,
    source_block: int,
    *,
    insn_kind_classifier: InsnKindClassifier | None = None,
    operand_kind_classifier: OperandKindClassifier | None = None,
) -> tuple[bool, frozenset[str]]:
    """Return ``(is_scaffolding, const_writes)`` for ``source_block``.

    ``is_scaffolding`` is true iff the source block contains a
    ``m_mov #const, %var_7BC`` write -- the identifying shape of an
    OLLVM state-machine constant write.
    """
    refs = collect_const_var_refs_in_block(
        mba,
        source_block,
        insn_kind_classifier=insn_kind_classifier,
        operand_kind_classifier=operand_kind_classifier,
    )
    return (_STATE_VAR_REF_TOKEN in refs, refs)


def _candidate_pair(mod: GraphModification) -> tuple[int, int, int] | None:
    """Return ``(from_serial, new_target, old_target)`` for redirect mods.

    Returns ``None`` for modifications this guard does not consider --
    the caller must keep them unchanged.
    """
    if not isinstance(mod, (RedirectGoto, RedirectBranch)):
        return None
    try:
        return int(mod.from_serial), int(mod.new_target), int(mod.old_target)
    except (TypeError, ValueError):
        return None


def _iter_block_insns(flow_graph: Any | None, block_serial: int):
    if flow_graph is None:
        return
    get_block = getattr(flow_graph, "get_block", None)
    block = get_block(int(block_serial)) if callable(get_block) else None
    if block is None:
        return
    iter_insns = getattr(block, "iter_insns", None)
    if callable(iter_insns):
        yield from iter_insns()
        return
    yield from getattr(block, "insn_snapshots", ()) or ()


def _insn_slot(insn: Any, slot_name: str) -> Any:
    for name, operand in getattr(insn, "operand_slots", ()) or ():
        if name == slot_name:
            return operand
    return getattr(insn, slot_name, None)


def _stkoff(mop: Any) -> int | None:
    if mop is None:
        return None
    if getattr(mop, "t", None) != int(ida_hexrays.mop_S):
        return None
    stkoff = getattr(mop, "stkoff", None)
    if stkoff is not None:
        return int(stkoff)
    stack_ref = getattr(mop, "s", None)
    stkoff = getattr(stack_ref, "off", None) if stack_ref is not None else None
    return int(stkoff) if stkoff is not None else None


def _const_value(mop: Any) -> int | None:
    if mop is None:
        return None
    if getattr(mop, "t", None) != int(ida_hexrays.mop_n):
        return None
    nnn = getattr(mop, "nnn", None)
    value = getattr(nnn, "value", None) if nnn is not None else None
    if value is not None:
        return int(value)
    value = getattr(mop, "value", None)
    if value is not None and not callable(value):
        return int(value)
    return None


def _mop_text(mop: Any) -> str:
    dstr = getattr(mop, "dstr", None)
    if callable(dstr):
        try:
            return str(dstr())
        except Exception:
            return ""
    if dstr is not None:
        return str(dstr)
    return ""


def _mov_const_to_stack_slot(insn: Any) -> int | None:
    if getattr(insn, "opcode", None) != int(ida_hexrays.m_mov):
        return None
    src = _insn_slot(insn, "l")
    dst = _insn_slot(insn, "d")
    if _const_value(src) is None:
        return None
    return _stkoff(dst)


def _xdu_state_to_stack_slot(insn: Any, *, state_var_token: str) -> int | None:
    if getattr(insn, "opcode", None) != int(ida_hexrays.m_xdu):
        return None
    src = _insn_slot(insn, "l")
    src_stkoff = _stkoff(src)
    dst_stkoff = _stkoff(_insn_slot(insn, "d"))
    if src_stkoff is None or dst_stkoff is None:
        return None
    src_token = f"{src_stkoff:x}".lower()
    src_dstr = _mop_text(src).lower()
    state_var_name = f"%var_{state_var_token.lower()}"
    if src_token != state_var_token and state_var_name not in src_dstr:
        return None
    if src_stkoff == dst_stkoff:
        return None
    return dst_stkoff


def _source_state_return_slot(flow_graph: Any | None, source_block: int) -> int | None:
    for insn in _iter_block_insns(flow_graph, source_block):
        slot = _xdu_state_to_stack_slot(insn, state_var_token=_STATE_VAR_REF_TOKEN)
        if slot is not None:
            return slot
    return None


def _constant_terminal_return_materializer_for_successor(
    flow_graph: Any | None,
    *,
    old_target: int,
    source_block: int,
) -> int | None:
    """Return the unique constant-return sibling that feeds ``old_target``.

    The zero-residual return artifact is a block like ``xdu state_var ->
    return_slot; goto return_suffix``.  Redirecting that artifact into a
    terminal byte-emitter is wrong, but leaving it alone returns the stale
    state value.  In the same return suffix family there is often a sibling
    block that materializes a literal return value into the same return slot,
    then jumps to the same suffix.  When that sibling is unique, it is the
    safe target for the zero-residual artifact path.
    """
    if flow_graph is None:
        return None
    return_slot = _source_state_return_slot(flow_graph, source_block)

    try:
        preds = tuple(int(pred) for pred in flow_graph.predecessors(int(old_target)))
    except Exception:
        suffix_block = getattr(flow_graph, "get_block", lambda _serial: None)(
            int(old_target)
        )
        preds = tuple(int(pred) for pred in getattr(suffix_block, "preds", ()) or ())

    matching_slot_candidates: list[int] = []
    constant_candidates: list[int] = []
    for pred in preds:
        if pred == int(source_block):
            continue
        try:
            succs = tuple(int(succ) for succ in flow_graph.successors(pred))
        except Exception:
            pred_block = getattr(flow_graph, "get_block", lambda _serial: None)(pred)
            succs = tuple(int(succ) for succ in getattr(pred_block, "succs", ()) or ())
        if int(old_target) not in succs:
            continue
        for insn in _iter_block_insns(flow_graph, pred):
            const_slot = _mov_const_to_stack_slot(insn)
            if const_slot is None:
                continue
            constant_candidates.append(pred)
            if return_slot is not None and const_slot == return_slot:
                matching_slot_candidates.append(pred)
            break

    unique = sorted(set(matching_slot_candidates))
    if len(unique) != 1 and return_slot is None:
        unique = sorted(set(constant_candidates))
    if len(unique) != 1:
        return None
    return int(unique[0])


def _replacement_redirect(
    mod: GraphModification,
    *,
    replacement_target: int,
) -> GraphModification:
    if isinstance(mod, RedirectGoto):
        return RedirectGoto(
            from_serial=int(mod.from_serial),
            old_target=int(mod.old_target),
            new_target=int(replacement_target),
        )
    if isinstance(mod, RedirectBranch):
        return RedirectBranch(
            from_serial=int(mod.from_serial),
            old_target=int(mod.old_target),
            new_target=int(replacement_target),
        )
    return mod


def append_protected_non_carrier_return_writer_direct_lowerings(
    modifications: list[GraphModification],
    *,
    mba: Any,
    carrier_facts: tuple[Any, ...],
) -> list[GraphModification]:
    """Keep protected non-carrier return-writer facts observational.

    Protected non-carrier return-frontier facts identify writers that have
    already lost recoverable carrier identity. Rewriting them through a sibling
    constant-return suffix can expose unrelated terminal values, so topology
    stays unchanged until a proof-backed lowering exists for that artifact
    class.
    """
    if not carrier_facts:
        return modifications

    _ = mba
    for fact in carrier_facts:
        if not is_protected_non_carrier_return_writer(fact):
            continue
        try:
            source = int(getattr(fact, "writer_block"))
        except (TypeError, ValueError):
            continue
        logger.info(
            "PROTECTED_NON_CARRIER_RETURN_WRITER_DIRECT_LOWERING_SKIPPED "
            "source=blk[%d] reason=observability_only",
            source,
        )
    return modifications


def filter_terminal_byte_emit_fact_redirects(
    modifications: list[GraphModification],
    *,
    mba: Any,
    fact_view: Any | None,
    dispatcher_serial: int,
    flow_graph: Any | None = None,
    dag_frontier_override_keys: frozenset[tuple[int, int, int]] = frozenset(),
    insn_kind_classifier: InsnKindClassifier | None = None,
    operand_kind_classifier: OperandKindClassifier | None = None,
) -> tuple[list[GraphModification], tuple[TerminalByteEmitFactRejection, ...]]:
    """Reject fact-proven state-flow predecessor injections.

    Both ``RedirectGoto`` and ``RedirectBranch`` candidates are
    considered.  If no validated fact view is attached, the guard is a
    no-op.  ``dispatcher_serial`` is accepted for symmetry with the
    return-carrier guard; the byte-emit guard does not gate on it.
    """
    if fact_view is None:
        return modifications, ()

    sites_for_block = getattr(fact_view, "terminal_byte_emit_sites_for_block", None)
    if not callable(sites_for_block):
        return modifications, ()
    zero_return_sites_for_block = getattr(
        fact_view,
        "terminal_zero_guard_return_sites_for_block",
        None,
    )

    filtered: list[GraphModification] = []
    rejections: list[TerminalByteEmitFactRejection] = []
    for mod in modifications:
        pair = _candidate_pair(mod)
        if pair is None:
            filtered.append(mod)
            continue
        source, target, old_target = pair

        try:
            sites = sites_for_block(target) or ()
        except Exception:
            logger.debug(
                "TERMINAL_BYTE_EMIT_FACT_GUARD: fact query failed for blk[%d]",
                target,
                exc_info=True,
            )
            filtered.append(mod)
            continue
        if not sites:
            filtered.append(mod)
            continue

        zero_return_sites = ()
        if callable(zero_return_sites_for_block):
            try:
                zero_return_sites = zero_return_sites_for_block(source) or ()
            except Exception:
                logger.debug(
                    "TERMINAL_BYTE_EMIT_FACT_GUARD: zero-return fact query failed "
                    "for blk[%d]",
                    source,
                    exc_info=True,
                )
        if zero_return_sites:
            site = zero_return_sites[0]
            fact_id = str(getattr(site, "fact_id", "<unknown>"))
            byte_index = _byte_index(site)
            upstream_ea = _byte_emit_source_ea(site)
            replacement_target = _constant_terminal_return_materializer_for_successor(
                flow_graph,
                old_target=old_target,
                source_block=source,
            )
            rejection = TerminalByteEmitFactRejection(
                source_block=source,
                target_block=target,
                old_target=old_target,
                fact_id=fact_id,
                byte_index=byte_index,
                state_const_writes=(),
                upstream_byte_emit_ea=upstream_ea,
                reason="terminal_zero_guard_return_redirect",
                replacement_target=replacement_target,
            )
            rejections.append(rejection)
            if replacement_target is not None:
                filtered.append(
                    _replacement_redirect(
                        mod,
                        replacement_target=replacement_target,
                    )
                )
                logger.info(
                    "TERMINAL_ZERO_GUARD_RETURN_REDIRECT_RETARGETED "
                    "source=blk[%d] rejected_target=blk[%d] "
                    "replacement_target=blk[%d] old_target=blk[%d] "
                    "fact_id=%s byte_index=%s guard_ea=%s",
                    source,
                    target,
                    replacement_target,
                    old_target,
                    fact_id,
                    byte_index,
                    (
                        f"0x{upstream_ea:x}"
                        if upstream_ea is not None
                        else "<unknown>"
                    ),
                )
            else:
                logger.info(
                    "TERMINAL_ZERO_GUARD_RETURN_REDIRECT_REJECTED "
                    "source=blk[%d] target=blk[%d] old_target=blk[%d] "
                    "fact_id=%s byte_index=%s guard_ea=%s",
                    source,
                    target,
                    old_target,
                    fact_id,
                    byte_index,
                    (
                        f"0x{upstream_ea:x}"
                        if upstream_ea is not None
                        else "<unknown>"
                    ),
                )
            continue

        is_scaffolding, const_refs = _is_state_flow_scaffolding(
            mba,
            source,
            insn_kind_classifier=insn_kind_classifier,
            operand_kind_classifier=operand_kind_classifier,
        )
        if not is_scaffolding:
            filtered.append(mod)
            continue

        if (source, old_target, target) in dag_frontier_override_keys:
            filtered.append(mod)
            site = sites[0]
            fact_id = str(getattr(site, "fact_id", "<unknown>"))
            byte_index = _byte_index(site)
            upstream_ea = _byte_emit_source_ea(site)
            logger.info(
                "TERMINAL_BYTE_EMIT_FACT_REDIRECT_DAG_FRONTIER_OVERRIDDEN "
                "source=blk[%d] target=blk[%d] old_target=blk[%d] "
                "byte_index=%s fact_id=%s state_const_writes=%s "
                "upstream_byte_emit_ea=%s",
                source,
                target,
                old_target,
                byte_index,
                fact_id,
                sorted(const_refs),
                (
                    f"0x{upstream_ea:x}"
                    if upstream_ea is not None
                    else "<unknown>"
                ),
            )
            continue

        # Pick the first matching fact for diagnostics.  All sites for
        # ``target`` share ``corridor_role == "terminal_tail"`` and we
        # only need representative metadata (byte_index + EA).
        site = sites[0]
        fact_id = str(getattr(site, "fact_id", "<unknown>"))
        byte_index = _byte_index(site)
        upstream_ea = _byte_emit_source_ea(site)
        rejection = TerminalByteEmitFactRejection(
            source_block=source,
            target_block=target,
            old_target=old_target,
            fact_id=fact_id,
            byte_index=byte_index,
            state_const_writes=tuple(sorted(const_refs)),
            upstream_byte_emit_ea=upstream_ea,
            reason="state_flow_scaffolding_redirect",
        )
        rejections.append(rejection)
        logger.info(
            "TERMINAL_BYTE_EMIT_FACT_REDIRECT_REJECTED "
            "source=blk[%d] target=blk[%d] old_target=blk[%d] "
            "byte_index=%s fact_id=%s state_const_writes=%s "
            "upstream_byte_emit_ea=%s",
            source,
            target,
            old_target,
            byte_index,
            fact_id,
            list(rejection.state_const_writes),
            (
                f"0x{upstream_ea:x}"
                if upstream_ea is not None
                else "<unknown>"
            ),
        )

    if rejections:
        logger.info(
            "TERMINAL_BYTE_EMIT_FACT_REDIRECT_SUMMARY rejected=%d kept=%d "
            "dispatcher_serial=%d",
            len(rejections),
            len(filtered),
            int(dispatcher_serial),
        )
    return filtered, tuple(rejections)


__all__ = [
    "TerminalByteEmitFactRejection",
    "append_protected_non_carrier_return_writer_direct_lowerings",
    "filter_terminal_byte_emit_fact_redirects",
]

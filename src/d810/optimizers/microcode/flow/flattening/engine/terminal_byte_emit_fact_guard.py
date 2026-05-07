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
* Restricts itself to facts with ``corridor_role == "terminal_tail"`` --
  ``non_terminal_byte_emitter`` and ``guard_only`` are ignored on
  purpose (the bulk emitter ``STATE_2FBA4611`` is non-terminal and must
  not be protected here).
* The state-flow scaffolding test is the sole source-side discriminator.
  Without a constant write to the state variable in H, the redirect is
  permitted -- the gate must not over-fire.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.graph_modification import (
    GraphModification,
    RedirectBranch,
    RedirectGoto,
)
from d810.cfg.loop_bound_writer_guard import collect_const_var_refs_in_block
from d810.core import logging
from d810.core.typing import Any

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


def _is_state_flow_scaffolding(mba: Any, source_block: int) -> tuple[bool, frozenset[str]]:
    """Return ``(is_scaffolding, const_writes)`` for ``source_block``.

    ``is_scaffolding`` is true iff the source block contains a
    ``m_mov #const, %var_7BC`` write -- the identifying shape of an
    OLLVM state-machine constant write.
    """
    refs = collect_const_var_refs_in_block(mba, source_block)
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


def filter_terminal_byte_emit_fact_redirects(
    modifications: list[GraphModification],
    *,
    mba: Any,
    fact_view: Any | None,
    dispatcher_serial: int,
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

        is_scaffolding, const_refs = _is_state_flow_scaffolding(mba, source)
        if not is_scaffolding:
            filtered.append(mod)
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
    "filter_terminal_byte_emit_fact_redirects",
]

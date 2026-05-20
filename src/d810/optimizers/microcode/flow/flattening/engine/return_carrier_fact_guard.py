"""Fact-backed redirect guard for return-carrier hazards.

This guard is deliberately narrow. It consumes only validated
``ReturnCarrierFact`` records (active or stale historical hazards) and rejects
redirects that would introduce constant definitions into a known return-carrier
materialization site. It never rediscovers return-carrier intent from live
microcode when the fact view is absent.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.graph_modification import GraphModification, RedirectGoto
from d810.cfg.loop_bound_writer_guard import (
    InsnKindClassifier,
    OperandKindClassifier,
    collect_const_var_refs_in_block,
)
from d810.core import logging
from d810.core.typing import Any

logger = logging.getLogger("D810.unflat.hodur.return_carrier_fact_guard")


@dataclass(frozen=True)
class ReturnCarrierFactRejection:
    """One rejected redirect and the fact evidence that rejected it."""

    source_block: int
    target_block: int
    hazard_block: int
    old_target: int
    fact_id: str
    fact_status: str
    overlap: tuple[str, ...]
    const_written: tuple[str, ...]
    reason: str = "const_feed"


def _payload(site: Any) -> dict:
    raw = getattr(site, "payload", None)
    if isinstance(raw, dict):
        return raw
    return {}


def _offset_token(value: Any) -> str | None:
    try:
        return f"{int(value):x}"
    except (TypeError, ValueError):
        return None


def _return_carrier_read_refs(site: Any) -> frozenset[str]:
    payload = _payload(site)
    raw_refs = payload.get("upstream_writer_var_refs")
    if not isinstance(raw_refs, (tuple, list)):
        return frozenset()
    refs = {str(ref).lower() for ref in raw_refs if str(ref)}
    for key in (
        "return_slot_stkoff",
        "carrier_dst_stkoff",
        "upstream_writer_dest_stkoff",
    ):
        token = _offset_token(payload.get(key))
        if token is not None:
            refs.discard(token)
    return frozenset(refs)


def _sites_for_block(
    fact_view: Any,
    target_block: int,
) -> tuple[tuple[str, Any], ...]:
    sites: list[tuple[str, Any]] = []
    active = getattr(fact_view, "return_carrier_sites_for_block", None)
    if callable(active):
        try:
            for site in active(target_block) or ():
                sites.append(("active", site))
        except Exception:
            logger.debug(
                "RETURN_CARRIER_FACT_GUARD: active fact query failed for blk[%d]",
                target_block,
                exc_info=True,
            )
    stale = getattr(fact_view, "stale_return_carrier_hazards_for_block", None)
    if callable(stale):
        try:
            for site in stale(target_block) or ():
                sites.append(("stale_hazard", site))
        except Exception:
            logger.debug(
                "RETURN_CARRIER_FACT_GUARD: stale hazard query failed for blk[%d]",
                target_block,
                exc_info=True,
            )
    return tuple(sites)


def _return_writer_sites_for_block(
    fact_view: Any,
    target_block: int,
) -> tuple[tuple[str, Any], ...]:
    try:
        target = int(target_block)
    except (TypeError, ValueError):
        return ()
    sites: list[tuple[str, Any]] = []
    for site in getattr(fact_view, "active_observations", ()) or ():
        if getattr(site, "kind", None) != "ReturnCarrierFact":
            continue
        payload = _payload(site)
        raw = payload.get("block_serial")
        if raw is None:
            continue
        try:
            if int(raw) != target:
                continue
        except (TypeError, ValueError):
            continue
        sites.append(("active_writer", site))
    return tuple(sites)


def _candidate_target_blocks(mba: Any, target_block: int) -> tuple[int, ...]:
    candidates = [target_block]
    try:
        blk = mba.get_mblock(target_block)
    except Exception:
        blk = None
    if blk is None:
        return tuple(candidates)
    try:
        for succ in getattr(blk, "succset", ()):
            succ_int = int(succ)
            if succ_int not in candidates:
                candidates.append(succ_int)
    except Exception:
        logger.debug(
            "RETURN_CARRIER_FACT_GUARD: successor scan failed for blk[%d]",
            target_block,
            exc_info=True,
        )
    return tuple(candidates)


def filter_return_carrier_fact_redirects(
    modifications: list[GraphModification],
    *,
    mba: Any,
    fact_view: Any | None,
    dispatcher_serial: int,
    stale_hazard_override_keys: frozenset[tuple[int, int, int]] = frozenset(),
    reject_carrier_writer_bypass: bool = False,
    insn_kind_classifier: InsnKindClassifier | None = None,
    operand_kind_classifier: OperandKindClassifier | None = None,
) -> tuple[list[GraphModification], tuple[ReturnCarrierFactRejection, ...]]:
    """Reject fact-proven return-carrier constant-feed redirects.

    Only ``RedirectGoto H -> T old=dispatcher`` candidates are considered. If
    no validated fact view is attached, the guard is a no-op.
    """
    if fact_view is None:
        return modifications, ()

    filtered: list[GraphModification] = []
    rejections: list[ReturnCarrierFactRejection] = []
    for mod in modifications:
        if not isinstance(mod, RedirectGoto):
            filtered.append(mod)
            continue
        try:
            source = int(mod.from_serial)
            target = int(mod.new_target)
            old_target = int(mod.old_target)
        except (TypeError, ValueError):
            filtered.append(mod)
            continue
        if dispatcher_serial >= 0 and old_target != int(dispatcher_serial):
            filtered.append(mod)
            continue

        candidate_sites: list[tuple[int, str, Any]] = []
        bypass_sites: list[tuple[int, str, Any]] = []
        seen_bypass_sites: set[tuple[int, str, str]] = set()
        for candidate_target in _candidate_target_blocks(mba, target):
            for fact_status, site in _sites_for_block(fact_view, candidate_target):
                candidate_sites.append((candidate_target, fact_status, site))
                fact_id = str(getattr(site, "fact_id", "<unknown>"))
                seen_bypass_sites.add((candidate_target, fact_status, fact_id))
                bypass_sites.append((candidate_target, fact_status, site))
            if reject_carrier_writer_bypass:
                for fact_status, site in _return_writer_sites_for_block(
                    fact_view,
                    candidate_target,
                ):
                    fact_id = str(getattr(site, "fact_id", "<unknown>"))
                    key = (candidate_target, fact_status, fact_id)
                    if key in seen_bypass_sites:
                        continue
                    seen_bypass_sites.add(key)
                    bypass_sites.append((candidate_target, fact_status, site))
        if not candidate_sites and not bypass_sites:
            filtered.append(mod)
            continue

        const_written = collect_const_var_refs_in_block(
            mba,
            source,
            insn_kind_classifier=insn_kind_classifier,
            operand_kind_classifier=operand_kind_classifier,
        )

        rejected = False
        for hazard_block, fact_status, site in bypass_sites:
            read_refs = _return_carrier_read_refs(site)
            fact_id = str(getattr(site, "fact_id", "<unknown>"))
            override_key = (source, old_target, target)
            if (
                fact_status == "stale_hazard"
                and override_key in stale_hazard_override_keys
            ):
                if const_written and read_refs and (const_written & read_refs):
                    logger.info(
                        "RETURN_CARRIER_FACT_REDIRECT_STALE_HAZARD_OVERRIDDEN "
                        "src=blk[%d] target=blk[%d] hazard=blk[%d] old=blk[%d] "
                        "fact_id=%s overlap=%s const_written=%s",
                        source,
                        target,
                        hazard_block,
                        old_target,
                        fact_id,
                        sorted(const_written & read_refs),
                        sorted(const_written),
                    )
                continue

            if reject_carrier_writer_bypass and int(hazard_block) != source:
                rejection = ReturnCarrierFactRejection(
                    source_block=source,
                    target_block=target,
                    hazard_block=hazard_block,
                    old_target=old_target,
                    fact_id=fact_id,
                    fact_status=fact_status,
                    overlap=(),
                    const_written=tuple(sorted(const_written)),
                    reason="carrier_writer_bypass",
                )
                rejections.append(rejection)
                logger.info(
                    "RECON_REDIRECT_REJECTED_RETURN_CARRIER_BYPASS "
                    "RETURN_CARRIER_FACT_REDIRECT_BYPASS_REJECTED "
                    "src=blk[%d] target=blk[%d] hazard=blk[%d] old=blk[%d] "
                    "fact_id=%s fact_status=%s const_written=%s",
                    source,
                    target,
                    hazard_block,
                    old_target,
                    fact_id,
                    fact_status,
                    list(rejection.const_written),
                )
                rejected = True
                break

            if fact_status == "active_writer":
                continue
            if not const_written or not read_refs:
                continue
            overlap = const_written & read_refs
            if not overlap:
                continue
            rejection = ReturnCarrierFactRejection(
                source_block=source,
                target_block=target,
                hazard_block=hazard_block,
                old_target=old_target,
                fact_id=fact_id,
                fact_status=fact_status,
                overlap=tuple(sorted(overlap)),
                const_written=tuple(sorted(const_written)),
            )
            rejections.append(rejection)
            logger.info(
                "RECON_REDIRECT_REJECTED_RETURN_CARRIER_CONST_FEED "
                "RETURN_CARRIER_FACT_REDIRECT_REJECTED "
                "src=blk[%d] target=blk[%d] hazard=blk[%d] old=blk[%d] fact_id=%s "
                "fact_status=%s overlap=%s const_written=%s",
                source,
                target,
                hazard_block,
                old_target,
                fact_id,
                fact_status,
                list(rejection.overlap),
                list(rejection.const_written),
            )
            rejected = True
            break
        if not rejected:
            filtered.append(mod)
    if reject_carrier_writer_bypass and any(
        rejection.reason == "carrier_writer_bypass" for rejection in rejections
    ):
        return [], tuple(rejections)
    return filtered, tuple(rejections)

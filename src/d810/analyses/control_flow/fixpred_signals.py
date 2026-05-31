"""FixPredSignalsCollector - recon signals for predecessor rewrite safety.

Produces deterministic metrics used by AnalysisPhase to decide the dedicated
``fixpred_gate`` contract independently from unflattening.

Fires at MMAT_CALLS (3) and MMAT_GLBOPT1 (14).

Metrics produced:
    - ``dispatcher_count``: number of detected dispatcher blocks
    - ``strong_dispatcher_count``: dispatchers with >=3 predecessors and >=2 successors
    - ``conditional_dispatcher_count``: BLT_2WAY dispatchers
    - ``switch_dispatcher_count``: BLT_NWAY dispatchers
    - ``unknown_dispatcher_count``: dispatchers of unrecognized type
    - ``max_dispatcher_predecessors``: maximum predecessor count among dispatchers
    - ``mean_dispatcher_predecessors``: mean predecessor count across dispatchers
    - ``ambiguous_dispatcher_count``: dispatchers with unexpected successor counts
    - ``ambiguous_dispatcher_ratio``: ratio of ambiguous to total dispatchers
    - ``predecessor_sample_count``: total predecessor blocks sampled
    - ``predecessor_1way_ratio``: fraction of sampled predecessors that are BLT_1WAY
    - ``predecessor_2way_ratio``: fraction of sampled predecessors that are BLT_2WAY
    - ``predecessor_nway_ratio``: fraction of sampled predecessors that are BLT_NWAY
    - ``state_variable_present``: 1 if a state variable was detected, else 0
    - ``dispatcher_state_constant_total``: unique state constants observed
    - ``dispatcher_type``: canonical dispatcher type string

Candidates:
    - ``"fixpred_high_fanin_dispatcher"`` for each dispatcher when max fan-in >= 3
"""
from __future__ import annotations

import time
from types import MappingProxyType

from d810.core.typing import TYPE_CHECKING

from d810.analyses.control_flow.models import CandidateFlag, ReconResult

if TYPE_CHECKING:
    pass

# IDA maturity constants - duplicated here so this file has no IDA dependency
# at import time. Matches ida_hexrays.MMAT_CALLS / MMAT_GLBOPT1.
_MMAT_CALLS = 3
_MMAT_GLBOPT1 = 14

# Block type constants - duplicated here for import-time safety.
_BLT_1WAY = 3
_BLT_2WAY = 4
_BLT_NWAY = 5


def _ratio(numerator: int, denominator: int) -> float:
    """Safe division returning 0.0 when denominator <= 0."""
    if denominator <= 0:
        return 0.0
    return float(numerator) / float(denominator)


def _canonical_dispatcher_type(raw: object) -> str:
    """Normalize a raw dispatcher type string to a canonical form."""
    text = str(raw or "").strip().upper()
    if text.endswith("CONDITIONAL_CHAIN"):
        return "CONDITIONAL_CHAIN"
    if text.endswith("SWITCH_TABLE"):
        return "SWITCH_TABLE"
    if text.endswith("INDIRECT_JUMP"):
        return "INDIRECT_JUMP"
    return "UNKNOWN"


def _portable_signals(
    target: object,
) -> tuple[dict[str, object], tuple[CandidateFlag, ...]]:
    """Extract fixpred signals from a portable FlowGraph-like snapshot.

    Expects ``target.metadata`` (dict) and ``target.blocks`` (dict mapping
    serial -> block snapshot with ``preds``, ``succs``, ``block_type``).
    """
    metadata = dict(getattr(target, "metadata", {}) or {})
    blocks = dict(getattr(target, "blocks", {}) or {})

    raw_dispatchers = metadata.get("dispatchers")
    if isinstance(raw_dispatchers, (list, tuple, set, frozenset)):
        dispatchers = sorted(
            int(serial) for serial in raw_dispatchers if int(serial) in blocks
        )
    else:
        dispatchers = sorted(
            int(serial)
            for serial, blk in blocks.items()
            if int(getattr(blk, "block_type", 0)) in (_BLT_2WAY, _BLT_NWAY)
            and len(tuple(int(p) for p in getattr(blk, "preds", ()))) >= 2
        )

    if not dispatchers:
        dispatchers = sorted(
            int(serial)
            for serial, blk in blocks.items()
            if len(tuple(int(p) for p in getattr(blk, "preds", ()))) >= 3
        )

    predecessor_sample_count = 0
    predecessor_1way_count = 0
    predecessor_2way_count = 0
    predecessor_nway_count = 0

    max_dispatcher_predecessors = 0
    predecessor_total = 0
    ambiguous_dispatcher_count = 0
    strong_dispatcher_count = 0
    conditional_dispatcher_count = 0
    switch_dispatcher_count = 0

    state_constant_total = 0
    state_var_present = 0

    compare_rows = metadata.get("compare_chain_comparisons", ())
    if isinstance(compare_rows, (list, tuple)) and compare_rows:
        state_var_present = 1
        seen_constants: set[int] = set()
        for row in compare_rows:
            if isinstance(row, dict) and "constant" in row:
                seen_constants.add(int(row["constant"]))
        state_constant_total = len(seen_constants)

    if state_constant_total <= 0:
        raw_state_writes = metadata.get("state_writes", {})
        if isinstance(raw_state_writes, dict):
            flattened: set[int] = set()
            for values in raw_state_writes.values():
                if isinstance(values, (list, tuple)):
                    for value in values:
                        flattened.add(int(value))
            state_constant_total = len(flattened)
            if flattened:
                state_var_present = 1

    for serial in dispatchers:
        blk = blocks.get(int(serial))
        if blk is None:
            continue
        preds = tuple(int(p) for p in getattr(blk, "preds", ()))
        succs = tuple(int(s) for s in getattr(blk, "succs", ()))
        block_type = int(getattr(blk, "block_type", 0))

        pred_count = len(preds)
        predecessor_total += pred_count
        if pred_count > max_dispatcher_predecessors:
            max_dispatcher_predecessors = pred_count

        if block_type == _BLT_2WAY:
            conditional_dispatcher_count += 1
            if len(succs) != 2:
                ambiguous_dispatcher_count += 1
        elif block_type == _BLT_NWAY:
            switch_dispatcher_count += 1
            if len(succs) <= 1:
                ambiguous_dispatcher_count += 1
        else:
            ambiguous_dispatcher_count += 1

        if pred_count >= 3 and len(succs) >= 2:
            strong_dispatcher_count += 1

        for pred_serial in sorted(preds):
            pred_blk = blocks.get(pred_serial)
            if pred_blk is None:
                continue
            predecessor_sample_count += 1
            pred_type = int(getattr(pred_blk, "block_type", 0))
            if pred_type == _BLT_1WAY:
                predecessor_1way_count += 1
            elif pred_type == _BLT_2WAY:
                predecessor_2way_count += 1
            elif pred_type == _BLT_NWAY:
                predecessor_nway_count += 1

    dispatcher_count = len(dispatchers)
    unknown_dispatcher_count = max(
        0,
        dispatcher_count - conditional_dispatcher_count - switch_dispatcher_count,
    )
    mean_dispatcher_predecessors = _ratio(predecessor_total, dispatcher_count)
    ambiguous_dispatcher_ratio = _ratio(ambiguous_dispatcher_count, dispatcher_count)

    metrics: dict[str, object] = {
        "dispatcher_count": dispatcher_count,
        "strong_dispatcher_count": strong_dispatcher_count,
        "conditional_dispatcher_count": conditional_dispatcher_count,
        "switch_dispatcher_count": switch_dispatcher_count,
        "unknown_dispatcher_count": unknown_dispatcher_count,
        "max_dispatcher_predecessors": max_dispatcher_predecessors,
        "mean_dispatcher_predecessors": round(mean_dispatcher_predecessors, 4),
        "ambiguous_dispatcher_count": ambiguous_dispatcher_count,
        "ambiguous_dispatcher_ratio": round(ambiguous_dispatcher_ratio, 4),
        "predecessor_sample_count": predecessor_sample_count,
        "predecessor_1way_ratio": round(
            _ratio(predecessor_1way_count, predecessor_sample_count),
            4,
        ),
        "predecessor_2way_ratio": round(
            _ratio(predecessor_2way_count, predecessor_sample_count),
            4,
        ),
        "predecessor_nway_ratio": round(
            _ratio(predecessor_nway_count, predecessor_sample_count),
            4,
        ),
        "state_variable_present": int(bool(state_var_present)),
        "dispatcher_state_constant_total": int(state_constant_total),
        "dispatcher_type": _canonical_dispatcher_type(
            metadata.get("dispatcher_type", "UNKNOWN")
        ),
    }

    candidates = tuple(
        CandidateFlag(
            kind="fixpred_high_fanin_dispatcher",
            block_serial=int(serial),
            confidence=min(1.0, 0.4 + 0.1 * max_dispatcher_predecessors),
            detail=(
                "dispatcher predecessor fan-in="
                f"{max_dispatcher_predecessors}"
            ),
        )
        for serial in dispatchers
        if max_dispatcher_predecessors >= 3
    )
    return metrics, candidates


# E3-rewire A: ``_live_signals`` was the live-``mba_t`` fallback
# path for this collector.  After E4a, the manager-side recon
# subscriber always invokes ``collect(target=flow_graph, ...)``,
# so the live path is dead code in production.  Re-routing it to
# ``d810.backends.hexrays.evidence.dispatcher.dispatcher_history.analyze_dispatcher_live`` would
# silently put a Hex-Rays import inside ``d810.recon.collectors``
# -- breaking ``recon-core-no-hexrays`` for any future test or
# adapter that pulls collectors from the recon package.  The path
# is therefore removed entirely; ``collect()`` now requires a
# ``FlowGraph``-shaped ``target``.
def _live_signals(
    target: object,
) -> tuple[dict[str, object], tuple[CandidateFlag, ...]]:
    """Extract fixpred signals from a live ``mba_t`` at IDA runtime.

    Uses ``analyze_dispatcher_live`` from the optimizer-layer dispatcher
    module when available; falls back to direct block iteration.
    """
    raise NotImplementedError(  # pragma: no cover - architectural pin
        "FixPredSignalsCollector._live_signals was removed in E3-rewire A. "
        "After E4a the collector always receives a FlowGraph snapshot from "
        "the FLOWGRAPH_READY subscriber on D810.  Reaching this code path "
        "indicates a caller passed a live mba_t instead of a FlowGraph -- "
        "wire the call through the subscriber pattern, or pass "
        "``lift(mba)`` explicitly."
    )


class FixPredSignalsCollector:
    """Collect predecessor-rewrite safety signals for fixpred decisioning.

    Operates on either a portable FlowGraph-like snapshot (for unit tests)
    or a live ``mba_t`` (at IDA runtime). Distinguishes the two by
    duck-typing: if the target has ``blocks`` and ``entry_serial``
    attributes, it is treated as a portable snapshot.
    """

    name: str = "FixPredSignalsCollector"
    maturities: frozenset[int] = frozenset({_MMAT_CALLS, _MMAT_GLBOPT1})
    level: str = "microcode"

    def collect(self, target: object, func_ea: int, maturity: int) -> ReconResult:
        """Collect fixpred safety signals from a portable ``FlowGraph``.

        :param target: Portable ``FlowGraph`` snapshot (after E4a, the
            ``FLOWGRAPH_READY`` subscriber on ``D810`` is the only
            invoker, and it always passes a ``FlowGraph``).  Passing a
            live ``mba_t`` will raise via the architectural-pin
            ``_live_signals`` stub.
        :param func_ea: Function effective address.
        :param maturity: Current maturity level.
        :return: Frozen ``ReconResult`` with fixpred metrics.
        """
        if hasattr(target, "blocks") and hasattr(target, "entry_serial"):
            metrics, candidates = _portable_signals(target)
        else:
            metrics, candidates = _live_signals(target)

        return ReconResult(
            collector_name=self.name,
            func_ea=int(func_ea),
            maturity=int(maturity),
            timestamp=time.time(),
            metrics=MappingProxyType(metrics),
            candidates=candidates,
        )

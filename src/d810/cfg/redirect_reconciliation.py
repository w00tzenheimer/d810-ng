"""Reconciliation between resolver predictions and live strategy emissions.

Piece 5.5 of uee-32r3. Pure-Python, no IDA dependency. Converts the
vague "resolver predicts 50, strategy emits 42" mismatch into a complete
named-bucket accounting that explains every edge.

Three observations per edge:

- ``resolver_target`` — what :func:`resolve_forward_target` predicts (Piece 5).
- ``logged_intent_target`` — what the strategy *intended* to redirect to,
  parsed from ``d810.log``'s ``trampoline skip:`` lines.
- ``persisted_target`` — what actually lives in the diag DB
  ``modifications`` table after the full pipeline runs.

The three views diverge in characteristic ways:

- Strategy logs an intent then the engine drops it for a reason that
  may or may not be logged per-source.
- Resolver predicts an edge the strategy never tried (e.g. a use-def
  veto suppressed it pre-emit).
- Both fire and disagree on the target (DAG canonical wins).

The bucketing here names every divergence so the next behavior step
(Piece 6) can be guarded by the same vocabulary the live pipeline uses.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from d810.core.logging import getLogger
from d810.core.typing import Iterable, Mapping

logger = getLogger(__name__)


class ReconciliationBucket(str, Enum):
    """Named outcome for a reconciliation between resolver and strategy."""

    AGREE_FULL = "AGREE_FULL"
    AGREE_INTENT_DROPPED_DAG = "AGREE_INTENT_DROPPED_DAG"
    AGREE_INTENT_DROPPED_PLANNER_CTX = "AGREE_INTENT_DROPPED_PLANNER_CTX"
    AGREE_INTENT_DROPPED_HCC_DUP_REDIRECT = "AGREE_INTENT_DROPPED_HCC_DUP_REDIRECT"
    AGREE_INTENT_DROPPED_HCC_REGION_HANDLER = "AGREE_INTENT_DROPPED_HCC_REGION_HANDLER"
    AGREE_INTENT_DROPPED_HCC_REGION_PRED = "AGREE_INTENT_DROPPED_HCC_REGION_PRED"
    AGREE_INTENT_DROPPED_HCC_REGION_TARGET = "AGREE_INTENT_DROPPED_HCC_REGION_TARGET"
    AGREE_INTENT_DROPPED_OTHER = "AGREE_INTENT_DROPPED_OTHER"
    RESOLVER_OK_STRATEGY_USE_DEF_VETO = "RESOLVER_OK_STRATEGY_USE_DEF_VETO"
    RESOLVER_ONLY_STRATEGY_DIDNT_LOG = "RESOLVER_ONLY_STRATEGY_DIDNT_LOG"
    DISAGREE_TARGET = "DISAGREE_TARGET"
    STRATEGY_ONLY_RESOLVER_NO_STATE = "STRATEGY_ONLY_RESOLVER_NO_STATE"
    STRATEGY_ONLY_STATE_NOT_IN_BST = "STRATEGY_ONLY_STATE_NOT_IN_BST"
    STRATEGY_ONLY_OTHER = "STRATEGY_ONLY_OTHER"
    BOTH_NONE_NO_STATE = "BOTH_NONE_NO_STATE"
    BOTH_NONE_STATE_NOT_IN_BST = "BOTH_NONE_STATE_NOT_IN_BST"


@dataclass(frozen=True, slots=True)
class StrategyLogSignals:
    """Per-source veto / conflict signals parsed from d810.log.

    The HCC fields capture region-collapse ownership: when HCC composes
    a region around a handler/pred/target, its typed clone or
    InsertBlock+region splice supersedes any plain RedirectGoto from
    later strategies. The trampoline-skip emission is silently dropped
    by intra-fragment dedup.
    """

    prior_use_def_vetoed: frozenset[int]
    dag_disagreement: Mapping[int, tuple[int, int]]
    planner_ctx_conflict: frozenset[int]
    hcc_dup_redirect_sources: frozenset[int] = frozenset()
    hcc_region_anchors: frozenset[int] = frozenset()
    hcc_region_preds: frozenset[int] = frozenset()
    hcc_region_handlers: frozenset[int] = frozenset()


@dataclass(frozen=True, slots=True)
class EdgeReconciliation:
    """One reconciled edge with full evidence trail."""

    src_serial: int
    tgt_serial: int
    bucket: ReconciliationBucket
    resolver_target: int | None
    logged_intent_target: int | None
    persisted_target: int | None
    state_const: int | None
    note: str = ""


@dataclass(frozen=True, slots=True)
class ReconciliationSummary:
    """Aggregated counts and full edge list."""

    edges: tuple[EdgeReconciliation, ...]

    @property
    def bucket_counts(self) -> dict[ReconciliationBucket, int]:
        out: dict[ReconciliationBucket, int] = {}
        for e in self.edges:
            out[e.bucket] = out.get(e.bucket, 0) + 1
        return out

    @property
    def total(self) -> int:
        return len(self.edges)

    @property
    def safe_overlap(self) -> int:
        return self.bucket_counts.get(ReconciliationBucket.AGREE_FULL, 0)


_RX_USE_DEF_VETO = re.compile(
    r"RECON_REDIRECT_REJECTED_PRIOR_USE_DEF_VETO source=blk\[(\d+)\]"
)
_RX_DAG_DISAGREEMENT = re.compile(
    r"src=(\d+) reason=DAG_DISAGREEMENT:\d+->\{planner=(\d+),dag=(\d+)\}"
)
_RX_PLANNER_CTX = re.compile(r"PLANNER_CTX_CONFLICT.*?src=(\d+)")
_RX_LOGGED_INTENT = re.compile(
    r"trampoline skip: blk\[(\d+)\] state=0x([0-9A-Fa-f]+) -> blk\[(\d+)\]"
)
_RX_HCC_INTRA_DUP = re.compile(
    r"intra-fragment duplicates of typed clone on the same source.*?"
    r"RedirectGoto\(src=(\d+) dropped_tgt=\d+\)",
    re.DOTALL,
)
_RX_HCC_REGION_DROP = re.compile(
    r"HandlerChainComposer: dropped \d+ SWR-style mod\(s\) overlapping "
    r"region-collapse anchors=\[([0-9, ]*)\] preds=\[([0-9, ]*)\]"
)
_RX_HCC_COMPOSED_REGION = re.compile(
    r"HandlerChainComposer: composed region pred=(\d+) succ=\d+ "
    r"handlers=\(([0-9, ]+)\)"
)


def _parse_int_list(text: str) -> set[int]:
    return {int(s) for s in text.replace(" ", "").split(",") if s}


def parse_log_signals(log_text: str) -> StrategyLogSignals:
    """Extract per-source veto / conflict signals from d810.log content.

    >>> sig = parse_log_signals("RECON_REDIRECT_REJECTED_PRIOR_USE_DEF_VETO source=blk[42] old_target=blk[2]")
    >>> 42 in sig.prior_use_def_vetoed
    True
    >>> sig = parse_log_signals("ENGINE DAG_GATE: dropped: RedirectGoto(src=110 reason=DAG_DISAGREEMENT:110->{planner=143,dag=142})")
    >>> sig.dag_disagreement[110]
    (143, 142)
    """
    use_def = frozenset(int(m.group(1)) for m in _RX_USE_DEF_VETO.finditer(log_text))
    dag_d: dict[int, tuple[int, int]] = {}
    for m in _RX_DAG_DISAGREEMENT.finditer(log_text):
        dag_d[int(m.group(1))] = (int(m.group(2)), int(m.group(3)))
    planner_ctx = frozenset(
        int(m.group(1)) for m in _RX_PLANNER_CTX.finditer(log_text)
    )
    hcc_dup = frozenset(int(m.group(1)) for m in _RX_HCC_INTRA_DUP.finditer(log_text))
    hcc_anchors: set[int] = set()
    hcc_preds: set[int] = set()
    for m in _RX_HCC_REGION_DROP.finditer(log_text):
        hcc_anchors.update(_parse_int_list(m.group(1)))
        hcc_preds.update(_parse_int_list(m.group(2)))
    hcc_handlers: set[int] = set()
    for m in _RX_HCC_COMPOSED_REGION.finditer(log_text):
        hcc_handlers.update(_parse_int_list(m.group(2)))
    return StrategyLogSignals(
        prior_use_def_vetoed=use_def,
        dag_disagreement=dag_d,
        planner_ctx_conflict=planner_ctx,
        hcc_dup_redirect_sources=hcc_dup,
        hcc_region_anchors=frozenset(hcc_anchors),
        hcc_region_preds=frozenset(hcc_preds),
        hcc_region_handlers=frozenset(hcc_handlers),
    )


def parse_logged_intent(log_text: str) -> dict[int, tuple[int, int]]:
    """Parse ``trampoline skip:`` lines into ``src -> (state, target)``.

    >>> got = parse_logged_intent("trampoline skip: blk[42] state=0x737189D5 -> blk[51]")
    >>> got[42] == (0x737189D5, 51)
    True
    """
    out: dict[int, tuple[int, int]] = {}
    for m in _RX_LOGGED_INTENT.finditer(log_text):
        out[int(m.group(1))] = (int(m.group(2), 16), int(m.group(3)))
    return out


def reconcile_edge(
    *,
    src_serial: int,
    tgt_serial: int,
    resolver_target: int | None,
    logged_intent_target: int | None,
    persisted_target: int | None,
    state_const: int | None,
    state_in_bst: bool,
    log_signals: StrategyLogSignals,
) -> EdgeReconciliation:
    """Bucket one edge from the three observations + log signals.

    Decision order matters: log signals take priority over heuristic
    fallbacks because they are ground truth from the live pipeline.
    """
    bucket: ReconciliationBucket
    note = ""
    rt = resolver_target
    lt = logged_intent_target
    pt = persisted_target

    if rt is not None and lt is not None and rt == lt and pt == rt:
        bucket = ReconciliationBucket.AGREE_FULL
    elif rt is not None and lt is not None and rt == lt and pt is None:
        if src_serial in log_signals.dag_disagreement:
            bucket = ReconciliationBucket.AGREE_INTENT_DROPPED_DAG
            planner, dag = log_signals.dag_disagreement[src_serial]
            note = f"planner={planner} dag={dag}"
        elif src_serial in log_signals.planner_ctx_conflict:
            bucket = ReconciliationBucket.AGREE_INTENT_DROPPED_PLANNER_CTX
        elif src_serial in log_signals.hcc_dup_redirect_sources:
            bucket = ReconciliationBucket.AGREE_INTENT_DROPPED_HCC_DUP_REDIRECT
            note = "intra-fragment dedup vs typed clone on same source"
        elif src_serial in log_signals.hcc_region_handlers:
            bucket = ReconciliationBucket.AGREE_INTENT_DROPPED_HCC_REGION_HANDLER
            note = "src is a handler in an HCC composed region"
        elif src_serial in log_signals.hcc_region_preds:
            bucket = ReconciliationBucket.AGREE_INTENT_DROPPED_HCC_REGION_PRED
            note = "src is a pred in an HCC composed region"
        elif rt in log_signals.hcc_region_anchors:
            bucket = ReconciliationBucket.AGREE_INTENT_DROPPED_HCC_REGION_TARGET
            note = f"intent target {rt} is an HCC region anchor"
        else:
            bucket = ReconciliationBucket.AGREE_INTENT_DROPPED_OTHER
            note = "no per-source drop log line"
    elif rt is not None and lt is not None and rt != lt:
        bucket = ReconciliationBucket.DISAGREE_TARGET
        note = f"resolver={rt} strategy_intent={lt} persisted={pt}"
    elif rt is not None and lt is None:
        if src_serial in log_signals.prior_use_def_vetoed:
            bucket = ReconciliationBucket.RESOLVER_OK_STRATEGY_USE_DEF_VETO
        else:
            bucket = ReconciliationBucket.RESOLVER_ONLY_STRATEGY_DIDNT_LOG
    elif rt is None and lt is not None:
        if state_const is None:
            bucket = ReconciliationBucket.STRATEGY_ONLY_RESOLVER_NO_STATE
        elif not state_in_bst:
            bucket = ReconciliationBucket.STRATEGY_ONLY_STATE_NOT_IN_BST
            note = f"state=0x{state_const:x}"
        else:
            bucket = ReconciliationBucket.STRATEGY_ONLY_OTHER
    else:
        if state_const is None:
            bucket = ReconciliationBucket.BOTH_NONE_NO_STATE
        else:
            bucket = ReconciliationBucket.BOTH_NONE_STATE_NOT_IN_BST
            note = f"state=0x{state_const:x}"

    return EdgeReconciliation(
        src_serial=int(src_serial),
        tgt_serial=int(tgt_serial),
        bucket=bucket,
        resolver_target=rt,
        logged_intent_target=lt,
        persisted_target=pt,
        state_const=state_const,
        note=note,
    )


def reconcile_edges(
    edges: Iterable[tuple[int, int]],
    *,
    resolver_targets: Mapping[tuple[int, int], int | None],
    logged_intent: Mapping[int, tuple[int, int]],
    persisted: Mapping[int, tuple[int | None, int | None]],
    state_consts: Mapping[int, int | None],
    bst_table: Mapping[int, int],
    log_signals: StrategyLogSignals,
) -> ReconciliationSummary:
    """Reconcile every edge from a back-edge list."""
    out: list[EdgeReconciliation] = []
    for src, tgt in edges:
        rt = resolver_targets.get((int(src), int(tgt)))
        li = logged_intent.get(int(src))
        pe = persisted.get(int(src))
        sc = state_consts.get(int(src))
        out.append(
            reconcile_edge(
                src_serial=int(src),
                tgt_serial=int(tgt),
                resolver_target=rt,
                logged_intent_target=li[1] if li else None,
                persisted_target=pe[1] if pe else None,
                state_const=sc,
                state_in_bst=(sc is not None and int(sc) in bst_table),
                log_signals=log_signals,
            )
        )
    return ReconciliationSummary(edges=tuple(out))


def format_summary(summary: ReconciliationSummary) -> str:
    """Render a markdown-style table of bucket counts."""
    counts = summary.bucket_counts
    lines = [
        "| bucket | count |",
        "|-|-|",
    ]
    order = list(ReconciliationBucket)
    for b in order:
        if counts.get(b, 0) > 0:
            lines.append(f"| {b.value} | {counts[b]} |")
    lines.append(f"| TOTAL | {summary.total} |")
    return "\n".join(lines)


__all__ = [
    "EdgeReconciliation",
    "ReconciliationBucket",
    "ReconciliationSummary",
    "StrategyLogSignals",
    "format_summary",
    "parse_log_signals",
    "parse_logged_intent",
    "reconcile_edge",
    "reconcile_edges",
]

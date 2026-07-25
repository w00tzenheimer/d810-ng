'CompareChainCollector - reconstruct compare-chain dispatch mappings.\n\nThin adapter wrapping ``CompareChainResolver`` (cfg.flow.compare_chain) into\nthe ``PreanalysisCollector`` protocol so dispatch-table signals are persisted per\nfunction/maturity.\n\nMetrics:\n    - ``compare_chain_length``: number of block comparisons fed to the resolver\n    - ``dispatch_table_size``: entries in the resolved dispatch table\n    - ``unique_constants``: distinct constant -> target mappings\n    - ``conflicting_count``: constants mapping to multiple targets\n    - ``default_serial``: fallthrough block serial (-1 when absent)\n\nCandidates:\n    - ``"compare_chain_entry"`` per resolved dispatch entry\n'

from __future__ import annotations

import time
from types import MappingProxyType

from d810.analyses.control_flow.compare_chain import (
    BlockComparison,
    CompareChainResolver,
)
from d810.analyses.control_flow.collection_context import (
    PreanalysisCollectionContext,
    coerce_preanalysis_collection_context,
)
from d810.analyses.control_flow.state_var_alias import VarRef
from d810.analyses.control_flow.models import CandidateFlag, PreanalysisResult

# IDA maturity constants - duplicated to avoid IDA import at module level.
_MMAT_CALLS = 3
_MMAT_GLBOPT1 = 14

_BLT_2WAY = 4


def _count_conflicting(
    comparisons: list[BlockComparison],
    aliases: frozenset[VarRef],
) -> int:
    """Count constants that map to more than one target."""
    first_target: dict[int, int] = {}
    conflicts = 0
    for comp in comparisons:
        constant: int | None = None
        var: VarRef | None = None
        if isinstance(comp.lhs, VarRef) and isinstance(comp.rhs, int):
            var, constant = comp.lhs, comp.rhs
        elif isinstance(comp.lhs, int) and isinstance(comp.rhs, VarRef):
            constant, var = comp.lhs, comp.rhs
        if var is None or constant is None or var not in aliases:
            continue
        existing = first_target.get(constant)
        if existing is None:
            first_target[constant] = comp.true_target
        elif existing != comp.true_target:
            conflicts += 1
    return conflicts


def _portable_comparisons(
    target,
) -> tuple[list[BlockComparison], frozenset[VarRef]]:
    """Extract comparisons from a PortableCFG / FlowGraph test fixture.

    Uses ``target.metadata`` if present; otherwise falls back to scanning
    BLT_2WAY blocks.
    """
    metadata = dict(getattr(target, "metadata", {}) or {})
    compare_rows = metadata.get("compare_chain_comparisons", ())
    comparisons: list[BlockComparison] = []
    aliases: set[VarRef] = set()

    for row in compare_rows:
        if not isinstance(row, dict):
            continue
        var = _varref_from_metadata(row.get("var"))
        aliases.add(var)
        comparisons.append(
            BlockComparison(
                block_serial=int(row.get("block_serial", 0)),
                lhs=var,
                rhs=int(row.get("constant", 0)),
                true_target=int(row.get("true_target", 0)),
                false_target=int(row.get("false_target", 0)),
            )
        )

    if comparisons:
        return comparisons, frozenset(aliases)

    # Fallback for synthetic FlowGraph tests with no metadata.
    fallback_var = VarRef("temp", 0, 4)
    for serial, blk in target.blocks.items():
        if int(getattr(blk, "block_type", 0)) != _BLT_2WAY:
            continue
        succs = tuple(int(s) for s in getattr(blk, "succs", ()))
        if len(succs) < 2:
            continue
        comparisons.append(
            BlockComparison(
                block_serial=int(serial),
                lhs=fallback_var,
                rhs=int(serial),
                true_target=succs[0],
                false_target=succs[1],
            )
        )
    return comparisons, frozenset({fallback_var}) if comparisons else frozenset()


def _varref_from_metadata(var_data: dict | None) -> VarRef:
    """Reconstruct a ``VarRef`` from serialized metadata dict."""
    if not isinstance(var_data, dict):
        return VarRef("temp", 0, 4)
    kind = str(var_data.get("kind", "temp"))
    if kind not in {"reg", "stack", "temp"}:
        kind = "temp"
    return VarRef(
        kind, int(var_data.get("identifier", 0)), int(var_data.get("size", 4))
    )


class CompareChainCollector:
    "Collect compare-chain derived dispatch table metrics.\n\n    Wraps ``CompareChainResolver.resolve()`` into the ``PreanalysisCollector``\n    protocol.  Accepts portable ``FlowGraph`` targets from the\n    ``FLOWGRAPH_READY`` preanalysis path.\n"

    name: str = "compare_chain"
    maturities: frozenset[int] = frozenset({_MMAT_CALLS, _MMAT_GLBOPT1})
    level: str = "microcode"

    def collect(
        self,
        target,
        context: PreanalysisCollectionContext | None = None,
        func_ea: int | None = None,
        **legacy_fields: object,
    ) -> PreanalysisResult:
        "Resolve compare-chain and wrap into ``PreanalysisResult``."
        context = coerce_preanalysis_collection_context(
            context,
            func_ea=func_ea,
            legacy_fields=legacy_fields,
        )
        if hasattr(target, "blocks") and hasattr(target, "entry_serial"):
            comparisons, aliases = _portable_comparisons(target)
        else:
            comparisons, aliases = [], frozenset()

        conflicting = _count_conflicting(comparisons, aliases)
        table = CompareChainResolver.resolve(comparisons, aliases)
        table_map = table.as_dict()
        entries = table.entries

        metrics = MappingProxyType(
            {
                "compare_chain_length": len(comparisons),
                "dispatch_table_size": len(entries),
                "unique_constants": len(table_map),
                "conflicting_count": conflicting,
                "default_serial": (
                    int(table.default_serial)
                    if table.default_serial is not None
                    else -1
                ),
            }
        )

        candidates = tuple(
            CandidateFlag(
                kind="compare_chain_entry",
                block_serial=int(entry.source_serial),
                confidence=0.7,
                detail=(f"0x{int(entry.constant):x} -> blk {int(entry.target_serial)}"),
            )
            for entry in table.entries
        )

        return PreanalysisResult(
            collector_name=self.name,
            func_ea=context.func_ea,
            provider_level=context.provider_level,
            timestamp=time.time(),
            metrics=metrics,
            candidates=candidates,
        )

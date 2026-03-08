"""CompareChainCollector - reconstruct compare-chain dispatch mappings.

Thin adapter wrapping ``CompareChainResolver`` (cfg.flow.compare_chain) into
the ``ReconCollector`` protocol so dispatch-table signals are persisted per
function/maturity.

Metrics:
    - ``compare_chain_length``: number of block comparisons fed to the resolver
    - ``dispatch_table_size``: entries in the resolved dispatch table
    - ``unique_constants``: distinct constant -> target mappings
    - ``conflicting_count``: constants mapping to multiple targets
    - ``default_serial``: fallthrough block serial (-1 when absent)

Candidates:
    - ``"compare_chain_entry"`` per resolved dispatch entry
"""
from __future__ import annotations

import time
from types import MappingProxyType

from d810.cfg.flow.compare_chain import (
    BlockComparison,
    CompareChainResolver,
)
from d810.cfg.flow.state_var_alias import VarRef
from d810.recon.models import CandidateFlag, ReconResult

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
    return VarRef(kind, int(var_data.get("identifier", 0)), int(var_data.get("size", 4)))


class CompareChainCollector:
    """Collect compare-chain derived dispatch table metrics.

    Wraps ``CompareChainResolver.resolve()`` into the ``ReconCollector``
    protocol.  Accepts both portable ``FlowGraph`` targets (unit tests) and
    live ``mba_t`` targets (IDA runtime).
    """

    name: str = "compare_chain"
    maturities: frozenset[int] = frozenset({_MMAT_CALLS, _MMAT_GLBOPT1})
    level: str = "microcode"

    def collect(self, target, func_ea: int, maturity: int) -> ReconResult:
        """Resolve compare-chain and wrap into ``ReconResult``."""
        if hasattr(target, "blocks") and hasattr(target, "entry_serial"):
            comparisons, aliases = _portable_comparisons(target)
        else:
            comparisons, aliases = self._live_mba_comparisons(target)

        conflicting = _count_conflicting(comparisons, aliases)
        table = CompareChainResolver.resolve(comparisons, aliases)
        table_map = table.as_dict()

        metrics = MappingProxyType(
            {
                "compare_chain_length": len(comparisons),
                "dispatch_table_size": len(table.entries),
                "unique_constants": len(table_map),
                "conflicting_count": conflicting,
                "default_serial": (
                    int(table.default_serial) if table.default_serial is not None else -1
                ),
            }
        )

        candidates = tuple(
            CandidateFlag(
                kind="compare_chain_entry",
                block_serial=int(entry.source_serial),
                confidence=0.7,
                detail=f"0x{int(entry.constant):x} -> blk {int(entry.target_serial)}",
            )
            for entry in table.entries
        )

        return ReconResult(
            collector_name=self.name,
            func_ea=int(func_ea),
            maturity=int(maturity),
            timestamp=time.time(),
            metrics=metrics,
            candidates=candidates,
        )

    # ------------------------------------------------------------------
    # Live mba_t path (IDA-dependent, guarded import)
    # ------------------------------------------------------------------

    @staticmethod
    def _live_mba_comparisons(
        target,
    ) -> tuple[list[BlockComparison], frozenset[VarRef]]:
        """Extract comparisons from a live ``mba_t`` by scanning 2-way blocks."""
        import ida_hexrays  # type: ignore[import-untyped]

        comparisons: list[BlockComparison] = []
        qty = int(getattr(target, "qty", 0) or 0)
        for i in range(qty):
            blk = target.get_mblock(i)
            if blk is None:
                continue
            if int(getattr(blk, "type", 0)) != int(ida_hexrays.BLT_2WAY):
                continue
            succs = tuple(int(s) for s in getattr(blk, "succset", ()))
            if len(succs) < 2:
                continue
            # Without deeper mop inspection we record a placeholder VarRef.
            comparisons.append(
                BlockComparison(
                    block_serial=int(blk.serial),
                    lhs=VarRef("temp", 0, 4),
                    rhs=int(blk.serial),
                    true_target=succs[0],
                    false_target=succs[1],
                )
            )

        fallback_var = VarRef("temp", 0, 4)
        return comparisons, frozenset({fallback_var}) if comparisons else frozenset()

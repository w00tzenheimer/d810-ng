"""CFG planning for selector/state-machine shell facts."""
from __future__ import annotations

from d810.cfg.flowgraph import FlowGraph
from d810.cfg.graph_modification import GraphModification, RedirectBranch, RedirectGoto
from d810.core.typing import Protocol, Sequence


class SelectorShellEdgeProofLike(Protocol):
    from_serial: int
    old_target: int
    new_target: int


class SelectorShellFactLike(Protocol):
    edge_proofs: Sequence[SelectorShellEdgeProofLike]


def plan_selector_shell_cleanup(
    facts: Sequence[SelectorShellFactLike],
    flow_graph: FlowGraph,
) -> list[GraphModification]:
    """Build backend-neutral redirects for proven selector-shell edges."""
    modifications: list[GraphModification] = []
    seen: set[tuple[int, int, int]] = set()
    for fact in facts:
        for proof in fact.edge_proofs:
            from_serial = int(proof.from_serial)
            old_target = int(proof.old_target)
            new_target = int(proof.new_target)
            key = (from_serial, old_target, new_target)
            if key in seen:
                continue
            block = flow_graph.get_block(from_serial)
            if block is None or old_target not in block.succs:
                continue
            if flow_graph.get_block(new_target) is None:
                continue
            if block.nsucc == 1:
                modifications.append(
                    RedirectGoto(
                        from_serial=from_serial,
                        old_target=old_target,
                        new_target=new_target,
                    )
                )
                seen.add(key)
            elif block.nsucc == 2:
                modifications.append(
                    RedirectBranch(
                        from_serial=from_serial,
                        old_target=old_target,
                        new_target=new_target,
                    )
                )
                seen.add(key)
    return modifications


__all__ = ["plan_selector_shell_cleanup"]

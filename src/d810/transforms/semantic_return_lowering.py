"""Semantic return lowering — one independent terminal return per CONDITIONAL_RETURN edge.

LLVM/LiSA shape: a recovered ``CONDITIONAL_RETURN`` edge is a *semantic terminal* (the handler, at a
branch arm, returns the function's value).  We lower it the way LLVM lowers a return-region and LiSA
models a ret-statement: each terminal becomes a ``ret <value-source>`` at its anchor, lowered
**independently**.  We do NOT clone a shared epilogue across handlers (the flattened-CFG hack the
pre-restructure branch used via ``PrivateTerminalSuffix`` / ``CLONE_MATERIALIZER``), because that
re-creates the shared-suffix fan-in that destroys reducibility and yields ``returns=0``.

The carrier (which value the return yields -- a constant, a stack slot, or the live return register)
is a *data-flow* property, resolved by an injected ``resolve_carrier`` callable (the live
implementation queries reaching definitions of the return register; see the value-range / use-def
capabilities).  This planner is portable and carrier-agnostic: it walks the DAG's return edges and
emits one :class:`TerminalReturnIntent` per anchor the resolver can classify.

Backend materialization (Layer 3) turns each intent into a ``m_ret`` terminator at the anchor; until
that lands these intents are produced + counted for diagnostics but not applied.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.transforms.graph_modification import DirectTerminalLoweringKind

__all__ = ["TerminalReturnIntent", "plan_semantic_returns"]


@dataclass(frozen=True, slots=True)
class TerminalReturnIntent:
    """A direct, corridor-free return at one anchor (the portable terminal spec).

    Attributes:
        anchor_serial: Block whose terminal becomes a return.
        branch_arm: Which arm returns (``None`` for a 1-way/goto anchor).
        kind: Value source -- ``RETURN_CONST`` / ``RETURN_FROM_SLOT`` / ``RETURN_FROM_REG``.
        const_value: The returned constant (``RETURN_CONST``).
        source_stkoff: Stack offset of the returned value (``RETURN_FROM_SLOT``).
        source_mreg: Micro-register holding the returned value (``RETURN_FROM_REG``).
        state: The recovered state constant this terminal belongs to (provenance only).
    """

    anchor_serial: int
    branch_arm: int | None
    kind: DirectTerminalLoweringKind
    const_value: int | None = None
    source_stkoff: int | None = None
    source_mreg: int | None = None
    state: int | None = None


def _edge_kind_name(edge) -> str:
    kind = getattr(edge, "kind", None)
    return getattr(kind, "name", str(kind))


def plan_semantic_returns(dag, *, resolve_carrier) -> tuple[TerminalReturnIntent, ...]:
    """Emit one :class:`TerminalReturnIntent` per resolvable ``CONDITIONAL_RETURN`` edge.

    Args:
        dag: The linearized state DAG (``.edges`` of ``StateDagEdge``).
        resolve_carrier: Callable ``(edge) -> TerminalReturnIntent | None``.  Given a return edge it
            resolves the value source (the carrier); returns ``None`` when it cannot classify the
            anchor (left unlowered -- never guessed).  Injected so the planner stays portable and
            unit-testable with a fake resolver; the live implementation is a data-flow capability.

    Returns:
        One intent per anchor the resolver classified, de-duplicated by ``(anchor, branch_arm)``.
    """
    intents: list[TerminalReturnIntent] = []
    seen: set[tuple[int, int | None]] = set()
    for edge in dag.edges:
        if _edge_kind_name(edge) != "CONDITIONAL_RETURN":
            continue
        anchor = getattr(edge, "source_anchor", None)
        if anchor is None or getattr(anchor, "block_serial", None) is None:
            continue
        intent = resolve_carrier(edge)
        if intent is None:
            continue
        key = (int(intent.anchor_serial), intent.branch_arm)
        if key in seen:
            continue
        seen.add(key)
        intents.append(intent)
    return tuple(intents)

"""DeflattenTerminalsPass — the first LiSA/LLVM-shaped transform pass.

Composes the two de-flatten primitives (tail-dup + DSE) and makes the LLVM pass contract
explicit: ``requires`` (the analyses it consumes), ``invalidates`` vs ``preserves`` (the
fine-grained analysis lifecycle our coarse ``PreservedAnalyses.all()/none()`` cannot express),
and ``run_before_structuring`` (the maturity-timing the lab proved load-bearing). Surfacing
those three is the point — they are the deficiencies in the pass API we're constructing.
"""
from __future__ import annotations

from d810.transforms.deflatten_terminals_pass import (
    DeflattenTerminalsFacts,
    plan_deflatten_terminals,
)
from d810.transforms.graph_modification import DuplicateBlock, NopInstructions


def _facts(**kw) -> DeflattenTerminalsFacts:
    base = dict(
        terminals=(10, 20, 30),
        convergence_block=5,
        return_target=99,
        staging_sites=((10, 0x1000), (20, 0x2000)),
    )
    base.update(kw)
    return DeflattenTerminalsFacts(**base)


def test_combines_tail_dup_per_terminal_and_dse_per_site() -> None:
    plan = plan_deflatten_terminals(_facts())
    dups = [m for m in plan.modifications if isinstance(m, DuplicateBlock)]
    nops = [m for m in plan.modifications if isinstance(m, NopInstructions)]
    assert len(dups) == 3  # one tail-dup per terminal (de-converge)
    assert len(nops) == 2  # one DSE op per staging block (de-stage)
    assert {m.pred_serial for m in dups} == {10, 20, 30}


def test_requires_ownership_and_transitions() -> None:
    plan = plan_deflatten_terminals(_facts())
    assert "BlockOwnership" in plan.requires
    assert "StateTransitions" in plan.requires


def test_preserves_value_analysis_but_invalidates_cfg() -> None:
    # The LLVM granularity our PreservedAnalyses.all()/none() cannot express:
    # tail-dup changes the CFG (invalidate block-keyed analyses) but the state-VALUE
    # lattice is unchanged (preserved). Making this explicit is the deficiency surfaced.
    plan = plan_deflatten_terminals(_facts())
    assert "BlockOwnership" in plan.invalidates        # CFG changed
    assert "StateValueDomain" in plan.preserves         # values unchanged
    assert "StateValueDomain" not in plan.invalidates


def test_must_run_before_structuring() -> None:
    # The maturity-timing the lab proved load-bearing: IDA pre-structures by GLBOPT1,
    # so the pass must run at LOCOPT on the still-flattened shape.
    assert plan_deflatten_terminals(_facts()).run_before_structuring is True


def test_no_terminals_yields_no_tail_dup() -> None:
    plan = plan_deflatten_terminals(_facts(terminals=()))
    assert not any(isinstance(m, DuplicateBlock) for m in plan.modifications)


def test_no_staging_yields_no_dse() -> None:
    plan = plan_deflatten_terminals(_facts(staging_sites=()))
    assert not any(isinstance(m, NopInstructions) for m in plan.modifications)


from d810.transforms.deflatten_terminals_pass import (  # noqa: E402
    deflatten_facts_from_analyses,
)


def _topo(edges):
    preds = {n: [] for n in edges}
    for s, ds in edges.items():
        for d in ds:
            preds.setdefault(d, []).append(s)
    return (lambda n: edges.get(n, [])), (lambda n: preds.get(n, []))


class TestFactExtractionFromAnalyses:
    """Derive the facts by composing BlockOwnership (shared_suffix = convergence) + topology."""

    def test_derives_convergence_and_terminals_from_owners(self) -> None:
        # byte-emits 1,2,3 -> shared_guard 5 -> return 99. Block 5 is owned by >1 handler.
        succ, pred = _topo({1: [5], 2: [5], 3: [5], 5: [99]})
        owners = {1: frozenset({10}), 2: frozenset({20}), 3: frozenset({30}),
                  5: frozenset({10, 20, 30}), 99: frozenset()}
        facts = deflatten_facts_from_analyses(
            owners=owners, successors_of=succ, predecessors_of=pred,
            return_block=99, staging_sites=((1, 0x1000),),
        )
        assert facts is not None
        assert facts.convergence_block == 5
        assert facts.terminals == (1, 2, 3)
        assert facts.return_target == 99
        assert facts.staging_sites == ((1, 0x1000),)

    def test_returns_none_when_no_shared_block_precedes_return(self) -> None:
        succ, pred = _topo({1: [99], 2: [99]})  # no shared fan-in block
        owners = {1: frozenset({10}), 2: frozenset({20}), 99: frozenset()}
        assert deflatten_facts_from_analyses(
            owners=owners, successors_of=succ, predecessors_of=pred, return_block=99,
        ) is None

    def test_exclusive_blocks_are_not_convergence(self) -> None:
        # block 5 precedes return but is owned by ONE handler -> not a convergence.
        succ, pred = _topo({1: [5], 5: [99]})
        owners = {1: frozenset({10}), 5: frozenset({10}), 99: frozenset()}
        assert deflatten_facts_from_analyses(
            owners=owners, successors_of=succ, predecessors_of=pred, return_block=99,
        ) is None

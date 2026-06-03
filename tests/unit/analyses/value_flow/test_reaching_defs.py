"""Reaching-definitions domain over the portable fixpoint engine.

The headline test encodes the sub_7FFD ``0x298372CC`` carrier scenario: at the
aligned terminal the return-slot's only reaching definition is the entry-default
(state) write, while the real carrier (``v49`` = ``a5+0xD0``) still dominates --
exactly the two facts the carrier-delivery fix queries.
"""
from __future__ import annotations

from d810.analyses.data_flow.configuration import Direction, FixpointConfiguration
from d810.analyses.data_flow.worklist import run_fixpoint
from d810.analyses.value_flow.reaching_defs import (
    BlockReachingFacts,
    ReachingDefsDomain,
    reaching_defs_of,
)


def _topology(succ):
    pred: dict[int, set[int]] = {n: set() for n in succ}
    for n, succs in succ.items():
        for s in succs:
            pred.setdefault(s, set()).add(n)
    return (lambda n: succ.get(n, ())), (lambda n: pred.get(n, ()))


def _run(succ, facts):
    succ_of, pred_of = _topology(succ)
    return run_fixpoint(
        ReachingDefsDomain(facts),
        nodes=list(succ),
        entry_nodes=[0],
        successors_of=succ_of,
        predecessors_of=pred_of,
        config=FixpointConfiguration(direction=Direction.FORWARD),
        raise_on_nonconvergence=True,
    )


def test_aligned_terminal_sees_only_entry_default_carrier():
    # 0: entry -> defines ret<-entry-default(state), v49<-dv49
    # 1: aligned terminal (no defs) -> returns ret
    # 2: byte path -> redefines ret<-real
    succ = {0: (1, 2), 1: (), 2: ()}
    facts = {
        0: BlockReachingFacts(
            gen={"ret": frozenset({"d0_state"}), "v49": frozenset({"dv49"})}
        ),
        1: BlockReachingFacts(),
        2: BlockReachingFacts(gen={"ret": frozenset({"d2_real"})}),
    }
    res = _run(succ, facts)
    in1 = res.in_states[1]

    # The leak is detectable: only the entry-default reaches the aligned terminal.
    assert reaching_defs_of(in1, "ret") == frozenset({"d0_state"})
    # ...and the real carrier dominates there -> it is the value to deliver.
    assert reaching_defs_of(in1, "v49") == frozenset({"dv49"})


def test_merge_unions_reaching_defs():
    # diamond: 0 -> {1,2} -> 3; 1 and 2 each redefine x
    succ = {0: (1, 2), 1: (3,), 2: (3,), 3: ()}
    facts = {
        0: BlockReachingFacts(gen={"x": frozenset({"d0"})}),
        1: BlockReachingFacts(gen={"x": frozenset({"d1"})}),
        2: BlockReachingFacts(gen={"x": frozenset({"d2"})}),
        3: BlockReachingFacts(),
    }
    res = _run(succ, facts)
    # At the merge, both branch definitions reach; the entry def is killed on both arms.
    assert reaching_defs_of(res.in_states[3], "x") == frozenset({"d1", "d2"})
    assert res.converged


def test_unkilled_def_dominates_all_blocks():
    succ = {0: (1,), 1: (2,), 2: ()}
    facts = {0: BlockReachingFacts(gen={"g": frozenset({"dg"})})}
    res = _run(succ, facts)
    for node in (1, 2):
        assert reaching_defs_of(res.in_states[node], "g") == frozenset({"dg"})

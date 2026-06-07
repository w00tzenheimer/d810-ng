"""ConcolicTransitionDomain reproduces StateTransitionDomain exactly (ticket llr-mauq).

S2 gate: the new FlowDomain[PartitionedState] (single partition), instantiated with
the existing StateValue powerset as its per-cell value algebra, must produce
byte-identical fixpoint results to StateTransitionDomain on the existing corpus.
The StateValue<->ValueLatticeOps adapter lives here (test-only) so the concolic
package stays decoupled from control_flow.
"""
from __future__ import annotations

from d810.analyses.control_flow.state_transition_domain import (
    StateTransitionDomain,
    StateValue,
)
from d810.analyses.data_flow import run_fixpoint
from d810.analyses.data_flow.concolic import (
    ConcolicTransitionDomain,
    LocationRef,
    PartitionedState,
    PathPredicate,
    TRIVIAL_PATH,
)
from d810.analyses.data_flow.domain import FlowDomain


# -- the StateValue powerset as the per-cell ValueLatticeOps (S2 instantiation) --
class _StateValueOps:
    def bottom(self) -> StateValue:
        return StateValue.bottom()

    def join(self, a: StateValue, b: StateValue) -> StateValue:
        return a.join(b)

    def widen(self, previous: StateValue, current: StateValue) -> StateValue:
        # matches StateTransitionDomain.widen = previous.widen(current) (= join)
        return previous.widen(current)

    def is_bottom(self, value: StateValue) -> bool:
        return value.is_bottom


# -- the existing corpus (mirrors test_state_transition_domain._CFF_*) ----------
_CFF_EDGES = {0: [1], 1: [2, 4], 2: [3], 3: [1], 4: [5, 6], 5: [1], 6: [1], 9: [1]}
_CFF_WRITES = {
    0: StateValue.of(10),
    3: StateValue.of(20),
    5: StateValue.of(30),
    6: StateValue.of(10),
    9: StateValue.of(999),
}
_STATE = LocationRef.stack(0x3C, 4)  # the single tracked dispatcher-state cell


def _topology(edges):
    nodes = set(edges)
    for succs in edges.values():
        nodes.update(succs)
    preds = {n: [] for n in nodes}
    for src, succs in edges.items():
        for dst in succs:
            preds[dst].append(src)
    return nodes, (lambda n: edges.get(n, [])), (lambda n: preds.get(n, []))


def _run_oracle(nodes, succ, pred):
    domain = StateTransitionDomain(_CFF_WRITES)
    return run_fixpoint(
        domain,
        nodes=nodes,
        entry_nodes={0},
        entry_state=StateValue.top(),
        successors_of=succ,
        predecessors_of=pred,
        raise_on_nonconvergence=True,
    )


def _run_concolic(nodes, succ, pred):
    domain = ConcolicTransitionDomain(
        writes={n: {_STATE: sv} for n, sv in _CFF_WRITES.items()},
        vops=_StateValueOps(),
        cells={_STATE},
    )
    return domain, run_fixpoint(
        domain,
        nodes=nodes,
        entry_nodes={0},
        entry_state=PartitionedState.single({_STATE: StateValue.top()}),
        successors_of=succ,
        predecessors_of=pred,
        raise_on_nonconvergence=True,
    )


class TestReproducesStateTransitionDomain:
    def test_byte_identical_in_and_out_states(self) -> None:
        nodes, succ, pred = _topology(_CFF_EDGES)
        oracle = _run_oracle(nodes, succ, pred)
        _, conc = _run_concolic(nodes, succ, pred)
        assert conc.converged is oracle.converged is True
        for n in nodes:
            assert conc.out_states[n].store()[_STATE] == oracle.out_states[n], f"out {n}"
            assert conc.in_states[n].store()[_STATE] == oracle.in_states[n], f"in {n}"

    def test_known_landmarks(self) -> None:
        # the same three assertions the StateTransitionDomain tests make
        nodes, succ, pred = _topology(_CFF_EDGES)
        _, conc = _run_concolic(nodes, succ, pred)
        out = {n: conc.out_states[n].store()[_STATE] for n in nodes}
        assert out[3] == StateValue.of(20)                 # strong update overwrites loop set
        assert out[1].constants == {10, 20, 30}            # dispatcher accumulates (powerset!)
        assert out[9].is_bottom                            # unreachable block stays ⊥


class TestPartitioningAndConformance:
    def test_single_partition_round_trip(self) -> None:
        store = {_STATE: StateValue.of(7)}
        ps = PartitionedState.single(store)
        assert ps.store()[_STATE] == StateValue.of(7)
        assert set(ps.partitions) == {TRIVIAL_PATH}

    def test_path_predicate_assume_extends_conjuncts(self) -> None:
        p = PathPredicate()
        assert p.conjuncts == ()
        p2 = p.assume("c0").assume("c1")
        assert p2.conjuncts == ("c0", "c1")
        assert p != p2 and p == PathPredicate()  # frozen/hashable, value-equal

    def test_is_a_flowdomain(self) -> None:
        domain = ConcolicTransitionDomain(
            writes={}, vops=_StateValueOps(), cells={_STATE}
        )
        assert isinstance(domain, FlowDomain)            # structural (runtime_checkable)
        assert domain.bottom().store()[_STATE].is_bottom  # bottom builds a complete ⊥ store

    def test_confluence_is_cellwise_join(self) -> None:
        domain = ConcolicTransitionDomain(
            writes={}, vops=_StateValueOps(), cells={_STATE}
        )
        left = PartitionedState.single({_STATE: StateValue.of(1)})
        right = PartitionedState.single({_STATE: StateValue.of(2)})
        merged = domain.confluence(left, right)
        assert merged.store()[_STATE] == StateValue.of_many([1, 2])

"""Backward live-variable domain over the portable fixpoint engine.

The headline test encodes the carrier scenario's liveness half: the dispatcher
state variable is dead at the aligned terminal (so NOP-ing its entry-default
write is sound) while it is live on the byte-processing path. Under the engine's
reversed edge relation, ``out_states[node]`` is the block's live-IN.
"""
from __future__ import annotations

from d810.analyses.data_flow.configuration import Direction, FixpointConfiguration
from d810.analyses.data_flow.worklist import run_fixpoint
from d810.analyses.value_flow.liveness import BlockLivenessFacts, LivenessDomain


def _topology(succ):
    pred: dict[int, set[int]] = {n: set() for n in succ}
    for n, succs in succ.items():
        for s in succs:
            pred.setdefault(s, set()).add(n)
    return (lambda n: succ.get(n, ())), (lambda n: pred.get(n, ()))


def _run(succ, facts, exits, live_at_exit):
    succ_of, pred_of = _topology(succ)
    return run_fixpoint(
        LivenessDomain(facts),
        nodes=list(succ),
        entry_nodes=exits,
        entry_state=frozenset(live_at_exit),
        successors_of=succ_of,
        predecessors_of=pred_of,
        config=FixpointConfiguration(direction=Direction.BACKWARD),
        raise_on_nonconvergence=True,
    )


def test_state_var_dead_at_aligned_terminal_live_on_byte_path():
    # 0: entry defines state,v49,ret
    # 1: aligned terminal -> uses only ret (returns it); state NOT used
    # 2: byte path -> uses state and ret, redefines ret
    succ = {0: (1, 2), 1: (), 2: ()}
    facts = {
        0: BlockLivenessFacts(defined=frozenset({"state", "v49", "ret"})),
        1: BlockLivenessFacts(used=frozenset({"ret"})),
        2: BlockLivenessFacts(used=frozenset({"state", "ret"}), defined=frozenset({"ret"})),
    }
    res = _run(succ, facts, exits=[1, 2], live_at_exit={"ret"})

    live_in_aligned = res.out_states[1]
    live_in_bytepath = res.out_states[2]

    # State var is DEAD at the aligned terminal -> entry-default write is removable.
    assert "state" not in live_in_aligned
    assert "ret" in live_in_aligned
    # ...but live on the byte-processing path.
    assert "state" in live_in_bytepath
    # Everything is defined at entry, so nothing is live-in there.
    assert res.out_states[0] == frozenset()
    assert res.converged


def test_use_before_def_keeps_location_live_in():
    succ = {0: (1,), 1: ()}
    facts = {
        0: BlockLivenessFacts(used=frozenset({"x"})),
        1: BlockLivenessFacts(used=frozenset({"y"})),
    }
    res = _run(succ, facts, exits=[1], live_at_exit=set())
    assert res.out_states[0] == frozenset({"x", "y"})

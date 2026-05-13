from __future__ import annotations

from types import SimpleNamespace

from d810.cfg.graph_modification import ZeroStateWrite
from d810.cfg.reconstruction_emission import _collect_zero_state_write_modifications
from d810.cfg.reconstruction_emission_planning import plan_reconstruction_emission


class _DummyBlock:
    def __init__(self, preds: tuple[int, ...], succs: tuple[int, ...]):
        self.preds = preds
        self.succs = succs
        self.npred = len(preds)
        self.nsucc = len(succs)


class _DummyFlowGraph:
    def __init__(self, mapping: dict[int, tuple[tuple[int, ...], tuple[int, ...]]]):
        self._mapping = {
            int(k): _DummyBlock(tuple(int(v) for v in preds), tuple(int(v) for v in succs))
            for k, (preds, succs) in mapping.items()
        }

    def get_block(self, serial: int):
        return self._mapping.get(int(serial))


class TestPlanReconstructionEmission:
    def test_accepts_direct_private_corridor(self):
        flow_graph = _DummyFlowGraph({
            14: ((12,), (16,)),
            16: ((14,), (18,)),
            18: ((16,), (20,)),
        })
        decision = plan_reconstruction_emission(
            flow_graph,
            (14, 16, 18),
            horizon_block=14,
            source_anchor_block=10,
            source_branch_arm=None,
            is_conditional_transition=False,
            shared_suffix_blocks=set(),
            dispatcher_region=set(),
            has_unsafe_trailing_insns=False,
        )
        assert decision.accepted
        assert decision.emission_mode == "direct"
        assert decision.first_shared_block is None

    def test_accepts_conditional_arm_at_branch_horizon(self):
        flow_graph = _DummyFlowGraph({
            14: ((12,), (16, 18)),
        })
        decision = plan_reconstruction_emission(
            flow_graph,
            (14, 16),
            horizon_block=14,
            source_anchor_block=14,
            source_branch_arm=1,
            is_conditional_transition=True,
            shared_suffix_blocks=set(),
            dispatcher_region=set(),
            has_unsafe_trailing_insns=False,
        )
        assert decision.accepted
        assert decision.emission_mode == "conditional_arm"

    def test_falls_back_to_pred_split_for_shared_block(self):
        flow_graph = _DummyFlowGraph({
            12: ((8,), (14,)),
            14: ((12, 13), (16,)),
            16: ((14,), (18,)),
        })
        decision = plan_reconstruction_emission(
            flow_graph,
            (12, 14, 16),
            horizon_block=14,
            source_anchor_block=10,
            source_branch_arm=None,
            is_conditional_transition=False,
            shared_suffix_blocks=set(),
            dispatcher_region=set(),
            has_unsafe_trailing_insns=False,
        )
        assert decision.accepted
        assert decision.emission_mode == "pred_split"
        assert decision.first_shared_block == 14
        assert decision.via_pred == 12

    def test_rejects_when_no_shared_site_and_trailing_effects_exist(self):
        flow_graph = _DummyFlowGraph({
            12: ((8,), (16, 18)),
        })
        decision = plan_reconstruction_emission(
            flow_graph,
            (12, 16),
            horizon_block=12,
            source_anchor_block=10,
            source_branch_arm=None,
            is_conditional_transition=False,
            shared_suffix_blocks=set(),
            dispatcher_region=set(),
            has_unsafe_trailing_insns=True,
        )
        assert not decision.accepted
        assert decision.rejection_reason == "blocked_side_effects"


def _make_zsw_candidate(
    *,
    block_serial: int,
    insn_ea: int,
    horizon_block: int | None = None,
    state_value: int = 0xDEADBEEF,
    ordered_path: tuple[int, ...] = (),
) -> SimpleNamespace:
    """Build a stand-in candidate for ``_collect_zero_state_write_modifications``.

    Mirrors the duck-typed shape the function reads from:
    - ``candidate.site.block_serial`` / ``insn_ea`` / ``state_value``
    - ``candidate.edge.target_state`` / ``observed_target_state`` / ``ordered_path``
    - ``candidate.horizon_block``

    The function also requires ``site.state_value`` to match
    ``edge.target_state`` (or ``edge.observed_target_state``) — both
    fields default to ``state_value`` so emission isn't skipped for
    state-mismatch reasons.
    """
    return SimpleNamespace(
        site=SimpleNamespace(
            block_serial=block_serial,
            insn_ea=insn_ea,
            state_value=state_value,
        ),
        edge=SimpleNamespace(
            target_state=state_value,
            observed_target_state=state_value,
            ordered_path=ordered_path,
        ),
        horizon_block=block_serial if horizon_block is None else horizon_block,
    )


class TestCollectZeroStateWriteDedup:
    """Verifies _collect_zero_state_write_modifications' intra-call dedup
    (uee-y1ko): the planner-level single-owner invariant for ZSW
    construction.

    Background: the function is called multiple times during a single
    ``execute_primary_reconstruction_modifications`` run (once per
    shared group, once per conditional, once per direct, once per
    passthrough — see four call sites in reconstruction_emission.py).
    Each call shares an accumulating ``modifications`` list.  Without
    seeding the ``seen`` set from prior emissions, the same
    ``(block_serial, insn_ea)`` ZSW could be emitted twice if two
    candidate buckets cover overlapping sites.

    Empirically: tracer revealed 47 sub_7FFD blocks where the same
    ``(block, insn_ea)`` ZSW was emitted from multiple collectors.
    The intra-call seed is one half of the fix (the cross-collector
    half is tracked separately under the DAG-as-arbiter ticket).
    """

    def test_dedup_within_a_single_call(self):
        # Two candidates pointing at the same (block, insn_ea) — only
        # one ZSW must be emitted.
        c1 = _make_zsw_candidate(block_serial=10, insn_ea=0x1000)
        c2 = _make_zsw_candidate(block_serial=10, insn_ea=0x1000)
        mods = _collect_zero_state_write_modifications((c1, c2))
        assert len(mods) == 1
        assert mods[0].block_serial == 10
        assert mods[0].insn_ea == 0x1000

    def test_existing_modifications_seed_skips_duplicate(self):
        # Caller already accumulated a ZSW for blk[10] @ 0x1000 from a
        # previous bucket; second call must not re-emit it even though
        # the candidate references the same site.
        prior = (ZeroStateWrite(block_serial=10, insn_ea=0x1000),)
        candidate = _make_zsw_candidate(block_serial=10, insn_ea=0x1000)
        mods = _collect_zero_state_write_modifications(
            (candidate,),
            existing_modifications=prior,
        )
        assert mods == ()

    def test_existing_modifications_seed_allows_distinct_emission(self):
        # Distinct (block, insn_ea) is not blocked by the seed.
        prior = (ZeroStateWrite(block_serial=10, insn_ea=0x1000),)
        candidate = _make_zsw_candidate(block_serial=11, insn_ea=0x2000)
        mods = _collect_zero_state_write_modifications(
            (candidate,),
            existing_modifications=prior,
        )
        assert len(mods) == 1
        assert mods[0].block_serial == 11
        assert mods[0].insn_ea == 0x2000

    def test_existing_modifications_ignores_non_zsw_mods(self):
        # Non-ZSW mods in the existing list must not contribute to the
        # seen set.  Use a stand-in object without block_serial/insn_ea.
        unrelated = SimpleNamespace(some_other_field="value")
        candidate = _make_zsw_candidate(block_serial=10, insn_ea=0x1000)
        mods = _collect_zero_state_write_modifications(
            (candidate,),
            existing_modifications=(unrelated,),
        )
        assert len(mods) == 1

    def test_existing_modifications_seed_works_across_multiple_calls(self):
        # Simulates the four-call pattern in
        # ``execute_primary_reconstruction_modifications``: each call
        # passes the accumulated ``modifications`` list as the seed.
        accumulated: list = []
        # Call 1 (e.g., conditional bucket)
        accumulated.extend(
            _collect_zero_state_write_modifications(
                (_make_zsw_candidate(block_serial=10, insn_ea=0x1000),),
                existing_modifications=accumulated,
            )
        )
        # Call 2 (e.g., direct bucket) - same candidate site
        accumulated.extend(
            _collect_zero_state_write_modifications(
                (_make_zsw_candidate(block_serial=10, insn_ea=0x1000),),
                existing_modifications=accumulated,
            )
        )
        # Call 3 (e.g., shared bucket) - new site
        accumulated.extend(
            _collect_zero_state_write_modifications(
                (_make_zsw_candidate(block_serial=20, insn_ea=0x2000),),
                existing_modifications=accumulated,
            )
        )
        # Final list: one entry per unique (block, insn_ea).
        keys = sorted((m.block_serial, m.insn_ea) for m in accumulated)
        assert keys == [(10, 0x1000), (20, 0x2000)]

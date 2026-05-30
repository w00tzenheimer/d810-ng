"""Tests for the unified ZeroStateWrite collector (Phase 4, uee-rjo8).

Validates the single-emitter consolidation: all three legacy collectors
(``cfg.reconstruction_emission._collect_zero_state_write_modifications``,
``hodur.strategies.linearized_flow_graph._collect_structured_region_zero_state_write_modifications``,
``hodur.strategies.linearized_flow_graph._collect_trivial_redirect_tail_zero_state_write_modifications``)
now delegate through :func:`collect_zero_state_writes`. The tests below
prove behavioural equivalence and the cross-source dedup invariant.
"""
from __future__ import annotations

from types import SimpleNamespace

from d810.transforms.graph_modification import ZeroStateWrite
from d810.transforms.zero_state_write_emission import (
    ZsvSiteRequest,
    ZsvSource,
    candidate_to_site_request,
    collect_zero_state_writes,
)


def _make_candidate(
    *,
    block_serial: int,
    insn_ea: int,
    horizon_block: int | None = None,
    state_value: int = 0xDEADBEEF,
    target_state: int | None = None,
    ordered_path: tuple[int, ...] = (),
) -> SimpleNamespace:
    """Build a stand-in reconstruction candidate.

    Mirrors the duck-typed shape :func:`candidate_to_site_request`
    inspects:
      * ``candidate.site.{block_serial, insn_ea, state_value}``
      * ``candidate.edge.{target_state, observed_target_state, ordered_path}``
      * ``candidate.horizon_block``
    """
    target = state_value if target_state is None else target_state
    return SimpleNamespace(
        site=SimpleNamespace(
            block_serial=block_serial,
            insn_ea=insn_ea,
            state_value=state_value,
        ),
        edge=SimpleNamespace(
            target_state=target,
            observed_target_state=target,
            ordered_path=ordered_path,
        ),
        horizon_block=block_serial if horizon_block is None else horizon_block,
    )


class TestCandidateProjection:
    """Validates ``candidate_to_site_request`` mirrors the legacy
    ``_collect_zero_state_write_modifications`` candidate decoding.
    """

    def test_basic_projection_succeeds(self):
        candidate = _make_candidate(block_serial=10, insn_ea=0x1000)
        request = candidate_to_site_request(candidate)
        assert request is not None
        assert request.block_serial == 10
        assert request.insn_ea == 0x1000
        assert request.site_state == 0xDEADBEEF
        assert (0xDEADBEEF & 0xFFFFFFFF) in request.target_states

    def test_projection_drops_zero_insn_ea(self):
        candidate = _make_candidate(block_serial=10, insn_ea=0)
        assert candidate_to_site_request(candidate) is None

    def test_projection_drops_missing_state(self):
        candidate = _make_candidate(block_serial=10, insn_ea=0x1000)
        candidate.site.state_value = None
        assert candidate_to_site_request(candidate) is None

    def test_projection_drops_pre_horizon_site(self):
        # Site (block_serial=20) sits BEFORE horizon (30) on the path.
        candidate = _make_candidate(
            block_serial=20,
            insn_ea=0x1000,
            horizon_block=30,
            ordered_path=(10, 20, 30, 40),
        )
        assert candidate_to_site_request(candidate) is None

    def test_projection_keeps_post_horizon_site(self):
        # Site (block_serial=40) sits AFTER horizon (30) on the path.
        candidate = _make_candidate(
            block_serial=40,
            insn_ea=0x1000,
            horizon_block=30,
            ordered_path=(10, 20, 30, 40),
        )
        request = candidate_to_site_request(candidate)
        assert request is not None
        assert request.block_serial == 40

    def test_projection_drops_path_disjoint_site(self):
        # Site block not on the ordered_path → drop.
        candidate = _make_candidate(
            block_serial=99,
            insn_ea=0x1000,
            horizon_block=30,
            ordered_path=(10, 20, 30, 40),
        )
        assert candidate_to_site_request(candidate) is None


class TestUnifiedEmitterDedup:
    """Validates :func:`collect_zero_state_writes` enforces the single-
    emitter invariant across all source kinds.
    """

    def test_intra_source_dedup(self):
        # Two requests for the same (block, insn_ea) → 1 emission.
        sites = [
            ZsvSiteRequest(block_serial=10, insn_ea=0x1000),
            ZsvSiteRequest(block_serial=10, insn_ea=0x1000),
        ]
        mods = collect_zero_state_writes(
            source=ZsvSource.from_resolved_sites(sites),
        )
        assert len(mods) == 1
        assert mods[0] == ZeroStateWrite(block_serial=10, insn_ea=0x1000)

    def test_existing_modifications_dedup(self):
        # Prior ZSW in accumulator → second call must skip.
        prior = (ZeroStateWrite(block_serial=10, insn_ea=0x1000),)
        sites = [ZsvSiteRequest(block_serial=10, insn_ea=0x1000)]
        mods = collect_zero_state_writes(
            source=ZsvSource.from_resolved_sites(sites),
            existing_modifications=prior,
        )
        assert mods == ()

    def test_cross_source_dedup_simulating_three_collectors(self):
        # Simulate the original three collectors converging on the same
        # site: structured-region first, then trivial-redirect-tail,
        # then candidate-based. Only one emission, regardless of order.
        accumulated: list = []

        # Source 1: structured region (LFG resolves a path-walked site).
        accumulated.extend(
            collect_zero_state_writes(
                source=ZsvSource.from_resolved_sites(
                    [
                        ZsvSiteRequest(
                            block_serial=10,
                            insn_ea=0x1000,
                            site_state=0xCAFEBABE,
                            target_states=frozenset({0xCAFEBABE}),
                            provenance="lfg_structured_region",
                        )
                    ]
                ),
                existing_modifications=accumulated,
            )
        )
        # Source 2: trivial redirect tail (no target_state filter).
        accumulated.extend(
            collect_zero_state_writes(
                source=ZsvSource.from_resolved_sites(
                    [
                        ZsvSiteRequest(
                            block_serial=10,
                            insn_ea=0x1000,
                            provenance="lfg_trivial_redirect_tail",
                        )
                    ]
                ),
                existing_modifications=accumulated,
            )
        )
        # Source 3: candidate-based (planner-resolved site).
        accumulated.extend(
            collect_zero_state_writes(
                source=ZsvSource.from_candidates(
                    [_make_candidate(block_serial=10, insn_ea=0x1000)],
                    provenance="reconstruction_candidates",
                ),
                existing_modifications=accumulated,
            )
        )
        # Final list: exactly one ZSW for (10, 0x1000).
        assert len(accumulated) == 1
        assert accumulated[0] == ZeroStateWrite(block_serial=10, insn_ea=0x1000)

    def test_distinct_sites_emitted_separately(self):
        # Distinct (block, insn_ea) tuples must all emit.
        sites = [
            ZsvSiteRequest(block_serial=10, insn_ea=0x1000),
            ZsvSiteRequest(block_serial=11, insn_ea=0x2000),
            ZsvSiteRequest(block_serial=12, insn_ea=0x3000),
        ]
        mods = collect_zero_state_writes(
            source=ZsvSource.from_resolved_sites(sites),
        )
        assert len(mods) == 3
        keys = sorted((m.block_serial, m.insn_ea) for m in mods)
        assert keys == [(10, 0x1000), (11, 0x2000), (12, 0x3000)]

    def test_zero_insn_ea_filtered(self):
        # Site with insn_ea == 0 must be silently dropped.
        sites = [ZsvSiteRequest(block_serial=10, insn_ea=0)]
        mods = collect_zero_state_writes(
            source=ZsvSource.from_resolved_sites(sites),
        )
        assert mods == ()

    def test_target_state_mismatch_filtered(self):
        # site_state not in target_states → drop.
        sites = [
            ZsvSiteRequest(
                block_serial=10,
                insn_ea=0x1000,
                site_state=0xAAAA,
                target_states=frozenset({0xBBBB}),
            )
        ]
        mods = collect_zero_state_writes(
            source=ZsvSource.from_resolved_sites(sites),
        )
        assert mods == ()

    def test_empty_target_states_skips_state_check(self):
        # Empty target_states means no state-match filter — used by
        # the dispatcher-redirect tail collector which has no target
        # state handle.
        sites = [
            ZsvSiteRequest(
                block_serial=10,
                insn_ea=0x1000,
                site_state=0xAAAA,
                target_states=frozenset(),
            )
        ]
        mods = collect_zero_state_writes(
            source=ZsvSource.from_resolved_sites(sites),
        )
        assert len(mods) == 1


class TestBehaviouralEquivalenceWithLegacy:
    """Behavioural equivalence regression tests.

    These mirror the test cases in
    ``tests/unit/cfg/test_reconstruction_emission.py::TestCollectZeroStateWriteDedup``
    using the new public surface to prove the legacy callers' invariants
    still hold post-consolidation.
    """

    def test_legacy_intra_call_dedup_preserved(self):
        c1 = _make_candidate(block_serial=10, insn_ea=0x1000)
        c2 = _make_candidate(block_serial=10, insn_ea=0x1000)
        mods = collect_zero_state_writes(
            source=ZsvSource.from_candidates((c1, c2)),
        )
        assert len(mods) == 1
        assert mods[0].block_serial == 10
        assert mods[0].insn_ea == 0x1000

    def test_legacy_existing_modifications_seed_skips_duplicate(self):
        prior = (ZeroStateWrite(block_serial=10, insn_ea=0x1000),)
        candidate = _make_candidate(block_serial=10, insn_ea=0x1000)
        mods = collect_zero_state_writes(
            source=ZsvSource.from_candidates((candidate,)),
            existing_modifications=prior,
        )
        assert mods == ()

    def test_legacy_existing_modifications_seed_allows_distinct_emission(self):
        prior = (ZeroStateWrite(block_serial=10, insn_ea=0x1000),)
        candidate = _make_candidate(block_serial=11, insn_ea=0x2000)
        mods = collect_zero_state_writes(
            source=ZsvSource.from_candidates((candidate,)),
            existing_modifications=prior,
        )
        assert len(mods) == 1
        assert mods[0].block_serial == 11

    def test_legacy_existing_modifications_ignores_non_zsw_mods(self):
        unrelated = SimpleNamespace(some_other_field="value")
        candidate = _make_candidate(block_serial=10, insn_ea=0x1000)
        mods = collect_zero_state_writes(
            source=ZsvSource.from_candidates((candidate,)),
            existing_modifications=(unrelated,),
        )
        assert len(mods) == 1

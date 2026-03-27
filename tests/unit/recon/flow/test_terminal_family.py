from __future__ import annotations

from types import SimpleNamespace

from d810.recon.flow.terminal_family import (
    TerminalFamilyCandidate,
    TerminalFamilySeed,
    candidate_shared_suffix_entries,
    probe_terminal_family_seed,
    resolve_terminal_source_arm_entry,
)


class _DummyBlock:
    def __init__(self, preds: tuple[int, ...], succs: tuple[int, ...], insn_snapshots: tuple[object, ...] = ()):
        self.preds = preds
        self.succs = succs
        self.insn_snapshots = insn_snapshots
        self.npred = len(preds)
        self.nsucc = len(succs)


class _DummyFlowGraph:
    def __init__(self, mapping: dict[int, tuple[tuple[int, ...], tuple[int, ...]]]):
        self.blocks = {
            int(k): _DummyBlock(tuple(int(v) for v in preds), tuple(int(v) for v in succs))
            for k, (preds, succs) in mapping.items()
        }

    def get_block(self, serial: int):
        return self.blocks.get(int(serial))


class TestResolveTerminalSourceArmEntry:
    def test_skips_dispatcher_successor_when_source_is_multiway(self):
        flow_graph = _DummyFlowGraph({
            40: ((12,), (6, 90)),
        })

        assert (
            resolve_terminal_source_arm_entry(
                40,
                None,
                projected_flow_graph=flow_graph,
                dispatcher_region={6},
            )
            == 90
        )


class TestProbeTerminalFamilySeed:
    def test_accepts_linear_terminal_family_seed(self):
        base_flow_graph = _DummyFlowGraph({
            40: ((12,), (90,)),
            90: ((40,), (94,)),
            94: ((90,), ()),
        })
        projected_flow_graph = _DummyFlowGraph({
            40: ((12,), (90,)),
            90: ((40,), (94,)),
            94: ((90,), ()),
        })

        probe = probe_terminal_family_seed(
            TerminalFamilySeed(source_block=40, branch_arm=None, edge=None),
            base_flow_graph=base_flow_graph,
            projected_flow_graph=projected_flow_graph,
            dispatcher_region={6},
            reachable_blocks={40, 90, 94},
        )

        assert probe.rejection_reason == "accepted"
        assert probe.family_entry == 90
        assert probe.path == (90, 94)
        assert probe.stop_block == 94


class TestCandidateSharedSuffixEntries:
    def test_prefers_longest_shared_suffix(self):
        candidates = (
            TerminalFamilyCandidate(
                edge=None,
                source_block=10,
                branch_arm=None,
                family_entry=20,
                path=(20, 30, 40),
                stop_block=40,
                materializer_block=None,
                writer_block=None,
                materializer_chain_blocks=(),
                value_family_signature=("a",),
                lineage_eas=(),
            ),
            TerminalFamilyCandidate(
                edge=None,
                source_block=11,
                branch_arm=None,
                family_entry=21,
                path=(21, 30, 40),
                stop_block=40,
                materializer_block=None,
                writer_block=None,
                materializer_chain_blocks=(),
                value_family_signature=("b",),
                lineage_eas=(),
            ),
        )

        shared = candidate_shared_suffix_entries(candidates)

        assert shared[(10, None, 20, (20, 30, 40))] == 30
        assert shared[(11, None, 21, (21, 30, 40))] == 30

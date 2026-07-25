from __future__ import annotations

from types import SimpleNamespace

from d810.ir.flowgraph import InsnKind, InsnSnapshot, MopSnapshot, OperandKind
from d810.ir.insn_projection import project_instruction_sequence
from d810.ir.expressions import ValueOpKind
from d810.ir.instructions import Instruction
from d810.ir.varnode import Space, Varnode
from d810.analyses.control_flow.terminal_family import (
    TerminalFamilyCandidate,
    TerminalFamilySeed,
    TerminalFamilySeedProbe,
    TerminalValueWrite,
    build_terminal_family_candidates,
    candidate_shared_suffix_entries,
    is_state_var_dest,
    probe_terminal_family_seed,
    resolve_terminal_source_arm_entry,
    resolve_terminal_value_chain,
    seed_terminal_family_probes,
    terminal_varnode_locator_key,
    terminal_varnode_source_signature,
    terminal_value_family_signature,
    terminal_write_signature,
)


class _DummyBlock:
    def __init__(
        self,
        preds: tuple[int, ...],
        succs: tuple[int, ...],
        insn_snapshots: tuple[object, ...] = (),
    ):
        self.preds = preds
        self.succs = succs
        self.insn_snapshots = insn_snapshots
        self.npred = len(preds)
        self.nsucc = len(succs)


class _DummyFlowGraph:
    def __init__(self, mapping: dict[int, tuple[tuple[int, ...], tuple[int, ...]]]):
        self.blocks = {
            int(k): _DummyBlock(
                tuple(int(v) for v in preds), tuple(int(v) for v in succs)
            )
            for k, (preds, succs) in mapping.items()
        }

    def get_block(self, serial: int):
        return self.blocks.get(int(serial))


class _InstructionBlock(_DummyBlock):
    def __init__(
        self,
        preds: tuple[int, ...],
        succs: tuple[int, ...],
        insn_snapshots: tuple[InsnSnapshot, ...],
    ):
        super().__init__(preds, succs, insn_snapshots)

    @property
    def instructions(self):
        return tuple(
            instruction
            for insn in self.insn_snapshots
            for instruction in project_instruction_sequence(insn)
        )


def _const(value: int, *, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.NUMBER, value=int(value), size=size)


def _reg(reg: int, *, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.REGISTER, reg=int(reg), size=size)


def _stack(off: int, *, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.STACK, stkoff=int(off), size=size)


def _mov(src: MopSnapshot, dst: MopSnapshot, *, ea: int) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=0,
        ea=int(ea),
        operands=(src, dst),
        kind=InsnKind.MOV,
        l=src,
        d=dst,
    )


class _DummyDag:
    def __init__(self, edges: tuple[object, ...]):
        self.edges = edges


class TestResolveTerminalSourceArmEntry:
    def test_skips_dispatcher_successor_when_source_is_multiway(self):
        flow_graph = _DummyFlowGraph(
            {
                40: ((12,), (6, 90)),
            }
        )

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
        base_flow_graph = _DummyFlowGraph(
            {
                40: ((12,), (90,)),
                90: ((40,), (94,)),
                94: ((90,), ()),
            }
        )
        projected_flow_graph = _DummyFlowGraph(
            {
                40: ((12,), (90,)),
                90: ((40,), (94,)),
                94: ((90,), ()),
            }
        )

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


class TestSeedTerminalFamilyProbes:
    def test_collects_dag_and_projected_cfg_seed_origins(self):
        flow_graph = _DummyFlowGraph(
            {
                40: ((12,), (90, 91)),
                90: ((40,), ()),
                91: ((40,), ()),
            }
        )
        edge = SimpleNamespace(
            kind=1,  # replaced below after import-time constant check
            source_anchor=SimpleNamespace(block_serial=40, branch_arm=1),
        )
        from d810.analyses.control_flow.linearized_state_dag import SemanticEdgeKind

        edge.kind = SemanticEdgeKind.CONDITIONAL_RETURN

        probes = seed_terminal_family_probes(
            _DummyDag((edge,)),
            base_flow_graph=flow_graph,
            projected_flow_graph=flow_graph,
            dispatcher_region={6},
            reachable_blocks={40, 90, 91},
        )

        by_key = {
            (probe.seed.source_block, probe.seed.branch_arm): probe for probe in probes
        }
        assert by_key[(40, 1)].seed_origins == ("dag_edge", "projected_cfg")
        assert by_key[(40, 0)].seed_origins == ("projected_cfg",)


class TestBuildTerminalFamilyCandidates:
    def test_deduplicates_candidates_by_source_arm_and_path(self):
        flow_graph = _DummyFlowGraph(
            {
                90: ((40,), (94,)),
                94: ((90,), ()),
            }
        )
        seed = TerminalFamilySeed(source_block=40, branch_arm=0, edge=None)
        probe = TerminalFamilySeedProbe(
            seed=seed,
            seed_origins=("dag_edge",),
            source_reachable=True,
            source_nsucc=2,
            arm_target=90,
            arm_target_projected_only=False,
            family_entry=90,
            family_entry_projected_only=False,
            path=(90, 94),
            path_projected_only_blocks=(),
            stop_block=94,
            rejection_reason="accepted",
        )

        candidates = build_terminal_family_candidates(
            (probe, probe),
            projected_flow_graph=flow_graph,
            state_var_stkoff=None,
        )

        assert len(candidates) == 1
        assert candidates[0].family_entry == 90
        assert candidates[0].path == (90, 94)


class TestTerminalValueSignatures:
    def test_terminal_locator_key_uses_canonical_storage_identity(self):
        stack_vn = Varnode(Space.STACK, 0x20, 4)
        reg_vn = Varnode(Space.REGISTER, 7, 8)

        assert terminal_varnode_locator_key(stack_vn) == ("stk", 0x20, 4)
        assert terminal_varnode_locator_key(reg_vn) == ("reg", 7, 8)

    def test_state_var_dest_uses_storage_identity(self):
        insn = Instruction(
            operation=ValueOpKind.MOVE,
            inputs=(Varnode(Space.CONST, 0xAA, 1),),
            result=Varnode(Space.STACK, 0x20, 1),
        )

        assert is_state_var_dest(insn, 0x20)
        assert not is_state_var_dest(insn, 0x24)

    def test_terminal_source_signature_uses_canonical_varnodes(self):
        assert terminal_varnode_source_signature(Varnode(Space.CONST, 0x42, 4)) == (
            "const",
            0x42,
        )
        assert terminal_varnode_source_signature(Varnode(Space.TEMP, 17, 4)) == (
            "varnode",
            "t",
            17,
            4,
        )

    def test_terminal_write_signature_uses_canonical_instruction(self):
        insn = Instruction(
            operation=ValueOpKind.MOVE,
            inputs=(Varnode(Space.CONST, 3, 4),),
            result=Varnode(Space.STACK, 0x10, 4),
        )

        assert terminal_write_signature(insn) == (
            "op",
            "move",
            "dst",
            ("stk", 0x10, 4),
            "src_l",
            ("const", 3),
            "src_r",
            ("none",),
        )

    def test_terminal_value_chain_uses_canonical_write_records(self):
        block = _InstructionBlock(
            preds=(),
            succs=(),
            insn_snapshots=(
                _mov(_const(3), _reg(7), ea=0x1000),
                _mov(_reg(7), _stack(0x10), ea=0x1004),
                _mov(_const(0xAA), _stack(0x20), ea=0x1008),
            ),
        )
        flow_graph = SimpleNamespace(
            get_block=lambda serial: block if int(serial) == 90 else None
        )

        chain = resolve_terminal_value_chain(
            flow_graph,
            path=(90,),
            state_var_stkoff=0x20,
        )

        assert all(isinstance(write, TerminalValueWrite) for write in chain)
        assert [write.block_serial for write in chain] == [90, 90]
        assert [write.ea for write in chain] == [0x1000, 0x1004]
        assert terminal_value_family_signature(chain) == (
            "terminal_value_chain",
            (
                (
                    "op",
                    "move",
                    "dst",
                    ("reg", 7, 4),
                    "src_l",
                    ("const", 3),
                    "src_r",
                    ("none",),
                ),
                (
                    "op",
                    "move",
                    "dst",
                    ("stk", 0x10, 4),
                    "src_l",
                    ("reg", 7, 4),
                    "src_r",
                    ("none",),
                ),
            ),
        )

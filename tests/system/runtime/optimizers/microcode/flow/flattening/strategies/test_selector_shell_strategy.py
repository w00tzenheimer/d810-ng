"""Runtime tests for normalized selector-shell cleanup."""
from __future__ import annotations

from dataclasses import replace

from d810.cfg.flowgraph import (
    BranchPredicate,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.cfg.graph_modification import RedirectGoto
from d810.cfg.selector_shell_planning import plan_selector_shell_cleanup
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
    AnalysisSnapshot,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import FAMILY_CLEANUP
from d810.optimizers.microcode.flow.flattening.strategies.selector_shell import (
    SelectorShellStrategy,
)
from d810.analyses.control_flow.selector_shell import (
    SELECTOR_SHELL_FACTS_METADATA_KEY,
    SelectorShellEdgeProof,
    SelectorShellFact,
    discover_selector_shell_facts,
    extract_selector_shell_facts,
    serialize_selector_shell_facts,
)


INIT = 0x62CE9A1C
SELECT = 0x0FCD789F
OTHER = 0xE9FD9EC4


def _reg(reg: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(t=1, size=size, reg=reg, kind=OperandKind.REGISTER)


def _num(value: int) -> MopSnapshot:
    return MopSnapshot(t=2, size=4, value=value, kind=OperandKind.NUMBER)


def _blk(serial: int) -> MopSnapshot:
    return MopSnapshot(t=7, size=-1, block_ref=serial, kind=OperandKind.BLOCK)


def _mov(src: MopSnapshot, dst: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=4,
        ea=0x1000,
        operands=(),
        operand_slots=(("l", src), ("d", dst)),
        l=src,
        d=dst,
        kind=InsnKind.MOV,
    )


def _jz(left: MopSnapshot, right: MopSnapshot, target: int) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=44,
        ea=0x1000,
        operands=(),
        operand_slots=(("l", left), ("r", right), ("d", _blk(target))),
        l=left,
        r=right,
        d=_blk(target),
        kind=InsnKind.EQUALITY_JUMP,
        branch_predicate=BranchPredicate.EQUAL,
    )


def _jnz(left: MopSnapshot, right: MopSnapshot, target: int) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=43,
        ea=0x1000,
        operands=(),
        operand_slots=(("l", left), ("r", right), ("d", _blk(target))),
        l=left,
        r=right,
        d=_blk(target),
        kind=InsnKind.COND_JUMP,
        branch_predicate=BranchPredicate.NOT_EQUAL,
    )


def _payload() -> InsnSnapshot:
    return InsnSnapshot(
        opcode=14,
        ea=0x1000,
        operands=(),
        kind=InsnKind.ADD,
    )


def _block(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    *insns: InsnSnapshot,
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=4 if len(succs) == 2 else 1 if len(succs) == 1 else 2,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x1000 + serial,
        insn_snapshots=tuple(insns),
    )


def _selector_shell_cfg() -> FlowGraph:
    selector = _reg(24)
    previous = _reg(8)
    blocks = {
        2: _block(2, (4,), (), _payload(), _mov(_num(INIT), selector)),
        3: _block(
            3,
            (4,),
            (5,),
            _mov(_num(INIT), previous),
            _mov(_num(SELECT), selector),
        ),
        4: _block(4, (5, 8), (2, 3, 6), _jz(selector, _num(SELECT), 8)),
        5: _block(5, (6, 3), (4,), _jz(selector, _num(INIT), 3)),
        6: _block(6, (4,), (5,), _jnz(selector, _num(OTHER), 4)),
        8: _block(8, (), (4,), _payload()),
    }
    return FlowGraph(blocks=blocks, entry_serial=2, func_ea=0x1000)


def _selector_shell_semantic_predicate_cfg() -> FlowGraph:
    cfg = _selector_shell_cfg()
    blocks = {}
    for serial, block in cfg.blocks.items():
        insns = tuple(
            replace(insn, opcode=999, kind=InsnKind.UNKNOWN)
            if insn.opcode in {43, 44}
            else insn
            for insn in block.insn_snapshots
        )
        blocks[serial] = replace(block, insn_snapshots=insns)
    return replace(cfg, blocks=blocks)


def test_discover_selector_shell_fact_proves_predecessor_continuation() -> None:
    assert discover_selector_shell_facts(_selector_shell_cfg()) == (
        SelectorShellFact(
            header_block=4,
            semantic_target=8,
            artifact_blocks=frozenset({3, 4, 5}),
            edge_proofs=(
                SelectorShellEdgeProof(
                    from_serial=2,
                    old_target=4,
                    new_target=8,
                    ordered_path=(4, 5, 3, 4, 8),
                    artifact_blocks=frozenset({3, 4, 5}),
                ),
            ),
        ),
    )


def test_discover_selector_shell_fact_uses_semantic_branch_predicates() -> None:
    assert discover_selector_shell_facts(_selector_shell_semantic_predicate_cfg()) == (
        SelectorShellFact(
            header_block=4,
            semantic_target=8,
            artifact_blocks=frozenset({3, 4, 5}),
            edge_proofs=(
                SelectorShellEdgeProof(
                    from_serial=2,
                    old_target=4,
                    new_target=8,
                    ordered_path=(4, 5, 3, 4, 8),
                    artifact_blocks=frozenset({3, 4, 5}),
                ),
            ),
        ),
    )


def test_discover_selector_shell_fact_accepts_header_self_loop_artifact() -> None:
    selector = _reg(24)
    previous = _reg(8)
    cfg = FlowGraph(
        blocks={
            2: _block(2, (4,), (), _mov(_num(INIT), selector)),
            4: _block(
                4,
                (8, 4),
                (2, 4),
                _mov(selector, previous),
                _mov(_num(SELECT), selector),
                _jz(previous, _num(INIT), 4),
            ),
            8: _block(8, (), (4,), _payload()),
        },
        entry_serial=2,
        func_ea=0x1000,
    )

    assert discover_selector_shell_facts(cfg) == (
        SelectorShellFact(
            header_block=4,
            semantic_target=8,
            artifact_blocks=frozenset({4}),
            edge_proofs=(
                SelectorShellEdgeProof(
                    from_serial=2,
                    old_target=4,
                    new_target=8,
                    ordered_path=(4, 4, 8),
                    artifact_blocks=frozenset({4}),
                ),
            ),
        ),
    )


def test_selector_shell_planner_emits_typed_redirect_from_fact() -> None:
    cfg = _selector_shell_cfg()
    facts = discover_selector_shell_facts(cfg)

    assert plan_selector_shell_cleanup(facts, cfg) == [
        RedirectGoto(from_serial=2, old_target=4, new_target=8),
    ]


def test_selector_shell_strategy_materializes_normalized_fact() -> None:
    cfg = _selector_shell_cfg()
    facts = discover_selector_shell_facts(cfg)
    cfg = replace(
        cfg,
        metadata={
            SELECTOR_SHELL_FACTS_METADATA_KEY: serialize_selector_shell_facts(facts)
        },
    )

    fragment = SelectorShellStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    )

    assert fragment is not None
    assert fragment.strategy_name == "selector_shell"
    assert fragment.family == FAMILY_CLEANUP
    assert fragment.ownership.blocks == frozenset({2})
    assert fragment.ownership.edges == frozenset({(2, 4)})
    assert fragment.modifications == [
        RedirectGoto(from_serial=2, old_target=4, new_target=8),
    ]


def test_extract_selector_shell_facts_rejects_stale_edges() -> None:
    cfg = _selector_shell_cfg()
    facts = discover_selector_shell_facts(cfg)
    stale = serialize_selector_shell_facts(facts)
    stale = (
        {
            **stale[0],
            "edge_proofs": (
                {
                    **stale[0]["edge_proofs"][0],
                    "old_target": 99,
                },
            ),
        },
    )
    cfg = replace(cfg, metadata={SELECTOR_SHELL_FACTS_METADATA_KEY: stale})

    assert extract_selector_shell_facts(cfg) == ()


def test_extract_selector_shell_facts_rejects_stale_ordered_path() -> None:
    cfg = _selector_shell_cfg()
    facts = discover_selector_shell_facts(cfg)
    stale = serialize_selector_shell_facts(facts)
    stale = (
        {
            **stale[0],
            "edge_proofs": (
                {
                    **stale[0]["edge_proofs"][0],
                    "ordered_path": (4, 8),
                },
            ),
        },
    )
    cfg = replace(cfg, metadata={SELECTOR_SHELL_FACTS_METADATA_KEY: stale})

    assert extract_selector_shell_facts(cfg) == ()


def test_extract_selector_shell_facts_rejects_stale_artifact_blocks() -> None:
    cfg = _selector_shell_cfg()
    facts = discover_selector_shell_facts(cfg)
    stale = serialize_selector_shell_facts(facts)
    stale = (
        {
            **stale[0],
            "artifact_blocks": (4, 5),
            "edge_proofs": (
                {
                    **stale[0]["edge_proofs"][0],
                    "artifact_blocks": (4, 5),
                },
            ),
        },
    )
    cfg = replace(cfg, metadata={SELECTOR_SHELL_FACTS_METADATA_KEY: stale})

    assert extract_selector_shell_facts(cfg) == ()


def test_extract_selector_shell_facts_reproves_predecessor_env() -> None:
    cfg = _selector_shell_cfg()
    facts = discover_selector_shell_facts(cfg)
    metadata = serialize_selector_shell_facts(facts)
    pred = cfg.blocks[2]
    blocks = {
        **cfg.blocks,
        2: replace(
            pred,
            insn_snapshots=(
                _payload(),
                _mov(_num(SELECT), _reg(24)),
            ),
        ),
    }
    cfg = replace(
        cfg,
        blocks=blocks,
        metadata={SELECTOR_SHELL_FACTS_METADATA_KEY: metadata},
    )

    assert extract_selector_shell_facts(cfg) == ()

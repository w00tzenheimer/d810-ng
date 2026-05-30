from __future__ import annotations

from dataclasses import dataclass

from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.transforms.graph_modification import RedirectBranch, RedirectGoto
from d810.transforms.loop_carrier_backedge_refresh import (
    LoopCarrierBackedgeRefreshPass,
)


@dataclass(frozen=True)
class _Obs:
    payload: dict[str, object]


class _View:
    def __init__(self, facts: dict[int, tuple[_Obs, ...]]) -> None:
        self._facts = facts

    def loop_carriers_for_predicate_block(self, block_serial: int) -> tuple[_Obs, ...]:
        return self._facts.get(block_serial, ())


def _insn(
    opcode: int,
    *,
    dst: int | None = None,
    l_stkoff: int | None = None,
    r_value: int | None = None,
) -> InsnSnapshot:
    d = (
        MopSnapshot(t=3, size=8, stkoff=dst, kind=OperandKind.STACK)
        if dst is not None
        else None
    )
    l = (
        MopSnapshot(t=3, size=8, stkoff=l_stkoff, kind=OperandKind.STACK)
        if l_stkoff is not None
        else None
    )
    r = (
        MopSnapshot(t=2, size=8, value=r_value, kind=OperandKind.NUMBER)
        if r_value is not None
        else None
    )
    kind = {
        2: InsnKind.LOAD,
        4: InsnKind.MOV,
        12: InsnKind.ADD,
    }.get(opcode, InsnKind.UNKNOWN)
    return InsnSnapshot(
        opcode=opcode,
        ea=0x1000 + opcode,
        operands=(),
        l=l,
        r=r,
        d=d,
        kind=kind,
    )


def _blk(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    *,
    block_type: int = 3,
    insns: tuple[InsnSnapshot, ...] = (),
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=block_type,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x1000 + serial,
        insn_snapshots=insns,
    )


def _cfg() -> FlowGraph:
    return FlowGraph(
        blocks={
            0: _blk(0, (15,), (), insns=()),
            15: _blk(15, (16, 13), (0, 43, 42, 99), block_type=4),
            26: _blk(26, (42,), (21,), insns=(_insn(2, dst=0x450),)),
            42: _blk(42, (15,), (26,), insns=(_insn(4, dst=0x650),)),
            43: _blk(43, (15,), (5,), insns=(_insn(13, dst=0x528),)),
            99: _blk(99, (15, 100), (98,), block_type=4, insns=(_insn(44),)),
        },
        entry_serial=0,
        func_ea=0x180012DF0,
        metadata={"maturity": 6},
    )


def _fact() -> _Obs:
    return _Obs(
        {
            "classification": "LOOP_CARRIER_WRITER_OUTSIDE_SCC",
            "predicate_block_serial": 15,
            "carrier_stkoff": 0x450,
            "carrier_reader_blocks": [42],
            "carrier_writer_blocks_outside_loop": [26],
            "loop_scc_blocks": [15, 43, 99],
        }
    )


def _pass(view: _View) -> LoopCarrierBackedgeRefreshPass:
    return LoopCarrierBackedgeRefreshPass(
        fact_view_provider=lambda _func_ea, _maturity: view,
    )


def test_disabled_without_env(monkeypatch) -> None:
    monkeypatch.delenv("D810_LOOP_CARRIER_BACKEDGE_REFRESH", raising=False)
    pass_ = _pass(_View({15: (_fact(),)}))

    assert not pass_.is_applicable(_cfg())
    assert pass_.transform(_cfg()) == []


def test_redirects_shortcut_goto_backedge_through_refresh_entry(monkeypatch) -> None:
    monkeypatch.setenv("D810_LOOP_CARRIER_BACKEDGE_REFRESH", "1")
    mods = _pass(_View({15: (_fact(),)})).transform(_cfg())

    assert RedirectGoto(from_serial=43, old_target=15, new_target=26) in mods
    assert all(not (getattr(mod, "from_serial", None) == 42) for mod in mods)


def test_redirects_shortcut_branch_backedge_through_refresh_entry(monkeypatch) -> None:
    monkeypatch.setenv("D810_LOOP_CARRIER_BACKEDGE_REFRESH", "1")
    mods = _pass(_View({15: (_fact(),)})).transform(_cfg())

    assert RedirectBranch(from_serial=99, old_target=15, new_target=26) in mods


def test_abstains_when_refresh_entry_is_not_unique(monkeypatch) -> None:
    monkeypatch.setenv("D810_LOOP_CARRIER_BACKEDGE_REFRESH", "1")
    cfg = FlowGraph(
        blocks={
            **dict(_cfg().blocks),
            27: _blk(27, (42,), (22,), insns=(_insn(2, dst=0x450),)),
        },
        entry_serial=0,
        func_ea=0x180012DF0,
        metadata={"maturity": 6},
    )
    fact = _Obs(
        {
            **_fact().payload,
            "carrier_writer_blocks_outside_loop": [26, 27],
        }
    )

    assert _pass(_View({15: (fact,)})).transform(cfg) == []


def test_redirects_initial_nonzero_parser_shortcut_through_advance_entry(
    monkeypatch,
) -> None:
    monkeypatch.setenv("D810_LOOP_CARRIER_BACKEDGE_REFRESH", "1")
    cfg = FlowGraph(
        blocks={
            15: _blk(15, (16, 13), (45, 46), block_type=4),
            24: _blk(24, (25, 36), (22,), block_type=4, insns=(
                _insn(43, l_stkoff=0x1F0, r_value=0),
            )),
            25: _blk(25, (45,), (24,), insns=(_insn(12, dst=0x450),)),
            26: _blk(26, (45,), (), insns=(_insn(2, dst=0x450),)),
            36: _blk(36, (37, 46), (24,), block_type=4, insns=(
                _insn(43, l_stkoff=0x1F0, r_value=1),
            )),
            37: _blk(37, (38, 39), (36,), block_type=4),
            45: _blk(45, (15,), (25, 26), insns=(_insn(4, dst=0x1A8),)),
            46: _blk(46, (15,), (36,), insns=(_insn(13, dst=0x528),)),
        },
        entry_serial=24,
        func_ea=0x180012DF0,
        metadata={"maturity": 6},
    )
    fact = _Obs(
        {
            "classification": "LOOP_CARRIER_WRITER_OUTSIDE_SCC",
            "predicate_block_serial": 15,
            "carrier_stkoff": 0x450,
            "carrier_reader_blocks": [45],
            "carrier_writer_blocks_outside_loop": [25, 26],
            "loop_scc_blocks": [15],
        }
    )

    mods = _pass(_View({15: (fact,)})).transform(cfg)

    assert RedirectBranch(from_serial=36, old_target=46, new_target=25) in mods


def test_structural_initial_nonzero_refresh_does_not_require_active_fact(
    monkeypatch,
) -> None:
    monkeypatch.setenv("D810_LOOP_CARRIER_BACKEDGE_REFRESH", "1")
    cfg = FlowGraph(
        blocks={
            15: _blk(15, (16, 13), (45, 46), block_type=4),
            24: _blk(24, (25, 36), (22,), block_type=4, insns=(
                _insn(43, l_stkoff=0x1F0, r_value=0),
            )),
            25: _blk(25, (45,), (24,), insns=(_insn(12, dst=0x450),)),
            36: _blk(36, (37, 46), (24,), block_type=4, insns=(
                _insn(43, l_stkoff=0x1F0, r_value=1),
            )),
            37: _blk(37, (38, 39), (36,), block_type=4),
            45: _blk(45, (15,), (25,), insns=(_insn(4, l_stkoff=0x450, dst=0x1A8),)),
            46: _blk(46, (15,), (36,), insns=(_insn(13, dst=0x528),)),
        },
        entry_serial=24,
        func_ea=0x180012DF0,
        metadata={"maturity": 6},
    )

    mods = _pass(_View({})).transform(cfg)

    assert RedirectBranch(from_serial=36, old_target=46, new_target=25) in mods


def test_does_not_redirect_initial_nonzero_when_old_target_is_not_predicate_path(
    monkeypatch,
) -> None:
    monkeypatch.setenv("D810_LOOP_CARRIER_BACKEDGE_REFRESH", "1")
    cfg = FlowGraph(
        blocks={
            15: _blk(15, (16, 13), (45,), block_type=4),
            24: _blk(24, (25, 36), (22,), block_type=4, insns=(
                _insn(43, l_stkoff=0x1F0, r_value=0),
            )),
            25: _blk(25, (45,), (24,), insns=(_insn(12, dst=0x450),)),
            26: _blk(26, (45,), (), insns=(_insn(2, dst=0x450),)),
            36: _blk(36, (37, 46), (24,), block_type=4, insns=(
                _insn(43, l_stkoff=0x1F0, r_value=1),
            )),
            37: _blk(37, (38, 39), (36,), block_type=4),
            45: _blk(45, (15,), (25, 26), insns=(_insn(4, dst=0x1A8),)),
            46: _blk(46, (99,), (36,), insns=(_insn(13, dst=0x528),)),
            99: _blk(99, (), (46,), block_type=1),
        },
        entry_serial=24,
        func_ea=0x180012DF0,
        metadata={"maturity": 6},
    )
    fact = _Obs(
        {
            "classification": "LOOP_CARRIER_WRITER_OUTSIDE_SCC",
            "predicate_block_serial": 15,
            "carrier_stkoff": 0x450,
            "carrier_reader_blocks": [45],
            "carrier_writer_blocks_outside_loop": [25, 26],
            "loop_scc_blocks": [15],
        }
    )

    mods = _pass(_View({15: (fact,)})).transform(cfg)

    assert RedirectBranch(from_serial=36, old_target=46, new_target=25) not in mods

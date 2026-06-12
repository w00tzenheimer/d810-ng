from __future__ import annotations

from d810.backends.hexrays.mutation.backend import HexRaysMutationBackend
from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph
from d810.transforms.plan import PatchConvertToGoto, PatchPlan, PatchRedirectGoto


def _make_block(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    *,
    kind: BlockKind | None = None,
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=0,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x1000 + serial,
        insn_snapshots=(),
        kind=kind or (
            BlockKind.ONE_WAY if len(succs) == 1 else BlockKind.ZERO_WAY
        ),
    )


def _make_cfg(
    edges: list[tuple[int, int]],
    *,
    stop_serials: tuple[int, ...] = (),
    entry_serial: int = 0,
) -> FlowGraph:
    succs: dict[int, list[int]] = {}
    preds: dict[int, list[int]] = {}
    nodes = {entry_serial, *stop_serials}
    for src, dst in edges:
        nodes.add(src)
        nodes.add(dst)
        succs.setdefault(src, []).append(dst)
        preds.setdefault(dst, []).append(src)
    blocks = {
        serial: _make_block(
            serial,
            tuple(succs.get(serial, ())),
            tuple(preds.get(serial, ())),
            kind=BlockKind.STOP if serial in stop_serials else None,
        )
        for serial in nodes
    }
    return FlowGraph(blocks=blocks, entry_serial=entry_serial, func_ea=0x1000)


class _FakeTranslator:
    def __init__(self, cfg: FlowGraph) -> None:
        self.cfg = cfg
        self.lower_calls: list[PatchPlan] = []
        self.lift_count = 0

    def lift(self, _live_source: object) -> FlowGraph:
        self.lift_count += 1
        return self.cfg

    def lower(self, rewrite_plan: PatchPlan, _live_source: object) -> int:
        self.lower_calls.append(rewrite_plan)
        return len(rewrite_plan.steps)


def test_apply_rejects_plan_that_orphans_reachable_terminal() -> None:
    cfg = _make_cfg(
        [(0, 1), (1, 2), (2, 3)],
        stop_serials=(3,),
    )
    translator = _FakeTranslator(cfg)
    backend = HexRaysMutationBackend(translator=translator)
    plan = PatchPlan(
        steps=(PatchRedirectGoto(from_serial=2, old_target=3, new_target=1),),
    )

    result = backend.apply(plan, live_source=object())

    assert result is cfg
    assert translator.lower_calls == []
    assert translator.lift_count == 1


def test_apply_rejects_plan_that_collapses_entry_reachability() -> None:
    cfg = _make_cfg([(serial, serial + 1) for serial in range(24)])
    translator = _FakeTranslator(cfg)
    backend = HexRaysMutationBackend(translator=translator)
    plan = PatchPlan(
        steps=(PatchRedirectGoto(from_serial=0, old_target=1, new_target=0),),
    )

    result = backend.apply(plan, live_source=object())

    assert result is cfg
    assert translator.lower_calls == []
    assert translator.lift_count == 1


def test_apply_lowers_plan_when_reachability_is_preserved() -> None:
    cfg = _make_cfg(
        [(0, 1), (1, 2), (2, 3)],
        stop_serials=(3,),
    )
    translator = _FakeTranslator(cfg)
    backend = HexRaysMutationBackend(translator=translator)
    plan = PatchPlan(
        steps=(PatchConvertToGoto(block_serial=0, goto_target=1),),
    )

    result = backend.apply(plan, live_source=object())

    assert result is cfg
    assert translator.lower_calls == [plan]
    assert translator.lift_count == 2

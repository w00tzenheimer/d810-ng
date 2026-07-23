from __future__ import annotations

import sys
from types import ModuleType

from d810.backends.hexrays.mutation.backend import HexRaysMutationBackend
from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph
from d810.transforms.plan import PatchConvertToGoto, PatchPlan, PatchRedirectGoto


MUTATION_GATEWAY = object()


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

    def lower(
        self,
        rewrite_plan: PatchPlan,
        _live_source: object,
        *,
        mutation_gateway: object,
    ) -> int:
        assert mutation_gateway is MUTATION_GATEWAY
        self.lower_calls.append(rewrite_plan)
        return len(rewrite_plan.steps)


def test_apply_rejects_plan_that_orphans_reachable_terminal() -> None:
    cfg = _make_cfg(
        [(0, 1), (1, 2), (2, 3)],
        stop_serials=(3,),
    )
    translator = _FakeTranslator(cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=MUTATION_GATEWAY,
        translator=translator,
    )
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
    backend = HexRaysMutationBackend(
        mutation_gateway=MUTATION_GATEWAY,
        translator=translator,
    )
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
    backend = HexRaysMutationBackend(
        mutation_gateway=MUTATION_GATEWAY,
        translator=translator,
    )
    plan = PatchPlan(
        steps=(PatchConvertToGoto(block_serial=0, goto_target=1),),
    )

    result = backend.apply(plan, live_source=object())

    assert result is cfg
    assert translator.lower_calls == [plan]
    assert translator.lift_count == 2


def test_publish_fragment_uses_independent_receipt_backed_gateway() -> None:
    cfg = _make_cfg(
        [(0, 1), (1, 2), (2, 3)],
        stop_serials=(3,),
    )
    translator = _FakeTranslator(cfg)
    plan = object()
    published = []

    class _Gateway:
        def __init__(self, name: str) -> None:
            self.name = name

        def new_transaction(self):
            return _Gateway("fragment")

        def publish_semantic_fragment(self, fragment_backend, fragment_plan):
            published.append((self.name, fragment_backend, fragment_plan))

    fragment_backend = object()
    backend = HexRaysMutationBackend(
        mutation_gateway=_Gateway("root"),
        translator=translator,
        fragment_backend_factory=lambda live_source, gateway: (
            fragment_backend
            if live_source == "LIVE" and gateway.name == "fragment"
            else None
        ),
    )

    result = backend.publish_fragment(plan, live_source="LIVE")

    assert result is cfg
    assert published == [("fragment", fragment_backend, plan)]
    assert translator.lift_count == 1


def test_default_fragment_backend_receives_native_body_materializer(
    monkeypatch,
) -> None:
    cfg = _make_cfg([(0, 1)], stop_serials=(1,))
    translator = _FakeTranslator(cfg)
    materializer = object()
    constructed = []

    class _Modifier:
        def __init__(
            self,
            live_source,
            *,
            mutation_gateway,
            semantic_native_body_materializer,
        ) -> None:
            constructed.append(
                (
                    live_source,
                    mutation_gateway,
                    semantic_native_body_materializer,
                )
            )

    deferred_modifier = ModuleType("d810.hexrays.mutation.deferred_modifier")
    deferred_modifier.DeferredGraphModifier = _Modifier
    monkeypatch.setitem(
        sys.modules,
        "d810.hexrays.mutation.deferred_modifier",
        deferred_modifier,
    )
    backend = HexRaysMutationBackend(
        mutation_gateway=MUTATION_GATEWAY,
        translator=translator,
        semantic_native_body_materializer=materializer,
    )

    fragment_backend = backend._new_fragment_backend("LIVE", MUTATION_GATEWAY)

    assert isinstance(fragment_backend, _Modifier)
    assert constructed == [("LIVE", MUTATION_GATEWAY, materializer)]

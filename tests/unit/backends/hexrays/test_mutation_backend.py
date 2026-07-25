from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace

import pytest

from d810.backends.hexrays.mutation.backend import HexRaysMutationBackend
from d810.ir.block_identity import (
    CurrentMbaBlockIdentityBinding,
    CurrentMbaIdentityBindingSnapshot,
    NativeEaInterval,
    StableBlockIdentity,
)
from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.transforms.cfg_transaction import LogicalBlockRef
from d810.transforms.fragment_plan import (
    FragmentBlock,
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentEdge,
    FragmentOperation,
    FragmentPlan,
    FragmentPublicationPurpose,
)
from d810.transforms.plan import PatchConvertToGoto, PatchPlan, PatchRedirectGoto
from tests.native_preanalysis import make_native_key


MUTATION_GATEWAY = object()
NATIVE_KEY = make_native_key()


def _ref(serial: int) -> LogicalBlockRef:
    return LogicalBlockRef("backend-test", f"block:{int(serial)}", 0)


def _source_coordinates(*serials: int):
    return tuple((_ref(serial), int(serial)) for serial in serials)


def _fragment_identity(start_ea: int) -> StableBlockIdentity:
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(start_ea, start_ea + 0x10),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(start_ea,),
    )


def _fragment_plan() -> FragmentPlan:
    original_identity = _fragment_identity(0x401000)
    return FragmentPlan(
        plan_id="backend-fragment",
        atomic_group_id="backend-route",
        publication_purpose=(FragmentPublicationPurpose.CANONICAL_SEMANTIC_LOWERING),
        native_key=NATIVE_KEY,
        blocks=(
            FragmentBlock(
                block_id="entry",
                role=FragmentBlockRole.EXTERNAL,
                materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
                semantic_anchor_ea=0x400000,
                stable_identity=_fragment_identity(0x400000),
            ),
            FragmentBlock(
                block_id="original",
                role=FragmentBlockRole.ORIGINAL,
                materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
                semantic_anchor_ea=0x401000,
                stable_identity=original_identity,
            ),
            FragmentBlock(
                block_id="replacement",
                role=FragmentBlockRole.REPLACEMENT,
                materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
                semantic_anchor_ea=0x401000,
                stable_identity=original_identity,
                replaces_block_id="original",
            ),
            FragmentBlock(
                block_id="target",
                role=FragmentBlockRole.EXTERNAL,
                materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
                semantic_anchor_ea=0x402000,
                stable_identity=_fragment_identity(0x402000),
            ),
            FragmentBlock(
                block_id="dispatcher",
                role=FragmentBlockRole.EXTERNAL,
                materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
                semantic_anchor_ea=0x403000,
                stable_identity=_fragment_identity(0x403000),
            ),
        ),
        roots=("replacement",),
        owned_originals=("original",),
        prohibited_dispatcher_blocks=("dispatcher",),
        operations=(
            FragmentOperation(
                operation_id="backend-direct-route",
                source_block_id="replacement",
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id="target",
                    ),
                ),
            ),
        ),
    )


def _current_mba_identity_binding() -> CurrentMbaIdentityBindingSnapshot:
    live_ea = 0xF10000
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401020),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x401010,),
    )
    return CurrentMbaIdentityBindingSnapshot(
        instruction_origins=((live_ea, 0x401010),),
        block_bindings=(
            CurrentMbaBlockIdentityBinding(
                stable_identity=identity,
                live_instruction_eas=frozenset({live_ea}),
            ),
        ),
    )


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
        kind=kind or (BlockKind.ONE_WAY if len(succs) == 1 else BlockKind.ZERO_WAY),
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
        steps=(
            PatchRedirectGoto(
                from_serial=_ref(2),
                old_target=_ref(3),
                new_target=_ref(1),
            ),
        ),
        source_coordinates=_source_coordinates(1, 2, 3),
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
        steps=(
            PatchRedirectGoto(
                from_serial=_ref(0),
                old_target=_ref(1),
                new_target=_ref(0),
            ),
        ),
        source_coordinates=_source_coordinates(0, 1),
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
        steps=(
            PatchConvertToGoto(
                block_serial=_ref(0),
                goto_target=_ref(1),
            ),
        ),
        source_coordinates=_source_coordinates(0, 1),
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
    plan = _fragment_plan()
    published = []
    snapshot = _current_mba_identity_binding()

    class _Gateway:
        def __init__(self, name: str) -> None:
            self.name = name

        def new_transaction(self):
            return _Gateway("fragment")

        def execute_patch_transaction(self, fragment_backend, fragment_plan):
            published.append((self.name, fragment_backend, fragment_plan))
            return SimpleNamespace(
                current_mba_identity_binding=snapshot,
            )

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

    result = backend.apply(plan, live_source="LIVE")

    assert result is cfg
    assert published == [("fragment", fragment_backend, plan)]
    assert translator.lift_count == 1
    assert backend.committed_current_mba_identity_binding() is snapshot


def test_publish_fragment_exposes_no_prior_origins_after_abort() -> None:
    cfg = _make_cfg([(0, 1)], stop_serials=(1,))
    translator = _FakeTranslator(cfg)
    snapshot = _current_mba_identity_binding()

    class _Gateway:
        fail = False

        def new_transaction(self):
            return self

        def execute_patch_transaction(self, _fragment_backend, _fragment_plan):
            if self.fail:
                raise RuntimeError("publication aborted")
            return SimpleNamespace(
                current_mba_identity_binding=snapshot,
            )

    gateway = _Gateway()
    backend = HexRaysMutationBackend(
        mutation_gateway=gateway,
        translator=translator,
        fragment_backend_factory=lambda _live_source, _transaction: object(),
    )
    plan = _fragment_plan()
    backend.apply(plan, live_source=object())
    assert backend.committed_current_mba_identity_binding() is snapshot

    gateway.fail = True
    with pytest.raises(RuntimeError, match="publication aborted"):
        backend.apply(plan, live_source=object())

    assert backend.committed_current_mba_identity_binding() is None


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

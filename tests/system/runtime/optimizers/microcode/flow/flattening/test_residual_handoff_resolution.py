from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

from d810.recon.flow import residual_handoff_resolution as resolution
from d810.recon.flow.linearized_state_dag import (
    RedirectSourceKind,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNodeKey,
    StateRedirectAnchor,
)


@contextmanager
def _replaced_attr(obj: object, name: str, value: object):
    original = getattr(obj, name)
    setattr(obj, name, value)
    try:
        yield
    finally:
        setattr(obj, name, original)


def _edge(*, source_block: int = 40, target_entry: int = 99) -> StateDagEdge:
    return StateDagEdge(
        kind=SemanticEdgeKind.TRANSITION,
        source_key=StateDagNodeKey(handler_serial=source_block, state_const=0x11),
        target_key=StateDagNodeKey(handler_serial=target_entry, state_const=0x22),
        target_state=0x22,
        target_entry_anchor=target_entry,
        target_label="0x22",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.EXIT_BLOCK,
            block_serial=source_block,
            branch_arm=None,
        ),
        ordered_path=(12, source_block),
        last_write_site=None,
    )


class _DiscoverRecorder:
    def __init__(self, result: object):
        self.result = result
        self.kwargs = None

    def __call__(self, *args, **kwargs):
        self.kwargs = kwargs
        return self.result


class _FakeTracker:
    def __init__(self, tracked_mops, *, max_nb_block: int, max_path: int):
        self.tracked_mops = tracked_mops
        self.max_nb_block = max_nb_block
        self.max_path = max_path
        self.reset_called = False
        self.search_args = None

    def reset(self):
        self.reset_called = True

    def search_backward(self, blk, tail):
        self.search_args = (blk, tail)
        return ("history",)


class TestResidualHandoffResolution:
    def test_has_live_exact_residual_handoff_injects_valrange_hook(self) -> None:
        resolver = object()
        discover = _DiscoverRecorder(True)
        with (
            _replaced_attr(resolution, "_resolve_state_via_valranges", lambda: resolver),
            _replaced_attr(
                resolution,
                "discover_has_live_exact_residual_handoff",
                discover,
            ),
        ):
            assert resolution.has_live_exact_residual_handoff_with_valranges(
                object(),
                (7, 8),
                state_var_stkoff=0x30,
                dispatcher=object(),
            )
        assert discover.kwargs["resolve_state_via_valranges"] is resolver

    def test_singleton_resolution_injects_valrange_hook(self) -> None:
        resolver = object()
        discover = _DiscoverRecorder(0x44)
        with (
            _replaced_attr(resolution, "_resolve_state_via_valranges", lambda: resolver),
            _replaced_attr(
                resolution,
                "discover_singleton_state_write_value",
                discover,
            ),
        ):
            assert (
                resolution.resolve_singleton_state_write_value(
                    object(),
                    12,
                    state_var_stkoff=0x38,
                )
                == 0x44
            )
        assert discover.kwargs["resolve_state_via_valranges"] is resolver

    def test_synthesized_resolution_injects_valrange_hook(self) -> None:
        resolver = object()
        discover = _DiscoverRecorder((0x11, 24))
        dag = SimpleNamespace()
        with (
            _replaced_attr(resolution, "_resolve_state_via_valranges", lambda: resolver),
            _replaced_attr(
                resolution,
                "discover_synthesized_handoff_target",
                discover,
            ),
        ):
            assert resolution.resolve_synthesized_handoff_target(
                dag,
                object(),
                12,
                state_var_stkoff=0x38,
                bst_node_blocks={1, 2},
                dispatcher=object(),
                via_pred=7,
            ) == (0x11, 24)
        assert discover.kwargs["resolve_state_via_valranges"] is resolver

    def test_effective_target_resolution_injects_valrange_hook(self) -> None:
        resolver = object()
        discover = _DiscoverRecorder(SimpleNamespace(target_entry=24))
        dag = SimpleNamespace()
        edge = _edge()
        with (
            _replaced_attr(resolution, "_resolve_state_via_valranges", lambda: resolver),
            _replaced_attr(
                resolution,
                "discover_effective_target_entry",
                discover,
            ),
        ):
            assert (
                resolution.resolve_effective_target_entry(
                    dag,
                    edge,
                    bst_node_blocks={1, 2},
                    state_var_stkoff=0x40,
                    dispatcher_lookup=None,
                    dispatcher=object(),
                    mba=object(),
                )
                == 24
            )
        assert discover.kwargs["resolve_state_via_valranges"] is resolver

    def test_semantic_handoff_redirect_prefers_immediate_handoff(self) -> None:
        dag = SimpleNamespace()
        edge = _edge(source_block=40, target_entry=24)

        def _immediate(*args, **kwargs):
            return (0x11, 24)

        synthesized_called = {"value": False}

        def _synthesized(*args, **kwargs):
            synthesized_called["value"] = True
            return None

        with (
            _replaced_attr(resolution, "resolve_immediate_handoff_target", _immediate),
            _replaced_attr(resolution, "resolve_synthesized_handoff_target", _synthesized),
        ):
            assert resolution.is_semantic_handoff_redirect(
                dag,
                edge,
                source_block=40,
                target_entry=24,
                state_var_stkoff=0x40,
                dispatcher_lookup=None,
                dispatcher=object(),
                mba=object(),
            )
        assert synthesized_called["value"] is False

    def test_resolve_predecessor_state_values_uses_tracker(self) -> None:
        tracker = _FakeTracker([object()], max_nb_block=20, max_path=15)
        mba = SimpleNamespace(get_mblock=lambda serial: SimpleNamespace(tail="tail"))

        with (
            _replaced_attr(resolution, "_mop_tracker_cls", lambda: (lambda *args, **kwargs: tracker)),
            _replaced_attr(
                resolution,
                "_all_possible_values",
                lambda: (lambda histories, tracked: [[0x22], [None], [0x11], [0x22]]),
            ),
        ):
            values = resolution.resolve_predecessor_state_values(
                mba,
                pred_serial=12,
                state_var=SimpleNamespace(name="state"),
            )

        assert tracker.reset_called is True
        assert tracker.search_args is not None
        assert values == (0x11, 0x22)

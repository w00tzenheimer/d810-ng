"""S1 unit tests: the grown ``DispatcherModel`` Protocol.

The ``_DispatcherMap`` minimal Protocol is upgraded to ``DispatcherModel`` with
``route()->RouteResult`` + ``state_var()`` / ``entry`` / ``is_dispatcher`` /
``region()``, and a deprecated default ``resolve_target`` that calls ``route``
and unwraps a single ``Block``.  No callers switched; golden untouched.
"""
from __future__ import annotations

from d810.analyses.data_flow.abstract_value import (
    Block,
    EntersDispatcher,
    RouteOneOf,
    RouteResult,
    Unknown,
)
from d810.transforms.state_machine_unflatten import DispatcherModel, _DispatcherMap


class _StubModel:
    """Concrete model exercising the Protocol's deprecated default resolve_target."""

    def __init__(self, table: dict[int, RouteResult]):
        self._table = table
        self._region = frozenset({2, 3, 4})

    def route(self, value: int) -> RouteResult:
        return self._table.get(int(value), Unknown("state_not_in_dispatcher_map"))

    def state_var(self) -> int | None:
        return 0x3C

    @property
    def entry(self) -> int | None:
        return 2

    def is_dispatcher(self, block_serial: int) -> bool:
        return int(block_serial) in self._region

    def region(self) -> frozenset[int]:
        return self._region

    # inherits resolve_target? No — Protocol defaults are not inherited by
    # non-subclasses; provide it via the default body explicitly to mirror
    # what concrete models that DO subclass would get.
    resolve_target = DispatcherModel.resolve_target


def test_alias_preserved():
    assert _DispatcherMap is DispatcherModel


def test_stub_is_structurally_a_dispatcher_model():
    stub = _StubModel({})
    assert isinstance(stub, DispatcherModel)  # runtime_checkable structural check


def test_resolve_target_unwraps_block():
    stub = _StubModel({0x79F598F7: Block(52, 0x18001450D)})
    assert stub.resolve_target(0x79F598F7) == 52


def test_resolve_target_none_for_non_block_routes():
    stub = _StubModel(
        {
            1: Unknown("nope"),
            2: RouteOneOf((Block(10), Block(11))),
            3: EntersDispatcher(object(), entry_serial=2),
        }
    )
    assert stub.resolve_target(1) is None
    assert stub.resolve_target(2) is None
    assert stub.resolve_target(3) is None
    # an unmapped value routes to Unknown -> None
    assert stub.resolve_target(0xDEAD) is None


def test_model_metadata_accessors():
    stub = _StubModel({})
    assert stub.state_var() == 0x3C
    assert stub.entry == 2
    assert stub.is_dispatcher(3) and not stub.is_dispatcher(99)
    assert stub.region() == frozenset({2, 3, 4})

"""Two SWIG proxies for one live ``mba_t`` must name one safe point.

``mblock_t.mba`` manufactures a fresh SWIG proxy on every access, so
``id(mba)`` names the Python wrapper rather than the C++ ``mba_t``.  Keying a
safe point on ``id`` therefore let one native epoch be claimed twice -- once
per proxy -- and a recycled ``id`` could equally suppress a genuinely new
epoch.  This test proves against live Hex-Rays that the coordinator key is the
native pointer and coincides for two distinct proxies of one MBA (ticket
d81-k5ku, P1-1).
"""

from __future__ import annotations

import ida_hexrays
import pytest

from d810.hexrays.hooks.safe_point_coordinator import (
    HexRaysSafePointCoordinator,
    OwnedStageOutcome,
    SafePointKey,
)
from d810.hexrays.ir.native_identity import (
    NativeIdentityKind,
    native_object_identity,
)
from tests.system.runtime.conftest import gen_microcode_at_maturity, get_func_ea


def _key(mba: object) -> SafePointKey:
    return SafePointKey.from_mba(
        session_id="session-a",
        function_ea=int(mba.entry_ea),
        mba=mba,
        maturity=int(ida_hexrays.MMAT_PREOPTIMIZED),
        generation=0,
        stage_id="d810.pass_pipeline",
    )


@pytest.mark.ida_required
def test_two_live_proxies_for_one_mba_share_one_safe_point_key(
    libobfuscated_setup,
) -> None:
    func_ea = get_func_ea("test_cst_simplification")
    mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_PREOPTIMIZED)
    assert mba is not None
    mba.build_graph()
    block = mba.get_mblock(0)
    assert block is not None

    # ``mblock_t.mba`` is the second proxy over the same native object.
    proxy_a = block.mba
    proxy_b = block.mba
    assert proxy_a is not proxy_b
    assert id(proxy_a) != id(proxy_b)

    identity_a = native_object_identity(proxy_a)
    identity_b = native_object_identity(proxy_b)
    assert identity_a.kind is NativeIdentityKind.NATIVE_POINTER
    assert identity_a == identity_b
    assert identity_a.value not in {id(proxy_a), id(proxy_b)}

    key_a = _key(proxy_a)
    key_b = _key(proxy_b)
    assert key_a == key_b
    assert hash(key_a) == hash(key_b)


@pytest.mark.ida_required
def test_second_live_proxy_cannot_reclaim_one_native_safe_point(
    libobfuscated_setup,
) -> None:
    func_ea = get_func_ea("test_cst_simplification")
    mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_PREOPTIMIZED)
    assert mba is not None
    mba.build_graph()
    block = mba.get_mblock(0)
    assert block is not None

    coordinator = HexRaysSafePointCoordinator()
    calls: list[str] = []

    first = coordinator.run(
        _key(block.mba),
        lambda: calls.append("first") or OwnedStageOutcome.mutated(1),
    )
    second = coordinator.run(
        _key(block.mba),
        lambda: calls.append("second") or OwnedStageOutcome.mutated(1),
    )

    assert first.claimed is True
    assert first.requires_stale_pointer_barrier is True
    assert second.claimed is False
    assert calls == ["first"]

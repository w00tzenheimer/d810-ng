"""Test-owned live MBA mutation gateways for system/runtime fixtures."""

from __future__ import annotations

from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.hexrays.mutation.mba_mutation_events import MbaMutationGateway
from tests.native_preanalysis import make_native_key


def make_mutation_gateway(mba, *, generation: int = 0) -> MbaMutationGateway:
    """Build an explicit gateway for a fake or live runtime-test MBA."""
    native_key = make_native_key()
    session_id = f"test-mutation:{id(mba):x}"
    if callable(getattr(mba, "get_mblock", None)):
        index = MbaBlockIdentityIndex.from_mba(
            mba,
            generation=generation,
            native_key=native_key,
            session_id=session_id,
        )
    else:
        index = MbaBlockIdentityIndex.from_bindings(
            generation=generation,
            native_key=native_key,
            bindings=(),
            session_id=session_id,
        )
        index.ensure_serial_space(int(getattr(mba, "qty", 0) or 0))
    return MbaMutationGateway(
        native_key=native_key,
        generation=generation,
        session_id=session_id,
        function_ea=int(getattr(mba, "entry_ea", 0) or 0),
        maturity=int(getattr(mba, "maturity", 0) or 0),
        identity_index=index,
    )


__all__ = ["make_mutation_gateway"]

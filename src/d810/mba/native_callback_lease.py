"""Callback-lifetime authority for live native MBA candidates.

The lease is vendor-neutral so the Hex-Rays callback owner and the IDA-bound
MBA backend can share one lifetime authority without an upward layer import.
"""

from __future__ import annotations

import contextlib
import contextvars
from dataclasses import dataclass

from d810.core.typing import Iterator
from d810.mba.extension_api import NativeMbaCandidateExpired


@dataclass(slots=True)
class NativeMbaCallbackLease:
    active: bool = True


_CURRENT_NATIVE_MBA_LEASE: contextvars.ContextVar[
    NativeMbaCallbackLease | None
] = contextvars.ContextVar("d810_native_mba_callback_lease", default=None)


@contextlib.contextmanager
def native_mba_callback_scope() -> Iterator[None]:
    """Own native MBA candidates for exactly one optinsn callback extent."""

    lease = NativeMbaCallbackLease()
    token = _CURRENT_NATIVE_MBA_LEASE.set(lease)
    try:
        yield
    finally:
        lease.active = False
        _CURRENT_NATIVE_MBA_LEASE.reset(token)


def active_native_mba_lease() -> NativeMbaCallbackLease:
    """Return the active callback lease or fail before native access."""

    lease = _CURRENT_NATIVE_MBA_LEASE.get()
    if lease is None or not lease.active:
        raise NativeMbaCandidateExpired(
            "native MBA operations require an active optinsn callback"
        )
    return lease


__all__ = [
    "NativeMbaCallbackLease",
    "active_native_mba_lease",
    "native_mba_callback_scope",
]

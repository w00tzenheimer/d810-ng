"""Host-owned lifetime for the MBA residual-observation capability.

The manager owns the sink, but the manager is IDA-bound and is rebuilt on
every reload, so the *sequencing* of register/publish/release lives here as
pure Python.  ``state.load_project()`` stops and restarts the manager after a
provider rule has already resolved the capability (d81-uncr), which makes the
restart path the interesting one and worth testing without IDA.

Every view this lifecycle issues names its own
:class:`~d810.mba.residual_observation_sink.MbaResidualSinkRelay`, created with
the lifecycle and owned by it alone.  A restart retargets that relay; it never
consults process state.  A view from one lifecycle therefore cannot reach
another lifecycle's store, and a retired lifecycle's views fail closed while a
successor lifecycle runs (d81-mcqr).
"""

from __future__ import annotations

import os
import threading
from collections.abc import Mapping
from pathlib import Path

from d810.core.typing import Any, Callable
from d810.mba.extension_api import (
    D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,
    MbaResidualObservationSink,
)
from d810.mba.residual_observation_sink import (
    MbaResidualSinkRelay,
    SqliteMbaResidualObservationSink,
)

__all__ = [
    "MbaResidualObservationLifecycle",
    "resolve_mba_discovery_store_path",
]


def resolve_mba_discovery_store_path(
    manager_log_dir: str | Path,
    *,
    environment: Mapping[str, str] | None = None,
) -> Path:
    """Return the discovery DB owned by this diagnostic execution.

    System-test batches set ``D810_DIAG_LOG_DIR`` to a directory unique to the
    batch.  Keeping the discovery store there prevents concurrent shards from
    migrating the same user-log database.  Interactive sessions do not set the
    override and retain the existing manager-log location.
    """

    active_environment = os.environ if environment is None else environment
    diagnostic_log_dir = active_environment.get("D810_DIAG_LOG_DIR", "").strip()
    base = Path(diagnostic_log_dir) if diagnostic_log_dir else Path(manager_log_dir)
    return base / "d810_mba_discovery.sqlite3"


class MbaResidualObservationLifecycle:
    """Own one capability registration and its replaceable sink generation."""

    def __init__(
        self,
        *,
        store_factory: Callable[[], Any],
        registry_factory: Callable[[], Any],
        sink_factory: Callable[
            [Any], SqliteMbaResidualObservationSink
        ] = SqliteMbaResidualObservationSink,
        capability_id: str = D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,
        protocol: type = MbaResidualObservationSink,
        relay_factory: Callable[[], MbaResidualSinkRelay] = MbaResidualSinkRelay,
    ) -> None:
        self._store_factory = store_factory
        self._registry_factory = registry_factory
        self._sink_factory = sink_factory
        self._capability_id = capability_id
        self._protocol = protocol
        self._lock = threading.RLock()
        # Created with the lifecycle and never replaced: this is the identity
        # every issued view is frozen against.
        self._relay = relay_factory()
        self._sink: SqliteMbaResidualObservationSink | None = None
        self._lease: Any = None
        self._closed = False

    @property
    def relay(self) -> MbaResidualSinkRelay:
        """The routing point every view issued by this lifecycle references."""
        return self._relay

    @property
    def sink(self) -> SqliteMbaResidualObservationSink | None:
        return self._sink

    @property
    def lease(self) -> Any:
        return self._lease

    @property
    def started(self) -> bool:
        return self._sink is not None

    @property
    def closed(self) -> bool:
        return self._closed

    def start(self) -> SqliteMbaResidualObservationSink:
        """Register a fresh sink generation and point the relay at it."""
        with self._lock:
            self._reject_if_closed()
            if self._sink is not None:
                return self._sink
            sink, lease = self._provision()
            self._relay.install(sink)
            self._sink = sink
            self._lease = lease
            return sink

    def restart(self) -> SqliteMbaResidualObservationSink:
        """Replace the generation without ever leaving the relay untargeted.

        The old sink stays live until the new one is ready, and the swap itself
        happens under the relay's own lock, so an observation racing the
        restart lands wholly in one generation instead of being rejected.
        """
        with self._lock:
            self._reject_if_closed()
            if self._sink is None:
                return self.start()
            sink, lease = self._provision(release_first=True)
            self._relay.install(sink)  # closes the previous generation
            self._sink = sink
            self._lease = lease
            return sink

    def stop(self) -> None:
        """Release the registration and close the generation it published."""
        with self._lock:
            self._release_lease()
            self._sink = None
            self._relay.retire()

    def close(self) -> None:
        """Retire this lifecycle for good: its views can never record again."""
        with self._lock:
            self._release_lease()
            self._sink = None
            self._closed = True
            self._relay.close()

    def _reject_if_closed(self) -> None:
        if self._closed:
            raise RuntimeError(
                "the MBA residual observation lifecycle is retired; "
                "build a new one instead of reviving its views"
            )

    def _release_lease(self) -> None:
        lease = self._lease
        self._lease = None
        if lease is not None:
            lease.release()

    def _provision(
        self, *, release_first: bool = False
    ) -> tuple[SqliteMbaResidualObservationSink, Any]:
        """Build the next sink and take the capability registration for it."""
        sink = self._sink_factory(self._store_factory())
        try:
            if release_first:
                # One capability ID at a time: the old lease must go before the
                # new one is taken.  The relay keeps routing to the old sink
                # meanwhile, so no observation is dropped in this window.
                self._release_lease()
            lease = self._registry_factory().register(
                self._capability_id,
                self._protocol,
                self._relay,
                activation_binder=self._relay.bind_activation,
                implementation_binder=self._relay.bind_implementation,
            )
        except BaseException:
            sink.close()
            raise
        return sink, lease

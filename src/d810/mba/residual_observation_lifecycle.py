"""Host-owned lifetime for the MBA residual-observation capability.

The manager owns the sink, but the manager is IDA-bound and is rebuilt on
every reload, so the *sequencing* of register/publish/release lives here as
pure Python.  ``state.load_project()`` stops and restarts the manager after a
provider rule has already resolved the capability (d81-uncr), which makes the
restart path the interesting one and worth testing without IDA.
"""

from __future__ import annotations

import threading

from d810.core.typing import Any, Callable
from d810.mba.extension_api import (
    D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,
    MbaResidualObservationSink,
)
from d810.mba.residual_observation_sink import (
    SqliteMbaResidualObservationSink,
    clear_active_residual_sink,
    install_active_residual_sink,
)

__all__ = ["MbaResidualObservationLifecycle"]


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
    ) -> None:
        self._store_factory = store_factory
        self._registry_factory = registry_factory
        self._sink_factory = sink_factory
        self._capability_id = capability_id
        self._protocol = protocol
        self._lock = threading.RLock()
        self._sink: SqliteMbaResidualObservationSink | None = None
        self._lease: Any = None

    @property
    def sink(self) -> SqliteMbaResidualObservationSink | None:
        return self._sink

    @property
    def lease(self) -> Any:
        return self._lease

    @property
    def started(self) -> bool:
        return self._sink is not None

    def start(self) -> SqliteMbaResidualObservationSink:
        """Register a fresh sink generation and publish it as the active one."""
        with self._lock:
            if self._sink is not None:
                return self._sink
            sink = self._sink_factory(self._store_factory())
            try:
                lease = self._registry_factory().register(
                    self._capability_id,
                    self._protocol,
                    sink,
                    activation_binder=sink.bind_activation,
                    implementation_binder=sink.bind_implementation,
                )
            except BaseException:
                sink.close()
                raise
            install_active_residual_sink(sink)
            self._sink = sink
            self._lease = lease
            return sink

    def stop(self) -> None:
        """Release the registration and close the generation it published."""
        with self._lock:
            lease = self._lease
            self._lease = None
            try:
                if lease is not None:
                    lease.release()
            finally:
                sink = self._sink
                self._sink = None
                if sink is not None:
                    clear_active_residual_sink(sink)
                    sink.close()

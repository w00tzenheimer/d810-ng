"""Opt-in native performance instrumentation registry.

The registry is deliberately owned by :mod:`d810.core`.  Optional/native
modules register their own callbacks when imported; the manager only toggles
and snapshots the registry at lifecycle boundaries.  This keeps the hot path
free of imports and prevents a core module from reaching upward into a native
backend.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Callable, Mapping
from d810.core.typing import Any

SCHEMA_VERSION = 1
RECEIPT_PREFIX = "D810_NATIVE_PERF_RECEIPT="
_CLOCK_METADATA = {
    "native_source": "std::chrono::steady_clock",
    "python_source": "time.perf_counter_ns",
    "unit": "ns",
    "monotonic": True,
    "read_counter": "counters.clock_reads",
}

SnapshotCallback = Callable[[], Mapping[str, Any]]
ConfigureCallback = Callable[[bool], None]
ResetCallback = Callable[[], None]


class _Provider:
    __slots__ = ("snapshot", "configure", "reset")

    def __init__(
        self,
        snapshot: SnapshotCallback,
        configure: ConfigureCallback | None,
        reset: ResetCallback | None,
    ) -> None:
        self.snapshot = snapshot
        self.configure = configure
        self.reset = reset


_lock = threading.RLock()
_providers: dict[str, _Provider] = {}
_provider_errors: dict[str, str] = {}
_enabled = False
_session_generation = 0
_session_context: dict[str, Any] = {}


def _safe_value(value: Any) -> Any:
    """Copy only JSON scalar/container values into a receipt.

    Native/IDA providers must never put SWIG-owned objects in a receipt.  An
    unknown object is represented by a type marker rather than retained or
    stringified through an object-specific ``__str__`` implementation.
    """

    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _safe_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_safe_value(item) for item in value]
    return f"<non-serializable:{type(value).__name__}>"


def _record_provider_error(name: str, phase: str, exc: Exception) -> None:
    _provider_errors[name] = f"{phase}: {type(exc).__name__}: {exc}"


def register_provider(
    name: str,
    *,
    snapshot: SnapshotCallback,
    configure: ConfigureCallback | None = None,
    reset: ResetCallback | None = None,
) -> None:
    """Register or replace one provider and synchronize its enabled state.

    Native modules can be imported after a manager session has started.  The
    newly registered provider therefore receives the current configuration
    immediately rather than waiting for the next session.
    """

    provider_name = str(name)
    if not provider_name:
        raise ValueError("native performance provider name must not be empty")
    if not callable(snapshot):
        raise TypeError("native performance provider snapshot must be callable")
    if configure is not None and not callable(configure):
        raise TypeError("native performance provider configure must be callable")
    if reset is not None and not callable(reset):
        raise TypeError("native performance provider reset must be callable")

    with _lock:
        previous = _providers.get(provider_name)
        if previous is not None and previous.configure is not None:
            try:
                # Retire a replaced provider before installing its successor;
                # this prevents a pure-Python callback from continuing to
                # count after the compiled provider takes its stable name.
                previous.configure(False)
            except Exception as exc:  # noqa: BLE001 - provider isolation
                _record_provider_error(provider_name, "retire", exc)
        _providers[provider_name] = _Provider(snapshot, configure, reset)
        enabled = _enabled
        _provider_errors.pop(provider_name, None)
        if configure is not None:
            try:
                configure(enabled)
            except Exception as exc:  # noqa: BLE001 - provider isolation
                _record_provider_error(provider_name, "configure", exc)


def enabled() -> bool:
    """Return whether native performance counters are enabled."""

    with _lock:
        return _enabled


def configure(value: bool) -> bool:
    """Set the process-wide instrumentation flag and notify providers."""

    requested = bool(value)
    with _lock:
        global _enabled
        _enabled = requested
        for name, provider in sorted(_providers.items()):
            if provider.configure is None:
                continue
            try:
                provider.configure(requested)
                _provider_errors.pop(name, None)
            except Exception as exc:  # noqa: BLE001 - provider isolation
                _record_provider_error(name, "configure", exc)
    return requested


def configure_from_env(
    environ: Mapping[str, str] | None = None,
) -> bool:
    """Configure from ``D810_NATIVE_PERF`` (only the value ``"1"`` opts in)."""

    values = os.environ if environ is None else environ
    return configure(values.get("D810_NATIVE_PERF", "") == "1")


def reset(session: Mapping[str, Any] | None = None) -> int:
    """Reset counters and advance the lifecycle generation.

    ``session`` is copied through :func:`_safe_value`, so a caller may pass
    event metadata without allowing native/IDA objects into the receipt.
    """

    global _session_context, _session_generation
    with _lock:
        _session_generation += 1
        _session_context = (
            {} if session is None else dict(_safe_value(session))
        )
        for name, provider in sorted(_providers.items()):
            if provider.reset is None:
                continue
            try:
                provider.reset()
                _provider_errors.pop(name, None)
            except Exception as exc:  # noqa: BLE001 - provider isolation
                _record_provider_error(name, "reset", exc)
        return _session_generation


def snapshot() -> dict[str, Any]:
    """Return a stable, JSON-compatible snapshot of all providers."""

    with _lock:
        provider_items = tuple(sorted(_providers.items()))
        current_enabled = _enabled
        generation = _session_generation
        session = dict(_session_context)

    snapshots: dict[str, Any] = {}
    for name, provider in provider_items:
        try:
            value = provider.snapshot()
            if not isinstance(value, Mapping):
                raise TypeError("provider snapshot must return a mapping")
            snapshots[name] = _safe_value(value)
        except Exception as exc:  # noqa: BLE001 - observability must not abort lifecycle
            snapshots[name] = {
                "backend": "unavailable",
                "counters": {},
            }
            with _lock:
                _record_provider_error(name, "snapshot", exc)

    with _lock:
        provider_errors = dict(sorted(_provider_errors.items()))
    backends = sorted(
        {
            str(value.get("backend"))
            for value in snapshots.values()
            if isinstance(value, Mapping) and value.get("backend") is not None
        }
    )
    backend = (
        "none"
        if not backends
        else backends[0]
        if len(backends) == 1
        else "mixed"
    )
    provider_identities = {
        name: {
            "backend": value.get("backend", "unknown"),
            "counter_domain": value.get("counter_domain", "unknown"),
            "provider_version": value.get("provider_version"),
        }
        for name, value in sorted(snapshots.items())
        if isinstance(value, Mapping)
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "enabled": current_enabled,
        "backend": backend,
        "provider_names": sorted(snapshots),
        "provider_identities": provider_identities,
        "session_generation": generation,
        "session": session,
        "clock": dict(_CLOCK_METADATA),
        "cython_profile_requested": os.environ.get("D810_CYTHON_PROFILE") == "1",
        "complete": not provider_errors,
        "provider_errors": provider_errors,
        "providers": snapshots,
    }


def receipt_json() -> str | None:
    """Serialize one deterministic receipt, or ``None`` when disabled."""

    if not enabled():
        return None
    return json.dumps(snapshot(), sort_keys=True, separators=(",", ":"))


def receipt_line() -> str | None:
    """Return the stable log-line representation used by lifecycle reporting."""

    payload = receipt_json()
    return None if payload is None else f"{RECEIPT_PREFIX}{payload}"


def clear_providers_for_tests() -> None:
    """Clear providers for isolated unit tests.

    Production lifecycle code never clears the registry: native modules remain
    importable for the lifetime of the IDA process and may re-register safely.
    """

    global _enabled, _session_context, _session_generation
    with _lock:
        callbacks = tuple(
            provider.configure
            for provider in _providers.values()
            if provider.configure is not None
        )
        for callback in callbacks:
            try:
                callback(False)
            except Exception:
                pass
        _providers.clear()
        _provider_errors.clear()
        _enabled = False
        _session_generation = 0
        _session_context = {}


__all__ = [
    "RECEIPT_PREFIX",
    "SCHEMA_VERSION",
    "clear_providers_for_tests",
    "configure",
    "configure_from_env",
    "enabled",
    "receipt_json",
    "receipt_line",
    "register_provider",
    "reset",
    "snapshot",
]

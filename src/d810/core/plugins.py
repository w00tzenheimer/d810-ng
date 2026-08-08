"""Backend plugin protocol: discovery, versioning, and status reporting.

d810's backends have always been *documented* as optional (see
``d810/backends/README.md``), but the mechanism was a per-module
``try: import x; X_AVAILABLE = True`` flag. That works in-tree and nowhere
else: an out-of-tree distribution has no way to announce itself, and the flag
collapses "optional dependency absent" together with "this plugin is buggy".

This module supplies the missing half. It is deliberately *not* a contract on
what a backend does -- that is domain-specific and belongs to the domain. It is
a contract on how a backend is **found**, **version-gated**, **loaded**, and
**reported on when it doesn't work**.

Three properties are load-bearing, each for a reason that has already bitten
this project:

**Builtins are a static table, not entry points.**
    d810 is deployed as a symlink into a source checkout
    (``~/.idapro/plugins/d810 -> <worktree>``) while ``pip`` metadata for
    ``d810-ng`` may separately exist in site-packages at a *different version*.
    Entry points are read from that metadata, so trusting them for in-tree
    backends would mean the plugin list describes one version while another
    version executes. Entry points are therefore an additive overlay for
    out-of-tree plugins only.

**The API version lives in the entry-point group name.**
    ``d810.backends.v1``. Reading a version attribute would require importing
    the plugin, which is exactly what must not happen for a plugin we are about
    to reject. A stale plugin is still *reported* (so the user learns why
    nothing happened) but never imported.

**Discovery is lazy and cached.**
    ``importlib.metadata.entry_points()`` measures ~31 ms cold / ~4 ms warm.
    That is not a cost to pay at import time inside an IDA plugin load.

Availability has one more subtlety that the old flags could not express: a
backend can import perfectly and still be unusable, because its native half is
missing. A backend says so by defining::

    def d810_backend_probe() -> str | None:
        '''Return None if usable, else a human-readable reason.'''

which is how ``COBRA BINDING: False`` becomes a reportable state rather than a
wheel that installs cleanly and silently simplifies nothing.
"""

from __future__ import annotations

import enum
import importlib
import threading
from dataclasses import dataclass, field

from d810.core.typing import Any, Callable, Iterable, Sequence

from .logging import getLogger

logger = getLogger(__name__)

__all__ = [
    "DEFECT_STATUSES",
    "PLUGIN_API_VERSION",
    "BackendInfo",
    "BackendRegistry",
    "BackendSpec",
    "BackendStatus",
    "BackendUnavailable",
    "builtin",
    "entry_point_group",
    "entry_point_source",
    "format_report",
    "has_defects",
    "make_singleton",
]

#: Protocol version this d810 speaks. Bump ONLY on a breaking change to what a
#: backend object must look like; the group name changes with it, so old
#: plugins stop being discovered instead of failing somewhere deep.
PLUGIN_API_VERSION = 1

_GROUP_PREFIX = "d810.backends.v"


def entry_point_group(version: int | None = None) -> str:
    """Return the entry-point group for *version* (default: the current one)."""
    return f"{_GROUP_PREFIX}{PLUGIN_API_VERSION if version is None else version}"


class BackendUnavailable(RuntimeError):
    """Raised when a backend is requested but cannot be provided."""


class BackendStatus(enum.Enum):
    """Why a backend is or isn't usable.

    ``UNAVAILABLE`` and ``BROKEN`` are separate on purpose: the first is a
    normal deployment fact (an optional dependency isn't installed), the second
    is a defect that someone must fix. Reporting them as one value is how a
    plugin raising ``AttributeError`` on import gets filed as "not installed".
    """

    NOT_LOADED = "not_loaded"
    """Discovered, version-compatible, not yet imported."""

    AVAILABLE = "available"
    """Imported, and its probe (if any) reported no problem."""

    UNAVAILABLE = "unavailable"
    """Expected absence: ImportError, or a probe that returned a reason."""

    INCOMPATIBLE = "incompatible"
    """Declares a protocol version this d810 does not speak. Never imported."""

    BROKEN = "broken"
    """Raised something other than ImportError. A bug in the plugin."""


@dataclass(frozen=True)
class BackendSpec:
    """A discovered backend, not yet imported.

    ``load`` is a thunk rather than a module path so tests and builtins can
    supply one without going through installed metadata.
    """

    name: str
    load: Callable[[], Any]
    api_version: int = PLUGIN_API_VERSION
    origin: str = "unknown"


@dataclass(frozen=True)
class BackendInfo:
    """Reportable state of one backend. Cheap to produce; never imports."""

    name: str
    status: BackendStatus
    origin: str
    api_version: int
    reason: str | None = None
    shadowed: tuple[str, ...] = field(default=())

    @property
    def usable(self) -> bool:
        return self.status is BackendStatus.AVAILABLE


def _import_target(target: str) -> Any:
    """Import ``"pkg.mod"`` or ``"pkg.mod:attr"``.

    A missing attribute raises AttributeError, which the registry classifies as
    BROKEN -- correct, because it means the plugin declared something it does
    not actually provide.
    """
    module_name, _, attr = target.partition(":")
    obj = importlib.import_module(module_name)
    return getattr(obj, attr) if attr else obj


def builtin(name: str, target: str) -> BackendSpec:
    """A backend that ships inside d810 and needs no installed metadata."""
    return BackendSpec(
        name=name,
        load=lambda: _import_target(target),
        api_version=PLUGIN_API_VERSION,
        origin="builtin",
    )


def _origin_of(entry_point: Any) -> str:
    """Best-effort ``"<dist> <version>"`` label, for diagnosing version skew."""
    dist = getattr(entry_point, "dist", None)
    if dist is None:
        return "entry-point"
    try:
        return f"{dist.metadata['Name']} {dist.version}"
    except Exception:
        return "entry-point"


def _parse_group_version(group: str) -> int | None:
    try:
        return int(group[len(_GROUP_PREFIX) :])
    except ValueError:
        return None


def entry_point_source() -> list[BackendSpec]:
    """Scan installed distributions for backends in any ``d810.backends.vN``.

    Every version is collected, not just the current one, so a stale plugin can
    be reported as INCOMPATIBLE rather than vanishing without explanation.
    """
    import importlib.metadata as metadata

    found = metadata.entry_points()
    specs: list[BackendSpec] = []
    for group in getattr(found, "groups", ()):
        if not group.startswith(_GROUP_PREFIX):
            continue
        version = _parse_group_version(group)
        if version is None:
            continue
        for entry_point in found.select(group=group):
            specs.append(
                BackendSpec(
                    name=entry_point.name,
                    load=entry_point.load,
                    api_version=version,
                    origin=_origin_of(entry_point),
                )
            )
    return specs


class BackendRegistry:
    """Discovers backends, gates them by version, and loads them on demand.

    Thread-safe: d810 loads backends from worker threads (the CoBRA escalation
    prover among them), and a re-entrant lock keeps a probe that triggers an
    import from deadlocking against the discovery that found it.
    """

    def __init__(
        self,
        *,
        builtins: Sequence[BackendSpec] = (),
        source: Callable[[], Iterable[BackendSpec]] | None = None,
    ) -> None:
        self._builtins = tuple(builtins)
        self._source = source if source is not None else entry_point_source
        self._lock = threading.RLock()
        self._discovered = False
        self._specs: dict[str, BackendSpec] = {}
        self._shadowed: dict[str, tuple[str, ...]] = {}
        self._status: dict[str, BackendStatus] = {}
        self._reason: dict[str, str | None] = {}
        self._loaded: dict[str, Any] = {}
        self._errors: dict[str, BaseException] = {}

    # -- discovery ---------------------------------------------------------

    def discover(self, *, force: bool = False) -> None:
        """Populate the registry. Cheap after the first call unless *force*."""
        with self._lock:
            if self._discovered and not force:
                return

            specs: dict[str, BackendSpec] = {s.name: s for s in self._builtins}
            shadowed: dict[str, tuple[str, ...]] = {}

            try:
                discovered = list(self._source())
            except Exception:
                # A corrupt dist-info in site-packages must not take d810 down;
                # builtins alone are a working configuration.
                logger.exception("backend discovery failed; using builtins only")
                discovered = []

            for spec in discovered:
                previous = specs.get(spec.name)
                if previous is not None:
                    shadowed[spec.name] = shadowed.get(spec.name, ()) + (
                        previous.origin,
                    )
                    logger.info(
                        "backend %r from %s shadows %s",
                        spec.name,
                        spec.origin,
                        previous.origin,
                    )
                specs[spec.name] = spec

            self._specs = specs
            self._shadowed = shadowed
            self._status = {}
            self._reason = {}
            self._loaded = {}
            self._errors = {}

            for name, spec in specs.items():
                if spec.api_version != PLUGIN_API_VERSION:
                    self._status[name] = BackendStatus.INCOMPATIBLE
                    self._reason[name] = (
                        f"declares plugin API v{spec.api_version}; "
                        f"this d810 speaks v{PLUGIN_API_VERSION}"
                    )
                else:
                    self._status[name] = BackendStatus.NOT_LOADED
                    self._reason[name] = None

            self._discovered = True

    # -- introspection (never imports) -------------------------------------

    def names(self) -> list[str]:
        self.discover()
        with self._lock:
            return sorted(self._specs)

    def info(self, name: str) -> BackendInfo:
        """Current known state of *name*. Does not import; see :meth:`probe`."""
        self.discover()
        with self._lock:
            spec = self._specs[name]
            return BackendInfo(
                name=name,
                status=self._status[name],
                origin=spec.origin,
                api_version=spec.api_version,
                reason=self._reason[name],
                shadowed=self._shadowed.get(name, ()),
            )

    def report(self) -> list[BackendInfo]:
        """Every backend's known state, sorted. Cheap: imports nothing."""
        return [self.info(name) for name in self.names()]

    # -- ground truth (imports) --------------------------------------------

    def probe(self, name: str) -> BackendInfo:
        """Resolve *name* to a definite status, importing it if necessary."""
        self.discover()
        with self._lock:
            if self._status[name] is BackendStatus.NOT_LOADED:
                self._attempt_load(name)
            return self.info(name)

    def probe_all(self) -> list[BackendInfo]:
        """Ground truth for every backend. Imports; use for diagnostics."""
        return [self.probe(name) for name in self.names()]

    def load(self, name: str) -> Any:
        """Return the backend object, or raise :class:`BackendUnavailable`."""
        self.discover()
        with self._lock:
            if name not in self._specs:
                raise BackendUnavailable(f"no backend named {name!r}")
            info = self.probe(name)
            if info.status is BackendStatus.AVAILABLE:
                return self._loaded[name]
            raise BackendUnavailable(
                f"backend {name!r} is {info.status.value}: {info.reason}"
            ) from self._errors.get(name)

    def optional(self, name: str) -> Any | None:
        """Return the backend object, or ``None``. Never raises."""
        try:
            return self.load(name)
        except BackendUnavailable:
            return None

    # -- internals ---------------------------------------------------------

    def _attempt_load(self, name: str) -> None:
        """Import *name* once and record the outcome. Caller holds the lock."""
        spec = self._specs[name]
        try:
            obj = spec.load()
        except ImportError as exc:
            self._settle(name, BackendStatus.UNAVAILABLE, str(exc), exc)
            return
        except Exception as exc:
            self._settle(
                name, BackendStatus.BROKEN, f"{type(exc).__name__}: {exc}", exc
            )
            logger.exception("backend %r raised while loading", name)
            return

        hook = getattr(obj, "d810_backend_probe", None)
        if hook is None:
            self._settle(name, BackendStatus.AVAILABLE, None, None, obj)
            return

        try:
            reason = hook()
        except Exception as exc:
            self._settle(
                name, BackendStatus.BROKEN, f"probe raised {type(exc).__name__}: {exc}", exc
            )
            logger.exception("backend %r probe raised", name)
            return

        if reason:
            self._settle(name, BackendStatus.UNAVAILABLE, str(reason), None)
        else:
            self._settle(name, BackendStatus.AVAILABLE, None, None, obj)

    def _settle(
        self,
        name: str,
        status: BackendStatus,
        reason: str | None,
        error: BaseException | None,
        obj: Any = None,
    ) -> None:
        self._status[name] = status
        self._reason[name] = reason
        if error is not None:
            self._errors[name] = error
        if status is BackendStatus.AVAILABLE:
            self._loaded[name] = obj


#: States that mean something is wrong rather than merely absent. An optional
#: dependency that isn't installed is a normal deployment; a plugin that raises
#: on import, or one built against a protocol version this d810 no longer
#: speaks, is a defect someone has to act on.
DEFECT_STATUSES = frozenset({BackendStatus.BROKEN, BackendStatus.INCOMPATIBLE})


def has_defects(infos: Iterable[BackendInfo]) -> bool:
    """Whether any backend is in a state that warrants a non-zero exit."""
    return any(info.status in DEFECT_STATUSES for info in infos)


def format_report(infos: Sequence[BackendInfo]) -> str:
    """Render a report for humans. Pure formatting; imports nothing."""
    if not infos:
        return "no backends registered"

    width = max(len(info.name) for info in infos)
    lines = []
    for info in infos:
        line = f"{info.name:<{width}}  {info.status.value:<12}  {info.origin}"
        if info.shadowed:
            line += f" (shadows {', '.join(info.shadowed)})"
        if info.reason:
            line += f"\n{' ' * width}  -> {info.reason}"
        lines.append(line)
    return "\n".join(lines)


def make_singleton(
    factory: Callable[[], BackendRegistry],
) -> Callable[[], BackendRegistry]:
    """Wrap *factory* so it builds one registry, once, thread-safely.

    Lives here because the locking is fiddly, but the registry it produces is
    assembled by the ``backends`` package -- this module deliberately does not
    know which backends d810 ships.
    """
    lock = threading.Lock()
    holder: list[BackendRegistry] = []

    def get() -> BackendRegistry:
        if not holder:
            with lock:
                if not holder:
                    holder.append(factory())
        return holder[0]

    return get

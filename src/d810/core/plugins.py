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

Four properties are load-bearing, each for a reason that has already bitten
this project:

**Builtins are a static table, not entry points.**
    d810 is deployed as a symlink into a source checkout
    (``~/.idapro/plugins/d810 -> <worktree>``) while ``pip`` metadata for
    ``d810-ng`` may separately exist in site-packages at a *different version*.
    Entry points are read from that metadata, so trusting them for in-tree
    backends would mean the plugin list describes one version while another
    version executes. Entry points are therefore an additive overlay for
    out-of-tree plugins only.

**The entry-point group carries no version.**
    It is ``d810.backends``, stable forever. Versioning the group name
    (``d810.backends.v1``) churns it on every protocol bump and forces every
    extension author to notice; the version belongs to the thing being
    versioned.

**A manifest may be declared with or without importing d810.**
    The manifest states the extension's ``api_version``. Importing
    :class:`BackendManifest` is perfectly fine and gives a typed declaration;
    :func:`manifest_of` equally accepts a plain mapping, or any object carrying
    ``name`` / ``api_version`` / ``provides``, for an extension that prefers no
    import-time dependency on d810 at all. Both are supported because
    supporting both costs one coercion function.

    The one thing to keep in mind: if a future protocol version renamed or
    removed ``BackendManifest``, manifests that import it would fail as
    UNAVAILABLE rather than reporting INCOMPATIBLE. That is entirely within our
    control -- treat the symbol as frozen.

**Discovery is lazy and cached.**
    ``importlib.metadata.entry_points()`` measures ~31 ms cold / ~4 ms warm.
    That is not a cost to pay at import time inside an IDA plugin load. Nothing
    may call the registry during d810's own import, or the manifests it loads
    can observe a half-initialised d810.

The manifest is contractually cheap to import and names its backend with a
``provides`` string resolved *lazily*, so an incompatible plugin costs one
import of a dataclass literal and its heavy half -- native extension, z3,
whatever -- is never touched.

Availability has one more subtlety the old flags could not express: a backend
can import perfectly and still be unusable, because its native half is missing.
A backend says so by defining::

    def d810_backend_probe() -> str | None:
        '''Return None if usable, else a human-readable reason.'''

which is how ``COBRA BINDING: False`` becomes a reportable state rather than a
wheel that installs cleanly and silently simplifies nothing.

An out-of-tree extension looks like this (dependency-free flavour; using
:class:`BackendManifest` instead is equally valid)::

    # pyproject.toml
    [project.entry-points."d810.backends"]
    cobra = "d810_backend_cobra:MANIFEST"

    # d810_backend_cobra/__init__.py
    MANIFEST = {"name": "cobra", "api_version": 1,
                "provides": "d810_backend_cobra.binding:api"}

The module named by ``provides`` may import d810 freely: it is resolved long
after d810 has finished loading. It must not, however, cache d810 objects at
module scope -- the reloader will not evict it (its name is not ``d810.*``), so
module-level references go stale across a hot reload.
"""

from __future__ import annotations

import enum
import importlib
import threading
from dataclasses import dataclass, field

from d810.core.typing import Any, Callable, Iterable, Mapping, Sequence

from .logging import getLogger

logger = getLogger(__name__)

__all__ = [
    "DEFECT_STATUSES",
    "ENTRY_POINT_GROUP",
    "PLUGIN_API_VERSION",
    "BackendInfo",
    "BackendManifest",
    "BackendRegistry",
    "BackendSpec",
    "BackendStatus",
    "BackendUnavailable",
    "builtin",
    "entry_point_source",
    "format_report",
    "has_defects",
    "make_singleton",
    "manifest_of",
]

#: Protocol version this d810 speaks. Bump ONLY on a breaking change to what a
#: backend object must look like. Extensions declare the version they were
#: built for in their manifest; a mismatch is reported, never imported further.
PLUGIN_API_VERSION = 1

#: Stable entry-point group. Deliberately unversioned -- see module docstring.
ENTRY_POINT_GROUP = "d810.backends"


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
    """Discovered; its manifest has not been read yet."""

    AVAILABLE = "available"
    """Resolved, and its probe (if any) reported no problem."""

    UNAVAILABLE = "unavailable"
    """Expected absence: ImportError, or a probe that returned a reason."""

    INCOMPATIBLE = "incompatible"
    """Manifest declares a version this d810 does not speak. Never resolved."""

    BROKEN = "broken"
    """Raised something other than ImportError, or shipped a bad manifest."""


@dataclass(frozen=True)
class BackendManifest:
    """What an extension declares about itself.

    Extensions may import this for a typed declaration, or skip it entirely:
    :func:`manifest_of` accepts any mapping or object carrying these three
    names. Treat this class as frozen -- renaming it would turn every manifest
    that imports it from INCOMPATIBLE into a bare ImportError.

    ``provides`` is an import target (``"pkg.mod:attr"``) resolved lazily, or a
    callable returning the backend. The indirection is what keeps a rejected
    plugin's heavy half from ever being imported.
    """

    name: str
    api_version: int
    provides: str | Callable[[], Any]


_MANIFEST_FIELDS = ("name", "api_version", "provides")


class ManifestError(ValueError):
    """A manifest is missing required fields or has the wrong shape."""


def manifest_of(raw: Any) -> BackendManifest:
    """Coerce a duck-typed manifest into a :class:`BackendManifest`."""
    if isinstance(raw, BackendManifest):
        return raw

    getter = (
        (lambda key: raw[key])
        if isinstance(raw, Mapping)
        else (lambda key: getattr(raw, key))
    )

    values = {}
    missing = []
    for key in _MANIFEST_FIELDS:
        try:
            values[key] = getter(key)
        except (KeyError, AttributeError):
            missing.append(key)
    if missing:
        raise ManifestError(
            f"manifest is missing {', '.join(missing)} "
            f"(needs {', '.join(_MANIFEST_FIELDS)})"
        )

    try:
        api_version = int(values["api_version"])
    except (TypeError, ValueError) as exc:
        raise ManifestError(
            f"manifest api_version must be an int, got {values['api_version']!r}"
        ) from exc

    return BackendManifest(
        name=str(values["name"]),
        api_version=api_version,
        provides=values["provides"],
    )


@dataclass(frozen=True)
class BackendSpec:
    """A discovered backend whose manifest has not been read yet.

    ``load_manifest`` is a thunk rather than a value so discovery stays free:
    nothing is imported until someone probes.
    """

    name: str
    load_manifest: Callable[[], Any]
    origin: str = "unknown"


@dataclass(frozen=True)
class BackendInfo:
    """Reportable state of one backend. Cheap to produce; never imports."""

    name: str
    status: BackendStatus
    origin: str
    api_version: int | None = None
    reason: str | None = None
    shadowed: tuple[str, ...] = field(default=())

    #: ``(origin, reason)`` for candidates tried before the one that settled.
    #: Non-empty means d810 is running on a fallback: something the user
    #: installed did not work and an in-tree backend took over. Counted as a
    #: defect so it cannot degrade silently.
    rejected: tuple[tuple[str, str], ...] = field(default=())

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


def _resolve_provides(provides: str | Callable[[], Any]) -> Any:
    return provides() if callable(provides) else _import_target(provides)


def builtin(name: str, target: str) -> BackendSpec:
    """A backend that ships inside d810 and needs no installed metadata.

    Its manifest is synthesised rather than imported: a builtin cannot be
    version-skewed against the d810 it lives in.
    """
    manifest = BackendManifest(
        name=name, api_version=PLUGIN_API_VERSION, provides=target
    )
    return BackendSpec(name=name, origin="builtin", load_manifest=lambda: manifest)


def _origin_of(entry_point: Any) -> str:
    """Best-effort ``"<dist> <version>"`` label, for diagnosing version skew."""
    dist = getattr(entry_point, "dist", None)
    if dist is None:
        return "entry-point"
    try:
        return f"{dist.metadata['Name']} {dist.version}"
    except Exception:
        return "entry-point"


def entry_point_source() -> list[BackendSpec]:
    """Scan installed distributions for backends in the ``d810.backends`` group.

    The entry point resolves to the extension's *manifest*, not its backend, so
    loading one is contractually cheap.
    """
    import importlib.metadata as metadata

    return [
        BackendSpec(
            name=entry_point.name,
            origin=_origin_of(entry_point),
            load_manifest=entry_point.load,
        )
        for entry_point in metadata.entry_points(group=ENTRY_POINT_GROUP)
    ]


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
        #: name -> candidates, most preferred first (entry points, then builtins)
        self._candidates: dict[str, tuple[BackendSpec, ...]] = {}
        self._settled: dict[str, BackendSpec] = {}
        self._rejected: dict[str, tuple[tuple[str, str], ...]] = {}
        self._status: dict[str, BackendStatus] = {}
        self._reason: dict[str, str | None] = {}
        self._api_version: dict[str, int | None] = {}
        self._loaded: dict[str, Any] = {}
        self._errors: dict[str, BaseException] = {}

    # -- discovery ---------------------------------------------------------

    def discover(self, *, force: bool = False) -> None:
        """Populate the registry. Cheap after the first call unless *force*."""
        with self._lock:
            if self._discovered and not force:
                return

            try:
                discovered = list(self._source())
            except Exception:
                # A corrupt dist-info in site-packages must not take d810 down;
                # builtins alone are a working configuration.
                logger.exception("backend discovery failed; using builtins only")
                discovered = []

            # Entry points are preferred, builtins are the fallback. Keeping
            # BOTH rather than overwriting is what stops a stale third-party
            # plugin from taking a working in-tree backend down with it.
            candidates: dict[str, list[BackendSpec]] = {}
            for spec in discovered:
                candidates.setdefault(spec.name, []).append(spec)
            for spec in self._builtins:
                candidates.setdefault(spec.name, []).append(spec)

            for name, specs in candidates.items():
                if len(specs) > 1:
                    logger.info(
                        "backend %r from %s shadows %s",
                        name,
                        specs[0].origin,
                        ", ".join(s.origin for s in specs[1:]),
                    )

            self._candidates = {n: tuple(s) for n, s in candidates.items()}
            self._settled = {}
            self._rejected = {}
            self._status = {name: BackendStatus.NOT_LOADED for name in candidates}
            self._reason = {name: None for name in candidates}
            self._api_version = {name: None for name in candidates}
            self._loaded = {}
            self._errors = {}
            self._discovered = True

    # -- introspection (never imports) -------------------------------------

    def names(self) -> list[str]:
        self.discover()
        with self._lock:
            return sorted(self._candidates)

    def info(self, name: str) -> BackendInfo:
        """Current known state of *name*. Does not import; see :meth:`probe`."""
        self.discover()
        with self._lock:
            candidates = self._candidates[name]
            # Before probing, report the preferred candidate; afterwards, the
            # one that actually settled -- which may be a fallback.
            spec = self._settled.get(name, candidates[0])
            # "shadowed" is what still sits BELOW the settled candidate. Taken
            # from a fixed offset instead, a fallback would claim to shadow
            # itself; anything the fallback stepped over is in `rejected`.
            below = candidates[candidates.index(spec) + 1 :]
            return BackendInfo(
                name=name,
                status=self._status[name],
                origin=spec.origin,
                api_version=self._api_version[name],
                reason=self._reason[name],
                shadowed=tuple(s.origin for s in below),
                rejected=self._rejected.get(name, ()),
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
            if name not in self._candidates:
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
        """Try each candidate in preference order. Caller holds the lock.

        Falling back matters because the alternative is worse than it looks: a
        third-party plugin that is merely out of date would otherwise win the
        name, fail the version gate, and leave the backend entirely dead even
        though d810 ships a working one.
        """
        candidates = self._candidates[name]
        rejected: list[tuple[str, str]] = []

        for index, spec in enumerate(candidates):
            status, reason, error, obj, api_version = self._try_candidate(name, spec)
            last = index == len(candidates) - 1
            if status is BackendStatus.AVAILABLE or last:
                self._settled[name] = spec
                self._api_version[name] = api_version
                self._rejected[name] = tuple(rejected)
                self._settle(name, status, reason, error, obj)
                return
            logger.info(
                "backend %r from %s is %s; falling back to %s",
                name,
                spec.origin,
                status.value,
                candidates[index + 1].origin,
            )
            rejected.append((spec.origin, reason or status.value))

    def _try_candidate(
        self, name: str, spec: BackendSpec
    ) -> tuple[BackendStatus, str | None, BaseException | None, Any, int | None]:
        """Resolve one candidate. Returns its outcome; settles nothing."""
        try:
            raw = spec.load_manifest()
        except ImportError as exc:
            return BackendStatus.UNAVAILABLE, str(exc), exc, None, None
        except Exception as exc:
            logger.exception("backend %r manifest raised", name)
            reason = f"manifest raised {type(exc).__name__}: {exc}"
            return BackendStatus.BROKEN, reason, exc, None, None

        try:
            manifest = manifest_of(raw)
        except ManifestError as exc:
            return BackendStatus.BROKEN, str(exc), exc, None, None

        version = manifest.api_version
        if version != PLUGIN_API_VERSION:
            # Stop here: the heavy half is never imported for a plugin we are
            # rejecting, which is the whole point of the manifest indirection.
            reason = (
                f"built for plugin API v{version}; "
                f"this d810 speaks v{PLUGIN_API_VERSION}"
            )
            return BackendStatus.INCOMPATIBLE, reason, None, None, version

        try:
            obj = _resolve_provides(manifest.provides)
        except ImportError as exc:
            return BackendStatus.UNAVAILABLE, str(exc), exc, None, version
        except Exception as exc:
            logger.exception("backend %r raised while loading", name)
            reason = f"{type(exc).__name__}: {exc}"
            return BackendStatus.BROKEN, reason, exc, None, version

        hook = getattr(obj, "d810_backend_probe", None)
        if hook is None:
            return BackendStatus.AVAILABLE, None, None, obj, version

        try:
            reason = hook()
        except Exception as exc:
            logger.exception("backend %r probe raised", name)
            detail = f"probe raised {type(exc).__name__}: {exc}"
            return BackendStatus.BROKEN, detail, exc, None, version

        if reason:
            return BackendStatus.UNAVAILABLE, str(reason), None, None, version
        return BackendStatus.AVAILABLE, None, None, obj, version

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
    """Whether any backend is in a state that warrants a non-zero exit.

    A rejected candidate counts even when a fallback took over: running on the
    builtin because the user's plugin is stale is a working configuration, but
    not the one they asked for, and it should not pass silently.
    """
    return any(
        info.status in DEFECT_STATUSES or info.rejected for info in infos
    )


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
        for origin, why in info.rejected:
            line += f"\n{' ' * width}  !! rejected {origin}: {why}"
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

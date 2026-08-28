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
    cobra = "d810_cobra:MANIFEST"

    # d810_cobra/__init__.py
    MANIFEST = {"name": "cobra", "api_version": 1,
                "provides": "d810_cobra.binding:api"}

The module named by ``provides`` may import d810 freely: it is resolved long
after d810 has finished loading. D810 snapshots extension-owned prefixes and
uses the generic reloader's policy-free eviction primitive before rebuilding
the core. The replacement D810 runtime then constructs a new registry and
cold-imports the manifests and rule modules. A manifest whose coupled runtime
lives under another prefix declares it in ``reload_modules``. Importing an
extension before the core reload finishes is a fail-closed ordering error that
requires an IDA restart.
"""

from __future__ import annotations

import enum
import importlib
import types
import threading
from dataclasses import dataclass, field

from d810.core.pass_ids import PassId
from d810.core.typing import (
    Any,
    Callable,
    Generic,
    Iterable,
    Mapping,
    Protocol,
    Sequence,
    TypeVar,
)

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
    "ManifestError",
    "PassImplementationAmbiguous",
    "PassImplementationCandidate",
    "ImplementationOwnership",
    "PassImplementationRequirement",
    "PassImplementationError",
    "PassImplementationMisdeclared",
    "PassImplementationMissing",
    "PassImplementationUnavailable",
    "PluginCapabilityOffer",
    "PluginIdentity",
    "PluginActivationContext",
    "PluginFunctionContext",
    "PluginHostCapabilities",
    "PluginRuleServices",
    "BackendPlugin",
    "PluginActivation",
    "builtin",
    "entry_point_source",
    "format_report",
    "has_defects",
    "make_singleton",
    "offers_capability",
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


C = TypeVar("C")


@dataclass(frozen=True, slots=True)
class PluginIdentity:
    name: str
    distribution: str | None
    version: str | None
    origin: str


class PluginHostCapabilities(Protocol):
    def require(self, capability: type[C]) -> C: ...

    def optional(self, capability: type[C]) -> C | None: ...


@dataclass(frozen=True, slots=True)
class PluginActivationContext:
    identity: PluginIdentity
    host: PluginHostCapabilities


@dataclass(frozen=True, slots=True)
class PluginRuleServices:
    """Activation-scoped services bound to one plugin-created rule."""

    plugin: PluginIdentity
    host: PluginHostCapabilities


@dataclass(frozen=True, slots=True)
class PluginFunctionContext:
    source: Any
    identity: Any
    host: PluginHostCapabilities


class PluginActivation(Protocol):
    def create_implementation(self, implementation_id: str) -> object: ...

    def capability_offers(self) -> tuple[PluginCapabilityOffer[object], ...]: ...

    def close(self) -> None: ...


class BackendPlugin(Protocol):
    def activate(self, context: PluginActivationContext) -> PluginActivation: ...


class _EmptyHostCapabilities:
    """Host view used for dependency-free activation contexts."""

    def require(self, capability: type[C]) -> C:
        raise BackendUnavailable(f"host capability {capability!r} is unavailable")

    def optional(self, capability: type[C]) -> C | None:
        return None

    def view_for(
        self, requirements: Sequence[str], identity: PluginIdentity
    ) -> PluginHostCapabilities:
        self.validate(requirements)
        return self

    def validate(self, requirements: Sequence[str]) -> None:
        if requirements:
            raise BackendUnavailable(f"missing host capability: {requirements[0]}")


@dataclass(frozen=True)
class PluginCapabilityOffer(Generic[C]):
    """A backend declaring it can satisfy one capability Protocol.

    Typed rather than stringly on purpose. ``capability`` is the Protocol
    *class*, so at the plugin author's site a type checker infers ``C`` from
    ``type[C]`` and then verifies the factory returns it::

        def _make_engine(context: PluginFunctionContext) -> ConcolicEngine:
            from d810_cobra.concolic import Engine   # deferred
            return Engine(context.source)

        PluginCapabilityOffer(ConcolicEngine, _make_engine)

    An import string would have moved that error to runtime for no gain: the
    closure above already defers the heavy import, so laziness never required
    giving up the type.

    **Construct via :func:`offers_capability`, not this class directly.**
    Verified with pyright: calling the constructor bare,
    ``PluginCapabilityOffer(Engine, wrong_factory)``, is NOT an error -- ``C``
    is solved from both arguments at once, so a mismatch widens the result to
    ``PluginCapabilityOffer[Engine | str]`` instead of failing. Direct
    construction is only checked when ``C`` is pinned, either by annotating the
    target or by writing ``PluginCapabilityOffer[Engine](...)``.
    :func:`offers_capability` pins it from the capability alone, so the factory
    is always checked.

    ``factory`` is called **per function**, not once at activation. Every
    capability in this codebase is built from live per-function state (a live
    ``mba_t`` reached through ``FunctionSource.live_source``), so an instance
    handed over at activation time would be wrong for every other function --
    and would be exactly the kind of stale cross-reload reference the hot
    reloader cannot clear.

    Neither the capability Protocol nor the factory's argument type is named
    here: ``d810.core`` is the bottom layer and may not import
    ``d810.capabilities`` or ``d810.passes``. The concrete types live at the
    author's call site, which is where checking matters.
    """

    capability: type[C]
    factory: Callable[[PluginFunctionContext], C]


def offers_capability(
    capability: type[C],
) -> Callable[[Callable[[PluginFunctionContext], C]], PluginCapabilityOffer[C]]:
    """Declare a capability offer with the factory actually type-checked.

    Curried so ``C`` is solved from *capability* alone; the returned binder then
    checks the factory against it. Calling
    :class:`PluginCapabilityOffer` directly does not achieve this -- see its
    docstring.

    Usable as a decorator::

        @offers_capability(ConcolicEngine)
        def make_engine(context: PluginFunctionContext) -> ConcolicEngine:
            from d810_cobra.concolic import Engine   # deferred
            return Engine(context.source)

        ACTIVATION = ...
    """

    def bind(factory: Callable[[PluginFunctionContext], C]) -> PluginCapabilityOffer[C]:
        return PluginCapabilityOffer(capability, factory)

    return bind


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
    #: Stable host capability identifiers required at activation time.
    requires: tuple[str, ...] = ()
    implements: Mapping[str, str] = field(
        default_factory=lambda: types.MappingProxyType({})
    )
    #: Module prefixes owned by this extension that retain D810 runtime types.
    #:
    #: The entry-point manifest module is included automatically.  Declare
    #: additional prefixes only when D810-coupled runtime code lives outside
    #: that package.  Exact prefixes avoid treating a shared namespace's first
    #: segment as extension-owned during hot reload.
    reload_modules: tuple[str, ...] = ()


_MANIFEST_FIELDS = ("name", "api_version", "provides")


class ManifestError(ValueError):
    """A manifest is missing required fields or has the wrong shape."""


@dataclass(frozen=True, slots=True)
class PassImplementationCandidate:
    """One declaration that can implement a config-v2 pass.

    The declaration contains only manifest data.  In particular, creating a
    candidate never resolves ``provides`` or imports any rule module.  This is
    what lets a caller distinguish a deterministic declaration conflict from a
    backend that is merely unavailable on the current machine.
    """

    pass_id: str
    backend_name: str
    backend_origin: str
    rule_modules: tuple[str, ...]
    rule_name: str


@dataclass(frozen=True, slots=True)
class ImplementationOwnership:
    """Exact registry ownership of one factory-created implementation."""

    candidate: PassImplementationCandidate
    instance: object


@dataclass(frozen=True, slots=True)
class PassImplementationRequirement:
    """Static optional-package requirement declared by a config-v2 pass.

    This is catalog metadata only.  It never imports, probes, or activates the
    provider.  ``activation_required`` distinguishes strict extension-backed
    passes from optional enhancement passes that remain inert when absent.
    """

    distribution: str
    backend_name: str
    activation_required: bool = True

    def __post_init__(self) -> None:
        distribution = str(self.distribution).strip()
        if not distribution:
            raise ValueError("implementation distribution must not be empty")
        backend_name = str(self.backend_name).strip()
        if not backend_name:
            raise ValueError("implementation backend name must not be empty")
        object.__setattr__(self, "distribution", distribution)
        object.__setattr__(self, "backend_name", backend_name)
        object.__setattr__(self, "activation_required", bool(self.activation_required))


class PassImplementationError(RuntimeError):
    """Base class for strict pass implementation resolution failures."""


class PassImplementationMissing(PassImplementationError):
    """No compatible backend declared an implementation for a pass."""

    def __init__(self, pass_id: str, install_hint: str) -> None:
        self.pass_id = str(pass_id)
        self.install_hint = str(install_hint)
        hint = self.install_hint
        if not hint.lower().startswith("install "):
            hint = f"install {hint}"
        super().__init__(f"pass {self.pass_id!r} has no implementation; {hint}")


class PassImplementationAmbiguous(PassImplementationError):
    """More than one compatible backend declared the same pass."""

    def __init__(
        self,
        pass_id: str,
        candidates: Iterable[PassImplementationCandidate],
    ) -> None:
        self.pass_id = str(pass_id)
        self.candidates = tuple(candidates)
        origins = ", ".join(
            f"{candidate.backend_name} ({candidate.backend_origin})"
            for candidate in self.candidates
        )
        super().__init__(
            f"pass {self.pass_id!r} has ambiguous implementations: {origins}"
        )


class PassImplementationUnavailable(PassImplementationError):
    """A declared implementation's backend could not be activated."""

    def __init__(
        self,
        candidate: PassImplementationCandidate,
        reason: str,
    ) -> None:
        self.candidate = candidate
        self.reason = str(reason)
        super().__init__(
            f"pass {candidate.pass_id!r} implementation "
            f"{candidate.rule_name!r} from {candidate.backend_origin!r} "
            f"is unavailable: {self.reason}"
        )


class PassImplementationMisdeclared(PassImplementationError):
    """A declaration or registered rule does not match its manifest."""

    def __init__(
        self,
        pass_id: str,
        *,
        backend_name: str,
        backend_origin: str,
        reason: str,
        candidate: PassImplementationCandidate | None = None,
    ) -> None:
        self.pass_id = str(pass_id)
        self.backend_name = backend_name
        self.backend_origin = backend_origin
        self.reason = str(reason)
        self.candidate = candidate
        super().__init__(
            f"pass {self.pass_id!r} implementation from "
            f"{backend_name!r} ({backend_origin!r}) is misdeclared: "
            f"{self.reason}"
        )


def manifest_of(raw: Any) -> BackendManifest:
    """Coerce a duck-typed manifest into a :class:`BackendManifest`."""
    if isinstance(raw, BackendManifest):
        requires = _validate_requires(raw.requires)
        implements = _coerce_implements(raw)
        reload_modules = _validate_reload_modules(raw.reload_modules)
        if (
            requires == raw.requires
            and implements == raw.implements
            and reload_modules == raw.reload_modules
        ):
            return raw
        return BackendManifest(
            name=raw.name,
            api_version=raw.api_version,
            provides=raw.provides,
            requires=requires,
            implements=implements,
            reload_modules=reload_modules,
        )

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

    if isinstance(raw, Mapping):
        removed = {key for key in ("rules", "capabilities") if key in raw}
    else:
        removed = {key for key in ("rules", "capabilities") if hasattr(raw, key)}
    if removed:
        raise ManifestError(
            "manifest contains removed field " + ", ".join(sorted(removed))
        )
    requires = _coerce_requires(raw)
    implements = _coerce_implements(raw)
    reload_modules = _coerce_reload_modules(raw)

    return BackendManifest(
        name=str(values["name"]),
        api_version=api_version,
        provides=values["provides"],
        requires=requires,
        implements=implements,
        reload_modules=reload_modules,
    )


def _coerce_requires(raw: Any) -> tuple[str, ...]:
    """Read and validate stable, dependency-free host capability IDs."""
    try:
        declared = raw["requires"] if isinstance(raw, Mapping) else raw.requires
    except (KeyError, AttributeError):
        return ()
    if declared is None:
        return ()
    if declared is None:
        return ()

    if isinstance(declared, str):
        raise ManifestError(
            "requires must be an ordered sequence of capability IDs, not a bare string: "
            f"{declared!r} (did you mean ({declared!r},)?)"
        )
    if isinstance(declared, (bytes, bytearray, memoryview)):
        raise ManifestError(
            "requires must be an ordered sequence of capability IDs, not "
            f"{type(declared).__name__}"
        )
    if isinstance(declared, Mapping):
        raise ManifestError(
            "requires must be an ordered sequence of capability IDs, not a mapping"
        )
    if not isinstance(declared, Sequence):
        raise ManifestError(
            "requires must be an ordered tuple/list-like sequence of capability "
            f"IDs, got {type(declared).__name__}: {declared!r}"
        )

    requirements = tuple(declared)
    seen: set[str] = set()
    for requirement in requirements:
        if not isinstance(requirement, str):
            raise ManifestError(
                "requires entries must be non-empty dotted strings, "
                f"got {type(requirement).__name__}: {requirement!r}"
            )
        if requirement in seen:
            raise ManifestError("requires entries must be unique")
        seen.add(requirement)
        if (
            not requirement
            or "." not in requirement
            or any(not part for part in requirement.split("."))
            or any(part.isspace() for part in requirement.split("."))
        ):
            raise ManifestError(
                "requires entries must be non-empty dotted capability IDs, "
                f"got {requirement!r}"
            )
    return requirements


def _validate_requires(declared: Any) -> tuple[str, ...]:
    return _coerce_requires({"requires": declared})


def _coerce_reload_modules(raw: Any) -> tuple[str, ...]:
    """Read optional extension-owned module prefixes for hot reload."""
    try:
        declared = (
            raw["reload_modules"] if isinstance(raw, Mapping) else raw.reload_modules
        )
    except (KeyError, AttributeError):
        return ()
    return _validate_reload_modules(declared)


def _validate_reload_modules(declared: Any) -> tuple[str, ...]:
    if declared is None:
        return ()
    if isinstance(declared, str):
        raise ManifestError(
            "reload_modules must be an ordered sequence of module prefixes, "
            f"not a bare string: {declared!r}"
        )
    if isinstance(declared, (bytes, bytearray, memoryview, Mapping)):
        raise ManifestError(
            "reload_modules must be an ordered sequence of module prefixes, "
            f"not {type(declared).__name__}"
        )
    if not isinstance(declared, Sequence):
        raise ManifestError(
            "reload_modules must be an ordered tuple/list-like sequence of "
            f"module prefixes, got {type(declared).__name__}: {declared!r}"
        )
    modules = tuple(declared)
    for module in modules:
        if not isinstance(module, str) or not module:
            raise ManifestError(
                "reload_modules entries must be non-empty import-path strings, "
                f"got {module!r}"
            )
    return modules


def _coerce_implements(raw: Any) -> Mapping[str, str]:
    """Read the optional ``implements`` mapping: ``{pass_id: rule class name}``."""
    try:
        declared = raw["implements"] if isinstance(raw, Mapping) else raw.implements
    except (KeyError, AttributeError):
        return types.MappingProxyType({})
    if declared is None:
        return types.MappingProxyType({})

    if not isinstance(declared, Mapping):
        raise ManifestError(
            f"implements must be a mapping of pass id -> rule class name, "
            f"got {type(declared).__name__}: {declared!r}"
        )
    for pass_id, rule_name in declared.items():
        if (
            not isinstance(pass_id, str)
            or not isinstance(rule_name, str)
            or not pass_id
            or not rule_name
        ):
            raise ManifestError(
                f"implements entries must be non-empty str -> str, "
                f"got {pass_id!r} -> {rule_name!r}"
            )
    return types.MappingProxyType(dict(declared))


@dataclass(frozen=True)
class BackendSpec:
    """A discovered backend whose manifest has not been read yet.

    ``load_manifest`` is a thunk rather than a value so discovery stays free:
    nothing is imported until someone probes.
    """

    name: str
    load_manifest: Callable[[], Any]
    origin: str = "unknown"
    reload_modules: tuple[str, ...] = ()


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


def _distribution_version(origin: str) -> tuple[str | None, str | None]:
    """Extract conventional distribution metadata from an origin label."""
    distribution, separator, version = str(origin).rpartition(" ")
    if not separator or not distribution or not version:
        return None, None
    if not version[0].isdigit():
        return None, None
    return distribution, version


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
            reload_modules=(entry_point.module,),
        )
        for entry_point in metadata.entry_points(group=ENTRY_POINT_GROUP)
    ]


@dataclass
class _ActivationRecord:
    condition: threading.Condition
    generation: int
    owner_thread: int
    in_progress: bool = True
    activation: PluginActivation | None = None
    error: BaseException | None = None


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
        host: PluginHostCapabilities | None = None,
        requirement_validator: Callable[[Sequence[str]], None] | None = None,
        host_view_factory: Callable[
            [Sequence[str], PluginIdentity], PluginHostCapabilities
        ]
        | None = None,
    ) -> None:
        self._builtins = tuple(builtins)
        self._source = source if source is not None else entry_point_source
        self._lock = threading.RLock()
        self._lifecycle = threading.Condition(self._lock)
        self._generation = 0
        self._rediscovering = False
        self._closing = False
        self._discovered = False
        #: name -> candidates, most preferred first (entry points, then builtins)
        self._candidates: dict[str, tuple[BackendSpec, ...]] = {}
        self._settled: dict[str, BackendSpec] = {}
        self._rejected: dict[str, tuple[tuple[str, str], ...]] = {}
        self._status: dict[str, BackendStatus] = {}
        self._reason: dict[str, str | None] = {}
        self._api_version: dict[str, int | None] = {}
        #: manifest of whichever candidate settled, for capability offers
        self._manifests: dict[str, BackendManifest] = {}
        self._loaded: dict[str, Any] = {}
        self._errors: dict[str, BaseException] = {}
        self._active_implementations: set[PassImplementationCandidate] = set()
        self._implementation_failures: dict[
            PassImplementationCandidate, dict[str, str]
        ] = {}
        self._host = host if host is not None else _EmptyHostCapabilities()
        self._requirement_validator = requirement_validator
        self._host_view_factory = (
            self._host.view_for
            if host is None and host_view_factory is None
            else host_view_factory
        )
        self._activated: dict[str, PluginActivation] = {}
        self._activation_contexts: dict[str, PluginActivationContext] = {}
        self._activation_records: dict[str, _ActivationRecord] = {}
        self._implementation_instances: dict[
            PassImplementationCandidate, list[object]
        ] = {}

    # -- discovery ---------------------------------------------------------

    def discover(self, *, force: bool = False) -> None:
        """Populate the registry. Cheap after the first call unless *force*."""
        force_cycle = False
        with self._lock:
            if self._discovered and not force:
                return
            if self._discovered and force:
                while self._rediscovering or self._closing:
                    self._lifecycle.wait()
                self._rediscovering = True
                self._generation += 1
                force_cycle = True

        if force_cycle:
            try:
                self._close_activations_impl()
            except BaseException:
                with self._lock:
                    self._rediscovering = False
                    self._lifecycle.notify_all()
                raise

        with self._lock:
            if self._discovered and not force:
                if force_cycle:
                    self._rediscovering = False
                    self._lifecycle.notify_all()
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
            self._manifests = {}
            self._loaded = {}
            self._errors = {}
            self._active_implementations = set()
            self._implementation_failures = {}
            self._activated = {}
            self._activation_contexts = {}
            self._implementation_instances = {}
            self._discovered = True
            if force_cycle:
                self._rediscovering = False
                self._lifecycle.notify_all()

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

    def capability_offers(self) -> tuple[PluginCapabilityOffer[Any], ...]:
        """Offers from currently activated plugins."""
        offers: list[PluginCapabilityOffer[Any]] = []
        with self._lock:
            activations = tuple(self._activated.values())
        for activation in activations:
            offers.extend(activation.capability_offers())
        return tuple(offers)

    def activate(self, name: str) -> PluginActivation:
        """Validate and activate one resolved plugin transactionally."""
        self.discover()
        with self._lock:
            while self._rediscovering or self._closing:
                self._lifecycle.wait()
            if name not in self._candidates:
                raise BackendUnavailable(f"no backend named {name!r}")
            existing = self._activated.get(name)
            if existing is not None:
                return existing
            record = self._activation_records.get(name)
            if record is not None:
                while record.in_progress:
                    record.condition.wait()
                existing = self._activated.get(name)
                if existing is not None:
                    return existing
                if record.activation is not None:
                    return record.activation
                if record.error is not None:
                    raise record.error
                while self._rediscovering or self._closing:
                    self._lifecycle.wait()
                existing = self._activated.get(name)
                if existing is not None:
                    return existing
            info = self.probe(name)
            if not info.usable:
                raise BackendUnavailable(
                    f"backend {name!r} is {info.status.value}: {info.reason}"
                ) from self._errors.get(name)
            manifest = self._manifests[name]
            plugin = self._loaded[name]
            spec = self._settled[name]
            activate = getattr(plugin, "activate", None)
            if not callable(activate):
                raise ManifestError(
                    f"backend {name!r} does not provide activate(context)"
                )

            distribution, version = _distribution_version(spec.origin)
            identity = PluginIdentity(
                name=manifest.name,
                distribution=distribution,
                version=version,
                origin=spec.origin,
            )
            view_factory = self._host_view_factory
            if view_factory is None:
                raise BackendUnavailable("no host view factory configured")
            record = _ActivationRecord(
                condition=threading.Condition(self._lock),
                generation=self._generation,
                owner_thread=threading.get_ident(),
            )
            self._activation_records[name] = record

        partial: Any = None
        try:
            host_view = view_factory(manifest.requires, identity)
            if host_view is None:
                raise BackendUnavailable("host view factory returned None")
            context = PluginActivationContext(identity=identity, host=host_view)
            partial = activate(context)
            self._validate_activation(partial)
        except Exception as exc:
            if partial is not None:
                close = getattr(partial, "close", None)
                if callable(close):
                    try:
                        close()
                    except Exception:
                        logger.exception("plugin %r failed while rolling back", name)
            with self._lock:
                record.error = exc
                record.in_progress = False
                if (
                    self._activation_records.get(name) is record
                    and not self._closing
                    and not self._rediscovering
                ):
                    del self._activation_records[name]
                record.condition.notify_all()
            raise

        with self._lock:
            record.in_progress = False
            if self._closing or self._rediscovering:
                # Keep ownership solely in the claimed record until the
                # concurrent close has drained it; never publish a closed
                # object as active.
                record.activation = partial
            else:
                self._activated[name] = partial
                self._activation_contexts[name] = context
            if (
                self._activation_records.get(name) is record
                and not self._closing
                and not self._rediscovering
            ):
                del self._activation_records[name]
            record.condition.notify_all()
            return partial

    def close_activations(self) -> None:
        """Close every activation once, retaining progress after failures."""
        self._close_selected_activations(())

    def close_activations_except(self, keep: Sequence[PluginActivation] = ()) -> None:
        """Close registry-owned activations not present in *keep*."""
        self._close_selected_activations(tuple(keep))

    def _close_selected_activations(self, keep: Sequence[PluginActivation]) -> None:
        keep_ids = {id(activation) for activation in keep}
        with self._lock:
            while self._rediscovering or self._closing:
                self._lifecycle.wait()
            self._closing = True
        self._close_activations_impl(keep_ids=keep_ids)

    def _close_activations_impl(self, *, keep_ids: set[int] | None = None) -> None:
        keep_ids = set() if keep_ids is None else set(keep_ids)
        with self._lock:
            records = tuple(self._activation_records.items())
            activations = {
                name: activation
                for name, activation in self._activated.items()
                if id(activation) not in keep_ids
            }
            retained = {
                name: activation
                for name, activation in self._activated.items()
                if id(activation) in keep_ids
            }
            self._activated = retained
            self._activation_contexts = {
                name: context
                for name, context in self._activation_contexts.items()
                if name in retained
            }
            retained_names = set(retained)
            self._active_implementations = {
                candidate
                for candidate in self._active_implementations
                if candidate.backend_name in retained_names
            }
            self._implementation_instances = {
                candidate: instances
                for candidate, instances in self._implementation_instances.items()
                if candidate.backend_name in retained_names
            }

        for name, record in records:
            with self._lock:
                while record.in_progress:
                    record.condition.wait()
                if record.activation is not None:
                    if id(record.activation) not in keep_ids:
                        activations[name] = record.activation

        for name, activation in activations.items():
            try:
                activation.close()
            except Exception:
                logger.exception("plugin %r failed while closing", name)

        with self._lock:
            for name, record in records:
                if self._activation_records.get(name) is record:
                    del self._activation_records[name]
            self._closing = False
            self._lifecycle.notify_all()

    def _validate_requirements(self, requirements: Sequence[str]) -> None:
        if not requirements:
            return
        validate = self._requirement_validator
        if validate is None:
            raise BackendUnavailable(
                "no host capability requirement validator configured"
            )
        validate(tuple(requirements))

    @staticmethod
    def _validate_activation(activation: Any) -> None:
        if activation is None:
            raise ManifestError("plugin.activate(context) returned None")
        for method in ("create_implementation", "capability_offers", "close"):
            if not callable(getattr(activation, method, None)):
                raise ManifestError(f"activation is missing callable {method}()")
        offers = activation.capability_offers()
        if not isinstance(offers, tuple):
            raise ManifestError("activation capability_offers() must return a tuple")
        if not all(isinstance(offer, PluginCapabilityOffer) for offer in offers):
            raise ManifestError(
                "activation capability_offers() returned an invalid offer"
            )

    def implementation_for(self, pass_id: PassId | str) -> str | None:
        """Return the opaque implementation ID declared for ``pass_id``.

        d810 derives a pass's ``allowed_rule_names`` from its stage
        descriptors, so it needs the implementing rule's *name* at pass
        registration time -- long before rules are imported. Hardcoding it
        (``MBA_SOLVE_IMPLEMENTATION = "CobraSolveRule"``) put one vendor's class
        name in core, which meant d810 could host exactly one solver and the
        name survived the backend being extracted into its own distribution.

        Reads manifests only. It deliberately does NOT probe: probing resolves
        ``provides`` and imports the backend, and this runs during pass
        registration, well before d810 is ready for that. A declared
        implementation whose binding turns out to be missing simply leaves an
        allowlist entry with no registered rule, which is inert -- the same
        state as no extension at all.

        Version-incompatible backends contribute nothing: their manifest is
        read, rejected, and never trusted for anything else.
        """
        declarations = self.implementation_declarations_for(
            pass_id, tolerate_manifest_errors=True
        )
        if len(declarations) > 1:
            raise PassImplementationAmbiguous(
                str(pass_id),
                tuple(candidate for candidate, _manifest in declarations),
            )
        if not declarations:
            return None
        return declarations[0][0].rule_name

    def implementation_candidates_for(
        self, pass_id: PassId | str
    ) -> tuple[PassImplementationCandidate, ...]:
        """Collect compatible declarations without activating a backend.

        This is the declaration phase of strict implementation resolution.  It
        reads manifests only: neither ``provides`` nor any rule module is
        imported, and no backend probe is called.  The result is sorted by the
        stable identity promised by the extension contract so ambiguity is
        reproducible across entry-point ordering.
        """
        return tuple(
            candidate
            for candidate, _manifest in self.implementation_declarations_for(pass_id)
        )

    def implementation_declarations_for(
        self,
        pass_id: PassId | str,
        *,
        tolerate_manifest_errors: bool = False,
    ) -> tuple[tuple[PassImplementationCandidate, BackendManifest], ...]:
        """Return exact compatible candidates paired with inert manifests.

        The candidate and manifest are read under the registry lock so callers
        can validate every declaration without reaching through mutable
        registry tables.  Resolving ``manifest.provides`` remains the concern
        of :meth:`probe`; this accessor only loads the cheap declaration.
        """
        pass_name = str(pass_id)
        while True:
            self.discover()
            with self._lock:
                while self._rediscovering or self._closing:
                    self._lifecycle.wait()
                generation = self._generation
                specs = tuple(
                    spec
                    for candidates in self._candidates.values()
                    for spec in candidates
                )

            found: list[tuple[PassImplementationCandidate, BackendManifest]] = []
            for spec in specs:
                try:
                    manifest = manifest_of(spec.load_manifest())
                except ImportError:
                    # A manifest import can itself depend on an optional package.
                    # It contributes no declaration, just as implementation_for()
                    # historically treated it.
                    continue
                except ManifestError as exc:
                    if tolerate_manifest_errors:
                        continue
                    raise PassImplementationMisdeclared(
                        pass_name,
                        backend_name=spec.name,
                        backend_origin=spec.origin,
                        reason=str(exc),
                    ) from exc
                except Exception:
                    # A broken manifest cannot be activated.  Keep declaration
                    # discovery conservative; probe() remains the diagnostic path
                    # that classifies arbitrary loader failures.
                    continue

                if manifest.api_version != PLUGIN_API_VERSION:
                    continue
                rule_name = manifest.implements.get(pass_name)
                if not rule_name:
                    continue
                found.append(
                    (
                        PassImplementationCandidate(
                            pass_id=pass_name,
                            backend_name=spec.name,
                            backend_origin=spec.origin,
                            rule_modules=(),
                            rule_name=rule_name,
                        ),
                        manifest,
                    )
                )

            with self._lock:
                if (
                    generation != self._generation
                    or self._rediscovering
                    or self._closing
                ):
                    continue
                return tuple(
                    sorted(
                        found,
                        key=lambda declaration: (
                            declaration[0].backend_name,
                            declaration[0].backend_origin,
                            declaration[0].rule_name,
                        ),
                    )
                )

    def validate_requirements(self, requirements: Sequence[str]) -> None:
        """Validate host requirements without resolving a provider."""
        with self._lock:
            self._validate_requirements(tuple(requirements))

    def extension_reload_module_prefixes(self) -> tuple[str, ...]:
        """Return declared extension-owned modules without probing providers.

        Reload preparation must include unavailable and incompatible backends:
        their manifest packages can still be cached with old D810 contract
        classes.  Read only the cheap manifest declaration and never resolve
        ``provides`` here.
        """
        self.discover()
        with self._lock:
            specs = tuple(
                spec for candidates in self._candidates.values() for spec in candidates
            )
        prefixes = {
            module_name for spec in specs for module_name in spec.reload_modules
        }
        for spec in specs:
            try:
                manifest = manifest_of(spec.load_manifest())
            except Exception:
                continue
            prefixes.update(manifest.reload_modules)
        return tuple(sorted(prefixes))

    def implementation_manifest_info(self, name: str) -> BackendInfo:
        """Classify one backend from its manifest without loading ``provides``.

        Unlike :meth:`info`, this distinguishes a fresh manifest import,
        validation, or API-version failure while preserving lazy backend
        activation.  It intentionally does not mutate the registry's runtime
        status; diagnostics and activation remain owned by :meth:`probe`.
        """
        self.discover()
        with self._lock:
            current = self.info(name)
            if current.status is not BackendStatus.NOT_LOADED:
                return current
            specs = self._candidates[name]

            rejected: list[tuple[str, str]] = []
            for index, spec in enumerate(specs):
                status = BackendStatus.NOT_LOADED
                reason: str | None = None
                api_version: int | None = None
                try:
                    manifest = manifest_of(spec.load_manifest())
                except ImportError as exc:
                    status = BackendStatus.UNAVAILABLE
                    reason = str(exc)
                except ManifestError as exc:
                    status = BackendStatus.BROKEN
                    reason = str(exc)
                except Exception as exc:
                    status = BackendStatus.BROKEN
                    reason = f"manifest raised {type(exc).__name__}: {exc}"
                else:
                    api_version = manifest.api_version
                    if api_version != PLUGIN_API_VERSION:
                        status = BackendStatus.INCOMPATIBLE
                        reason = (
                            f"built for plugin API v{api_version}; "
                            f"this d810 speaks v{PLUGIN_API_VERSION}"
                        )

                if status is BackendStatus.NOT_LOADED or index == len(specs) - 1:
                    below = specs[index + 1 :]
                    return BackendInfo(
                        name=name,
                        status=status,
                        origin=spec.origin,
                        api_version=api_version,
                        reason=reason,
                        shadowed=tuple(candidate.origin for candidate in below),
                        rejected=tuple(rejected),
                    )
                rejected.append((spec.origin, reason or status.value))

        raise AssertionError(f"backend {name!r} has no manifest candidates")

    def implementation_is_active(self, candidate: PassImplementationCandidate) -> bool:
        """Whether this exact declaration completed activation successfully."""
        with self._lock:
            return candidate in self._active_implementations

    def implementation_failure(
        self, candidate: PassImplementationCandidate
    ) -> str | None:
        """Return retained candidate-level load/activation failure evidence."""
        with self._lock:
            failures = self._implementation_failures.get(candidate, {})
            if not failures:
                return None
            return "; ".join(failures[key] for key in sorted(failures))

    def require_unique_implementation(
        self, pass_id: PassId | str, *, install_hint: str
    ) -> PassImplementationCandidate:
        """Return the one compatible declaration, or report strict failure."""
        pass_name = str(pass_id)
        candidates = self.implementation_candidates_for(pass_name)
        if not candidates:
            raise PassImplementationMissing(pass_name, install_hint)
        if len(candidates) > 1:
            raise PassImplementationAmbiguous(pass_name, candidates)
        return candidates[0]

    def activate_implementation(self, candidate: PassImplementationCandidate) -> object:
        """Activate exactly one declaration and retain truthful failure state."""
        with self._lock:
            was_active = candidate in self._active_implementations
            failures = self._implementation_failures.get(candidate)
            if failures is not None:
                failures.pop("activation", None)
                if not failures:
                    self._implementation_failures.pop(candidate, None)
        try:
            implementation = self._activate_implementation_once(candidate)
        except Exception as exc:
            with self._lock:
                if was_active:
                    self._active_implementations.add(candidate)
                self._implementation_failures.setdefault(candidate, {})[
                    "activation"
                ] = f"{type(exc).__name__}: {exc}"
            raise
        return implementation

    def _activate_implementation_once(
        self, candidate: PassImplementationCandidate
    ) -> object:
        """Probe, import, and verify one selected implementation.

        The sequence is intentionally explicit: backend availability is known
        before the declared implementation factory is called, and this
        portable registry never imports optimizer layers.
        """
        try:
            info = self.probe(candidate.backend_name)
        except (KeyError, BackendUnavailable) as exc:
            raise PassImplementationUnavailable(candidate, str(exc)) from exc

        if info.status is not BackendStatus.AVAILABLE:
            raise PassImplementationUnavailable(
                candidate,
                info.reason or info.status.value,
            )
        if info.origin != candidate.backend_origin:
            raise PassImplementationUnavailable(
                candidate,
                f"resolved backend origin is {info.origin!r}",
            )

        declarations = self.implementation_declarations_for(candidate.pass_id)
        exact = [item for item in declarations if item[0] == candidate]
        if not exact:
            raise PassImplementationMisdeclared(
                candidate.pass_id,
                backend_name=candidate.backend_name,
                backend_origin=candidate.backend_origin,
                candidate=candidate,
                reason="implementation ID is not declared by the manifest",
            )
        activation = self.activate(candidate.backend_name)
        try:
            implementation = activation.create_implementation(candidate.rule_name)
        except Exception as exc:
            raise PassImplementationUnavailable(
                candidate,
                f"implementation factory raised {type(exc).__name__}: {exc}",
            ) from exc
        if implementation is None:
            raise PassImplementationMisdeclared(
                candidate.pass_id,
                backend_name=candidate.backend_name,
                backend_origin=candidate.backend_origin,
                candidate=candidate,
                reason="implementation factory returned None",
            )
        with self._lock:
            if any(
                existing is implementation
                for instances in self._implementation_instances.values()
                for existing in instances
            ):
                raise PassImplementationMisdeclared(
                    candidate.pass_id,
                    backend_name=candidate.backend_name,
                    backend_origin=candidate.backend_origin,
                    candidate=candidate,
                    reason="implementation factory reused an instance",
                )
            self._implementation_instances.setdefault(candidate, []).append(
                implementation
            )
        with self._lock:
            self._active_implementations.add(candidate)
            failures = self._implementation_failures.get(candidate)
            if failures is not None:
                failures.pop("registration", None)
                if not failures:
                    self._implementation_failures.pop(candidate, None)
        return implementation

    def discard_implementation_instances(
        self, ownership: Sequence[ImplementationOwnership]
    ) -> None:
        """Discard only exact candidate/object ownership from registry truth."""
        if not ownership:
            return
        with self._lock:
            for owner in ownership:
                owned = self._implementation_instances.get(owner.candidate)
                if not owned:
                    continue
                remaining = [
                    instance for instance in owned if instance is not owner.instance
                ]
                if remaining:
                    self._implementation_instances[owner.candidate] = remaining
                else:
                    self._implementation_instances.pop(owner.candidate, None)
                    self._active_implementations.discard(owner.candidate)

    def activation_for_candidate(
        self, candidate: PassImplementationCandidate
    ) -> PluginActivation:
        """Return the activation owning an exact implementation candidate."""
        activation = self.activate(candidate.backend_name)
        with self._lock:
            spec = self._settled.get(candidate.backend_name)
            if spec is None or spec.origin != candidate.backend_origin:
                raise PassImplementationUnavailable(
                    candidate,
                    "resolved backend origin changed",
                )
        return activation

    def plugin_rule_services(
        self, candidate: PassImplementationCandidate
    ) -> PluginRuleServices:
        """Return immutable services for rules created by *candidate*."""
        self.activation_for_candidate(candidate)
        with self._lock:
            context = self._activation_contexts.get(candidate.backend_name)
        if context is None:
            raise PassImplementationUnavailable(candidate, "activation context missing")
        return PluginRuleServices(plugin=context.identity, host=context.host)

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

        self._manifests[name] = manifest

        try:
            self._validate_requirements(manifest.requires)
        except BackendUnavailable as exc:
            return BackendStatus.UNAVAILABLE, str(exc), exc, None, version
        except Exception as exc:
            reason = (
                f"host capability requirement validator raised "
                f"{type(exc).__name__}: {exc}"
            )
            return BackendStatus.BROKEN, reason, exc, None, version

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
    return any(info.status in DEFECT_STATUSES or info.rejected for info in infos)


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

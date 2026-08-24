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
after d810 has finished loading. Hot reload evicts the extension entry point's
manifest module prefix and cold-imports it against the rebuilt D810 core. A
manifest whose coupled runtime lives under another prefix declares it in
``reload_modules``.
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
    "PassImplementationRequirement",
    "PassImplementationError",
    "PassImplementationMisdeclared",
    "PassImplementationMissing",
    "PassImplementationUnavailable",
    "PluginCapabilityOffer",
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


@dataclass(frozen=True)
class PluginCapabilityOffer(Generic[C]):
    """A backend declaring it can satisfy one capability Protocol.

    Typed rather than stringly on purpose. ``capability`` is the Protocol
    *class*, so at the plugin author's site a type checker infers ``C`` from
    ``type[C]`` and then verifies the factory returns it::

        def _make_engine(source: FunctionSource) -> ConcolicEngine:
            from d810_cobra.concolic import Engine   # deferred
            return Engine(source.live_source)

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
    factory: Callable[[Any], C]


def offers_capability(
    capability: type[C],
) -> Callable[[Callable[[Any], C]], PluginCapabilityOffer[C]]:
    """Declare a capability offer with the factory actually type-checked.

    Curried so ``C`` is solved from *capability* alone; the returned binder then
    checks the factory against it. Calling
    :class:`PluginCapabilityOffer` directly does not achieve this -- see its
    docstring.

    Usable as a decorator::

        @offers_capability(ConcolicEngine)
        def make_engine(source: FunctionSource) -> ConcolicEngine:
            from d810_cobra.concolic import Engine   # deferred
            return Engine(source.live_source)

        MANIFEST = BackendManifest(..., capabilities=(make_engine,))
    """

    def bind(factory: Callable[[Any], C]) -> PluginCapabilityOffer[C]:
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
    capabilities: tuple[PluginCapabilityOffer[Any], ...] = ()
    #: Optimizer rule modules this backend contributes, as import paths.
    #:
    #: d810 loads rules by scanning ``d810.optimizers.__path__`` and letting
    #: ``Registrant`` self-register on import. That scan is path-scoped, so a
    #: rule shipped inside an installed extension is never imported and never
    #: registers -- the backend reports ``available`` while its pass silently
    #: does nothing, which looks exactly like the pass not matching anything.
    #:
    #: Declared rather than discovered: importing an extension's whole package
    #: to find rules would drag in its heavy half (for CoBRA, the compiled
    #: binding and ida_hexrays) during discovery, which is what ``provides``
    #: being lazily resolved exists to avoid.
    rules: tuple[str, ...] = ()
    #: Which d810 pass each contributed rule implements: ``{pass_id: class}``.
    #:
    #: d810 derives a pass's ``allowed_rule_names`` from its stage descriptors,
    #: and a rule outside that allowlist is skipped at dispatch. Naming the
    #: class in d810 would mean core code hardcoding one vendor's class -- and
    #: d810 could then host exactly one solver, forever.
    #:
    #: The extension knows what it implements; d810 asks.
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
        super().__init__(
            f"pass {self.pass_id!r} has no implementation; {hint}"
        )


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
        rules = _validate_rules(raw.rules)
        implements = _coerce_implements(raw)
        reload_modules = _validate_reload_modules(raw.reload_modules)
        if (
            rules == raw.rules
            and implements == raw.implements
            and reload_modules == raw.reload_modules
        ):
            return raw
        return BackendManifest(
            name=raw.name,
            api_version=raw.api_version,
            provides=raw.provides,
            capabilities=raw.capabilities,
            rules=rules,
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

    offers = _coerce_offers(raw)
    rules = _coerce_rules(raw)
    implements = _coerce_implements(raw)
    reload_modules = _coerce_reload_modules(raw)

    return BackendManifest(
        name=str(values["name"]),
        api_version=api_version,
        provides=values["provides"],
        capabilities=offers,
        rules=rules,
        implements=implements,
        reload_modules=reload_modules,
    )


def _coerce_offers(raw: Any) -> tuple[PluginCapabilityOffer[Any], ...]:
    """Read the optional ``capabilities`` field and check its shape.

    Rejecting a bad entry here means the plugin author learns at declaration
    time; the alternative is a pass discovering mid-run that its capability is
    a string.
    """
    try:
        declared = raw["capabilities"] if isinstance(raw, Mapping) else raw.capabilities
    except (KeyError, AttributeError):
        return ()
    if declared is None:
        return ()

    offers = tuple(declared)
    for offer in offers:
        if not isinstance(offer, PluginCapabilityOffer):
            raise ManifestError(
                f"capabilities entries must be PluginCapabilityOffer, "
                f"got {type(offer).__name__}: {offer!r}"
            )
    return offers


def _coerce_rules(raw: Any) -> tuple[str, ...]:
    """Read the optional ``rules`` field: import paths, checked at declaration.

    A non-string here would otherwise surface much later as an obscure failure
    inside ``import_module``, long after the manifest that caused it.
    """
    try:
        declared = raw["rules"] if isinstance(raw, Mapping) else raw.rules
    except (KeyError, AttributeError):
        return ()
    return _validate_rules(declared)


def _validate_rules(declared: Any) -> tuple[str, ...]:
    """Validate and freeze an ordered manifest rule-module declaration."""
    if declared is None:
        return ()

    if isinstance(declared, str):
        raise ManifestError(
            f"rules must be an ordered sequence of import paths, not a bare string: "
            f"{declared!r} (did you mean ({declared!r},)?)"
        )
    if isinstance(declared, (bytes, bytearray, memoryview)):
        raise ManifestError(
            "rules must be an ordered sequence of text import paths, not "
            f"{type(declared).__name__}"
        )
    if isinstance(declared, Mapping):
        raise ManifestError(
            "rules must be an ordered sequence of import paths, not a mapping"
        )
    if not isinstance(declared, Sequence):
        raise ManifestError(
            "rules must be an ordered tuple/list-like sequence of import "
            f"paths, got {type(declared).__name__}: {declared!r}"
        )

    modules = tuple(declared)
    for module in modules:
        if not isinstance(module, str):
            raise ManifestError(
                f"rules entries must be import-path strings, "
                f"got {type(module).__name__}: {module!r}"
            )
        if not module:
            raise ManifestError("rules entries must be nonempty import paths")
    return modules


def _coerce_reload_modules(raw: Any) -> tuple[str, ...]:
    """Read optional extension-owned module prefixes for hot reload."""
    try:
        declared = (
            raw["reload_modules"]
            if isinstance(raw, Mapping)
            else raw.reload_modules
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
        registration_lookup: Callable[
            [PassImplementationCandidate], Any | None
        ] | None = None,
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
        #: manifest of whichever candidate settled, for capability offers
        self._manifests: dict[str, BackendManifest] = {}
        self._loaded: dict[str, Any] = {}
        self._errors: dict[str, BaseException] = {}
        self._active_implementations: set[PassImplementationCandidate] = set()
        self._implementation_failures: dict[
            PassImplementationCandidate, dict[str, str]
        ] = {}
        #: Injected to keep optimizer-layer imports out of ``core.plugins``.
        self._registration_lookup = registration_lookup

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
            self._manifests = {}
            self._loaded = {}
            self._errors = {}
            self._active_implementations = set()
            self._implementation_failures = {}
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

    def capability_offers(self) -> tuple[PluginCapabilityOffer[Any], ...]:
        """Every offer from backends that actually resolved.

        Probes, because an offer from a backend that turns out UNAVAILABLE or
        INCOMPATIBLE must not reach the pipeline -- binding a capability slot
        to something that cannot run is worse than leaving the slot empty,
        which callers already handle via ``CapabilitySet.optional``.
        """
        offers: list[PluginCapabilityOffer[Any]] = []
        for name in self.names():
            if not self.probe(name).usable:
                continue
            with self._lock:
                manifest = self._manifests.get(name)
            if manifest is not None:
                offers.extend(manifest.capabilities)
        return tuple(offers)

    def implementation_for(self, pass_id: PassId | str) -> str | None:
        """The rule class name an installed extension declares for ``pass_id``.

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
        self.discover()
        with self._lock:
            candidates = {n: list(c) for n, c in self._candidates.items()}
        for specs in candidates.values():
            for spec in specs:
                try:
                    manifest = manifest_of(spec.load_manifest())
                except Exception:
                    # Classification is probe()'s job and it reports properly
                    # there; here a bad manifest simply contributes nothing.
                    continue
                if manifest.api_version != PLUGIN_API_VERSION:
                    continue
                found = manifest.implements.get(pass_id)
                if found:
                    return found
        return None

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
        pass_name = str(pass_id)
        self.discover()
        with self._lock:
            specs = tuple(
                spec
                for candidates in self._candidates.values()
                for spec in candidates
            )

        found: list[PassImplementationCandidate] = []
        for spec in specs:
            try:
                manifest = manifest_of(spec.load_manifest())
            except ImportError:
                # A manifest import can itself depend on an optional package.
                # It contributes no declaration, just as implementation_for()
                # historically treated it.
                continue
            except ManifestError as exc:
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
            if not manifest.rules:
                raise PassImplementationMisdeclared(
                    pass_name,
                    backend_name=spec.name,
                    backend_origin=spec.origin,
                    reason=(
                        f"implementation {rule_name!r} does not declare any "
                        "rule modules"
                    ),
                )
            found.append(
                PassImplementationCandidate(
                    pass_id=pass_name,
                    backend_name=spec.name,
                    backend_origin=spec.origin,
                    rule_modules=tuple(manifest.rules),
                    rule_name=rule_name,
                )
            )

        return tuple(
            sorted(
                found,
                key=lambda candidate: (
                    candidate.backend_name,
                    candidate.backend_origin,
                    candidate.rule_name,
                ),
            )
        )

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
                spec
                for candidates in self._candidates.values()
                for spec in candidates
            )
        prefixes = {
            module_name
            for spec in specs
            for module_name in spec.reload_modules
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

    def implementation_is_active(
        self, candidate: PassImplementationCandidate
    ) -> bool:
        """Whether this exact declaration completed activation successfully."""
        with self._lock:
            return candidate in self._active_implementations

    def implementation_registration_available(
        self, candidate: PassImplementationCandidate
    ) -> bool:
        """Whether an already-loaded rule registration matches ``candidate``.

        This is a read-only lookup for non-strict implementations whose rule
        modules are loaded by the normal optimizer catalogue lifecycle rather
        than :meth:`activate_implementation`.
        """
        lookup = self._registration_lookup
        if lookup is None:
            return False
        try:
            return lookup(candidate) is not None
        except Exception:
            return False

    def implementation_failure(
        self, candidate: PassImplementationCandidate
    ) -> str | None:
        """Return retained candidate-level load/activation failure evidence."""
        with self._lock:
            failures = self._implementation_failures.get(candidate, {})
            if not failures:
                return None
            return "; ".join(failures[key] for key in sorted(failures))

    def record_rule_module_result(
        self, module_name: str, error: BaseException | None
    ) -> None:
        """Record or clear normal extension-loader evidence for one module."""
        source = f"module:{module_name}"
        with self._lock:
            candidates: list[PassImplementationCandidate] = []
            for backend_name, manifest in self._manifests.items():
                if module_name not in manifest.rules:
                    continue
                spec = self._settled.get(backend_name)
                if spec is None:
                    continue
                candidates.extend(
                    PassImplementationCandidate(
                        pass_id=str(pass_id),
                        backend_name=backend_name,
                        backend_origin=spec.origin,
                        rule_modules=tuple(manifest.rules),
                        rule_name=rule_name,
                    )
                    for pass_id, rule_name in manifest.implements.items()
                )
            for candidate in candidates:
                failures = self._implementation_failures.setdefault(candidate, {})
                if error is None:
                    failures.pop(source, None)
                    if not failures:
                        self._implementation_failures.pop(candidate, None)
                else:
                    failures[source] = f"{type(error).__name__}: {error}"

    def finalize_rule_module_loading(self) -> None:
        """Validate declarations after the normal extension loader finishes."""
        with self._lock:
            candidates = tuple(
                PassImplementationCandidate(
                    pass_id=str(pass_id),
                    backend_name=backend_name,
                    backend_origin=spec.origin,
                    rule_modules=tuple(manifest.rules),
                    rule_name=rule_name,
                )
                for backend_name, manifest in self._manifests.items()
                if (spec := self._settled.get(backend_name)) is not None
                and self._status.get(backend_name) is BackendStatus.AVAILABLE
                for pass_id, rule_name in manifest.implements.items()
            )
        for candidate in candidates:
            reason: str | None = None
            lookup = self._registration_lookup
            if lookup is None:
                reason = "no registration lookup was injected"
            else:
                try:
                    if lookup(candidate) is None:
                        reason = f"rule {candidate.rule_name!r} is not registered"
                except Exception as exc:
                    reason = (
                        f"registration lookup raised {type(exc).__name__}: {exc}"
                    )
            with self._lock:
                failures = self._implementation_failures.setdefault(candidate, {})
                if reason is None:
                    failures.pop("registration", None)
                    if not failures:
                        self._implementation_failures.pop(candidate, None)
                else:
                    failures["registration"] = reason

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

    def activate_implementation(
        self, candidate: PassImplementationCandidate
    ) -> None:
        """Activate exactly one declaration and retain truthful failure state."""
        with self._lock:
            self._active_implementations.discard(candidate)
            failures = self._implementation_failures.get(candidate)
            if failures is not None:
                failures.pop("activation", None)
                if not failures:
                    self._implementation_failures.pop(candidate, None)
        try:
            self._activate_implementation_once(candidate)
        except Exception as exc:
            with self._lock:
                self._implementation_failures.setdefault(candidate, {})[
                    "activation"
                ] = f"{type(exc).__name__}: {exc}"
            raise

    def _activate_implementation_once(
        self, candidate: PassImplementationCandidate
    ) -> None:
        """Probe, import, and verify one selected implementation.

        The sequence is intentionally explicit: backend availability is known
        before any extension rule module is imported, and registration lookup
        remains injected so this portable registry never imports optimizer
        layers.
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

        for module_name in candidate.rule_modules:
            try:
                importlib.import_module(module_name)
            except Exception as exc:
                raise PassImplementationUnavailable(
                    candidate,
                    f"rule module {module_name!r} failed to import: "
                    f"{type(exc).__name__}: {exc}",
                ) from exc
            self.record_rule_module_result(module_name, None)

        if self._registration_lookup is None:
            raise PassImplementationMisdeclared(
                candidate.pass_id,
                backend_name=candidate.backend_name,
                backend_origin=candidate.backend_origin,
                candidate=candidate,
                reason="no registration lookup was injected",
            )
        try:
            registered = self._registration_lookup(candidate)
        except Exception as exc:
            raise PassImplementationMisdeclared(
                candidate.pass_id,
                backend_name=candidate.backend_name,
                backend_origin=candidate.backend_origin,
                candidate=candidate,
                reason=(
                    f"registration lookup raised {type(exc).__name__}: {exc}"
                ),
            ) from exc
        if registered is None:
            raise PassImplementationMisdeclared(
                candidate.pass_id,
                backend_name=candidate.backend_name,
                backend_origin=candidate.backend_origin,
                candidate=candidate,
                reason=f"rule {candidate.rule_name!r} is not registered",
            )
        with self._lock:
            self._active_implementations.add(candidate)
            failures = self._implementation_failures.get(candidate)
            if failures is not None:
                failures.pop("registration", None)
                if not failures:
                    self._implementation_failures.pop(candidate, None)

    def rule_modules(self) -> tuple[str, ...]:
        """Optimizer rule modules contributed by backends that resolved.

        d810's rule loader scans ``d810.optimizers.__path__``, which cannot
        reach a rule shipped inside an installed extension. These paths are
        what closes that gap; see :attr:`BackendManifest.rules`.

        Gated on ``usable`` for the same reason as :meth:`capability_offers`: a
        rule whose backend is UNAVAILABLE would register and then fail on every
        invocation, which is worse than never registering -- d810 already
        handles a missing rule, but not one that raises mid-pass.
        """
        modules: list[str] = []
        for name in self.names():
            if not self.probe(name).usable:
                continue
            with self._lock:
                manifest = self._manifests.get(name)
            if manifest is not None:
                modules.extend(manifest.rules)
        return tuple(modules)

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

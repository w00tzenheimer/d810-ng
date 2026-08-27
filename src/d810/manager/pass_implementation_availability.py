"""Pure operator projection for optional config-v2 pass implementations."""

from __future__ import annotations

from d810.core.plugins import (
    BackendRegistry,
    BackendStatus,
    BackendUnavailable,
    PLUGIN_API_VERSION,
    PassImplementationMisdeclared,
    PassImplementationRequirement,
    manifest_of,
)
from d810.manager.workbench_recipe_models import (
    PassImplementationAvailability,
    PassImplementationStatus,
)


def _detail(
    requirement: PassImplementationRequirement,
    status: PassImplementationStatus,
    reason: str | None = None,
) -> str:
    if status is PassImplementationStatus.READY:
        return f"{requirement.distribution} is ready."
    if status is PassImplementationStatus.INSTALLED_NOT_LOADED:
        return (
            f"{requirement.distribution} is installed and will load when this "
            "pass is activated."
        )
    if status is PassImplementationStatus.UNKNOWN:
        return "Provider availability was not checked."
    suffix = (
        "Project activation is blocked while this pass is configured."
        if requirement.activation_required
        else "This pass remains inactive until an implementation is available."
    )
    prefix = f"Install {requirement.distribution}."
    if reason:
        prefix = f"{reason.rstrip('.')}."
    return f"{prefix} {suffix}"


def _host_requirement_failure(
    backend_registry: BackendRegistry,
    pass_id: str,
    backend_name: str,
) -> tuple[PassImplementationStatus, str] | None:
    """Validate a cheap manifest before availability projects activation state.

    ``BackendRegistry.implementation_candidates_for`` intentionally returns
    declaration-only candidates, not manifests.  The availability projection
    still needs to expose a missing host requirement without resolving
    ``provides``, so use the registry's already-discovered candidate/spec
    tables to read the inert manifest and invoke its explicit validator seam.
    The normal probe path performs the same gate before provider resolution.
    """
    validator = getattr(backend_registry, "_requirement_validator", None)
    if validator is None:
        return None
    backend_registry.discover()
    candidates = getattr(backend_registry, "_candidates", {}).get(backend_name, ())
    settled = getattr(backend_registry, "_settled", {}).get(backend_name)
    specs = (settled,) if settled is not None else candidates
    for spec in specs:
        try:
            manifest = manifest_of(spec.load_manifest())
        except Exception:
            continue
        if (
            manifest.api_version != PLUGIN_API_VERSION
            or pass_id not in manifest.implements
        ):
            continue
        try:
            validator(manifest.requires)
        except BackendUnavailable as exc:
            return PassImplementationStatus.UNAVAILABLE, str(exc)
        except Exception as exc:
            return (
                PassImplementationStatus.BROKEN,
                f"host capability requirement validator raised "
                f"{type(exc).__name__}: {exc}",
            )
        return None
    return None


def project_pass_implementation_availability(
    pass_id: str,
    requirement: PassImplementationRequirement | None,
    backend_registry: BackendRegistry | None,
) -> PassImplementationAvailability | None:
    """Project lazy registry truth without importing a provider implementation."""
    if requirement is None:
        return None
    if backend_registry is None:
        status = PassImplementationStatus.UNKNOWN
        return PassImplementationAvailability(
            distribution=requirement.distribution,
            status=status,
            status_label="Not checked",
            detail=_detail(requirement, status),
            activation_required=requirement.activation_required,
        )
    try:
        candidates = backend_registry.implementation_candidates_for(pass_id)
    except PassImplementationMisdeclared as exc:
        status = PassImplementationStatus.BROKEN
        return PassImplementationAvailability(
            distribution=requirement.distribution,
            status=status,
            status_label="Broken declaration",
            detail=_detail(requirement, status, str(exc)),
            activation_required=requirement.activation_required,
            backend_names=(exc.backend_name,),
        )

    info_by_name = {info.name: info for info in backend_registry.report()}
    if not candidates:
        info = info_by_name.get(requirement.backend_name)
        if info is not None and info.status is BackendStatus.NOT_LOADED:
            info = backend_registry.implementation_manifest_info(
                requirement.backend_name
            )
        if info is None:
            status = PassImplementationStatus.NOT_INSTALLED
            label = "Not installed"
            reason = None
        elif info.status is BackendStatus.INCOMPATIBLE:
            status = PassImplementationStatus.INCOMPATIBLE
            label = "Incompatible"
            reason = info.reason
        elif info.status is BackendStatus.UNAVAILABLE:
            status = PassImplementationStatus.UNAVAILABLE
            label = "Unavailable"
            reason = info.reason
        elif info.status is BackendStatus.BROKEN:
            status = PassImplementationStatus.BROKEN
            label = "Broken"
            reason = info.reason
        else:
            status = PassImplementationStatus.INCOMPATIBLE
            label = "Does not implement pass"
            reason = (
                f"Installed backend {requirement.backend_name!r} does not "
                f"declare {pass_id!r}"
            )
        return PassImplementationAvailability(
            distribution=requirement.distribution,
            status=status,
            status_label=label,
            detail=_detail(requirement, status, reason),
            activation_required=requirement.activation_required,
            backend_names=(() if info is None else (info.name,)),
        )

    backend_names = tuple(candidate.backend_name for candidate in candidates)
    requirement_failure = _host_requirement_failure(
        backend_registry, pass_id, candidates[0].backend_name
    )
    if requirement_failure is not None:
        status, reason = requirement_failure
        label = {
            PassImplementationStatus.UNAVAILABLE: "Unavailable",
            PassImplementationStatus.BROKEN: "Broken",
        }[status]
        return PassImplementationAvailability(
            distribution=requirement.distribution,
            status=status,
            status_label=label,
            detail=_detail(requirement, status, reason),
            activation_required=requirement.activation_required,
            backend_names=(candidates[0].backend_name,),
        )
    if len(candidates) > 1:
        status = PassImplementationStatus.AMBIGUOUS
        return PassImplementationAvailability(
            distribution=requirement.distribution,
            status=status,
            status_label="Ambiguous",
            detail=_detail(
                requirement,
                status,
                f"Multiple implementations are installed: {', '.join(backend_names)}",
            ),
            activation_required=requirement.activation_required,
            backend_names=backend_names,
        )

    info = info_by_name.get(candidates[0].backend_name)
    implementation_failure = backend_registry.implementation_failure(candidates[0])
    if implementation_failure is not None:
        status = PassImplementationStatus.BROKEN
        return PassImplementationAvailability(
            distribution=requirement.distribution,
            status=status,
            status_label="Broken",
            detail=_detail(requirement, status, implementation_failure),
            activation_required=requirement.activation_required,
            backend_names=backend_names,
        )
    backend_status = info.status if info is not None else BackendStatus.NOT_LOADED
    activation_reason: str | None = None
    if backend_status is BackendStatus.AVAILABLE:
        if info is not None and info.origin != candidates[0].backend_origin:
            backend_status = BackendStatus.UNAVAILABLE
            activation_reason = (
                f"Resolved backend origin is {info.origin!r}, not the declared "
                f"origin {candidates[0].backend_origin!r}"
            )
        elif (
            requirement.activation_required
            and not backend_registry.implementation_is_active(candidates[0])
        ) or (
            not requirement.activation_required
            and not backend_registry.implementation_registration_available(
                candidates[0]
            )
        ):
            backend_status = BackendStatus.NOT_LOADED
            activation_reason = "Implementation is installed but not activated"
    status_map = {
        BackendStatus.NOT_LOADED: (
            PassImplementationStatus.INSTALLED_NOT_LOADED,
            "Installed, not loaded",
        ),
        BackendStatus.AVAILABLE: (PassImplementationStatus.READY, "Ready"),
        BackendStatus.UNAVAILABLE: (
            PassImplementationStatus.UNAVAILABLE,
            "Unavailable",
        ),
        BackendStatus.INCOMPATIBLE: (
            PassImplementationStatus.INCOMPATIBLE,
            "Incompatible",
        ),
        BackendStatus.BROKEN: (PassImplementationStatus.BROKEN, "Broken"),
    }
    status, label = status_map[backend_status]
    return PassImplementationAvailability(
        distribution=requirement.distribution,
        status=status,
        status_label=label,
        detail=_detail(
            requirement,
            status,
            activation_reason
            if activation_reason is not None
            else (None if info is None else info.reason),
        ),
        activation_required=requirement.activation_required,
        backend_names=backend_names,
    )


__all__ = ["project_pass_implementation_availability"]

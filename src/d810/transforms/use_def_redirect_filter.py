"""Use-def-safe redirect filtering — veto spine redirects that orphan non-state-var uses.

Mirrors the legacy ``LinearizedFlowGraph`` postprocess: a redirect that severs a use-def dominance
chain for a NON-state variable would orphan handler-body data (the over-redirect that DCEs handler
bodies and collapses the function).  The state variable itself is *meant* to be severed -- that is
the unflattening -- so violations on ``state_var_stkoff`` are ignored.

Portable: the live use-def query is the injected :class:`d810.capabilities.UseDefSafetyCapability`;
the caller passes the opaque live function (``ida_hexrays.mba_t``) and the pre-modification
``FlowGraph``.  When no capability / live function is available the redirects pass through unfiltered
(the portable/test path).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from d810.core import logging
from d810.transforms.graph_modification import (
    RedirectBranch,
    RedirectGoto,
    to_redirect_intent,
)

logger = logging.getLogger("d810.transforms.use_def_filter")


@dataclass(frozen=True, slots=True)
class UseDefBlockAnchor:
    """A serial/EA pair whose identity is invalid if either half is absent."""

    serial: int | None
    ea: int | None

    def __post_init__(self) -> None:
        serial = None if self.serial is None else int(self.serial)
        ea = None if self.ea is None else int(self.ea)
        if serial is None or ea is None:
            serial = None
            ea = None
        object.__setattr__(self, "serial", serial)
        object.__setattr__(self, "ea", ea)

    @property
    def label(self) -> str:
        if self.serial is None or self.ea is None:
            return "unknown"
        return f"blk{self.serial}@0x{self.ea:x}"

    def to_payload(self) -> dict[str, int | str | None]:
        return {
            "serial": self.serial,
            "ea": self.ea,
            "label": self.label,
        }


@dataclass(frozen=True, slots=True)
class UseDefSeveranceEvidence:
    """Immutable evidence for one non-state use-def severance."""

    source: UseDefBlockAnchor
    old_target: UseDefBlockAnchor
    new_target: UseDefBlockAnchor
    stack_offset: int | None
    stack_size: int | None
    use: UseDefBlockAnchor
    use_instruction_ea: int | None = None

    def to_payload(self) -> dict[str, object]:
        return {
            "source": self.source.to_payload(),
            "old_target": self.old_target.to_payload(),
            "new_target": self.new_target.to_payload(),
            "stack_offset": self.stack_offset,
            "stack_size": self.stack_size,
            "use": self.use.to_payload(),
            "use_instruction_ea": self.use_instruction_ea,
        }


@dataclass(frozen=True, slots=True)
class UseDefSeveranceAudit:
    """Typed whole-fragment result for a non-state use-def safety query."""

    executed: bool
    severance_count: int
    failure_reason: str | None = None
    enforced: bool = False
    violations: tuple[UseDefSeveranceEvidence, ...] = ()

    @property
    def clean(self) -> bool:
        return self.executed and self.severance_count == 0

    @property
    def enforcement_enabled(self) -> bool:
        """Compatibility spelling for consumers that describe policy state."""
        return self.enforced

    @property
    def enforcement_status(self) -> str:
        """Describe authority before policy so partial audits fail closed."""
        if not self.executed:
            return "safety_unavailable"
        if self.severance_count > 0:
            return "fragment_rejected" if self.enforced else "heuristic_observed"
        return "clean"

    def to_metadata(self, *, function_ea: int | None = None) -> dict[str, object]:
        metadata: dict[str, object] = {
            "executed": bool(self.executed),
            "clean": bool(self.clean),
            "severance_count": int(self.severance_count),
            "failure_reason": self.failure_reason,
            "enforced": bool(self.enforced),
            "enforcement_enabled": bool(self.enforced),
            "enforcement_status": self.enforcement_status,
            "violations": [violation.to_payload() for violation in self.violations],
        }
        if function_ea is not None:
            metadata["function_ea"] = int(function_ea)
        return metadata


def _veto_enabled() -> bool:
    """The use-def severance veto is OFF by default; opt in with
    ``D810_USE_DEF_VETO=1``.

    Empirically (sub_7FFD, unflatten and HCC) the veto is not load-bearing: with it
    disabled the redirects apply without INTERR, carriers (e.g. ``a5+0xD0``) are
    preserved, and the dispatcher output is no worse — the veto's dominance-only
    check mostly produces *false* severances (see d81-7zf7).  It stays available
    as an opt-in safety gate for functions where genuine non-state severances
    must be blocked."""
    return os.environ.get("D810_USE_DEF_VETO", "0").strip() == "1"


def severance_bail_enabled() -> bool:
    """Return the legacy S1A-only fragment-bail policy, OFF by default.

    ``D810_S1A_SEVERANCE_BAIL=1`` is consumed by
    :func:`emit_minimal_unflatten`: an executed actionable audit rejects that
    emitter's complete fragment.  It is deliberately not consumed by the
    exported redirect filter or the legacy state-machine caller; those use the
    global ``D810_USE_DEF_VETO`` policy.  This preserves the historical S1A
    compatibility knob without widening its scope.
    """
    return os.environ.get("D810_S1A_SEVERANCE_BAIL", "0").strip() == "1"


def count_use_def_severances(
    mods,
    *,
    use_def_safety,
    live_function,
    pre_cfg,
    state_var_stkoff=None,
):
    """Count redirects that would orphan a NON-state-variable use.

    This compatibility helper performs the same typed whole-fragment audit as
    :func:`filter_use_def_severing_redirects` but never applies either policy
    gate.  Callers that need enforcement must retain the full audit result so
    unavailable authority cannot be mistaken for a clean proof.  The state
    variable's own severance is the intended unflattening and is not counted.
    """
    audit = audit_use_def_severances(
        mods,
        use_def_safety=use_def_safety,
        live_function=live_function,
        pre_cfg=pre_cfg,
        state_var_stkoff=state_var_stkoff,
    )
    return audit.severance_count if audit.executed else 0


def audit_use_def_severances(
    mods,
    *,
    use_def_safety,
    live_function,
    pre_cfg,
    state_var_stkoff=None,
    enforce: bool | None = None,
) -> UseDefSeveranceAudit:
    """Audit every redirect or fail closed for the retirement allowance.

    The audit always runs over the full final fragment.  The environment toggle
    is recorded as policy state, but it never changes which evidence is
    collected.  A capability/query failure is not equivalent to zero
    severances.
    """
    # ``enforce`` is an explicit caller-scoped override.  The S1A emitter uses
    # it for the legacy compatibility gate; the exported redirect filter leaves
    # it unset and therefore remains controlled only by D810_USE_DEF_VETO.
    enforced = _veto_enabled() if enforce is None else bool(enforce)
    if use_def_safety is None or live_function is None:
        return UseDefSeveranceAudit(
            False,
            0,
            "capability_unavailable",
            enforced=enforced,
        )
    severed = 0
    evidence: list[UseDefSeveranceEvidence] = []
    for mod in mods:
        if not isinstance(mod, (RedirectGoto, RedirectBranch)):
            continue
        try:
            violations = use_def_safety.redirect_use_def_violations(
                to_redirect_intent(mod), live_function, pre_cfg
            )
        except Exception as error:  # noqa: BLE001 - safety authority is unavailable
            return UseDefSeveranceAudit(
                False,
                severed,
                f"query_failed:{type(error).__name__}",
                enforced=enforced,
                violations=tuple(evidence),
            )
        real = []
        for violation in violations:
            var_stkoff = _optional_int(getattr(violation, "var_stkoff", None))
            if (
                state_var_stkoff is not None
                and var_stkoff is not None
                and var_stkoff == int(state_var_stkoff)
            ):
                continue
            real.append(violation)
        severed += len(real)
        evidence.extend(
            _severance_evidence(mod, violation, pre_cfg) for violation in real
        )
    return UseDefSeveranceAudit(
        True,
        severed,
        enforced=enforced,
        violations=tuple(evidence),
    )


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _block_anchor(
    pre_cfg: object,
    serial: object,
) -> UseDefBlockAnchor:
    serial_int = _optional_int(serial)
    if serial_int is None:
        return UseDefBlockAnchor(None, None)
    block = None
    get_block = getattr(pre_cfg, "get_block", None)
    if callable(get_block):
        block = get_block(serial_int)
    ea = None if block is None else getattr(block, "start_ea", None)
    return UseDefBlockAnchor(serial_int, _optional_int(ea))


def _severance_evidence(
    mod: RedirectGoto | RedirectBranch,
    violation: object,
    pre_cfg: object,
) -> UseDefSeveranceEvidence:
    intent = to_redirect_intent(mod)
    use_block = getattr(violation, "use_block", None)
    use_instruction_ea = _optional_int(getattr(violation, "use_ea", None))
    return UseDefSeveranceEvidence(
        source=_block_anchor(pre_cfg, intent.from_serial),
        old_target=_block_anchor(pre_cfg, intent.old_target),
        new_target=_block_anchor(pre_cfg, intent.new_target),
        stack_offset=_optional_int(getattr(violation, "var_stkoff", None)),
        stack_size=_optional_int(getattr(violation, "var_size", None)),
        use=_block_anchor(pre_cfg, use_block),
        use_instruction_ea=use_instruction_ea,
    )


__all__ = [
    "filter_use_def_severing_redirects",
    "UseDefBlockAnchor",
    "UseDefSeveranceEvidence",
    "UseDefSeveranceAudit",
    "audit_use_def_severances",
    "count_use_def_severances",
    "severance_bail_enabled",
]


def filter_use_def_severing_redirects(
    mods,
    *,
    use_def_safety,
    live_function,
    pre_cfg,
    state_var_stkoff=None,
):
    """Apply the use-def policy atomically to one complete redirect fragment.

    Args:
        mods: Iterable of ``GraphModification`` (only ``RedirectGoto`` / ``RedirectBranch`` are
            checked; everything else passes through).
        use_def_safety: An injected ``UseDefSafetyCapability`` (or ``None`` -> no filtering).
        live_function: Opaque live backend function the capability queries (``mba_t``); ``None`` ->
            no filtering.
        pre_cfg: Pre-modification ``FlowGraph`` snapshot the capability reads.
        state_var_stkoff: Stack offset of the state variable; violations on it are the intended
            unflattening and are ignored.

    Returns:
        The complete input batch, or an empty batch when an enabled veto finds
        any actionable non-state severance. Query failure keeps the complete
        batch without claiming a clean authoritative audit.
    """
    modifications = list(mods)
    audit = audit_use_def_severances(
        modifications,
        use_def_safety=use_def_safety,
        live_function=live_function,
        pre_cfg=pre_cfg,
        state_var_stkoff=state_var_stkoff,
    )
    if not audit.executed:
        logger.debug(
            "use-def audit unavailable; retaining complete redirect batch: %s",
            audit.failure_reason,
        )
        return modifications
    if audit.severance_count == 0:
        return modifications
    if not audit.enforced:
        logger.info(
            "use-def advisory observed %d non-state severance(s); retaining "
            "complete redirect batch",
            audit.severance_count,
        )
        return modifications
    logger.info(
        "use-def veto rejected complete redirect fragment with %d non-state "
        "severance(s)",
        audit.severance_count,
    )
    return []

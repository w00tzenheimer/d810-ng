"""Materialize computed-goto label targets before Hex-Rays builds an MBA.

Tigress indirect flattening copies a native label table to the stack and then
dispatches with ``ijmp`` through that stack slot.  IDA may keep the native label
bodies outside the function graph used by Hex-Rays, so the resulting MBA only
contains the table-copy stub and final indirect jump.  This module performs the
IDA-specific preanalysis needed to make those labels visible to Hex-Rays.

Indirect-dispatcher materialization family
------------------------------------------
This module also owns the *shared contract* by which any register-indirect
computed-goto dispatcher is made visible to Hex-Rays on the flowchart-preanalysis
seam and routed for CFF recovery. A dispatcher "shape" is a member of the family
if it implements discovery + delivery and then uses these two shared
primitives:

* :func:`mark_indirect_dispatcher` -- record that a function was materialized as
  a register-indirect dispatcher.
* :func:`is_materialized_indirect_dispatcher` -- the address-agnostic signal the
  CFF unflattener reads to route recovery to ``MMAT_CALLS`` (the maturity at
  which the ``cmp state,K; jz`` equality chain is still intact; GLBOPT1
  constant-folds it away).

Two shapes are registered today; they share the contract above but keep their own
discovery + delivery because both differ fundamentally:

* **Pointer-table (indexed N-way switch)** -- Tigress ``ijmp`` through a qword
  array of absolute code pointers. Discovery: :func:`discover_indirect_jump_table`
  (a data-structure scan). Delivery: *crefs* -- the state var indexes the table,
  so there is no per-target condition to lose and Hex-Rays rebuilds the switch.
* **Comparison-tree (binary search)** -- ``cmp state,K; setcc/cmov; jmp reg`` with
  ``target = dword[table]+KEY``. Discovery +
  delivery live in :mod:`d810.optimizers.microcode.flow.jumps.computed_goto_resolver` (concolic
  execution for the x64 cmov shape; a static const-prop fixpoint for the x86
  binary search). Delivery: *condition-preserving byte-patch* to an explicit
  ``j<cc>`` -- crefs decouple the condition from the target, so ``mba-simplify``
  strips the dead ``cmp/cmov`` and collapses the tree to a single comparison
  (verified). The delivery mechanism is a property of the topology, not a knob.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
    TerminalReturnCarrierRequest,
)
from d810.analyses.control_flow.native_preanalysis_session import (
    ResolverEvidenceAttachment,
)
from d810.core.logging import getLogger
from d810.hexrays.preanalysis.indirect_jump_discovery import (
    discover_indirect_jump_table,
)

logger = getLogger("d810.hexrays.preanalysis.indirect_jump_labels")


@dataclass(frozen=True)
class IndirectLabelMaterializationPlan:
    """Native label range to attach to a function before decompile."""

    function_ea: int
    label_start: int
    label_end: int
    table_address: int
    table_count: int
    target_eas: tuple[int, ...]


@dataclass(frozen=True)
class IndirectLabelMaterializationResult:
    """Outcome from one configured indirect-label materialization attempt."""

    function_ea: int
    table_address: int | None
    table_count: int
    label_start: int | None
    label_end: int | None
    target_count: int
    materialized_target_count: int
    dispatch_jump_ea: int | None
    jump_xref_count: int
    switch_info_installed: bool
    appended_tail: bool
    success: bool
    reason: str
    boundary_flow_xref_count: int = 0
    resolved_state_xref_count: int = 0


@dataclass(frozen=True)
class NativePatchPlanRequest:
    """Compatibility proposal shape retained for manager wiring.

    The generic native-patch gateway consumes this proposal after discovery.
    Keeping the request primitive prevents Hex-Rays lifecycle code from owning
    IDA database mutations directly.
    """

    materialization: IndirectLabelMaterializationPlan
    dispatch_jump_ea: int | None
    switch_start_ea: int | None
    install_switch_info: bool
    state_base: int
    state_var_stkoff: int | None


NativePatchPlanRequestExecutor = Callable[
    [NativePatchPlanRequest], IndirectLabelMaterializationResult
]


def _parse_int(value: object, *, default: int | None = None) -> int | None:
    if value is None:
        return default
    if isinstance(value, int):
        return int(value)
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return default


def plan_indirect_label_materialization(
    *,
    function_ea: int,
    table_address: int,
    target_eas: Sequence[int],
    configured_label_start: int | None = None,
    configured_label_end: int | None = None,
    discovered_function_end: int | None = None,
    discovered_next_function_start: int | None = None,
) -> IndirectLabelMaterializationPlan | None:
    """Plan the native label range represented by a computed-goto table."""
    unique_targets = tuple(sorted({int(target) for target in target_eas if target}))
    if not unique_targets:
        return None
    label_start = int(configured_label_start or min(unique_targets))
    if configured_label_end is not None:
        label_end = int(configured_label_end)
    elif discovered_function_end is not None and int(discovered_function_end) > max(
        unique_targets
    ):
        label_end = int(discovered_function_end)
    elif discovered_next_function_start is not None and int(
        discovered_next_function_start
    ) > max(unique_targets):
        label_end = int(discovered_next_function_start)
    else:
        return None
    if label_end <= label_start:
        return None
    return IndirectLabelMaterializationPlan(
        function_ea=int(function_ea),
        label_start=label_start,
        label_end=label_end,
        table_address=int(table_address),
        table_count=len(tuple(target_eas)),
        target_eas=unique_targets,
    )


def _target_owner_matches(func: object, target_ea: int) -> bool:
    try:
        import ida_funcs  # type: ignore[import-untyped]

        owner = ida_funcs.get_func(int(target_ea))
        return owner is not None and int(getattr(owner, "start_ea", -1)) == int(
            getattr(func, "start_ea", -2)
        )
    except Exception:
        return False


def _count_materialized_targets(
    func: object,
    targets: Sequence[int],
) -> int:
    return sum(1 for target in targets if _target_owner_matches(func, int(target)))


def _read_table_targets(table_address: int, table_count: int) -> tuple[int, ...]:
    import ida_bytes  # type: ignore[import-untyped]

    return tuple(
        int(ida_bytes.get_qword(int(table_address) + index * 8))
        for index in range(int(table_count))
    )


def _discover_next_function_start(function_ea: int) -> int | None:
    try:
        import ida_funcs  # type: ignore[import-untyped]

        next_func = ida_funcs.get_next_func(int(function_ea))
        if next_func is None:
            return None
        return int(getattr(next_func, "start_ea", 0) or 0) or None
    except Exception:
        return None


def _find_indirect_jump_ea(start: int, end: int) -> int | None:
    import ida_bytes  # type: ignore[import-untyped]
    import idaapi  # type: ignore[import-untyped]
    import idc  # type: ignore[import-untyped]

    ea = int(start)
    stop = int(end)
    badaddr = int(getattr(idaapi, "BADADDR", -1))
    while ea != badaddr and ea < stop:
        mnemonic = str(idc.print_insn_mnem(ea) or "").lower()
        operand = str(idc.print_operand(ea, 0) or "").lower()
        if mnemonic == "jmp" and operand:
            if operand.startswith(("loc_", "sub_", "0x")):
                pass
            elif operand.startswith(("qword ptr", "cs:", "ds:")):
                pass
            else:
                return ea
        next_ea = int(ida_bytes.next_head(ea, stop))
        if next_ea == badaddr or next_ea <= ea:
            break
        ea = next_ea
    return None



def materialize_indirect_label_targets(
    *,
    function_ea: int,
    table_address: int,
    table_count: int,
    label_start: int | None = None,
    label_end: int | None = None,
    dispatch_jump_ea: int | None = None,
    switch_start_ea: int | None = None,
    install_switch_info: bool = False,
    state_base: int = 1,
    state_var_stkoff: int | None = None,
) -> IndirectLabelMaterializationResult:
    """Discover one dispatcher and submit it to the manager-selected writer."""
    import ida_funcs  # type: ignore[import-untyped]

    function_ea = int(function_ea)
    table_address = int(table_address)
    table_count = int(table_count)
    if table_count <= 0:
        return IndirectLabelMaterializationResult(
            function_ea=function_ea,
            table_address=table_address,
            table_count=table_count,
            label_start=None,
            label_end=None,
            target_count=0,
            materialized_target_count=0,
            dispatch_jump_ea=None,
            jump_xref_count=0,
            switch_info_installed=False,
            appended_tail=False,
            success=False,
            reason="empty_table",
        )
    func = ida_funcs.get_func(function_ea)
    if func is None:
        return IndirectLabelMaterializationResult(
            function_ea=function_ea,
            table_address=table_address,
            table_count=table_count,
            label_start=None,
            label_end=None,
            target_count=0,
            materialized_target_count=0,
            dispatch_jump_ea=None,
            jump_xref_count=0,
            switch_info_installed=False,
            appended_tail=False,
            success=False,
            reason="missing_function",
        )
    targets = _read_table_targets(table_address, table_count)
    plan = plan_indirect_label_materialization(
        function_ea=function_ea,
        table_address=table_address,
        target_eas=targets,
        configured_label_start=label_start,
        configured_label_end=label_end,
        discovered_function_end=int(getattr(func, "end_ea", 0) or 0) or None,
        discovered_next_function_start=_discover_next_function_start(function_ea),
    )
    if plan is None:
        return IndirectLabelMaterializationResult(
            function_ea=function_ea,
            table_address=table_address,
            table_count=table_count,
            label_start=None,
            label_end=None,
            target_count=len(tuple(targets)),
            materialized_target_count=_count_materialized_targets(func, targets),
            dispatch_jump_ea=None,
            jump_xref_count=0,
            switch_info_installed=False,
            appended_tail=False,
            success=False,
            reason="unbounded_label_range",
        )
    indirect_jump_ea = (
        int(dispatch_jump_ea)
        if dispatch_jump_ea is not None
        else _find_indirect_jump_ea(function_ea, plan.label_end)
    )
    request = NativePatchPlanRequest(
        materialization=plan,
        dispatch_jump_ea=indirect_jump_ea,
        switch_start_ea=switch_start_ea,
        install_switch_info=bool(install_switch_info),
        state_base=int(state_base),
        state_var_stkoff=state_var_stkoff,
    )
    executor = _INDIRECT_MATERIALIZATION_EXECUTOR
    if executor is not None:
        return executor(request)
    return IndirectLabelMaterializationResult(
        function_ea=function_ea,
        table_address=table_address,
        table_count=table_count,
        label_start=plan.label_start,
        label_end=plan.label_end,
        target_count=len(plan.target_eas),
        materialized_target_count=_count_materialized_targets(func, plan.target_eas),
        dispatch_jump_ea=indirect_jump_ea,
        jump_xref_count=0,
        switch_info_installed=False,
        appended_tail=False,
        success=False,
        reason="native_patch_policy_disabled",
    )


def _config_for_function_ea(
    goto_table_info: Mapping[str, object],
    function_ea: int,
) -> Mapping[str, object] | None:
    """Return the config entry whose key matches *function_ea*, if any."""
    key = int(function_ea)
    for raw_function_ea, raw_config in goto_table_info.items():
        if not isinstance(raw_config, Mapping):
            continue
        parsed = _parse_int(raw_function_ea)
        if parsed is not None and int(parsed) == key:
            return raw_config
    return None


def _config_table_valid_for_function(
    function_ea: int,
    table_address: int | None,
    table_count: int | None,
) -> bool:
    """True when configured table reads in-function code pointers for *function_ea*."""
    if not table_address or not table_count:
        return False
    try:
        import ida_bytes  # type: ignore[import-untyped]
        import ida_funcs  # type: ignore[import-untyped]

        func = ida_funcs.get_func(int(function_ea))
        if func is None:
            return False
        first = int(ida_bytes.get_qword(int(table_address)))
        return int(func.start_ea) <= first < int(func.end_ea)
    except Exception:
        return False


def materialize_indirect_label_targets_for_function(
    function_ea: int,
    goto_table_info: Mapping[str, object] | None = None,
) -> IndirectLabelMaterializationResult | None:
    """Materialize one function's indirect labels, config-or-discovery.

    Resolves the table layout from a matching config entry when present and
    valid for *function_ea*; otherwise discovers it structurally.  Returns
    ``None`` when the function is not an indirect-table dispatcher (no
    register-indirect jump with a resolvable in-function table), keeping the
    prepass behavior-neutral for every other function.
    """
    info = goto_table_info if isinstance(goto_table_info, Mapping) else {}
    cfg = _config_for_function_ea(info, int(function_ea))
    cfg_table_address = (
        _parse_int(cfg.get("table_address")) if cfg is not None else None
    )
    cfg_table_count = (
        _parse_int(cfg.get("table_nb_elt"), default=0) if cfg is not None else 0
    )
    if _config_table_valid_for_function(
        int(function_ea), cfg_table_address, cfg_table_count
    ):
        return materialize_indirect_label_targets(
            function_ea=int(function_ea),
            table_address=int(cfg_table_address),
            table_count=int(cfg_table_count),
            label_start=_parse_int(cfg.get("label_start")),
            label_end=_parse_int(
                cfg.get("label_end"),
                default=_parse_int(cfg.get("function_end")),
            ),
            dispatch_jump_ea=_parse_int(cfg.get("dispatch_jump_ea")),
            switch_start_ea=_parse_int(cfg.get("switch_start_ea")),
            install_switch_info=bool(cfg.get("install_switch_info", False)),
            state_base=_parse_int(cfg.get("state_base"), default=1) or 1,
            state_var_stkoff=_parse_int(cfg.get("state_var_stkoff")),
        )

    discovered = discover_indirect_jump_table(int(function_ea))
    if discovered is None:
        return None
    state_base = (_parse_int(cfg.get("state_base"), default=1) or 1) if cfg else 1
    state_var_stkoff = _parse_int(cfg.get("state_var_stkoff")) if cfg else None
    if state_var_stkoff is None and discovered.state_var_stkoff is not None:
        state_var_stkoff = int(discovered.state_var_stkoff)
    install_switch = bool(cfg.get("install_switch_info", False)) if cfg else False
    return materialize_indirect_label_targets(
        function_ea=int(discovered.function_ea),
        table_address=int(discovered.table_address),
        table_count=int(discovered.table_count),
        label_start=int(discovered.label_start),
        label_end=int(discovered.label_end),
        dispatch_jump_ea=int(discovered.dispatch_jump_ea),
        switch_start_ea=int(discovered.dispatch_jump_ea),
        install_switch_info=install_switch,
        state_base=int(state_base),
        state_var_stkoff=state_var_stkoff,
    )


def materialize_discovered_indirect_label_targets(
    goto_table_info: Mapping[str, object] | None = None,
) -> tuple[IndirectLabelMaterializationResult, ...]:
    """Discover and materialize every indirect-table dispatcher in the database.

    Address-agnostic configure-time prepass: scans all functions for the
    register-indirect jump-table signature and materializes the recovered label
    bodies, so the engine fires without per-binary configured addresses even
    after a rebuild shifts the binary.  Behavior-neutral for any function that
    is not a real indirect-table dispatcher (discovery returns ``None``).

    Configured ``goto_table_info`` (if any) supplies per-function state-machine
    overrides (state base / slot) when a config entry matches a discovered EA.
    """
    results: list[IndirectLabelMaterializationResult] = []
    try:
        import idautils  # type: ignore[import-untyped]
    except Exception:
        logger.debug("idautils unavailable; skipping indirect discovery scan")
        return ()
    info = goto_table_info if isinstance(goto_table_info, Mapping) else {}
    seen: set[int] = set()
    for function_ea in idautils.Functions():
        key = int(function_ea)
        if key in seen:
            continue
        seen.add(key)
        try:
            result = materialize_indirect_label_targets_for_function(key, info)
        except Exception:
            logger.debug(
                "discovery-scan materialization failed for 0x%X",
                key,
                exc_info=True,
            )
            continue
        if result is not None:
            results.append(result)
    logger.info(
        "Tigress indirect discovery scan materialized %d dispatcher(s)",
        len(results),
    )
    return tuple(results)


def materialize_indirect_label_targets_from_config(
    goto_table_info: Mapping[str, object],
) -> tuple[IndirectLabelMaterializationResult, ...]:
    """Materialize all configured Tigress indirect target-label ranges."""
    results: list[IndirectLabelMaterializationResult] = []
    for raw_function_ea, raw_config in goto_table_info.items():
        if not isinstance(raw_config, Mapping):
            continue
        function_ea = _parse_int(raw_function_ea)
        table_address = _parse_int(raw_config.get("table_address"))
        table_count = _parse_int(raw_config.get("table_nb_elt"), default=0)
        if function_ea is None or table_address is None or not table_count:
            logger.warning(
                "Skipping malformed indirect-label materialization config for %r",
                raw_function_ea,
            )
            continue
        results.append(
            materialize_indirect_label_targets(
                function_ea=function_ea,
                table_address=table_address,
                table_count=int(table_count),
                label_start=_parse_int(raw_config.get("label_start")),
                label_end=_parse_int(
                    raw_config.get("label_end"),
                    default=_parse_int(raw_config.get("function_end")),
                ),
                dispatch_jump_ea=_parse_int(raw_config.get("dispatch_jump_ea")),
                switch_start_ea=_parse_int(raw_config.get("switch_start_ea")),
                install_switch_info=bool(raw_config.get("install_switch_info", False)),
                state_base=_parse_int(raw_config.get("state_base"), default=1) or 1,
                state_var_stkoff=_parse_int(raw_config.get("state_var_stkoff")),
            )
        )
    return tuple(results)


# --- Flowchart-stage materialization registry -------------------------------
#
# The indirect engine registers its ``goto_table_info`` here at project-load
# time; the generic Hex-Rays flowchart preanalysis event materializes labels for
# the function being decompiled and requests a one-shot Hex-Rays redo.  That
# keeps the work current-function scoped while letting the rebuilt MBA see the
# computed crefs.  Registration is behavior-neutral: discovery returns ``None``
# for any function that is not a real indirect-table dispatcher.

_INDIRECT_MATERIALIZATION_REGISTERED = False
_INDIRECT_MATERIALIZATION_GOTO_TABLE: dict = {}
_INDIRECT_MATERIALIZATION_EXECUTOR: NativePatchPlanRequestExecutor | None = None
_INDIRECT_MATERIALIZATION_HANDLER = "hexrays.indirect_jump_label_materialization"


@dataclass(frozen=True, slots=True)
class IndirectMaterializationRegistrySnapshot:
    """Identity-preserving snapshot of profile-global materialization state."""

    registered: bool
    goto_table_ref: dict
    goto_table_contents: dict
    executor: NativePatchPlanRequestExecutor | None
    flowchart_registry: tuple[dict, dict]


def snapshot_indirect_materialization_registry() -> IndirectMaterializationRegistrySnapshot:
    """Capture all globals changed by indirect-profile rule configuration."""

    from d810.hexrays.preanalysis.flowchart_preanalysis import (
        snapshot_flowchart_preanalysis_registry,
    )

    return IndirectMaterializationRegistrySnapshot(
        registered=_INDIRECT_MATERIALIZATION_REGISTERED,
        goto_table_ref=_INDIRECT_MATERIALIZATION_GOTO_TABLE,
        goto_table_contents=dict(_INDIRECT_MATERIALIZATION_GOTO_TABLE),
        executor=_INDIRECT_MATERIALIZATION_EXECUTOR,
        flowchart_registry=snapshot_flowchart_preanalysis_registry(),
    )


def restore_indirect_materialization_registry(
    snapshot: IndirectMaterializationRegistrySnapshot,
) -> None:
    """Restore indirect materialization state and handler registry in place."""

    global _INDIRECT_MATERIALIZATION_REGISTERED
    global _INDIRECT_MATERIALIZATION_GOTO_TABLE
    global _INDIRECT_MATERIALIZATION_EXECUTOR
    from d810.hexrays.preanalysis.flowchart_preanalysis import (
        restore_flowchart_preanalysis_registry,
    )

    snapshot.goto_table_ref.clear()
    snapshot.goto_table_ref.update(snapshot.goto_table_contents)
    _INDIRECT_MATERIALIZATION_REGISTERED = snapshot.registered
    _INDIRECT_MATERIALIZATION_GOTO_TABLE = snapshot.goto_table_ref
    _INDIRECT_MATERIALIZATION_EXECUTOR = snapshot.executor
    restore_flowchart_preanalysis_registry(snapshot.flowchart_registry)


def merge_materialized_indirect_transfers(
    state: object,
    transfers: tuple[MaterializedIndirectTransfer, ...],
) -> bool:
    """Merge resolver proof through its owning lifecycle session."""
    if not isinstance(state, ResolverEvidenceAttachment):
        raise TypeError("materialized transfers require ResolverSessionState")
    changed = state.native_preanalysis.merge_materialized_transfers(
        state.native_key,
        transfers,
    )
    if changed:
        state.invalidate_current_mba_binding()
    return changed


def materialized_indirect_transfers(
    state: object,
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Return session-owned computed-goto proof for the active callback."""
    if not isinstance(state, ResolverEvidenceAttachment):
        raise TypeError("materialized transfers require ResolverSessionState")
    facts = state.native_preanalysis.facts
    return () if facts is None else facts.transfers


def merge_terminal_return_carrier_requests(
    state: object,
    requests: tuple[TerminalReturnCarrierRequest, ...],
) -> bool:
    """Merge exact carrier requests through their lifecycle owner."""
    if not isinstance(state, ResolverEvidenceAttachment):
        raise TypeError("terminal carrier requests require ResolverSessionState")
    return state.native_preanalysis.merge_terminal_return_carrier_requests(
        state.native_key,
        requests,
    )


def terminal_return_carrier_requests(
    state: object,
) -> tuple[TerminalReturnCarrierRequest, ...]:
    """Return session-owned terminal-carrier proof for the active callback."""
    if not isinstance(state, ResolverEvidenceAttachment):
        raise TypeError("terminal carrier requests require ResolverSessionState")
    evidence = state.native_preanalysis.resolver_evidence
    return () if evidence is None else evidence.terminal_return_carrier_requests


def _on_flowchart_preanalysis(*, function_ea: int, mba: object, decision: dict) -> None:
    session = decision.get("session")
    if session is None:
        return
    try:
        from d810.analyses.control_flow.native_preanalysis_session import (
            attached_resolver_session_state,
        )

        state = attached_resolver_session_state(session)
    except (TypeError, ValueError):
        return
    if state is None:
        return
    result = run_indirect_materialization_for_function(int(function_ea), state=state)
    if result is None or not result.success:
        return
    from d810.hexrays.preanalysis.flowchart_preanalysis import request_hexrays_redo

    request_hexrays_redo(
        decision,
        "indirect_jump_label_materialized",
        function_ea=result.function_ea,
        target_count=result.target_count,
        materialized_target_count=result.materialized_target_count,
    )


def register_indirect_materialization(goto_table_info: Mapping[str, object]) -> None:
    """Register table info for flowchart-stage current-function materialization."""
    global _INDIRECT_MATERIALIZATION_REGISTERED, _INDIRECT_MATERIALIZATION_GOTO_TABLE
    from d810.hexrays.preanalysis.flowchart_preanalysis import (
        register_flowchart_preanalysis_handler,
    )

    _INDIRECT_MATERIALIZATION_REGISTERED = True
    _INDIRECT_MATERIALIZATION_GOTO_TABLE = dict(goto_table_info or {})
    register_flowchart_preanalysis_handler(
        _INDIRECT_MATERIALIZATION_HANDLER,
        _on_flowchart_preanalysis,
    )


def reset_indirect_materialization() -> None:
    """Clear the flowchart-stage materialization registration."""
    global _INDIRECT_MATERIALIZATION_REGISTERED, _INDIRECT_MATERIALIZATION_GOTO_TABLE
    from d810.hexrays.preanalysis.flowchart_preanalysis import (
        unregister_flowchart_preanalysis_handler,
    )

    _INDIRECT_MATERIALIZATION_REGISTERED = False
    _INDIRECT_MATERIALIZATION_GOTO_TABLE = {}
    unregister_flowchart_preanalysis_handler(_INDIRECT_MATERIALIZATION_HANDLER)


def set_indirect_materialization_default_executor(
    executor: NativePatchPlanRequestExecutor | None,
) -> None:
    """Install the manager-selected execution policy for this profile."""
    global _INDIRECT_MATERIALIZATION_EXECUTOR
    _INDIRECT_MATERIALIZATION_EXECUTOR = executor


def run_indirect_materialization_for_function(
    function_ea: int,
    *,
    state: object,
) -> IndirectLabelMaterializationResult | None:
    """Materialize indirect labels for *function_ea* if registered (idempotent).

    Called from the flowchart preanalysis event subscriber.  Returns ``None``
    (no-op) unless the indirect engine is active and the function is a real
    indirect-table dispatcher.  Each function EA is materialized at most once per
    registration.
    """
    if not _INDIRECT_MATERIALIZATION_REGISTERED:
        return None
    if not isinstance(state, ResolverEvidenceAttachment):
        raise TypeError("indirect materialization requires ResolverSessionState")
    key = int(function_ea)
    if state.indirect_label_materialized:
        return None
    state.indirect_label_materialized = True
    try:
        result = materialize_indirect_label_targets_for_function(
            key,
            _INDIRECT_MATERIALIZATION_GOTO_TABLE,
        )
    except Exception:
        logger.warning(
            "flowchart-stage indirect materialization failed for 0x%X",
            key,
            exc_info=True,
        )
        return None
    if result is not None:
        state.indirect_dispatcher_materialized = True
        logger.info(
            "Tigress indirect flowchart materialization 0x%X: success=%s "
            "targets=%d/%d jump_xrefs=%d reason=%s",
            result.function_ea,
            result.success,
            result.materialized_target_count,
            result.target_count,
            result.jump_xref_count,
            result.reason,
        )
    return result


def is_materialized_indirect_dispatcher(state: object) -> bool:
    """Return the active session's structural indirect-dispatcher marker."""
    if not isinstance(state, ResolverEvidenceAttachment):
        raise TypeError("indirect dispatcher marker requires ResolverSessionState")
    return state.indirect_dispatcher_materialized


def mark_indirect_dispatcher(state: object) -> None:
    """Mark the active lifecycle session as an indirect dispatcher profile."""
    if not isinstance(state, ResolverEvidenceAttachment):
        raise TypeError("indirect dispatcher marker requires ResolverSessionState")
    state.indirect_dispatcher_materialized = True


__all__ = [
    "mark_indirect_dispatcher",
    "merge_materialized_indirect_transfers",
    "materialized_indirect_transfers",
    "merge_terminal_return_carrier_requests",
    "terminal_return_carrier_requests",
    "IndirectLabelMaterializationPlan",
    "NativePatchPlanRequest",
    "is_materialized_indirect_dispatcher",
    "IndirectLabelMaterializationResult",
    "materialize_indirect_label_targets",
    "materialize_discovered_indirect_label_targets",
    "materialize_indirect_label_targets_for_function",
    "register_indirect_materialization",
    "reset_indirect_materialization",
    "set_indirect_materialization_default_executor",
    "IndirectMaterializationRegistrySnapshot",
    "snapshot_indirect_materialization_registry",
    "restore_indirect_materialization_registry",
    "run_indirect_materialization_for_function",
    "materialize_indirect_label_targets_from_config",
    "plan_indirect_label_materialization",
]

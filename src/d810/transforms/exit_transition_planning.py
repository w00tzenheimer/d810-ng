from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ExitRedirectAttempt:
    source_block: int
    target_entry: int
    state_value: int
    exit_state_value: int | None = None
    handler_entry: int | None = None
    discovery_kind: str = ""


@dataclass(frozen=True, slots=True)
class ExitRedirectDecision:
    source_block: int
    target_entry: int
    state_value: int
    redirect_kind: str
    old_target: int | None = None
    exit_state_value: int | None = None
    handler_entry: int | None = None
    discovery_kind: str = ""


@dataclass(frozen=True, slots=True)
class ExitRedirectSelection:
    accepted: tuple[ExitRedirectDecision, ...]
    emitted: frozenset[tuple[int, int]]
    claimed_1way: dict[int, int]
    remaining_targets: frozenset[int] | None = None


def _resolve_old_target_for_two_way(
    *,
    source_block: int,
    target_entry: int,
    block_succ_map: dict[int, tuple[int, ...]] | dict[int, list[int]],
    bst_node_blocks: set[int],
    dispatcher_region: set[int],
    owned_blocks: set[int],
) -> int | None:
    from_succs = tuple(int(succ) for succ in block_succ_map.get(int(source_block), ()))
    for succ_serial in from_succs:
        if succ_serial in bst_node_blocks:
            return succ_serial
    for succ_serial in from_succs:
        if succ_serial not in owned_blocks:
            return succ_serial
    for succ_serial in from_succs:
        if succ_serial in dispatcher_region:
            return succ_serial
    for succ_serial in from_succs:
        if succ_serial != int(target_entry):
            return succ_serial
    return None


def plan_exit_redirects(
    attempts: tuple[ExitRedirectAttempt, ...],
    *,
    block_nsucc_map: dict[int, int],
    block_succ_map: dict[int, tuple[int, ...]] | dict[int, list[int]],
    bst_node_blocks: set[int],
    dispatcher_region: set[int],
    owned_blocks: set[int],
    emitted: set[tuple[int, int]] | frozenset[tuple[int, int]],
    claimed_1way: dict[int, int],
    target_allowlist: set[int] | frozenset[int] | None = None,
    skip_owned_sources: bool = False,
) -> ExitRedirectSelection:
    local_emitted = set((int(src), int(dst)) for src, dst in emitted)
    local_claimed = {int(src): int(dst) for src, dst in claimed_1way.items()}
    remaining_targets = (
        set(int(target) for target in target_allowlist)
        if target_allowlist is not None
        else None
    )
    accepted: list[ExitRedirectDecision] = []

    for attempt in attempts:
        source_block = int(attempt.source_block)
        target_entry = int(attempt.target_entry)
        emit_key = (source_block, target_entry)

        if remaining_targets is not None and target_entry not in remaining_targets:
            continue
        if emit_key in local_emitted:
            continue
        if skip_owned_sources and source_block in owned_blocks:
            continue

        from_nsucc = int(block_nsucc_map.get(source_block, 1))
        if from_nsucc == 2:
            old_target = _resolve_old_target_for_two_way(
                source_block=source_block,
                target_entry=target_entry,
                block_succ_map=block_succ_map,
                bst_node_blocks=bst_node_blocks,
                dispatcher_region=dispatcher_region,
                owned_blocks=owned_blocks,
            )
            if old_target is None:
                continue
            accepted.append(
                ExitRedirectDecision(
                    source_block=source_block,
                    target_entry=target_entry,
                    state_value=int(attempt.state_value),
                    redirect_kind="edge",
                    old_target=int(old_target),
                    exit_state_value=(
                        int(attempt.exit_state_value)
                        if attempt.exit_state_value is not None
                        else None
                    ),
                    handler_entry=(
                        int(attempt.handler_entry)
                        if attempt.handler_entry is not None
                        else None
                    ),
                    discovery_kind=str(attempt.discovery_kind),
                )
            )
            local_emitted.add(emit_key)
            if remaining_targets is not None:
                remaining_targets.discard(target_entry)
            continue

        first_target = local_claimed.get(source_block)
        if first_target is not None:
            continue

        accepted.append(
            ExitRedirectDecision(
                source_block=source_block,
                target_entry=target_entry,
                state_value=int(attempt.state_value),
                redirect_kind="goto",
                exit_state_value=(
                    int(attempt.exit_state_value)
                    if attempt.exit_state_value is not None
                    else None
                ),
                handler_entry=(
                    int(attempt.handler_entry)
                    if attempt.handler_entry is not None
                    else None
                ),
                discovery_kind=str(attempt.discovery_kind),
            )
        )
        local_claimed[source_block] = target_entry
        local_emitted.add(emit_key)
        if remaining_targets is not None:
            remaining_targets.discard(target_entry)

    return ExitRedirectSelection(
        accepted=tuple(accepted),
        emitted=frozenset(local_emitted),
        claimed_1way=dict(local_claimed),
        remaining_targets=(
            frozenset(remaining_targets) if remaining_targets is not None else None
        ),
    )


__all__ = [
    "ExitRedirectAttempt",
    "ExitRedirectDecision",
    "ExitRedirectSelection",
    "plan_exit_redirects",
]

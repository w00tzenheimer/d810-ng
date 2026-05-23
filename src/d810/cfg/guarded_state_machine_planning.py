"""CFG planning for guarded_state_machine facts."""
from __future__ import annotations

from d810.cfg.graph_modification import GraphModification, RedirectBranch, RedirectGoto
from d810.core.typing import Protocol, Sequence


class GuardedStateMachineFixLike(Protocol):
    outer_guard_block: int
    outer_guard_old_target: int
    inner_guard_block: int
    inner_guard_old_target: int
    inner_override_block: int
    inner_override_old_target: int
    invalid_target: int
    success_target: int


def build_guarded_state_machine_modifications(
    fixes: Sequence[GuardedStateMachineFixLike],
) -> list[GraphModification]:
    """Translate guarded state-machine evidence into graph edits."""
    modifications: list[GraphModification] = []
    for fix in fixes:
        # Apply the inner edits before severing the outer guard's edge into
        # the inner guard.  Otherwise the inner guard's predecessor set changes
        # first and the backend's target-change precondition can reject the
        # second redirect.
        modifications.append(
            RedirectBranch(
                from_serial=int(fix.inner_guard_block),
                old_target=int(fix.inner_guard_old_target),
                new_target=int(fix.invalid_target),
            )
        )
        modifications.append(
            RedirectGoto(
                from_serial=int(fix.inner_override_block),
                old_target=int(fix.inner_override_old_target),
                new_target=int(fix.success_target),
            )
        )
        modifications.append(
            RedirectBranch(
                from_serial=int(fix.outer_guard_block),
                old_target=int(fix.outer_guard_old_target),
                new_target=int(fix.invalid_target),
            )
        )
    return modifications


__all__ = [
    "build_guarded_state_machine_modifications",
]

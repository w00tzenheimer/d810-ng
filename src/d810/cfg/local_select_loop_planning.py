"""CFG planning for local_select_loop facts."""
from __future__ import annotations

from d810.cfg.graph_modification import (
    ConvertToGoto,
    GraphModification,
    RedirectBranch,
    RedirectGoto,
)
from d810.core.typing import Protocol, Sequence


class LocalSelectLoopFixLike(Protocol):
    init_block: int
    init_old_target: int
    test_block: int
    test_old_target: int
    assignment_block: int
    assignment_old_target: int
    exit_target: int
    selector_assignment_block: int | None
    selector_assignment_old_target: int | None


class LocalSelectConvergenceLoopFixLike(Protocol):
    init_block: int
    header_block: int
    loop_entry_target: int
    exit_target: int


class LocalSelectTerminalLoopFixLike(Protocol):
    init_block: int
    init_old_target: int
    sink_block: int
    sink_old_target: int
    exit_target: int | None


class LocalSelectDirectExitLoopFixLike(Protocol):
    init_block: int
    init_old_target: int
    header_block: int
    loop_entry_target: int
    exit_target: int


LocalSelectLoopCandidateLike = (
    LocalSelectLoopFixLike
    | LocalSelectConvergenceLoopFixLike
    | LocalSelectTerminalLoopFixLike
    | LocalSelectDirectExitLoopFixLike
)


def _has_attrs(value: object, attrs: tuple[str, ...]) -> bool:
    return all(hasattr(value, attr) for attr in attrs)


def build_local_select_loop_modifications(
    fixes: Sequence[LocalSelectLoopCandidateLike],
) -> list[GraphModification]:
    """Translate local select-loop evidence into graph edits."""
    modifications: list[GraphModification] = []
    for fix in fixes:
        if _has_attrs(fix, ("header_block", "loop_entry_target")) and not hasattr(
            fix,
            "init_old_target",
        ):
            modifications.append(
                ConvertToGoto(
                    block_serial=int(fix.header_block),
                    goto_target=int(fix.exit_target),
                )
            )
            continue
        if _has_attrs(fix, ("sink_block", "sink_old_target")):
            if fix.exit_target is not None:
                modifications.append(
                    RedirectGoto(
                        from_serial=int(fix.init_block),
                        old_target=int(fix.init_old_target),
                        new_target=int(fix.exit_target),
                    )
                )
            continue
        if _has_attrs(fix, ("header_block", "loop_entry_target")):
            modifications.append(
                RedirectGoto(
                    from_serial=int(fix.init_block),
                    old_target=int(fix.init_old_target),
                    new_target=int(fix.exit_target),
                )
            )
            continue
        if (
            fix.selector_assignment_block is not None
            and fix.selector_assignment_old_target is not None
        ):
            modifications.append(
                RedirectGoto(
                    from_serial=int(fix.selector_assignment_block),
                    old_target=int(fix.selector_assignment_old_target),
                    new_target=int(fix.assignment_block),
                )
            )
            modifications.append(
                RedirectGoto(
                    from_serial=int(fix.init_block),
                    old_target=int(fix.init_old_target),
                    new_target=int(fix.exit_target),
                )
            )
            modifications.append(
                RedirectGoto(
                    from_serial=int(fix.assignment_block),
                    old_target=int(fix.assignment_old_target),
                    new_target=int(fix.exit_target),
                )
            )
            modifications.append(
                ConvertToGoto(
                    block_serial=int(fix.init_old_target),
                    goto_target=int(fix.exit_target),
                )
            )
            modifications.append(
                ConvertToGoto(
                    block_serial=int(fix.test_block),
                    goto_target=int(fix.exit_target),
                )
            )
            continue
        modifications.append(
            RedirectBranch(
                from_serial=int(fix.test_block),
                old_target=int(fix.test_old_target),
                new_target=int(fix.exit_target),
            )
        )
        modifications.append(
            RedirectGoto(
                from_serial=int(fix.assignment_block),
                old_target=int(fix.assignment_old_target),
                new_target=int(fix.exit_target),
            )
        )
        modifications.append(
            RedirectGoto(
                from_serial=int(fix.init_block),
                old_target=int(fix.init_old_target),
                new_target=int(fix.test_block),
            )
        )
        modifications.append(
            ConvertToGoto(
                block_serial=int(fix.init_old_target),
                goto_target=int(fix.exit_target),
            )
        )
    return modifications


__all__ = [
    "build_local_select_loop_modifications",
]

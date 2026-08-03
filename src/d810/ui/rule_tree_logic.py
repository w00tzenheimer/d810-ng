"""Pure policy for state-aware rule-tree context actions."""

from __future__ import annotations

import dataclasses
import enum
from collections.abc import Iterable, Set as AbstractSet


class RuleTreeTargetKind(str, enum.Enum):
    """Kinds of selectable tree targets that can receive a context action."""

    RULE = "rule"
    GROUP = "group"


class RuleTreeContextAction(str, enum.Enum):
    """State-changing intent exposed by a rule-tree context menu."""

    ENABLE = "enable"
    DISABLE = "disable"
    ENABLE_ALL = "enable-all"
    DISABLE_ALL = "disable-all"

    @property
    def label(self) -> str:
        return {
            RuleTreeContextAction.ENABLE: "Enable",
            RuleTreeContextAction.DISABLE: "Disable",
            RuleTreeContextAction.ENABLE_ALL: "Enable All",
            RuleTreeContextAction.DISABLE_ALL: "Disable All",
        }[self]


@dataclasses.dataclass(frozen=True, slots=True)
class RuleTreeContextTarget:
    """Qt-free description of a rule or aggregate tree target."""

    kind: RuleTreeTargetKind
    rule_names: tuple[str, ...]
    enabled_count: int
    total_count: int
    rule_name: str | None = None
    optimizer_type: str | None = None

    def __post_init__(self) -> None:
        names = tuple(dict.fromkeys(str(name) for name in self.rule_names if name))
        object.__setattr__(self, "rule_names", names)
        object.__setattr__(self, "enabled_count", max(0, int(self.enabled_count)))
        object.__setattr__(self, "total_count", max(0, int(self.total_count)))


@dataclasses.dataclass(frozen=True, slots=True)
class RuleTreeContextRequest:
    """A target plus the state-changing operation selected by the user."""

    target: RuleTreeContextTarget
    action: RuleTreeContextAction


def context_action_for(
    target: RuleTreeContextTarget,
) -> RuleTreeContextAction | None:
    """Return the one state action appropriate for *target*."""

    if not target.rule_names or target.total_count <= 0:
        return None
    if target.kind is RuleTreeTargetKind.RULE:
        return (
            RuleTreeContextAction.DISABLE
            if target.enabled_count > 0
            else RuleTreeContextAction.ENABLE
        )
    return (
        RuleTreeContextAction.DISABLE_ALL
        if target.enabled_count >= target.total_count
        else RuleTreeContextAction.ENABLE_ALL
    )


def apply_context_action(
    enabled_names: AbstractSet[str] | Iterable[str],
    target: RuleTreeContextTarget,
    action: RuleTreeContextAction,
) -> set[str]:
    """Return a legacy draft set after applying *action* to *target*.

    The input collection is never mutated. Unsupported action/target pairs are
    intentionally no-ops so callers can safely pass a request from a generic
    menu dispatcher.
    """

    result = {str(name) for name in enabled_names}
    names = set(target.rule_names)
    if action in (RuleTreeContextAction.ENABLE, RuleTreeContextAction.ENABLE_ALL):
        result.update(names)
    elif action in (
        RuleTreeContextAction.DISABLE,
        RuleTreeContextAction.DISABLE_ALL,
    ):
        result.difference_update(names)
    return result


__all__ = [
    "RuleTreeContextAction",
    "RuleTreeContextRequest",
    "RuleTreeContextTarget",
    "RuleTreeTargetKind",
    "apply_context_action",
    "context_action_for",
]

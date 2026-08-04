"""Pure projection for the public pass, transform, and stage tree."""

from __future__ import annotations

import dataclasses
import enum
from collections.abc import Iterable, Sequence


class PassTreeNodeKind(str, enum.Enum):
    PASS = "pass"
    TRANSFORM = "transform"
    STAGE = "stage"


@dataclasses.dataclass(frozen=True, slots=True)
class PassTreeNode:
    pass_id: str
    node_id: str
    label: str
    kind: PassTreeNodeKind
    enabled: bool
    editable: bool


@dataclasses.dataclass(frozen=True, slots=True)
class PassTreeRow:
    parent: PassTreeNode
    children: tuple[PassTreeNode, ...]


def project_pass_tree(
    catalog: Sequence[object],
    enabled_pass_ids: Iterable[str],
) -> tuple[PassTreeRow, ...]:
    """Return public tree rows in effective pipeline order, then catalog order."""

    enabled_order = tuple(dict.fromkeys(str(value) for value in enabled_pass_ids))
    enabled = set(enabled_order)
    by_id = {
        str(getattr(entry, "pass_id")): entry
        for entry in catalog
        if getattr(entry, "pass_id", None)
    }
    ordered_ids = enabled_order + tuple(
        pass_id for pass_id in by_id if pass_id not in enabled
    )
    rows: list[PassTreeRow] = []
    for pass_id in ordered_ids:
        entry = by_id.get(pass_id)
        if entry is None:
            rows.append(
                PassTreeRow(
                    parent=PassTreeNode(
                        pass_id,
                        pass_id,
                        pass_id,
                        PassTreeNodeKind.PASS,
                        True,
                        True,
                    ),
                    children=(),
                )
            )
            continue
        active = pass_id in enabled
        display_name = str(getattr(entry, "display_name", pass_id))
        children = tuple(
            PassTreeNode(
                pass_id,
                str(transform_id),
                str(transform_id),
                PassTreeNodeKind.TRANSFORM,
                active,
                True,
            )
            for transform_id in getattr(entry, "transform_ids", ())
        ) + tuple(
            PassTreeNode(
                pass_id,
                str(stage_id),
                str(stage_id),
                PassTreeNodeKind.STAGE,
                active,
                False,
            )
            for stage_id in getattr(entry, "stage_ids", ())
        )
        rows.append(
            PassTreeRow(
                parent=PassTreeNode(
                    pass_id,
                    pass_id,
                    f"{display_name} ({pass_id})",
                    PassTreeNodeKind.PASS,
                    active,
                    True,
                ),
                children=children,
            )
        )
    return tuple(rows)


__all__ = [
    "PassTreeNode",
    "PassTreeNodeKind",
    "PassTreeRow",
    "project_pass_tree",
]

"""Portable receipt lineage for scoped fragment publication authority."""

from __future__ import annotations

from dataclasses import dataclass


def _identifier(value: str, description: str) -> str:
    value = str(value).strip()
    if not value:
        raise ValueError(f"{description} must not be empty")
    return value


@dataclass(frozen=True, slots=True)
class NormalizationWorkItemAuthority:
    """One committed normalization work item that may authorize a later plan."""

    evidence_generation: int
    publication_revision: int
    source_plan_id: str
    source_atomic_group_id: str
    work_item_id: str
    published_operation_ids: tuple[str, ...]
    selected_obligation_ids: tuple[str, ...]
    remaining_obligation_ids: tuple[str, ...]
    unreachable_obligation_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        evidence_generation = int(self.evidence_generation)
        publication_revision = int(self.publication_revision)
        if evidence_generation <= 0:
            raise ValueError(
                "normalization work-item authority generation must be positive"
            )
        if publication_revision <= 0:
            raise ValueError(
                "normalization work-item authority revision must be positive"
            )
        published_operations = tuple(
            _identifier(value, "published normalization operation")
            for value in self.published_operation_ids
        )
        selected = tuple(
            _identifier(value, "selected normalization obligation")
            for value in self.selected_obligation_ids
        )
        remaining = tuple(
            _identifier(value, "remaining normalization obligation")
            for value in self.remaining_obligation_ids
        )
        unreachable = tuple(
            _identifier(value, "unreachable normalization obligation")
            for value in self.unreachable_obligation_ids
        )
        if not published_operations or not selected:
            raise ValueError(
                "normalization work-item authority requires published operations "
                "and selected obligations"
            )
        if len(published_operations) != len(set(published_operations)):
            raise ValueError(
                "normalization work-item authority operations must be unique"
            )
        obligation_sets = tuple(map(set, (selected, remaining, unreachable)))
        if any(
            len(values) != len(set(values))
            for values in (selected, remaining, unreachable)
        ) or any(
            left & right
            for index, left in enumerate(obligation_sets)
            for right in obligation_sets[index + 1 :]
        ):
            raise ValueError(
                "normalization work-item authority obligations must be unique "
                "and disjoint"
            )
        if not set(selected).issubset(published_operations):
            raise ValueError(
                "selected normalization obligations must be published operations"
            )
        if set(published_operations).intersection((*remaining, *unreachable)):
            raise ValueError(
                "unpublished normalization obligations cannot be published operations"
            )
        object.__setattr__(self, "evidence_generation", evidence_generation)
        object.__setattr__(self, "publication_revision", publication_revision)
        object.__setattr__(
            self,
            "source_plan_id",
            _identifier(self.source_plan_id, "normalization source plan id"),
        )
        object.__setattr__(
            self,
            "source_atomic_group_id",
            _identifier(
                self.source_atomic_group_id,
                "normalization source atomic group id",
            ),
        )
        object.__setattr__(
            self,
            "work_item_id",
            _identifier(self.work_item_id, "normalization work-item id"),
        )
        object.__setattr__(self, "published_operation_ids", published_operations)
        object.__setattr__(self, "selected_obligation_ids", selected)
        object.__setattr__(self, "remaining_obligation_ids", remaining)
        object.__setattr__(self, "unreachable_obligation_ids", unreachable)

    def is_immediate_successor_of(
        self,
        previous: NormalizationWorkItemAuthority,
    ) -> bool:
        """Return whether this is the next receipt for the same plan lineage."""
        if not isinstance(previous, NormalizationWorkItemAuthority):
            raise TypeError("normalization authority predecessor has the wrong type")
        return bool(
            self.evidence_generation == previous.evidence_generation
            and self.publication_revision == previous.publication_revision + 1
            and self.source_plan_id == previous.source_plan_id
            and self.source_atomic_group_id == previous.source_atomic_group_id
        )


__all__ = ["NormalizationWorkItemAuthority"]

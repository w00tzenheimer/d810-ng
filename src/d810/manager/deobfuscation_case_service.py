"""Manager-owned projection of diagnostic evidence into Workbench decisions."""

from __future__ import annotations

import sqlite3

from d810.core.deobfuscation_case import DeobfuscationCaseEvidence
from d810.core.deobfuscation_case import DeobfuscationCaseSnapshot
from d810.core.typing import Protocol
from d810.diagnostics.deobfuscation_case_repository import (
    DeobfuscationCaseEvidenceError,
)
from d810.manager.workbench_models import FunctionRef, RuntimeConfigRef
from d810.manager.workbench_recipe_models import FunctionPipelineOverride

__all__ = [
    "DeobfuscationCaseCollectionError",
    "DeobfuscationCaseRepositoryPort",
    "DeobfuscationCaseService",
]


class DeobfuscationCaseCollectionError(RuntimeError):
    """A diagnostic case could not be read without weakening its contract."""


class DeobfuscationCaseRepositoryPort(Protocol):
    """The narrow diagnostic repository boundary consumed by the manager."""

    def load(
        self,
        function_ea: int,
        function_fingerprint: str | None,
    ) -> DeobfuscationCaseEvidence | None: ...


def _is_current_saved_recipe(
    recipe: FunctionPipelineOverride | None,
    *,
    function: FunctionRef,
    runtime: RuntimeConfigRef,
) -> bool:
    """Defend the direct-run gate even if an upstream selection regresses."""
    return bool(
        recipe is not None
        and int(recipe.function_ea) == int(function.ea)
        and recipe.function_fingerprint == function.fingerprint
        and str(recipe.source_path) == runtime.source_path
        and str(recipe.runtime_path) == runtime.runtime_path
    )


class DeobfuscationCaseService:
    """Combine read-only case evidence with the already-selected recipe runtime."""

    def __init__(self, repository: DeobfuscationCaseRepositoryPort) -> None:
        self._repository = repository

    def collect(
        self,
        *,
        function: FunctionRef,
        runtime: RuntimeConfigRef,
        saved_recipe: FunctionPipelineOverride | None,
    ) -> DeobfuscationCaseSnapshot:
        """Return a dossier without treating diagnostic progress as execution proof.

        The current Workbench byte fingerprint is intentionally not passed into
        the diagnostics repository: its contiguous-range hash differs from the
        producer's native item/RVA identity.  A compatible producer identity
        may be supplied by a future adapter; until then the diagnostic reader
        binds evidence within its own native-key domain and direct execution is
        independently guarded by the validated saved recipe.
        """
        try:
            evidence = self._repository.load(int(function.ea), None)
        except (DeobfuscationCaseEvidenceError, OSError, sqlite3.Error) as exc:
            raise DeobfuscationCaseCollectionError(str(exc)) from exc

        if _is_current_saved_recipe(
            saved_recipe,
            function=function,
            runtime=runtime,
        ):
            return DeobfuscationCaseSnapshot(
                evidence=evidence,
                strategy=None,
                direct_run_permitted=True,
                direct_run_reason="A current saved function recipe is active.",
            )
        return DeobfuscationCaseSnapshot(
            evidence=evidence,
            strategy=None,
            direct_run_permitted=False,
            direct_run_reason="Build a strategy before running it.",
        )

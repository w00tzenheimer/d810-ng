"""Function-scoped analysis priors supplied by tests, projects, or callers."""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.recon.flow.return_frontier_artifacts import ReturnFrontierArtifactPriors
from d810.recon.flow.terminal_tail_priors import TerminalTailCascadeEgressPriors


@dataclass(frozen=True, slots=True)
class FunctionAnalysisPriors:
    """Typed caller knowledge for one function.

    These are not optimizer decisions and not family-specific configuration.
    They are explicit facts supplied by the harness/project layer when it knows
    something recon cannot infer safely from the current microcode alone.
    """

    return_frontier_artifacts: ReturnFrontierArtifactPriors = field(
        default_factory=ReturnFrontierArtifactPriors
    )
    terminal_tail_cascade_egress: TerminalTailCascadeEgressPriors = field(
        default_factory=TerminalTailCascadeEgressPriors
    )

    @property
    def is_empty(self) -> bool:
        return (
            not self.return_frontier_artifacts.known_impossible_return_constants
            and not self.return_frontier_artifacts.impossible_return_artifact_edges
            and self.terminal_tail_cascade_egress.is_empty
        )

    def merge(
        self,
        other: "FunctionAnalysisPriors | None",
    ) -> "FunctionAnalysisPriors":
        if other is None:
            return self
        return FunctionAnalysisPriors(
            return_frontier_artifacts=(
                self.return_frontier_artifacts.merge(
                    other.return_frontier_artifacts
                )
            ),
            terminal_tail_cascade_egress=(
                self.terminal_tail_cascade_egress.merge(
                    other.terminal_tail_cascade_egress
                )
            ),
        )


__all__ = ["FunctionAnalysisPriors"]

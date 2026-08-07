"""Locate the cobra-cli binary, or report a structured skip.

Mirrors the optional-native-binary pattern already used for LLVM
(``d810.backends.llvm.optimization.find_llvm_opt``): absence is a *result*,
never an exception, so a machine without CoBRA behaves identically to one where
the feature is switched off.
"""

from __future__ import annotations

import dataclasses
import enum
import os
import pathlib
import shutil

#: Environment variable pointing directly at the cobra-cli executable.
COBRA_CLI_ENV = "COBRA_CLI"
#: Environment variable pointing at a CoBRA build tree.
COBRA_ROOT_ENV = "COBRA_ROOT"
#: Set to 1 to turn a missing binary into a hard error (CI).
COBRA_REQUIRED_ENV = "D810_REQUIRE_COBRA"

_RELATIVE_BUILD_PATHS = (
    "build/tools/cobra-cli/cobra-cli",
    "build/tools/cobra-cli/Release/cobra-cli.exe",
    "tools/cobra-cli/cobra-cli",
)


class CobraStatus(enum.Enum):
    AVAILABLE = "available"
    SKIPPED = "skipped"


@dataclasses.dataclass(frozen=True)
class CobraProbe:
    """Outcome of looking for cobra-cli."""

    status: CobraStatus
    path: pathlib.Path | None = None
    reason: str = ""

    @property
    def available(self) -> bool:
        return self.status is CobraStatus.AVAILABLE


def _candidate_paths() -> list[pathlib.Path]:
    candidates: list[pathlib.Path] = []

    explicit = os.environ.get(COBRA_CLI_ENV)
    if explicit:
        candidates.append(pathlib.Path(explicit))

    root = os.environ.get(COBRA_ROOT_ENV)
    if root:
        base = pathlib.Path(root)
        candidates.extend(base / rel for rel in _RELATIVE_BUILD_PATHS)

    on_path = shutil.which("cobra-cli")
    if on_path:
        candidates.append(pathlib.Path(on_path))

    return candidates


def find_cobra_cli() -> CobraProbe:
    """Return an AVAILABLE probe, or SKIPPED with a reason that names the fix."""
    for candidate in _candidate_paths():
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return CobraProbe(CobraStatus.AVAILABLE, candidate)

    reason = (
        f"cobra-cli not found; set {COBRA_CLI_ENV} to the executable, "
        f"{COBRA_ROOT_ENV} to a CoBRA build tree, or put cobra-cli on PATH"
    )
    if os.environ.get(COBRA_REQUIRED_ENV) == "1":
        raise RuntimeError(f"{COBRA_REQUIRED_ENV}=1 but {reason}")
    return CobraProbe(CobraStatus.SKIPPED, None, reason)
